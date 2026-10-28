//! The HTTP gateway (spec §8.8) end to end in process: a daemon context on
//! temp dirs (the real audit writer and vault), `gateway::serve_with` on a
//! Unix socket, the `test-echo` connector and a loopback TLS upstream. The
//! tests talk HTTP/1.1 over the socket: through a hyper client, and by hand
//! where the request target must reach the daemon byte for byte. Nothing
//! leaves 127.0.0.1. The loopback TCP listener (`gateway::serve_tcp`) runs
//! beside it on `127.0.0.1:0`, with its bearer tokens on an injected clock.
#![cfg(target_os = "linux")]

use bytes::Bytes;
use http::{HeaderMap, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;
use saiife_audit::{ChainWriter, WriterOptions};
use saiife_broker::pipeline::PolicySnapshot;
use saiife_broker::upstream::{Resolver, Upstream};
use saiife_broker::{Catalog, Manifest};
use saiife_daemon::gateway::{self, Opts};
use saiife_daemon::ops::{Ctx, CtxInit, GatewayPolicy, PolicyState};
use saiife_daemon::sessions::RealProc;
use saiife_daemon::tokens::Tokens;
use saiife_daemon::vault::{self, Entry, Kind, VaultState};
use saiife_daemon::writer::{self, WriterConfig};
use saiife_ipc::msg::Request as IpcRequest;
use saiife_ipc::peer::PeerCred;
use saiife_policy::{Directory, Fsync, GroupEntry, Mode, SystemConfig, UserEntry};
use serde_json::{json, Value};
use std::convert::Infallible;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use zeroize::Zeroizing;

const TOKEN: &str = "echo-token-7f3a9c";
const AGENT_TOKEN: &str = "agent-own-token-55d1";
/// The size of `/api/files/big`.
const BIG: usize = 3 * 1024 * 1024;

// ---------------------------------------------------------------- mock

type Seen = Arc<Mutex<Vec<(String, HeaderMap)>>>;

struct Mock {
    hits: Arc<AtomicUsize>,
    seen: Seen,
}

struct Loopback(u16);

impl Resolver for Loopback {
    fn resolve(&self, host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
        if host.ends_with(".echo.test") {
            Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, self.0))])
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "unknown test host"))
        }
    }
}

async fn answer(
    req: Request<Incoming>,
    hits: Arc<AtomicUsize>,
    seen: Seen,
) -> Result<Response<Full<Bytes>>, Infallible> {
    hits.fetch_add(1, Ordering::SeqCst);
    let (parts, _body) = req.into_parts();
    let token = parts
        .headers
        .get("x-echo-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    seen.lock()
        .unwrap()
        .push((parts.uri.to_string(), parts.headers.clone()));
    let json = |status: u16, b: String| {
        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .header(
                "link",
                format!(
                    "<https://acme.echo.test/api/orders.json?since_id=42&page_info={token}>; rel=\"next\""
                ),
            )
            .header("set-cookie", "s=1")
            .body(Full::new(Bytes::from(b)))
            .unwrap()
    };
    if parts.uri.path() == "/api/files/slow" {
        // Long enough for the client to give up while the call is upstream.
        tokio::time::sleep(Duration::from_millis(700)).await;
    }
    if parts.uri.path() == "/api/files/hang" {
        // An upstream that does not answer while the test runs.
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
    let resp = match parts.uri.path() {
        "/api/orders.json" => json(
            200,
            format!(r#"{{"orders":[{{"id":1}}],"echo":"{token}"}}"#),
        ),
        "/api/orders/404" => json(404, r#"{"errors":"Not Found"}"#.into()),
        // Far more than a socket buffer holds.
        "/api/files/big" => json(200, format!(r#"{{"blob":"{}"}}"#, "b".repeat(BIG))),
        _ => json(404, "{}".into()),
    };
    Ok(resp)
}

async fn mock(timeout: Duration) -> (Mock, Upstream) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["acme.echo.test".to_string()])
        .unwrap()
        .signed_by(&leaf_key, &ca)
        .unwrap();
    let leaf_der: CertificateDer<'static> = leaf.der().clone();
    let key = PrivatePkcs8KeyDer::from(leaf_key.serialize_der());
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![leaf_der], PrivateKeyDer::Pkcs8(key))
    .unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let hits = Arc::new(AtomicUsize::new(0));
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let (h2, s2) = (hits.clone(), seen.clone());
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let (h, s) = (h2.clone(), s2.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let svc = service_fn(move |req| answer(req, h.clone(), s.clone()));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let up = Upstream::with_roots(roots, Arc::new(Loopback(port)), timeout);
    (Mock { hits, seen }, up)
}

// ---------------------------------------------------------------- daemon

/// Names come from the context (`own_user`); no group lookups.
struct NoDirectory;

impl Directory for NoDirectory {
    fn user(&self, _name: &str) -> Option<UserEntry> {
        None
    }
    fn name_of(&self, _uid: u32) -> Option<String> {
        None
    }
    fn group(&self, _name: &str) -> Option<GroupEntry> {
        None
    }
    fn groups_of(&self, _user: &str) -> Vec<String> {
        Vec::new()
    }
}

struct World {
    ctx: Arc<Ctx>,
    m: Mock,
    sock: PathBuf,
    /// The loopback TCP listener.
    tcp: SocketAddr,
    /// The token clock, seconds since the epoch.
    clock: Arc<AtomicU64>,
    audit: PathBuf,
    _dir_fd: std::fs::File,
    _tmp: tempfile::TempDir,
}

/// A scratch dir outside /tmp: `SAIIFE_TEST_TMP`, else cargo's target tmp.
fn scratch() -> tempfile::TempDir {
    let base = std::env::var_os("SAIIFE_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    std::fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

struct Setup {
    /// The scope's `users`.
    users: &'static str,
    /// TOML appended to `[services.shop]`.
    shop_extra: &'static str,
    opts: Opts,
    upstream_timeout: Duration,
    /// `false`: no valid policy (connectors denied with `policy_invalid`).
    policy: bool,
    /// Services `s0`.. like `shop` (same secret, same scope), each with
    /// its own 4 upstream slots.
    extra_services: usize,
}

impl Default for Setup {
    fn default() -> Setup {
        Setup {
            users: r#""agent""#,
            shop_extra: "",
            opts: Opts::default(),
            upstream_timeout: Duration::from_secs(5),
            policy: true,
            extra_services: 0,
        }
    }
}

async fn world() -> World {
    world_with(Setup::default()).await
}

async fn world_with(s: Setup) -> World {
    let tmp = scratch();
    let audit = tmp.path().join("audit");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&audit).unwrap();
    std::fs::create_dir_all(tmp.path().join("proc")).unwrap();
    std::fs::create_dir_all(tmp.path().join("run")).unwrap();

    let cw = ChainWriter::open(
        &audit,
        WriterOptions {
            mode: "locked".into(),
            saiife: "test".into(),
            key: None,
        },
    )
    .unwrap();
    let (handle, _join) = writer::spawn(
        cw,
        WriterConfig {
            checkpoint_every: 1000,
            checkpoint_interval: Duration::from_secs(900),
            fsync: Fsync::Always,
        },
        None,
    )
    .unwrap();

    // The vault: the service's token, as `saiife secret add` would store it.
    let key_file = tmp.path().join("vault-key");
    std::fs::write(&key_file, [7u8; 32]).unwrap();
    let vault_path = state.join("vault").join("vault.bin");
    let mut vault = vault::open(&key_file, &vault_path);
    let VaultState::Ready(v) = &mut vault else {
        panic!("vault not ready");
    };
    v.put(Entry {
        name: "echo-tok".into(),
        kind: Kind::Token,
        fields: [("token".to_string(), Zeroizing::new(TOKEN.to_string()))].into(),
        allowed_services: std::iter::once("shop".to_string())
            .chain((0..s.extra_services).map(|i| format!("s{i}")))
            .collect(),
        created_by: 0,
        created: "2026-10-26T00:00:00Z".into(),
        last_used: None,
        rotate_after: None,
    })
    .unwrap();

    let extra_names: String = (0..s.extra_services)
        .map(|i| format!(", \"s{i}\""))
        .collect();
    let extra_tables: String = (0..s.extra_services)
        .map(|i| {
            format!(
                "\n[services.s{i}]\nconnector = \"test-echo\"\nsecret = \"echo-tok\"\n\
                 params = {{ shop = \"acme\" }}\nallow = [\"files:read\"]\n"
            )
        })
        .collect();
    let text = format!(
        r#"version = 2
locked = true

[[scope]]
name = "agents"
users = [{users}]
services = ["shop"{extra_names}]
env = "prod"

[services.shop]
connector = "test-echo"
secret = "echo-tok"
params = {{ shop = "acme" }}
allow = ["orders:read", "files:read"]
{extra}

[services.other]
connector = "test-echo"
params = {{ shop = "other" }}
allow = ["orders:read"]
{extra_tables}"#,
        users = s.users,
        extra = s.shop_extra,
    );
    let config: SystemConfig = toml::from_str(&text).unwrap();
    let manifest = Manifest::parse(include_str!("../../broker/connectors/test-echo.toml")).unwrap();
    let policy = PolicyState {
        hash: Some("sha256:test".into()),
        ok: s.policy,
        min_free_mb: 0,
        admin_groups: Vec::new(),
        system: s.policy.then(|| Arc::new(config.clone())),
        gateway: s.policy.then(|| {
            Arc::new(GatewayPolicy {
                snap: PolicySnapshot {
                    config,
                    hash: "sha256:test".into(),
                    mode: Mode::Locked,
                },
                catalog: Catalog::new(&[], vec![manifest]),
            })
        }),
    };

    let (m, up) = mock(s.upstream_timeout).await;
    let clock = Arc::new(AtomicU64::new(1_800_000_000));
    let c2 = Arc::clone(&clock);
    let tokens = Tokens::memory_with_clock(Arc::new(move || c2.load(Ordering::SeqCst)));
    let writer_cfg = WriterConfig {
        checkpoint_every: 1000,
        checkpoint_interval: Duration::from_secs(900),
        fsync: Fsync::Always,
    };
    let ctx = Arc::new(Ctx::new(CtxInit {
        // The peer is this process: its uid is the daemon's, named `agent`.
        own_user: "agent".into(),
        audit_dir: audit.clone(),
        socket_dir: tmp.path().join("run"),
        config_path: tmp.path().join("config.toml"),
        policy,
        // No agent ancestors: no session.
        proc: Box::new(RealProc::new(tmp.path().join("proc"))),
        vault,
        vault_path,
        backup_dir: state.join("import-backup"),
        upstream: Ok(up),
        tokens: Arc::new(tokens),
        approvals: saiife_daemon::approvals::Store::open(&state.join("approvals"))
            .map_err(|e| e.to_string()),
        lockdown: saiife_daemon::lockdown::Store::memory(),
        grants: saiife_daemon::grants::Grants::memory(),
        ..CtxInit::minimal(handle, writer_cfg, Arc::new(NoDirectory), &state)
    }));

    // The socket path through the held dir: short whatever the scratch dir.
    let dir_fd = std::fs::File::open(tmp.path().join("run")).unwrap();
    let sock = PathBuf::from(format!("/proc/self/fd/{}/gateway.sock", dir_fd.as_raw_fd()));
    let listener = UnixListener::bind(&sock).unwrap();
    tokio::spawn(gateway::serve_with(listener, Arc::clone(&ctx), s.opts));
    let tcp_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let tcp = tcp_listener.local_addr().unwrap();
    tokio::spawn(gateway::serve_tcp(tcp_listener, Arc::clone(&ctx), s.opts));
    World {
        ctx,
        m,
        sock,
        tcp,
        clock,
        audit,
        _dir_fd: dir_fd,
        _tmp: tmp,
    }
}

impl World {
    fn hits(&self) -> usize {
        self.m.hits.load(Ordering::SeqCst)
    }

    fn connector_records(&self) -> Vec<Value> {
        let mut files: Vec<PathBuf> = std::fs::read_dir(&self.audit)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
            .collect();
        files.sort();
        let mut out = Vec::new();
        for f in files {
            for l in std::fs::read_to_string(f).unwrap().lines() {
                let v: Value = serde_json::from_str(l).unwrap();
                if v["kind"] == "connector" {
                    out.push(v);
                }
            }
        }
        out
    }

    fn audit_text(&self) -> String {
        let mut s = String::new();
        for e in std::fs::read_dir(&self.audit).unwrap() {
            s.push_str(&std::fs::read_to_string(e.unwrap().path()).unwrap_or_default());
        }
        s
    }

    /// One request through a hyper client.
    async fn send(
        &self,
        method: &str,
        uri: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> (StatusCode, HeaderMap, Bytes) {
        let s = UnixStream::connect(&self.sock).await.unwrap();
        let (mut tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(s))
            .await
            .unwrap();
        tokio::spawn(conn);
        let mut b = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "saiife");
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let resp = tx
            .send_request(b.body(Full::new(Bytes::copy_from_slice(body))).unwrap())
            .await
            .unwrap();
        let (parts, body) = resp.into_parts();
        let body = body.collect().await.unwrap().to_bytes();
        (parts.status, parts.headers, body)
    }

    /// One request through a hyper client on the TCP listener.
    async fn send_tcp(
        &self,
        method: &str,
        uri: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> (StatusCode, HeaderMap, Bytes) {
        let s = tokio::net::TcpStream::connect(self.tcp).await.unwrap();
        let (mut tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(s))
            .await
            .unwrap();
        tokio::spawn(conn);
        let mut b = Request::builder().method(method).uri(uri);
        if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
            b = b.header("host", format!("127.0.0.1:{}", self.tcp.port()));
        }
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let resp = tx
            .send_request(b.body(Full::new(Bytes::copy_from_slice(body))).unwrap())
            .await
            .unwrap();
        let (parts, body) = resp.into_parts();
        let body = body.collect().await.unwrap().to_bytes();
        (parts.status, parts.headers, body)
    }

    /// `api.token` as this process (the peer uid) asks for it.
    async fn token_op(&self) -> Value {
        let peer = PeerCred {
            uid: rustix::process::getuid().as_raw(),
            gid: rustix::process::getgid().as_raw(),
            pid: std::process::id(),
        };
        let req = IpcRequest {
            id: 9,
            op: "api.token".into(),
            args: Default::default(),
        };
        saiife_daemon::ops::dispatch(&self.ctx, &peer, req).await
    }

    async fn token(&self) -> String {
        let a = self.token_op().await;
        assert_eq!(a["ok"], true, "{a}");
        a["token"].as_str().unwrap().to_string()
    }

    async fn api(&self, service_op: &str, body: Value) -> (StatusCode, HeaderMap, Value) {
        let (st, h, b) = self
            .send(
                "POST",
                &format!("/v1/api/{service_op}"),
                &[("content-type", "application/json")],
                body.to_string().as_bytes(),
            )
            .await;
        (st, h, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    /// Bytes written as given, the whole answer read back (the request
    /// asks for `Connection: close`).
    async fn raw(&self, req: &[u8]) -> String {
        let mut s = UnixStream::connect(&self.sock).await.unwrap();
        s.write_all(req).await.unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut out)).await;
        String::from_utf8_lossy(&out).into_owned()
    }
}

fn status_of(raw: &str) -> u16 {
    raw.split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn body_of(raw: &str) -> Value {
    let b = raw.split_once("\r\n\r\n").map(|x| x.1).unwrap_or("");
    serde_json::from_str(b).unwrap_or(Value::Null)
}

// ---------------------------------------------------------------- tests

#[tokio::test]
async fn services_lists_scope() {
    let w = world().await;
    let (st, h, b) = w.send("GET", "/v1/services", &[], b"").await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(h["content-type"], "application/json");
    let v: Value = serde_json::from_slice(&b).unwrap();
    let services = v["services"].as_array().unwrap();
    // `other` is defined but not in the scope.
    assert_eq!(services.len(), 1, "{v}");
    assert_eq!(services[0]["name"], "shop");
    let ops = services[0]["operations"].as_array().unwrap();
    let list = ops.iter().find(|o| o["id"] == "orders.list").unwrap();
    assert_eq!(list["action"], "allow");
    let refunds = ops.iter().find(|o| o["id"] == "refunds.create").unwrap();
    assert_eq!(refunds["action"], "deny");
    // Listing is not a connector call.
    assert!(w.connector_records().is_empty());
    // Only GET.
    let (st, h, _) = w.send("POST", "/v1/services", &[], b"").await;
    assert_eq!(st, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(h["allow"], "GET");
}

#[tokio::test]
async fn api_route_200_with_upstream_status_header() {
    let w = world().await;
    let (st, h, b) = w
        .api(
            "shop/orders.list",
            json!({"params": {"status": "open"}, "wait": "10m"}),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{b}");
    assert_eq!(h["x-saiife-upstream-status"], "200");
    assert_eq!(h["content-type"], "application/json");
    // The next page from the masked `Link` (decision 8), as `k=v`.
    assert_eq!(h["x-saiife-next"], "since_id=42");
    // The upstream echoed the vault token: masked.
    assert_eq!(b["echo"], "[MASKED]");
    assert_eq!(b["orders"][0]["id"], 1);
    assert!(h.get("link").is_none() && h.get("set-cookie").is_none());

    // A 404 upstream is a done call: 200 here, the status in the header.
    let (st, h, b) = w
        .api("shop/orders.get", json!({"params": {"order_id": 404}}))
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(h["x-saiife-upstream-status"], "404");
    assert_eq!(b["errors"], "Not Found");
    assert_eq!(w.hits(), 2);

    // One record per request, via http, with the upstream status.
    let recs = w.connector_records();
    assert_eq!(recs.len(), 2);
    assert!(recs.iter().all(|r| r["via"] == "http"), "{recs:?}");
    assert_eq!(recs[0]["operation"], "orders.list");
    assert_eq!(recs[0]["status"], 200);
    assert_eq!(recs[1]["status"], 404);
    assert!(!w.audit_text().contains(TOKEN));

    // Unknown operation, bad params, a bad body: denied or refused, never sent.
    let (st, _, b) = w.api("shop/orders.nope", json!({})).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(b, json!({"error": "denied", "rule": "unknown_operation"}));
    let (st, _, b) = w
        .api("shop/orders.list", json!({"params": {"bogus": "1"}}))
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(b["rule"], "bad_param");
    let (st, _, b) = w.api("shop/orders.list", json!({"extra": 1})).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{b}");
    let (st, _, _) = w.send("GET", "/v1/api/shop/orders.list", &[], b"").await;
    assert_eq!(st, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(w.hits(), 2);
    // The two denials are records; the bad request is not.
    assert_eq!(w.connector_records().len(), 4);
}

#[tokio::test]
async fn proxy_passthrough_status_and_masked_link() {
    let w = world().await;
    let (st, h, b) = w
        .send("GET", "/v1/proxy/shop/orders.json?status=open", &[], b"")
        .await;
    assert_eq!(st, StatusCode::OK);
    let link = h["link"].to_str().unwrap();
    assert!(link.contains("page_info=[MASKED]"), "{link}");
    assert!(!link.contains(TOKEN));
    assert!(h.get("set-cookie").is_none());
    assert!(h.get("x-saiife-upstream-status").is_none());
    let v: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["echo"], "[MASKED]");
    // The query reached the upstream as sent.
    assert_eq!(
        w.m.seen.lock().unwrap()[0].0,
        "/api/orders.json?status=open"
    );

    // The upstream status passes through.
    let (st, _, b) = w.send("GET", "/v1/proxy/shop/orders/404", &[], b"").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_eq!(&b[..], br#"{"errors":"Not Found"}"#);

    let recs = w.connector_records();
    assert_eq!(recs.len(), 2);
    assert!(recs.iter().all(|r| r["via"] == "http"));
    assert_eq!(recs[0]["operation"], "orders.list");
    assert_eq!(recs[1]["operation"], "orders.get");

    // No match is unknown_operation.
    let (st, _, b) = w
        .send("DELETE", "/v1/proxy/shop/orders.json", &[], b"")
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(
        serde_json::from_slice::<Value>(&b).unwrap()["rule"],
        "unknown_operation"
    );
}

#[tokio::test]
async fn proxy_traversal_403_bad_path() {
    let w = world().await;
    // §6.7.1 step 4, sent raw: what the daemon sees is exactly this target.
    let bad = [
        "/v1/proxy/shop/orders/%2e%2e/admin",
        "/v1/proxy/shop/%2e%2e/x",
        "/v1/proxy/shop/%2E%2E/x",
        "/v1/proxy/shop/orders/%2e%2e",
        "/v1/proxy/shop/../admin",
        "/v1/proxy/shop/orders/../../v1/services",
        "/v1/proxy/shop/a//b",
        "/v1/proxy/shop//orders.json",
        "/v1/proxy/shop/http://evil/x",
        "/v1/proxy/shop//evil/x",
        "/v1/proxy/shop/a%2fb",
        "/v1/proxy/shop/a%2Fb",
        "/v1/proxy/shop/a%5cb",
        "/v1/proxy/shop/orders/1%00",
        "/v1/proxy/shop/a\\b",
    ];
    for target in bad {
        let raw = w
            .raw(
                format!("GET {target} HTTP/1.1\r\nHost: saiife\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await;
        assert_eq!(status_of(&raw), 403, "{target}: {raw}");
        assert_eq!(
            body_of(&raw),
            json!({"error": "denied", "rule": "bad_path"}),
            "{target}"
        );
    }
    let recs = w.connector_records();
    assert_eq!(recs.len(), bad.len());
    // The pipeline saw the target as sent, not normalized.
    assert_eq!(
        recs[0]["input"], "shop GET /orders/%2e%2e/admin",
        "{:?}",
        recs[0]
    );
    assert_eq!(recs[4]["input"], "shop GET /../admin");
    assert!(recs
        .iter()
        .all(|r| r["rule"] == "bad_path" && r["via"] == "http"));
    // A fragment, a control byte or an absolute target
    // never reaches the pipeline: 400, from this gateway (a JSON body) or
    // from the HTTP parser (none).
    for (target, from_gateway) in [
        ("/v1/proxy/shop/a#b", true),
        ("/v1/proxy/shop/orders.json#frag", true),
        ("/v1/proxy/shop/orders.json?status=open#x", true),
        ("/v1/proxy/shop/a\x01b", false),
        ("http://evil/v1/proxy/shop/orders.json", true),
    ] {
        let raw = w
            .raw(
                format!("GET {target} HTTP/1.1\r\nHost: saiife\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await;
        assert_eq!(status_of(&raw), 400, "{target:?}: {raw}");
        if from_gateway {
            assert_eq!(body_of(&raw)["error"], "bad_request", "{target:?}: {raw}");
        }
    }
    assert_eq!(w.connector_records().len(), bad.len());
    assert_eq!(w.hits(), 0);
}

#[tokio::test]
async fn authorization_header_from_agent_not_forwarded() {
    let w = world().await;
    let bearer = format!("Bearer {AGENT_TOKEN}");
    let (st, _, _) = w
        .send(
            "GET",
            "/v1/proxy/shop/orders.json",
            &[
                ("authorization", &bearer),
                ("cookie", "session=agent"),
                ("x-echo-token", AGENT_TOKEN),
                ("x-forwarded-user", "root"),
                ("forwarded", "for=10.0.0.1;by=root"),
                ("accept", "application/json"),
            ],
            b"",
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    let seen = w.m.seen.lock().unwrap();
    let (_, h) = &seen[0];
    // The vault token, not the agent's: neither its Authorization nor its
    // own copy of the auth header got through.
    assert_eq!(h["x-echo-token"], TOKEN);
    assert_eq!(h.get_all("x-echo-token").iter().count(), 1);
    assert!(h.get("authorization").is_none());
    assert!(h.get("cookie").is_none());
    assert!(h.get("x-forwarded-user").is_none() && h.get("forwarded").is_none());
    assert_eq!(h["accept"], "application/json");
    for (_, v) in h.iter() {
        assert!(!v.to_str().unwrap_or("").contains(AGENT_TOKEN));
    }
}

#[tokio::test]
async fn body_over_1mib_413() {
    let w = world().await;
    // Declared too large: refused before a byte of the body is read.
    let raw = w
        .raw(
            format!(
                "POST /v1/api/shop/orders.list HTTP/1.1\r\nHost: saiife\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                1024 * 1024 + 1
            )
            .as_bytes(),
        )
        .await;
    assert_eq!(status_of(&raw), 413, "{raw}");

    // Chunked, no length: refused once 1 MiB is passed, while the client
    // has not finished the body (no last chunk is ever sent).
    let mut s = UnixStream::connect(&w.sock).await.unwrap();
    s.write_all(b"POST /v1/proxy/shop/orders.json HTTP/1.1\r\nHost: saiife\r\nTransfer-Encoding: chunked\r\n\r\n")
        .await
        .unwrap();
    let (mut rd, mut wr) = s.into_split();
    let writer = tokio::spawn(async move {
        let chunk = vec![b'a'; 64 * 1024];
        for _ in 0..17 {
            let head = format!("{:x}\r\n", chunk.len());
            if wr.write_all(head.as_bytes()).await.is_err()
                || wr.write_all(&chunk).await.is_err()
                || wr.write_all(b"\r\n").await.is_err()
            {
                return;
            }
        }
        // Hold the request open: the answer must not wait for the end.
        tokio::time::sleep(Duration::from_secs(30)).await;
        drop(wr);
    });
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let read = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    out.extend_from_slice(&buf[..n]);
                    if out.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
            }
        }
    })
    .await;
    assert!(read.is_ok(), "no answer while the body was still open");
    let raw = String::from_utf8_lossy(&out);
    assert_eq!(status_of(&raw), 413, "{raw}");
    writer.abort();

    // Exactly 1 MiB is not refused for its size (the pipeline judges it).
    let body = vec![b' '; 1024 * 1024];
    let (st, _, _) = w.send("POST", "/v1/api/shop/orders.list", &[], &body).await;
    assert_eq!(st, StatusCode::OK);
    // The refused bodies never made a call or a record.
    assert_eq!(w.hits(), 1);
    assert_eq!(w.connector_records().len(), 1);
}

#[tokio::test]
async fn slow_headers_closed_after_10s() {
    assert_eq!(gateway::HEADER_READ_TIMEOUT, Duration::from_secs(10));
    assert_eq!(gateway::MAX_HEAD_BYTES, 64 * 1024);
    let w = world_with(Setup {
        opts: Opts {
            header_read_timeout: Duration::from_millis(200),
            ..Opts::default()
        },
        ..Setup::default()
    })
    .await;
    let mut s = UnixStream::connect(&w.sock).await.unwrap();
    let t0 = Instant::now();
    // Half a head, then nothing.
    s.write_all(b"GET /v1/services HTTP/1.1\r\nHost: sai")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let r = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await;
    let took = t0.elapsed();
    assert!(r.is_ok(), "the connection stayed open");
    assert!(took >= Duration::from_millis(200), "{took:?}");
    assert!(!String::from_utf8_lossy(&buf).contains("200 OK"));

    // A connection that sends nothing is closed the same way.
    let mut s = UnixStream::connect(&w.sock).await.unwrap();
    let t0 = Instant::now();
    let mut buf = Vec::new();
    let r = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await;
    assert!(r.is_ok());
    assert!(t0.elapsed() >= Duration::from_millis(200));

    // A head over 64 KiB is refused.
    let big = format!(
        "GET /v1/services HTTP/1.1\r\nHost: saiife\r\nX-Big: {}\r\nConnection: close\r\n\r\n",
        "a".repeat(70 * 1024)
    );
    let raw = w.raw(big.as_bytes()).await;
    assert_eq!(status_of(&raw), 431, "{raw}");
}

#[tokio::test]
async fn limit_429() {
    let w = world_with(Setup {
        shop_extra: "limits = { requests_per_minute = 1 }",
        upstream_timeout: Duration::from_millis(300),
        ..Setup::default()
    })
    .await;
    let (st, _, _) = w.api("shop/orders.list", json!({})).await;
    assert_eq!(st, StatusCode::OK);
    let (st, _, b) = w.api("shop/orders.list", json!({})).await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(b, json!({"error": "limit", "limit": "requests_per_minute"}));
    let (st, _, _) = w.send("GET", "/v1/proxy/shop/orders.json", &[], b"").await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(w.hits(), 1);
    let recs = w.connector_records();
    assert_eq!(recs.len(), 3);
    assert_eq!(recs[1]["limit"], "requests_per_minute");
}

#[tokio::test]
async fn concurrency_limit_429() {
    let w = world_with(Setup {
        upstream_timeout: Duration::from_millis(300),
        ..Setup::default()
    })
    .await;
    // The service's 4 upstream slots are all taken.
    let held = w.ctx.pools.get("shop").acquire_many_owned(4).await.unwrap();
    let (st, _, b) = w.api("shop/orders.list", json!({})).await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(b, json!({"error": "limit", "limit": "concurrency"}));
    drop(held);
    let (st, _, _) = w.api("shop/orders.list", json!({})).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(w.hits(), 1);
}

#[tokio::test]
async fn non_scoped_uid_403_no_scope() {
    let w = world_with(Setup {
        users: r#""someone-else""#,
        ..Setup::default()
    })
    .await;
    // Claimed identities are not identities: only the peer uid counts.
    let hdrs = [
        ("authorization", "Bearer someone-else"),
        ("x-forwarded-user", "someone-else"),
        ("forwarded", "for=someone-else"),
    ];
    let (st, _, b) = w
        .send(
            "POST",
            "/v1/api/shop/orders.list",
            &hdrs,
            br#"{"params":{}}"#,
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(
        serde_json::from_slice::<Value>(&b).unwrap(),
        json!({"error": "denied", "rule": "no_scope"})
    );
    let (st, _, b) = w
        .send("GET", "/v1/proxy/shop/orders.json", &hdrs, b"")
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(
        serde_json::from_slice::<Value>(&b).unwrap()["rule"],
        "no_scope"
    );
    let (st, _, b) = w.send("GET", "/v1/services", &hdrs, b"").await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(&b).unwrap()["services"],
        json!([])
    );
    assert_eq!(w.hits(), 0);
    let recs = w.connector_records();
    assert_eq!(recs.len(), 2);
    assert!(recs
        .iter()
        .all(|r| r["rule"] == "no_scope" && r["user"] == "agent"));
}

#[tokio::test]
async fn invalid_policy_403_requests_503_unknown_404() {
    let w = world_with(Setup {
        policy: false,
        ..Setup::default()
    })
    .await;
    let (st, _, b) = w.api("shop/orders.list", json!({})).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(b, json!({"error": "denied", "rule": "policy_invalid"}));
    let recs = w.connector_records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["via"], "http");

    // No such request: 404, as for another uid's.
    let (st, _, _) = w.send("GET", "/v1/requests/42", &[], b"").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _, _) = w.send("GET", "/v1/requests/042", &[], b"").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _, _) = w.send("POST", "/v1/requests/42", &[], b"").await;
    assert_eq!(st, StatusCode::METHOD_NOT_ALLOWED);
    let (st, _, _) = w.send("GET", "/v1/nope", &[], b"").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _, _) = w.send("GET", "/v1/../v1/services", &[], b"").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_eq!(w.hits(), 0);
}

async fn wait_until(limit: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + limit;
    while Instant::now() < end {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    cond()
}

#[tokio::test]
async fn client_that_never_reads_is_closed_after_write_timeout() {
    assert_eq!(gateway::WRITE_TIMEOUT, Duration::from_secs(10));
    let w = world_with(Setup {
        opts: Opts {
            write_timeout: Duration::from_millis(300),
            ..Opts::default()
        },
        ..Setup::default()
    })
    .await;
    let uid = rustix::process::getuid().as_raw();
    let mut s = UnixStream::connect(&w.sock).await.unwrap();
    s.write_all(b"GET /v1/proxy/shop/files/big HTTP/1.1\r\nHost: saiife\r\n\r\n")
        .await
        .unwrap();
    // The answer is on its way and the client reads nothing: the slot is
    // held while the write stalls ...
    assert!(wait_until(Duration::from_secs(10), || w.hits() == 1).await);
    assert_eq!(w.ctx.conns.open_for(uid), 1);
    // ... and given back once no write progressed for the write timeout.
    let t0 = Instant::now();
    assert!(
        wait_until(Duration::from_secs(10), || w.ctx.conns.open_for(uid) == 0).await,
        "the stalled connection kept its slot"
    );
    assert!(t0.elapsed() < Duration::from_secs(5), "{:?}", t0.elapsed());
    // What was buffered can still be read, then the end: never all of it.
    let mut out = Vec::new();
    let r = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut out)).await;
    assert!(r.is_ok(), "the connection was not closed");
    assert!(
        out.starts_with(b"HTTP/1.1 200"),
        "{:?}",
        &out[..out.len().min(64)]
    );
    assert!(out.len() < BIG, "{}", out.len());
    // The call itself was made and recorded.
    assert_eq!(w.connector_records().len(), 1);

    // A client that does read gets all of it.
    let (st, _, b) = w.send("GET", "/v1/proxy/shop/files/big", &[], b"").await;
    assert_eq!(st, StatusCode::OK);
    assert!(b.len() > BIG);
}

#[tokio::test]
async fn client_gone_mid_call_still_records_and_counts() {
    let w = world_with(Setup {
        shop_extra: "limits = { requests_per_minute = 1 }",
        ..Setup::default()
    })
    .await;
    let mut s = UnixStream::connect(&w.sock).await.unwrap();
    s.write_all(b"GET /v1/proxy/shop/files/slow HTTP/1.1\r\nHost: saiife\r\n\r\n")
        .await
        .unwrap();
    // The request is upstream; the client closes its socket.
    assert!(wait_until(Duration::from_secs(10), || w.hits() == 1).await);
    drop(s);
    // The call finishes anyway: its record is written ...
    assert!(
        wait_until(Duration::from_secs(10), || w.connector_records().len() == 1).await,
        "no connector record for a call the client walked away from"
    );
    let recs = w.connector_records();
    assert_eq!(recs[0]["decision"], "allow");
    assert_eq!(recs[0]["status"], 404);
    // ... and it counts: the next call is over the limit.
    let (st, _, b) = w.api("shop/orders.list", json!({})).await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS, "{b}");
    assert_eq!(b["limit"], "requests_per_minute");
    assert_eq!(w.hits(), 1);
}

#[tokio::test]
async fn walked_away_calls_keep_their_in_flight_slot() {
    // 16 services x 4 upstream slots: 64 calls can hang upstream at once.
    let w = world_with(Setup {
        extra_services: 15,
        upstream_timeout: Duration::from_secs(30),
        ..Setup::default()
    })
    .await;
    let services: Vec<String> = std::iter::once("shop".to_string())
        .chain((0..15).map(|i| format!("s{i}")))
        .collect();
    // Each client sends a call to a hanging upstream and walks away once
    // it is upstream (one at a time: the per-uid connection cap is 32).
    for i in 0..64 {
        let mut s = UnixStream::connect(&w.sock).await.unwrap();
        let req = format!(
            "GET /v1/proxy/{}/files/hang HTTP/1.1\r\nHost: saiife\r\n\r\n",
            services[i / 4]
        );
        s.write_all(req.as_bytes()).await.unwrap();
        assert!(
            wait_until(Duration::from_secs(10), || w.hits() == i + 1).await,
            "call {i} did not reach the upstream"
        );
        drop(s);
    }
    let uid = rustix::process::getuid().as_raw();
    assert!(wait_until(Duration::from_secs(10), || w.ctx.conns.open_for(uid) == 0).await);
    // Every client is gone, but 64 calls still run: the 65th is busy (not
    // admitted and then refused by a service's upstream slots).
    let (st, h, b) = w.api("shop/orders.list", json!({})).await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS, "{b}");
    assert_eq!(b["error"], "busy", "{b}");
    assert_eq!(h.get("retry-after").unwrap(), "1");
    assert_eq!(w.hits(), 64);
}

#[tokio::test]
async fn pre_pipeline_refusals_leave_one_notice_per_kind_a_minute() {
    let w = world().await;
    let refusals = |w: &World| -> Vec<Value> {
        w.audit_text()
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|v| v["event"] == "gateway_refused")
            .collect()
    };
    for _ in 0..3 {
        let (st, _, _) = w.send("GET", "/v1/api/shop/orders.list", &[], b"").await;
        assert_eq!(st, StatusCode::METHOD_NOT_ALLOWED);
        let (st, _, _) = w.send("POST", "/v1/api/shop/orders.list", &[], b"[]").await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        let (st, _, _) = w.send_tcp("GET", "/v1/services", &[], b"").await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }
    // Method, bad request (this uid) and token (an unknown TCP client).
    assert!(wait_until(Duration::from_secs(10), || refusals(&w).len() >= 3).await);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let r = refusals(&w);
    assert_eq!(r.len(), 3, "{r:?}");
    let reasons: Vec<&str> = r.iter().map(|v| v["reason"].as_str().unwrap()).collect();
    assert!(reasons.iter().any(|s| s.contains("(405)")), "{reasons:?}");
    assert!(reasons.iter().any(|s| s.contains("(400)")), "{reasons:?}");
    assert!(
        reasons
            .iter()
            .any(|s| s.contains("(401)") && s.contains("without a valid token")),
        "{reasons:?}"
    );
    assert!(w.connector_records().is_empty());
}

/// `policy.reload` as root (always an admin).
async fn reload_op(ctx: &Arc<Ctx>, id: u64) -> Value {
    let peer = PeerCred {
        uid: 0,
        gid: 0,
        pid: std::process::id(),
    };
    let req = IpcRequest {
        id,
        op: "policy.reload".into(),
        args: Default::default(),
    };
    saiife_daemon::ops::dispatch(ctx, &peer, req).await
}

#[tokio::test]
async fn concurrent_reloads_run_one_at_a_time_in_order() {
    let w = world().await;
    let policy_records = |w: &World| w.audit_text().matches("\"kind\":\"policy\"").count();
    // A reload in progress holds the lock: hold it here, as one would.
    let held = w.ctx.reloads.lock().await;
    let done = Arc::new(Mutex::new(Vec::new()));
    let mut tasks = Vec::new();
    for id in [1u64, 2] {
        let (ctx, done) = (Arc::clone(&w.ctx), Arc::clone(&done));
        tasks.push(tokio::spawn(async move {
            let a = reload_op(&ctx, id).await;
            done.lock().unwrap().push(id);
            a
        }));
        // Queue them in a known order.
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        done.lock().unwrap().is_empty(),
        "a reload ran while another held the lock"
    );
    assert_eq!(policy_records(&w), 0);
    drop(held);
    for t in tasks {
        let a = t.await.unwrap();
        // No config file in this world: each reload is refused, recorded.
        assert_eq!(a["ok"], true, "{a}");
        assert_eq!(a["result"], "rejected", "{a}");
    }
    assert_eq!(*done.lock().unwrap(), [1, 2]);
    assert_eq!(policy_records(&w), 2);
}

#[tokio::test]
async fn api_token_withheld_without_its_record_or_below_the_disk_floor() {
    let w = world().await;
    let me = rustix::process::getuid().as_raw();
    // Below `[audit] min_free_mb` a uid other than the daemon's gets none.
    w.ctx.policy.lock().unwrap().min_free_mb = u64::MAX;
    let peer = PeerCred {
        uid: me + 1,
        gid: rustix::process::getgid().as_raw(),
        pid: std::process::id(),
    };
    let req = IpcRequest {
        id: 9,
        op: "api.token".into(),
        args: Default::default(),
    };
    let a = saiife_daemon::ops::dispatch(&w.ctx, &peer, req).await;
    assert_eq!(a["ok"], false, "{a}");
    assert!(a.get("token").is_none(), "{a}");
    assert_eq!(a["error"], "low_disk", "{a}");
    assert_eq!(w.ctx.tokens.live_for(me + 1), 0);
    w.ctx.policy.lock().unwrap().min_free_mb = 0;
    // The record cannot be written: no token, and none left live.
    // (No signing key here: the stop fails its checkpoint, and stops.)
    let _ = w.ctx.writer.stop(None).await;
    let a = w.token_op().await;
    assert_eq!(a["ok"], false, "{a}");
    assert!(a.get("token").is_none(), "{a}");
    assert!(
        a["message"].as_str().unwrap().contains("no token issued"),
        "{a}"
    );
    assert_eq!(w.ctx.tokens.live_for(me), 0);
}

#[tokio::test]
async fn content_length_checked_only_without_transfer_encoding() {
    let w = world().await;
    let raw = w
        .raw(b"POST /v1/api/shop/orders.list HTTP/1.1\r\nHost: saiife\r\nContent-Length: abc\r\nConnection: close\r\n\r\n")
        .await;
    assert_eq!(status_of(&raw), 400, "{raw}");
    // Chunked: a stale Content-Length says nothing; the body is small.
    let raw = w
        .raw(b"POST /v1/api/shop/orders.list HTTP/1.1\r\nHost: saiife\r\nTransfer-Encoding: chunked\r\nContent-Length: 99999999\r\nConnection: close\r\n\r\n2\r\n{}\r\n0\r\n\r\n")
        .await;
    assert_eq!(status_of(&raw), 200, "{raw}");
    assert_eq!(w.hits(), 1);
}

#[tokio::test]
async fn proxy_outcome_header_tells_upstream_from_saiife() {
    let w = world_with(Setup {
        shop_extra: "limits = { requests_per_minute = 2 }",
        ..Setup::default()
    })
    .await;
    let outcome = |h: &HeaderMap| h["x-saiife-outcome"].to_str().unwrap().to_string();
    let (st, h, _) = w.send("GET", "/v1/proxy/shop/orders.json", &[], b"").await;
    assert_eq!((st, outcome(&h).as_str()), (StatusCode::OK, "upstream"));
    // An upstream 404 is the upstream's.
    let (st, h, _) = w.send("GET", "/v1/proxy/shop/orders/404", &[], b"").await;
    assert_eq!(
        (st, outcome(&h).as_str()),
        (StatusCode::NOT_FOUND, "upstream")
    );
    // saiife's own 403, 429 and 400.
    let (st, h, _) = w
        .send("DELETE", "/v1/proxy/shop/orders.json", &[], b"")
        .await;
    assert_eq!(
        (st, outcome(&h).as_str()),
        (StatusCode::FORBIDDEN, "saiife")
    );
    let (st, h, _) = w.send("GET", "/v1/proxy/shop/orders.json", &[], b"").await;
    assert_eq!(
        (st, outcome(&h).as_str()),
        (StatusCode::TOO_MANY_REQUESTS, "saiife")
    );
    let raw = w
        .raw(b"GET /v1/proxy/shop/a#b HTTP/1.1\r\nHost: saiife\r\nConnection: close\r\n\r\n")
        .await;
    assert_eq!(status_of(&raw), 400);
    assert!(raw.contains("x-saiife-outcome: saiife"), "{raw}");
    // `/v1/api` says it with X-Saiife-Upstream-Status instead.
    let (_, h, _) = w.api("shop/orders.list", json!({})).await;
    assert!(h.get("x-saiife-outcome").is_none());
}

// ---------------------------------------------------------------- tcp

#[tokio::test]
async fn token_maps_to_uid() {
    let w = world().await;
    let me = rustix::process::getuid().as_raw();
    let a = w.token_op().await;
    assert_eq!(a["ok"], true, "{a}");
    let tok = a["token"].as_str().unwrap();
    assert!(
        tok.starts_with("saiife_gw_") && tok.len() == 10 + 43,
        "{tok}"
    );
    // 12 h on the injected clock, in the record format.
    assert_eq!(a["expires"], "2027-01-15T20:00:00Z");
    let bearer = format!("Bearer {tok}");
    let auth = [("authorization", bearer.as_str())];

    // The same routes as on the Unix socket, the identity from the token.
    let (st, _, b) = w.send_tcp("GET", "/v1/services", &auth, b"").await;
    assert_eq!(st, StatusCode::OK);
    let v: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["services"][0]["name"], "shop", "{v}");
    let (st, h, b) = w
        .send_tcp(
            "POST",
            "/v1/api/shop/orders.list",
            &auth,
            br#"{"params":{"status":"open"}}"#,
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{b:?}");
    assert_eq!(h["x-saiife-upstream-status"], "200");
    assert_eq!(w.hits(), 1);
    let recs = w.connector_records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["uid"], me);
    assert_eq!(recs[0]["user"], "agent");
    assert_eq!(recs[0]["via"], "http");
    assert_eq!(recs[0]["peer"]["auth"], "token");
    assert!(recs[0]["peer"]["tcp"]
        .as_str()
        .unwrap()
        .starts_with("127.0.0.1:"));
    // The issue is in the log; the token is not.
    let issued: Vec<Value> = w
        .audit_text()
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .filter(|r| r["event"] == "gateway_token")
        .collect();
    assert_eq!(issued.len(), 1);
    assert_eq!(issued[0]["token_uid"], me);
    assert!(!w.audit_text().contains(&tok[10..]));
}

#[tokio::test]
async fn tcp_without_a_good_token_401() {
    let w = world().await;
    let tok = w.token().await;
    let wrong = format!("Bearer {}", tok.replace("saiife_gw_", "saiife_gw_x"));
    let basic = format!("Basic {tok}");
    let bare = tok.clone();
    let cases: Vec<Vec<(&str, &str)>> = vec![
        vec![],
        vec![("authorization", wrong.as_str())],
        vec![("authorization", basic.as_str())],
        vec![("authorization", bare.as_str())],
        vec![("authorization", "Bearer ")],
        // Who the agent says it is never counts.
        vec![("x-forwarded-user", "agent")],
    ];
    for hdrs in &cases {
        for (m, uri, body) in [
            ("GET", "/v1/services", &b""[..]),
            ("POST", "/v1/api/shop/orders.list", &b"{}"[..]),
            ("GET", "/v1/proxy/shop/orders.json", &b""[..]),
        ] {
            let (st, h, b) = w.send_tcp(m, uri, hdrs, body).await;
            assert_eq!(st, StatusCode::UNAUTHORIZED, "{hdrs:?} {uri}");
            assert_eq!(
                serde_json::from_slice::<Value>(&b).unwrap(),
                json!({"error": "token"})
            );
            assert_eq!(h["www-authenticate"], "Bearer");
        }
    }
    // Two Authorization headers, one good: refused.
    let good = format!("Bearer {tok}");
    let (st, _, _) = w
        .send_tcp(
            "GET",
            "/v1/services",
            &[
                ("authorization", good.as_str()),
                ("authorization", "Bearer x"),
            ],
            b"",
        )
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(w.hits(), 0);
    assert!(w.connector_records().is_empty());
}

#[tokio::test]
async fn expired_token_401() {
    let w = world().await;
    let tok = w.token().await;
    let bearer = format!("Bearer {tok}");
    let auth = [("authorization", bearer.as_str())];
    w.clock.fetch_add(12 * 3600 - 1, Ordering::SeqCst);
    let (st, _, _) = w.send_tcp("GET", "/v1/services", &auth, b"").await;
    assert_eq!(st, StatusCode::OK);
    w.clock.fetch_add(1, Ordering::SeqCst);
    let (st, _, b) = w.send_tcp("GET", "/v1/services", &auth, b"").await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(
        serde_json::from_slice::<Value>(&b).unwrap(),
        json!({"error": "token"})
    );
}

#[tokio::test]
async fn token_never_forwarded_upstream() {
    let w = world().await;
    let tok = w.token().await;
    let bearer = format!("Bearer {tok}");
    for uri in ["/v1/proxy/shop/orders.json", "/v1/api/shop/orders.list"] {
        let method = if uri.starts_with("/v1/api/") {
            "POST"
        } else {
            "GET"
        };
        let (st, _, _) = w
            .send_tcp(
                method,
                uri,
                &[
                    ("authorization", bearer.as_str()),
                    ("accept", "application/json"),
                ],
                b"",
            )
            .await;
        assert_eq!(st, StatusCode::OK, "{uri}");
    }
    let seen = w.m.seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    for (_, h) in seen.iter() {
        assert!(h.get("authorization").is_none());
        // The vault credential went up, as on the Unix socket.
        assert_eq!(h["x-echo-token"], TOKEN);
        for (_, v) in h.iter() {
            assert!(!v.to_str().unwrap_or("").contains(&tok[10..]));
        }
    }
}

#[tokio::test]
async fn token_masked_in_records() {
    let w = world().await;
    let tok = w.token().await;
    let bearer = format!("Bearer {tok}");
    // An agent that puts its token where it does not belong: in a query
    // parameter, sent upstream. The record keeps the request, masked.
    let body = json!({"params": {"name": tok}}).to_string();
    let (st, _, b) = w
        .send_tcp(
            "POST",
            "/v1/api/shop/files.get",
            &[("authorization", bearer.as_str())],
            body.as_bytes(),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{b:?}");
    let seen = w.m.seen.lock().unwrap().clone();
    assert!(
        seen[0].0.contains(&tok[10..]),
        "the agent's choice: {seen:?}"
    );
    let recs = w.connector_records();
    assert_eq!(recs.len(), 1);
    let text = w.audit_text();
    assert!(!text.contains(&tok[10..]), "{text}");
    assert!(recs[0].to_string().contains("[MASKED]"), "{}", recs[0]);
}

#[tokio::test]
async fn api_token_needs_a_scope() {
    let w = world_with(Setup {
        users: r#""someone-else""#,
        ..Setup::default()
    })
    .await;
    let a = w.token_op().await;
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["error"], "forbidden");
    assert_eq!(w.ctx.tokens.live_for(rustix::process::getuid().as_raw()), 0);
}

/// Open `n` TCP connections that send nothing.
async fn idle(w: &World, n: usize) -> Vec<tokio::net::TcpStream> {
    let mut held = Vec::new();
    for _ in 0..n {
        held.push(tokio::net::TcpStream::connect(w.tcp).await.unwrap());
    }
    // Let the listener take all of them.
    tokio::time::sleep(Duration::from_millis(200)).await;
    held
}

/// Whether the peer closed `s` within `limit`.
async fn closed(s: &mut tokio::net::TcpStream, limit: Duration) -> bool {
    let mut b = [0u8; 64];
    matches!(
        tokio::time::timeout(limit, s.read(&mut b)).await,
        Ok(Ok(0)) | Ok(Err(_))
    )
}

#[tokio::test]
async fn idle_unauthenticated_connections_do_not_block_a_token_holder() {
    let w = world().await;
    let tok = w.token().await;
    let bearer = format!("Bearer {tok}");
    let mut held = idle(&w, gateway::MAX_TCP_PRE_AUTH).await;
    // The token holder gets in at once (the oldest idle one goes).
    let started = Instant::now();
    let (st, _, _) = w
        .send_tcp(
            "GET",
            "/v1/services",
            &[("authorization", bearer.as_str())],
            b"",
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(closed(&mut held[0], Duration::from_millis(500)).await);
    // Never more than 16 pre-auth at once: 16 more push all the old out.
    let _more = idle(&w, gateway::MAX_TCP_PRE_AUTH).await;
    for s in held.iter_mut().skip(1) {
        assert!(closed(s, Duration::from_millis(500)).await);
    }
}

#[tokio::test]
async fn pre_auth_head_timeout_is_2s() {
    let w = world().await;
    let mut held = idle(&w, 1).await;
    let started = Instant::now();
    assert!(closed(&mut held[0], Duration::from_secs(5)).await);
    let t = started.elapsed();
    assert!(
        t >= Duration::from_millis(1500) && t < Duration::from_millis(3500),
        "{t:?}"
    );
}

#[tokio::test]
async fn authenticated_tcp_connections_capped() {
    let w = world_with(Setup {
        opts: Opts {
            tcp_max_conns: 2,
            ..Opts::default()
        },
        upstream_timeout: Duration::from_millis(1500),
        ..Setup::default()
    })
    .await;
    let tok = w.token().await;
    let bearer = format!("Bearer {tok}");
    let auth = [("authorization", bearer.as_str())];
    // The upstream slots are taken: two calls stay in flight a while.
    let held = w.ctx.pools.get("shop").acquire_many_owned(4).await.unwrap();
    let slow = || w.send_tcp("POST", "/v1/api/shop/orders.list", &auth, b"{}");
    let third = async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        w.send_tcp("GET", "/v1/services", &auth, b"").await
    };
    let ((a, _, _), (b, _, _), (c, _, body)) = tokio::join!(slow(), slow(), third);
    assert_eq!(a, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(b, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(c, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["message"],
        "too many open connections"
    );
    drop(held);
    // Their slots came back.
    let (st, _, _) = w.send_tcp("GET", "/v1/services", &auth, b"").await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn unix_socket_ignores_bearer_token() {
    let w = world().await;
    let me = rustix::process::getuid().as_raw();
    let other = me + 1;
    let tok = w.ctx.tokens.issue(other).unwrap();
    assert_eq!(w.ctx.tokens.verify(&tok.token), Some(other));
    let bearer = format!("Bearer {}", tok.token.as_str());
    let (st, _, _) = w
        .send(
            "POST",
            "/v1/api/shop/orders.list",
            &[("authorization", &bearer)],
            b"{}",
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    let recs = w.connector_records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["uid"], me);
    assert_eq!(recs[0]["user"], "agent");
    assert_eq!(recs[0]["peer"]["pid"], std::process::id());
    assert!(recs[0]["peer"].get("auth").is_none());
}

#[tokio::test]
async fn tcp_refuses_browser_origin_and_foreign_host() {
    let w = world().await;
    let tok = w.token().await;
    let bearer = format!("Bearer {tok}");
    let port = w.tcp.port();
    let ok_hosts = [
        format!("127.0.0.1:{port}"),
        format!("[::1]:{port}"),
        format!("localhost:{port}"),
        format!("LocalHost:{port}"),
    ];
    for h in &ok_hosts {
        let (st, _, _) = w
            .send_tcp(
                "GET",
                "/v1/services",
                &[("authorization", bearer.as_str()), ("host", h.as_str())],
                b"",
            )
            .await;
        assert_eq!(st, StatusCode::OK, "{h}");
    }
    let bad_hosts = [
        "evil.example:80".to_string(),
        format!("evil.example:{port}"),
        "127.0.0.1".to_string(),
        "localhost".to_string(),
        format!("127.0.0.1:{}", port.wrapping_add(1)),
        format!("127.0.0.2:{port}"),
    ];
    for h in &bad_hosts {
        let (st, _, b) = w
            .send_tcp(
                "GET",
                "/v1/services",
                &[("authorization", bearer.as_str()), ("host", h.as_str())],
                b"",
            )
            .await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{h}");
        assert_eq!(
            serde_json::from_slice::<Value>(&b).unwrap(),
            json!({"error": "origin"})
        );
    }
    // Any Origin, even a loopback one, with or without a token.
    for o in [
        "https://evil.example",
        "null",
        &format!("http://127.0.0.1:{port}"),
    ] {
        for hdrs in [
            vec![("origin", o), ("authorization", bearer.as_str())],
            vec![("origin", o)],
        ] {
            let (st, h, b) = w
                .send_tcp("POST", "/v1/api/shop/orders.list", &hdrs, b"{}")
                .await;
            assert_eq!(st, StatusCode::FORBIDDEN, "{o}");
            assert_eq!(
                serde_json::from_slice::<Value>(&b).unwrap(),
                json!({"error": "origin"})
            );
            assert!(h.get("access-control-allow-origin").is_none());
        }
    }
    assert_eq!(w.hits(), 0);
    assert!(w.connector_records().is_empty());
    // The Unix socket has no such rule (no browser reaches it).
    let (st, _, _) = w
        .send("GET", "/v1/services", &[("origin", "https://x")], b"")
        .await;
    assert_eq!(st, StatusCode::OK);
}
