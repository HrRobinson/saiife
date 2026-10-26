//! The HTTP gateway (spec §8.8) end to end in process: a daemon context on
//! temp dirs (the real audit writer and vault), `gateway::serve_with` on a
//! Unix socket, the `test-echo` connector and a loopback TLS upstream. The
//! tests talk HTTP/1.1 over the socket: through a hyper client, and by hand
//! where the request target must reach the daemon byte for byte. Nothing
//! leaves 127.0.0.1.
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
use saiife_broker::limits::Limiter;
use saiife_broker::pipeline::PolicySnapshot;
use saiife_broker::upstream::{Resolver, Upstream};
use saiife_broker::{Catalog, Manifest};
use saiife_daemon::gateway::{self, Opts};
use saiife_daemon::ops::{Ctx, CtxInit, GatewayPolicy, PolicyState};
use saiife_daemon::sessions::RealProc;
use saiife_daemon::vault::{self, Entry, Kind, VaultState};
use saiife_daemon::writer::{self, WriterConfig};
use saiife_policy::{Directory, Fsync, GroupEntry, Mode, SystemConfig, UserEntry};
use serde_json::{json, Value};
use std::convert::Infallible;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
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
}

impl Default for Setup {
    fn default() -> Setup {
        Setup {
            users: r#""agent""#,
            shop_extra: "",
            opts: Opts::default(),
            upstream_timeout: Duration::from_secs(5),
            policy: true,
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
        allowed_services: vec!["shop".into()],
        created_by: 0,
        created: "2026-10-26T00:00:00Z".into(),
        last_used: None,
        rotate_after: None,
    })
    .unwrap();

    let text = format!(
        r#"version = 2
locked = true

[[scope]]
name = "agents"
users = [{users}]
services = ["shop"]
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
"#,
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
    let ctx = Arc::new(Ctx::new(CtxInit {
        writer: handle,
        writer_cfg: WriterConfig {
            checkpoint_every: 1000,
            checkpoint_interval: Duration::from_secs(900),
            fsync: Fsync::Always,
        },
        directory: Arc::new(NoDirectory),
        own_uid: rustix::process::getuid().as_raw(),
        // The peer is this process: its uid is the daemon's, named `agent`.
        own_user: "agent".into(),
        audit_dir: audit.clone(),
        socket_dir: tmp.path().join("run"),
        key_path: state.join("keys/audit.ed25519"),
        config_path: tmp.path().join("config.toml"),
        catalog: Vec::new(),
        policy,
        // No agent ancestors: no session.
        proc: Box::new(RealProc::new(tmp.path().join("proc"))),
        vault,
        vault_path,
        backup_dir: state.join("import-backup"),
        limiter: Limiter::new(),
        upstream: Ok(up),
    }));

    // The socket path through the held dir: short whatever the scratch dir.
    let dir_fd = std::fs::File::open(tmp.path().join("run")).unwrap();
    let sock = PathBuf::from(format!("/proc/self/fd/{}/gateway.sock", dir_fd.as_raw_fd()));
    let listener = UnixListener::bind(&sock).unwrap();
    tokio::spawn(gateway::serve_with(listener, Arc::clone(&ctx), s.opts));
    World {
        ctx,
        m,
        sock,
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

    let (st, _, b) = w.send("GET", "/v1/requests/42", &[], b"").await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        serde_json::from_slice::<Value>(&b).unwrap(),
        json!({"error": "approvals come in plan 11"})
    );
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
