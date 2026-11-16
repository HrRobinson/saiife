//! The model forwarder (plan 40, Task 2; spec §7.4, §7.9): a box's
//! `vsock.sock_5002` driven through the real gateway listeners in a
//! tempdir box directory. The upstream is a loopback rustls server with an
//! rcgen certificate for the three model hosts of plan 42 D1, trusted
//! through `Upstream::with_roots`, and its resolver maps exactly those three
//! names to it and records each name asked: no test touches the network,
//! and no VM is ever started. The vault keys are built with `concat!`.
#![cfg(all(unix, feature = "fake-vmm", debug_assertions))]

use bytes::Bytes;
use http::{HeaderMap, Request, Response};
use http_body_util::{BodyExt, Either, Full};
use hyper::body::{Body, Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;
use saiife_audit::{ChainWriter, WriterOptions};
use saiife_boxes::capacity::{self, HostFacts};
use saiife_boxes::guest::fake::FakeGuest;
use saiife_boxes::guest::GuestLink;
use saiife_boxes::manager::{Manager, ManagerInit, SpawnArgs};
use saiife_boxes::store::Store;
use saiife_boxes::template::{self, AgentKind, BoxTemplate, Login, ModelCred, Size};
use saiife_boxes::vmm::fake::FakeVmm;
use saiife_boxes::BoxId;
use saiife_boxhost::paths::BoxPaths;
use saiife_boxhost::vmm::VmHooks;
use saiife_boxproto::ports;
use saiife_broker::pipeline::{LockScope, Lockdown};
use saiife_broker::upstream::{Resolver, Upstream};
use saiife_daemon::box_gateway::model::ModelConfig;
use saiife_daemon::box_gateway::{GatewayConfig, GatewayHooks, Limits, SystemResolve};
use saiife_daemon::box_ops;
use saiife_daemon::ops::{Ctx, CtxInit, Mode};
use saiife_daemon::vault::{self, Entry, Kind, VaultState};
use saiife_daemon::writer::{self, WriterConfig};
use saiife_policy::{Directory, Fsync};
use serde_json::Value;
use std::convert::Infallible;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};
use zeroize::Zeroizing;

const T0: u64 = 1_000_000;
/// The vault's model keys (not token-shaped as a whole literal).
const REAL_KEY: &str = concat!("sk-", "ant-", "api03-", "REALKEY", "0123456789");
const ROTATED_KEY: &str = concat!("sk-", "ant-", "api03-", "ROTATED", "9876543210");
const REAL_SUB: &str = concat!("sk-", "ant-", "oat01-", "REALSUB", "0123456789");
const REAL_OPENAI: &str = concat!("sk-", "proj-", "REALOPENAI", "0123456789");
const REAL_GOOGLE: &str = concat!("AIza", "REALGOOGLE", "0123456789");
/// The three model hosts (plan 42 D1).
const HOSTS: [&str; 3] = [
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
];
/// A marker in request bodies: never in the audit.
const BODY_MARK: &str = "BODYMARK-7f3a";

fn scratch() -> tempfile::TempDir {
    let base = std::env::var_os("SAIIFE_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    std::fs::create_dir_all(&base).unwrap();
    tempfile::Builder::new()
        .prefix("m")
        .tempdir_in(base)
        .unwrap()
}

// ---------------------------------------------------------------- upstream

/// What the upstream saw of one request.
#[derive(Clone)]
struct Seen {
    method: String,
    uri: String,
    headers: HeaderMap,
    body: Bytes,
}

/// A body fed by a channel.
struct Chan(tokio::sync::mpsc::Receiver<Bytes>);

impl Body for Chan {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.0.poll_recv(cx).map(|o| o.map(|b| Ok(Frame::data(b))))
    }
}

type UpBody = Either<Full<Bytes>, Chan>;

#[derive(Clone, Default)]
struct Up {
    seen: Arc<Mutex<Vec<Seen>>>,
    /// TLS connections accepted.
    conns: Arc<AtomicUsize>,
    /// `/forever`'s body could no longer be sent (the connection is gone).
    closed: Arc<AtomicBool>,
    /// When the `sse` behaviour sent its third event.
    third_at: Arc<Mutex<Option<Instant>>>,
    /// Every host name the forwarder asked the resolver for.
    asked: Arc<Mutex<Vec<String>>>,
}

impl Up {
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn asked(&self) -> Vec<String> {
        self.asked.lock().unwrap().clone()
    }
}

fn sse_event(i: usize) -> Bytes {
    Bytes::from(format!("event: ping\ndata: {{\"n\":{i}}}\n\n"))
}

/// The request body that picks the fake upstream's `kind` behaviour.
fn fake(kind: &str) -> String {
    format!(r#"{{"saiife_fake":"{kind}"}}"#)
}

async fn upstream_answer(req: Request<Incoming>, up: Up) -> Result<Response<UpBody>, Infallible> {
    let (parts, body) = req.into_parts();
    let body = body
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    let text = String::from_utf8_lossy(&body).into_owned();
    let stream_asked = text.contains(r#""stream":true"#);
    up.seen.lock().unwrap().push(Seen {
        method: parts.method.to_string(),
        uri: parts.uri.to_string(),
        headers: parts.headers.clone(),
        body,
    });
    let full = |code: u16, text: &str| {
        Response::builder()
            .status(code)
            .header("content-type", "application/json")
            .header("set-cookie", "upstream=1; Path=/")
            .header("x-upstream", "yes")
            .body(Either::Left(Full::new(Bytes::from(text.to_string()))))
            .unwrap()
    };
    let stream = |rx| {
        Response::builder()
            .status(200)
            .header("content-type", "text/event-stream")
            .body(Either::Right(Chan(rx)))
            .unwrap()
    };
    let path = parts.uri.path().to_string();
    // The test behaviours are picked by the request body on
    // `POST /v1/messages` ([`fake`]; plan 42 R12: only exact paths pass).
    // Codex's streamed Responses call and Gemini's streamed call answer
    // with the same three events as `sse`.
    let streamed = (path == "/v1/responses" && stream_asked)
        || path == "/v1beta/models/m:streamGenerateContent";
    let kind = if streamed {
        "sse"
    } else if path == "/v1/messages" {
        ["sse", "forever", "stall", "nohead"]
            .into_iter()
            .find(|k| text == fake(k))
            .unwrap_or("")
    } else {
        ""
    };
    Ok(match kind {
        "sse" => {
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            let third = Arc::clone(&up.third_at);
            tokio::spawn(async move {
                for i in 0..3 {
                    if i > 0 {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                    }
                    if i == 2 {
                        *third.lock().unwrap() = Some(Instant::now());
                    }
                    if tx.send(sse_event(i)).await.is_err() {
                        return;
                    }
                }
            });
            stream(rx)
        }
        "forever" => {
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            let closed = Arc::clone(&up.closed);
            tokio::spawn(async move {
                for i in 0.. {
                    if tx.send(sse_event(i)).await.is_err() {
                        closed.store(true, Ordering::SeqCst);
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            });
            stream(rx)
        }
        "stall" => {
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            tokio::spawn(async move {
                let _ = tx.send(sse_event(0)).await;
                // Then nothing, for far longer than the test's idle limit.
                tokio::time::sleep(Duration::from_secs(60)).await;
                drop(tx);
            });
            stream(rx)
        }
        "nohead" => {
            // No answer at all, far longer than the test's idle limit.
            tokio::time::sleep(Duration::from_secs(30)).await;
            full(200, "{}")
        }
        _ => full(200, r#"{"type":"message","ok":true}"#),
    })
}

/// The fake model hosts and the client that trusts them. With `dead`, the
/// resolver points at a port nothing listens on.
async fn upstream(dead: bool) -> (Up, Upstream) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(HOSTS.iter().map(|h| h.to_string()).collect::<Vec<_>>())
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
    let up = Up::default();
    let u2 = up.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let u = u2.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                u.conns.fetch_add(1, Ordering::SeqCst);
                let svc = service_fn(move |req| upstream_answer(req, u.clone()));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let port = if dead {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        l.local_addr().unwrap().port()
    } else {
        port
    };
    let client = Upstream::with_roots(
        roots,
        Arc::new(OnlyModelHosts {
            port,
            asked: Arc::clone(&up.asked),
        }),
        Duration::from_secs(30),
    );
    (up, client)
}

/// The three model hosts are the loopback upstream; every other name
/// fails. Every name asked is recorded.
struct OnlyModelHosts {
    port: u16,
    asked: Arc<Mutex<Vec<String>>>,
}

impl Resolver for OnlyModelHosts {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        self.asked.lock().unwrap().push(host.to_string());
        assert_eq!(port, 443, "the forwarder asks for the fixed port");
        if HOSTS.contains(&host) {
            Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, self.port))])
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "unknown test host"))
        }
    }
}

// ---------------------------------------------------------------- world

struct W {
    ctx: Arc<Ctx>,
    _gw: Arc<GatewayHooks>,
    /// An api-key box, a second one, and a subscription box.
    a: Bx,
    b: Bx,
    sub: Bx,
    up: Up,
    clock: Arc<AtomicU64>,
    audit: PathBuf,
    _tmp: tempfile::TempDir,
}

struct Bx {
    id: BoxId,
    session: String,
    paths: BoxPaths,
    placeholder: String,
}

struct Opts {
    model: ModelConfig,
    /// The agent of boxes `a` and `b` (plan 42); `sub` is always Claude's.
    agent: AgentKind,
    /// Boxes `a` and `b` are spawned as `agent`, then their template is
    /// edited to this agent (as a template switched after spawn).
    switch_to: Option<AgentKind>,
    /// The services of `agent`'s vault entry ([`cred_name`]); `None`: no
    /// such entry.
    services: Option<Vec<&'static str>>,
    /// The upstream cannot be reached (connection refused).
    dead_upstream: bool,
    /// The gateway's debug-only C4 override: the forwarder serves the
    /// subscription box (the constant itself stays false).
    subscription_cleared: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            model: ModelConfig::default(),
            agent: AgentKind::ClaudeCode,
            switch_to: None,
            services: Some(vec!["box-model"]),
            dead_upstream: false,
            subscription_cleared: true,
        }
    }
}

impl Opts {
    /// Boxes `a` and `b` of `agent`, its key allowing the route's service.
    fn agent(agent: AgentKind) -> Opts {
        let services = match agent {
            AgentKind::ClaudeCode => vec!["box-model"],
            AgentKind::Codex => vec!["box-model-openai"],
            AgentKind::Gemini => vec!["box-model-google"],
        };
        Opts {
            agent,
            services: Some(services),
            ..Opts::default()
        }
    }
}

/// The vault entry name of `agent`'s templates (plan 42 D7).
fn cred_name(agent: AgentKind) -> &'static str {
    match agent {
        AgentKind::ClaudeCode => "anthropic",
        AgentKind::Codex => "openai",
        AgentKind::Gemini => "gemini",
    }
}

/// The real key in `agent`'s vault entry.
fn real_key(agent: AgentKind) -> &'static str {
    match agent {
        AgentKind::ClaudeCode => REAL_KEY,
        AgentKind::Codex => REAL_OPENAI,
        AgentKind::Gemini => REAL_GOOGLE,
    }
}

fn host_facts() -> HostFacts {
    HostFacts {
        mem_total_mib: 8192 + 3 * capacity::charge_mib(&Size::default()),
        mem_avail_mib: 4096,
        threads: 12,
        disk_free_mib: 1024 * 1024,
        cpu_pct: None,
    }
}

fn tmpl(name: &str, login: Login, credential: &str) -> BoxTemplate {
    tmpl_of(AgentKind::ClaudeCode, name, login, credential)
}

fn tmpl_of(agent: AgentKind, name: &str, login: Login, credential: &str) -> BoxTemplate {
    let mut t = template::builtin()
        .into_iter()
        .find(|t| t.agent == agent)
        .unwrap();
    t.name = name.into();
    t.login = login;
    t.credential = credential.into();
    t
}

fn manager(state: &std::path::Path, templates: Vec<BoxTemplate>) -> Manager {
    let host = host_facts();
    let guest: Arc<dyn GuestLink> = Arc::new(FakeGuest::new());
    Manager::open(ManagerInit {
        store: Store::open(box_ops::dir_in(state)).unwrap(),
        vmm: Arc::new(FakeVmm::new()),
        guest,
        templates,
        host: Arc::new(move || host),
        clock: Arc::new(|| T0),
        disk_place: box_ops::disk_place(),
    })
    .unwrap()
    .manager
}

fn vault_entry(name: &str, value: &str, services: &[&str]) -> Entry {
    Entry {
        name: name.into(),
        kind: Kind::Token,
        fields: [("token".to_string(), Zeroizing::new(value.to_string()))].into(),
        allowed_services: services.iter().map(|s| s.to_string()).collect(),
        created_by: 0,
        created: "2026-11-16T00:00:00Z".into(),
        last_used: None,
        rotate_after: None,
    }
}

async fn world(o: Opts) -> W {
    let tmp = scratch();
    let audit = tmp.path().join("audit");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&audit).unwrap();
    std::fs::create_dir_all(&state).unwrap();
    let cw = ChainWriter::open(
        &audit,
        WriterOptions {
            mode: "locked".into(),
            saiife: "test".into(),
            key: None,
        },
    )
    .unwrap();
    let cfg = WriterConfig {
        checkpoint_every: 1000,
        checkpoint_interval: Duration::from_secs(900),
        fsync: Fsync::Always,
    };
    let (handle, _join) = writer::spawn(cw, cfg, None).unwrap();
    let dirs: Arc<dyn Directory + Send + Sync> = Arc::new(
        saiife_policy::FixedDirectory::from_text("saiife:x:999:999::/var/lib/saiife:/bin/sh\n", ""),
    );

    // Spawn refuses subscription login (C4): the boxes are spawned with an
    // api-key "model-sub", then the manager is opened again over the same
    // store with "model-sub" as a subscription template, as a template
    // edited after spawn would be. The const stays false: the forwarder
    // serves this box only through the gateway's debug-only test override
    // (`Opts::subscription_cleared`).
    let spawn_api = tmpl_of(o.agent, "model-api", Login::ApiKey, cred_name(o.agent));
    let spawn_cred = spawn_api.model_cred();
    let now = o.switch_to.unwrap_or(o.agent);
    let spawn_templates = vec![spawn_api, tmpl("model-sub", Login::ApiKey, "anthropic-sub")];
    let first = manager(&state, spawn_templates);
    let spawn = |t: &str| {
        first
            .spawn(&SpawnArgs {
                template: t.into(),
                repo: "shop".into(),
                repo_dir: None,
                task: String::new(),
                start: saiife_wire::source::Start::Queue,
                owner_uid: 2000,
                repo_image: None,
                base_manifest: None,
            })
            .unwrap()
    };
    let (ra, rb, rs) = (spawn("model-api"), spawn("model-api"), spawn("model-sub"));
    drop(first);
    let mgr = manager(
        &state,
        vec![
            tmpl_of(now, "model-api", Login::ApiKey, cred_name(now)),
            tmpl("model-sub", Login::Subscription, "anthropic-sub"),
        ],
    );
    let root = mgr.root().to_path_buf();
    let ph = |id: &BoxId, login| {
        saiife_boxhost::placeholder::read_or_make_placeholder(
            &saiife_boxhost::paths::RecordPaths::of(&root, id),
            login,
        )
        .unwrap()
    };
    let (pa, pb, ps) = (
        ph(&ra.id, spawn_cred),
        ph(&rb.id, spawn_cred),
        ph(&rs.id, ModelCred::AnthropicSubscription),
    );

    let key_file = tmp.path().join("vault-key");
    std::fs::write(&key_file, [7u8; 32]).unwrap();
    std::fs::set_permissions(
        &key_file,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
    )
    .unwrap();
    let mut vault = vault::open(&key_file, &state.join("vault").join("vault.bin"));
    let VaultState::Ready(v) = &mut vault else {
        panic!("vault not ready");
    };
    if let Some(services) = &o.services {
        v.put(vault_entry(cred_name(o.agent), real_key(o.agent), services))
            .unwrap();
    }
    v.put(vault_entry("anthropic-sub", REAL_SUB, &["box-model"]))
        .unwrap();

    let (up, client) = upstream(o.dead_upstream).await;
    let base = CtxInit::minimal(handle, cfg, dirs, &state);
    let ctx = Arc::new(Ctx::new(CtxInit {
        audit_dir: audit.clone(),
        own_user: "saiife".into(),
        own_uid: 999,
        mode: Mode::Locked,
        box_manager: Some(Arc::new(mgr)),
        vault,
        upstream: Ok(client),
        ..base
    }));
    let clock = Arc::new(AtomicU64::new(T0));
    let c = Arc::clone(&clock);
    let gw = GatewayHooks::new(
        Arc::clone(&ctx),
        tokio::runtime::Handle::current(),
        Arc::new(SystemResolve::new()),
        GatewayConfig {
            limits: Limits::default(),
            allow_loopback_for_tests: true,
            subscription_cleared_for_tests: o.subscription_cleared,
            clock: Arc::new(move || c.load(Ordering::SeqCst)),
            model: o.model,
        },
    );
    let mut boxes = Vec::new();
    for (i, (rec, placeholder)) in [(ra, pa), (rb, pb), (rs, ps)].into_iter().enumerate() {
        let dir = tmp.path().join(format!("run{i}"));
        std::fs::create_dir(&dir).unwrap();
        let paths = BoxPaths::new(dir);
        gw.before_boot(&rec.id, &paths).unwrap();
        boxes.push(Bx {
            id: rec.id,
            session: rec.session,
            paths,
            placeholder,
        });
    }
    let sub = boxes.pop().unwrap();
    let b = boxes.pop().unwrap();
    let a = boxes.pop().unwrap();
    W {
        ctx,
        _gw: gw,
        a,
        b,
        sub,
        up,
        clock,
        audit,
        _tmp: tmp,
    }
}

// ---------------------------------------------------------------- box side

type Sender = hyper::client::conn::http1::SendRequest<Full<Bytes>>;

/// A keep-alive HTTP/1.1 client on the box's model port.
async fn client(b: &Bx) -> (Sender, tokio::task::JoinHandle<()>) {
    let s = UnixStream::connect(b.paths.vsock_port(ports::MODEL))
        .await
        .unwrap();
    let (tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(s))
        .await
        .unwrap();
    let task = tokio::spawn(async move {
        let _ = conn.await;
    });
    (tx, task)
}

fn post(path: &str, headers: &[(&str, &str)], body: &str) -> Request<Full<Bytes>> {
    let mut r = Request::builder().method("POST").uri(path);
    for (k, v) in headers {
        r = r.header(*k, *v);
    }
    r.body(Full::new(Bytes::from(body.to_string()))).unwrap()
}

fn messages_body() -> String {
    format!(r#"{{"model":"m","max_tokens":1,"messages":[],"note":"{BODY_MARK}"}}"#)
}

/// One request on a fresh connection: (status, headers, body).
async fn ask(b: &Bx, req: Request<Full<Bytes>>) -> (u16, HeaderMap, String) {
    let (mut tx, _task) = client(b).await;
    send(&mut tx, req).await
}

async fn send(tx: &mut Sender, req: Request<Full<Bytes>>) -> (u16, HeaderMap, String) {
    let resp = tokio::time::timeout(Duration::from_secs(15), tx.send_request(req))
        .await
        .expect("an answer in time")
        .expect("an answer");
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = tokio::time::timeout(Duration::from_secs(15), resp.into_body().collect())
        .await
        .expect("the body in time")
        .map(|c| String::from_utf8_lossy(&c.to_bytes()).into_owned())
        .unwrap_or_default();
    (status, headers, body)
}

/// The api-key box's normal request.
fn api_req(b: &Bx) -> Request<Full<Bytes>> {
    post(
        "/v1/messages?beta=true",
        &[
            ("x-api-key", &b.placeholder),
            ("anthropic-version", "2023-06-01"),
            ("content-type", "application/json"),
        ],
        &messages_body(),
    )
}

/// Bytes by hand (for targets a client would not send); the whole answer.
async fn raw(b: &Bx, bytes: &[u8]) -> (u16, String) {
    let mut s = UnixStream::connect(b.paths.vsock_port(ports::MODEL))
        .await
        .unwrap();
    let _ = s.write_all(bytes).await;
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(15), async {
        let mut buf = [0u8; 4096];
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
    })
    .await;
    let t = String::from_utf8_lossy(&out).into_owned();
    let code = t
        .strip_prefix("HTTP/1.1 ")
        .and_then(|r| r.get(..3))
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("no status in {t:?}"));
    (code, t)
}

impl W {
    fn all_records(&self) -> Vec<Value> {
        let mut files: Vec<_> = std::fs::read_dir(&self.audit)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
            .collect();
        files.sort();
        files
            .iter()
            .flat_map(|f| {
                std::fs::read_to_string(f)
                    .unwrap()
                    .lines()
                    .filter_map(|l| serde_json::from_str::<Value>(l).ok())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    fn audit_text(&self) -> String {
        std::fs::read_dir(&self.audit)
            .unwrap()
            .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap_or_default())
            .collect()
    }

    fn records(&self, kind: &str) -> Vec<Value> {
        self.all_records()
            .into_iter()
            .filter(|r| r["kind"] == kind)
            .collect()
    }

    async fn wait_records(&self, kind: &str, n: usize) -> Vec<Value> {
        let t0 = Instant::now();
        loop {
            let r = self.records(kind);
            if r.len() >= n || t0.elapsed() > Duration::from_secs(10) {
                return r;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn lockdown(&self) {
        self.ctx
            .lockdown
            .set(Some(Lockdown {
                scope: LockScope::Connectors,
                reason: "test".into(),
                by_uid: 0,
                since: "2026-11-16T00:00:00.000Z".into(),
            }))
            .unwrap();
    }

    fn rotate(&self, value: &str) {
        self.ctx
            .vault
            .writer()
            .put(vault_entry("anthropic", value, &["box-model"]))
            .unwrap();
    }
}

fn has(h: &HeaderMap, needle: &str) -> bool {
    h.iter().any(|(k, v)| {
        k.as_str().contains(needle) || String::from_utf8_lossy(v.as_bytes()).contains(needle)
    })
}

const NOT_VALID: &str = "this box's model credential is not valid";

// ---------------------------------------------------------------- tests

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_key_swap() {
    let w = world(Opts::default()).await;
    let (code, h, body) = ask(&w.a, api_req(&w.a)).await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(body, r#"{"type":"message","ok":true}"#);
    assert_eq!(h["x-upstream"], "yes");
    let seen = w.up.seen();
    assert_eq!(seen.len(), 1);
    let s = &seen[0];
    assert_eq!(s.method, "POST");
    assert_eq!(s.uri, "/v1/messages?beta=true");
    assert_eq!(s.headers["x-api-key"], REAL_KEY);
    assert_eq!(s.headers.get_all("x-api-key").iter().count(), 1);
    assert_eq!(s.headers["anthropic-version"], "2023-06-01");
    assert!(s.headers.get("authorization").is_none());
    assert!(!has(&s.headers, &w.a.placeholder));
    // The body is never touched.
    assert_eq!(s.body, Bytes::from(messages_body()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_key_body_with_the_placeholder_is_passed_unchanged() {
    let w = world(Opts::default()).await;
    let text = format!(r#"{{"say":"{}"}}"#, w.a.placeholder);
    let req = post("/v1/messages", &[("x-api-key", &w.a.placeholder)], &text);
    assert_eq!(ask(&w.a, req).await.0, 200);
    assert_eq!(w.up.seen()[0].body, Bytes::from(text));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscription_swap() {
    let w = world(Opts::default()).await;
    let bearer = format!("Bearer {}", w.sub.placeholder);
    let req = post(
        "/v1/messages",
        &[
            ("authorization", &bearer),
            ("anthropic-beta", "oauth-2025-04-20"),
        ],
        &messages_body(),
    );
    let (code, _, body) = ask(&w.sub, req).await;
    assert_eq!(code, 200, "{body}");
    let s = &w.up.seen()[0];
    assert_eq!(s.headers["authorization"], format!("Bearer {REAL_SUB}"));
    assert_eq!(s.headers.get_all("authorization").iter().count(), 1);
    assert!(s.headers.get("x-api-key").is_none());
    assert_eq!(s.headers["anthropic-beta"], "oauth-2025-04-20");
    assert!(!has(&s.headers, &w.sub.placeholder));
    let recs = w.wait_records("model", 1).await;
    assert_eq!(recs[0]["login"], "subscription");
}

/// C4 beyond spawn: with the gate closed (the constant, no test override),
/// a box whose template was edited to subscription after spawn gets a fixed
/// 403 for its own valid placeholder, nothing reaches the upstream, and the
/// `model_denied` records are rate-limited.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscription_is_refused_by_the_forwarder() {
    if saiife_boxes::template::SUBSCRIPTION_LOGIN_CLEARED {
        return; // the owner opened the gate: nothing is refused
    }
    let w = world(Opts {
        subscription_cleared: false,
        ..Opts::default()
    })
    .await;
    let bearer = format!("Bearer {}", w.sub.placeholder);
    for _ in 0..3 {
        let req = post(
            "/v1/messages",
            &[("authorization", &bearer)],
            &messages_body(),
        );
        let (code, _, body) = ask(&w.sub, req).await;
        assert_eq!(code, 403, "{body}");
        assert_eq!(body.trim(), saiife_boxes::template::SUBSCRIPTION_GATED);
        assert!(!body.contains(&w.sub.placeholder));
    }
    assert!(w.up.seen().is_empty(), "nothing was forwarded");
    let recs = w.wait_records("model_denied", 1).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(w.records("model_denied").len(), 1, "{recs:?}");
    assert_eq!(recs[0]["reason"], "subscription_gated");
    assert_eq!(recs[0]["box"], w.sub.id.as_str());
    assert!(w.records("model").is_empty());
    // The api-key box is unaffected.
    assert_eq!(ask(&w.a, api_req(&w.a)).await.0, 200);
}

/// C4 beyond spawn: the setup of a box whose template was edited to
/// subscription after spawn is refused with the spawn's message, and its
/// placeholder file is left as it was (no OAuth placeholder is made).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscription_setup_is_refused() {
    use saiife_boxhost::guest::SetupSource;
    use saiife_daemon::box_setup::TemplateSetup;
    if saiife_boxes::template::SUBSCRIPTION_LOGIN_CLEARED {
        return; // the owner opened the gate: nothing is refused
    }
    let w = world(Opts::default()).await;
    let mgr = w.ctx.box_manager.as_ref().unwrap();
    let file = saiife_boxhost::paths::RecordPaths::of(mgr.root(), &w.sub.id).placeholder();
    let before = std::fs::read(&file).unwrap();
    let setups = TemplateSetup::new(w._tmp.path().join("packs"));
    setups.attach(mgr);
    assert_eq!(
        setups.setup_for(&w.sub.id).unwrap_err(),
        saiife_boxes::template::SUBSCRIPTION_GATED
    );
    assert_eq!(std::fs::read(&file).unwrap(), before);
    // An api-key box of the same manager still sets up.
    assert!(setups.setup_for(&w.a.id).is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_placeholder_is_401() {
    let w = world(Opts::default()).await;
    let req = post("/v1/messages", &[], &messages_body());
    let (code, _, body) = ask(&w.a, req).await;
    assert_eq!(code, 401);
    assert_eq!(body.trim(), NOT_VALID);
    assert!(w.up.seen().is_empty());
    let recs = w.wait_records("model_denied", 1).await;
    assert_eq!(recs[0]["reason"], "bad_credential");
    assert_eq!(recs[0]["box"], w.a.id.as_str());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn other_box_placeholder_is_401() {
    let w = world(Opts::default()).await;
    let req = post("/v1/messages", &[("x-api-key", &w.b.placeholder)], "{}");
    assert_eq!(ask(&w.a, req).await.0, 401);
    // The subscription box's placeholder on an api-key box, in either header.
    let req = post("/v1/messages", &[("x-api-key", &w.sub.placeholder)], "{}");
    assert_eq!(ask(&w.a, req).await.0, 401);
    // A prefix of the right one.
    let short = &w.a.placeholder[..w.a.placeholder.len() - 1];
    let req = post("/v1/messages", &[("x-api-key", short)], "{}");
    assert_eq!(ask(&w.a, req).await.0, 401);
    assert!(w.up.seen().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_header_is_401() {
    let w = world(Opts::default()).await;
    let bearer = format!("Bearer {}", w.a.placeholder);
    // api-key box: the placeholder as a bearer token.
    let req = post("/v1/messages", &[("authorization", &bearer)], "{}");
    assert_eq!(ask(&w.a, req).await.0, 401);
    // Subscription box: the placeholder as an API key.
    let req = post("/v1/messages", &[("x-api-key", &w.sub.placeholder)], "{}");
    assert_eq!(ask(&w.sub, req).await.0, 401);
    // Subscription box: no "Bearer ".
    let req = post(
        "/v1/messages",
        &[("authorization", &w.sub.placeholder)],
        "{}",
    );
    assert_eq!(ask(&w.sub, req).await.0, 401);
    // The right header, and the placeholder in another one too.
    let req = post(
        "/v1/messages",
        &[
            ("x-api-key", &w.a.placeholder),
            ("x-other", &w.a.placeholder),
        ],
        "{}",
    );
    assert_eq!(ask(&w.a, req).await.0, 401);
    // Two x-api-key headers.
    let req = post(
        "/v1/messages",
        &[
            ("x-api-key", &w.a.placeholder),
            ("x-api-key", &w.a.placeholder),
        ],
        "{}",
    );
    assert_eq!(ask(&w.a, req).await.0, 401);
    assert!(w.up.seen().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn absolute_target_is_400() {
    let w = world(Opts::default()).await;
    let req = format!(
        "POST http://evil.test/v1/messages HTTP/1.1\r\nHost: evil.test\r\nx-api-key: {}\r\n\
         Content-Length: 2\r\n\r\n{{}}",
        w.a.placeholder
    );
    let (code, t) = raw(&w.a, req.as_bytes()).await;
    assert_eq!(code, 400, "{t}");
    let req = format!(
        "GET https://api.anthropic.com/v1/models HTTP/1.1\r\nHost: api.anthropic.com\r\n\
         x-api-key: {}\r\n\r\n",
        w.a.placeholder
    );
    assert_eq!(raw(&w.a, req.as_bytes()).await.0, 400);
    assert!(w.up.seen().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_header_is_replaced() {
    let w = world(Opts::default()).await;
    let req = post(
        "/v1/messages",
        &[("x-api-key", &w.a.placeholder), ("host", "evil.test:8443")],
        "{}",
    );
    assert_eq!(ask(&w.a, req).await.0, 200);
    let s = &w.up.seen()[0];
    assert_eq!(s.headers["host"], "api.anthropic.com");
    assert_eq!(s.headers.get_all("host").iter().count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_and_upgrade_are_refused() {
    let w = world(Opts::default()).await;
    let (code, t) = raw(
        &w.a,
        format!(
            "CONNECT evil.test:443 HTTP/1.1\r\nHost: evil.test:443\r\nx-api-key: {}\r\n\r\n",
            w.a.placeholder
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(code, 405, "{t}");
    for m in ["PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"] {
        let req = Request::builder()
            .method(m)
            .uri("/v1/messages")
            .header("x-api-key", &w.a.placeholder)
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert_eq!(ask(&w.a, req).await.0, 405, "{m}");
    }
    let req = Request::builder()
        .method("GET")
        .uri("/v1/messages")
        .header("x-api-key", &w.a.placeholder)
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .body(Full::new(Bytes::new()))
        .unwrap();
    assert_eq!(ask(&w.a, req).await.0, 400);
    assert!(w.up.seen().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cookies_and_forwarded_are_stripped() {
    let w = world(Opts::default()).await;
    let req = post(
        "/v1/messages",
        &[
            ("x-api-key", &w.a.placeholder),
            ("cookie", "session=box"),
            ("forwarded", "for=10.0.0.1"),
            ("x-forwarded-for", "10.0.0.1"),
            ("x-forwarded-host", "evil.test"),
            ("proxy-authorization", "Basic Ym94OmJveA=="),
            ("authorization", "Bearer whatever"),
            ("connection", "x-hop"),
            ("x-hop", "1"),
            ("keep-alive", "timeout=5"),
            ("te", "trailers"),
            ("proxy-connection", "keep-alive"),
            ("anthropic-version", "2023-06-01"),
            ("user-agent", "claude-cli/1"),
        ],
        "{}",
    );
    assert_eq!(ask(&w.a, req).await.0, 200);
    let s = &w.up.seen()[0];
    for gone in [
        "cookie",
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "proxy-authorization",
        "authorization",
        "x-hop",
        "keep-alive",
        "te",
        "proxy-connection",
    ] {
        assert!(s.headers.get(gone).is_none(), "{gone} reached the upstream");
    }
    assert_eq!(s.headers["anthropic-version"], "2023-06-01");
    assert_eq!(s.headers["user-agent"], "claude-cli/1");
    assert_eq!(s.headers["x-api-key"], REAL_KEY);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_cookie_is_stripped() {
    let w = world(Opts::default()).await;
    let (code, h, _) = ask(&w.a, api_req(&w.a)).await;
    assert_eq!(code, 200);
    assert!(h.get("set-cookie").is_none());
    assert_eq!(h["x-upstream"], "yes");
    assert_eq!(h["content-type"], "application/json");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn body_cap_is_413() {
    let w = world(Opts {
        model: ModelConfig {
            body_max: 1024,
            ..ModelConfig::default()
        },
        ..Opts::default()
    })
    .await;
    // Declared too large: refused before any of it is read.
    let big = "x".repeat(2000);
    let req = post("/v1/messages", &[("x-api-key", &w.a.placeholder)], &big);
    assert_eq!(ask(&w.a, req).await.0, 413);
    assert!(w.up.seen().is_empty());
    // Chunked, no length: refused once the cap is passed.
    let head = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: x\r\nx-api-key: {}\r\n\
         Transfer-Encoding: chunked\r\n\r\n",
        w.a.placeholder
    );
    let mut bytes = head.into_bytes();
    for _ in 0..4 {
        bytes.extend_from_slice(format!("200\r\n{}\r\n", "y".repeat(512)).as_bytes());
    }
    bytes.extend_from_slice(b"0\r\n\r\n");
    let (code, t) = raw(&w.a, &bytes).await;
    assert_eq!(code, 413, "{t}");
    // At the cap is fine.
    let ok = "z".repeat(1024);
    let req = post("/v1/messages", &[("x-api-key", &w.a.placeholder)], &ok);
    assert_eq!(ask(&w.a, req).await.0, 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_events_arrive_incrementally() {
    let w = world(Opts::default()).await;
    let (mut tx, _task) = client(&w.a).await;
    let req = post(
        "/v1/messages",
        &[("x-api-key", &w.a.placeholder)],
        &fake("sse"),
    );
    let resp = tokio::time::timeout(Duration::from_secs(15), tx.send_request(req))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resp.status(), 200);
    let mut body = resp.into_body();
    let first = tokio::time::timeout(Duration::from_secs(15), body.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let first_at = Instant::now();
    assert_eq!(first.into_data().unwrap(), sse_event(0));
    let mut rest = Vec::new();
    while let Some(f) = tokio::time::timeout(Duration::from_secs(15), body.frame())
        .await
        .unwrap()
    {
        if let Ok(d) = f.unwrap().into_data() {
            rest.extend_from_slice(&d);
        }
    }
    let mut want = Vec::new();
    want.extend_from_slice(&sse_event(1));
    want.extend_from_slice(&sse_event(2));
    assert_eq!(rest, want);
    let third_at =
        w.up.third_at
            .lock()
            .unwrap()
            .expect("the third event was sent");
    assert!(
        first_at < third_at,
        "the first event arrived only after the upstream sent the third"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_disconnect_closes_upstream() {
    let w = world(Opts::default()).await;
    let (mut tx, task) = client(&w.a).await;
    let req = post(
        "/v1/messages",
        &[("x-api-key", &w.a.placeholder)],
        &fake("forever"),
    );
    let resp = tokio::time::timeout(Duration::from_secs(15), tx.send_request(req))
        .await
        .unwrap()
        .unwrap();
    let mut body = resp.into_body();
    let _ = tokio::time::timeout(Duration::from_secs(15), body.frame())
        .await
        .unwrap();
    // The box goes away mid-stream.
    drop(body);
    drop(tx);
    task.abort();
    let _ = task.await;
    let t0 = Instant::now();
    while !w.up.closed.load(Ordering::SeqCst) {
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "the upstream stream was not closed"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let recs = w.wait_records("model", 1).await;
    assert_eq!(recs[0]["outcome"], "client_closed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_upstream_times_out() {
    let w = world(Opts {
        model: ModelConfig {
            idle_secs: 1,
            ..ModelConfig::default()
        },
        ..Opts::default()
    })
    .await;
    let (mut tx, _task) = client(&w.a).await;
    let req = post(
        "/v1/messages",
        &[("x-api-key", &w.a.placeholder)],
        &fake("stall"),
    );
    let t0 = Instant::now();
    let resp = tokio::time::timeout(Duration::from_secs(15), tx.send_request(req))
        .await
        .unwrap()
        .unwrap();
    let mut body = resp.into_body();
    let first = body.frame().await.unwrap().unwrap();
    assert_eq!(first.into_data().unwrap(), sse_event(0));
    // The stall ends the response with an error, not a clean end.
    let next = tokio::time::timeout(Duration::from_secs(15), body.frame())
        .await
        .unwrap();
    assert!(
        matches!(next, Some(Err(_))),
        "the cut looked like a clean end"
    );
    assert!(t0.elapsed() < Duration::from_secs(10), "{:?}", t0.elapsed());
    let recs = w.wait_records("model", 1).await;
    assert_eq!(recs[0]["outcome"], "idle");
    assert_eq!(recs[0]["bytes_down"], sse_event(0).len() as u64);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn errors_never_echo_credentials() {
    let w = world(Opts {
        model: ModelConfig {
            body_max: 64,
            ..ModelConfig::default()
        },
        ..Opts::default()
    })
    .await;
    let mut bodies = Vec::new();
    let pa = &w.a.placeholder;
    let bearer = format!("Bearer {pa}");
    for req in [
        post("/v1/messages", &[("x-api-key", &w.b.placeholder)], "{}"),
        post("/v1/messages", &[("authorization", &bearer)], "{}"),
        post("/v1/messages", &[("x-api-key", pa), ("x-other", pa)], "{}"),
        post("/v1/messages", &[("x-api-key", pa)], &"q".repeat(100)),
        post(
            "/v1/messages",
            &[
                ("x-api-key", pa),
                ("upgrade", "h2c"),
                ("connection", "upgrade"),
            ],
            "{}",
        ),
    ] {
        let (code, h, body) = ask(&w.a, req).await;
        assert!(code >= 400, "{code}");
        bodies.push(format!("{h:?}{body}"));
    }
    let raw_put = format!("PUT /v1/messages HTTP/1.1\r\nHost: x\r\nx-api-key: {pa}\r\n\r\n");
    bodies.push(raw(&w.a, raw_put.as_bytes()).await.1);
    let raw_abs = format!("GET http://{pa}/ HTTP/1.1\r\nHost: {pa}\r\nx-api-key: {pa}\r\n\r\n");
    bodies.push(raw(&w.a, raw_abs.as_bytes()).await.1);
    // Lockdown, and a vault without the secret.
    w.lockdown();
    bodies.push(ask(&w.a, api_req(&w.a)).await.2);
    w.ctx.lockdown.set(None).unwrap();
    w.ctx.vault.writer().remove("anthropic").unwrap();
    let req = post("/v1/messages", &[("x-api-key", pa)], "{}");
    let (code, _, b) = ask(&w.a, req).await;
    assert_eq!(code, 503);
    bodies.push(b);
    for b in &bodies {
        for secret in [
            pa.as_str(),
            &w.b.placeholder,
            &w.sub.placeholder,
            REAL_KEY,
            REAL_SUB,
        ] {
            assert!(
                !b.contains(secret),
                "an error answer quoted a credential: {b}"
            );
        }
    }
    let audit = w.audit_text();
    for secret in [pa.as_str(), &w.b.placeholder, REAL_KEY, REAL_SUB, BODY_MARK] {
        assert!(!audit.contains(secret), "the audit holds {secret}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_secret_is_503() {
    let w = world(Opts {
        services: None,
        ..Opts::default()
    })
    .await;
    let (code, _, body) = ask(&w.a, api_req(&w.a)).await;
    assert_eq!(code, 503);
    assert_eq!(
        body.trim(),
        "the vault has no secret anthropic for box-model-anthropic: \
         saiife secret add anthropic --kind token --service box-model-anthropic"
    );
    assert!(w.up.seen().is_empty());
    let recs = w.wait_records("model_denied", 1).await;
    assert_eq!(recs[0]["reason"], "secret_missing");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secret_without_box_model_service_is_503() {
    let w = world(Opts {
        services: Some(vec!["github"]),
        ..Opts::default()
    })
    .await;
    let (code, _, body) = ask(&w.a, api_req(&w.a)).await;
    assert_eq!(code, 503);
    assert!(
        body.contains("saiife secret add anthropic --kind token --service box-model-anthropic"),
        "{body}"
    );
    assert!(w.up.seen().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotated_key_applies_next_request() {
    let w = world(Opts::default()).await;
    let (mut tx, _task) = client(&w.a).await;
    assert_eq!(send(&mut tx, api_req(&w.a)).await.0, 200);
    w.rotate(ROTATED_KEY);
    assert_eq!(send(&mut tx, api_req(&w.a)).await.0, 200);
    let seen = w.up.seen();
    assert_eq!(seen[0].headers["x-api-key"], REAL_KEY);
    assert_eq!(seen[1].headers["x-api-key"], ROTATED_KEY);
    // Both on the one keep-alive connection, and one upstream connection.
    assert_eq!(w.up.conns.load(Ordering::SeqCst), 1);
}

/// Every model audit line parses back as a `saiife_audit::Record` and
/// carries each key once (`session` and `reason` are top-level record
/// fields; the flattened extras must not repeat them).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn model_records_carry_each_key_once() {
    let w = world(Opts::default()).await;
    assert_eq!(ask(&w.a, api_req(&w.a)).await.0, 200);
    w.wait_records("model", 1).await;
    // A refused request writes a `model_denied` record (reason is top-level).
    let req = post("/v1/messages", &[], &messages_body());
    assert_eq!(ask(&w.a, req).await.0, 401);
    w.wait_records("model_denied", 1).await;
    let read = saiife_audit::store::read_all(&w.audit);
    assert_eq!(read.skipped_lines, 0, "an audit line did not parse");
    for kind in ["model", "model_denied"] {
        let lines: Vec<String> = std::fs::read_dir(&w.audit)
            .unwrap()
            .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap_or_default())
            .flat_map(|t| t.lines().map(String::from).collect::<Vec<_>>())
            .filter(|l| l.contains(&format!("\"kind\":\"{kind}\"")))
            .collect();
        assert!(!lines.is_empty(), "no {kind} line");
        for l in lines {
            assert_eq!(l.matches("\"session\":").count(), 1, "{l}");
            assert_eq!(l.matches("\"reason\":").count(), 1, "{l}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn records_per_request() {
    let w = world(Opts::default()).await;
    let (mut tx, _task) = client(&w.a).await;
    assert_eq!(send(&mut tx, api_req(&w.a)).await.0, 200);
    let req = Request::builder()
        .method("GET")
        .uri("/v1/models?limit=5")
        .header("x-api-key", &w.a.placeholder)
        .body(Full::new(Bytes::new()))
        .unwrap();
    assert_eq!(send(&mut tx, req).await.0, 200);
    let recs = w.wait_records("model", 2).await;
    assert_eq!(recs.len(), 2, "{recs:?}");
    let r = &recs[0];
    assert_eq!(r["box"], w.a.id.as_str());
    assert_eq!(r["session"], w.a.session.as_str());
    assert_eq!(r["method"], "POST");
    assert_eq!(r["path"], "/v1/messages");
    assert_eq!(r["status"], 200);
    assert_eq!(r["bytes_up"], messages_body().len() as u64);
    assert_eq!(
        r["bytes_down"],
        r#"{"type":"message","ok":true}"#.len() as u64
    );
    assert!(r["ms"].is_u64());
    assert_eq!(r["login"], "api-key");
    assert_eq!(r["credential"], "gateway");
    assert_eq!(r["outcome"], "done");
    assert_eq!(recs[1]["method"], "GET");
    assert_eq!(recs[1]["path"], "/v1/models");
    assert_eq!(recs[1]["bytes_up"], 0);
    let audit = w.audit_text();
    assert!(!audit.contains(BODY_MARK));
    assert!(!audit.contains("limit=5"));
    assert!(!audit.contains(REAL_KEY));
    assert!(!audit.contains(&w.a.placeholder));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn denied_records_are_rate_limited() {
    let w = world(Opts::default()).await;
    for _ in 0..5 {
        let req = post("/v1/messages", &[], "{}");
        assert_eq!(ask(&w.a, req).await.0, 401);
    }
    // Another reason is its own key.
    let put = Request::builder()
        .method("PUT")
        .uri("/v1/messages")
        .body(Full::new(Bytes::new()))
        .unwrap();
    assert_eq!(ask(&w.a, put).await.0, 405);
    let recs = w.wait_records("model_denied", 2).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(recs.len(), 2, "{recs:?}");
    assert_eq!(w.records("model_denied").len(), 2);
    w.clock.fetch_add(60_000, Ordering::SeqCst);
    let req = post("/v1/messages", &[], "{}");
    assert_eq!(ask(&w.a, req).await.0, 401);
    let recs = w.wait_records("model_denied", 3).await;
    assert_eq!(recs.len(), 3);
    assert_eq!(recs[2]["reason"], "bad_credential");
    assert_eq!(recs[2]["suppressed"], 4);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lockdown_cuts_streams() {
    let w = world(Opts::default()).await;
    let (mut tx, _task) = client(&w.a).await;
    let req = post(
        "/v1/messages",
        &[("x-api-key", &w.a.placeholder)],
        &fake("forever"),
    );
    let resp = tokio::time::timeout(Duration::from_secs(15), tx.send_request(req))
        .await
        .unwrap()
        .unwrap();
    let mut body = resp.into_body();
    let _ = body.frame().await.unwrap().unwrap();
    w.lockdown();
    let t0 = Instant::now();
    let end = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match body.frame().await {
                Some(Ok(_)) => continue,
                other => return other.is_none(),
            }
        }
    })
    .await
    .expect("the stream was cut");
    assert!(!end, "the cut looked like a clean end");
    assert!(
        t0.elapsed() < Duration::from_millis(6500),
        "{:?}",
        t0.elapsed()
    );
    let recs = w.wait_records("model", 1).await;
    assert_eq!(recs[0]["outcome"], "lockdown");
    // New requests: 503.
    let (code, _, b) = ask(&w.a, api_req(&w.a)).await;
    assert_eq!(code, 503);
    assert_eq!(b.trim(), "lockdown is on");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_head_is_closed() {
    let w = world(Opts {
        model: ModelConfig {
            head_secs: 1,
            ..ModelConfig::default()
        },
        ..Opts::default()
    })
    .await;
    let mut s = UnixStream::connect(w.a.paths.vsock_port(ports::MODEL))
        .await
        .unwrap();
    let t0 = Instant::now();
    // A head that never ends, one byte at a time.
    let ended = tokio::time::timeout(Duration::from_secs(10), async {
        let _ = s.write_all(b"POST /v1/messages HTTP/1.1\r\n").await;
        let mut buf = [0u8; 256];
        loop {
            tokio::select! {
                r = s.read(&mut buf) => match r {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                },
                () = tokio::time::sleep(Duration::from_millis(200)) => {
                    let _ = s.write_all(b"x").await;
                }
            }
        }
    })
    .await;
    assert!(ended.is_ok(), "the slow head was never closed");
    assert!(t0.elapsed() < Duration::from_secs(5), "{:?}", t0.elapsed());
    assert!(w.up.seen().is_empty());
}

/// The failure answers after the credential check: an unusable vault
/// value (503), an upstream that never answers (504) and one that cannot
/// be reached (502) quote no credential, and neither does the audit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failure_answers_never_echo_credentials() {
    const BAD_KEY: &str = concat!("sk-", "ant-", "api03-", "BADKEY", "4242 ");
    let w = world(Opts {
        model: ModelConfig {
            idle_secs: 1,
            ..ModelConfig::default()
        },
        ..Opts::default()
    })
    .await;
    let pa = w.a.placeholder.clone();
    let mut bodies = Vec::new();
    w.rotate(BAD_KEY);
    let (code, h, b) = ask(&w.a, post("/v1/messages", &[("x-api-key", &pa)], "{}")).await;
    assert_eq!(code, 503, "{b}");
    assert!(b.contains("is not a usable token"), "{b}");
    bodies.push(format!("{h:?}{b}"));
    assert!(w.up.seen().is_empty());
    let recs = w.wait_records("model_denied", 1).await;
    assert_eq!(recs[0]["reason"], "secret_invalid");
    w.rotate(REAL_KEY);
    let (code, h, b) = ask(
        &w.a,
        post("/v1/messages", &[("x-api-key", &pa)], &fake("nohead")),
    )
    .await;
    assert_eq!(code, 504, "{b}");
    bodies.push(format!("{h:?}{b}"));
    let recs = w.wait_records("model", 1).await;
    assert_eq!(recs[0]["status"], 504);
    assert_eq!(recs[0]["outcome"], "idle");

    let dead = world(Opts {
        dead_upstream: true,
        ..Opts::default()
    })
    .await;
    let pd = dead.a.placeholder.clone();
    let (code, h, b) = ask(&dead.a, post("/v1/messages", &[("x-api-key", &pd)], "{}")).await;
    assert_eq!(code, 502, "{b}");
    bodies.push(format!("{h:?}{b}"));
    let recs = dead.wait_records("model", 1).await;
    assert_eq!(recs[0]["status"], 502);

    for b in &bodies {
        for secret in [pa.as_str(), pd.as_str(), REAL_KEY, BAD_KEY.trim(), REAL_SUB] {
            assert!(
                !b.contains(secret),
                "a failure answer quoted a credential: {b}"
            );
        }
    }
    for audit in [w.audit_text(), dead.audit_text()] {
        for secret in [pa.as_str(), pd.as_str(), REAL_KEY, BAD_KEY.trim()] {
            assert!(!audit.contains(secret), "the audit holds {secret}");
        }
    }
}

// ---------------------------------------------------------------- plan 42

const NOT_FORWARDED: &str = "this path is not forwarded to the model service";
const NOT_PLAIN: &str = "the request path is not plain";
const QUERY_KEY: &str = "the key query parameter is not forwarded";
const ALL_AGENTS: [AgentKind; 3] = [AgentKind::ClaudeCode, AgentKind::Codex, AgentKind::Gemini];

/// The header and value that carry `ph` on `agent`'s route.
fn auth(agent: AgentKind, ph: &str) -> (&'static str, String) {
    match agent {
        AgentKind::ClaudeCode => ("x-api-key", ph.to_string()),
        AgentKind::Codex => ("authorization", format!("Bearer {ph}")),
        AgentKind::Gemini => ("x-goog-api-key", ph.to_string()),
    }
}

/// An allowed path of `agent`'s route.
fn ok_path(agent: AgentKind) -> &'static str {
    match agent {
        AgentKind::ClaudeCode => "/v1/messages",
        AgentKind::Codex => "/v1/responses",
        AgentKind::Gemini => "/v1beta/models/m:generateContent",
    }
}

fn host_of(agent: AgentKind) -> &'static str {
    match agent {
        AgentKind::ClaudeCode => "api.anthropic.com",
        AgentKind::Codex => "api.openai.com",
        AgentKind::Gemini => "generativelanguage.googleapis.com",
    }
}

/// A request from box `b` of `agent` with its own credential header.
fn req_as(agent: AgentKind, b: &Bx, path: &str, extra: &[(&str, &str)]) -> Request<Full<Bytes>> {
    let (k, v) = auth(agent, &b.placeholder);
    let mut h: Vec<(&str, &str)> = vec![(k, &v)];
    h.extend_from_slice(extra);
    post(path, &h, "{}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_swap() {
    let w = world(Opts::agent(AgentKind::Codex)).await;
    let bearer = format!("Bearer {}", w.a.placeholder);
    let req = post(
        "/v1/responses",
        &[
            ("authorization", &bearer),
            ("content-type", "application/json"),
        ],
        &messages_body(),
    );
    let (code, _, body) = ask(&w.a, req).await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(body, r#"{"type":"message","ok":true}"#);
    let seen = w.up.seen();
    assert_eq!(seen.len(), 1);
    let s = &seen[0];
    assert_eq!(s.uri, "/v1/responses");
    assert_eq!(s.headers["host"], "api.openai.com");
    assert_eq!(s.headers["authorization"], format!("Bearer {REAL_OPENAI}"));
    assert_eq!(s.headers.get_all("authorization").iter().count(), 1);
    assert!(s.headers.get("x-api-key").is_none());
    assert!(s.headers.get("x-goog-api-key").is_none());
    assert!(!has(&s.headers, &w.a.placeholder));
    assert_eq!(s.body, Bytes::from(messages_body()));
    assert_eq!(w.up.asked(), vec!["api.openai.com".to_string()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn google_swap() {
    let w = world(Opts::agent(AgentKind::Gemini)).await;
    let target = "/v1beta/models/m:streamGenerateContent?alt=sse";
    let req = post(
        target,
        &[
            ("x-goog-api-key", &w.a.placeholder),
            ("content-type", "application/json"),
        ],
        &messages_body(),
    );
    let (code, _, body) = ask(&w.a, req).await;
    assert_eq!(code, 200, "{body}");
    let want: String = (0..3)
        .map(|i| String::from_utf8(sse_event(i).to_vec()).unwrap())
        .collect();
    assert_eq!(body, want);
    let s = &w.up.seen()[0];
    assert_eq!(s.uri, target);
    assert_eq!(s.headers["host"], "generativelanguage.googleapis.com");
    assert_eq!(s.headers["x-goog-api-key"], REAL_GOOGLE);
    assert_eq!(s.headers.get_all("x-goog-api-key").iter().count(), 1);
    assert!(s.headers.get("authorization").is_none());
    assert!(s.headers.get("x-api-key").is_none());
    assert!(!has(&s.headers, &w.a.placeholder));
    assert!(!s.uri.contains(&w.a.placeholder));
    assert_eq!(w.up.asked(), vec![HOSTS[2].to_string()]);
}

/// Review Focus 1: a codex box cannot use Anthropic's header or path, and
/// no other host is ever resolved.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn route_comes_from_the_template() {
    let w = world(Opts::agent(AgentKind::Codex)).await;
    let ph = &w.a.placeholder;
    let bearer = format!("Bearer {ph}");
    let req = post("/v1/responses", &[("x-api-key", ph)], "{}");
    let (code, _, body) = ask(&w.a, req).await;
    assert_eq!(code, 401, "{body}");
    assert_eq!(body.trim(), NOT_VALID);
    let req = post("/v1/responses", &[("x-goog-api-key", ph)], "{}");
    assert_eq!(ask(&w.a, req).await.0, 401);
    let req = post("/v1/messages", &[("authorization", &bearer)], "{}");
    let (code, _, body) = ask(&w.a, req).await;
    assert_eq!(code, 403, "{body}");
    assert_eq!(body.trim(), NOT_FORWARDED);
    let req = post("/v1/messages", &[("x-api-key", ph)], "{}");
    assert_eq!(ask(&w.a, req).await.0, 403);
    // A host header naming another provider changes nothing.
    let req = post(
        "/v1/responses",
        &[("authorization", &bearer), ("host", "api.anthropic.com")],
        "{}",
    );
    assert_eq!(ask(&w.a, req).await.0, 200);
    assert!(
        w.up.asked().iter().all(|h| h == "api.openai.com"),
        "{:?}",
        w.up.asked()
    );
    assert_eq!(w.up.seen().len(), 1);
    assert_eq!(w.up.seen()[0].headers["host"], "api.openai.com");
}

/// A request from box `b` of `agent`: `method` and `target`, its own
/// credential header, an empty body for GET.
fn reqm(agent: AgentKind, b: &Bx, method: &str, target: &str) -> Request<Full<Bytes>> {
    let (k, v) = auth(agent, &b.placeholder);
    let body = if method == "POST" { "{}" } else { "" };
    Request::builder()
        .method(method)
        .uri(target)
        .header(k, v)
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// Review Focus 1 and SEC4 (ruling R12): every (method, path, query) off
/// the route's exact list is a 403 with a `model_denied` record per
/// distinct (method, path), and the upstream sees nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paths_outside_the_route_are_403() {
    let id129 = format!("/v1/models/{}", "a".repeat(129));
    let cases: [(AgentKind, Vec<(&str, &str)>); 3] = [
        (
            AgentKind::ClaudeCode,
            vec![
                ("POST", "/v1/responses?x=1"),
                ("GET", "/api/hello"),
                ("POST", "/v1/files"),
                ("POST", "/v1/messages/batches"),
                ("POST", "/v1/messages/batches/x"),
                ("GET", "/v1/messages/batches"),
                ("GET", "/v1/messages"),
                ("POST", "/v1/models"),
                ("POST", "/v1/messages?x=1"),
                ("POST", "/v1/messages?beta=true&beta=true"),
                ("GET", "/v1/models?after_id=x"),
                ("GET", &id129),
                ("GET", "/v1/models/a$b"),
            ],
        ),
        (
            AgentKind::Codex,
            vec![
                ("POST", "/v1/messages?x=1"),
                ("POST", "/v1/files"),
                ("GET", "/v1/responses/abc"),
                ("POST", "/v1/responses/compact"),
                ("POST", "/v1/responses?stream=true"),
                ("GET", "/v1/responses"),
                ("POST", "/v1/chat/completions"),
            ],
        ),
        (
            AgentKind::Gemini,
            vec![
                ("POST", "/upload/v1beta/files?uploadType=resumable"),
                ("POST", "/v1/responses"),
                ("GET", "/v1beta/models"),
                ("POST", "/v1beta/models/m:streamGenerateContent?alt=json"),
                ("POST", "/v1beta/models/m:streamGenerateContent"),
                ("POST", "/v1beta/models/m:generateContent?alt=sse"),
                ("POST", "/v1beta/models/a$b:generateContent"),
            ],
        ),
    ];
    for (agent, reqs) in cases {
        let w = world(Opts::agent(agent)).await;
        let mut want: Vec<(String, String)> = Vec::new();
        for (m, target) in &reqs {
            let (code, h, body) = ask(&w.a, reqm(agent, &w.a, m, target)).await;
            assert_eq!(code, 403, "{agent:?} {m} {target}: {body}");
            assert_eq!(body.trim(), NOT_FORWARDED);
            let path = target.split('?').next().unwrap();
            assert!(!format!("{h:?}{body}").contains(path));
            let k = (m.to_string(), path.to_string());
            if !want.contains(&k) {
                want.push(k);
            }
        }
        assert!(w.up.seen().is_empty(), "{agent:?}");
        assert!(w.up.asked().is_empty(), "{agent:?}");
        let recs = w.wait_records("model_denied", want.len()).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let recs_now = w.records("model_denied");
        assert_eq!(recs_now.len(), want.len(), "{agent:?}: {recs:?}");
        let mut got: Vec<(String, String)> = recs_now
            .iter()
            .map(|r| {
                assert_eq!(r["reason"], "path_not_allowed", "{agent:?}");
                assert_eq!(r["box"], w.a.id.as_str());
                (
                    r["method"].as_str().unwrap().to_string(),
                    r["path"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        got.sort();
        want.sort();
        assert_eq!(got, want, "{agent:?}");
        let audit = w.audit_text();
        for q in [
            "x=1",
            "uploadType",
            "alt=json",
            "after_id",
            "stream=true",
            "beta=true",
        ] {
            assert!(
                !audit.contains(q),
                "{agent:?}: the audit holds the query {q}"
            );
        }
        assert!(w.records("model").is_empty());
    }
    // Methods other than GET and POST stop earlier (405).
    for (agent, m, target) in [
        (AgentKind::Codex, "DELETE", "/v1/responses/abc"),
        (AgentKind::ClaudeCode, "HEAD", "/api/hello"),
    ] {
        let w = world(Opts::agent(agent)).await;
        let (code, _, _) = ask(&w.a, reqm(agent, &w.a, m, target)).await;
        assert_eq!(code, 405, "{m} {target}");
        assert!(w.up.seen().is_empty());
    }
}

/// R12: each allowed (method, path, query) of each route reaches its
/// upstream unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_allow_list_passes() {
    let cases: [(AgentKind, &[(&str, &str)]); 3] = [
        (
            AgentKind::ClaudeCode,
            &[
                ("POST", "/v1/messages"),
                ("POST", "/v1/messages?beta=true"),
                ("POST", "/v1/messages/count_tokens"),
                ("POST", "/v1/messages/count_tokens?beta=true"),
                ("GET", "/v1/models"),
                ("GET", "/v1/models?beta=true"),
                ("GET", "/v1/models?beta=true&limit=1000"),
                ("GET", "/v1/models/claude-opus-4-1"),
                ("GET", "/v1/models/claude-opus-4-1?beta=true"),
            ],
        ),
        (
            AgentKind::Codex,
            &[
                ("POST", "/v1/responses"),
                ("GET", "/v1/models"),
                ("GET", "/v1/models?client_version=0.169.0"),
                ("GET", "/v1/models/gpt-5.1-codex"),
            ],
        ),
        (
            AgentKind::Gemini,
            &[
                ("POST", "/v1beta/models/m:streamGenerateContent?alt=sse"),
                ("POST", "/v1beta/models/gemini-2.5-pro:generateContent"),
                ("POST", "/v1beta/models/gemini-2.5-pro:countTokens"),
            ],
        ),
    ];
    for (agent, reqs) in cases {
        let w = world(Opts::agent(agent)).await;
        for (m, target) in reqs {
            let (code, _, body) = ask(&w.a, reqm(agent, &w.a, m, target)).await;
            assert_eq!(code, 200, "{agent:?} {m} {target}: {body}");
        }
        let seen = w.up.seen();
        assert_eq!(seen.len(), reqs.len(), "{agent:?}");
        for (s, (m, target)) in seen.iter().zip(reqs.iter()) {
            assert_eq!(s.method, *m);
            assert_eq!(s.uri, *target);
            assert_eq!(s.headers["host"], host_of(agent));
        }
        assert!(w.up.asked().iter().all(|h| h == host_of(agent)));
        assert!(w.records("model_denied").is_empty(), "{agent:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn path_tricks_are_400() {
    let cases: [(AgentKind, &[&str]); 3] = [
        (
            AgentKind::ClaudeCode,
            &[
                "/v1/messages/../x",
                "/v1/messages/%2E%2E/x",
                "/v1//messages",
                "/v1/messages%2fx",
                "/v1/messages\\x",
                "/v1/models/%2e%2e/files",
                "/v1/messages/./count_tokens",
                "/v1/messages%5Cx",
                "/v1/messages%00",
            ],
        ),
        (
            AgentKind::Codex,
            &[
                "/v1/responses/%2e%2e/x",
                "/v1/responses//x",
                "/v1/responses\\x",
            ],
        ),
        (
            AgentKind::Gemini,
            &["/v1beta/models/..", "/v1beta//models", "/v1beta/models%2Fx"],
        ),
    ];
    for (agent, paths) in cases {
        let w = world(Opts::agent(agent)).await;
        for p in paths {
            let (code, _, body) = ask(&w.a, req_as(agent, &w.a, p, &[])).await;
            assert_eq!(code, 400, "{agent:?} {p}: {body}");
            assert_eq!(body.trim(), NOT_PLAIN, "{p}");
        }
        assert!(w.up.seen().is_empty());
        assert!(w.up.asked().is_empty());
        let recs = w.wait_records("model_denied", 1).await;
        assert_eq!(recs[0]["reason"], "path", "{agent:?}");
    }
    // A NUL or a byte outside visible ASCII, by hand.
    let w = world(Opts::default()).await;
    for target in [
        &b"/v1/messages\x00"[..],
        b"/v1/messages/\xc3\xa9",
        b"/v1/messages\x7f",
    ] {
        let mut bytes = b"POST ".to_vec();
        bytes.extend_from_slice(target);
        bytes.extend_from_slice(
            format!(
                " HTTP/1.1\r\nHost: x\r\nx-api-key: {}\r\nContent-Length: 2\r\n\r\n{{}}",
                w.a.placeholder
            )
            .as_bytes(),
        );
        let (code, t) = raw(&w.a, &bytes).await;
        assert_eq!(code, 400, "{t}");
    }
    assert!(w.up.seen().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lookalike_prefix_is_403() {
    for (agent, p) in [
        (AgentKind::ClaudeCode, "/v1/messagesX"),
        (AgentKind::ClaudeCode, "/v1/models-all"),
        (AgentKind::Codex, "/v1/responsesX"),
        (AgentKind::Gemini, "/v1beta/modelsX"),
    ] {
        let w = world(Opts::agent(agent)).await;
        let (code, _, body) = ask(&w.a, req_as(agent, &w.a, p, &[])).await;
        assert_eq!(code, 403, "{p}: {body}");
        assert_eq!(body.trim(), NOT_FORWARDED);
        assert!(w.up.seen().is_empty());
        let recs = w.wait_records("model_denied", 1).await;
        assert_eq!(recs[0]["reason"], "path_not_allowed");
        assert_eq!(recs[0]["method"], "POST");
        assert_eq!(recs[0]["path"], p);
    }
}

/// The placeholder in the target. R12 leaves one place it can pass the
/// allow-list, a model ID segment, and there it is a 401; anywhere else
/// (a query value, percent-encoded) the exact list refuses it first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn placeholder_in_target_is_401() {
    for agent in ALL_AGENTS {
        let w = world(Opts::agent(agent)).await;
        let ph = w.a.placeholder.clone();
        // Percent-encoding its first character does not hide it.
        let enc = format!("%{:02X}{}", ph.as_bytes()[0], &ph[1..]);
        let (m, in_id) = match agent {
            AgentKind::Gemini => ("POST", format!("/v1beta/models/{ph}:generateContent")),
            _ => ("GET", format!("/v1/models/{ph}")),
        };
        let (code, _, body) = ask(&w.a, reqm(agent, &w.a, m, &in_id)).await;
        assert_eq!(code, 401, "{agent:?} {in_id}: {body}");
        assert_eq!(body.trim(), NOT_VALID);
        let base = ok_path(agent);
        for target in [
            format!("{base}/{ph}"),
            format!("{base}?beta={ph}"),
            format!("{base}?alt=sse&q=x{ph}y"),
            format!("{base}/{enc}"),
            format!("{base}?q={enc}"),
            format!("/v1/models?client_version={ph}"),
            match agent {
                AgentKind::Gemini => format!("/v1beta/models/{enc}:generateContent"),
                _ => format!("/v1/models/{enc}"),
            },
        ] {
            let m = if target.starts_with("/v1/models") {
                "GET"
            } else {
                "POST"
            };
            let (code, _, body) = ask(&w.a, reqm(agent, &w.a, m, &target)).await;
            // Off the exact list: 403 before the credential check.
            assert_eq!(code, 403, "{agent:?} {target}: {body}");
            assert_eq!(body.trim(), NOT_FORWARDED);
        }
        assert!(w.up.seen().is_empty(), "{agent:?}");
        let recs = w.wait_records("model_denied", 1).await;
        assert_eq!(recs[0]["reason"], "bad_credential");
        assert!(!w.audit_text().contains(&ph));
        assert!(!w.audit_text().contains(&ph[1..]));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_key_is_400() {
    let w = world(Opts::agent(AgentKind::Gemini)).await;
    let base = "/v1beta/models/m:streamGenerateContent";
    for q in ["?alt=sse&key=x", "?key=x", "?%6Bey=x", "?alt=sse;key=x"] {
        let target = format!("{base}{q}");
        let (code, _, body) = ask(&w.a, req_as(AgentKind::Gemini, &w.a, &target, &[])).await;
        assert_eq!(code, 400, "{q}: {body}");
        assert_eq!(body.trim(), QUERY_KEY);
    }
    assert!(w.up.seen().is_empty());
    let recs = w.wait_records("model_denied", 1).await;
    assert_eq!(recs[0]["reason"], "query_key");
    // Lookalike names are not `key`, but R12's exact list refuses them.
    let target = format!("{base}?alt=sse&keys=1&Key=2");
    let (code, _, body) = ask(&w.a, req_as(AgentKind::Gemini, &w.a, &target, &[])).await;
    assert_eq!(code, 403, "{body}");
    assert_eq!(body.trim(), NOT_FORWARDED);
    assert!(w.up.seen().is_empty());
}

/// Review Focus 2: another provider's credential and billing headers never
/// reach the upstream; only the route's own header carries the real key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provider_headers_are_stripped() {
    let smuggled = [
        ("x-api-key", "box-own-a"),
        ("x-goog-api-key", "box-own-g"),
        ("authorization", "Bearer box-own-o"),
        ("openai-organization", "org-box"),
        ("openai-project", "proj-box"),
        ("x-goog-user-project", "gp-box"),
    ];
    for agent in ALL_AGENTS {
        let w = world(Opts::agent(agent)).await;
        let (k, v) = auth(agent, &w.a.placeholder);
        let mut h: Vec<(&str, &str)> = smuggled.iter().filter(|(n, _)| *n != k).copied().collect();
        h.push((k, &v));
        h.push(("user-agent", "agent/1"));
        let (code, _, body) = ask(&w.a, post(ok_path(agent), &h, "{}")).await;
        assert_eq!(code, 200, "{agent:?}: {body}");
        let s = &w.up.seen()[0];
        for (n, val) in smuggled {
            if n == k {
                continue;
            }
            assert!(
                s.headers.get(n).is_none(),
                "{agent:?}: {n} reached the upstream"
            );
            assert!(
                !has(&s.headers, val),
                "{agent:?}: {val} reached the upstream"
            );
        }
        let want = match agent {
            AgentKind::Codex => format!("Bearer {REAL_OPENAI}"),
            other => real_key(other).to_string(),
        };
        assert_eq!(s.headers[k], want.as_str());
        assert_eq!(s.headers.get_all(k).iter().count(), 1);
        assert_eq!(s.headers["user-agent"], "agent/1");
        assert_eq!(s.headers["host"], host_of(agent));
    }
}

/// Review Focus 3.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secret_services_are_per_provider() {
    let openai_missing = "the vault has no secret openai for box-model-openai: \
                          saiife secret add openai --kind token --service box-model-openai";
    for services in [vec!["box-model-anthropic"], vec!["box-model"]] {
        let w = world(Opts {
            services: Some(services.clone()),
            ..Opts::agent(AgentKind::Codex)
        })
        .await;
        let (code, _, body) = ask(&w.a, req_as(AgentKind::Codex, &w.a, "/v1/responses", &[])).await;
        assert_eq!(code, 503, "{services:?}: {body}");
        assert_eq!(body.trim(), openai_missing);
        assert!(w.up.seen().is_empty());
        let recs = w.wait_records("model_denied", 1).await;
        assert_eq!(recs[0]["reason"], "secret_not_allowed");
    }
    let w = world(Opts {
        services: Some(vec!["box-model-openai"]),
        ..Opts::agent(AgentKind::Gemini)
    })
    .await;
    let (code, _, body) = ask(
        &w.a,
        req_as(AgentKind::Gemini, &w.a, ok_path(AgentKind::Gemini), &[]),
    )
    .await;
    assert_eq!(code, 503, "{body}");
    assert_eq!(
        body.trim(),
        "the vault has no secret gemini for box-model-google: \
         saiife secret add gemini --kind token --service box-model-google"
    );
    // Anthropic: the legacy name and the new one both pass.
    for services in [
        vec!["box-model"],
        vec!["box-model-anthropic"],
        vec!["github", "box-model-anthropic"],
    ] {
        let w = world(Opts {
            services: Some(services.clone()),
            ..Opts::default()
        })
        .await;
        let (code, _, body) = ask(&w.a, api_req(&w.a)).await;
        assert_eq!(code, 200, "{services:?}: {body}");
    }
    let w = world(Opts {
        services: Some(vec!["box-model-openai"]),
        ..Opts::default()
    })
    .await;
    let (code, _, body) = ask(&w.a, api_req(&w.a)).await;
    assert_eq!(code, 503, "{body}");
    assert!(body.contains("--service box-model-anthropic"), "{body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn records_name_the_provider() {
    for (agent, provider) in [
        (AgentKind::ClaudeCode, "anthropic"),
        (AgentKind::Codex, "openai"),
        (AgentKind::Gemini, "google"),
    ] {
        let w = world(Opts::agent(agent)).await;
        let (path, query) = match agent {
            AgentKind::ClaudeCode => ("/v1/messages", "?beta=true"),
            AgentKind::Codex => ("/v1/responses", ""),
            AgentKind::Gemini => ("/v1beta/models/m:streamGenerateContent", "?alt=sse"),
        };
        let target = format!("{path}{query}");
        let (code, _, body) = ask(&w.a, req_as(agent, &w.a, &target, &[])).await;
        assert_eq!(code, 200, "{body}");
        let recs = w.wait_records("model", 1).await;
        let r = &recs[0];
        assert_eq!(r["provider"], provider);
        assert_eq!(r["login"], "api-key");
        assert_eq!(r["credential"], "gateway");
        assert_eq!(r["path"], path);
        assert_eq!(r["box"], w.a.id.as_str());
        assert_eq!(r["outcome"], "done");
        let audit = w.audit_text();
        assert!(!audit.contains("beta=true"));
        assert!(!audit.contains("alt=sse"));
        assert!(!audit.contains(real_key(agent)));
        assert!(!audit.contains(&w.a.placeholder));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upgrade_refused_on_every_route() {
    for agent in ALL_AGENTS {
        let w = world(Opts::agent(agent)).await;
        let (k, v) = auth(agent, &w.a.placeholder);
        let path = match agent {
            AgentKind::Codex => "/v1/responses",
            other => ok_path(other),
        };
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .header(k, v)
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let (code, _, body) = ask(&w.a, req).await;
        assert_eq!(code, 400, "{agent:?}: {body}");
        assert!(w.up.seen().is_empty());
    }
}

/// The three events reach the box one by one: the first before the
/// upstream sent the third.
async fn sse_arrives_incrementally(w: &W, req: Request<Full<Bytes>>) {
    let (mut tx, _task) = client(&w.a).await;
    let resp = tokio::time::timeout(Duration::from_secs(15), tx.send_request(req))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resp.status(), 200);
    let mut body = resp.into_body();
    let first = tokio::time::timeout(Duration::from_secs(15), body.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let first_at = Instant::now();
    assert_eq!(first.into_data().unwrap(), sse_event(0));
    let mut rest = Vec::new();
    while let Some(f) = tokio::time::timeout(Duration::from_secs(15), body.frame())
        .await
        .unwrap()
    {
        if let Ok(d) = f.unwrap().into_data() {
            rest.extend_from_slice(&d);
        }
    }
    let mut want = Vec::new();
    want.extend_from_slice(&sse_event(1));
    want.extend_from_slice(&sse_event(2));
    assert_eq!(rest, want);
    let third_at =
        w.up.third_at
            .lock()
            .unwrap()
            .expect("the third event was sent");
    assert!(
        first_at < third_at,
        "the first event arrived only after the third was sent"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_streams_on_every_route() {
    let w = world(Opts::agent(AgentKind::Codex)).await;
    let bearer = format!("Bearer {}", w.a.placeholder);
    let req = post(
        "/v1/responses",
        &[("authorization", &bearer), ("accept", "text/event-stream")],
        r#"{"model":"m","stream":true,"input":[]}"#,
    );
    sse_arrives_incrementally(&w, req).await;
    let w = world(Opts::agent(AgentKind::Gemini)).await;
    let req = post(
        "/v1beta/models/m:streamGenerateContent?alt=sse",
        &[("x-goog-api-key", &w.a.placeholder)],
        "{}",
    );
    sse_arrives_incrementally(&w, req).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn new_routes_never_echo_credentials() {
    for agent in [AgentKind::Codex, AgentKind::Gemini] {
        let w = world(Opts {
            model: ModelConfig {
                body_max: 64,
                ..ModelConfig::default()
            },
            ..Opts::agent(agent)
        })
        .await;
        let pa = w.a.placeholder.clone();
        let pb = w.b.placeholder.clone();
        let (k, v) = auth(agent, &pa);
        let (_, vb) = auth(agent, &pb);
        let base = ok_path(agent);
        let mut bodies = Vec::new();
        let reqs = vec![
            post(base, &[(k, &vb)], "{}"),
            post(base, &[("x-api-key", &pa)], "{}"),
            post(base, &[(k, &v), ("x-other", &pa)], "{}"),
            post(&format!("{base}/{pa}"), &[(k, &v)], "{}"),
            post(&format!("{base}?q={pa}"), &[(k, &v)], "{}"),
            post(&format!("/v1/files/{pa}"), &[(k, &v)], "{}"),
            post(&format!("{base}/../{pa}"), &[(k, &v)], "{}"),
            post(&format!("{base}?key={pa}"), &[(k, &v)], "{}"),
            post(base, &[(k, &v)], &"q".repeat(100)),
            post(
                base,
                &[(k, &v), ("upgrade", "websocket"), ("connection", "upgrade")],
                "{}",
            ),
        ];
        for req in reqs {
            let (code, h, body) = ask(&w.a, req).await;
            assert!(code >= 400, "{agent:?} {code}");
            bodies.push(format!("{h:?}{body}"));
        }
        w.lockdown();
        bodies.push(ask(&w.a, req_as(agent, &w.a, base, &[])).await.2);
        w.ctx.lockdown.set(None).unwrap();
        w.ctx.vault.writer().remove(cred_name(agent)).unwrap();
        let (code, _, b) = ask(&w.a, req_as(agent, &w.a, base, &[])).await;
        assert_eq!(code, 503);
        bodies.push(b);
        let real = real_key(agent);
        for b in &bodies {
            for secret in [pa.as_str(), pb.as_str(), real] {
                assert!(
                    !b.contains(secret),
                    "{agent:?}: an error answer quoted a credential: {b}"
                );
            }
        }
        assert!(w.up.seen().is_empty(), "{agent:?}");
        let audit = w.audit_text();
        for secret in [pa.as_str(), pb.as_str(), real] {
            assert!(
                !audit.contains(secret),
                "{agent:?}: the audit holds a credential"
            );
        }
    }
}

/// Review Focus 5: a box spawned as claude-code whose template now names
/// codex fails closed, and its placeholder file is never remade.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn template_switched_agent_is_401() {
    let w = world(Opts {
        switch_to: Some(AgentKind::Codex),
        ..Opts::default()
    })
    .await;
    let mgr = w.ctx.box_manager.as_ref().unwrap();
    let file = saiife_boxhost::paths::RecordPaths::of(mgr.root(), &w.a.id).placeholder();
    let before = std::fs::read(&file).unwrap();
    let ph = &w.a.placeholder;
    let bearer = format!("Bearer {ph}");
    for h in [
        ("x-api-key", ph.as_str()),
        ("authorization", bearer.as_str()),
    ] {
        let (code, _, body) = ask(&w.a, post("/v1/responses", &[h], "{}")).await;
        assert_eq!(code, 401, "{h:?}: {body}");
        assert_eq!(body.trim(), NOT_VALID);
    }
    assert!(w.up.seen().is_empty());
    assert!(w.up.asked().is_empty());
    let recs = w.wait_records("model_denied", 1).await;
    assert_eq!(recs[0]["reason"], "no_placeholder");
    assert_eq!(std::fs::read(&file).unwrap(), before);
}
