//! OAuth2 secrets end to end in process (plan 14, Task 7): a daemon context
//! on temp dirs (the real audit writer and vault), an `oauth2` connector,
//! and one loopback TLS mock serving both the token endpoint and the API.
//! Calls go through `api.call` as a client would send them. Nothing leaves
//! 127.0.0.1.
#![cfg(target_os = "linux")]

use bytes::Bytes;
use http::{Request, Response};
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
use saiife_daemon::ops::{Ctx, CtxInit, GatewayPolicy, PolicyState};
use saiife_daemon::sessions::RealProc;
use saiife_daemon::tokens::Tokens;
use saiife_daemon::vault::{self, Entry, Kind, VaultState};
use saiife_daemon::writer::{self, WriterConfig};
use saiife_ipc::msg::Request as IpcRequest;
use saiife_ipc::peer::PeerCred;
use saiife_policy::{Directory, Event, Fsync, GroupEntry, Mode, SystemConfig, UserEntry};
use serde_json::{json, Value};
use std::convert::Infallible;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use zeroize::Zeroizing;

const SECRET: &str = "sf-oauth";
const MANIFEST: &str = r#"
id = "sfx"
version = 1
title = "SF test"
base_url = "https://{instance_host}/services/data/v60.0"
hosts = ["{instance_host}"]
auth = [{ kind = "oauth2", token_path = "/services/oauth2/token" }]

[params.instance_host]
type = "string"
pattern = "^[a-z0-9-]+\\.sf\\.test$"
required = true

[[operation]]
id = "limits"
capability = "limits:read"
kind = "read"
method = "GET"
path = "/limits"
"#;

fn client_secret() -> String {
    format!("cs-{}", "k9".repeat(10))
}

fn initial_refresh() -> String {
    format!("rt-initial-{}", "5f".repeat(8))
}

// ---------------------------------------------------------------- mock

/// What the mock does and what it saw.
#[derive(Default)]
struct State {
    /// Token POSTs: the refresh token each one sent.
    posts: Vec<String>,
    /// Every token POST form, raw.
    forms: Vec<String>,
    /// API requests: the bearer each one sent.
    api: Vec<String>,
    /// The access token the API accepts (the last one issued).
    current: String,
    token_status: u16,
    /// `instance_url` of the token response (none when empty).
    instance: String,
    expires_in: Option<u64>,
    /// Each refresh returns a new refresh token.
    rotate: bool,
    /// The API answers 401 whatever the token.
    always_401: bool,
    /// How long the token endpoint takes.
    delay_ms: u64,
    /// The vault's refresh token, read when the API was called.
    vault_at_api: Vec<String>,
    vault: Option<(PathBuf, PathBuf)>,
}

type Shared = Arc<Mutex<State>>;

struct Loopback(u16);

impl Resolver for Loopback {
    fn resolve(&self, host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
        if host.ends_with(".sf.test") {
            Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, self.0))])
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "unknown test host"))
        }
    }
}

fn form_field(form: &str, name: &str) -> String {
    form.split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{name}=")))
        .map(|v| {
            percent_encoding::percent_decode_str(v)
                .decode_utf8_lossy()
                .into_owned()
        })
        .unwrap_or_default()
}

fn vault_refresh(key: &Path, file: &Path) -> String {
    match vault::open(key, file) {
        VaultState::Ready(v) => v
            .get(SECRET)
            .and_then(|e| e.fields.get("refresh_token").map(|r| r.to_string()))
            .unwrap_or_default(),
        VaultState::Unavailable(_) => String::new(),
    }
}

async fn answer(req: Request<Incoming>, st: Shared) -> Result<Response<Full<Bytes>>, Infallible> {
    let (parts, body) = req.into_parts();
    let body = body
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let json = |status: u16, b: String| {
        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(b)))
            .unwrap()
    };
    if parts.uri.path() == "/services/oauth2/token" {
        let delay = st.lock().unwrap().delay_ms;
        if delay > 0 {
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        let form = String::from_utf8_lossy(&body).into_owned();
        let mut s = st.lock().unwrap();
        s.posts.push(form_field(&form, "refresh_token"));
        s.forms.push(form);
        if s.token_status != 200 {
            return Ok(json(s.token_status, r#"{"error":"invalid_grant"}"#.into()));
        }
        let n = s.posts.len();
        let access = format!("at-{n}-{}", "q7".repeat(8));
        s.current = access.clone();
        let mut o = json!({"access_token": access, "token_type": "Bearer"});
        if !s.instance.is_empty() {
            o["instance_url"] = s.instance.clone().into();
        }
        if let Some(e) = s.expires_in {
            o["expires_in"] = e.into();
        }
        if s.rotate {
            o["refresh_token"] = format!("rt-rot-{n}-{}", "c3".repeat(8)).into();
        }
        return Ok(json(200, o.to_string()));
    }
    let bearer = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
        .to_string();
    let mut s = st.lock().unwrap();
    s.api.push(bearer.clone());
    if let Some((k, f)) = s.vault.clone() {
        let r = vault_refresh(&k, &f);
        s.vault_at_api.push(r);
    }
    if s.always_401 || bearer != s.current {
        return Ok(json(401, r#"[{"errorCode":"INVALID_SESSION_ID"}]"#.into()));
    }
    // The upstream echoes the token: the response must come back masked.
    Ok(json(200, json!({"ok": true, "seen": bearer}).to_string()))
}

async fn mock(st: Shared) -> Upstream {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["acme.sf.test".to_string()])
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
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let st = st.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let svc = service_fn(move |req| answer(req, st.clone()));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    Upstream::with_roots(roots, Arc::new(Loopback(port)), Duration::from_secs(5))
}

// ---------------------------------------------------------------- daemon

/// The caller (`agent`, the context's own user) is in group `admins`.
struct Dir;

impl Directory for Dir {
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
        vec!["admins".into()]
    }
}

struct World {
    ctx: Arc<Ctx>,
    st: Shared,
    audit: PathBuf,
    vault_dir: PathBuf,
    key_file: PathBuf,
    vault_file: PathBuf,
    _tmp: tempfile::TempDir,
}

fn scratch() -> tempfile::TempDir {
    let base = std::env::var_os("SAIIFE_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    std::fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

fn oauth_fields(refresh: &str) -> std::collections::BTreeMap<String, Zeroizing<String>> {
    [
        ("client_id", "cid-test".to_string()),
        ("client_secret", client_secret()),
        ("refresh_token", refresh.to_string()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), Zeroizing::new(v)))
    .collect()
}

async fn world(setup: impl FnOnce(&mut State)) -> World {
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
    let wcfg = WriterConfig {
        checkpoint_every: 1000,
        checkpoint_interval: Duration::from_secs(900),
        fsync: Fsync::Always,
    };
    let (handle, _join) = writer::spawn(cw, wcfg, None).unwrap();

    let key_file = tmp.path().join("vault-key");
    std::fs::write(&key_file, [7u8; 32]).unwrap();
    let vault_dir = state.join("vault");
    let vault_file = vault_dir.join("vault.bin");
    let mut vault = vault::open(&key_file, &vault_file);
    let VaultState::Ready(v) = &mut vault else {
        panic!("vault not ready");
    };
    v.put(Entry {
        name: SECRET.into(),
        kind: Kind::OAuth2,
        fields: oauth_fields(&initial_refresh()),
        allowed_services: vec!["sf".into()],
        created_by: 0,
        created: "2026-10-28T00:00:00Z".into(),
        last_used: None,
        rotate_after: None,
    })
    .unwrap();

    let text = r#"version = 2
locked = true

[[scope]]
name = "agents"
users = ["agent"]
services = ["sf"]

[services.sf]
connector = "sfx"
secret = "sf-oauth"
params = { instance_host = "acme.sf.test" }
allow = ["limits:read"]
"#;
    let config: SystemConfig = toml::from_str(text).unwrap();
    let manifest = Manifest::parse(MANIFEST).unwrap();
    let policy = PolicyState {
        hash: Some("sha256:test".into()),
        ok: true,
        min_free_mb: 0,
        admin_groups: vec!["admins".into()],
        system: Some(Arc::new(config.clone())),
        gateway: Some(Arc::new(GatewayPolicy {
            snap: PolicySnapshot {
                config,
                hash: "sha256:test".into(),
                mode: Mode::Locked,
                env: None,
            },
            by_env: Default::default(),
            catalog: Catalog::new(&[], vec![manifest]),
        })),
    };

    let mut s = State {
        token_status: 200,
        instance: "https://acme.sf.test".into(),
        vault: Some((key_file.clone(), vault_file.clone())),
        ..State::default()
    };
    setup(&mut s);
    let st: Shared = Arc::new(Mutex::new(s));
    let up = mock(st.clone()).await;
    let ctx = Arc::new(Ctx::new(CtxInit {
        own_user: "agent".into(),
        audit_dir: audit.clone(),
        socket_dir: tmp.path().join("run"),
        key_path: state.join("keys/audit.ed25519"),
        config_path: tmp.path().join("config.toml"),
        catalog: Vec::new(),
        policy,
        proc: Box::new(RealProc::new(tmp.path().join("proc"))),
        vault,
        vault_path: vault_file.clone(),
        backup_dir: state.join("import-backup"),
        limiter: Limiter::new(),
        upstream: Ok(up),
        tokens: Arc::new(Tokens::memory_with_clock(Arc::new(|| 1_800_000_000))),
        approvals: saiife_daemon::approvals::Store::open(&state.join("approvals"))
            .map_err(|e| e.to_string()),
        lockdown: saiife_daemon::lockdown::Store::memory(),
        grants: saiife_daemon::grants::Grants::memory(),
        ..CtxInit::minimal(handle, wcfg, Arc::new(Dir), &state)
    }));
    World {
        ctx,
        st,
        audit,
        vault_dir,
        key_file,
        vault_file,
        _tmp: tmp,
    }
}

fn peer() -> PeerCred {
    PeerCred {
        uid: rustix::process::getuid().as_raw(),
        gid: rustix::process::getgid().as_raw(),
        pid: std::process::id(),
    }
}

impl World {
    async fn op(&self, op: &str, args: Value) -> Value {
        let req = IpcRequest {
            id: 1,
            op: op.into(),
            args: args.as_object().unwrap().clone(),
        };
        saiife_daemon::ops::dispatch(&self.ctx, &peer(), req).await
    }

    async fn call(&self) -> Value {
        self.op("api.call", json!({"service": "sf", "operation": "limits"}))
            .await
    }

    fn posts(&self) -> Vec<String> {
        self.st.lock().unwrap().posts.clone()
    }

    fn api(&self) -> Vec<String> {
        self.st.lock().unwrap().api.clone()
    }

    fn audit_text(&self) -> String {
        let mut s = String::new();
        for e in std::fs::read_dir(&self.audit).unwrap() {
            s.push_str(&std::fs::read_to_string(e.unwrap().path()).unwrap_or_default());
        }
        s
    }

    fn records(&self, kind: &str) -> Vec<Value> {
        self.audit_text()
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|v| v["kind"] == kind)
            .collect()
    }

    fn refresh_failed(&self) -> Vec<Value> {
        self.records("secret")
            .into_iter()
            .filter(|r| r["event"] == "refresh_failed")
            .collect()
    }

    fn vault_refresh(&self) -> String {
        vault_refresh(&self.key_file, &self.vault_file)
    }
}

fn status(a: &Value) -> u64 {
    assert_eq!(a["ok"], true, "{a}");
    a["status"].as_u64().unwrap()
}

fn body(a: &Value) -> String {
    use base64::Engine as _;
    let b = base64::engine::general_purpose::STANDARD
        .decode(a["body_b64"].as_str().unwrap())
        .unwrap();
    String::from_utf8(b).unwrap()
}

fn rule(a: &Value) -> String {
    assert_eq!(a["ok"], false, "{a}");
    a["rule"].as_str().unwrap_or_default().to_string()
}

// ---------------------------------------------------------------- tests

#[tokio::test]
async fn cold_call_refreshes_then_sends() {
    let w = world(|_| {}).await;
    let a = w.call().await;
    assert_eq!(status(&a), 200);
    let posts = w.posts();
    assert_eq!(posts, vec![initial_refresh()]);
    let form = w.st.lock().unwrap().forms[0].clone();
    assert!(form.starts_with("grant_type=refresh_token&client_id=cid-test&client_secret="));
    let access = w.st.lock().unwrap().current.clone();
    assert_eq!(w.api(), vec![access.clone()]);
    // The echoed token comes back masked.
    let b = body(&a);
    assert!(!b.contains(&access), "{b}");
    assert!(b.contains("\"ok\":true"), "{b}");
    let rec = w.records("connector");
    assert_eq!(rec.len(), 1);
    assert_eq!(rec[0]["secret"], SECRET);
    assert!(rec[0].get("auth_retry").is_none(), "{}", rec[0]);
}

#[tokio::test]
async fn cached_token_reused_until_ttl() {
    // 61 s lifetime, refreshed 60 s early: fresh for one second.
    let w = world(|s| s.expires_in = Some(61)).await;
    assert_eq!(status(&w.call().await), 200);
    assert_eq!(status(&w.call().await), 200);
    assert_eq!(w.posts().len(), 1);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(status(&w.call().await), 200);
    assert_eq!(w.posts().len(), 2);
    let api = w.api();
    assert_eq!(api.len(), 3);
    assert_eq!(api[0], api[1]);
    assert_ne!(api[1], api[2]);
}

#[tokio::test]
async fn concurrent_cold_calls_refresh_once() {
    let w = Arc::new(world(|s| s.delay_ms = 200).await);
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let w = Arc::clone(&w);
        tasks.push(tokio::spawn(async move { w.call().await }));
    }
    for t in tasks {
        assert_eq!(status(&t.await.unwrap()), 200);
    }
    assert_eq!(w.posts().len(), 1);
    assert_eq!(w.api().len(), 10);
}

#[tokio::test]
async fn upstream_401_refreshes_once_and_retries_once() {
    let w = world(|_| {}).await;
    assert_eq!(status(&w.call().await), 200);
    // The session is revoked upstream: one forced refresh, one resend.
    w.st.lock().unwrap().current = String::new();
    let a = w.call().await;
    assert_eq!(status(&a), 200);
    assert_eq!(w.posts().len(), 2);
    assert_eq!(w.api().len(), 3);
    let rec = w.records("connector");
    assert_eq!(rec[1]["auth_retry"], true, "{}", rec[1]);
    assert_eq!(rec[1]["status"], 200);

    // A second 401 is the answer (exit 1): no third send, no second
    // refresh for this call.
    w.st.lock().unwrap().always_401 = true;
    let a = w.call().await;
    assert_eq!(status(&a), 401);
    assert_eq!(w.posts().len(), 3);
    assert_eq!(w.api().len(), 5);
    let rec = w.records("connector");
    assert_eq!(rec[2]["auth_retry"], true);
    assert_eq!(rec[2]["status"], 401);
    assert_eq!(rec[2]["decision"], "allow");
}

#[tokio::test]
async fn rotated_refresh_token_persisted_first() {
    let w = world(|s| s.rotate = true).await;
    assert_eq!(status(&w.call().await), 200);
    let st = w.st.lock().unwrap();
    assert_eq!(st.posts, vec![initial_refresh()]);
    let rotated = format!("rt-rot-1-{}", "c3".repeat(8));
    // When the API saw the request, the vault already held the new token.
    assert_eq!(st.vault_at_api, vec![rotated.clone()]);
    drop(st);
    assert_eq!(w.vault_refresh(), rotated);
}

#[tokio::test]
async fn persist_failure_keeps_token_in_memory() {
    let w = world(|s| s.rotate = true).await;
    // The vault cannot be written: its temp file's name is taken by a dir.
    let block = w.vault_dir.join(".vault.bin.tmp");
    std::fs::create_dir(&block).unwrap();
    let a = w.call().await;
    assert_eq!(rule(&a), "vault_unavailable");
    assert!(w.api().is_empty(), "the new access token was used");
    assert_eq!(w.posts().len(), 1);
    assert_eq!(w.vault_refresh(), initial_refresh());
    let f = w.refresh_failed();
    assert_eq!(f.len(), 1);
    assert_eq!(f[0]["reason"], "persist");
    assert_eq!(f[0]["name"], SECRET);
    assert_eq!(f[0]["service"], "sf");

    // The next call writes it first, then uses the token held in memory:
    // no second refresh (the old refresh token may already be dead).
    std::fs::remove_dir(&block).unwrap();
    let a = w.call().await;
    assert_eq!(status(&a), 200);
    assert_eq!(w.posts().len(), 1);
    let rotated = format!("rt-rot-1-{}", "c3".repeat(8));
    assert_eq!(w.vault_refresh(), rotated);
    assert_eq!(w.st.lock().unwrap().vault_at_api, vec![rotated]);
}

#[tokio::test]
async fn instance_url_mismatch_refused() {
    let w = world(|s| {
        s.instance = "https://evil.sf.test".into();
        s.rotate = true;
    })
    .await;
    let a = w.call().await;
    assert_eq!(rule(&a), "refresh_failed");
    assert!(w.api().is_empty());
    // Nothing from that response is kept.
    assert_eq!(w.vault_refresh(), initial_refresh());
    let f = w.refresh_failed();
    assert_eq!(f.len(), 1);
    assert_eq!(f[0]["reason"], "instance_mismatch");
}

#[tokio::test]
async fn instance_url_required_for_an_instance_host() {
    // The manifest's host is `{instance_host}`: a response that names no
    // instance is refused.
    let w = world(|s| {
        s.instance = String::new();
        s.rotate = true;
    })
    .await;
    assert_eq!(rule(&w.call().await), "refresh_failed");
    assert!(w.api().is_empty());
    assert_eq!(w.vault_refresh(), initial_refresh());
    assert_eq!(w.refresh_failed()[0]["reason"], "instance_mismatch");
}

#[tokio::test]
async fn failed_refresh_backs_off() {
    let w = Arc::new(world(|s| s.token_status = 400).await);
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let w = Arc::clone(&w);
        tasks.push(tokio::spawn(async move { w.call().await }));
    }
    for t in tasks {
        assert_eq!(rule(&t.await.unwrap()), "refresh_failed");
    }
    assert_eq!(w.posts().len(), 1, "one POST per backoff window");
    assert_eq!(w.refresh_failed().len(), 1, "one record per window");
    assert!(w.api().is_empty());

    // The first window (5 s) has passed: one POST again, then a 10 s
    // window.
    tokio::time::sleep(Duration::from_millis(5100)).await;
    assert_eq!(rule(&w.call().await), "refresh_failed");
    assert_eq!(rule(&w.call().await), "refresh_failed");
    assert_eq!(w.posts().len(), 2);
    let f = w.refresh_failed();
    assert_eq!(f.len(), 2);
    for r in &f {
        assert_eq!(r["reason"], "http_400");
        assert_eq!(r["name"], SECRET);
        assert_eq!(r["service"], "sf");
        assert!(!r.to_string().contains("invalid_grant"), "a body: {r}");
    }
    let ev: Vec<_> = w
        .ctx
        .notifier
        .queued_events()
        .into_iter()
        .filter(|e| e.event == Event::RefreshFailed)
        .collect();
    assert_eq!(ev.len(), 1, "at most one notification per secret per hour");
    assert_eq!(ev[0].reason.as_deref(), Some("http_400"));
    assert_eq!(ev[0].service.as_deref(), Some("sf"));

    // `forget` (secret rotate/remove) ends the backoff.
    w.st.lock().unwrap().token_status = 200;
    assert_eq!(rule(&w.call().await), "refresh_failed");
    assert_eq!(w.posts().len(), 2);
    w.ctx.oauth.forget(SECRET);
    assert_eq!(status(&w.call().await), 200);
    assert_eq!(w.posts().len(), 3);
}

#[tokio::test]
async fn refresh_started_before_shutdown_still_persists() {
    let w = world(|s| {
        s.rotate = true;
        s.delay_ms = 500;
    })
    .await;
    let ctx = Arc::clone(&w.ctx);
    // The daemon's own runtime (the mock runs on the test's): a call starts
    // a refresh, then `serve` returns and the caller is gone.
    let left = tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let c = Arc::clone(&ctx);
            let call = tokio::spawn(async move {
                let req = IpcRequest {
                    id: 1,
                    op: "api.call".into(),
                    args: json!({"service": "sf", "operation": "limits"})
                        .as_object()
                        .unwrap()
                        .clone(),
                };
                saiife_daemon::ops::dispatch(&c, &peer(), req).await
            });
            while ctx.oauth.in_flight() == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            call.abort();
        });
        let left = ctx.oauth.in_flight();
        // What `start` does before `shutdown_timeout`.
        assert!(rt.block_on(ctx.oauth.drain(saiife_daemon::oauth::DRAIN)));
        rt.shutdown_timeout(Duration::from_secs(1));
        left
    })
    .await
    .unwrap();
    assert_eq!(left, 1, "the refresh was in flight at shutdown");
    assert_eq!(w.posts(), vec![initial_refresh()]);
    assert_eq!(w.vault_refresh(), format!("rt-rot-1-{}", "c3".repeat(8)));
    assert!(w.api().is_empty(), "the caller was gone");
}

/// Set in the child run of [`tokens_never_in_records_errors_or_stderr`].
const LEAK_CHILD: &str = "SAIIFE_OAUTH2_LEAK_CHILD";

/// Every token value could appear in the daemon's stderr; the test binary
/// runs this test again as a child (`--nocapture`, so `eprintln!` reaches
/// the real stderr) and reads what it wrote.
#[test]
fn tokens_never_in_records_errors_or_stderr() {
    if std::env::var_os(LEAK_CHILD).is_some() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(leak_scenario());
        return;
    }
    let o = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "tokens_never_in_records_errors_or_stderr",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(LEAK_CHILD, "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&o.stderr).into_owned();
    let stdout = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(o.status.success(), "child failed:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("1 passed"),
        "the child ran nothing:\n{stdout}"
    );
    // The persist failure was said, by name.
    assert!(
        stderr.contains(&format!(
            "{SECRET}: rotated refresh token not persisted; do not restart the daemon"
        )),
        "{stderr}"
    );
    let mut needles: Vec<String> = vec![client_secret(), initial_refresh()];
    for n in 1..=20 {
        needles.push(format!("at-{n}-{}", "q7".repeat(8)));
        needles.push(format!("rt-rot-{n}-{}", "c3".repeat(8)));
    }
    for n in &needles {
        assert!(!stderr.contains(n.as_str()), "{n} leaked to stderr");
        assert!(!stdout.contains(n.as_str()), "{n} leaked to stdout");
    }
}

async fn leak_scenario() {
    let w = world(|s| s.rotate = true).await;
    let mut answers = Vec::new();
    answers.push(w.call().await);
    // A 401 and a forced refresh with a second rotation.
    w.st.lock().unwrap().current = String::new();
    answers.push(w.call().await);
    // A failing refresh.
    w.st.lock().unwrap().always_401 = true;
    w.st.lock().unwrap().token_status = 500;
    answers.push(w.call().await);
    // A persist failure.
    w.st.lock().unwrap().token_status = 200;
    w.ctx.oauth.forget(SECRET);
    std::fs::create_dir(w.vault_dir.join(".vault.bin.tmp")).unwrap();
    answers.push(w.call().await);

    let st = w.st.lock().unwrap();
    let mut needles: Vec<String> = vec![client_secret(), initial_refresh()];
    for n in 1..=st.posts.len() {
        needles.push(format!("at-{n}-{}", "q7".repeat(8)));
        needles.push(format!("rt-rot-{n}-{}", "c3".repeat(8)));
    }
    drop(st);
    let mut hay = w.audit_text();
    for a in &answers {
        hay.push_str(&a.to_string());
        if a["body_b64"].is_string() {
            hay.push_str(&body(a));
        }
    }
    hay.push_str(&format!("{:?}", w.ctx.oauth));
    for e in w.ctx.notifier.queued_events() {
        hay.push_str(&format!("{e:?}"));
    }
    for n in &needles {
        assert!(!hay.contains(n.as_str()), "{n} leaked");
    }
    assert!(w.refresh_failed().len() >= 2);
}

#[tokio::test]
async fn rotate_drops_cache() {
    let w = world(|_| {}).await;
    assert_eq!(status(&w.call().await), 200);
    assert_eq!(status(&w.call().await), 200);
    assert_eq!(w.posts().len(), 1);
    let fresh = format!("rt-admin-{}", "9d".repeat(8));
    let a = w
        .op(
            "secret.rotate",
            json!({"name": SECRET, "fields": {
                "client_id": "cid-test",
                "client_secret": client_secret(),
                "refresh_token": fresh,
            }}),
        )
        .await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(status(&w.call().await), 200);
    assert_eq!(w.posts(), vec![initial_refresh(), fresh]);
}

#[tokio::test]
async fn secret_add_oauth2_fields() {
    let w = world(|_| {}).await;
    let rt = format!("rt-new-{}", "e1".repeat(8));
    let a = w
        .op(
            "secret.add",
            json!({"name": "sf2", "kind": "oauth2", "allowed_services": ["sf"], "fields": {
                "client_id": "c1",
                "client_secret": client_secret(),
                "refresh_token": rt,
            }}),
        )
        .await;
    assert_eq!(a["ok"], true, "{a}");
    let l = w.op("secret.list", json!({})).await;
    let e = l["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "sf2")
        .cloned()
        .unwrap();
    assert_eq!(e["kind"], "oauth2");
    // Missing a field: refused, without echoing values.
    let a = w
        .op(
            "secret.add",
            json!({"name": "sf3", "kind": "oauth2", "allowed_services": ["sf"], "fields": {
                "client_id": "c1", "refresh_token": rt,
            }}),
        )
        .await;
    assert_eq!(a["ok"], false);
    assert!(!a.to_string().contains(&rt), "{a}");
    // Never leased: the refresh token stays with the daemon.
    let st = w
        .op("secret.lease", json!({"name": "sf2", "exe": "/bin/true"}))
        .await;
    assert_eq!(st["ok"], false, "{st}");
    assert!(!st.to_string().contains(&rt));
}
