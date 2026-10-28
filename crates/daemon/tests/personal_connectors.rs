//! Plan 14's connectors under the personal broker (plan 16), end to end in
//! process: a daemon context of mode `Personal` whose policy is loaded the
//! way the broker loads it (`personal::apply`, `check_services_owned` with
//! the user's own uid, `from_loaded_in(.., Personal)`), a vault opened with
//! a key as the keychain hands it over (`vault::open_with_key`), and
//! loopback mocks: HTTPS for Salesforce (the OAuth2 token endpoint and the
//! API) and SMTP/IMAP for Email. Calls go through `api.call` as a client
//! sends them.
//!
//! No keychain and no session bus take part: the broker reads its vault key
//! before the runtime starts and drops the keychain, so neither the OAuth2
//! token cache nor the mail transport can reach one. Nothing leaves
//! 127.0.0.1.
#![cfg(target_os = "linux")]

#[allow(dead_code)]
#[path = "../../broker/tests/common/mail_mock.rs"]
mod mail_mock;

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use mail_mock::{imap_server, pki, smtp_server, Imap, Smtp};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use saiife_audit::{ChainWriter, WriterOptions};
use saiife_broker::upstream::{Resolver, Upstream};
use saiife_daemon::ops::{check_services_owned, Ctx, CtxInit, Mode, PolicyState};
use saiife_daemon::personal::{self, PersonalCfg};
use saiife_daemon::vault::{self, Entry, Kind, VaultState};
use saiife_daemon::writer::{self, WriterConfig};
use saiife_ipc::msg::Request as IpcRequest;
use saiife_ipc::peer::PeerCred;
use saiife_policy::{Directory, Fsync, GroupEntry, UserEntry};
use serde_json::{json, Value};
use std::convert::Infallible;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use zeroize::Zeroizing;

const SF_HOST: &str = "acme.my.salesforce.com";
const KEY: [u8; 32] = [9u8; 32];

fn client_secret() -> String {
    format!("cs-{}", "p4".repeat(10))
}

fn initial_refresh() -> String {
    format!("rt-initial-{}", "8d".repeat(8))
}

fn rotated_refresh() -> String {
    format!("rt-rotated-{}", "e1".repeat(8))
}

fn access_token() -> String {
    format!("at-{}", "w2".repeat(10))
}

// ------------------------------------------------------- Salesforce mock

#[derive(Default)]
struct Sf {
    /// The refresh token of each token POST.
    posts: Vec<String>,
    /// The bearer of each API request, with its path.
    api: Vec<(String, String)>,
}

type Shared = Arc<Mutex<Sf>>;

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

async fn sf_answer(
    req: Request<Incoming>,
    st: Shared,
) -> Result<Response<Full<Bytes>>, Infallible> {
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
        let form = String::from_utf8_lossy(&body).into_owned();
        st.lock()
            .unwrap()
            .posts
            .push(form_field(&form, "refresh_token"));
        let o = json!({
            "access_token": access_token(),
            "token_type": "Bearer",
            "instance_url": format!("https://{SF_HOST}"),
            "refresh_token": rotated_refresh(),
        });
        return Ok(json(200, o.to_string()));
    }
    let bearer = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
        .to_string();
    st.lock()
        .unwrap()
        .api
        .push((parts.uri.path().to_string(), bearer.clone()));
    if bearer != access_token() {
        return Ok(json(401, r#"[{"errorCode":"INVALID_SESSION_ID"}]"#.into()));
    }
    Ok(json(
        200,
        r#"{"encoding":"UTF-8","maxBatchSize":200,"sobjects":[{"name":"Account"}]}"#.into(),
    ))
}

/// The HTTPS mock (its CA, its port).
async fn sf_mock(st: Shared) -> (CertificateDer<'static>, u16) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![SF_HOST.to_string()])
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
                let svc = service_fn(move |req| sf_answer(req, st.clone()));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    (ca.der().clone(), port)
}

/// Salesforce's host at the HTTPS mock; `*.mail.test` at the port asked
/// for (the mail mocks).
struct Loopback(u16);

impl Resolver for Loopback {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        if host == SF_HOST {
            Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, self.0))])
        } else if host.ends_with(".mail.test") {
            Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, port))])
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "unknown test host"))
        }
    }
}

// ---------------------------------------------------------------- broker

/// The user (`me`, the context's own) is in no group.
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
        Vec::new()
    }
}

struct World {
    ctx: Arc<Ctx>,
    sf: Shared,
    smtp_log: Arc<mail_mock::Log>,
    audit: PathBuf,
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

fn fields(kv: &[(&str, String)]) -> std::collections::BTreeMap<String, Zeroizing<String>> {
    kv.iter()
        .map(|(k, v)| (k.to_string(), Zeroizing::new(v.clone())))
        .collect()
}

fn entry(name: &str, kind: Kind, f: &[(&str, String)], service: &str) -> Entry {
    Entry {
        name: name.into(),
        kind,
        fields: fields(f),
        allowed_services: vec![service.into()],
        created_by: rustix::process::getuid().as_raw(),
        created: "2026-10-28T00:00:00Z".into(),
        last_used: None,
        rotate_after: None,
    }
}

/// A personal broker config: no `[[scope]]` (the implicit `personal`
/// scope lists both services), no `locked`.
fn config_text(smtp: u16, imap: u16) -> String {
    format!(
        r#"version = 2

[services.sf]
connector = "salesforce"
secret = "sf-oauth"
params = {{ instance_host = "{SF_HOST}", api_version = "v60.0" }}
allow = ["sobjects:read"]

[services.mail]
connector = "email"
secret = "mailbox"
params = {{ smtp_host = "smtp.mail.test", smtp_port = "{smtp}", smtp_tls = "implicit", imap_host = "imap.mail.test", imap_port = "{imap}", imap_tls = "implicit", from = "bot@acme.com" }}
allow = ["mail:write", "folders:read"]
"#
    )
}

async fn world() -> World {
    let tmp = scratch();
    let audit = tmp.path().join("audit");
    let state = tmp.path().join("state");
    let run = tmp.path().join("run");
    for d in [&audit, &state, &run, &tmp.path().join("proc")] {
        std::fs::create_dir_all(d).unwrap();
    }
    let uid = rustix::process::getuid().as_raw();

    // The mocks first: the config names their ports.
    let p = pki();
    let (smtp, smtp_log) = smtp_server(&p, Smtp::Implicit).await;
    let (imap, _) = imap_server(&p, Imap::Implicit).await;
    let sf: Shared = Arc::default();
    let (sf_ca, sf_port) = sf_mock(sf.clone()).await;
    let mut roots = p.roots.clone();
    roots.add(sf_ca).unwrap();
    let up = Upstream::with_roots(roots, Arc::new(Loopback(sf_port)), Duration::from_secs(5));

    // The policy as `start::load_policy` loads it for the broker.
    let config = tmp.path().join("config.toml");
    let text = config_text(smtp, imap);
    std::fs::write(&config, &text).unwrap();
    let pc = PersonalCfg {
        own_user: "me".into(),
        own_uid: uid,
        socket_dir: run.clone(),
        audit_dir: audit.clone(),
    };
    let mut l = saiife_policy::load_system(&config).unwrap();
    let raw: toml::Table = text.parse().unwrap();
    let warnings = personal::apply(&mut l.config, &raw, &pc, &Dir);
    assert!(warnings.is_empty(), "{warnings:?}");
    let cat = check_services_owned(&l, &config, uid).unwrap();
    let policy = PolicyState::from_loaded_in(&l, &[], cat, Mode::Personal);
    assert!(policy.ok);

    // The vault under the keychain's key, as the broker opens it.
    let vault_file = state.join("vault").join("vault.bin");
    let mut vault = vault::open_with_key(Zeroizing::new(KEY), &vault_file);
    let VaultState::Ready(v) = &mut vault else {
        panic!("vault not ready");
    };
    v.put(entry(
        "sf-oauth",
        Kind::OAuth2,
        &[
            ("client_id", "cid-test".into()),
            ("client_secret", client_secret()),
            ("refresh_token", initial_refresh()),
        ],
        "sf",
    ))
    .unwrap();
    v.put(entry(
        "mailbox",
        Kind::Basic,
        &[
            ("username", mail_mock::USER.into()),
            ("password", mail_mock::pass()),
        ],
        "mail",
    ))
    .unwrap();

    let cw = ChainWriter::open(
        &audit,
        WriterOptions {
            mode: Mode::Personal.as_str().into(),
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
    let ctx = Arc::new(Ctx::new(CtxInit {
        mode: Mode::Personal,
        own_user: "me".into(),
        audit_dir: audit.clone(),
        socket_dir: run,
        config_path: config,
        policy,
        vault,
        vault_path: vault_file.clone(),
        upstream: Ok(up),
        lockdown: saiife_daemon::lockdown::Store::memory(),
        grants: saiife_daemon::grants::Grants::memory(),
        ..CtxInit::minimal(handle, wcfg, Arc::new(Dir), &state)
    }));
    World {
        ctx,
        sf,
        smtp_log,
        audit,
        vault_file,
        _tmp: tmp,
    }
}

fn me() -> PeerCred {
    PeerCred {
        uid: rustix::process::getuid().as_raw(),
        gid: rustix::process::getgid().as_raw(),
        pid: std::process::id(),
    }
}

impl World {
    async fn call(&self, args: Value) -> Value {
        let req = IpcRequest {
            id: 1,
            op: "api.call".into(),
            args: args.as_object().unwrap().clone(),
        };
        saiife_daemon::ops::dispatch(&self.ctx, &me(), req).await
    }

    fn audit_text(&self) -> String {
        let mut s = String::new();
        for e in std::fs::read_dir(&self.audit).unwrap() {
            s.push_str(&std::fs::read_to_string(e.unwrap().path()).unwrap_or_default());
        }
        s
    }

    fn connector_records(&self) -> Vec<Value> {
        self.audit_text()
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|v| v["kind"] == "connector")
            .collect()
    }
}

fn vault_field(file: &Path, name: &str, field: &str) -> String {
    match vault::open_with_key(Zeroizing::new(KEY), file) {
        VaultState::Ready(v) => v
            .get(name)
            .and_then(|e| e.fields.get(field).map(|r| r.to_string()))
            .unwrap_or_default(),
        VaultState::Unavailable(r) => panic!("vault: {r}"),
    }
}

fn body(a: &Value) -> Value {
    use base64::Engine as _;
    let b = base64::engine::general_purpose::STANDARD
        .decode(a["body_b64"].as_str().unwrap())
        .unwrap();
    serde_json::from_slice(&b).unwrap()
}

fn secrets() -> Vec<String> {
    vec![
        client_secret(),
        initial_refresh(),
        rotated_refresh(),
        access_token(),
        mail_mock::pass(),
        mail_mock::auth_b64(),
    ]
}

// ----------------------------------------------------------------- tests

/// Salesforce (OAuth2) through the personal broker: the broker refreshes
/// the access token itself, keeps it in memory, persists the rotated
/// refresh token to the key-sealed vault before using it, and reuses the
/// cached token on the next call.
#[tokio::test]
async fn personal_broker_runs_salesforce_oauth2_call() {
    let w = world().await;
    let a = w
        .call(json!({"service": "sf", "operation": "sobjects.list"}))
        .await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a["status"], 200, "{a}");
    assert_eq!(body(&a)["sobjects"][0]["name"], "Account");
    let a = w
        .call(json!({"service": "sf", "operation": "sobjects.list"}))
        .await;
    assert_eq!(a["status"], 200, "{a}");
    {
        let sf = w.sf.lock().unwrap();
        // One refresh, with the vault's refresh token; the cached access
        // token served both calls.
        assert_eq!(sf.posts, vec![initial_refresh()]);
        assert_eq!(sf.api.len(), 2);
        for (path, bearer) in &sf.api {
            assert_eq!(path, "/services/data/v60.0/sobjects");
            assert_eq!(bearer, &access_token());
        }
    }
    // The rotated refresh token is in the vault; the access token is not.
    assert_eq!(
        vault_field(&w.vault_file, "sf-oauth", "refresh_token"),
        rotated_refresh()
    );
    let raw = std::fs::read(&w.vault_file).unwrap();
    for s in secrets() {
        assert!(!raw.windows(s.len()).any(|x| x == s.as_bytes()));
    }
    let recs = w.connector_records();
    assert_eq!(recs.len(), 2, "{recs:?}");
    assert_eq!(recs[0]["decision"], "allow", "{}", recs[0]);
    assert_eq!(recs[0]["secret"], "sf-oauth");
    assert_eq!(recs[0]["uid"], json!(rustix::process::getuid().as_raw()));
    let text = w.audit_text();
    for s in secrets() {
        assert!(!text.contains(&s), "the audit holds a secret");
    }
}

/// Email (SMTP send, IMAP read) through the personal broker: the mail
/// transport runs with the vault's basic secret, and nothing secret reaches
/// the audit.
#[tokio::test]
async fn personal_broker_runs_email_send_and_read() {
    let w = world().await;
    let a = w
        .call(json!({"service": "mail", "operation": "mail.send",
                     "params": {"to": "a@acme.com", "subject": "Weekly report"},
                     "body_b64": "SGVsbG8K"}))
        .await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(body(&a), json!({"sent": true, "to": "a@acme.com"}));
    assert!(
        w.smtp_log.any(|l| l == "MAIL FROM:<bot@acme.com>"),
        "{:?}",
        w.smtp_log.lines()
    );
    let a = w
        .call(json!({"service": "mail", "operation": "folders.list"}))
        .await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(body(&a)["folders"][0]["name"], "INBOX");
    // `mail:read` is in no list: denied, as in locked mode.
    let a = w
        .call(json!({"service": "mail", "operation": "mail.list",
                     "params": {"folder": "INBOX"}}))
        .await;
    assert_eq!(a["ok"], false, "{a}");
    let recs = w.connector_records();
    assert_eq!(recs.len(), 3, "{recs:?}");
    assert_eq!(recs[0]["capability"], "mail:write:to=a@acme.com");
    assert_eq!(recs[0]["decision"], "allow");
    assert_eq!(recs[2]["decision"], "deny");
    let text = w.audit_text();
    for s in secrets() {
        assert!(!text.contains(&s), "the audit holds a secret");
    }
}
