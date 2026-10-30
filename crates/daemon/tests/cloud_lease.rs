//! STS mode (plan 15, Task 10): `cloud.lease {service, exe}` in process. A
//! daemon context on temp dirs (the real audit writer and vault), the
//! built-in `aws-s3` manifest, and a loopback TLS mock of STS with an
//! `rcgen` certificate for the real host name. The test resolver maps it to
//! 127.0.0.1; nothing leaves the host.
#![cfg(unix)]

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
use saiife_broker::cloud::session_policy;
use saiife_broker::limits::Limiter;
use saiife_broker::pipeline::{LockScope, Lockdown};
use saiife_broker::upstream::{Resolver, Upstream};
use saiife_broker::{Catalog, Manifest};
use saiife_daemon::ops::{Ctx, CtxInit, GatewayPolicy, Mode as DaemonMode, PolicyState};
use saiife_daemon::sessions::RealProc;
use saiife_daemon::tokens::Tokens;
use saiife_daemon::vault::{self, Entry, Kind, VaultState};
use saiife_daemon::writer::{self, WriterConfig};
use saiife_ipc::msg::Request as IpcRequest;
use saiife_ipc::peer::PeerCred;
use saiife_policy::{Directory, Fsync, GroupEntry, Mode, SystemConfig, UserEntry};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use zeroize::Zeroizing;

const STS_HOST: &str = "sts.eu-west-1.amazonaws.com";
const ROLE: &str = "arn:aws:iam::123456789012:role/saiife-lease";
const EXTERNAL: &str = "ext-lease-42";
/// A root-owned, non-interpreter program, by its canonical path: on some
/// hosts `/usr/bin/true` is a symlink (a multicall coreutils), and a lease
/// refuses an exe path that is not canonical.
fn exe() -> &'static str {
    static EXE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    EXE.get_or_init(|| {
        std::fs::canonicalize("/usr/bin/true")
            .unwrap()
            .to_string_lossy()
            .into_owned()
    })
}

/// A lease is only granted for an exe with a root-owned chain. In a user
/// namespace (the offline CI job) `/` is owned by the overflow uid, so the
/// tests that need a granted lease skip there, as the run_cmd tests do.
macro_rules! need_root_chain {
    () => {
        if saiife_system::fsops::root_owned_chain(std::path::Path::new(exe())).is_err() {
            eprintln!("skipped: {} has no root-owned chain here", exe());
            return;
        }
    };
}

// Built at runtime: no token-shaped literal in the source.
const VAULT_AK: &str = concat!("AK", "IA", "TESTVAULT0000002");
const VAULT_SK: &str = concat!("vaultSecret", "Key/1234567890", "lEaSeKEY+abc");
const STAGING_AK: &str = concat!("AK", "IA", "TESTSTAGE0000003");
const STAGING_SK: &str = concat!("stagingSecret", "Key/1234567890", "sTaGeKEY+abc");
const PROD_AK: &str = concat!("AK", "IA", "TESTPROD00000004");
const PROD_SK: &str = concat!("prodSecret", "Key/1234567890", "pRoDkEy+abcdef");
const SESSION_AK: &str = concat!("AS", "IA", "TESTLEASE000001");
const SESSION_SK: &str = concat!("leaseSecret", "Key/0987654321", "QwErTyUi");
const SESSION_TOKEN: &str = concat!("leaseSession", "EXAMPLEsession", "TokenValue7777==");
/// What the STS error message says; it must never be recorded or answered.
const STS_MESSAGE: &str = "User is not authorized to perform sts:AssumeRole on the lease role";

fn secret_values() -> [&'static str; 9] {
    [
        VAULT_AK,
        VAULT_SK,
        STAGING_AK,
        STAGING_SK,
        PROD_AK,
        PROD_SK,
        SESSION_AK,
        SESSION_SK,
        SESSION_TOKEN,
    ]
}

/// The `allow` of `s3sts` in the `staging` environment: narrower than the
/// base `s3:read`.
const STAGING_ALLOW: &str = "s3:read:arn:aws:s3:::reports/**";

// ---------------------------------------------------------------- mock

#[derive(Default)]
struct State {
    /// The form of each STS call, and the access key id that signed it.
    sts: Vec<(BTreeMap<String, String>, String)>,
    status: u16,
}

type Shared = Arc<Mutex<State>>;

struct Loopback(u16);

impl Resolver for Loopback {
    fn resolve(&self, host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
        if host == STS_HOST {
            Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, self.0))])
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "unknown test host"))
        }
    }
}

fn form(body: &[u8]) -> BTreeMap<String, String> {
    String::from_utf8_lossy(body)
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| {
            (
                k.to_string(),
                percent_encoding::percent_decode_str(v)
                    .decode_utf8_lossy()
                    .into_owned(),
            )
        })
        .collect()
}

fn sts_xml() -> String {
    format!(
        r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>{SESSION_AK}</AccessKeyId>
      <SecretAccessKey>{SESSION_SK}</SecretAccessKey>
      <SessionToken>{SESSION_TOKEN}</SessionToken>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>
"#
    )
}

async fn answer(req: Request<Incoming>, st: Shared) -> Result<Response<Full<Bytes>>, Infallible> {
    let (parts, body) = req.into_parts();
    let body = body
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let reply = |status: u16, b: String| {
        Response::builder()
            .status(status)
            .header("content-type", "text/xml")
            .body(Full::new(Bytes::from(b)))
            .unwrap()
    };
    let akid = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|a| a.split("Credential=").nth(1))
        .and_then(|c| c.split('/').next())
        .unwrap_or_default()
        .to_string();
    let mut s = st.lock().unwrap();
    s.sts.push((form(&body), akid));
    if s.status != 200 {
        // The message echoes the vault key: neither may be recorded.
        return Ok(reply(
            s.status,
            format!(
                "<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code>\
                 <Message>{STS_MESSAGE} ({VAULT_SK})</Message></Error></ErrorResponse>"
            ),
        ));
    }
    Ok(reply(200, sts_xml()))
}

async fn mock(st: Shared) -> Upstream {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![STS_HOST.to_string()])
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
    Upstream::with_roots(roots, Arc::new(Loopback(port)), Duration::from_secs(30))
}

// ---------------------------------------------------------------- daemon

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
    st: Shared,
    audit: PathBuf,
    config: SystemConfig,
    tmp: tempfile::TempDir,
}

fn scratch() -> tempfile::TempDir {
    let base = std::env::var_os("SAIIFE_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    std::fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

fn s3_manifest() -> Manifest {
    let text = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../broker/connectors/aws-s3.toml"),
    )
    .unwrap();
    Manifest::parse(&text).unwrap()
}

/// `link` is a `run_allow` entry that is a symlink to an interpreter;
/// `scope_env` binds the caller's scope to an environment. Two
/// environments override `s3sts`: `staging` (its own secret, a narrower
/// allow) and `prod` (its own secret).
fn config(link: &Path, scope_env: Option<&str>) -> String {
    let exe = exe();
    let scope_env = scope_env
        .map(|e| format!("env = \"{e}\"\n"))
        .unwrap_or_default();
    format!(
        r#"version = 2
locked = true

[[scope]]
name = "agents"
users = ["agent"]
services = ["s3sts", "s3sign", "s3link", "s3rpm", "s3unrep"]
{scope_env}
[environments.staging.services.s3sts]
secret = "aws-staging"
allow = ["{STAGING_ALLOW}"]

[environments.prod.services.s3sts]
secret = "aws-prod"

[services.s3unrep]
connector = "aws-s3"
secret = "aws-keys"
params = {{ region = "eu-west-1" }}
mode = "sts"
# A single `*` stays within one `/` level in saiife, not in IAM.
allow = ["s3:read:arn:aws:s3:::rep*"]
limits = {{ requests_per_minute = 1 }}
[services.s3unrep.cloud]
role_arn = "{ROLE}"
run_allow = ["{exe}"]

[services.s3sts]
connector = "aws-s3"
secret = "aws-keys"
params = {{ region = "eu-west-1" }}
mode = "sts"
allow = ["s3:read"]
deny = ["s3:delete"]
[services.s3sts.cloud]
role_arn = "{ROLE}"
external_id = "{EXTERNAL}"
run_allow = ["{exe}"]

[services.s3rpm]
connector = "aws-s3"
secret = "aws-keys"
params = {{ region = "eu-west-1" }}
mode = "sts"
allow = ["s3:read"]
limits = {{ requests_per_minute = 2, writes_per_hour = 1 }}
[services.s3rpm.cloud]
role_arn = "{ROLE}"
run_allow = ["{exe}"]

[services.s3sign]
connector = "aws-s3"
secret = "aws-keys"
params = {{ region = "eu-west-1" }}
allow = ["s3:read"]
[services.s3sign.cloud]
role_arn = "{ROLE}"
run_allow = ["{exe}"]

[services.s3out]
connector = "aws-s3"
secret = "aws-keys"
params = {{ region = "eu-west-1" }}
mode = "sts"
allow = ["s3:read"]
[services.s3out.cloud]
role_arn = "{ROLE}"
run_allow = ["{exe}"]

[services.s3link]
connector = "aws-s3"
secret = "aws-keys"
params = {{ region = "eu-west-1" }}
mode = "sts"
allow = ["s3:read"]
[services.s3link.cloud]
role_arn = "{ROLE}"
run_allow = ["{link}"]
"#,
        link = link.display()
    )
}

async fn world(status: u16) -> World {
    world_in(scratch(), status, Limiter::new()).await
}

/// A daemon on `tmp` (fresh, or the dirs of a stopped one: a restart),
/// with `limiter`.
async fn world_in(tmp: tempfile::TempDir, status: u16, limiter: Limiter) -> World {
    world_setup(tmp, status, limiter, DaemonMode::Locked, None).await
}

/// A daemon of `mode` (locked, or the personal broker), its scope bound to
/// `scope_env`.
async fn world_setup(
    tmp: tempfile::TempDir,
    status: u16,
    limiter: Limiter,
    mode: DaemonMode,
    scope_env: Option<&str>,
) -> World {
    let audit = tmp.path().join("audit");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&audit).unwrap();
    std::fs::create_dir_all(tmp.path().join("proc")).unwrap();
    std::fs::create_dir_all(tmp.path().join("run")).unwrap();
    let link = tmp.path().join("s3tool");
    if !link.exists() {
        std::os::unix::fs::symlink("/usr/bin/bash", &link).unwrap();
    }
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
    // The key is the daemon's own and private (macOS checks it).
    std::fs::set_permissions(
        &key_file,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
    )
    .unwrap();
    let vault_file = state.join("vault").join("vault.bin");
    let mut vault = vault::open(&key_file, &vault_file);
    let VaultState::Ready(v) = &mut vault else {
        panic!("vault not ready");
    };
    // Every service may use `aws-keys`; `s3out` is out of the caller's
    // scope. The environments' secrets are for `s3sts`.
    let all: &[&str] = &["s3sts", "s3sign", "s3out", "s3link", "s3rpm", "s3unrep"];
    for (name, ak, sk, services) in [
        ("aws-keys", VAULT_AK, VAULT_SK, all),
        ("aws-staging", STAGING_AK, STAGING_SK, &["s3sts"][..]),
        ("aws-prod", PROD_AK, PROD_SK, &["s3sts"][..]),
    ] {
        v.put(Entry {
            name: name.into(),
            kind: Kind::Aws,
            fields: [("access_key_id", ak), ("secret_access_key", sk)]
                .iter()
                .map(|(k, v)| (k.to_string(), Zeroizing::new(v.to_string())))
                .collect(),
            allowed_services: services.iter().map(|s| s.to_string()).collect(),
            created_by: 0,
            created: "2026-10-28T00:00:00Z".into(),
            last_used: None,
            rotate_after: None,
        })
        .unwrap();
    }

    let config: SystemConfig = toml::from_str(&config(&link, scope_env)).unwrap();
    let gateway = GatewayPolicy::build(
        &config,
        &[],
        Catalog::new(&[], vec![s3_manifest()]),
        mode.policy_mode(),
    )
    .unwrap();
    let policy = PolicyState {
        hash: Some("sha256:test".into()),
        ok: true,
        min_free_mb: 0,
        admin_groups: vec![],
        system: Some(Arc::new(config.clone())),
        gateway: Some(Arc::new(gateway)),
    };
    let st: Shared = Arc::new(Mutex::new(State {
        status,
        ..State::default()
    }));
    let up = mock(st.clone()).await;
    let ctx = Arc::new(Ctx::new(CtxInit {
        mode,
        own_user: "agent".into(),
        audit_dir: audit.clone(),
        socket_dir: tmp.path().join("run"),
        key_path: state.join("keys/audit.ed25519"),
        config_path: tmp.path().join("config.toml"),
        catalog: Vec::new(),
        policy,
        proc: Box::new(RealProc::new(tmp.path().join("proc"))),
        vault,
        vault_path: vault_file,
        backup_dir: state.join("import-backup"),
        limiter,
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
        config,
        tmp,
    }
}

fn uid() -> u32 {
    rustix::process::getuid().as_raw()
}

fn peer() -> PeerCred {
    PeerCred {
        uid: uid(),
        gid: rustix::process::getgid().as_raw(),
        pid: std::process::id(),
    }
}

impl World {
    async fn lease(&self, service: &str, exe: &str) -> Value {
        self.lease_with(json!({"service": service, "exe": exe}))
            .await
    }

    async fn lease_with(&self, args: Value) -> Value {
        let req = IpcRequest {
            id: 1,
            op: "cloud.lease".into(),
            args: args.as_object().unwrap().clone(),
        };
        saiife_daemon::ops::dispatch(&self.ctx, &peer(), req).await
    }

    /// The `Policy` of each STS call, in order.
    fn policies_sent(&self) -> Vec<String> {
        self.st
            .lock()
            .unwrap()
            .sts
            .iter()
            .map(|(f, _)| f.get("Policy").cloned().unwrap_or_default())
            .collect()
    }

    fn audit_text(&self) -> String {
        let mut s = String::new();
        for e in std::fs::read_dir(&self.audit).unwrap() {
            s.push_str(&std::fs::read_to_string(e.unwrap().path()).unwrap_or_default());
        }
        s
    }

    fn leases(&self) -> Vec<Value> {
        self.audit_text()
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|v| v["kind"] == "secret" && v["event"] == "cloud_lease")
            .collect()
    }

    fn sts_calls(&self) -> usize {
        self.st.lock().unwrap().sts.len()
    }

    fn assert_records_clean(&self) {
        let text = self.audit_text();
        for s in secret_values() {
            assert!(!text.contains(s), "a credential value is in a record");
        }
        assert!(!text.contains(STS_MESSAGE), "an STS message is in a record");
    }
}

fn rule(a: &Value) -> String {
    assert_eq!(a["ok"], false, "{a}");
    a["rule"].as_str().unwrap_or_default().to_string()
}

/// A refused lease: the rule, no STS call, one deny record with that rule
/// and no value anywhere.
async fn refused(w: &World, service: &str, exe: &str, want: &str) -> Value {
    let a = w.lease(service, exe).await;
    assert_eq!(rule(&a), want, "{a}");
    assert_eq!(w.sts_calls(), 0, "a refused lease called STS");
    let recs = w.leases();
    assert_eq!(recs.len(), 1, "{recs:?}");
    assert_eq!(recs[0]["decision"], "deny");
    assert_eq!(recs[0]["rule"], want);
    assert_eq!(recs[0]["service"], service);
    w.assert_records_clean();
    a
}

// ---------------------------------------------------------------- tests

#[tokio::test]
async fn lease_requires_sts_mode() {
    let w = world(200).await;
    refused(&w, "s3sign", exe(), "sts_not_enabled").await;
}

#[tokio::test]
async fn lease_exe_not_listed_refused() {
    let w = world(200).await;
    let a = refused(&w, "s3sts", "/usr/bin/false", "exe_not_allowed").await;
    let m = a["message"].as_str().unwrap_or_default();
    assert!(
        m.contains("cloud.run_allow") && !m.contains("secret"),
        "{m}"
    );
}

#[tokio::test]
async fn lease_run_allow_symlink_to_interpreter_refused() {
    let w = world(200).await;
    let link = w.tmp.path().join("s3tool");
    // The listed link itself, as a client that does not resolve it sends it.
    let a = refused(&w, "s3link", link.to_str().unwrap(), "exe_not_allowed").await;
    assert!(
        a["message"]
            .as_str()
            .unwrap_or_default()
            .contains("interpreter"),
        "{a}"
    );
    // The link's target, as `saiife run` sends it (canonical).
    let a = w.lease("s3link", "/usr/bin/bash").await;
    assert_eq!(rule(&a), "exe_not_allowed", "{a}");
    assert_eq!(w.sts_calls(), 0);
}

#[tokio::test]
async fn lease_outside_scope_no_scope() {
    let w = world(200).await;
    refused(&w, "s3out", exe(), "no_scope").await;
    // A service that is not defined at all: the same.
    let a = w.lease("nosuch", exe()).await;
    assert_eq!(rule(&a), "no_scope", "{a}");
}

#[tokio::test]
async fn lease_during_lockdown_denied() {
    let w = world(200).await;
    w.ctx
        .lockdown
        .set(Some(Lockdown {
            scope: LockScope::Connectors,
            reason: "incident".into(),
            by_uid: 0,
            since: "2026-10-29T00:00:00Z".into(),
        }))
        .unwrap();
    refused(&w, "s3sts", exe(), "lockdown").await;
}

#[tokio::test]
async fn lease_sends_session_policy_and_900s() {
    need_root_chain!();
    let w = world(200).await;
    let a = w.lease("s3sts", exe()).await;
    assert_eq!(a["ok"], true, "{a}");
    let calls = w.st.lock().unwrap().sts.clone();
    assert_eq!(calls.len(), 1);
    let (f, akid) = &calls[0];
    assert_eq!(akid, VAULT_AK, "signed with the vault keys");
    assert_eq!(f["Action"], "AssumeRole");
    assert_eq!(f["DurationSeconds"], "900");
    assert_eq!(f["RoleArn"], ROLE);
    assert_eq!(f["ExternalId"], EXTERNAL);
    let session = f["RoleSessionName"].clone();
    assert!(
        session.starts_with(&format!("saiife-{}-", uid())),
        "{session}"
    );
    // The policy is built from the config: the service's allow and deny.
    let svc = &w.config.services["s3sts"];
    let want = session_policy::build(svc, &s3_manifest(), None, Mode::Locked).unwrap();
    assert_eq!(f["Policy"], want.json);
    assert!(want.json.contains("s3:GetObject") && want.json.contains("s3:DeleteObject"));
    // The answer: the environment, the expiry and the session.
    let env = &a["env"];
    assert_eq!(env["AWS_ACCESS_KEY_ID"], SESSION_AK);
    assert_eq!(env["AWS_SECRET_ACCESS_KEY"], SESSION_SK);
    assert_eq!(env["AWS_SESSION_TOKEN"], SESSION_TOKEN);
    assert_eq!(env["AWS_REGION"], "eu-west-1");
    assert_eq!(env["AWS_DEFAULT_REGION"], "eu-west-1");
    assert_eq!(a["session"], session.as_str());
    // At most 900 s from now, whatever the answer's Expiration says
    // (`YYYY-MM-DDTHH:MM:SSZ`, so it compares as text).
    let at = |secs: i64| {
        let f = time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
        (time::OffsetDateTime::now_utc() + time::Duration::seconds(secs))
            .format(f)
            .unwrap()
    };
    let exp = a["expires"].as_str().unwrap();
    assert_eq!(exp.len(), "2026-10-29T00:00:00Z".len(), "{exp}");
    assert!(exp <= at(901).as_str() && exp > at(800).as_str(), "{exp}");
    let recs = w.leases();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["policy_sha256"], want.sha256);
}

#[tokio::test]
async fn lease_record_has_no_values() {
    need_root_chain!();
    let w = world(200).await;
    let a = w.lease("s3sts", exe()).await;
    assert_eq!(a["ok"], true, "{a}");
    let recs = w.leases();
    assert_eq!(recs.len(), 1, "one record per lease");
    let r = &recs[0];
    assert_eq!(r["decision"], "allow");
    assert_eq!(r["service"], "s3sts");
    assert_eq!(r["role_arn"], ROLE);
    assert_eq!(r["sts_session"], a["session"]);
    // `session` is the agent session (none here), never the STS name.
    assert!(r["session"].is_null(), "{r}");
    assert_eq!(r["expires"], a["expires"]);
    assert_eq!(r["exe"], exe());
    assert_eq!(r["policy_sha256"].as_str().unwrap().len(), 64);
    w.assert_records_clean();
}

#[tokio::test]
async fn lease_sts_error_code_recorded_message_not() {
    need_root_chain!();
    let w = world(403).await;
    let a = w.lease("s3sts", exe()).await;
    assert_eq!(rule(&a), "token_mint_failed", "{a}");
    let text = a.to_string();
    assert!(text.contains("AccessDenied"), "{a}");
    assert!(
        !text.contains(STS_MESSAGE) && !text.contains(VAULT_SK),
        "{a}"
    );
    let recs = w.leases();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["decision"], "deny");
    assert_eq!(recs[0]["rule"], "token_mint_failed");
    assert!(
        recs[0]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("AccessDenied"),
        "{}",
        recs[0]
    );
    w.assert_records_clean();
}

#[tokio::test]
async fn lease_counts_requests_per_minute() {
    need_root_chain!();
    let w = world(200).await;
    for _ in 0..2 {
        let a = w.lease("s3rpm", exe()).await;
        assert_eq!(a["ok"], true, "{a}");
    }
    let a = w.lease("s3rpm", exe()).await;
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["limit"], "requests_per_minute", "{a}");
    assert_eq!(w.sts_calls(), 2, "a limited lease called STS");
    let recs = w.leases();
    assert_eq!(recs.len(), 3);
    assert_eq!(recs[2]["decision"], "deny");
    assert_eq!(recs[2]["rule"], "requests_per_minute");
    // Leases of another service count apart.
    let a = w.lease("s3sts", exe()).await;
    assert_eq!(a["ok"], true, "{a}");
}

// ------------------------------------------------- fix round 1

/// The overlay as `saiife run --cloud` sends it for a service.
fn overlay_of(deny: &[&str]) -> saiife_policy::ServiceOverlay {
    saiife_policy::ServiceOverlay {
        allow: vec![],
        ask: vec![],
        deny: deny.iter().map(|s| s.to_string()).collect(),
    }
}

/// The statements of `json` with `effect`.
fn statements(json: &str, effect: &str) -> Vec<Value> {
    let d: Value = serde_json::from_str(json).unwrap();
    d["Statement"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["Effect"] == effect)
        .cloned()
        .collect()
}

#[tokio::test]
async fn project_deny_narrows_the_lease() {
    need_root_chain!();
    let w = world(200).await;
    let base = w.lease("s3sts", exe()).await;
    assert_eq!(base["ok"], true, "{base}");
    // The admin allows `s3:read`; the project denies one prefix of it.
    let deny = "s3:read:arn:aws:s3:::reports/secret/**";
    let a = w
        .lease_with(json!({"service": "s3sts", "exe": exe(), "overlay": {"deny": [deny]}}))
        .await;
    assert_eq!(a["ok"], true, "{a}");
    let svc = &w.config.services["s3sts"];
    let plain = session_policy::build(svc, &s3_manifest(), None, Mode::Locked).unwrap();
    let narrowed = session_policy::build(
        svc,
        &s3_manifest(),
        Some(&overlay_of(&[deny])),
        Mode::Locked,
    )
    .unwrap();
    let sent = w.policies_sent();
    assert_eq!(sent, [plain.json.clone(), narrowed.json.clone()]);
    // The extra statement is a Deny on the project's prefix (made at least
    // as wide: each letter becomes IAM's `?`, decision 10).
    let denies = statements(&sent[1], "Deny");
    assert_eq!(
        denies.len(),
        statements(&sent[0], "Deny").len() + 1,
        "{}",
        sent[1]
    );
    assert!(
        denies.iter().any(
            |s| s["Resource"] == json!(["arn:aws:s3:::???????/??????/*"])
                && s["Action"].to_string().contains("s3:GetObject")
        ),
        "{}",
        sent[1]
    );
    // The allows are the admin's, unchanged.
    assert_eq!(statements(&sent[0], "Allow"), statements(&sent[1], "Allow"));
    let recs = w.leases();
    assert_eq!(recs[0]["policy_sha256"], plain.sha256);
    assert_eq!(recs[1]["policy_sha256"], narrowed.sha256);
    assert_ne!(plain.sha256, narrowed.sha256);
}

#[tokio::test]
async fn project_allow_never_widens_the_lease() {
    need_root_chain!();
    let w = world(200).await;
    let a = w
        .lease_with(json!({"service": "s3sts", "exe": exe(),
                           "overlay": {"allow": ["s3:write", "s3:*"]}}))
        .await;
    assert_eq!(a["ok"], true, "{a}");
    let svc = &w.config.services["s3sts"];
    let plain = session_policy::build(svc, &s3_manifest(), None, Mode::Locked).unwrap();
    let sent = w.policies_sent();
    assert_eq!(
        sent,
        std::slice::from_ref(&plain.json),
        "an overlay allow changed the policy"
    );
    assert!(!sent[0].contains("s3:PutObject"), "{}", sent[0]);
    // A malformed overlay is a bad request: no lease, no STS call.
    let a = w
        .lease_with(json!({"service": "s3sts", "exe": exe(), "overlay": {"deny": "x"}}))
        .await;
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["error"], "bad_request", "{a}");
    assert_eq!(w.sts_calls(), 1);
}

#[tokio::test]
async fn lease_unrepresentable_policy_refused_without_sts_or_rpm() {
    need_root_chain!();
    let w = world(200).await;
    // `requests_per_minute = 1`: were the first refusal counted, the
    // second would be `limited`.
    for _ in 0..2 {
        let a = w.lease("s3unrep", exe()).await;
        assert_eq!(rule(&a), "session_policy_unrepresentable", "{a}");
        assert_eq!(a["error"], "denied", "{a}");
    }
    assert_eq!(w.sts_calls(), 0);
    let recs = w.leases();
    assert_eq!(recs.len(), 2);
    assert!(recs
        .iter()
        .all(|r| r["rule"] == "session_policy_unrepresentable"));
    w.assert_records_clean();
}

#[tokio::test]
async fn lease_too_large_policy_refused_without_sts_or_rpm() {
    need_root_chain!();
    let w = world(200).await;
    let deny: Vec<String> = (0..80)
        .map(|i| format!("s3:read:arn:aws:s3:::project-bucket-{i:03}/some/long/prefix/**"))
        .collect();
    // `s3rpm` allows 2 a minute: two refusals, then two leases.
    for _ in 0..2 {
        let a = w
            .lease_with(json!({"service": "s3rpm", "exe": exe(), "overlay": {"deny": deny}}))
            .await;
        assert_eq!(rule(&a), "session_policy_too_large", "{a}");
    }
    assert_eq!(w.sts_calls(), 0);
    for _ in 0..2 {
        let a = w.lease("s3rpm", exe()).await;
        assert_eq!(a["ok"], true, "{a}");
    }
    assert_eq!(
        w.lease("s3rpm", exe()).await["limit"],
        "requests_per_minute"
    );
    assert_eq!(w.sts_calls(), 2);
}

/// The limiter as the daemon rebuilds it at start (`start.rs`): every
/// record of the window through `pipeline::limit_event`.
fn rebuilt(audit: &Path) -> (Limiter, usize) {
    let read = saiife_audit::store::read_recent(audit, 2, |_| true);
    assert_eq!(read.skipped_lines, 0, "a record does not read back");
    assert_eq!(read.unreadable_files, 0);
    let events: Vec<_> = read
        .records
        .iter()
        .filter_map(saiife_broker::pipeline::limit_event)
        .collect();
    let n = events.len();
    (
        Limiter::rebuild(events.into_iter(), time::OffsetDateTime::now_utc()),
        n,
    )
}

#[tokio::test]
async fn leases_count_after_a_restart() {
    need_root_chain!();
    let w = world(200).await;
    for _ in 0..2 {
        let a = w.lease("s3rpm", exe()).await;
        assert_eq!(a["ok"], true, "{a}");
    }
    // A refusal before the send never counts.
    assert_eq!(w.lease("s3rpm", "/usr/bin/false").await["ok"], false);
    // Each lease record has one `session` key (the agent session).
    for l in w.audit_text().lines().filter(|l| l.contains("cloud_lease")) {
        assert_eq!(l.matches("\"session\":").count(), 1, "{l}");
    }
    // Stop the daemon; start a new one on the same dirs.
    let World { ctx, tmp, .. } = w;
    drop(ctx);
    let (limiter, n) = rebuilt(&tmp.path().join("audit"));
    assert_eq!(n, 2, "only the two sent leases count");
    let w = world_in(tmp, 200, limiter).await;
    let a = w.lease("s3rpm", exe()).await;
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["error"], "limited", "{a}");
    assert_eq!(a["limit"], "requests_per_minute", "{a}");
    assert_eq!(w.sts_calls(), 0, "the new daemon called STS");
}

// ------------------------------------------------- the project env

/// The personal broker (developer mode) on a fresh dir, its scope bound
/// to `prod` (which a personal broker does not act on).
async fn personal() -> World {
    world_setup(
        scratch(),
        200,
        Limiter::new(),
        DaemonMode::Personal,
        Some("prod"),
    )
    .await
}

/// The access key id that signed each STS call, in order.
fn signers(w: &World) -> Vec<String> {
    w.st.lock()
        .unwrap()
        .sts
        .iter()
        .map(|(_, a)| a.clone())
        .collect()
}

#[tokio::test]
async fn personal_lease_follows_the_project_env() {
    need_root_chain!();
    let w = personal().await;
    let g = w.ctx.policy().gateway.unwrap();
    // No env: the base config (its secret, its allow).
    let a = w.lease("s3sts", exe()).await;
    assert_eq!(a["ok"], true, "{a}");
    assert!(a.get("warning").is_none(), "{a}");
    // `env = "staging"`: that environment's secret signs the AssumeRole,
    // and the session policy follows its narrower allow.
    let a = w
        .lease_with(json!({"service": "s3sts", "exe": exe(), "env": "staging",
                           "project": "/home/agent/proj"}))
        .await;
    assert_eq!(a["ok"], true, "{a}");
    assert!(a.get("warning").is_none(), "{a}");
    assert_eq!(signers(&w), [VAULT_AK, STAGING_AK]);
    let base_svc = &g.snapshot_for(None).config.services["s3sts"];
    let staging_svc = &g.snapshot_for(Some("staging")).config.services["s3sts"];
    assert_eq!(staging_svc.allow, [STAGING_ALLOW]);
    let base = session_policy::build(base_svc, &s3_manifest(), None, Mode::Developer).unwrap();
    let staging =
        session_policy::build(staging_svc, &s3_manifest(), None, Mode::Developer).unwrap();
    assert_ne!(base.json, staging.json);
    assert_eq!(w.policies_sent(), [base.json.clone(), staging.json.clone()]);
    assert!(
        staging.json.contains("arn:aws:s3:::reports/*"),
        "{}",
        staging.json
    );
    // The records name the environment and the project.
    let recs = w.leases();
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0]["env"], Value::Null);
    assert_eq!(recs[0]["project"], "");
    assert_eq!(recs[1]["env"], "staging");
    assert_eq!(recs[1]["project"], "/home/agent/proj");
    assert_eq!(recs[1]["policy_sha256"], staging.sha256);
    // The record's `policy` is that environment's hash, as for `api.call`.
    assert_eq!(recs[0]["policy"], g.snapshot_for(None).hash.as_str());
    assert_eq!(
        recs[1]["policy"],
        g.snapshot_for(Some("staging")).hash.as_str()
    );
    assert_ne!(recs[0]["policy"], recs[1]["policy"]);
    w.assert_records_clean();
}

#[tokio::test]
async fn personal_lease_undefined_env_warns() {
    need_root_chain!();
    let w = personal().await;
    let a = w
        .lease_with(json!({"service": "s3sts", "exe": exe(), "env": "qa"}))
        .await;
    assert_eq!(a["ok"], true, "{a}");
    let warn = a["warning"].as_str().unwrap_or_default();
    assert!(
        warn.contains("\"qa\"") && warn.contains("not defined"),
        "{a}"
    );
    // The base config: its secret, env null in the record.
    assert_eq!(signers(&w), [VAULT_AK]);
    let recs = w.leases();
    assert_eq!(recs[0]["env"], Value::Null);
    // A refused lease keeps the warning too.
    let a = w
        .lease_with(json!({"service": "s3sts", "exe": "/usr/bin/false", "env": "qa"}))
        .await;
    assert_eq!(rule(&a), "exe_not_allowed", "{a}");
    assert!(
        a["warning"].as_str().unwrap_or_default().contains("qa"),
        "{a}"
    );
}

#[tokio::test]
async fn locked_lease_ignores_a_client_env() {
    need_root_chain!();
    let w = world_setup(
        scratch(),
        200,
        Limiter::new(),
        DaemonMode::Locked,
        Some("prod"),
    )
    .await;
    // The scope's `prod`, whatever the client sends; no warning, even for
    // an undefined name.
    for env in [json!("staging"), json!("qa"), Value::Null] {
        let a = w
            .lease_with(json!({"service": "s3sts", "exe": exe(), "env": env}))
            .await;
        assert_eq!(a["ok"], true, "{a}");
        assert!(a.get("warning").is_none(), "{a}");
    }
    assert_eq!(signers(&w), [PROD_AK, PROD_AK, PROD_AK]);
    let recs = w.leases();
    assert!(recs.iter().all(|r| r["env"] == "prod"), "{recs:?}");
    // A malformed env is a bad request in every mode: no lease, no record.
    let a = w
        .lease_with(json!({"service": "s3sts", "exe": exe(), "env": "Bad Name"}))
        .await;
    assert_eq!(a["error"], "bad_request", "{a}");
    assert_eq!(w.sts_calls(), 3);
    assert_eq!(w.leases().len(), 3);
    w.assert_records_clean();
}

#[tokio::test]
async fn locked_lease_without_scope_env_runs_base() {
    need_root_chain!();
    // No scope env: a client `env` still does not pick one.
    let w = world(200).await;
    let a = w
        .lease_with(json!({"service": "s3sts", "exe": exe(), "env": "staging"}))
        .await;
    assert_eq!(a["ok"], true, "{a}");
    assert!(a.get("warning").is_none(), "{a}");
    assert_eq!(signers(&w), [VAULT_AK]);
    assert_eq!(w.leases()[0]["env"], Value::Null);
}
