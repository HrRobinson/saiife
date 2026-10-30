//! `saiife approvals`, `approve` and `reject` end to end (plan 11, Task 5),
//! against the in-process daemon of tests/approvals.rs (same world: the
//! real audit writer, vault, approval store and control server on temp
//! dirs). The CLI user is made an approver with a fake re-authentication
//! (`same_user = "reauth"`); `boss` (4242) and `carol` (4343) are ops-level
//! second uids. `pkttyagent` is a fake script (`SAIIFE_TEST_PKTTYAGENT`).
//!
//! An approval needs a second uid (`same_user = "deny"`), and the tests run
//! as one user. So the daemon is an in-process context (the real audit
//! writer, vault, approval store, control server and HTTP gateway on temp
//! dirs) served on a Unix socket to the real `saiife` binary, and the
//! approver is a fake `PeerCred` (uid 4242, `boss`, listed in `[approval]
//! approvers`) calling `approval.decide` at the ops level. The directory is
//! a fixed passwd/group text naming the test user, `boss` and `carol`
//! (4343, not an approver); the daemon looks `boss` up by uid itself.
//! The upstream is a loopback HTTPS mock; nothing leaves 127.0.0.1.
// Debug builds only: the CLI honours SAIIFE_TEST_PKTTYAGENT only there, so a release test could start the real pkttyagent.
#![cfg(all(unix, debug_assertions))]
#![allow(dead_code)]

mod common;

use common::daemon::{own_group, own_uid, own_user, wait_for};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use saiife_audit::{ChainWriter, WriterOptions};
use saiife_daemon::approvals::{dir_in, State};
use saiife_daemon::ops::{dispatch_conn, Conn, Ctx, CtxInit, PolicyState};
use saiife_daemon::sessions::RealProc;
use saiife_daemon::vault::{self, Entry, Kind, VaultState};
use saiife_daemon::writer::{self, WriterConfig};
use saiife_ipc::msg::Request;
use saiife_ipc::peer::PeerCred;
use saiife_policy::{FixedDirectory, Fsync};
use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

const SECRET: &str = "erp-secret-value-123";
const BOSS: u32 = 4242;
const CAROL: u32 = 4343;
const BODY_A: &str = r#"{"amount": 5, "to": "acme"}"#;
const BODY_B: &str = r#"{"amount": 5000, "to": "mallory"}"#;

// ---------------------------------------------------------------- mock

struct Mock {
    port: u16,
    /// `(method path, body)` of every request.
    hits: Arc<Mutex<Vec<(String, String)>>>,
    ca_pem: String,
}

impl Mock {
    fn hits(&self) -> Vec<(String, String)> {
        self.hits.lock().unwrap().clone()
    }
}

fn mock() -> Mock {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["127.0.0.1".to_string()])
        .unwrap()
        .signed_by(&leaf_key, &ca)
        .unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    )
    .unwrap();
    let cfg = Arc::new(cfg);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(Mutex::new(Vec::new()));
    let h = hits.clone();
    std::thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            let (cfg, h) = (cfg.clone(), h.clone());
            std::thread::spawn(move || serve_one(cfg, tcp, h));
        }
    });
    Mock {
        port,
        hits,
        ca_pem: ca.pem(),
    }
}

fn serve_one(
    cfg: Arc<rustls::ServerConfig>,
    tcp: TcpStream,
    hits: Arc<Mutex<Vec<(String, String)>>>,
) {
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(20)));
    let conn = rustls::ServerConnection::new(cfg).unwrap();
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        match tls.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.lines();
    let mut first = lines.next().unwrap_or("").split(' ');
    let method = first.next().unwrap_or("").to_string();
    let path = first.next().unwrap_or("").to_string();
    let len: usize = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0);
    while buf.len() < head_end + len {
        match tls.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let body = String::from_utf8_lossy(&buf[head_end..]).into_owned();
    hits.lock()
        .unwrap()
        .push((format!("{method} {path}"), body.clone()));
    let out = json!({"created": true, "got": body}).to_string();
    let resp = format!(
        "HTTP/1.1 201 X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}",
        out.len()
    );
    let _ = tls.write_all(resp.as_bytes());
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

// ---------------------------------------------------------------- world

/// The re-authentication seam: answers `allow`, instantly.
struct FakeReauth {
    allow: AtomicBool,
    /// The `--detail request` of every check.
    details: Mutex<Vec<String>>,
}

impl saiife_daemon::reauth::Reauth for FakeReauth {
    fn available(&self) -> bool {
        true
    }
    fn check(
        &self,
        _who: &saiife_daemon::reauth::Subject,
        detail: &str,
        _t: Duration,
    ) -> saiife_daemon::reauth::ReauthResult {
        self.details.lock().unwrap().push(detail.to_string());
        if self.allow.load(Ordering::SeqCst) {
            saiife_daemon::reauth::ReauthResult::Authorized
        } else {
            saiife_daemon::reauth::ReauthResult::Denied(String::new())
        }
    }
}

/// The daemon allows one re-authentication per uid in this process at a
/// time (`reauth_busy` otherwise), and every test here is the same uid:
/// the tests that re-authenticate take turns.
static REAUTH_SERIAL: Mutex<()> = Mutex::new(());

struct World {
    reauth: Arc<FakeReauth>,
    rt: tokio::runtime::Runtime,
    ctx: Arc<Ctx>,
    m: Mock,
    tmp: tempfile::TempDir,
    /// Held from the first [`World::own_reauth`] to the end of the test.
    serial: std::cell::OnceCell<std::sync::MutexGuard<'static, ()>>,
}

fn config_text(tmp: &Path, port: u16, erp_extra: &str) -> String {
    format!(
        r#"version = 2
locked = true

[daemon]
user = {user:?}
socket_dir = {run:?}

[audit]
dir = {audit:?}

[approval]
approvers = ["boss"]

[[scope]]
name = "agents"
users = [{user:?}, "carol"]
services = ["erp", "pay"]

[services.erp]
connector = "http"
base_url = "https://127.0.0.1:{port}/api"
secret = "erp-key"
auth = {{ kind = "header", name = "X-Api-Key" }}
allow = ["invoices:read"]
ask = ["invoices:write"]
{erp_extra}

[[services.erp.operation]]
id = "invoices.list"
capability = "invoices:read"
kind = "read"
method = "GET"
path = "/invoices"

[[services.erp.operation]]
id = "invoices.create"
capability = "invoices:write"
kind = "write"
method = "POST"
path = "/invoices"
query = ["ref"]
body = "json"

[services.pay]
connector = "test-pay"
secret = "erp-key"
ask = ["refunds:write"]
"#,
        user = own_user(),
        run = tmp.join("run").display().to_string(),
        audit = tmp.join("audit").display().to_string(),
    )
}

/// An admin manifest whose operation moves money (an `amount`).
fn pay_manifest(port: u16) -> saiife_broker::Manifest {
    saiife_broker::Manifest::parse(&format!(
        r#"id = "test-pay"
version = 1
title = "Test payments"
base_url = "https://127.0.0.1:{port}/api"
hosts = ["127.0.0.1"]
auth = [{{ kind = "header", name = "X-Api-Key", secret_field = "value" }}]
request_headers = ["Content-Type", "Accept"]

[[operation]]
id = "refunds.create"
capability = "refunds:write"
kind = "write"
method = "POST"
path = "/refunds"
body = "json"
amount = {{ field = "refund.amount", currency_field = "refund.currency", unit = "major" }}
"#
    ))
    .unwrap()
}

/// The policy state of `text` (written to `etc/config.toml`), with the
/// built-in connectors and `test-pay`.
fn policy_of(tmp: &Path, port: u16, text: &str) -> PolicyState {
    let config = tmp.join("etc/config.toml");
    fs::write(&config, text).unwrap();
    let l = saiife_policy::load_system(&config).unwrap();
    let cat = saiife_broker::Catalog::new(saiife_broker::builtin(), vec![pay_manifest(port)]);
    saiife_broker::catalog::validate(&l.config, &cat).unwrap();
    PolicyState::from_loaded(&l, &[], cat)
}

fn world() -> World {
    world_with("")
}

fn world_with(erp_extra: &str) -> World {
    world_capped(erp_extra, None)
}

/// [`world_with`], the approval store keeping results of at most
/// `result_cap` sealed bytes.
fn world_capped(erp_extra: &str, result_cap: Option<usize>) -> World {
    let m = mock();
    let tmp = common::tmp::short_tempdir();
    let t = tmp.path();
    for d in [
        "etc/ca", "audit", "state", "run", "proc", "home", "data", "project",
    ] {
        fs::create_dir_all(t.join(d)).unwrap();
    }
    fs::write(t.join("etc/ca/test-ca.pem"), &m.ca_pem).unwrap();
    let policy = policy_of(t, m.port, &config_text(t, m.port, erp_extra));

    let cw = ChainWriter::open(
        &t.join("audit"),
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
    let key_file = t.join(saiife_daemon::VAULT_KEY_FILE);
    fs::write(&key_file, [7u8; 32]).unwrap();
    // macOS: the vault refuses a key open to group or others.
    fs::set_permissions(
        &key_file,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();
    let vault_path = t.join("state/vault/vault.bin");
    let mut vault = vault::open(&key_file, &vault_path);
    let VaultState::Ready(v) = &mut vault else {
        panic!("vault not ready");
    };
    v.put(Entry {
        name: "erp-key".into(),
        kind: Kind::Header,
        fields: [("value".to_string(), Zeroizing::new(SECRET.to_string()))].into(),
        allowed_services: vec!["erp".into(), "pay".into()],
        created_by: 0,
        created: "2026-10-27T00:00:00Z".into(),
        last_used: None,
        rotate_after: None,
    })
    .unwrap();

    let (me, uid) = (own_user(), own_uid());
    let gid = rustix::process::getgid().as_raw();
    let passwd = format!(
        "{me}:x:{uid}:{gid}::/:/bin/sh\nboss:x:{BOSS}:{BOSS}::/:/bin/sh\ncarol:x:{CAROL}:{CAROL}::/:/bin/sh\n"
    );
    let group = format!(
        "{}:x:{gid}:\nboss:x:{BOSS}:\ncarol:x:{CAROL}:\n",
        own_group()
    );
    let upstream = saiife_broker::upstream::Upstream::with_ca_dir(
        Some(&t.join("etc/ca")),
        Duration::from_secs(10),
    )
    .map_err(|e| e.to_string());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let reauth = Arc::new(FakeReauth {
        allow: AtomicBool::new(true),
        details: Mutex::new(Vec::new()),
    });
    let ctx = rt.block_on(async {
        let writer_cfg = WriterConfig {
            checkpoint_every: 1000,
            checkpoint_interval: Duration::from_secs(900),
            fsync: Fsync::Always,
        };
        let directory = Arc::new(FixedDirectory::from_text(&passwd, &group));
        let state = t.join("state");
        let mut ctx = Ctx::new(CtxInit {
            own_uid: uid,
            own_user: me,
            audit_dir: t.join("audit"),
            socket_dir: t.join("run"),
            config_path: t.join("etc/config.toml"),
            policy,
            proc: Box::new(RealProc::new("/proc")),
            vault,
            vault_path,
            upstream,
            backup_dir: t.join("state/import-backup"),
            tokens: Arc::new(saiife_daemon::tokens::Tokens::memory_with_clock(Arc::new(
                || 1_800_000_000,
            ))),
            approvals: saiife_daemon::approvals::Store::open(&dir_in(&state))
                .map(|s| match result_cap {
                    Some(c) => s.with_result_cap(c),
                    None => s,
                })
                .map_err(|e| e.to_string()),
            lockdown: saiife_daemon::lockdown::Store::memory(),
            grants: saiife_daemon::grants::Grants::memory(),
            ..CtxInit::minimal(handle, writer_cfg, directory, &state)
        });
        ctx.reauth = reauth.clone();
        Arc::new(ctx)
    });
    // The control socket (the CLI's) and the HTTP gateway.
    let control =
        rt.block_on(async { tokio::net::UnixListener::bind(t.join("run/saiife.sock")).unwrap() });
    let gw =
        rt.block_on(async { tokio::net::UnixListener::bind(t.join("run/gateway.sock")).unwrap() });
    {
        let ctx = Arc::clone(&ctx);
        rt.spawn(async move {
            while let Ok((s, _)) = control.accept().await {
                tokio::spawn(saiife_daemon::server::connection(s, Arc::clone(&ctx)));
            }
        });
    }
    rt.spawn(saiife_daemon::gateway::serve(gw, Arc::clone(&ctx)));
    World {
        reauth,
        rt,
        ctx,
        m,
        tmp,
        serial: std::cell::OnceCell::new(),
    }
}

impl World {
    fn path(&self) -> &Path {
        self.tmp.path()
    }

    /// `saiife api --system-config ... <args>` as the requester.
    fn api_cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_saiife"));
        c.env("HOME", self.path().join("home"))
            .env("XDG_RUNTIME_DIR", self.path().join("no-runtime"))
            .env("PATH", "/usr/bin:/bin")
            .env("SAIIFE_DATA_DIR", self.path().join("data"))
            .env("SAIIFE_AUDIT_DIR", self.path().join("audit"))
            .stdin(Stdio::null())
            .arg("api")
            .arg("--system-config")
            .arg(self.path().join("etc/config.toml"))
            .args(args)
            .current_dir(self.path().join("project"));
        c
    }

    fn api(&self, args: &[&str]) -> Output {
        self.api_cmd(args).output().unwrap()
    }

    /// `invoices.create` with `body` through the CLI: the pending id.
    fn ask(&self, body: &str) -> u64 {
        self.ask_with(body, &[])
    }

    /// [`World::ask`] with more arguments (parameters).
    fn ask_with(&self, body: &str, more: &[&str]) -> u64 {
        let f = self.path().join(format!("body-{}.json", body.len()));
        fs::write(&f, body).unwrap();
        let at = format!("@{}", f.display());
        let mut args = vec!["erp", "invoices.create", "--body", &at];
        args.extend_from_slice(more);
        let o = self.api(&args);
        assert_eq!(o.status.code(), Some(3), "{}", stderr(&o));
        pending_id(&o)
    }

    /// One op as `uid` (pid: this process; start time unknown).
    fn op(&self, uid: u32, op: &str, args: Value) -> Value {
        let conn = self.conn(uid);
        self.op_on(&conn, op, args)
    }

    /// A connection as `uid` (pid: this process; start time unknown), for
    /// several ops on one connection.
    fn conn(&self, uid: u32) -> Conn {
        Conn::new(
            PeerCred {
                uid,
                gid: uid,
                pid: std::process::id(),
            },
            None,
        )
    }

    /// One op on `conn`.
    fn op_on(&self, conn: &Conn, op: &str, args: Value) -> Value {
        let Value::Object(args) = args else {
            panic!("args must be an object")
        };
        let req = Request {
            id: 7,
            op: op.into(),
            args,
        };
        self.rt.block_on(dispatch_conn(&self.ctx, conn, req))
    }

    fn decide(&self, uid: u32, id: u64, action: &str) -> Value {
        self.op(
            uid,
            "approval.decide",
            json!({"request": id, "action": action}),
        )
    }

    fn state(&self, id: u64) -> Option<State> {
        self.ctx
            .approvals
            .as_ref()
            .unwrap()
            .get(id)
            .map(|r| r.state)
    }

    /// Wait (at most 10 s) for request `id` to reach `s`.
    fn wait_state(&self, id: u64, s: State) {
        assert!(
            wait_for(Duration::from_secs(10), || self.state(id) == Some(s)),
            "request #{id} is {:?}, not {s:?}",
            self.state(id)
        );
    }

    fn records(&self) -> Vec<Value> {
        let mut files: Vec<PathBuf> = fs::read_dir(self.path().join("audit"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
            .collect();
        files.sort();
        files
            .iter()
            .flat_map(|f| {
                let text = fs::read_to_string(f).unwrap();
                common::complete_lines(&text)
                    .map(|l| serde_json::from_str(l).unwrap())
                    .collect::<Vec<Value>>()
            })
            .collect()
    }

    fn approval_records(&self, id: u64) -> Vec<Value> {
        self.records()
            .into_iter()
            .filter(|r| r["kind"] == "approval" && r["approval"] == id)
            .collect()
    }

    /// Wait (at most 10 s) for the `approval` record of `action` for `id`.
    /// The `lockdown` record with `rule`, once written.
    fn wait_lockdown_record(&self, rule: &str) -> Value {
        let mut found = None;
        wait_for(Duration::from_secs(10), || {
            found = self
                .records()
                .into_iter()
                .find(|r| r["kind"] == "lockdown" && r["rule"] == rule);
            found.is_some()
        });
        found.unwrap_or_else(|| panic!("no lockdown record with {rule}: {:?}", self.records()))
    }

    fn wait_record(&self, id: u64, action: &str) -> Value {
        let mut found = None;
        wait_for(Duration::from_secs(10), || {
            found = self
                .approval_records(id)
                .into_iter()
                .find(|r| r["action"] == action);
            found.is_some()
        });
        found.unwrap_or_else(|| panic!("no {action} record for #{id}: {:?}", self.records()))
    }

    /// One HTTP/1.1 request on `gateway.sock`; the whole answer.
    fn http(&self, req: &str) -> String {
        let mut s =
            std::os::unix::net::UnixStream::connect(self.path().join("run/gateway.sock")).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        s.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    }

    fn get_request(&self, id: u64) -> String {
        self.http(&format!(
            "GET /v1/requests/{id} HTTP/1.1\r\nHost: saiife\r\nConnection: close\r\n\r\n"
        ))
    }
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// The id of `saiife: pending approval #<id> (saiife api result <id>)`.
fn pending_id(o: &Output) -> u64 {
    let e = stderr(o);
    let line = e
        .lines()
        .find(|l| l.starts_with("saiife: pending approval #"))
        .unwrap_or_else(|| panic!("no pending line: {e}"));
    let id: u64 = line["saiife: pending approval #".len()..]
        .split(' ')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        line,
        format!("saiife: pending approval #{id} (saiife api result {id})")
    );
    id
}

// ------------------------------------------------------- CLI helpers

impl World {
    /// `saiife <cmd> --system-config ... <args>` as the own user.
    fn cli_cmd(&self, cmd: &str, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_saiife"));
        c.env_clear()
            .env("HOME", self.path().join("home"))
            .env("XDG_RUNTIME_DIR", self.path().join("no-runtime"))
            .env("PATH", "/usr/bin:/bin")
            .env("SAIIFE_DATA_DIR", self.path().join("data"))
            .env("SAIIFE_AUDIT_DIR", self.path().join("audit"))
            // Never the real /usr/bin/pkttyagent: a missing one by
            // default (tests that want an agent set a fake).
            .env("SAIIFE_TEST_PKTTYAGENT", self.path().join("no-pkttyagent"))
            .stdin(Stdio::null())
            .arg(cmd)
            .arg("--system-config")
            .arg(self.path().join("etc/config.toml"))
            .args(args)
            .current_dir(self.path().join("project"));
        c
    }

    fn cli(&self, cmd: &str, args: &[&str]) -> Output {
        self.cli_cmd(cmd, args).output().unwrap()
    }

    /// Make the own user an approver who re-authenticates for its own
    /// requests (`same_user = "reauth"`); `ok` is the fake's answer.
    fn own_reauth(&self, ok: bool) {
        self.serial
            .get_or_init(|| REAUTH_SERIAL.lock().unwrap_or_else(|p| p.into_inner()));
        self.reauth.allow.store(ok, Ordering::SeqCst);
        let text = config_text(self.path(), self.m.port, "").replace(
            "approvers = [\"boss\"]",
            &format!(
                "approvers = [\"boss\", {:?}]\nsame_user = \"reauth\"",
                own_user()
            ),
        );
        *self.ctx.policy.lock().unwrap() = policy_of(self.path(), self.m.port, &text);
    }
}

fn json_out(o: &Output) -> Value {
    serde_json::from_str(stdout(o).trim()).unwrap_or_else(|e| panic!("{e}: {}", stdout(o)))
}

fn ok(o: &Output) {
    assert_eq!(o.status.code(), Some(0), "{}", stderr(o));
}

/// A fake `pkttyagent`: writes its pid (`$$`, the script `exec`s), its
/// parent's pid and its argv, then sleeps until it is killed.
fn fake_agent(dir: &Path) -> PathBuf {
    let script = dir.join("pkttyagent");
    let d = dir.display();
    fs::write(
        &script,
        format!(
            "#!/bin/sh\necho $$ > {d}/agent.pid.tmp && mv {d}/agent.pid.tmp {d}/agent.pid\n\
             echo $PPID > {d}/agent.ppid\necho \"$@\" > {d}/agent.argv\nexec sleep 120\n"
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    script
}

// ---------------------------------------------------------------- tests

#[test]
fn list_shows_pending_masked() {
    let w = world();
    // A secret in the body is never stored for approval
    // (`masked_content`); in a parameter it is masked for display.
    let body = r#"{"amount": 5, "memo": "plain"}"#;
    let id = w.ask_with(body, &[&format!("ref={SECRET}")]);
    // The own user is the requester: it sees its own request.
    let o = w.cli("approvals", &[]);
    ok(&o);
    let out = stdout(&o);
    let line = out.lines().nth(1).unwrap_or_else(|| panic!("{out}"));
    assert!(out.lines().next().unwrap().starts_with("ID"), "{out}");
    let cols: Vec<&str> = line.split_whitespace().collect();
    assert_eq!(cols[0], id.to_string());
    assert_eq!(cols[2], own_user());
    assert_eq!(cols[3], "connector");
    assert_eq!((cols[4], cols[5]), ("erp", "invoices.create"));
    // Asked under the base config, recorded as such.
    assert_eq!((cols[6], cols[7]), ("(env", "base)"));
    assert_eq!(cols[8], "pending");
    assert!(!out.contains(SECRET));

    // `list --json`: one array.
    let o = w.cli("approvals", &["list", "--json"]);
    ok(&o);
    let v = json_out(&o);
    let items = v.as_array().unwrap();
    assert_eq!(items.len(), 1, "{v}");
    assert_eq!(items[0]["id"], id);
    assert_eq!(items[0]["user"], own_user());
    assert_eq!(items[0]["type"], "connector");
    assert_eq!(items[0]["state"], "pending");
    assert!(!v.to_string().contains(SECRET));

    // A decided request leaves the pending list, stays in --all.
    assert_eq!(w.decide(BOSS, id, "reject")["ok"], true);
    let o = w.cli("approvals", &["--json"]);
    assert_eq!(json_out(&o), json!([]));
    assert!(stdout(&w.cli("approvals", &[])).contains("no pending requests"));
    let v = json_out(&w.cli("approvals", &["--all", "--json"]));
    assert_eq!(v[0]["state"], "rejected", "{v}");
    let v = json_out(&w.cli("approvals", &["list", "--all", "--json"]));
    assert_eq!(v[0]["id"], id);
}

#[test]
fn show_masks_params() {
    let w = world();
    let pad = "p".repeat(3000);
    let body = format!(r#"{{"memo": "plain", "pad": "{pad}", "zz": "tail-marker"}}"#);
    let id = w.ask_with(&body, &[&format!("ref={SECRET}")]);
    let o = w.cli("approvals", &["show", &id.to_string()]);
    ok(&o);
    let out = stdout(&o);
    assert!(!out.contains(SECRET), "{out}");
    assert!(out.contains("[MASKED]"), "{out}");
    assert!(out.contains(&format!("request #{id}")), "{out}");
    assert!(out.contains("erp invoices.create"), "{out}");
    assert!(out.contains("(cut; use --full)"), "{out}");
    assert!(!out.contains("tail-marker"), "{out}");
    assert!(!out.contains("WARNING"), "{out}");

    let o = w.cli("approvals", &["show", &id.to_string(), "--full"]);
    ok(&o);
    let out = stdout(&o);
    assert!(out.contains("tail-marker"), "{out}");
    assert!(!out.contains("(cut; use --full)"), "{out}");
    assert!(!out.contains(SECRET), "{out}");

    let o = w.cli("approvals", &["show", &id.to_string(), "--json"]);
    ok(&o);
    let v = json_out(&o);
    assert_eq!(v["id"], id);
    assert_eq!(v["body_truncated"], false);
    assert!(v["body_display"].as_str().unwrap().contains("tail-marker"));
    assert!(!v.to_string().contains(SECRET));
    assert!(v.get("request_sealed").is_none());
}

/// A command request shows the project tree its grant covers (`scope`),
/// in text and in `--json`.
#[test]
fn show_prints_the_scope_of_a_command_request() {
    use saiife_daemon::approvals::{ApprovalType, NewRequest};
    let w = world();
    let r = w
        .ctx
        .approvals
        .as_ref()
        .unwrap()
        .create(
            NewRequest {
                uid: own_uid(),
                user: own_user(),
                session: None,
                agent: "claude".into(),
                project: "/srv/shop/sub".into(),
                kind: ApprovalType::Command,
                service: None,
                operation: None,
                capability: None,
                params: Default::default(),
                input: Some("git push --force origin main".into()),
                grant_key: Some("00".repeat(32)),
                scope: Some("/srv/shop".into()),
                ask_rule: Some("core.git/push-force".into()),
                send: Default::default(),
            },
            |_| Ok(None),
            Duration::from_secs(600),
            std::time::SystemTime::now(),
        )
        .unwrap();
    let o = w.cli("approvals", &["show", &r.id.to_string()]);
    ok(&o);
    let out = stdout(&o);
    assert!(out.contains("  scope      /srv/shop\n"), "{out}");
    assert!(out.contains("git push --force origin main"), "{out}");
    let v = json_out(&w.cli("approvals", &["show", &r.id.to_string(), "--json"]));
    assert_eq!(v["scope"], "/srv/shop", "{v}");
    assert!(v.get("grant_key").is_none(), "{v}");
}

/// A connector request asked under an environment names it: `approvals
/// show` on its own line, the list after the operation, `--json` as
/// `env`. One with no environment shows none.
#[test]
fn show_and_list_print_the_env_of_a_connector_request() {
    use saiife_daemon::approvals::{ApprovalType, NewRequest, SendDisplay};
    let w = world();
    let new = |env: Option<&str>, env_base: bool| NewRequest {
        uid: own_uid(),
        user: own_user(),
        session: None,
        agent: "claude".into(),
        project: "/srv/shop".into(),
        kind: ApprovalType::Connector,
        service: Some("erp".into()),
        operation: Some("invoices.create".into()),
        capability: Some("invoices:write".into()),
        params: Default::default(),
        input: None,
        grant_key: None,
        scope: None,
        ask_rule: None,
        send: SendDisplay {
            env: env.map(str::to_string),
            env_base,
            ..Default::default()
        },
    };
    let store = w.ctx.approvals.as_ref().unwrap();
    let create = |n| {
        store
            .create(
                n,
                |_| Ok(None),
                Duration::from_secs(600),
                std::time::SystemTime::now(),
            )
            .unwrap()
    };
    let with = create(new(Some("prod"), false));
    let without = create(new(None, false));
    let base = create(new(None, true));
    assert_eq!(
        saiife_daemon::approvals::offhost_summary(&base),
        "erp invoices.create (env base)"
    );
    let out = stdout(&w.cli("approvals", &["show", &base.id.to_string()]));
    assert!(out.contains("  env        base\n"), "{out}");
    assert_eq!(
        saiife_daemon::approvals::offhost_summary(&with),
        "erp invoices.create (env prod)"
    );
    assert_eq!(
        saiife_daemon::approvals::offhost_summary(&without),
        "erp invoices.create"
    );

    let out = stdout(&w.cli("approvals", &["show", &with.id.to_string()]));
    assert!(out.contains("  env        prod\n"), "{out}");
    let out = stdout(&w.cli("approvals", &["show", &without.id.to_string()]));
    assert!(!out.contains("  env "), "{out}");
    let v = json_out(&w.cli("approvals", &["show", &with.id.to_string(), "--json"]));
    assert_eq!(v["env"], "prod", "{v}");

    let out = stdout(&w.cli("approvals", &[]));
    let line = |id: u64| {
        out.lines()
            .find(|l| l.split_whitespace().next() == Some(&id.to_string()))
            .unwrap_or_else(|| panic!("{out}"))
            .to_string()
    };
    assert!(
        line(with.id).contains("erp invoices.create (env prod)"),
        "{out}"
    );
    assert!(!line(without.id).contains("(env"), "{out}");
    assert!(
        line(base.id).contains("erp invoices.create (env base)"),
        "{out}"
    );
}

/// An MCP gateway request (plan 17): `show` prints the server, the tool
/// and the masked arguments; the list names it `mcp:<server> <tool>`.
#[test]
fn show_prints_server_tool_and_masked_arguments_of_an_mcp_request() {
    use saiife_daemon::approvals::{ApprovalType, NewRequest, SendDisplay};
    let w = world();
    let store = w.ctx.approvals.as_ref().unwrap();
    let new = |truncated: bool| NewRequest {
        uid: own_uid(),
        user: own_user(),
        session: None,
        agent: "claude".into(),
        project: "/srv/shop".into(),
        kind: ApprovalType::Mcp,
        service: Some("mcp:linear".into()),
        operation: Some("create_issue".into()),
        capability: None,
        params: Default::default(),
        input: None,
        grant_key: None,
        scope: None,
        ask_rule: None,
        send: SendDisplay {
            body_display: Some("{\"team\":\"ENG\",\"title\":\"Bug\"}".into()),
            body_sha256: Some("ab".repeat(32)),
            body_truncated: truncated,
            env_base: true,
            ..Default::default()
        },
    };
    let create = |n| {
        store
            .create(
                n,
                |_| Ok(None),
                Duration::from_secs(600),
                std::time::SystemTime::now(),
            )
            .unwrap()
    };
    let r = create(new(false));
    let o = w.cli("approvals", &["show", &r.id.to_string()]);
    ok(&o);
    let out = stdout(&o);
    assert!(out.contains("  type       mcp\n"), "{out}");
    assert!(out.contains("  server     linear\n"), "{out}");
    assert!(out.contains("  tool       create_issue\n"), "{out}");
    assert!(out.contains("  env        base\n"), "{out}");
    assert!(out.contains("  arguments (masked)\n"), "{out}");
    assert!(
        out.contains("{\"team\":\"ENG\",\"title\":\"Bug\"}"),
        "{out}"
    );
    assert!(
        out.contains(&format!("  arguments sha256 {}", "ab".repeat(32))),
        "{out}"
    );
    assert!(!out.contains("WARNING"), "{out}");
    let v = json_out(&w.cli("approvals", &["show", &r.id.to_string(), "--json"]));
    assert_eq!(v["type"], "mcp", "{v}");
    let out = stdout(&w.cli("approvals", &[]));
    assert!(out.contains("mcp:linear create_issue"), "{out}");
    // Shown cut: approving needs --accept-truncated.
    let cut = create(new(true));
    let out = stdout(&w.cli("approvals", &["show", &cut.id.to_string()]));
    assert!(
        out.contains("WARNING: the arguments are over 4 KiB"),
        "{out}"
    );
    assert!(out.contains("--accept-truncated"), "{out}");
}

#[test]
fn show_warns_when_the_full_body_was_cut() {
    let w = world();
    let id = w.ask(BODY_A);
    let file = dir_in(&w.path().join("state")).join(format!("{id}.json"));
    let mut v: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    v["body_truncated"] = json!(true);
    fs::write(&file, serde_json::to_vec(&v).unwrap()).unwrap();
    let o = w.cli("approvals", &["show", &id.to_string(), "--full"]);
    ok(&o);
    let out = stdout(&o);
    assert!(out.contains("WARNING"), "{out}");
    assert!(out.contains("--accept-truncated"), "{out}");
}

#[test]
fn approve_and_reject_round_trip() {
    let w = world();
    // The own user is not a second account: boss decides at the ops level
    // as the control, the CLI as an approver whose own request it is not.
    // Here the CLI user is the approver (reauth passes), so it can decide.
    w.own_reauth(true);
    let a = w.ask(BODY_A);
    let o = w.cli("approve", &[&a.to_string(), "--note", "looks fine"]);
    ok(&o);
    assert!(
        stdout(&o).contains(&format!("request #{a} approved")),
        "{}",
        stdout(&o)
    );
    w.wait_state(a, State::Sent);
    assert_eq!(w.m.hits().len(), 1);
    assert_eq!(w.wait_record(a, "approved")["note"], "looks fine");

    let b = w.ask(BODY_B);
    let o = w.cli("reject", &[&b.to_string(), "--note", "no"]);
    ok(&o);
    assert!(
        stdout(&o).contains(&format!("request #{b} rejected")),
        "{}",
        stdout(&o)
    );
    assert_eq!(w.state(b), Some(State::Rejected));
    // Its own request: a withdrawal, noted as such.
    assert_eq!(
        w.wait_record(b, "rejected")["note"],
        "cancelled by requester: no"
    );
    assert_eq!(w.m.hits().len(), 1, "a rejected request is never sent");

    // Deciding again is refused with the state (exit 2).
    let o = w.cli("reject", &[&b.to_string()]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(stderr(&o).contains("is rejected"), "{}", stderr(&o));
}

#[test]
fn refusal_prints_rule_and_exit_2() {
    let w = world();
    // Not an approver (a reject of its own request is a withdrawal).
    let id = w.ask(BODY_A);
    let o = w.cli("approve", &[&id.to_string()]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("saiife: refused (not_approver)"),
        "{}",
        stderr(&o)
    );
    // Re-authentication denied.
    w.own_reauth(false);
    let o = w.cli("approve", &[&id.to_string()]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("saiife: refused (reauth_failed)"),
        "{}",
        stderr(&o)
    );
    // What is approved is printed before any prompt, and with no
    // pkttyagent (env cleared: a terminal-only session) a hint says so.
    assert!(
        stderr(&o).contains(&format!(
            "saiife: approving request #{id}: connector erp invoices.create"
        )),
        "{}",
        stderr(&o)
    );
    // pkttyagent is polkit's: never started on macOS.
    assert_eq!(
        stderr(&o).contains("no-pkttyagent is missing"),
        cfg!(target_os = "linux"),
        "{}",
        stderr(&o)
    );
    assert_eq!(w.state(id), Some(State::Pending));
    assert!(w.m.hits().is_empty());
    // polkit was told what is approved.
    assert_eq!(
        *w.reauth.details.lock().unwrap(),
        vec![format!("#{id} erp invoices.create")]
    );
    // A failed prompt cools the uid down: the next try is refused at once,
    // without asking polkit again.
    w.own_reauth(true);
    let o = w.cli("approve", &[&id.to_string()]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("saiife: refused (reauth_cooldown)"),
        "{}",
        stderr(&o)
    );
    assert_eq!(w.reauth.details.lock().unwrap().len(), 1);
    assert_eq!(w.state(id), Some(State::Pending));
    // An unknown id.
    let o = w.cli("approve", &["999"]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
}

#[test]
fn accept_truncated_sends_the_ack() {
    let w = world();
    w.own_reauth(true);
    let id = w.ask(BODY_A);
    let file = dir_in(&w.path().join("state")).join(format!("{id}.json"));
    let mut v: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    v["body_truncated"] = json!(true);
    fs::write(&file, serde_json::to_vec(&v).unwrap()).unwrap();
    let o = w.cli("approve", &[&id.to_string()]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("refused (truncated_not_acknowledged)"),
        "{}",
        stderr(&o)
    );
    assert_eq!(w.state(id), Some(State::Pending));
    let o = w.cli("approve", &[&id.to_string(), "--accept-truncated"]);
    ok(&o);
    w.wait_state(id, State::Sent);
}

#[test]
fn daemon_unavailable_is_exit_5() {
    let w = world();
    let id = w.ask(BODY_A);
    // Stop answering on the control socket.
    fs::remove_file(w.path().join("run/saiife.sock")).unwrap();
    for (cmd, args) in [
        ("approvals", vec![]),
        ("approve", vec![id.to_string()]),
        ("reject", vec![id.to_string()]),
    ] {
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        let o = w.cli(cmd, &a);
        assert_eq!(o.status.code(), Some(5), "{cmd}: {}", stderr(&o));
    }
}

/// Linux: macOS has no polkit, so no pkttyagent.
#[cfg(target_os = "linux")]
#[test]
fn pkttyagent_started_and_stopped_for_same_uid_reauth() {
    let w = world();
    w.own_reauth(true);
    let agent = fake_agent(w.path());
    let id = w.ask(BODY_A);
    let mut cmd = w.cli_cmd("approve", &[&id.to_string()]);
    cmd.env("SAIIFE_TEST_PKTTYAGENT", &agent);
    let o = cmd.output().unwrap();
    ok(&o);
    w.wait_state(id, State::Sent);

    let pid: u32 = fs::read_to_string(w.path().join("agent.pid"))
        .expect("the fake pkttyagent was started")
        .trim()
        .parse()
        .unwrap();
    let argv = fs::read_to_string(w.path().join("agent.argv")).unwrap();
    let ppid: u32 = fs::read_to_string(w.path().join("agent.ppid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    // `--process <the CLI's own pid> --fallback`; the CLI was its parent.
    assert_eq!(argv.trim(), format!("--process {ppid} --fallback"));
    assert_ne!(ppid, std::process::id());
    // The CLI is gone, and so is the agent (its own child, killed through
    // its handle and reaped): no /proc entry for it.
    assert!(
        wait_for(Duration::from_secs(5), || !Path::new(&format!(
            "/proc/{pid}"
        ))
        .exists()),
        "the fake pkttyagent {pid} is still running"
    );
}

/// `lockdown off` by an approver who is not an admin needs polkit
/// re-authentication: authorized turns it off, denied keeps it on
/// (`reauth_failed`); root turns it off without one.
#[test]
fn lockdown_off_by_an_approver_needs_reauth() {
    let w = world();
    w.own_reauth(true);
    let agent = fake_agent(w.path());
    let lockdown = |args: &[&str]| {
        let mut cmd = w.cli_cmd("lockdown", args);
        cmd.env("SAIIFE_TEST_PKTTYAGENT", &agent);
        cmd.output().unwrap()
    };
    ok(&lockdown(&["on", "--scope", "connectors"]));
    let o = lockdown(&["off"]);
    ok(&o);
    assert!(
        stderr(&o).contains("turning lockdown off"),
        "{}",
        stderr(&o)
    );
    assert!(w.ctx.lockdown.get().is_none());
    assert_eq!(
        *w.reauth.details.lock().unwrap(),
        vec!["lockdown off".to_string()]
    );
    // The CLI started its agent first (Linux: macOS has no pkttyagent).
    assert_eq!(
        w.path().join("agent.pid").exists(),
        cfg!(target_os = "linux")
    );

    ok(&lockdown(&["on", "--scope", "connectors"]));
    w.own_reauth(false);
    let o = lockdown(&["off"]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("refused (reauth_failed)"),
        "{}",
        stderr(&o)
    );
    assert!(w.ctx.lockdown.get().is_some(), "still on");
    // The refusal is on record.
    let rec = w.wait_lockdown_record("reauth_failed");
    assert_eq!(rec["decision"], "deny", "{rec}");
    assert_eq!(rec["action"], "off", "{rec}");

    // Root needs no re-authentication.
    let r = w.op(0, "lockdown.set", json!({"on": false}));
    assert_eq!(r["ok"], true, "{r}");
    assert!(w.ctx.lockdown.get().is_none());
}

/// Narrowing an active lockdown by an approver who is not an admin needs
/// re-authentication (detail `lockdown change`): authorized narrows it,
/// denied keeps it (`reauth_failed`, recorded).
#[test]
fn lockdown_narrowing_by_an_approver_needs_reauth() {
    let w = world();
    let agent = fake_agent(w.path());
    let lockdown = |args: &[&str]| {
        let mut cmd = w.cli_cmd("lockdown", args);
        cmd.env("SAIIFE_TEST_PKTTYAGENT", &agent);
        cmd.output().unwrap()
    };
    use saiife_broker::pipeline::LockScope;
    let scope = || w.ctx.lockdown.get().map(|l| l.scope);
    w.own_reauth(true);
    ok(&lockdown(&["on"]));
    ok(&lockdown(&["on", "--scope", "connectors"]));
    assert_eq!(scope(), Some(LockScope::Connectors));
    // Widening is free: no re-authentication.
    ok(&lockdown(&["on", "--scope", "all"]));
    assert_eq!(scope(), Some(LockScope::All));
    assert_eq!(
        *w.reauth.details.lock().unwrap(),
        vec!["lockdown change".to_string()]
    );

    w.own_reauth(false);
    let o = lockdown(&["on", "--scope", "connectors"]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("refused (reauth_failed)"),
        "{}",
        stderr(&o)
    );
    assert_eq!(scope(), Some(LockScope::All));
    let rec = w.wait_lockdown_record("reauth_failed");
    assert_eq!(rec["decision"], "deny", "{rec}");
    assert_eq!(rec["action"], "on", "{rec}");
}

#[test]
fn pkttyagent_not_started_for_other_users_requests_or_a_desktop() {
    let w = world();
    let agent = fake_agent(w.path());
    let started = || w.path().join("agent.pid").exists();

    // A request of another user (carol): boss's decision is not the
    // CLI's business, and the own-uid rule keeps the agent away. The CLI
    // user is an approver with reauth for its own requests only.
    w.own_reauth(true);
    let carol = ops_ask_as(&w, CAROL, BODY_A);
    // Own uid is an approver, so it sees carol's request; approving it
    // needs no re-authentication (a different requester).
    let mut cmd = w.cli_cmd("approve", &[&carol.to_string()]);
    cmd.env("SAIIFE_TEST_PKTTYAGENT", &agent);
    ok(&cmd.output().unwrap());
    assert!(!started(), "an agent for another user's request");

    // Own request on a desktop session (DISPLAY set, no SSH_TTY): none.
    let id = w.ask(BODY_B);
    let mut cmd = w.cli_cmd("approve", &[&id.to_string()]);
    cmd.env("SAIIFE_TEST_PKTTYAGENT", &agent)
        .env("DISPLAY", ":0");
    ok(&cmd.output().unwrap());
    assert!(!started(), "an agent on a desktop session");

    // An SSH session with a desktop variable: started.
    let id = w.ask(BODY_B);
    let mut cmd = w.cli_cmd("approve", &[&id.to_string()]);
    cmd.env("SAIIFE_TEST_PKTTYAGENT", &agent)
        .env("DISPLAY", ":0")
        .env("SSH_TTY", "/dev/pts/9");
    ok(&cmd.output().unwrap());
    // Linux only: macOS has no pkttyagent.
    assert_eq!(started(), cfg!(target_os = "linux"), "no agent over ssh");

    // A rejection never prompts.
    let _ = fs::remove_file(w.path().join("agent.pid"));
    let id = w.ask(BODY_B);
    let mut cmd = w.cli_cmd("reject", &[&id.to_string()]);
    cmd.env("SAIIFE_TEST_PKTTYAGENT", &agent);
    ok(&cmd.output().unwrap());
    assert!(!started(), "an agent for a rejection");
}

/// `api.call` as `uid` at the ops level: the pending request's id.
fn ops_ask_as(w: &World, uid: u32, body: &str) -> u64 {
    use base64::Engine as _;
    let a = w.op(
        uid,
        "api.call",
        json!({"service": "erp", "operation": "invoices.create",
               "body_b64": base64::engine::general_purpose::STANDARD.encode(body)}),
    );
    a["pending"].as_u64().unwrap_or_else(|| panic!("{a}"))
}

#[test]
fn requester_sees_only_own() {
    let w = world();
    let mine = w.ask(BODY_A);
    let carols = ops_ask_as(&w, CAROL, BODY_B);
    assert_ne!(mine, carols);

    let v = json_out(&w.cli("approvals", &["--all", "--json"]));
    let ids: Vec<u64> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["id"].as_u64().unwrap())
        .collect();
    assert_eq!(ids, vec![mine], "{v}");
    let o = w.cli("approvals", &["show", &carols.to_string()]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(stderr(&o).contains("not yours"), "{}", stderr(&o));
    let o = w.cli("approve", &[&carols.to_string()]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    // An approver sees both.
    let l = w.op(BOSS, "approval.list", json!({}));
    assert_eq!(l["items"].as_array().unwrap().len(), 2);
    assert_eq!(w.state(carols), Some(State::Pending));
}
