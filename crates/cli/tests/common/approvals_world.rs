//! The in-process daemon world of `saiife approvals` and `saiife touch`
//! (tests/approvals_cmd.rs, tests/touch_cmd.rs): the real audit writer,
//! vault, approval store, touch state, control server and HTTP gateway on
//! temp dirs, served on a Unix socket to the real `saiife` binary. The
//! directory is a fixed passwd/group text naming the test user, `boss`
//! (4242, an approver) and `carol` (4343, not one). The upstream is a
//! loopback HTTPS mock; nothing leaves 127.0.0.1. Included with
//! `#[path = "common/approvals_world.rs"] mod approvals_world;` next to
//! `mod common;`, so the other test binaries do not build it.
#![allow(dead_code)]

use crate::common::daemon::{own_group, own_uid, own_user, wait_for};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use saiife_audit::{ChainWriter, WriterOptions};
use saiife_daemon::approvals::{dir_in, State};
use saiife_daemon::ops::{dispatch_conn, Conn, Ctx, CtxInit, PolicyState};
use saiife_daemon::sessions::host_proc;
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

pub const SECRET: &str = "erp-secret-value-123";
pub const BOSS: u32 = 4242;
pub const CAROL: u32 = 4343;
pub const BODY_A: &str = r#"{"amount": 5, "to": "acme"}"#;
pub const BODY_B: &str = r#"{"amount": 5000, "to": "mallory"}"#;

// ---------------------------------------------------------------- mock

pub struct Mock {
    pub port: u16,
    /// `(method path, body)` of every request.
    pub hits: Arc<Mutex<Vec<(String, String)>>>,
    pub ca_pem: String,
}

impl Mock {
    pub fn hits(&self) -> Vec<(String, String)> {
        self.hits.lock().unwrap().clone()
    }
}

pub fn mock() -> Mock {
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

pub fn serve_one(
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
pub struct FakeReauth {
    pub allow: AtomicBool,
    /// The `--detail request` of every check.
    pub details: Mutex<Vec<String>>,
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
pub static REAUTH_SERIAL: Mutex<()> = Mutex::new(());

pub struct World {
    pub reauth: Arc<FakeReauth>,
    pub rt: tokio::runtime::Runtime,
    pub ctx: Arc<Ctx>,
    pub m: Mock,
    pub tmp: tempfile::TempDir,
    /// Held from the first [`World::own_reauth`] to the end of the test.
    pub serial: std::cell::OnceCell<std::sync::MutexGuard<'static, ()>>,
}

pub fn config_text(tmp: &Path, port: u16, erp_extra: &str) -> String {
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
pub fn pay_manifest(port: u16) -> saiife_broker::Manifest {
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
pub fn policy_of(tmp: &Path, port: u16, text: &str) -> PolicyState {
    let config = tmp.join("etc/config.toml");
    fs::write(&config, text).unwrap();
    let l = saiife_policy::load_system(&config).unwrap();
    let cat = saiife_broker::Catalog::new(saiife_broker::builtin(), vec![pay_manifest(port)]);
    saiife_broker::catalog::validate(&l.config, &cat).unwrap();
    PolicyState::from_loaded(&l, &[], cat)
}

pub fn world() -> World {
    world_with("")
}

pub fn world_with(erp_extra: &str) -> World {
    world_capped(erp_extra, None)
}

/// [`world_with`], the approval store keeping results of at most
/// `result_cap` sealed bytes.
pub fn world_capped(erp_extra: &str, result_cap: Option<usize>) -> World {
    let m = mock();
    let tmp = crate::common::tmp::short_tempdir();
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
            proc: host_proc(),
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
    pub fn path(&self) -> &Path {
        self.tmp.path()
    }

    /// `saiife api --system-config ... <args>` as the requester.
    pub fn api_cmd(&self, args: &[&str]) -> Command {
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

    pub fn api(&self, args: &[&str]) -> Output {
        self.api_cmd(args).output().unwrap()
    }

    /// `invoices.create` with `body` through the CLI: the pending id.
    pub fn ask(&self, body: &str) -> u64 {
        self.ask_with(body, &[])
    }

    /// [`World::ask`] with more arguments (parameters).
    pub fn ask_with(&self, body: &str, more: &[&str]) -> u64 {
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
    pub fn op(&self, uid: u32, op: &str, args: Value) -> Value {
        let conn = self.conn(uid);
        self.op_on(&conn, op, args)
    }

    /// A connection as `uid` (pid: this process; start time unknown), for
    /// several ops on one connection.
    pub fn conn(&self, uid: u32) -> Conn {
        Conn::new(
            PeerCred {
                uid,
                gid: uid,
                pid: std::process::id(),
                sid: None,
                group_sids: Vec::new(),
            },
            None,
        )
    }

    /// One op on `conn`.
    pub fn op_on(&self, conn: &Conn, op: &str, args: Value) -> Value {
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

    pub fn decide(&self, uid: u32, id: u64, action: &str) -> Value {
        self.op(
            uid,
            "approval.decide",
            json!({"request": id, "action": action}),
        )
    }

    pub fn state(&self, id: u64) -> Option<State> {
        self.ctx
            .approvals
            .as_ref()
            .unwrap()
            .get(id)
            .map(|r| r.state)
    }

    /// Wait (at most 10 s) for request `id` to reach `s`.
    pub fn wait_state(&self, id: u64, s: State) {
        assert!(
            wait_for(Duration::from_secs(10), || self.state(id) == Some(s)),
            "request #{id} is {:?}, not {s:?}",
            self.state(id)
        );
    }

    pub fn records(&self) -> Vec<Value> {
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
                crate::common::complete_lines(&text)
                    .map(|l| serde_json::from_str(l).unwrap())
                    .collect::<Vec<Value>>()
            })
            .collect()
    }

    pub fn approval_records(&self, id: u64) -> Vec<Value> {
        self.records()
            .into_iter()
            .filter(|r| r["kind"] == "approval" && r["approval"] == id)
            .collect()
    }

    /// Wait (at most 10 s) for the `approval` record of `action` for `id`.
    /// The `lockdown` record with `rule`, once written.
    pub fn wait_lockdown_record(&self, rule: &str) -> Value {
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

    pub fn wait_record(&self, id: u64, action: &str) -> Value {
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
    pub fn http(&self, req: &str) -> String {
        let mut s =
            std::os::unix::net::UnixStream::connect(self.path().join("run/gateway.sock")).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        s.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    }

    pub fn get_request(&self, id: u64) -> String {
        self.http(&format!(
            "GET /v1/requests/{id} HTTP/1.1\r\nHost: saiife\r\nConnection: close\r\n\r\n"
        ))
    }
}

pub fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

pub fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// The id of `saiife: pending approval #<id> (saiife api result <id>)`.
pub fn pending_id(o: &Output) -> u64 {
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
    pub fn cli_cmd(&self, cmd: &str, args: &[&str]) -> Command {
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

    pub fn cli(&self, cmd: &str, args: &[&str]) -> Output {
        self.cli_cmd(cmd, args).output().unwrap()
    }

    /// Make the own user an approver who re-authenticates for its own
    /// requests (`same_user = "reauth"`); `ok` is the fake's answer.
    pub fn own_reauth(&self, ok: bool) {
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

pub fn json_out(o: &Output) -> Value {
    serde_json::from_str(stdout(o).trim()).unwrap_or_else(|e| panic!("{e}: {}", stdout(o)))
}

pub fn ok(o: &Output) {
    assert_eq!(o.status.code(), Some(0), "{}", stderr(o));
}

/// A fake `pkttyagent`: writes its pid (`$$`, the script `exec`s), its
/// parent's pid and its argv, then sleeps until it is killed.
pub fn fake_agent(dir: &Path) -> PathBuf {
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
