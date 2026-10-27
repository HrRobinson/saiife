//! Connector approvals end to end (plan 11, Task 3): `saiife api` hits an
//! `ask` rule, gets exit 3, an approver decides, the daemon sends the
//! stored request, and the requester fetches the result.
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
#![cfg(target_os = "linux")]

mod common;

use common::daemon::{own_group, own_uid, own_user, wait_for};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use saiife_audit::{ChainWriter, WriterOptions};
use saiife_broker::limits::Limiter;
use saiife_daemon::approvals::{dir_in, State};
use saiife_daemon::ops::{dispatch_conn, Conn, Ctx, CtxInit, PolicyState};
use saiife_daemon::sessions::RealProc;
use saiife_daemon::vault::{self, Entry, Kind, VaultState};
use saiife_daemon::writer::{self, WriterConfig};
use saiife_ipc::msg::Request;
use saiife_ipc::peer::PeerCred;
use saiife_policy::{FixedDirectory, Fsync};
use serde_json::{json, Map, Value};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
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

struct World {
    rt: tokio::runtime::Runtime,
    ctx: Arc<Ctx>,
    m: Mock,
    tmp: tempfile::TempDir,
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
users = [{user:?}]
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
    world_full(erp_extra, result_cap, "")
}

/// [`world`] with `[guard] ask = [<ask>]` (command approvals, Task 4).
fn world_ask(ask: &str) -> World {
    world_full("", None, &format!("\n[guard]\nask = [{ask}]\n"))
}

/// The world; `tail` is appended to the config text.
fn world_full(erp_extra: &str, result_cap: Option<usize>, tail: &str) -> World {
    let m = mock();
    let tmp = common::tmp::short_tempdir();
    let t = tmp.path();
    for d in [
        "etc/ca", "audit", "state", "run", "proc", "home", "data", "project",
    ] {
        fs::create_dir_all(t.join(d)).unwrap();
    }
    fs::write(t.join("etc/ca/test-ca.pem"), &m.ca_pem).unwrap();
    let text = format!("{}{tail}", config_text(t, m.port, erp_extra));
    let policy = policy_of(t, m.port, &text);

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
    let key_file = t.join("vault-key");
    fs::write(&key_file, [7u8; 32]).unwrap();
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
    let ctx = rt.block_on(async {
        Arc::new(Ctx::new(CtxInit {
            writer: handle,
            writer_cfg: WriterConfig {
                checkpoint_every: 1000,
                checkpoint_interval: Duration::from_secs(900),
                fsync: Fsync::Always,
            },
            directory: Arc::new(FixedDirectory::from_text(&passwd, &group)),
            own_uid: uid,
            own_user: me,
            audit_dir: t.join("audit"),
            socket_dir: t.join("run"),
            key_path: t.join("state/keys/audit.ed25519"),
            config_path: t.join("etc/config.toml"),
            catalog: Vec::new(),
            policy,
            proc: Box::new(RealProc::new(t.join("proc"))),
            vault,
            vault_path,
            limiter: Limiter::new(),
            upstream,
            backup_dir: t.join("state/import-backup"),
            tokens: Arc::new(saiife_daemon::tokens::Tokens::memory_with_clock(Arc::new(
                || 1_800_000_000,
            ))),
            approvals: saiife_daemon::approvals::Store::open(&dir_in(&t.join("state")))
                .map(|s| match result_cap {
                    Some(c) => s.with_result_cap(c),
                    None => s,
                })
                .map_err(|e| e.to_string()),
            lockdown: saiife_daemon::lockdown::Store::memory(),
            grants: saiife_daemon::grants::Grants::open(
                saiife_daemon::grants::path_in(&t.join("state")),
                std::time::SystemTime::now(),
            )
            .0,
        }))
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
    World { rt, ctx, m, tmp }
}

impl World {
    fn path(&self) -> &Path {
        self.tmp.path()
    }

    /// `saiife api --system-config ... <args>` as the requester.
    fn api_cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_saiife"));
        c.env("HOME", self.path().join("home"))
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
        let f = self.path().join(format!("body-{}.json", body.len()));
        fs::write(&f, body).unwrap();
        let o = self.api(&[
            "erp",
            "invoices.create",
            "--body",
            &format!("@{}", f.display()),
        ]);
        assert_eq!(o.status.code(), Some(3), "{}", stderr(&o));
        pending_id(&o)
    }

    /// One op as `uid` (pid: this process; start time unknown).
    fn op(&self, uid: u32, op: &str, args: Value) -> Value {
        let conn = Conn {
            peer: PeerCred {
                uid,
                gid: uid,
                pid: std::process::id(),
            },
            start_time: None,
        };
        let Value::Object(args) = args else {
            panic!("args must be an object")
        };
        let req = Request {
            id: 7,
            op: op.into(),
            args,
        };
        self.rt.block_on(dispatch_conn(&self.ctx, &conn, req))
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
                fs::read_to_string(f)
                    .unwrap()
                    .lines()
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

fn http_status(raw: &str) -> u16 {
    raw.split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn http_body(raw: &str) -> Value {
    let b = raw.split_once("\r\n\r\n").map(|x| x.1).unwrap_or("");
    serde_json::from_str(b).unwrap_or(Value::Null)
}

fn canonical(body: &str) -> String {
    serde_json::to_string(&serde_json::from_str::<Value>(body).unwrap()).unwrap()
}

// ---------------------------------------------------------------- tests

/// A second uid listed in `approvers` approves: the daemon sends the
/// request once, and the requester gets the result.
#[test]
fn approve_by_second_uid_sends_once() {
    let w = world();
    let id = w.ask(BODY_A);
    // Nothing was sent while it waits; `api result` says pending (3).
    assert!(w.m.hits().is_empty());
    let o = w.api(&["result", &id.to_string()]);
    assert_eq!(o.status.code(), Some(3), "{}", stderr(&o));
    assert_eq!(pending_id(&o), id);

    let a = w.decide(BOSS, id, "approve");
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a["state"], "approved");
    w.wait_state(id, State::Sent);
    assert_eq!(w.m.hits().len(), 1);
    // Deciding again changes nothing and sends nothing.
    let again = w.decide(BOSS, id, "approve");
    assert_eq!(again["ok"], false, "{again}");
    assert!(
        again["message"].as_str().unwrap().contains("is sent"),
        "{again}"
    );
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(w.m.hits().len(), 1);

    let o = w.api(&["result", &id.to_string()]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let out: Value = serde_json::from_str(stdout(&o).trim()).unwrap();
    assert_eq!(out["created"], true);
    assert!(
        stderr(&o).contains(&format!("request #{id} → 201")),
        "{}",
        stderr(&o)
    );
    // The approver came from the daemon's own lookup of uid 4242.
    let approved = w.wait_record(id, "approved");
    assert_eq!(approved["by_uid"], BOSS);
}

/// Under `same_user = "deny"` the requester cannot approve its own
/// request; the refusal is recorded with its rule, and nothing is sent.
#[test]
fn self_approval_refused_and_recorded() {
    let w = world();
    let id = w.ask(BODY_A);
    // The requester is not listed: `not_approver`.
    let a = w.decide(own_uid(), id, "approve");
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["error"], "forbidden");
    assert_eq!(a["rule"], "not_approver");
    // Listed, but it is its own request: `same_user`.
    let text = config_text(w.path(), w.m.port, "").replace(
        "approvers = [\"boss\"]",
        &format!("approvers = [\"boss\", {:?}]", own_user()),
    );
    *w.ctx.policy.lock().unwrap() = policy_of(w.path(), w.m.port, &text);
    let a = w.op(
        own_uid(),
        "approval.decide",
        json!({"request": id, "action": "reject"}),
    );
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["rule"], "same_user");
    let refused: Vec<Value> = w
        .approval_records(id)
        .into_iter()
        .filter(|r| r["action"] == "refused")
        .collect();
    assert_eq!(refused.len(), 2, "{refused:?}");
    assert_eq!(refused[0]["rule"], "not_approver");
    assert_eq!(refused[1]["rule"], "same_user");
    assert_eq!(refused[1]["by_uid"], own_uid());
    assert_eq!(refused[1]["decision"], "rejected");
    // A uid that is neither an approver nor the requester.
    let a = w.decide(CAROL, id, "approve");
    assert_eq!(a["ok"], false, "{a}");
    // carol cannot even see the request: it answers as unknown.
    assert_eq!(a["error"], "bad_request", "{a}");
    assert_eq!(w.state(id), Some(State::Pending));
    assert!(w.m.hits().is_empty());
}

/// What is sent is the stored request: a second call with a changed body
/// after the approval is a new request of its own, not an edit.
#[test]
fn approve_sends_stored_body_not_new_one() {
    let w = world();
    let first = w.ask(BODY_A);
    let a = w.decide(BOSS, first, "approve");
    assert_eq!(a["ok"], true, "{a}");
    // The agent tries again with another body while the first is sent.
    let second = w.ask(BODY_B);
    assert_ne!(first, second);
    w.wait_state(first, State::Sent);
    let hits = w.m.hits();
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0].0, "POST /api/invoices");
    assert_eq!(hits[0].1, canonical(BODY_A));
    // The second waits for its own approval.
    assert_eq!(w.state(second), Some(State::Pending));
    // Each request shows its own body to the approver (masked; the exact
    // request is sealed).
    let file: Value = serde_json::from_slice(
        &fs::read(dir_in(&w.path().join("state")).join(format!("{second}.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(file["body_display"], canonical(BODY_B));
    let first_file: Value = serde_json::from_slice(
        &fs::read(dir_in(&w.path().join("state")).join(format!("{first}.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(first_file["body_display"], canonical(BODY_A));
}

#[test]
fn reject_gives_410_and_exit_2() {
    let w = world();
    let id = w.ask(BODY_A);
    let a = w.op(
        BOSS,
        "approval.decide",
        json!({"request": id, "action": "reject", "note": "no"}),
    );
    assert_eq!(a["state"], "rejected", "{a}");
    let raw = w.get_request(id);
    assert_eq!(http_status(&raw), 410, "{raw}");
    assert_eq!(http_body(&raw), json!({"state": "rejected"}));
    let o = w.api(&["result", &id.to_string()]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(
        stderr(&o).contains(&format!("request #{id} was rejected")),
        "{}",
        stderr(&o)
    );
    let r = w.wait_record(id, "rejected");
    assert_eq!(r["note"], "no");
    assert!(w.m.hits().is_empty());
}

/// Decision 2: the stored call is decided again against the policy in
/// force at send; a now-`deny` is `send_failed`, `rule = policy_changed`.
#[test]
fn policy_changed_to_deny_send_failed() {
    let w = world();
    let id = w.ask(BODY_A);
    let text = config_text(w.path(), w.m.port, "deny = [\"invoices:write\"]\n");
    *w.ctx.policy.lock().unwrap() = policy_of(w.path(), w.m.port, &text);
    assert_eq!(w.decide(BOSS, id, "approve")["ok"], true);
    w.wait_state(id, State::SendFailed);
    assert!(w.m.hits().is_empty());
    let r = w.wait_record(id, "send_failed");
    assert_eq!(r["rule"], "policy_changed");
    let o = w.api(&["result", &id.to_string()]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("denied (policy_changed)"),
        "{}",
        stderr(&o)
    );
    let raw = w.get_request(id);
    assert_eq!(http_status(&raw), 410, "{raw}");
    assert_eq!(http_body(&raw)["state"], "send_failed");
    assert_eq!(http_body(&raw)["rule"], "policy_changed");
}

/// Decision 1: creation checks the limits without counting; the send
/// counts for real, and over a limit then is `send_failed` with it.
#[test]
fn limit_reached_at_send_send_failed() {
    let w = world_with("[services.erp.limits]\nwrites_per_hour = 1\n");
    let a = w.ask(BODY_A);
    let b = w.ask(BODY_B);
    assert_eq!(w.decide(BOSS, a, "approve")["ok"], true);
    w.wait_state(a, State::Sent);
    assert_eq!(w.decide(BOSS, b, "approve")["ok"], true);
    w.wait_state(b, State::SendFailed);
    assert_eq!(w.m.hits().len(), 1);
    let r = w.wait_record(b, "send_failed");
    assert_eq!(r["limit"], "writes_per_hour");
    let o = w.api(&["result", &b.to_string()]);
    assert_eq!(o.status.code(), Some(4), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("limit reached (writes_per_hour)"),
        "{}",
        stderr(&o)
    );
    // Now the hour is full: a new ask is denied at once with its limit.
    let f = w.path().join("c.json");
    fs::write(&f, BODY_A).unwrap();
    let o = w.api(&[
        "erp",
        "invoices.create",
        "--body",
        &format!("@{}", f.display()),
    ]);
    assert_eq!(o.status.code(), Some(4), "{}", stderr(&o));
}

/// Decision 4: the requester sees its own requests and results, approvers
/// see every request, anyone else nothing (as an unknown id).
#[test]
fn result_visible_to_requester_only() {
    let w = world();
    let id = w.ask(BODY_A);
    // Another uid: unknown, for the result, the request and the list.
    let a = w.op(CAROL, "api.result", json!({"request": id}));
    assert_eq!(a["error"], "bad_request", "{a}");
    let a = w.op(CAROL, "approval.show", json!({"request": id}));
    assert_eq!(a["error"], "bad_request", "{a}");
    let a = w.op(CAROL, "approval.list", json!({}));
    assert_eq!(a["items"], json!([]), "{a}");
    // Even the approver gets no result (it is the requester's).
    let a = w.op(BOSS, "api.result", json!({"request": id}));
    assert_eq!(a["error"], "bad_request", "{a}");
    // The approver sees the masked request; the requester its own.
    let a = w.op(BOSS, "approval.list", json!({"states": ["pending"]}));
    let items = a["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{a}");
    assert_eq!(items[0]["id"], id);
    assert!(items[0].get("request_sealed").is_none(), "{a}");
    // `own` (as `saiife status` asks): the approver's own requests only.
    let a = w.op(BOSS, "approval.list", json!({"own": true}));
    assert_eq!(a["items"], json!([]), "{a}");
    let a = w.op(own_uid(), "approval.list", json!({"own": true}));
    assert_eq!(a["items"].as_array().unwrap().len(), 1, "{a}");
    let a = w.op(own_uid(), "approval.show", json!({"request": id}));
    assert_eq!(a["item"]["operation"], "invoices.create", "{a}");
    let a = w.op(own_uid(), "api.result", json!({"request": id}));
    assert_eq!(a["state"], "pending", "{a}");
    // Over HTTP the requester gets 202; an unknown id is 404.
    let raw = w.get_request(id);
    assert_eq!(http_status(&raw), 202, "{raw}");
    assert_eq!(http_body(&raw)["pending"], id);
    assert_eq!(http_status(&w.get_request(id + 100)), 404);
    let o = w.api(&["result", &(id + 100).to_string()]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
}

/// Every step is a record linked by the approval id; the connector record
/// of the send says `via = approval`.
#[test]
fn records_linked_by_approval_id() {
    let w = world();
    let id = w.ask(BODY_A);
    assert_eq!(w.decide(BOSS, id, "approve")["ok"], true);
    w.wait_state(id, State::Sent);
    w.wait_record(id, "sent");
    let actions: Vec<Value> = w
        .approval_records(id)
        .iter()
        .map(|r| r["action"].clone())
        .collect();
    assert_eq!(
        actions,
        vec![json!("created"), json!("approved"), json!("sent")]
    );
    for r in w.approval_records(id) {
        assert_eq!(r["id"], id);
        assert_eq!(r["uid"], own_uid());
        assert_eq!(r["service"], "erp");
        assert_eq!(r["operation"], "invoices.create");
    }
    let conn: Vec<Value> = w
        .records()
        .into_iter()
        .filter(|r| r["kind"] == "connector")
        .collect();
    assert_eq!(conn.len(), 2, "{conn:?}");
    assert_eq!(conn[0]["decision"], "ask");
    assert_eq!(conn[0]["approval"], id);
    assert_eq!(conn[0]["via"], "cli");
    assert_eq!(conn[1]["decision"], "allow");
    assert_eq!(conn[1]["approval"], id);
    assert_eq!(conn[1]["via"], "approval");
    assert_eq!(conn[1]["approved_by"], BOSS);
    assert_eq!(conn[1]["asked_via"], "cli");
    assert_eq!(w.wait_record(id, "sent")["asked_via"], "cli");
    assert_eq!(conn[1]["status"], 201);
    assert_eq!(conn[1]["uid"], own_uid());
    // No record holds the vault value.
    let all = serde_json::to_string(&w.records()).unwrap();
    assert!(!all.contains(SECRET));
}

/// Decision 3: `--wait` polls `api.result` every 2 s; an approval while it
/// waits ends it with the result, exit 0.
#[test]
fn wait_returns_after_approval() {
    let w = world();
    let f = w.path().join("a.json");
    fs::write(&f, BODY_A).unwrap();
    let started = Instant::now();
    let child = w
        .api_cmd(&[
            "erp",
            "invoices.create",
            "--body",
            &format!("@{}", f.display()),
            "--wait",
            "30s",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let store = w.ctx.approvals.as_ref().unwrap();
    assert!(wait_for(Duration::from_secs(10), || !store
        .list(Default::default())
        .is_empty()));
    let id = store.list(Default::default())[0].id;
    assert_eq!(w.decide(BOSS, id, "approve")["ok"], true);
    let o = child.wait_with_output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(started.elapsed() < Duration::from_secs(25));
    let out: Value = serde_json::from_str(stdout(&o).trim()).unwrap();
    assert_eq!(out["got"], canonical(BODY_A));
    // Without an approval `--wait` gives up with exit 3.
    let started = Instant::now();
    let o = w
        .api_cmd(&[
            "erp",
            "invoices.create",
            "--body",
            &format!("@{}", f.display()),
            "--wait",
            "1s",
        ])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(3), "{}", stderr(&o));
    assert!(started.elapsed() >= Duration::from_secs(1));
    pending_id(&o);
}

/// The HTTP gateway answers 202 `{"pending": id}` at once; once sent,
/// `GET /v1/requests/{id}` gives the result with the upstream status.
#[test]
fn gateway_pending_then_result() {
    let w = world();
    let body = format!(r#"{{"body":{BODY_A},"wait":"10m"}}"#);
    let raw = w.http(&format!(
        "POST /v1/api/erp/invoices.create HTTP/1.1\r\nHost: saiife\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    ));
    assert_eq!(http_status(&raw), 202, "{raw}");
    let id = http_body(&raw)["pending"].as_u64().unwrap();
    assert_eq!(http_status(&w.get_request(id)), 202);
    assert_eq!(w.decide(BOSS, id, "approve")["ok"], true);
    w.wait_state(id, State::Sent);
    let raw = w.get_request(id);
    assert_eq!(http_status(&raw), 200, "{raw}");
    assert!(
        raw.to_ascii_lowercase()
            .contains("x-saiife-upstream-status: 201"),
        "{raw}"
    );
    assert_eq!(http_body(&raw)["got"], canonical(BODY_A));
    let conn: Vec<Value> = w
        .records()
        .into_iter()
        .filter(|r| r["kind"] == "connector")
        .collect();
    assert_eq!(conn[0]["via"], "http");
    assert_eq!(conn[1]["via"], "approval");
}

/// A stored request that cannot be opened at send (the vault became
/// unavailable) is never sent: `send_failed`, `rule = vault_unavailable`.
#[test]
fn vault_unavailable_at_send_send_failed() {
    let w = world();
    let id = w.ask(BODY_A);
    *w.ctx.vault.lock() = VaultState::Unavailable("gone".into());
    assert_eq!(w.decide(BOSS, id, "approve")["ok"], true);
    w.wait_state(id, State::SendFailed);
    assert_eq!(
        w.wait_record(id, "send_failed")["rule"],
        "vault_unavailable"
    );
    assert!(w.m.hits().is_empty());
    let mut m = Map::new();
    m.insert("request".into(), id.into());
    let a = w.op(own_uid(), "api.result", Value::Object(m));
    assert_eq!(a["state"], "send_failed", "{a}");
}

/// The approver sees what will be sent: `approval.show` has the amount,
/// the masked canonical body and its SHA-256, which is the hash of what
/// the upstream gets after the approval (the sealed request is what is
/// sent). `approval.list` has them too, the body cut short.
#[test]
fn show_displays_amount_masked_body_and_its_hash() {
    let w = world();
    let body = format!(
        r#"{{ "refund": {{"amount": "12.50", "currency": "EUR"}}, "memo": "{SECRET}", "pad": "{}" }}"#,
        "x".repeat(300)
    );
    let f = w.path().join("refund.json");
    fs::write(&f, &body).unwrap();
    let o = w.api(&[
        "pay",
        "refunds.create",
        "--body",
        &format!("@{}", f.display()),
    ]);
    assert_eq!(o.status.code(), Some(3), "{}", stderr(&o));
    let id = pending_id(&o);

    let a = w.op(BOSS, "approval.show", json!({"request": id}));
    let item = &a["item"];
    assert_eq!(
        item["amount"],
        json!({"minor": 1250, "currency": "EUR"}),
        "{a}"
    );
    let shown = item["body_display"].as_str().unwrap();
    assert!(shown.contains(r#""memo":"[MASKED]""#), "{shown}");
    assert!(shown.contains(r#""amount":"12.50""#), "{shown}");
    assert!(!a.to_string().contains(SECRET), "{a}");
    let hash = item["body_sha256"].as_str().unwrap().to_string();
    assert_eq!(item["headers"], json!([]));
    // The list shows the same, the body cut short.
    let l = w.op(BOSS, "approval.list", json!({}));
    let li = &l["items"][0];
    assert_eq!(li["body_sha256"], hash);
    assert_eq!(li["amount"]["minor"], 1250);
    assert!(
        li["body_display"].as_str().unwrap().chars().count() <= 201,
        "{l}"
    );

    assert_eq!(w.decide(BOSS, id, "approve")["ok"], true);
    w.wait_state(id, State::Sent);
    let hits = w.m.hits();
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0].0, "POST /api/refunds");
    use sha2::Digest as _;
    let got = sha2::Sha256::digest(hits[0].1.as_bytes());
    let got: String = got.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(got, hash);
    // The sent body holds the real value: only the display copy is masked.
    assert!(hits[0].1.contains(SECRET));
}

/// Review focus 4: a pending request approved during a lockdown is not
/// sent: `send_failed`, `rule = lockdown`.
#[test]
fn lockdown_at_send_send_failed() {
    let w = world();
    let id = w.ask(BODY_A);
    w.ctx
        .lockdown
        .set(Some(saiife_broker::pipeline::Lockdown {
            scope: saiife_broker::pipeline::LockScope::Connectors,
            reason: "drill".into(),
            by_uid: BOSS,
            since: "now".into(),
        }))
        .unwrap();
    assert_eq!(w.decide(BOSS, id, "approve")["ok"], true);
    w.wait_state(id, State::SendFailed);
    assert_eq!(w.wait_record(id, "send_failed")["rule"], "lockdown");
    assert!(w.m.hits().is_empty());
}

/// `api.call` as the requester (this process's uid) at the ops level.
fn ops_ask(w: &World, body: &str) -> Value {
    use base64::Engine as _;
    w.op(
        own_uid(),
        "api.call",
        json!({"service": "erp", "operation": "invoices.create",
               "body_b64": base64::engine::general_purpose::STANDARD.encode(body)}),
    )
}

/// A sealed result over the store's cap is not kept: a small
/// `result_too_large` note is, the request stays `sent`, and the `sent`
/// record says so. A result under the cap is kept whole.
#[test]
fn result_too_large_to_keep_is_a_note() {
    let cap = 16 * 1024;
    let w = world_capped("", Some(cap));
    // About 4 KiB echoed back: kept.
    let small = format!(r#"{{"note": "{}"}}"#, "s".repeat(4000));
    let a = w.ask(&small);
    assert_eq!(w.decide(BOSS, a, "approve")["ok"], true);
    w.wait_state(a, State::Sent);
    let o = w.api(&["result", &a.to_string()]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    // Near the cap and over it once sealed (base64 in the answer).
    let big = format!(r#"{{"note": "{}"}}"#, "b".repeat(cap - 100));
    let b = w.ask(&big);
    assert_eq!(w.decide(BOSS, b, "approve")["ok"], true);
    w.wait_state(b, State::Sent);
    assert_eq!(w.m.hits().len(), 2);
    let rec = w.wait_record(b, "sent");
    assert_eq!(rec["result_too_large"], true, "{rec}");
    assert_eq!(rec["status"], 201);
    let res = w.op(own_uid(), "api.result", json!({"request": b}));
    assert_eq!(res["state"], "sent", "{res}");
    assert_eq!(res["result"]["error"], "result_too_large", "{res}");
    assert_eq!(res["result"]["status"], 201, "{res}");
    assert!(res["result"]["resp_bytes"].as_u64().unwrap() > (cap - 100) as u64);
    let o = w.api(&["result", &b.to_string()]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(stderr(&o).contains("too large to keep"), "{}", stderr(&o));
    // The result file is the raw sealed bytes, not base64 in JSON.
    let raw = fs::read(dir_in(&w.path().join("state")).join(format!("{a}.result"))).unwrap();
    assert!(raw.starts_with(b"SAIIFER2"));
}

/// `approval.show` has the whole masked body (up to 1 MiB): a large key
/// that sorts first hides nothing. A body shown cut must be approved with
/// `ack_truncated`.
#[test]
fn show_has_the_whole_body_and_a_cut_one_needs_an_ack() {
    let w = world();
    let body = format!(
        r#"{{"aaa": "{}", "zz_to": "mallory", "zz_amount": 9999}}"#,
        "p".repeat(100_000)
    );
    let id = w.ask(&body);
    let a = w.op(BOSS, "approval.show", json!({"request": id}));
    let shown = a["item"]["body_display"].as_str().unwrap();
    assert_eq!(shown, canonical(&body));
    assert!(shown.contains(r#""zz_to":"mallory""#));
    assert_eq!(a["item"]["body_truncated"], false);
    let l = w.op(BOSS, "approval.list", json!({}));
    assert!(
        l["items"][0]["body_display"]
            .as_str()
            .unwrap()
            .chars()
            .count()
            <= 201
    );

    // A request whose body was shown cut (over 1 MiB masked).
    let file = dir_in(&w.path().join("state")).join(format!("{id}.json"));
    let mut v: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    v["body_truncated"] = json!(true);
    fs::write(&file, serde_json::to_vec(&v).unwrap()).unwrap();
    let a = w.decide(BOSS, id, "approve");
    assert_eq!(a["rule"], "truncated_not_acknowledged", "{a}");
    assert_eq!(
        w.wait_record(id, "refused")["rule"],
        "truncated_not_acknowledged"
    );
    assert_eq!(w.state(id), Some(State::Pending));
    let a = w.op(
        BOSS,
        "approval.decide",
        json!({"request": id, "action": "approve", "ack_truncated": true}),
    );
    assert_eq!(a["ok"], true, "{a}");
    w.wait_state(id, State::Sent);
}

/// The `created` record could not be written: the request is expired at
/// once, so nobody can approve it.
#[test]
fn unrecorded_ask_is_expired_at_once() {
    let w = world();
    // No signing key here: the stop says the checkpoint failed, and stops.
    let _ = w.rt.block_on(w.ctx.writer.stop(None));
    let a = ops_ask(&w, BODY_A);
    assert_eq!(a["ok"], false, "{a}");
    let all = w.ctx.approvals.as_ref().unwrap().list(Default::default());
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].state, State::Expired);
    let d = w.decide(BOSS, all[0].id, "approve");
    assert_eq!(d["ok"], false, "{d}");
    assert!(w.m.hits().is_empty());
}

/// At most 20 pending requests per uid; the next is denied
/// (`approvals_full`) and recorded.
#[test]
fn at_most_20_pending_per_uid() {
    let w = world();
    for _ in 0..20 {
        assert!(ops_ask(&w, BODY_A)["pending"].is_u64());
    }
    let a = ops_ask(&w, BODY_A);
    assert_eq!(a["rule"], "approvals_full", "{a}");
    let conn: Vec<Value> = w
        .records()
        .into_iter()
        .filter(|r| r["kind"] == "connector")
        .collect();
    assert_eq!(conn.last().unwrap()["rule"], "approvals_full");
    // One decided frees a place.
    assert_eq!(w.decide(BOSS, 1, "reject")["ok"], true);
    assert!(ops_ask(&w, BODY_A)["pending"].is_u64());
}

/// An approved `/v1/proxy` request is sent with the method, path and
/// query of the original.
#[test]
fn approved_proxy_request_sends_the_same_method_path_and_query() {
    let w = world();
    let raw = w.http(&format!(
        "POST /v1/proxy/erp/invoices?ref=abc-7 HTTP/1.1\r\nHost: saiife\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY_A}",
        BODY_A.len()
    ));
    assert_eq!(http_status(&raw), 202, "{raw}");
    let id = http_body(&raw)["pending"].as_u64().unwrap();
    assert_eq!(w.decide(BOSS, id, "approve")["ok"], true);
    w.wait_state(id, State::Sent);
    let hits = w.m.hits();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].0, "POST /api/invoices?ref=abc-7");
    assert_eq!(hits[0].1, canonical(BODY_A));
    let rec = w.wait_record(id, "sent");
    assert_eq!(rec["asked_via"], "http");
}

// ------------------------------------------------- command approvals (Task 4)

const FORCE_PUSH: &str = "git push --force origin main";
const ASK_FORCE_PUSH: &str = "\"core.git/force-push\"";

impl World {
    /// One `saiife check --managed` call for a Bash `command` in the
    /// project, as the requester.
    fn hook(&self, command: &str) -> Output {
        let payload = json!({
            "session_id": "s-cmd",
            "cwd": self.path().join("project"),
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command}
        })
        .to_string();
        let mut child = Command::new(env!("CARGO_BIN_EXE_saiife"))
            .env("HOME", self.path().join("home"))
            .env("PATH", "/usr/bin:/bin")
            .env("SAIIFE_DATA_DIR", self.path().join("data"))
            .env("SAIIFE_AUDIT_DIR", self.path().join("audit"))
            .current_dir(self.path().join("project"))
            .args(["check", "--managed", "--agent", "claude", "--system-config"])
            .arg(self.path().join("etc/config.toml"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut sin = child.stdin.take().unwrap();
        let wr = std::thread::spawn(move || {
            let _ = sin.write_all(payload.as_bytes());
        });
        let out = child.wait_with_output().unwrap();
        wr.join().unwrap();
        out
    }

    /// The guard records, in order.
    fn guard_records(&self) -> Vec<Value> {
        self.records()
            .into_iter()
            .filter(|r| r["kind"] == "guard")
            .collect()
    }

    /// The project as the key holds it: canonical (no `.saiife/config.toml`
    /// here, so the cwd).
    fn project(&self) -> String {
        fs::canonicalize(self.path().join("project"))
            .unwrap()
            .display()
            .to_string()
    }

    fn requests(&self) -> Vec<saiife_daemon::approvals::Request> {
        self.ctx
            .approvals
            .as_ref()
            .unwrap()
            .list(Default::default())
    }
}

fn sha_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The key the daemon must compute for `input` run by this user.
fn key_for(project: &str, input: &str, raw: &str) -> String {
    use sha2::{Digest, Sha256};
    let raw: [u8; 32] = Sha256::digest(raw.as_bytes()).into();
    let k = saiife_daemon::grants::grant_key(own_uid(), "claude", project, "Bash", input, &raw);
    saiife_daemon::grants::hex(&k)
}

/// The args of `grant.consume` / `approval.create` for `input`, as the hook
/// sends them, with `raw` as the exact command.
fn call_args(input: &str, raw: &str, rule_id: &str) -> Value {
    let mut r = common::daemon::guard_rec(input);
    r["decision"] = "deny".into();
    r["pack"] = "core.git".into();
    r["rule_id"] = rule_id.into();
    r["grant_key"] = "00".repeat(32).into();
    json!({"rec": r, "raw_sha256": sha_hex(raw), "project": "/p"})
}

/// The request id of `Needs approval: request #<id>. ...`, checking the
/// whole line is the spec's message.
fn needs_approval_id(o: &Output) -> u64 {
    let e = stderr(o);
    let line = e
        .lines()
        .find(|l| l.starts_with("Needs approval: request #"))
        .unwrap_or_else(|| panic!("no needs-approval line: {e}"));
    let id: u64 = line["Needs approval: request #".len()..]
        .split('.')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        line,
        format!("Needs approval: request #{id}. Run the same command again after it is approved.")
    );
    id
}

/// A force-push under `[guard] ask`: a pending command request (with the
/// daemon's key), the exact spec message, exit 2, and a guard record
/// `ask` linked by the id.
#[test]
fn hook_ask_rule_creates_request_and_denies_with_message() {
    let w = world_ask(ASK_FORCE_PUSH);
    let o = w.hook(FORCE_PUSH);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    let id = needs_approval_id(&o);
    let r = w.ctx.approvals.as_ref().unwrap().get(id).unwrap();
    assert_eq!(r.state, State::Pending);
    assert_eq!(r.kind, saiife_daemon::approvals::ApprovalType::Command);
    assert_eq!(r.uid, own_uid());
    assert_eq!(r.agent, "claude");
    assert_eq!(r.input.as_deref(), Some(FORCE_PUSH));
    assert!(r.request_sealed.is_none());
    let want = key_for(&w.project(), FORCE_PUSH, FORCE_PUSH);
    assert_eq!(r.grant_key.as_deref(), Some(want.as_str()));
    // `show` never gives the key away.
    let shown = w.op(BOSS, "approval.show", json!({"request": id}));
    assert_eq!(shown["item"]["type"], "command", "{shown}");
    assert!(shown["item"].get("grant_key").is_none(), "{shown}");

    let g = w.guard_records();
    let last = g.last().unwrap();
    assert_eq!(last["decision"], "ask", "{last}");
    assert_eq!(last["approval"], id);
    assert_eq!(last["pack"], "core.git");
    assert_eq!(last["rule_id"], "force-push");
    assert_eq!(last["reason"], format!("needs approval: request #{id}"));
    let created = w.wait_record(id, "created");
    assert_eq!(created["type"], "command");
    assert_eq!(created["input"], FORCE_PUSH);
    assert_eq!(created["uid"], own_uid());
}

/// Approved once: the same command runs once (record `approved` with the
/// id), then needs approval again. A trailing space is another command.
#[test]
fn hook_after_approval_allows_once_then_asks_again() {
    let w = world_ask(ASK_FORCE_PUSH);
    let first = needs_approval_id(&w.hook(FORCE_PUSH));
    let a = w.decide(BOSS, first, "approve");
    assert_eq!(a["ok"], true, "{a}");
    w.wait_state(first, State::Sent);
    assert_eq!(w.ctx.grants.len(), 1);
    let sent = w.wait_record(first, "sent");
    assert_eq!(sent["by_uid"], BOSS);

    // Not the approved command: a request of its own; the grant stays.
    let spaced = w.hook(&format!("{FORCE_PUSH} "));
    assert_eq!(spaced.status.code(), Some(2), "{}", stderr(&spaced));
    let other = needs_approval_id(&spaced);
    assert_ne!(other, first);
    assert_eq!(w.ctx.grants.len(), 1);

    let o = w.hook(FORCE_PUSH);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let last = w.guard_records().pop().unwrap();
    assert_eq!(last["decision"], "approved", "{last}");
    assert_eq!(last["approval"], first);
    assert_eq!(last["input"], FORCE_PUSH);
    assert!(w.ctx.grants.is_empty());

    let again = w.hook(FORCE_PUSH);
    assert_eq!(again.status.code(), Some(2), "{}", stderr(&again));
    let next = needs_approval_id(&again);
    assert!(next != first && next != other);
}

/// The requester cannot approve its own command under `same_user =
/// "deny"`: refused, still pending, no grant, the command still blocked.
#[test]
fn self_approval_of_command_refused() {
    let w = world_ask(ASK_FORCE_PUSH);
    let id = needs_approval_id(&w.hook(FORCE_PUSH));
    let text = format!(
        "{}\n[guard]\nask = [{ASK_FORCE_PUSH}]\n",
        config_text(w.path(), w.m.port, "")
    )
    .replace(
        "approvers = [\"boss\"]",
        &format!("approvers = [\"boss\", {:?}]", own_user()),
    );
    *w.ctx.policy.lock().unwrap() = policy_of(w.path(), w.m.port, &text);
    let a = w.decide(own_uid(), id, "approve");
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["rule"], "same_user", "{a}");
    assert_eq!(w.state(id), Some(State::Pending));
    assert!(w.ctx.grants.is_empty());
    // Asking again gives the same pending request, not a new one.
    let o = w.hook(FORCE_PUSH);
    assert_eq!(o.status.code(), Some(2));
    assert_eq!(needs_approval_id(&o), id);
    assert_eq!(w.requests().len(), 1);
}

/// A deny rule not under `[guard] ask` is denied as before, without a
/// grant lookup or a request.
#[test]
fn non_ask_deny_unchanged() {
    let w = world_ask(ASK_FORCE_PUSH);
    let o = w.hook("git reset --hard");
    assert_eq!(o.status.code(), Some(2));
    assert!(
        stderr(&o).starts_with("BLOCKED by core.git: "),
        "{}",
        stderr(&o)
    );
    assert_eq!(w.ctx.grants.consume_count(), 0);
    let all = w.ctx.approvals.as_ref().unwrap().list(Default::default());
    assert!(all.is_empty(), "{all:?}");
    let last = w.guard_records().pop().unwrap();
    assert_eq!(last["decision"], "deny");
    assert!(last.get("approval").is_none(), "{last}");
    // An allowed command makes no extra round trip either.
    assert_eq!(w.hook("git status").status.code(), Some(0));
    assert_eq!(w.ctx.grants.consume_count(), 0);
    // The ask rule does.
    w.hook(FORCE_PUSH);
    assert_eq!(w.ctx.grants.consume_count(), 1);
}

/// A request that cannot be stored fails closed: `error_denied`.
#[test]
fn ask_without_store_is_error_denied() {
    use std::os::unix::fs::PermissionsExt;
    let w = world_ask(ASK_FORCE_PUSH);
    let dir = dir_in(&w.path().join("state"));
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
    let o = w.hook(FORCE_PUSH);
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(
        stderr(&o).contains("BLOCKED (fail closed)"),
        "{}",
        stderr(&o)
    );
    let last = w.guard_records().pop().unwrap();
    assert_eq!(last["decision"], "error_denied", "{last}");
}

/// `approval.create` takes only a call one of the `[guard] ask` rules
/// denied, and never a key from the client.
#[test]
fn approval_create_takes_only_ask_rules() {
    let w = world_ask(ASK_FORCE_PUSH);
    let create = |args: Value| w.op(own_uid(), "approval.create", args);
    // A rule that is not under ask.
    let a = create(call_args(FORCE_PUSH, FORCE_PUSH, "reset-hard"));
    assert_eq!(a["rule"], "not_ask", "{a}");
    // An ask rule that does not deny the submitted command.
    let a = create(call_args("echo hi", "echo hi", "force-push"));
    assert_eq!(a["rule"], "ask_rule_mismatch", "{a}");
    let refused: Vec<Value> = w
        .records()
        .into_iter()
        .filter(|r| r["kind"] == "approval" && r["action"] == "refused")
        .collect();
    assert_eq!(refused.len(), 2, "{refused:?}");
    assert_eq!(refused[1]["rule"], "ask_rule_mismatch");
    assert_eq!(refused[1]["uid"], own_uid());
    // No raw hash: refused.
    let mut no_raw = call_args(FORCE_PUSH, FORCE_PUSH, "force-push");
    no_raw.as_object_mut().unwrap().remove("raw_sha256");
    assert_eq!(create(no_raw)["error"], "bad_request");
    assert!(w.requests().is_empty());

    let a = create(call_args(FORCE_PUSH, FORCE_PUSH, "force-push"));
    assert_eq!(a["ok"], true, "{a}");
    let id = a["request"].as_u64().unwrap();
    let r = w.ctx.approvals.as_ref().unwrap().get(id).unwrap();
    assert_eq!(
        r.grant_key.as_deref(),
        Some(key_for("/p", FORCE_PUSH, FORCE_PUSH).as_str())
    );
}

/// The grant is for the exact command: the same shown input with another
/// raw command (what a masked span could hide) is not granted.
#[test]
fn grant_is_bound_to_the_raw_command() {
    let w = world_ask(ASK_FORCE_PUSH);
    let a = w.op(
        own_uid(),
        "approval.create",
        call_args(FORCE_PUSH, FORCE_PUSH, "force-push"),
    );
    let id = a["request"].as_u64().unwrap();
    assert_eq!(w.decide(BOSS, id, "approve")["ok"], true);
    let consume = |raw: &str| {
        w.op(
            own_uid(),
            "grant.consume",
            call_args(FORCE_PUSH, raw, "force-push"),
        )
    };
    let other = consume("GH_TOKEN=$(echo x) git push --force origin main");
    assert_eq!(other["granted"], false, "{other}");
    let used = consume(FORCE_PUSH);
    assert_eq!(used["granted"], true, "{used}");
    assert_eq!(used["approval"], id);
    // The use is on record.
    let rec = w.wait_record(id, "grant_used");
    assert_eq!(rec["uid"], own_uid());
    assert_eq!(consume(FORCE_PUSH)["granted"], false);
}

/// A command with a masked span cannot be approved: a plain deny saying
/// so, no request. The attack: `GH_TOKEN=abc ...` shows as
/// `GH_TOKEN=[MASKED] ...`, as would `GH_TOKEN=$(echo x) ...`.
#[test]
fn masked_command_is_a_plain_deny() {
    let w = world_ask(ASK_FORCE_PUSH);
    for (i, cmd) in [
        "GH_TOKEN=abc git push --force origin main",
        "GH_TOKEN=$(echo x) git push --force origin main",
    ]
    .into_iter()
    .enumerate()
    {
        let o = w.hook(cmd);
        assert_eq!(o.status.code(), Some(2), "{cmd}: {}", stderr(&o));
        assert!(!stderr(&o).contains("Needs approval"), "{}", stderr(&o));
        let last = w.guard_records().pop().unwrap();
        assert_eq!(last["decision"], "deny", "{last}");
        assert!(last.get("approval").is_none(), "{last}");
        if i == 0 {
            assert_eq!(
                last["reason"],
                "cannot be approved: the command contains masked or overlong content",
                "{last}"
            );
        }
    }
    assert!(w.requests().is_empty());
    assert_eq!(w.ctx.grants.consume_count(), 0);
}

/// A command over the record's 4096 characters is shown cut: a plain deny.
#[test]
fn overlong_command_is_a_plain_deny() {
    let w = world_ask(ASK_FORCE_PUSH);
    let cmd = format!("{FORCE_PUSH} {}", "x".repeat(4100));
    let o = w.hook(&cmd);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("cannot be approved: the command contains masked or overlong content"),
        "{}",
        stderr(&o)
    );
    assert!(w.requests().is_empty());
}

/// A compound command another rule denies too is a plain deny.
#[test]
fn compound_command_with_a_hard_deny_is_a_plain_deny() {
    let w = world_ask(ASK_FORCE_PUSH);
    let o = w.hook(&format!("{FORCE_PUSH}; rm -rf /"));
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(!stderr(&o).contains("Needs approval"), "{}", stderr(&o));
    assert!(w.requests().is_empty());
    let last = w.guard_records().pop().unwrap();
    assert_eq!(last["decision"], "deny", "{last}");
}

/// At most 20 pending requests: the 21st command gets the spec'd hint.
#[test]
fn too_many_pending_commands_say_so() {
    let w = world_ask(ASK_FORCE_PUSH);
    for i in 0..20 {
        let a = w.op(
            own_uid(),
            "approval.create",
            call_args(FORCE_PUSH, &format!("{FORCE_PUSH} #{i}"), "force-push"),
        );
        assert_eq!(a["ok"], true, "{a}");
    }
    let o = w.hook(FORCE_PUSH);
    assert_eq!(o.status.code(), Some(2));
    assert_eq!(
        stderr(&o).trim_end(),
        "Too many pending approval requests (20); ask an approver to decide the open ones."
    );
    let last = w.guard_records().pop().unwrap();
    assert_eq!(last["decision"], "deny", "{last}");
}

/// A command approved but not marked sent when the daemon stopped: at
/// start its grant is revoked and it is `send_failed` (`interrupted`).
#[test]
fn interrupted_command_approval_revokes_its_grant() {
    let w = world_ask(ASK_FORCE_PUSH);
    let a = w.op(
        own_uid(),
        "approval.create",
        call_args(FORCE_PUSH, FORCE_PUSH, "force-push"),
    );
    let id = a["request"].as_u64().unwrap();
    let store = w.ctx.approvals.as_ref().unwrap();
    let r = store
        .transition(
            id,
            &[State::Pending],
            State::Approved,
            Some(BOSS),
            None,
            std::time::SystemTime::now(),
        )
        .unwrap();
    let key = saiife_daemon::grants::unhex(r.grant_key.as_deref().unwrap()).unwrap();
    w.ctx
        .grants
        .insert(
            key,
            id,
            std::time::SystemTime::now() + Duration::from_secs(900),
        )
        .unwrap();
    let recs = saiife_daemon::approval_ops::reconcile_interrupted(&w.ctx);
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].rule.as_deref(), Some("interrupted"));
    assert!(w.ctx.grants.is_empty());
    assert_eq!(w.state(id), Some(State::SendFailed));
}

/// A project config cannot define a pack or rule ids: only the built-in
/// catalog counts, so a fake `core.git` with a `force-push` rule that
/// matches `echo` changes nothing.
#[test]
fn project_cannot_define_packs_or_rule_ids() {
    let w = world_ask(ASK_FORCE_PUSH);
    fs::create_dir_all(w.path().join("project/.saiife")).unwrap();
    fs::write(
        w.path().join("project/.saiife/config.toml"),
        "packs = [\"core.git\"]\n[pack]\nid = \"core.git\"\n[[deny]]\nid = \"force-push\"\npattern = \"^echo\"\nreason = \"x\"\n",
    )
    .unwrap();
    let o = w.hook("echo hi");
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(w.requests().is_empty());
    // The real rule still asks, keyed by the project root.
    let o = w.hook(FORCE_PUSH);
    let id = needs_approval_id(&o);
    let r = w.ctx.approvals.as_ref().unwrap().get(id).unwrap();
    assert_eq!(
        r.grant_key.as_deref(),
        Some(key_for(&w.project(), FORCE_PUSH, FORCE_PUSH).as_str())
    );
    let p = saiife_policy::parse_project(
        &fs::read(w.path().join("project/.saiife/config.toml")).unwrap(),
    )
    .unwrap();
    assert_eq!(p.packs, ["core.git"]);
}

/// `[guard] ask` naming a rule no active pack has makes the policy
/// invalid: the daemon accepts audit only.
#[test]
fn unknown_guard_ask_rule_is_config_error() {
    use common::daemon::{Opts, TestDaemon};
    let d = TestDaemon::start(Opts {
        extra: "[guard]\nask = [\"core.git/no-such-rule\"]\n".into(),
        ..Default::default()
    });
    let st = d.status();
    assert_eq!(st["policy_ok"], false, "{st:?}");
    assert!(
        d.stderr_text().contains("core.git/no-such-rule"),
        "{}",
        d.stderr_text()
    );
    // A pack that is not active is an error too.
    let d = TestDaemon::start(Opts {
        extra: "[guard]\nask = [\"db.postgres/drop-database\"]\n".into(),
        ..Default::default()
    });
    assert_eq!(d.status()["policy_ok"], false);
    // Listed in an active pack: fine.
    let d = TestDaemon::start(Opts {
        extra: "[guard]\npacks = [\"db.postgres\"]\nask = [\"core.git/force-push\", \"db.postgres/drop-database\"]\n".into(),
        ..Default::default()
    });
    assert_eq!(d.status()["policy_ok"], true, "{}", d.stderr_text());
}

/// Hook latency with `[guard] ask` set (run with `--release --ignored`):
/// an allowed call, a deny not under ask (no extra round trip) and an ask
/// (two extra round trips). Prints the median and p95 in ms.
#[test]
#[ignore]
fn bench_managed_hook_with_ask() {
    let w = world_ask(ASK_FORCE_PUSH);
    let n = 19;
    let time = |cmd: &str| {
        let mut t: Vec<f64> = (0..n)
            .map(|_| {
                let s = Instant::now();
                w.hook(cmd);
                s.elapsed().as_secs_f64() * 1000.0
            })
            .collect();
        t.sort_by(|a, b| a.partial_cmp(b).unwrap());
        (t[n / 2], t[(n * 95 / 100).min(n - 1)])
    };
    for (name, cmd) in [
        ("allow", "git status && ls -la src"),
        ("deny", "git reset --hard"),
        ("ask", FORCE_PUSH),
    ] {
        let (p50, p95) = time(cmd);
        eprintln!("bench {name}: median {p50:.1} ms, p95 {p95:.1} ms");
    }
}
