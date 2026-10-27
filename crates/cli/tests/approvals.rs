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
use saiife_daemon::ops::{check_services, dispatch_conn, Conn, Ctx, CtxInit, PolicyState};
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
services = ["erp"]

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
body = "json"
"#,
        user = own_user(),
        run = tmp.join("run").display().to_string(),
        audit = tmp.join("audit").display().to_string(),
    )
}

/// The policy state of `text` (written to `etc/config.toml`).
fn policy_of(tmp: &Path, text: &str) -> PolicyState {
    let config = tmp.join("etc/config.toml");
    fs::write(&config, text).unwrap();
    let l = saiife_policy::load_system(&config).unwrap();
    let cat = check_services(&l, &config).unwrap();
    PolicyState::from_loaded(&l, &[], cat)
}

fn world() -> World {
    world_with("")
}

fn world_with(erp_extra: &str) -> World {
    let m = mock();
    let tmp = common::tmp::short_tempdir();
    let t = tmp.path();
    for d in [
        "etc/ca", "audit", "state", "run", "proc", "home", "data", "project",
    ] {
        fs::create_dir_all(t.join(d)).unwrap();
    }
    fs::write(t.join("etc/ca/test-ca.pem"), &m.ca_pem).unwrap();
    let policy = policy_of(t, &config_text(t, m.port, erp_extra));

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
        allowed_services: vec!["erp".into()],
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
                .map_err(|e| e.to_string()),
            lockdown: saiife_daemon::lockdown::Store::memory(),
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
    *w.ctx.policy.lock().unwrap() = policy_of(w.path(), &text);
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
    // The request file holds the exact request only sealed.
    let file =
        fs::read_to_string(dir_in(&w.path().join("state")).join(format!("{second}.json"))).unwrap();
    assert!(!file.contains("mallory"), "{file}");
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
    *w.ctx.policy.lock().unwrap() = policy_of(w.path(), &text);
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
