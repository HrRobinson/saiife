//! `saiife api` end to end (plan 10, Task 9): a real daemon on temp dirs, a
//! generic `http` service pointing at a loopback HTTPS mock, and a vault
//! secret added through `saiife secret add`. The mock's CA is trusted
//! through `<config dir>/ca/`, the same directory production uses, and
//! the service's base URL is the IP literal `127.0.0.1`: no test seam in
//! the daemon. Nothing leaves loopback; signals go to the test's own child
//! through a syscall.
#![cfg(target_os = "linux")]

mod common;

use common::daemon::{own_group, own_user, wait_for, Opts, TestDaemon};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

const SECRET: &str = "erp-secret-value-123";
const SECRET_NAME: &str = "erp-key";

// ---------------------------------------------------------------- mock

struct Mock {
    port: u16,
    hits: Arc<Mutex<Vec<String>>>,
    gate: Arc<(Mutex<bool>, Condvar)>,
    ca_pem: String,
}

impl Mock {
    fn hits(&self) -> Vec<String> {
        self.hits.lock().unwrap().clone()
    }
    fn release(&self) {
        let (m, c) = &*self.gate;
        *m.lock().unwrap() = true;
        c.notify_all();
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
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let (h, g) = (hits.clone(), gate.clone());
    std::thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            let (cfg, h, g) = (cfg.clone(), h.clone(), g.clone());
            std::thread::spawn(move || serve_one(cfg, tcp, h, g));
        }
    });
    Mock {
        port,
        hits,
        gate,
        ca_pem: ca.pem(),
    }
}

fn serve_one(
    cfg: Arc<rustls::ServerConfig>,
    tcp: TcpStream,
    hits: Arc<Mutex<Vec<String>>>,
    gate: Arc<(Mutex<bool>, Condvar)>,
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
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let header = |n: &str| {
        headers
            .iter()
            .find(|(k, _)| k == n)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    let len: usize = header("content-length").parse().unwrap_or(0);
    while buf.len() < head_end + len {
        match tls.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    hits.lock().unwrap().push(format!("{method} {path}"));
    let (status, body) = match path.split('?').next().unwrap_or("") {
        "/api/echo" => (
            200,
            json!({"echo": header("x-api-key"), "items": [1, 2]}).to_string(),
        ),
        "/api/missing" => (404, r#"{"error":"no such invoice"}"#.to_string()),
        "/api/block" => {
            let (m, c) = &*gate;
            let mut open = m.lock().unwrap();
            while !*open {
                let (g, t) = c.wait_timeout(open, Duration::from_secs(20)).unwrap();
                open = g;
                if t.timed_out() {
                    break;
                }
            }
            (200, r#"{"ok":true,"blocked":true}"#.to_string())
        }
        _ => (200, r#"{"ok":true}"#.to_string()),
    };
    let resp = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = tls.write_all(resp.as_bytes());
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

// ---------------------------------------------------------------- setup

struct World {
    d: TestDaemon,
    m: Mock,
    opts: Opts,
    project: PathBuf,
}

/// The policy: one scope for the test user with `erp`; `other` exists
/// but is not in the scope. `{limits}` goes into `[services.erp]`.
fn policy(port: u16, scope_services: &str, erp_extra: &str) -> String {
    let base = format!("https://127.0.0.1:{port}/api");
    format!(
        r#"[admin]
groups = [{group:?}]

[[scope]]
name = "agents"
users = [{user:?}]
services = [{scope_services}]
env = "prod"

[services.erp]
connector = "http"
base_url = "{base}"
secret = "{SECRET_NAME}"
auth = {{ kind = "header", name = "X-Api-Key" }}
allow = ["invoices:read"]
ask = ["invoices:write"]
{erp_extra}

[[services.erp.operation]]
id = "invoices.list"
capability = "invoices:read"
kind = "read"
method = "GET"
path = "/echo"
query = ["status"]

[[services.erp.operation]]
id = "invoices.missing"
capability = "invoices:read"
kind = "read"
method = "GET"
path = "/missing"

[[services.erp.operation]]
id = "invoices.block"
capability = "invoices:read"
kind = "read"
method = "GET"
path = "/block"

[[services.erp.operation]]
id = "invoices.create"
capability = "invoices:write"
kind = "write"
method = "POST"
path = "/invoices"
body = "json"

[[services.erp.operation]]
id = "reports.get"
capability = "reports:read"
kind = "read"
method = "GET"
path = "/reports"

[services.other]
connector = "http"
base_url = "{base}"
allow = ["things:read"]

[[services.other.operation]]
id = "things.list"
capability = "things:read"
kind = "read"
method = "GET"
path = "/echo"
"#,
        group = own_group(),
        user = own_user(),
    )
}

/// The CA dir is the test user's, not root's: the debug-build owner seam.
fn spawn(d: &mut TestDaemon) {
    let uid = common::daemon::own_uid().to_string();
    d.spawn_and_wait_with(&[("SAIIFE_TEST_CA_OWNER", &uid)]);
}

fn world_with(policy_text: impl FnOnce(u16) -> String, secret_services: &[&str]) -> World {
    world_spawned(policy_text, secret_services, spawn)
}

fn world_spawned(
    policy_text: impl FnOnce(u16) -> String,
    secret_services: &[&str],
    start: impl FnOnce(&mut TestDaemon),
) -> World {
    let m = mock();
    let opts = Opts {
        extra: policy_text(m.port),
        ..Opts::default()
    };
    let mut d = TestDaemon::prepare(&opts);
    let ca = d.path().join("etc/ca");
    fs::create_dir_all(&ca).unwrap();
    fs::write(ca.join("test-ca.pem"), &m.ca_pem).unwrap();
    start(&mut d);
    let project = d.path().join("project");
    fs::create_dir_all(&project).unwrap();
    let mut args = vec!["add", SECRET_NAME, "--kind", "header", "--from-env", "SV"];
    for s in secret_services {
        args.push("--service");
        args.push(s);
    }
    // No services: no secret (a test whose policy does not load).
    if !secret_services.is_empty() {
        let o = secret(&d, &args);
        assert_eq!(
            o.status.code(),
            Some(0),
            "{} daemon: {}",
            stderr(&o),
            d.stderr_text()
        );
    }
    World {
        d,
        m,
        opts,
        project,
    }
}

fn world() -> World {
    world_with(|p| policy(p, "\"erp\"", ""), &["erp"])
}

fn base_cmd(d: &TestDaemon) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_saiife"));
    c.env("HOME", d.path().join("home"))
        .env("PATH", "/usr/bin:/bin")
        .env("SAIIFE_DATA_DIR", d.path().join("data"))
        .env("SAIIFE_AUDIT_DIR", d.audit_dir())
        .stdin(Stdio::null());
    c
}

fn secret(d: &TestDaemon, args: &[&str]) -> Output {
    base_cmd(d)
        .arg("secret")
        .arg("--system-config")
        .arg(d.config())
        .args(args)
        .env("SV", SECRET)
        .output()
        .unwrap()
}

fn api_cmd(w: &World, args: &[&str]) -> Command {
    let mut c = base_cmd(&w.d);
    c.arg("api")
        .arg("--system-config")
        .arg(w.d.config())
        .args(args)
        .current_dir(&w.project);
    c
}

fn api(w: &World, args: &[&str]) -> Output {
    api_cmd(w, args).output().unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn connector(d: &TestDaemon) -> Vec<Value> {
    d.of_kind("connector")
}

fn signal(d: &TestDaemon, sig: rustix::process::Signal) {
    let pid = rustix::process::Pid::from_raw(d.pid() as i32).unwrap();
    rustix::process::kill_process(pid, sig).unwrap();
}

fn policy_records(d: &TestDaemon, result: &str) -> Vec<Value> {
    d.of_kind("policy")
        .into_iter()
        .filter(|r| r["result"] == json!(result))
        .collect()
}

fn reload(w: &World) {
    signal(&w.d, rustix::process::Signal::HUP);
}

fn denied_rule(o: &Output) -> String {
    assert_eq!(o.status.code(), Some(2), "{}", stderr(o));
    let e = stderr(o);
    let rule = e
        .lines()
        .find_map(|l| l.strip_prefix("saiife: denied ("))
        .and_then(|r| r.strip_suffix(')'))
        .unwrap_or_else(|| panic!("no denied line: {e}"));
    rule.to_string()
}

// ---------------------------------------------------------------- tests

/// One HTTP/1.1 request by hand on `gateway.sock`; the whole answer.
fn gateway(d: &TestDaemon, req: &str) -> String {
    let mut s =
        std::os::unix::net::UnixStream::connect(d.socket_dir().join("gateway.sock")).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    s.write_all(req.as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

#[test]
fn gateway_socket_runs_the_same_pipeline() {
    let w = world();
    let body = r#"{"params":{"status":"open"}}"#;
    let out = gateway(
        &w.d,
        &format!(
            "POST /v1/api/erp/invoices.list HTTP/1.1\r\nHost: saiife\r\nAuthorization: Bearer agent-tok\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    );
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert!(
        out.to_ascii_lowercase()
            .contains("x-saiife-upstream-status: 200"),
        "{out}"
    );
    // The vault value the mock echoed is masked.
    assert!(out.contains("[MASKED]") && !out.contains(SECRET), "{out}");
    let out = gateway(
        &w.d,
        "GET /v1/proxy/erp/echo/%2e%2e HTTP/1.1\r\nHost: saiife\r\nConnection: close\r\n\r\n",
    );
    assert!(out.starts_with("HTTP/1.1 403"), "{out}");
    assert!(out.contains(r#""rule":"bad_path""#), "{out}");
    assert_eq!(w.m.hits(), vec!["GET /api/echo?status=open".to_string()]);
    let recs = connector(&w.d);
    assert_eq!(recs.len(), 2);
    assert!(recs.iter().all(|r| r["via"] == "http"), "{recs:?}");
}

#[test]
fn no_scope_denied_no_upstream_call() {
    let w = world_with(|p| policy(p, "", ""), &["erp"]);
    let o = api(&w, &["erp", "invoices.list"]);
    assert_eq!(denied_rule(&o), "no_scope");
    assert!(w.m.hits().is_empty());
    let r = &connector(&w.d)[0];
    assert_eq!(r["decision"], "deny");
    assert_eq!(r["rule"], "no_scope");
}

#[test]
fn scope_conflict_denied() {
    // The user's primary group in a second scope: only the per-request
    // check sees it (a group line that lists the user would be caught at
    // load time instead, so skip then).
    let g = own_group();
    let line = Command::new("getent").args(["group", &g]).output().unwrap();
    let members = String::from_utf8_lossy(&line.stdout)
        .trim()
        .rsplit(':')
        .next()
        .unwrap_or("")
        .to_string();
    if members.split(',').any(|m| m == own_user()) {
        eprintln!("skipped: {g} lists {} as a member", own_user());
        return;
    }
    let w = world_with(
        |p| {
            format!(
                "{}\n[[scope]]\nname = \"by-group\"\nusers = [\"group:{g}\"]\nservices = [\"erp\"]\n",
                policy(p, "\"erp\"", "")
            )
        },
        &["erp"],
    );
    let o = api(&w, &["erp", "invoices.list"]);
    assert_eq!(denied_rule(&o), "scope_conflict");
    assert!(w.m.hits().is_empty());
}

#[test]
fn unknown_operation_denied() {
    let w = world();
    let o = api(&w, &["erp", "invoices.nuke"]);
    assert_eq!(denied_rule(&o), "unknown_operation");
    assert!(w.m.hits().is_empty());
}

#[test]
fn default_deny_denied() {
    let w = world();
    let o = api(&w, &["erp", "reports.get"]);
    assert_eq!(denied_rule(&o), "default_deny");
    assert!(w.m.hits().is_empty());
}

#[test]
fn ask_denied_until_plan_11() {
    let w = world();
    let body = w.d.path().join("body.json");
    fs::write(&body, br#"{"amount": 5}"#).unwrap();
    let at = format!("@{}", body.display());
    let o = api(&w, &["erp", "invoices.create", "--body", &at]);
    assert_eq!(denied_rule(&o), "approval_not_available");
    assert!(w.m.hits().is_empty());
}

#[test]
fn project_deny_tightens() {
    let w = world();
    fs::create_dir_all(w.project.join(".saiife")).unwrap();
    fs::write(
        w.project.join(".saiife/config.toml"),
        "version = 2\n[services.erp]\ndeny = [\"invoices:read\"]\nallow = [\"reports:read\"]\n",
    )
    .unwrap();
    let o = api(&w, &["erp", "invoices.list"]);
    assert_eq!(denied_rule(&o), "deny:invoices:read");
    let o = api(&w, &["erp", "reports.get"]);
    assert_eq!(denied_rule(&o), "default_deny");
    assert!(w.m.hits().is_empty());
}

#[test]
fn secret_not_allowed_for_service() {
    let w = world_with(|p| policy(p, "\"erp\"", ""), &["billing"]);
    let o = api(&w, &["erp", "invoices.list"]);
    assert_eq!(denied_rule(&o), "secret_not_allowed_for_service");
    assert!(w.m.hits().is_empty());
}

#[test]
fn limit_reached_exit_4() {
    let w = world_with(
        |p| {
            policy(
                p,
                "\"erp\"",
                "[services.erp.limits]\nrequests_per_minute = 2\n",
            )
        },
        &["erp"],
    );
    for _ in 0..2 {
        let o = api(&w, &["erp", "invoices.list"]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    }
    let o = api(&w, &["erp", "invoices.list"]);
    assert_eq!(o.status.code(), Some(4), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("limit reached (requests_per_minute)"),
        "{}",
        stderr(&o)
    );
    assert_eq!(w.m.hits().len(), 2);
    let r = connector(&w.d).pop().unwrap();
    assert_eq!(r["decision"], "deny");
    assert_eq!(r["limit"], "requests_per_minute");
}

#[test]
fn limit_survives_restart() {
    let mut w = world_with(
        |p| {
            policy(
                p,
                "\"erp\"",
                "[services.erp.limits]\nrequests_per_minute = 1\n",
            )
        },
        &["erp"],
    );
    let o = api(&w, &["erp", "invoices.list"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    signal(&w.d, rustix::process::Signal::TERM);
    assert!(w.d.wait_exit(Duration::from_secs(10)).is_some());
    spawn(&mut w.d);
    let o = api(&w, &["erp", "invoices.list"]);
    assert_eq!(o.status.code(), Some(4), "{}", stderr(&o));
    assert_eq!(w.m.hits().len(), 1);
}

#[test]
fn reload_mid_request_uses_start_snapshot() {
    let mut w = world();
    let h1 = w.d.status()["policy"].clone();
    let child = api_cmd(&w, &["erp", "invoices.block"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    assert!(wait_for(Duration::from_secs(10), || w
        .m
        .hits()
        .iter()
        .any(|h| h == "GET /api/block")));
    // The new policy no longer allows invoices:read.
    w.opts.extra = policy(w.m.port, "\"erp\"", "")
        .replace("allow = [\"invoices:read\"]", "allow = [\"reports:read\"]");
    w.d.write_config(&w.opts);
    reload(&w);
    assert!(wait_for(Duration::from_secs(10), || policy_records(
        &w.d, "loaded"
    )
    .len()
        >= 2));
    let h2 = w.d.status()["policy"].clone();
    assert_ne!(h1, h2);
    w.m.release();
    let o = child.wait_with_output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(stdout(&o).contains("blocked"));
    let r = connector(&w.d)
        .into_iter()
        .find(|r| r["operation"] == "invoices.block")
        .unwrap();
    assert_eq!(r["policy"], h1);
    assert_eq!(r["decision"], "allow");
    // A call that starts after the reload runs under the new policy.
    let o = api(&w, &["erp", "invoices.list"]);
    assert_eq!(denied_rule(&o), "default_deny");
    assert_eq!(connector(&w.d).pop().unwrap()["policy"], h2);
}

#[test]
fn connector_record_fields_exact() {
    let w = world();
    let o = api(&w, &["erp", "invoices.list", "status=open"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let r = connector(&w.d).pop().unwrap();
    let mut keys: Vec<&str> = r.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort();
    let mut want = vec![
        "v",
        "seq",
        "prev",
        "ts",
        "kind",
        "host",
        "uid",
        "user",
        "mode",
        "policy",
        "agent",
        "project",
        "session",
        "tool",
        "input",
        "decision",
        "pack",
        "rule",
        "reason",
        "saiife",
        "peer",
        "service",
        "operation",
        "capability",
        "env",
        "params",
        "body_sha256",
        "body_bytes",
        "status",
        "resp_bytes",
        "duration_ms",
        "secret",
        "limit",
        "via",
        "op_kind",
        "amount",
    ];
    want.sort();
    assert_eq!(keys, want);
    assert_eq!(r["v"], 2);
    assert_eq!(r["kind"], "connector");
    assert_eq!(r["uid"], common::daemon::own_uid());
    assert_eq!(r["user"], own_user());
    assert_eq!(r["mode"], "locked");
    assert_eq!(r["policy"], w.d.status()["policy"]);
    assert_eq!(r["project"], w.project.display().to_string());
    assert_eq!(r["tool"], "api");
    assert_eq!(r["input"], "erp invoices.list status=open");
    assert_eq!(r["decision"], "allow");
    assert_eq!(r["service"], "erp");
    assert_eq!(r["operation"], "invoices.list");
    assert_eq!(r["capability"], "invoices:read");
    assert_eq!(r["env"], "prod");
    assert_eq!(r["params"], json!({"status": "open"}));
    assert_eq!(r["body_sha256"], Value::Null);
    assert_eq!(r["body_bytes"], 0);
    assert_eq!(r["status"], 200);
    assert!(r["resp_bytes"].as_u64().unwrap() > 0);
    assert!(r["duration_ms"].is_u64());
    assert_eq!(r["secret"], SECRET_NAME);
    assert_eq!(r["limit"], Value::Null);
    assert_eq!(r["via"], "cli");
    assert_eq!(r["op_kind"], "read");
    assert_eq!(r["amount"], Value::Null);
    assert!(r["peer"]["pid"].is_u64());
    // The chain still verifies with connector records in it.
    let v = w.d.verify();
    assert_eq!(v.status.code(), Some(0), "{}", stderr(&v));
}

#[test]
fn response_value_masked_end_to_end() {
    let w = world();
    let o = api(&w, &["erp", "invoices.list"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let out = stdout(&o);
    assert!(!out.contains(SECRET), "{out}");
    let v: Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(v["echo"], "[MASKED]");
    assert!(
        stderr(&o).contains("saiife: erp invoices.list → 200 ("),
        "{}",
        stderr(&o)
    );
    // The upstream got the vault value.
    assert_eq!(w.m.hits(), vec!["GET /api/echo"]);
}

#[test]
fn secret_values_absent_from_all_audit_files() {
    let w = world();
    let mut errs = String::new();
    for args in [
        vec!["erp", "invoices.list"],
        vec!["erp", "invoices.missing"],
        vec!["erp", "invoices.list", &format!("status={SECRET}")],
        vec!["erp", "reports.get", &format!("x={SECRET}")],
        vec!["erp", "--json", "invoices.list"],
    ] {
        let args: Vec<&str> = args.iter().map(|s| s.as_ref()).collect();
        let o = api(&w, &args);
        errs.push_str(&stderr(&o));
        assert!(!stdout(&o).contains(SECRET));
    }
    let mut texts = vec![errs, w.d.stderr_text()];
    for e in fs::read_dir(w.d.audit_dir()).unwrap() {
        texts.push(String::from_utf8_lossy(&fs::read(e.unwrap().path()).unwrap()).into_owned());
    }
    let b64 = common_b64(SECRET.as_bytes());
    for t in &texts {
        assert!(!t.contains(SECRET), "a secret value in: {t}");
        assert!(!t.contains(&b64), "a base64 secret value in: {t}");
    }
    assert!(connector(&w.d).len() >= 5);
}

fn common_b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..=c.len() {
            out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

#[test]
fn upstream_404_exit_1_and_body_on_stdout() {
    let w = world();
    let o = api(&w, &["erp", "invoices.missing"]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(stdout(&o).contains("no such invoice"), "{}", stdout(&o));
    assert!(
        stderr(&o).contains("saiife: erp invoices.missing → 404 ("),
        "{}",
        stderr(&o)
    );
    assert_eq!(connector(&w.d).pop().unwrap()["status"], 404);
}

#[test]
fn json_envelope() {
    let w = world();
    let o = api(&w, &["--json", "erp", "invoices.list"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["status"], 200);
    assert_eq!(v["body"]["items"], json!([1, 2]));
    assert_eq!(v["truncated"], false);
}

#[test]
fn daemon_down_exit_5() {
    let d = TestDaemon::prepare(&Opts::default());
    let o = base_cmd(&d)
        .args(["api", "--system-config"])
        .arg(d.config())
        .args(["erp", "invoices.list"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(5), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("cannot reach the saiife daemon"),
        "{}",
        stderr(&o)
    );
}

#[test]
fn list_shows_only_scoped_services() {
    let w = world();
    let o = api(&w, &["--list", "--json"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    let names: Vec<&str> = v["services"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["erp"]);
    let ops = v["services"][0]["operations"].as_array().unwrap();
    let action = |id: &str| {
        ops.iter()
            .find(|o| o["id"] == id)
            .map(|o| o["action"].as_str().unwrap().to_string())
            .unwrap()
    };
    assert_eq!(action("invoices.list"), "allow");
    assert_eq!(action("invoices.create"), "ask");
    assert_eq!(action("reports.get"), "deny");
    assert_eq!(ops[0]["kind"], "read");
    // The text form names the service; no scope lists nothing.
    let o = api(&w, &["--list"]);
    assert!(stdout(&o).contains("invoices.list"), "{}", stdout(&o));
    let w2 = world_with(|p| policy(p, "", ""), &["erp"]);
    let o = api(&w2, &["--list", "--json"]);
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["services"], json!([]));
}

#[test]
fn policy_with_unknown_connector_rejected_on_reload() {
    let mut w = world();
    let h1 = w.d.status()["policy"].clone();
    w.opts.extra = format!(
        "{}\n[services.bad]\nconnector = \"nope\"\n",
        policy(w.m.port, "\"erp\"", "")
    );
    w.d.write_config(&w.opts);
    reload(&w);
    assert!(wait_for(Duration::from_secs(10), || !policy_records(
        &w.d, "rejected"
    )
    .is_empty()));
    let r = &policy_records(&w.d, "rejected")[0];
    assert!(r["reason"].as_str().unwrap().contains("nope"), "{r}");
    // The old policy stays, and connectors keep working under it.
    assert_eq!(w.d.status()["policy"], h1);
    let o = api(&w, &["erp", "invoices.list"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert_eq!(connector(&w.d).pop().unwrap()["policy"], h1);
}

#[test]
fn broken_service_config_at_start_denies_policy_invalid() {
    let w = world_with(
        |p| {
            format!(
                "{}\n[services.bad]\nconnector = \"nope\"\n",
                policy(p, "\"erp\"", "")
            )
        },
        &[],
    );
    let o = api(&w, &["erp", "invoices.list"]);
    assert_eq!(denied_rule(&o), "policy_invalid");
    assert!(w.m.hits().is_empty());
}

#[test]
fn api_result_unavailable_until_plan_11() {
    let w = world();
    let mut c = w.d.client();
    let e = c
        .call("api.result", serde_json::Map::new(), common::daemon::dl())
        .unwrap_err();
    assert_eq!(common::daemon::refused_code(&e), "unavailable");
}

/// Without the owner seam the CA dir is not root's: the daemon starts
/// without the extra CAs, says so in a `ca_refused` record, and the
/// loopback upstream (signed by that CA) is not trusted.
#[test]
fn ca_dir_not_owned_by_root_refused() {
    let w = world_spawned(
        |p| policy(p, "\"erp\"", ""),
        &["erp"],
        |d| d.spawn_and_wait(),
    );
    let ev = w.d.events("ca_refused");
    assert_eq!(ev.len(), 1, "{:?}", w.d.records());
    assert!(ev[0]["reason"].as_str().unwrap().contains("owned by root"));
    assert!(w.d.stderr_text().contains("extra CAs not used"));
    let o = api(&w, &["erp", "invoices.list"]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(stderr(&o).contains("upstream failed"), "{}", stderr(&o));
}

#[test]
fn oversized_overlay_is_bad_request() {
    let w = world();
    fs::create_dir_all(w.project.join(".saiife")).unwrap();
    let many: Vec<String> = (0..300).map(|i| format!("\"r{i}:read\"")).collect();
    fs::write(
        w.project.join(".saiife/config.toml"),
        format!(
            "version = 2\n[services.erp]\ndeny = [{}]\n",
            many.join(", ")
        ),
    )
    .unwrap();
    let o = api(&w, &["erp", "invoices.list"]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(stderr(&o).contains("overlay too large"), "{}", stderr(&o));
    let o = api(&w, &["--list"]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(w.m.hits().is_empty());
}

// ---------------------------------------------------------------- tcp

const TCP_ON: &str = "\n[gateway]\ntcp = \"127.0.0.1:0\"\n";

/// One HTTP/1.1 request by hand on the loopback TCP listener.
fn tcp_request(addr: &str, req: &str) -> String {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    s.write_all(req.as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn tcp_addr(d: &TestDaemon) -> Option<String> {
    d.status()
        .get("gateway_tcp")
        .and_then(Value::as_str)
        .map(str::to_string)
}

#[test]
fn tcp_off_by_default() {
    let w = world();
    assert_eq!(w.d.status().get("gateway_tcp"), Some(&Value::Null));
    assert!(w.d.events("gateway_tcp").is_empty());
}

#[test]
fn tcp_listener_with_api_token() {
    let w = world_with(
        |p| format!("{}{TCP_ON}", policy(p, "\"erp\"", "")),
        &["erp"],
    );
    // The ephemeral port, as bound.
    let addr = tcp_addr(&w.d).expect("a TCP listener");
    let port: u16 = addr.strip_prefix("127.0.0.1:").unwrap().parse().unwrap();
    assert_ne!(port, 0);
    let ev = w.d.events("gateway_tcp");
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0]["addr"], json!(addr));

    let o = api(&w, &["token", "--json"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let v: Value = serde_json::from_str(stdout(&o).trim()).unwrap();
    let tok = v["token"].as_str().unwrap().to_string();
    assert!(tok.starts_with("saiife_gw_"), "{tok}");
    assert!(v["expires"].as_str().unwrap().ends_with('Z'));
    assert!(stderr(&o).contains("valid until"), "{}", stderr(&o));
    // Plain: the token alone on stdout.
    let o = api(&w, &["token"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(stdout(&o).trim().starts_with("saiife_gw_"));

    let body = r#"{"params":{"status":"open"}}"#;
    let call = |auth: &str| {
        tcp_request(
            &addr,
            &format!(
                "POST /v1/api/erp/invoices.list HTTP/1.1\r\nHost: 127.0.0.1\r\n{auth}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
        )
    };
    let out = call(&format!("Authorization: Bearer {tok}\r\n"));
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert!(out.contains("[MASKED]") && !out.contains(SECRET), "{out}");
    let out = call("");
    assert!(out.starts_with("HTTP/1.1 401"), "{out}");
    assert!(out.ends_with(r#"{"error":"token"}"#), "{out}");
    assert_eq!(w.m.hits().len(), 1);
    let recs = connector(&w.d);
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["uid"], json!(common::daemon::own_uid()));
    assert_eq!(recs[0]["peer"]["auth"], "token");

    // Stored hashed, 0600; the token is in no record and no log line.
    use std::os::unix::fs::PermissionsExt;
    let file = w.d.state_dir().join("state/gateway-tokens.json");
    let text = fs::read_to_string(&file).unwrap();
    assert!(!text.contains(&tok[10..]), "{text}");
    assert_eq!(
        fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let audit: String =
        w.d.records()
            .iter()
            .map(|r| r.to_string())
            .collect::<Vec<_>>()
            .join("\n");
    assert!(!audit.contains(&tok[10..]));
    assert!(!w.d.stderr_text().contains(&tok[10..]));
}

#[test]
fn api_token_without_scope_forbidden() {
    // The only scope is someone else's.
    let w = world_with(
        |p| {
            let text = policy(p, "\"erp\"", "").replace(
                &format!("users = [{:?}]", own_user()),
                "users = [\"someone-else\"]",
            );
            format!("{text}{TCP_ON}")
        },
        &["erp"],
    );
    let o = api(&w, &["token"]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(stdout(&o).is_empty());
}

#[test]
fn tcp_bind_failure_keeps_the_daemon() {
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = taken.local_addr().unwrap().to_string();
    let w = world_with(
        |p| {
            format!(
                "{}\n[gateway]\ntcp = \"{addr}\"\n",
                policy(p, "\"erp\"", "")
            )
        },
        &["erp"],
    );
    let ev = w.d.events("gateway_tcp_failed");
    assert_eq!(ev.len(), 1, "{:?}", w.d.records());
    assert!(ev[0]["reason"].as_str().unwrap().contains(&addr));
    assert_eq!(tcp_addr(&w.d), None);
    // The Unix sockets serve as before.
    let o = api(&w, &["erp", "invoices.list"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    drop(taken);
}

#[test]
fn non_loopback_tcp_rejected_at_reload() {
    let w = world_with(
        |p| format!("{}{TCP_ON}", policy(p, "\"erp\"", "")),
        &["erp"],
    );
    let addr = tcp_addr(&w.d).unwrap();
    let text = fs::read_to_string(w.d.config())
        .unwrap()
        .replace("tcp = \"127.0.0.1:0\"", "tcp = \"0.0.0.0:7431\"");
    fs::write(w.d.config(), text).unwrap();
    reload(&w);
    assert!(wait_for(Duration::from_secs(5), || !policy_records(
        &w.d, "rejected"
    )
    .is_empty()));
    let r = &policy_records(&w.d, "rejected")[0];
    assert!(r["reason"].as_str().unwrap().contains("loopback"), "{r}");
    // The listener stays as started.
    assert_eq!(tcp_addr(&w.d), Some(addr));
}

#[test]
fn corrupt_token_file_resets() {
    let w = world_spawned(
        |p| format!("{}{TCP_ON}", policy(p, "\"erp\"", "")),
        &["erp"],
        |d| {
            let dir = d.state_dir().join("state");
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("gateway-tokens.json"), "{not json").unwrap();
            spawn(d);
        },
    );
    let ev = w.d.events("tokens_reset");
    assert_eq!(ev.len(), 1, "{:?}", w.d.records());
    // Tokens work again from scratch.
    let o = api(&w, &["token"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
}
