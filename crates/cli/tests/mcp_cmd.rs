//! `saiife mcp` end to end (plan 17, Task 4): the real binary on piped
//! stdio, spoken to by an in-process MCP client (`common::mcp`), against a
//! real daemon on temp dirs with a generic `http` service pointing at a
//! loopback HTTPS mock (as in `tests/api_cmd.rs`). The approval test uses
//! an in-process daemon context (as in `tests/approvals.rs`), because an
//! approval needs a second uid. Nothing leaves loopback; signals go to the
//! test's own daemon child through a syscall.
#![cfg(target_os = "linux")]

mod common;

use common::daemon::{own_group, own_uid, own_user, wait_for, Opts, TestDaemon};
use common::mcp::{texts, McpClient, Where};
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
    let req_body = String::from_utf8_lossy(&buf[head_end..]).into_owned();
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
        "/api/invoices" => (201, json!({"created": true, "got": req_body}).to_string()),
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
}

/// One scope for the test user with `{scope}`; `erp` allows reads and
/// asks for writes, `reports:read` is not allowed (default deny), `other`
/// is in no scope. `{erp_extra}` goes into `[services.erp]`, `{tail}` at
/// the end.
fn policy(port: u16, scope: &str, erp_extra: &str, erp_allow: &str, tail: &str) -> String {
    let base = format!("https://127.0.0.1:{port}/api");
    format!(
        r#"[admin]
groups = [{group:?}]

[[scope]]
name = "agents"
users = [{user:?}]
services = [{scope}]

[services.erp]
connector = "http"
base_url = "{base}"
secret = "{SECRET_NAME}"
auth = {{ kind = "header", name = "X-Api-Key" }}
allow = [{erp_allow}]
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
id = "invoices.delete"
capability = "invoices:delete"
kind = "delete"
method = "DELETE"
path = "/invoices/{{id}}"

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
{tail}"#,
        group = own_group(),
        user = own_user(),
    )
}

fn default_policy(port: u16) -> String {
    policy(
        port,
        "\"erp\"",
        "",
        "\"invoices:read\", \"invoices:delete\"",
        "",
    )
}

fn spawn(d: &mut TestDaemon) {
    let uid = own_uid().to_string();
    d.spawn_and_wait_with(&[("SAIIFE_TEST_CA_OWNER", &uid)]);
}

fn base_cmd(d: &TestDaemon) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_saiife"));
    c.env("HOME", d.path().join("home"))
        .env("XDG_RUNTIME_DIR", d.path().join("no-runtime"))
        .env("PATH", "/usr/bin:/bin")
        .env("SAIIFE_DATA_DIR", d.path().join("data"))
        .env("SAIIFE_AUDIT_DIR", d.audit_dir())
        .stdin(Stdio::null());
    c
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn world_with(policy_text: impl FnOnce(u16) -> String, secret_services: &[&str]) -> World {
    let m = mock();
    let opts = Opts {
        extra: policy_text(m.port),
        ..Opts::default()
    };
    let mut d = TestDaemon::prepare(&opts);
    let ca = d.path().join("etc/ca");
    fs::create_dir_all(&ca).unwrap();
    fs::write(ca.join("test-ca.pem"), &m.ca_pem).unwrap();
    spawn(&mut d);
    fs::create_dir_all(d.path().join("project")).unwrap();
    let mut args = vec!["add", SECRET_NAME, "--kind", "header", "--from-env", "SV"];
    for s in secret_services {
        args.push("--service");
        args.push(s);
    }
    let o = base_cmd(&d)
        .arg("secret")
        .arg("--system-config")
        .arg(d.config())
        .args(&args)
        .env("SV", SECRET)
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(0),
        "{} daemon: {}",
        stderr(&o),
        d.stderr_text()
    );
    World { d, m }
}

fn world() -> World {
    world_with(default_policy, &["erp"])
}

impl World {
    fn mcp(&self, args: &[&str]) -> McpClient {
        let mut c = McpClient::spawn(&self.d, args);
        c.initialize();
        c
    }

    fn connector(&self) -> Vec<Value> {
        self.d.of_kind("connector")
    }
}

fn tool<'a>(list: &'a Value, name: &str) -> Option<&'a Value> {
    list["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == name)
}

fn rpc_code(a: &Value) -> i64 {
    a["error"]["code"]
        .as_i64()
        .unwrap_or_else(|| panic!("not an error: {a}"))
}

const PENDING_TEXT: &str = "waiting for approval #{id}. Call the tool saiife_result with {\"request\": {id}} later to get the result. Do not repeat this call.";

fn pending_text(id: u64) -> String {
    PENDING_TEXT.replace("{id}", &id.to_string())
}

// ---------------------------------------------------------------- tests

#[test]
fn initialize_negotiates_and_lists_tools() {
    let w = world();
    let mut c = McpClient::spawn(&w.d, &[]);
    let r = c.initialize_as("2025-06-18");
    assert_eq!(r["protocolVersion"], "2025-06-18");
    assert_eq!(r["capabilities"], json!({"tools": {"listChanged": true}}));
    assert_eq!(r["serverInfo"]["name"], "saiife");
    assert_eq!(r["serverInfo"]["version"], env!("CARGO_PKG_VERSION"));
    // An unsupported (or unknown) version: the preferred one.
    let mut c2 = McpClient::spawn(&w.d, &[]);
    assert_eq!(
        c2.initialize_as("2025-03-26")["protocolVersion"],
        "2025-11-25"
    );
    let mut c3 = McpClient::spawn(&w.d, &[]);
    assert_eq!(
        c3.initialize_as("2099-01-01")["protocolVersion"],
        "2025-11-25"
    );

    assert_eq!(c.result("ping", json!({})), json!({}));
    let list = c.result("tools/list", json!({}));
    let names: Vec<&str> = list["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec![
            "erp_invoices_block",
            "erp_invoices_create",
            "erp_invoices_delete",
            "erp_invoices_list",
            "erp_invoices_missing",
            "saiife_result"
        ],
        "{list}"
    );
    let l = tool(&list, "erp_invoices_list").unwrap();
    assert!(
        l["description"]
            .as_str()
            .unwrap()
            .ends_with("Policy: allowed."),
        "{l}"
    );
    assert_eq!(l["annotations"]["readOnlyHint"], true);
    assert!(l["annotations"].get("destructiveHint").is_none());
    assert_eq!(l["inputSchema"]["properties"]["status"]["type"], "string");
    assert_eq!(l["inputSchema"]["additionalProperties"], false);
    let cr = tool(&list, "erp_invoices_create").unwrap();
    assert!(
        cr["description"]
            .as_str()
            .unwrap()
            .ends_with("Policy: needs approval; the result says how to get it."),
        "{cr}"
    );
    assert_eq!(cr["inputSchema"]["properties"]["body"]["type"], "object");
    assert!(cr["annotations"].get("readOnlyHint").is_none());
    let del = tool(&list, "erp_invoices_delete").unwrap();
    assert_eq!(del["annotations"]["destructiveHint"], true);
    assert_eq!(del["inputSchema"]["required"], json!(["id"]));
    let r = tool(&list, "saiife_result").unwrap();
    assert_eq!(
        r["inputSchema"]["properties"]["request"],
        json!({"type": "integer", "minimum": 1})
    );
    // Listing makes no connector record.
    assert!(w.connector().is_empty());
}

#[test]
fn deny_operations_not_listed() {
    let w = world();
    // The project tightens one operation: deny is honoured in the listing.
    fs::create_dir_all(w.d.path().join("project/.saiife")).unwrap();
    fs::write(
        w.d.path().join("project/.saiife/config.toml"),
        "version = 2\n[services.erp]\ndeny = [\"invoices:delete\"]\n",
    )
    .unwrap();
    let mut c = w.mcp(&[]);
    let names = c.tool_names();
    assert!(!names.iter().any(|n| n == "erp_reports_get"), "{names:?}");
    assert!(
        !names.iter().any(|n| n == "erp_invoices_delete"),
        "{names:?}"
    );
    assert!(!names.iter().any(|n| n.starts_with("other_")), "{names:?}");
    assert!(names.iter().any(|n| n == "erp_invoices_list"), "{names:?}");
}

#[test]
fn call_allowed_tool_returns_masked_body_and_records_via_mcp() {
    let w = world();
    let mut c = w.mcp(&[]);
    let r = c.call("erp_invoices_list", json!({"status": "open"}));
    assert_eq!(r["isError"], false, "{r}");
    let body: Value = serde_json::from_str(&texts(&r)).unwrap();
    assert_eq!(body, json!({"echo": "[MASKED]", "items": [1, 2]}));
    assert_eq!(w.m.hits(), vec!["GET /api/echo?status=open"]);
    let recs = w.connector();
    assert_eq!(recs.len(), 1, "{recs:?}");
    let rec = &recs[0];
    assert_eq!(rec["via"], "mcp");
    assert_eq!(rec["tool"], "mcp");
    assert_eq!(rec["service"], "erp");
    assert_eq!(rec["operation"], "invoices.list");
    assert_eq!(rec["decision"], "allow");
    assert_eq!(rec["params"]["status"], "open");
    // A number argument is sent as its string.
    let r = c.call("erp_invoices_list", json!({"status": 7}));
    assert_eq!(r["isError"], false, "{r}");
    assert_eq!(w.m.hits()[1], "GET /api/echo?status=7");
    // Upstream status >= 400: an error result with the body.
    let r = c.call("erp_invoices_missing", json!({}));
    assert_eq!(r["isError"], true, "{r}");
    let t = texts(&r);
    assert!(t.starts_with("upstream status 404\n"), "{t}");
    assert!(t.contains("no such invoice"), "{t}");
}

#[test]
fn vault_value_in_response_masked() {
    let w = world();
    let mut c = w.mcp(&[]);
    let mut seen = String::new();
    for args in [json!({}), json!({"status": SECRET})] {
        let r = c.call("erp_invoices_list", args);
        assert_eq!(r["isError"], false, "{r}");
        seen.push_str(&r.to_string());
    }
    assert!(seen.contains("[MASKED]"), "{seen}");
    assert!(!seen.contains(SECRET), "{seen}");
    let mut texts = vec![seen, c.stderr_text(), w.d.stderr_text()];
    for e in fs::read_dir(w.d.audit_dir()).unwrap() {
        texts.push(String::from_utf8_lossy(&fs::read(e.unwrap().path()).unwrap()).into_owned());
    }
    for t in &texts {
        assert!(!t.contains(SECRET), "a secret value in: {t}");
    }
}

#[test]
fn denied_call_is_error_result_not_rpc_error() {
    // The secret is not allowed for erp: listed (the policy allows the
    // operation), denied by the pipeline.
    let w = world_with(default_policy, &["billing"]);
    let mut c = w.mcp(&[]);
    let a = c.request(
        "tools/call",
        json!({"name": "erp_invoices_list", "arguments": {}}),
    );
    assert!(a.get("error").is_none(), "{a}");
    let r = &a["result"];
    assert_eq!(r["isError"], true, "{r}");
    assert_eq!(texts(r), "denied (secret_not_allowed_for_service)", "{r}");
    assert!(w.m.hits().is_empty());
    let rec = w.connector().pop().unwrap();
    assert_eq!(rec["decision"], "deny");
    assert_eq!(rec["via"], "mcp");

    // A tool listed earlier, now denied by the project: still a result,
    // decided by the daemon (listing grants nothing).
    let w = world();
    let mut c = w.mcp(&[]);
    assert!(c.tool_names().iter().any(|n| n == "erp_invoices_list"));
    fs::create_dir_all(w.d.path().join("project/.saiife")).unwrap();
    fs::write(
        w.d.path().join("project/.saiife/config.toml"),
        "version = 2\n[services.erp]\ndeny = [\"invoices:read\"]\n",
    )
    .unwrap();
    let r = c.call("erp_invoices_list", json!({}));
    assert_eq!(r["isError"], true, "{r}");
    assert_eq!(texts(&r), "denied (deny:invoices:read)");
    assert!(w.m.hits().is_empty());
}

#[test]
fn limit_is_error_result() {
    let w = world_with(
        |p| {
            policy(
                p,
                "\"erp\"",
                "[services.erp.limits]\nrequests_per_minute = 1\n",
                "\"invoices:read\"",
                "",
            )
        },
        &["erp"],
    );
    let mut c = w.mcp(&[]);
    let r = c.call("erp_invoices_list", json!({}));
    assert_eq!(r["isError"], false, "{r}");
    let r = c.call("erp_invoices_list", json!({}));
    assert_eq!(r["isError"], true, "{r}");
    assert_eq!(texts(&r), "limit reached (requests_per_minute)");
    assert_eq!(w.m.hits().len(), 1);
    let rec = w.connector().pop().unwrap();
    assert_eq!(rec["limit"], "requests_per_minute");
    assert_eq!(rec["via"], "mcp");
}

#[test]
fn ask_returns_pending_text_and_structured() {
    let w = world();
    let mut c = w.mcp(&[]);
    let r = c.call("erp_invoices_create", json!({"body": {"amount": 5}}));
    assert_eq!(r["isError"], false, "{r}");
    let id = r["structuredContent"]["pending"].as_u64().unwrap();
    assert!(id >= 1);
    assert_eq!(
        r["content"],
        json!([{"type": "text", "text": pending_text(id)}])
    );
    assert!(w.m.hits().is_empty());
    let rec = w.connector().pop().unwrap();
    assert_eq!(rec["decision"], "ask");
    assert_eq!(rec["approval"], json!(id));
    assert_eq!(rec["via"], "mcp");
    // The body went as body_b64 of its compact JSON.
    let file = w.d.state_dir().join(format!("approvals/{id}.json"));
    let v: Value = serde_json::from_slice(&fs::read(file).unwrap()).unwrap();
    assert_eq!(v["body_display"], r#"{"amount":5}"#, "{v}");
    // saiife_result while it waits: the same pending answer.
    let r = c.call("saiife_result", json!({"request": id}));
    assert_eq!(r["isError"], false, "{r}");
    assert_eq!(r["structuredContent"], json!({"pending": id}));
    assert_eq!(texts(&r), pending_text(id));
    // Not the requester's (or no such) request: an error result.
    let r = c.call("saiife_result", json!({"request": id + 100}));
    assert_eq!(r["isError"], true, "{r}");
    // A bad request argument is -32602.
    for bad in [json!({}), json!({"request": 0}), json!({"request": "1"})] {
        let a = c.request(
            "tools/call",
            json!({"name": "saiife_result", "arguments": bad}),
        );
        assert_eq!(rpc_code(&a), -32602, "{a}");
    }
}

#[test]
fn wait_flag_polls_and_sends_progress() {
    let w = world();
    let mut c = w.mcp(&["--wait", "5s"]);
    let started = std::time::Instant::now();
    let r = c.result(
        "tools/call",
        json!({
            "name": "erp_invoices_create",
            "arguments": {"body": {"amount": 5}},
            "_meta": {"progressToken": "tok-1"},
        }),
    );
    assert!(started.elapsed() >= Duration::from_secs(4), "did not wait");
    let id = r["structuredContent"]["pending"].as_u64().unwrap();
    assert_eq!(texts(&r), pending_text(id));
    let mut progress = Vec::new();
    while let Some(n) = c.next_notification(Duration::from_millis(200)) {
        progress.push(n);
    }
    assert!(progress.len() >= 2, "{progress:?}");
    for (i, n) in progress.iter().enumerate() {
        assert_eq!(n["method"], "notifications/progress");
        assert_eq!(n["params"]["progressToken"], "tok-1");
        assert_eq!(n["params"]["progress"], json!((i + 1) as f64));
    }
    assert!(w.m.hits().is_empty());
}

#[test]
fn cancelled_stops_a_wait_poll() {
    let w = world();
    let mut c = w.mcp(&["--wait", "1h"]);
    let id = c.send_request(
        "tools/call",
        json!({
            "name": "erp_invoices_create",
            "arguments": {"body": {"amount": 5}},
            "_meta": {"progressToken": 9},
        }),
    );
    let first = c.next_notification(Duration::from_secs(30)).unwrap();
    assert_eq!(first["params"]["progressToken"], 9);
    c.notify(
        "notifications/cancelled",
        json!({"requestId": id.to_value(), "reason": "test"}),
    );
    // Drain what was in flight, then nothing more: the poll stopped.
    std::thread::sleep(Duration::from_millis(300));
    while c.next_notification(Duration::from_millis(50)).is_some() {}
    assert!(c.next_notification(Duration::from_secs(3)).is_none());
    // A cancelled request is not answered.
    assert!(c.answer_within(&id, Duration::from_millis(500)).is_none());
    // The daemon call was made and recorded (it is not undone).
    assert_eq!(w.connector().pop().unwrap()["decision"], "ask");
    // The server goes on.
    assert!(c.tool_names().contains(&"saiife_result".to_string()));
}

#[test]
fn unknown_tool_is_32602_without_daemon_call() {
    let w = world();
    let mut c = w.mcp(&[]);
    let before = w.d.records().len();
    for name in ["erp_nope", "other_things_list", "erp_reports_get", "erp__x"] {
        let a = c.request("tools/call", json!({"name": name, "arguments": {}}));
        assert_eq!(rpc_code(&a), -32602, "{a}");
    }
    let a = c.request("tools/call", json!({"arguments": {}}));
    assert_eq!(rpc_code(&a), -32602, "{a}");
    let a = c.request("tools/nope", json!({}));
    assert_eq!(rpc_code(&a), -32601, "{a}");
    assert_eq!(w.d.records().len(), before);
    assert!(w.m.hits().is_empty());
}

#[test]
fn bad_argument_type_is_32602() {
    let w = world();
    let mut c = w.mcp(&[]);
    let before = w.d.records().len();
    for (name, args) in [
        ("erp_invoices_list", json!({"status": {"a": 1}})),
        ("erp_invoices_list", json!({"status": [1]})),
        ("erp_invoices_list", json!({"status": null})),
        ("erp_invoices_list", json!({"nope": "x"})),
        ("erp_invoices_create", json!({"body": "not an object"})),
        ("erp_invoices_create", json!({"body": [1, 2]})),
        // No free body on a GET: `body` is an unknown argument.
        ("erp_invoices_list", json!({"body": {}})),
    ] {
        let a = c.request("tools/call", json!({"name": name, "arguments": args}));
        assert_eq!(rpc_code(&a), -32602, "{name} {args}: {a}");
    }
    let a = c.request(
        "tools/call",
        json!({"name": "erp_invoices_list", "arguments": "status=open"}),
    );
    assert_eq!(rpc_code(&a), -32602, "{a}");
    assert_eq!(w.d.records().len(), before);
    assert!(w.m.hits().is_empty());
}

#[test]
fn colliding_tool_names_dropped_not_misrouted() {
    // `erp` `x.list` and `erp-x` `list` are both `erp_x_list`.
    let tail = |base: &str| {
        format!(
            r#"
[[services.erp.operation]]
id = "x.list"
capability = "invoices:read"
kind = "read"
method = "GET"
path = "/x"

[services.erp-x]
connector = "http"
base_url = "{base}"
secret = "{SECRET_NAME}"
auth = {{ kind = "header", name = "X-Api-Key" }}
allow = ["things:read"]

[[services.erp-x.operation]]
id = "list"
capability = "things:read"
kind = "read"
method = "GET"
path = "/echo"
"#
        )
    };
    let w = world_with(
        |p| {
            policy(
                p,
                "\"erp\", \"erp-x\"",
                "",
                "\"invoices:read\"",
                &tail(&format!("https://127.0.0.1:{p}/api")),
            )
        },
        &["erp", "erp-x"],
    );
    let mut c = w.mcp(&[]);
    let names = c.tool_names();
    assert!(!names.iter().any(|n| n == "erp_x_list"), "{names:?}");
    assert!(names.iter().any(|n| n == "erp_invoices_list"), "{names:?}");
    let a = c.request("tools/call", json!({"name": "erp_x_list", "arguments": {}}));
    assert_eq!(rpc_code(&a), -32602, "{a}");
    assert!(w.m.hits().is_empty());
    assert!(w.connector().is_empty());
    let e = c.stderr_text();
    assert!(e.contains("tool name erp_x_list is shared by"), "{e}");
}

#[test]
fn overlong_name_dropped() {
    let long = "a".repeat(48); // erp_ + 48 = 52 chars
    let tail = format!(
        r#"
[[services.erp.operation]]
id = "{long}"
capability = "invoices:read"
kind = "read"
method = "GET"
path = "/long"

[[services.erp.operation]]
id = "{}"
capability = "invoices:read"
kind = "read"
method = "GET"
path = "/fits"

[[services.erp.operation]]
id = "bad__op"
capability = "invoices:read"
kind = "read"
method = "GET"
path = "/bad"
"#,
        "b".repeat(47)
    );
    let w = world_with(
        |p| policy(p, "\"erp\"", "", "\"invoices:read\"", &tail),
        &["erp"],
    );
    let mut c = w.mcp(&[]);
    let names = c.tool_names();
    let fits = format!("erp_{}", "b".repeat(47));
    assert_eq!(fits.len(), 51);
    assert!(names.contains(&fits), "{names:?}");
    assert!(!names.iter().any(|n| n.contains("aaaa")), "{names:?}");
    assert!(!names.iter().any(|n| n.contains("bad")), "{names:?}");
    for name in [format!("erp_{long}"), "erp_bad__op".to_string()] {
        let a = c.request("tools/call", json!({"name": name, "arguments": {}}));
        assert_eq!(rpc_code(&a), -32602, "{a}");
    }
    assert!(w.m.hits().is_empty());
}

#[test]
fn daemon_down_list_is_32603_call_is_error() {
    let mut w = world();
    let mut c = w.mcp(&[]);
    // Listed while the daemon is up.
    assert!(c.tool_names().iter().any(|n| n == "erp_invoices_list"));
    w.d.signal("TERM");
    assert!(w.d.wait_exit(Duration::from_secs(10)).is_some());
    let a = c.request("tools/list", json!({}));
    assert_eq!(rpc_code(&a), -32603, "{a}");
    let m = a["error"]["message"].as_str().unwrap();
    assert!(m.starts_with("saiife unavailable: "), "{m}");
    // A listed tool: an error result.
    let r = c.call("erp_invoices_list", json!({}));
    assert_eq!(r["isError"], true, "{r}");
    assert!(texts(&r).starts_with("saiife unavailable: "), "{r}");
    // Never listed (a fresh server): an error result too, not -32602.
    let mut c2 = w.mcp(&[]);
    let r = c2.call("erp_invoices_list", json!({}));
    assert_eq!(r["isError"], true, "{r}");
    assert!(texts(&r).starts_with("saiife unavailable: "), "{r}");
    let r = c2.call("saiife_result", json!({"request": 1}));
    assert_eq!(r["isError"], true, "{r}");
}

#[test]
fn requests_before_initialize_refused() {
    let w = world();
    let mut c = McpClient::spawn(&w.d, &[]);
    let a = c.request("tools/list", json!({}));
    assert_eq!(rpc_code(&a), -32600, "{a}");
    let a = c.request(
        "tools/call",
        json!({"name": "erp_invoices_list", "arguments": {}}),
    );
    assert_eq!(rpc_code(&a), -32600, "{a}");
    // ping is always answered.
    assert_eq!(c.result("ping", json!({})), json!({}));
    // Not a message: answered, and the server goes on.
    c.send_line("{not json");
    c.send_line(r#"[{"jsonrpc":"2.0","id":99,"method":"ping"}]"#);
    let a = c.request("initialize", json!({}));
    assert_eq!(rpc_code(&a), -32602, "{a}");
    c.initialize();
    assert!(c.tool_names().iter().any(|n| n == "erp_invoices_list"));
    assert!(w.m.hits().is_empty());
    assert!(w.connector().is_empty());
}

#[test]
fn eof_waits_for_inflight_then_exits_0() {
    let w = world();
    let mut c = w.mcp(&[]);
    let id = c.send_request(
        "tools/call",
        json!({"name": "erp_invoices_block", "arguments": {}}),
    );
    assert!(
        wait_for(Duration::from_secs(20), || !w.m.hits().is_empty()),
        "the call did not reach the upstream"
    );
    c.close_stdin();
    std::thread::sleep(Duration::from_millis(500));
    assert!(c.try_wait().is_none(), "exited with a call in flight");
    w.m.release();
    let a = c
        .answer_within(&id, Duration::from_secs(30))
        .expect("the in-flight call was answered");
    assert_eq!(a["result"]["isError"], false, "{a}");
    assert!(texts(&a["result"]).contains("blocked"), "{a}");
    let st = c.wait_exit(Duration::from_secs(20)).expect("exited");
    assert_eq!(st.code(), Some(0));
    assert_eq!(w.connector().pop().unwrap()["via"], "mcp");
}

#[test]
fn list_changed_after_reload() {
    let w = world();
    let mut c = McpClient::spawn_env(&w.d, &[], &[("SAIIFE_TEST_MCP_HASH_MS", "200")]);
    c.initialize();
    let names = c.tool_names();
    assert!(!names.iter().any(|n| n == "erp_reports_get"));
    // No change, no notification.
    assert!(c.next_notification(Duration::from_millis(800)).is_none());
    w.d.write_config(&Opts {
        extra: policy(
            w.m.port,
            "\"erp\"",
            "",
            "\"invoices:read\", \"invoices:delete\", \"reports:read\"",
            "",
        ),
        ..Opts::default()
    });
    w.d.signal("HUP");
    let n = c
        .next_notification(Duration::from_secs(20))
        .unwrap_or_else(|| panic!("no list_changed: {}", c.stderr_text()));
    assert_eq!(n["method"], "notifications/tools/list_changed");
    assert!(c.tool_names().iter().any(|n| n == "erp_reports_get"));
    // Once per change.
    assert!(c.next_notification(Duration::from_millis(800)).is_none());
}

// ------------------------------------------------- approval (in-process)

mod inproc {
    use super::*;
    use saiife_audit::{ChainWriter, WriterOptions};
    use saiife_daemon::approvals::{dir_in, State};
    use saiife_daemon::ops::{dispatch_conn, Conn, Ctx, CtxInit, Mode, PolicyState};
    use saiife_daemon::sessions::RealProc;
    use saiife_daemon::vault::{self, Entry, Kind, VaultState};
    use saiife_daemon::writer::{self, WriterConfig};
    use saiife_ipc::msg::Request;
    use saiife_ipc::peer::PeerCred;
    use saiife_policy::{FixedDirectory, Fsync};
    use std::path::Path;
    use zeroize::Zeroizing;

    pub const BOSS: u32 = 4242;

    pub struct Inproc {
        pub rt: tokio::runtime::Runtime,
        pub ctx: Arc<Ctx>,
        pub m: Mock,
        pub tmp: tempfile::TempDir,
    }

    fn config_text(tmp: &Path, port: u16) -> String {
        format!(
            "version = 2\nlocked = true\n\n[daemon]\nuser = {user:?}\nsocket_dir = {run:?}\n\n[audit]\ndir = {audit:?}\n\n[approval]\napprovers = [\"boss\"]\n\n{}",
            policy(port, "\"erp\"", "", "\"invoices:read\"", ""),
            user = own_user(),
            run = tmp.join("run").display().to_string(),
            audit = tmp.join("audit").display().to_string(),
        )
    }

    pub fn world() -> Inproc {
        let m = mock();
        let tmp = common::tmp::short_tempdir();
        let t = tmp.path();
        for d in [
            "etc/ca", "audit", "state", "run", "proc", "home", "data", "project",
        ] {
            fs::create_dir_all(t.join(d)).unwrap();
        }
        fs::write(t.join("etc/ca/test-ca.pem"), &m.ca_pem).unwrap();
        let config = t.join("etc/config.toml");
        fs::write(&config, config_text(t, m.port)).unwrap();
        let l = saiife_policy::load_system(&config).unwrap();
        let cat = saiife_broker::Catalog::new(saiife_broker::builtin(), vec![]);
        saiife_broker::catalog::validate(&l.config, &cat).unwrap();
        let policy = PolicyState::from_loaded_in(&l, &[], cat, Mode::Locked);
        let writer_cfg = || WriterConfig {
            checkpoint_every: 1000,
            checkpoint_interval: Duration::from_secs(900),
            fsync: Fsync::Always,
        };
        let cw = ChainWriter::open(
            &t.join("audit"),
            WriterOptions {
                mode: "locked".into(),
                saiife: "test".into(),
                key: None,
            },
        )
        .unwrap();
        let (handle, _join) = writer::spawn(cw, writer_cfg(), None).unwrap();
        let key_file = t.join("vault-key");
        fs::write(&key_file, [7u8; 32]).unwrap();
        let vault_path = t.join("state/vault/vault.bin");
        let mut vault = vault::open(&key_file, &vault_path);
        let VaultState::Ready(v) = &mut vault else {
            panic!("vault not ready");
        };
        v.put(Entry {
            name: SECRET_NAME.into(),
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
        let passwd = format!("{me}:x:{uid}:{gid}::/:/bin/sh\nboss:x:{BOSS}:{BOSS}::/:/bin/sh\n");
        let group = format!("{}:x:{gid}:\nboss:x:{BOSS}:\n", own_group());
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
            let directory = Arc::new(FixedDirectory::from_text(&passwd, &group));
            let state = t.join("state");
            Arc::new(Ctx::new(CtxInit {
                own_uid: uid,
                own_user: me,
                audit_dir: t.join("audit"),
                socket_dir: t.join("run"),
                config_path: config.clone(),
                policy,
                proc: Box::new(RealProc::new(t.join("proc"))),
                vault,
                vault_path,
                upstream,
                backup_dir: t.join("state/import-backup"),
                tokens: Arc::new(saiife_daemon::tokens::Tokens::memory_with_clock(Arc::new(
                    || 1_800_000_000,
                ))),
                approvals: saiife_daemon::approvals::Store::open(&dir_in(&state))
                    .map_err(|e| e.to_string()),
                lockdown: saiife_daemon::lockdown::Store::memory(),
                mode: Mode::Locked,
                ..CtxInit::minimal(handle, writer_cfg(), directory, &state)
            }))
        });
        let control = rt
            .block_on(async { tokio::net::UnixListener::bind(t.join("run/saiife.sock")).unwrap() });
        {
            let ctx = Arc::clone(&ctx);
            rt.spawn(async move {
                while let Ok((s, _)) = control.accept().await {
                    tokio::spawn(saiife_daemon::server::connection(s, Arc::clone(&ctx)));
                }
            });
        }
        Inproc { rt, ctx, m, tmp }
    }

    impl Inproc {
        pub fn mcp(&self) -> McpClient {
            let t = self.tmp.path();
            let mut c = McpClient::spawn_at(
                &Where {
                    root: t,
                    config: &t.join("etc/config.toml"),
                    audit: &t.join("audit"),
                    cwd: &t.join("project"),
                },
                &[],
                &[],
            );
            c.initialize();
            c
        }

        /// `approval.decide` as `uid` at the ops level (pid: this process).
        pub fn decide(&self, uid: u32, id: u64, action: &str) -> Value {
            let conn = Conn::new(
                PeerCred {
                    uid,
                    gid: uid,
                    pid: std::process::id(),
                },
                None,
            );
            let Value::Object(args) = json!({"request": id, "action": action}) else {
                unreachable!()
            };
            let req = Request {
                id: 7,
                op: "approval.decide".into(),
                args,
            };
            self.rt.block_on(dispatch_conn(&self.ctx, &conn, req))
        }

        pub fn state(&self, id: u64) -> Option<State> {
            self.ctx
                .approvals
                .as_ref()
                .unwrap()
                .get(id)
                .map(|r| r.state)
        }

        pub fn records(&self) -> Vec<Value> {
            let mut files: Vec<PathBuf> = fs::read_dir(self.tmp.path().join("audit"))
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
    }
}

#[test]
fn saiife_result_after_approve() {
    use saiife_daemon::approvals::State;
    let w = inproc::world();
    let mut c = w.mcp();
    let r = c.call("erp_invoices_create", json!({"body": {"amount": 5}}));
    assert_eq!(r["isError"], false, "{r}");
    let id = r["structuredContent"]["pending"].as_u64().unwrap();
    assert!(w.m.hits().is_empty());
    let d = w.decide(inproc::BOSS, id, "approve");
    assert_eq!(d["ok"], true, "{d}");
    assert!(
        wait_for(Duration::from_secs(10), || w.state(id) == Some(State::Sent)),
        "request #{id} is {:?}",
        w.state(id)
    );
    let r = c.call("saiife_result", json!({"request": id}));
    assert_eq!(r["isError"], false, "{r}");
    let body: Value = serde_json::from_str(&texts(&r)).unwrap();
    assert_eq!(body["created"], true, "{body}");
    assert_eq!(body["got"], r#"{"amount":5}"#);
    assert_eq!(w.m.hits(), vec!["POST /api/invoices"]);
    let recs: Vec<Value> = w
        .records()
        .into_iter()
        .filter(|r| r["kind"] == "connector")
        .collect();
    assert_eq!(recs[0]["via"], "mcp", "{recs:?}");
    assert_eq!(recs[0]["decision"], "ask");
    assert_eq!(recs.last().unwrap()["via"], "approval", "{recs:?}");
}
