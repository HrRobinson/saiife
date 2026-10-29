//! The gateway pipeline against a fake [`ToolCaller`]: a real daemon
//! context (chain writer, vault, approval store) with the tool caller
//! replaced, calls made as a client makes them (`mcp.call`, `mcp.list`,
//! `api.result` through `ops::dispatch`).

use super::*;
use crate::approvals::{Filter, State, Store};
use crate::mcp_gateway::{CallFuture, ChildError};
use crate::ops::{CtxInit, PolicyState};
use crate::writer::WriterConfig;
use saiife_ipc::msg::Request as IpcRequest;
use saiife_mcp::types::Tool;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;
use zeroize::Zeroizing;

/// The fake server's secret, built at run time.
fn token() -> String {
    concat!("lin", "_tok_", "Zx9Qw7Er5Ty3Ui1Op").to_string()
}

/// One `call`: server, tool, arguments, timeout, cap.
type Sent = (String, String, Value, Duration, usize);

type Answer = Box<dyn Fn(&str, &Value) -> Result<Value, ChildError> + Send + Sync>;

/// A stand-in for the gateway: a fixed tool list for `linear`, every call
/// kept, answers from `answer` (raw: nothing masked, unlike the real
/// supervisor, so the pipeline's own masking is what the tests see).
struct Fake {
    tools: Mutex<Option<Vec<Tool>>>,
    calls: Mutex<Vec<Sent>>,
    answer: Mutex<Answer>,
    /// The server's secret values (the token by default).
    secrets: Mutex<Vec<String>>,
}

impl Fake {
    fn new(names: &[&str]) -> Fake {
        Fake {
            tools: Mutex::new(Some(names.iter().map(|n| tool(n)).collect())),
            calls: Mutex::new(Vec::new()),
            answer: Mutex::new(Box::new(|tool, args| {
                Ok(
                    json!({"content": [{"type": "text", "text": format!("{tool} {args}")}],
                          "isError": false}),
                )
            })),
            secrets: Mutex::new(vec![token()]),
        }
    }

    fn answer(
        &self,
        f: impl Fn(&str, &Value) -> Result<Value, ChildError> + Send + Sync + 'static,
    ) {
        *self.answer.lock().unwrap() = Box::new(f);
    }

    fn calls(&self) -> Vec<Sent> {
        self.calls.lock().unwrap().clone()
    }
}

fn tool(name: &str) -> Tool {
    Tool {
        name: name.to_string(),
        title: None,
        description: Some(format!("The {name} tool.")),
        input_schema: json!({"type": "object"}),
        output_schema: None,
        annotations: None,
    }
}

impl ToolCaller for Fake {
    fn tools(&self, server: &str) -> Option<Arc<Vec<Tool>>> {
        if server != "linear" {
            return None;
        }
        self.tools.lock().unwrap().clone().map(Arc::new)
    }

    fn call<'a>(
        &'a self,
        server: &'a str,
        tool: &'a str,
        args: Value,
        timeout: Duration,
        cap: usize,
    ) -> CallFuture<'a> {
        self.calls.lock().unwrap().push((
            server.to_string(),
            tool.to_string(),
            args.clone(),
            timeout,
            cap,
        ));
        let r = (self.answer.lock().unwrap())(tool, &args);
        Box::pin(async move { r })
    }

    fn secret_values(&self, server: &str) -> Vec<Zeroizing<String>> {
        if server == "linear" {
            self.secrets
                .lock()
                .unwrap()
                .iter()
                .map(|v| Zeroizing::new(v.clone()))
                .collect()
        } else {
            Vec::new()
        }
    }
}

const TOOLS: &[&str] = &[
    "list_issues",
    "get_issue",
    "create_issue",
    "delete_issue",
    "DELETE_ISSUE",
    "echo",
    "secret_tool",
];

struct W {
    ctx: Arc<Ctx>,
    fake: Arc<Fake>,
    t: tempfile::TempDir,
    _join: std::thread::JoinHandle<()>,
}

/// The policy: `ann` (this process's uid) in scope `dev` with `services`,
/// and `[mcp.linear]` with `extra` appended to its table.
fn policy_text(t: &Path, services: &str, extra: &str, tail: &str) -> String {
    format!(
        r#"version = 2
locked = true

[daemon]
user = "ann"
socket_dir = {run:?}

[audit]
dir = {audit:?}
min_free_mb = 0

[[scope]]
name = "dev"
users = ["ann"]
services = {services}
{tail}

[mcp.linear]
command = "/usr/bin/true"
allow = ["list_*", "get_issue", "echo", "create_*"]
ask = ["create_*"]
deny = ["delete_*"]
read_tools = ["list_*", "get_*"]
env = {{ LINEAR_TOKEN = "linear-tok" }}
{extra}
"#,
        run = t.join("run").display().to_string(),
        audit = t.join("audit").display().to_string(),
    )
}

fn load(t: &Path, text: &str) -> PolicyState {
    let config = t.join("etc").join("config.toml");
    std::fs::write(&config, text).unwrap();
    let l = saiife_policy::load_system(&config).unwrap();
    let p = PolicyState::from_loaded(&l, &[], saiife_broker::Catalog::default());
    assert!(p.ok);
    p
}

fn world(services: &str, extra: &str) -> W {
    world_with(services, extra, "")
}

fn world_with(services: &str, extra: &str, tail: &str) -> W {
    let t = tempfile::tempdir().unwrap();
    for d in ["etc", "audit", "state", "run"] {
        std::fs::create_dir_all(t.path().join(d)).unwrap();
    }
    let policy = load(t.path(), &policy_text(t.path(), services, extra, tail));
    let cw = saiife_audit::ChainWriter::open(
        &t.path().join("audit"),
        saiife_audit::WriterOptions {
            mode: "locked".into(),
            saiife: VERSION.into(),
            key: None,
        },
    )
    .unwrap();
    let cfg = WriterConfig {
        checkpoint_every: 1000,
        checkpoint_interval: Duration::from_secs(900),
        fsync: saiife_policy::Fsync::Always,
    };
    let (handle, join) = crate::writer::spawn(cw, cfg, None).unwrap();
    let key = t.path().join("vault-key");
    std::fs::write(&key, [7u8; 32]).unwrap();
    let vault = crate::vault::open(&key, &t.path().join("state/vault/vault.bin"));
    let state = t.path().join("state");
    let dirs: Arc<dyn saiife_policy::Directory + Send + Sync> =
        Arc::new(saiife_policy::FixedDirectory::from_text("", ""));
    let mut ctx = Ctx::new(CtxInit {
        own_uid: me().uid,
        own_user: "ann".into(),
        audit_dir: t.path().join("audit"),
        policy,
        vault,
        approvals: Ok(Store::open(&crate::approvals::dir_in(&state)).unwrap()),
        lockdown: crate::lockdown::Store::memory(),
        grants: crate::grants::Grants::memory(),
        ..CtxInit::minimal(handle, cfg, dirs, &state)
    });
    let fake = Arc::new(Fake::new(TOOLS));
    ctx.tool_caller = fake.clone();
    W {
        ctx: Arc::new(ctx),
        fake,
        t,
        _join: join,
    }
}

fn me() -> PeerCred {
    PeerCred {
        uid: rustix::process::getuid().as_raw(),
        gid: rustix::process::getgid().as_raw(),
        pid: std::process::id(),
    }
}

impl W {
    async fn op(&self, op: &str, args: Value) -> Value {
        let req = IpcRequest {
            id: 5,
            op: op.into(),
            args: args.as_object().unwrap().clone(),
        };
        crate::ops::dispatch(&self.ctx, &me(), req).await
    }

    async fn call(&self, tool: &str, args: &str) -> Value {
        self.op(
            "mcp.call",
            json!({"server": "linear", "tool": tool, "arguments": args, "project": "/p"}),
        )
        .await
    }

    async fn call_with(&self, tool: &str, args: &str, overlay: Value) -> Value {
        self.op(
            "mcp.call",
            json!({"server": "linear", "tool": tool, "arguments": args, "overlay": overlay}),
        )
        .await
    }

    fn audit_text(&self) -> String {
        let mut s = String::new();
        let mut files: Vec<_> = std::fs::read_dir(self.t.path().join("audit"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
            .collect();
        files.sort();
        for f in files {
            s.push_str(&std::fs::read_to_string(f).unwrap());
        }
        s
    }

    fn records(&self) -> Vec<Value> {
        self.audit_text()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    fn connector(&self) -> Vec<Value> {
        self.records()
            .into_iter()
            .filter(|r| r["kind"] == "connector")
            .collect()
    }

    fn approvals(&self) -> Vec<crate::approvals::Request> {
        self.ctx.approvals.as_ref().unwrap().list(Filter::default())
    }

    fn set_policy(&self, services: &str, extra: &str) {
        self.set_policy_with(services, extra, "");
    }

    fn set_policy_with(&self, services: &str, extra: &str, tail: &str) {
        let p = load(
            self.t.path(),
            &policy_text(self.t.path(), services, extra, tail),
        );
        *self.ctx.policy.lock().unwrap() = p;
    }

    /// Approve request `id` as the store does, then send it as
    /// `approval.decide` does.
    async fn approve(&self, id: u64) {
        let s = self.ctx.approvals.as_ref().unwrap();
        let r = s
            .transition(
                id,
                &[State::Pending],
                State::Approved,
                Some(me().uid),
                None,
                std::time::SystemTime::now(),
            )
            .unwrap();
        crate::approval_ops::send(Arc::clone(&self.ctx), r, me().uid).await;
    }

    async fn result(&self, id: u64) -> Value {
        self.op("api.result", json!({ "request": id })).await
    }
}

fn denied_rule(a: &Value) -> &str {
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["error"], "denied", "{a}");
    a["rule"].as_str().unwrap()
}

fn text(a: &Value) -> String {
    a["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

// ------------------------------------------------------------------ tests

#[tokio::test]
async fn no_scope_denied() {
    let w = world("[]", "");
    let a = w.call("list_issues", "{}").await;
    assert_eq!(denied_rule(&a), "no_scope");
    assert!(w.fake.calls().is_empty());
    let recs = w.connector();
    assert_eq!(recs.len(), 1, "{recs:#?}");
    assert_eq!(recs[0]["rule"], "no_scope");
    assert_eq!(recs[0]["service"], "mcp:linear");
    // A scope listing another server does not cover this one.
    let w = world("[\"mcp:jira\"]", "");
    let a = w.call("list_issues", "{}").await;
    assert_eq!(denied_rule(&a), "no_scope");
    // Nothing listed either.
    let l = w.op("mcp.list", json!({})).await;
    assert_eq!(l["servers"], json!([]), "{l}");
}

#[tokio::test]
async fn lockdown_denied() {
    let w = world("[\"mcp:linear\"]", "");
    w.ctx
        .lockdown
        .set(Some(saiife_broker::pipeline::Lockdown {
            scope: saiife_broker::pipeline::LockScope::Connectors,
            reason: "incident".into(),
            by_uid: 0,
            since: "2026-10-29T00:00:00Z".into(),
        }))
        .unwrap();
    let a = w.call("list_issues", "{}").await;
    assert_eq!(denied_rule(&a), "lockdown");
    assert!(w.fake.calls().is_empty());
    assert_eq!(w.connector()[0]["rule"], "lockdown");
}

#[tokio::test]
async fn unknown_tool_denied_and_recorded() {
    let w = world("[\"mcp:linear\"]", "");
    let a = w.call("drop_everything", "{\"x\":1}").await;
    assert_eq!(denied_rule(&a), "unknown_operation");
    // Byte for byte: a differently-cased listed name is not that tool.
    let a = w.call("LIST_ISSUES", "{}").await;
    assert_eq!(denied_rule(&a), "unknown_operation");
    assert!(w.fake.calls().is_empty());
    let recs = w.connector();
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0]["operation"], "drop_everything");
    assert_eq!(recs[0]["rule"], "unknown_operation");
    assert_eq!(recs[0]["tool"], "mcp");
    assert_eq!(recs[0]["params"]["x"], "1");
    // A tool named after the secret is recorded masked.
    let a = w.call(&token(), "{}").await;
    assert_eq!(denied_rule(&a), "unknown_operation");
    assert!(!w.audit_text().contains(&token()));
    // A server that is not running: nothing can be sent.
    *w.fake.tools.lock().unwrap() = None;
    let a = w.call("list_issues", "{}").await;
    assert_eq!(denied_rule(&a), "upstream_unavailable");
}

#[tokio::test]
async fn duplicate_key_args_refused() {
    let w = world("[\"mcp:linear\"]", "");
    for args in [
        r#"{"a":1,"a":2}"#,
        r#"{"x":{"b":1,"b":1}}"#,
        r#"{"x":[{"k":"v","k":"w"}]}"#,
    ] {
        let a = w.call("list_issues", args).await;
        assert_eq!(denied_rule(&a), "bad_param", "{args}");
    }
    // Not an object, or not JSON.
    for args in ["[1]", "\"s\"", "{", "{} {}"] {
        let a = w.call("list_issues", args).await;
        assert_eq!(denied_rule(&a), "bad_param", "{args}");
    }
    assert!(w.fake.calls().is_empty());
    // An object instead of its text is a bad request: the frame's parser
    // would have kept one of two equal keys unseen.
    let a = w
        .op(
            "mcp.call",
            json!({"server": "linear", "tool": "list_issues", "arguments": {"a": 1}}),
        )
        .await;
    assert_eq!(a["error"], "bad_request", "{a}");
    // Recorded with no params: the policy saw none.
    let recs = w.connector();
    assert_eq!(recs.len(), 7);
    assert_eq!(recs[0]["params"], json!({}));
}

#[tokio::test]
async fn args_over_256k_refused() {
    let w = world("[\"mcp:linear\"]", "");
    let pad = "x".repeat(MAX_ARGUMENTS);
    let big = format!("{{\"q\":\"{pad}\"}}");
    assert!(big.len() > MAX_ARGUMENTS);
    let a = w.call("list_issues", &big).await;
    assert_eq!(denied_rule(&a), "bad_param");
    assert!(w.fake.calls().is_empty());
    // Just under: allowed and sent.
    let ok_args = format!("{{\"q\":\"{}\"}}", "x".repeat(MAX_ARGUMENTS - 10));
    assert!(ok_args.len() <= MAX_ARGUMENTS);
    let a = w.call("list_issues", &ok_args).await;
    assert_eq!(a["ok"], true, "{}", a["error"]);
    assert_eq!(w.fake.calls().len(), 1);
    // The record's params are cut at 1 KiB.
    let recs = w.connector();
    assert!(recs[1]["params"]["q"].as_str().unwrap().len() < 1100);
}

#[tokio::test]
async fn deny_ask_allow_order() {
    let w = world("[\"mcp:linear\"]", "");
    // deny > ask > allow; deny folds ASCII case.
    assert_eq!(
        denied_rule(&w.call("delete_issue", "{}").await),
        "deny:delete_*"
    );
    assert_eq!(
        denied_rule(&w.call("DELETE_ISSUE", "{}").await),
        "deny:delete_*"
    );
    let a = w.call("create_issue", "{}").await;
    assert!(a["pending"].as_u64().is_some(), "{a}");
    let a = w.call("list_issues", "{}").await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a["status"], Value::Null);
    // Listed in no list: default deny.
    assert_eq!(
        denied_rule(&w.call("secret_tool", "{}").await),
        "default_deny"
    );
    let calls = w.fake.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1, "list_issues");
    // mcp.list shows allow and ask, never deny.
    let l = w.op("mcp.list", json!({})).await;
    let tools = l["servers"][0]["tools"].as_array().unwrap();
    let got: Vec<(String, String)> = tools
        .iter()
        .map(|t| {
            (
                t["name"].as_str().unwrap().to_string(),
                t["action"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            ("list_issues".into(), "allow".into()),
            ("get_issue".into(), "allow".into()),
            ("create_issue".into(), "ask".into()),
            ("echo".into(), "allow".into()),
        ]
    );
    assert_eq!(l["servers"][0]["name"], "linear");
    assert_eq!(tools[0]["inputSchema"], json!({"type": "object"}));
    assert_eq!(tools[0]["description"], "The list_issues tool.");
    assert!(l["tools_hash"].as_str().unwrap().starts_with("sha256:"));
}

#[tokio::test]
async fn project_overlay_can_only_tighten() {
    let w = world("[\"mcp:linear\"]", "");
    let o =
        json!({"allow": ["delete_issue", "secret_tool"], "ask": ["get_issue"], "deny": ["list_*"]});
    // The overlay's deny and ask apply...
    assert_eq!(
        denied_rule(&w.call_with("list_issues", "{}", o.clone()).await),
        "deny:list_*"
    );
    let a = w.call_with("get_issue", "{}", o.clone()).await;
    assert!(a["pending"].as_u64().is_some(), "{a}");
    // ...its allow never does in locked mode.
    assert_eq!(
        denied_rule(&w.call_with("delete_issue", "{}", o.clone()).await),
        "deny:delete_*"
    );
    assert_eq!(
        denied_rule(&w.call_with("secret_tool", "{}", o.clone()).await),
        "default_deny"
    );
    assert!(w.fake.calls().is_empty());
    // mcp.list with the same overlay hides what it denies and never adds.
    let l = w
        .op("mcp.list", json!({"overlays": {"mcp:linear": o}}))
        .await;
    let names: Vec<&str> = l["servers"][0]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["get_issue", "create_issue", "echo"]);
    // Keys are mcp:<server>.
    let l = w.op("mcp.list", json!({"overlays": {"linear": {}}})).await;
    assert_eq!(l["error"], "bad_request", "{l}");
}

#[tokio::test]
async fn rate_limit_and_writes_per_hour() {
    let w = world(
        "[\"mcp:linear\"]",
        "[mcp.linear.limits]\nrequests_per_minute = 3\n",
    );
    for _ in 0..3 {
        assert_eq!(w.call("list_issues", "{}").await["ok"], true);
    }
    let a = w.call("list_issues", "{}").await;
    assert_eq!(a["error"], "limited", "{a}");
    assert_eq!(a["limit"], "requests_per_minute");
    assert_eq!(w.fake.calls().len(), 3);
    let recs = w.connector();
    assert_eq!(recs[3]["limit"], "requests_per_minute");

    let w = world(
        "[\"mcp:linear\"]",
        "[mcp.linear.limits]\nwrites_per_hour = 1\n",
    );
    assert_eq!(w.call("echo", "{}").await["ok"], true);
    let a = w.call("echo", "{}").await;
    assert_eq!(a["limit"], "writes_per_hour", "{a}");
    // An ask that could never be sent is limited at once.
    let a = w.call("create_issue", "{}").await;
    assert_eq!(a["limit"], "writes_per_hour", "{a}");
    assert!(w.approvals().is_empty());
}

#[tokio::test]
async fn read_tools_counted_as_read() {
    let w = world(
        "[\"mcp:linear\"]",
        "[mcp.linear.limits]\nwrites_per_hour = 1\n",
    );
    for _ in 0..3 {
        assert_eq!(w.call("list_issues", "{}").await["ok"], true);
        assert_eq!(w.call("get_issue", "{}").await["ok"], true);
    }
    assert_eq!(w.call("echo", "{}").await["ok"], true);
    let recs = w.connector();
    assert_eq!(recs[0]["op_kind"], "read");
    assert_eq!(recs[1]["op_kind"], "read");
    assert_eq!(recs[6]["op_kind"], "write");
    // The limiter key is the server's service.
    let a = w.call("echo", "{}").await;
    assert_eq!(a["limit"], "writes_per_hour", "{a}");
}

#[tokio::test]
async fn ask_creates_mcp_approval_nothing_sent() {
    let w = world("[\"mcp:linear\"]", "");
    let a = w
        .call("create_issue", r#"{"title":"Bug","team":"ENG","n":2}"#)
        .await;
    let id = a["pending"].as_u64().unwrap_or_else(|| panic!("{a}"));
    assert!(w.fake.calls().is_empty());
    let reqs = w.approvals();
    assert_eq!(reqs.len(), 1);
    let r = &reqs[0];
    assert_eq!(r.id, id);
    assert_eq!(r.kind, crate::approvals::ApprovalType::Mcp);
    assert_eq!(r.service.as_deref(), Some("mcp:linear"));
    assert_eq!(r.operation.as_deref(), Some("create_issue"));
    // The display is the canonical arguments; the hash is of those bytes.
    let canonical = r#"{"n":2,"team":"ENG","title":"Bug"}"#;
    assert_eq!(r.body_display.as_deref(), Some(canonical));
    assert_eq!(
        r.body_sha256.as_deref(),
        Some(hex(&Sha256::digest(canonical.as_bytes())).as_str())
    );
    assert!(!r.body_truncated);
    assert_eq!(crate::approvals::summary(r), "mcp:linear create_issue");
    // The ask record names the request; the approval record is type mcp.
    let recs = w.records();
    let ask: Vec<&Value> = recs.iter().filter(|r| r["kind"] == "connector").collect();
    assert_eq!(ask.len(), 1);
    assert_eq!(ask[0]["decision"], "ask");
    assert_eq!(ask[0]["approval"], id);
    let created: Vec<&Value> = recs
        .iter()
        .filter(|r| r["kind"] == "approval" && r["action"] == "created")
        .collect();
    assert_eq!(created.len(), 1);
    assert_eq!(created[0]["type"], "mcp");
    // Arguments holding the secret cannot be shown faithfully.
    let a = w
        .call("create_issue", &format!("{{\"k\":\"{}\"}}", token()))
        .await;
    assert_eq!(denied_rule(&a), "masked_content");
    // Over 4 KiB: shown cut, and the approval must acknowledge it.
    let a = w
        .call(
            "create_issue",
            &format!("{{\"k\":\"{}\"}}", "y".repeat(5000)),
        )
        .await;
    let big = a["pending"].as_u64().unwrap();
    let r = w.approvals().into_iter().find(|r| r.id == big).unwrap();
    assert!(r.body_truncated);
    assert!(r.body_display.unwrap().len() < 4200);
    assert!(w.fake.calls().is_empty());
}

#[tokio::test]
async fn identical_pending_call_returns_same_id() {
    let w = world("[\"mcp:linear\"]", "");
    let args = r#"{"title":"Bug"}"#;
    let a = w.call("create_issue", args).await["pending"]
        .as_u64()
        .unwrap();
    let b = w.call("create_issue", args).await["pending"]
        .as_u64()
        .unwrap();
    // Key order does not make another request (canonical arguments).
    let c = w.call("create_issue", r#"{ "title" : "Bug" }"#).await["pending"]
        .as_u64()
        .unwrap();
    assert_eq!((a, b, c), (a, a, a));
    let d = w.call("create_issue", r#"{"title":"Other"}"#).await["pending"]
        .as_u64()
        .unwrap();
    assert_ne!(a, d);
    assert_eq!(w.approvals().len(), 2);
    let recs = w.records();
    let asks: Vec<&Value> = recs
        .iter()
        .filter(|r| r["kind"] == "connector" && r["approval"] == a)
        .collect();
    assert_eq!(asks.len(), 3);
    let created = recs
        .iter()
        .filter(|r| r["kind"] == "approval" && r["action"] == "created")
        .count();
    assert_eq!(created, 2);
    assert!(w.fake.calls().is_empty());
}

#[tokio::test]
async fn approved_call_resent_under_current_policy() {
    let w = world("[\"mcp:linear\"]", "");
    let a = w.call("create_issue", r#"{"title":"Bug"}"#).await;
    let id = a["pending"].as_u64().unwrap();
    // A reload since the ask (here the response cap): the send runs under
    // the policy in force now.
    w.set_policy(
        "[\"mcp:linear\"]",
        "[mcp.linear.limits]\nmax_response_bytes = 4096\n",
    );
    let hash_now = w.ctx.policy().hash.unwrap();
    w.approve(id).await;
    let calls = w.fake.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1, "create_issue");
    assert_eq!(calls[0].2, json!({"title": "Bug"}));
    assert_eq!(calls[0].4, 4096 + READ_SLACK);
    let r = w.approvals().into_iter().find(|r| r.id == id).unwrap();
    assert_eq!(r.state, State::Sent);
    let recs = w.connector();
    let sent = recs.iter().find(|r| r["via"] == "approval").unwrap();
    assert_eq!(sent["approval"], id);
    assert_eq!(sent["asked_via"], "mcp");
    assert_eq!(sent["tool"], "mcp");
    assert_eq!(sent["decision"], "allow");
    assert_eq!(sent["policy"], hash_now);
    // A request whose scope environment changed since the ask is not sent.
    let a = w.call("create_issue", r#"{"title":"Env"}"#).await;
    let id = a["pending"].as_u64().unwrap();
    w.set_policy_with(
        "[\"mcp:linear\"]\nenv = \"staging\"",
        "",
        "\n[environments.staging]\n",
    );
    w.approve(id).await;
    let r = w.result(id).await;
    assert_eq!(r["state"], "send_failed", "{r}");
    assert_eq!(r["result"]["rule"], "env_changed", "{r}");
    assert_eq!(w.fake.calls().len(), 1);
}

#[tokio::test]
async fn policy_changed_after_approval_denied() {
    let w = world("[\"mcp:linear\"]", "");
    let id = w.call("create_issue", "{}").await["pending"]
        .as_u64()
        .unwrap();
    let id2 = w.call("create_issue", r#"{"a":1}"#).await["pending"]
        .as_u64()
        .unwrap();
    // Now denied.
    let text = policy_text(w.t.path(), "[\"mcp:linear\"]", "", "").replace(
        "deny = [\"delete_*\"]",
        "deny = [\"delete_*\", \"create_*\"]",
    );
    *w.ctx.policy.lock().unwrap() = load(w.t.path(), &text);
    w.approve(id).await;
    let r = w.result(id).await;
    assert_eq!(r["state"], "send_failed", "{r}");
    assert_eq!(r["result"]["rule"], "policy_changed", "{r}");
    // Out of scope now.
    w.set_policy("[]", "");
    w.approve(id2).await;
    let r = w.result(id2).await;
    assert_eq!(r["result"]["rule"], "policy_changed", "{r}");
    assert!(w.fake.calls().is_empty());
    let recs = w.connector();
    let sends: Vec<&Value> = recs.iter().filter(|r| r["via"] == "approval").collect();
    assert_eq!(sends.len(), 2);
    assert!(sends.iter().all(|r| r["rule"] == "policy_changed"));
}

#[tokio::test]
async fn server_echoing_its_token_is_masked_everywhere() {
    use base64::Engine as _;
    let w = world("[\"mcp:linear\"]", "");
    let tok = token();
    let b64 = base64::engine::general_purpose::STANDARD.encode(&tok);
    let hexed: String = tok.bytes().map(|b| format!("{b:02x}")).collect();
    let t2 = tok.clone();
    w.fake.answer(move |_, _| {
        Ok(json!({
            "content": [
                {"type": "text", "text": format!("your token is {t2}")},
                {"type": "text", "text": format!("b64 {} hex {}", base64::engine::general_purpose::STANDARD.encode(&t2), t2.bytes().map(|b| format!("{b:02x}")).collect::<String>())},
                {"type": "resource", "resource": {"uri": format!("x://{t2}"), "text": t2.clone()}},
                {"type": "image", "data": "aGk=", "mimeType": "image/png"},
            ],
            "structuredContent": {"token": t2.clone(), t2.clone(): [t2.clone()]},
            "isError": true,
        }))
    });
    let a = w
        .call(
            "list_issues",
            &format!("{{\"q\":\"{tok}\",\"n\":[\"{tok}\"]}}"),
        )
        .await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a["result"]["isError"], true);
    let shown = a.to_string();
    for form in [&tok, &b64, &hexed] {
        assert!(!shown.contains(form.as_str()), "{shown}");
    }
    assert!(shown.contains("[MASKED]"), "{shown}");
    assert!(!shown.contains("aGk="), "media replaced: {shown}");
    let audit = w.audit_text();
    for form in [&tok, &b64, &hexed] {
        assert!(
            !audit.contains(form.as_str()),
            "a secret form in the audit log"
        );
    }
    let rec = &w.connector()[0];
    assert_eq!(rec["params"]["q"], "[MASKED]");
    assert_eq!(rec["mcp_is_error"], true);
    // An error message from the server is masked too.
    let t3 = tok.clone();
    w.fake
        .answer(move |_, _| Err(ChildError::Protocol(format!("bad {t3}"))));
    let a = w.call("list_issues", "{}").await;
    assert_eq!(a["error"], "upstream_failed", "{a}");
    assert!(!a.to_string().contains(&tok), "{a}");
    assert!(!w.audit_text().contains(&tok));
}

#[tokio::test]
async fn response_cut_at_max_response_bytes() {
    let w = world(
        "[\"mcp:linear\"]",
        "[mcp.linear.limits]\nmax_response_bytes = 2000\n",
    );
    let tok = token();
    // A secret just before the cut, and one straddling it.
    let t2 = tok.clone();
    w.fake.answer(move |_, _| {
        let text = format!(
            "{}{t2}{}{t2}{}",
            "a".repeat(1500),
            "b".repeat(160),
            "b".repeat(50_000)
        );
        Ok(json!({"content": [{"type": "text", "text": text},
                              {"type": "text", "text": "second"}],
                  "structuredContent": {"big": "c".repeat(10_000)}}))
    });
    let a = w.call("list_issues", "{}").await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a["truncated"], true);
    let result = &a["result"];
    let n = serde_json::to_vec(result).unwrap().len();
    assert!(n <= 2000, "{n}");
    let first = result["content"][0]["text"].as_str().unwrap();
    assert!(first.starts_with("aaaa"), "{first}");
    assert!(first.contains("[MASKED]"), "{first}");
    // No prefix of the secret survives the cut.
    assert!(!a.to_string().contains(&tok[..8]), "{a}");
    assert!(result.get("structuredContent").is_none());
    let last = result["content"].as_array().unwrap().last().unwrap();
    assert!(last["text"]
        .as_str()
        .unwrap()
        .contains("cut at max_response_bytes"));
    let rec = &w.connector()[0];
    assert!(rec["resp_bytes"].as_u64().unwrap() <= 2000, "{rec}");
    // A small result is whole.
    w.fake
        .answer(|_, _| Ok(json!({"content": [{"type": "text", "text": "ok"}]})));
    let a = w.call("list_issues", "{}").await;
    assert_eq!(a["truncated"], false);
    assert_eq!(text(&a), "ok");
}

#[tokio::test]
async fn one_connector_record_per_call_with_via_mcp() {
    let w = world("[\"mcp:linear\"]", "");
    let a = w
        .call("list_issues", r#"{"team":"ENG","limit":5,"f":{"a":[1,2]}}"#)
        .await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(
        text(&a),
        r#"list_issues {"f":{"a":[1,2]},"limit":5,"team":"ENG"}"#
    );
    let recs = w.connector();
    assert_eq!(recs.len(), 1, "{recs:#?}");
    let r = &recs[0];
    assert_eq!(r["tool"], "mcp");
    assert_eq!(r["via"], "mcp");
    assert_eq!(r["service"], "mcp:linear");
    assert_eq!(r["operation"], "list_issues");
    assert_eq!(r["capability"], Value::Null);
    assert_eq!(r["op_kind"], "read");
    assert_eq!(r["status"], Value::Null);
    assert_eq!(r["mcp_is_error"], false);
    assert_eq!(r["decision"], "allow");
    assert_eq!(r["secret"], "linear-tok");
    assert_eq!(r["project"], "/p");
    assert_eq!(r["uid"], me().uid);
    assert_eq!(r["user"], "ann");
    assert_eq!(
        r["params"],
        json!({"team": "ENG", "limit": "5", "f": "{\"a\":[1,2]}"})
    );
    let canonical = r#"{"f":{"a":[1,2]},"limit":5,"team":"ENG"}"#;
    assert_eq!(r["body_sha256"], hex(&Sha256::digest(canonical.as_bytes())));
    assert_eq!(r["body_bytes"], canonical.len());
    assert!(r["resp_bytes"].as_u64().unwrap() > 0);
    assert!(r["duration_ms"].is_u64());
    assert!(r["input"]
        .as_str()
        .unwrap()
        .starts_with("mcp:linear list_issues "));
    assert_eq!(r["peer"]["pid"], std::process::id());
    // `via` is the client's word, attribution only.
    let a = w
        .op(
            "mcp.call",
            json!({"server": "linear", "tool": "list_issues", "arguments": "{}", "via": "cli"}),
        )
        .await;
    assert_eq!(a["ok"], true);
    assert_eq!(w.connector()[1]["via"], "cli");
    let a = w
        .op(
            "mcp.call",
            json!({"server": "linear", "tool": "list_issues", "via": "approval"}),
        )
        .await;
    assert_eq!(a["error"], "bad_request", "{a}");
    // The timeout is the server's.
    assert_eq!(w.fake.calls()[0].3, Duration::from_secs(30));
}

#[tokio::test]
async fn unrecorded_result_withheld() {
    let w = world("[\"mcp:linear\"]", "");
    let _ = w.ctx.writer.stop(None).await;
    w.fake
        .answer(|_, _| Ok(json!({"content": [{"type": "text", "text": "the answer"}]})));
    let a = w.call("list_issues", "{}").await;
    assert_eq!(a["ok"], false, "{a}");
    assert!(a.get("result").is_none(), "{a}");
    assert!(!a.to_string().contains("the answer"), "{a}");
    assert!(a["message"]
        .as_str()
        .unwrap()
        .contains("record could not be written"));
}

#[tokio::test]
async fn api_result_returns_mcp_result() {
    let w = world("[\"mcp:linear\"]", "");
    w.fake
        .answer(|_, a| Ok(json!({"content": [{"type": "text", "text": format!("made {a}")}]})));
    let id = w.call("create_issue", r#"{"title":"Bug"}"#).await["pending"]
        .as_u64()
        .unwrap();
    let r = w.result(id).await;
    assert_eq!(r["state"], "pending", "{r}");
    w.approve(id).await;
    let r = w.result(id).await;
    assert_eq!(r["state"], "sent", "{r}");
    assert_eq!(r["result"]["ok"], true, "{r}");
    assert_eq!(r["result"]["status"], Value::Null, "{r}");
    assert_eq!(
        r["result"]["result"]["content"][0]["text"],
        r#"made {"title":"Bug"}"#
    );
    assert_eq!(r["result"]["truncated"], false);
}

#[tokio::test]
async fn limiter_rebuild_counts_mcp_records() {
    let w = world("[\"mcp:linear\"]", "");
    assert_eq!(w.call("echo", "{}").await["ok"], true);
    assert_eq!(w.call("list_issues", "{}").await["ok"], true);
    assert_eq!(
        denied_rule(&w.call("delete_issue", "{}").await),
        "deny:delete_*"
    );
    let records: Vec<saiife_audit::Record> = w
        .audit_text()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let events: Vec<_> = records
        .iter()
        .filter_map(saiife_broker::pipeline::limit_event)
        .collect();
    // The two sent calls, not the denied one.
    assert_eq!(events.len(), 2);
    assert!(events.iter().all(|e| e.key.service == "mcp:linear"));
    assert_eq!(events[0].kind, OpKind::Write);
    assert_eq!(events[1].kind, OpKind::Read);
    // A limiter rebuilt from them counts them.
    let now = OffsetDateTime::now_utc();
    let lim = Limiter::rebuild(events.clone().into_iter(), now);
    let limits = saiife_policy::service::LimitsCfg {
        requests_per_minute: Some(2),
        writes_per_hour: Some(1),
        ..Default::default()
    };
    assert_eq!(
        lim.would_allow(&events[0].key, OpKind::Read, None, false, &limits, now),
        Err("requests_per_minute")
    );
}

// ------------------------------------------------------------ fix round 1

#[tokio::test]
async fn masked_tool_name_or_escaped_secret_cannot_be_approved() {
    let w = world("[\"mcp:linear\"]", "");
    // A listed tool (ask) whose name holds the secret.
    let named = format!("create_{}", token());
    *w.fake.tools.lock().unwrap() = Some(vec![tool(&named), tool("create_issue")]);
    let a = w.call(&named, "{}").await;
    assert_eq!(denied_rule(&a), "masked_content");
    // A secret holding a `"`: escaped in the canonical text, found in the
    // parsed string.
    let quoted = concat!("q\"uo", "te-sec", "ret-7Hk2").to_string();
    w.fake.secrets.lock().unwrap().push(quoted.clone());
    let args = serde_json::to_string(&json!({ "k": quoted })).unwrap();
    assert!(!args.contains(&quoted));
    let a = w.call("create_issue", &args).await;
    assert_eq!(denied_rule(&a), "masked_content");
    // In a key too.
    let args = serde_json::to_string(&json!({ quoted.clone(): 1 })).unwrap();
    let a = w.call("create_issue", &args).await;
    assert_eq!(denied_rule(&a), "masked_content");
    assert!(w.approvals().is_empty());
    assert!(w.fake.calls().is_empty());
}

#[tokio::test]
async fn numbers_that_change_on_the_round_trip_are_refused() {
    let w = world("[\"mcp:linear\"]", "");
    for args in [
        r#"{"n":1e2}"#,
        r#"{"n":1E2}"#,
        r#"{"n":1.5e3}"#,
        r#"{"n":18446744073709551616}"#,
        r#"{"n":-9223372036854775809}"#,
        r#"{"a":[{"n":2e0}]}"#,
        r#"{"n":123456789012345.678}"#,
    ] {
        let a = w.call("list_issues", args).await;
        assert_eq!(denied_rule(&a), "bad_param", "{args}");
    }
    assert!(w.fake.calls().is_empty());
    for args in [
        r#"{"n":18446744073709551615}"#,
        r#"{"n":-9223372036854775808}"#,
        r#"{"n":1.5,"m":-0.25,"s":"1e2 and 18446744073709551616","e":"\"9e9\""}"#,
    ] {
        let a = w.call("list_issues", args).await;
        assert_eq!(a["ok"], true, "{args}: {a}");
    }
    assert_eq!(w.fake.calls()[0].2["n"], json!(u64::MAX));
    for ok in [
        r#"{"n":0.1}"#,
        r#"{"n":1.50}"#,
        r#"{"n":-0.0}"#,
        r#"{"n":100.25}"#,
    ] {
        assert!(numbers_exact(ok.as_bytes()), "{ok}");
    }
    assert!(numbers_exact(br#"{"s":"\\","n":3}"#));
    assert!(!numbers_exact(br#"{"s":"\\","n":3e1}"#));
}

#[tokio::test]
async fn tool_removed_before_approval_is_refused() {
    let w = world("[\"mcp:linear\"]", "");
    let id = w.call("create_issue", "{}").await["pending"]
        .as_u64()
        .unwrap();
    // The server no longer lists it (a relist after the ask).
    *w.fake.tools.lock().unwrap() = Some(vec![tool("list_issues")]);
    w.approve(id).await;
    let r = w.result(id).await;
    assert_eq!(r["state"], "send_failed", "{r}");
    assert_eq!(r["result"]["rule"], "unknown_operation", "{r}");
    assert!(w.fake.calls().is_empty());
    // Not running at all: nothing is sent either.
    let w = world("[\"mcp:linear\"]", "");
    let id = w.call("create_issue", "{}").await["pending"]
        .as_u64()
        .unwrap();
    *w.fake.tools.lock().unwrap() = None;
    w.approve(id).await;
    assert_eq!(w.result(id).await["result"]["rule"], "upstream_unavailable");
    assert!(w.fake.calls().is_empty());
}

#[test]
fn cut_result_keeps_the_note_and_never_exceeds_max() {
    let big = json!({"content": [{"type": "text", "text": "x".repeat(10_000)}], "isError": true});
    // A result that is not an object gets the note too.
    let (v, cut) = cut_result(Value::String("y".repeat(5000)), 1000);
    assert!(cut);
    assert!(json_len(&v) <= 1000, "{v}");
    assert!(v["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("cut at max_response_bytes"));
    // Below the note's reserve: the note never makes it larger than max.
    for max in [300, 120, 60, 40, 14, 5, 0] {
        let (v, cut) = cut_result(big.clone(), max);
        assert!(cut);
        let n = json_len(&v);
        assert!(n <= max.max(14), "{max}: {n} {v}");
        assert!(v["content"].is_array(), "{v}");
    }
    let (v, _) = cut_result(big.clone(), 60);
    assert_eq!(v["content"][0]["text"], "[saiife: cut]", "{v}");
    let (v, _) = cut_result(big, 10);
    assert_eq!(v, json!({"content": []}));
}
