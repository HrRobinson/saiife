//! The hook table over the real control socket (plan 20, Task 2): a hook
//! connection that ends without a verdict is a `hook` record with decision
//! `no_verdict`; one with a verdict, and a CLI connection, are not.
#![cfg(unix)]

use saiife_audit::{ChainWriter, DecisionKind, NewRecord, Record, WriterOptions};
use saiife_daemon::hooks::{Waited, NO_VERDICT_REASON, RECONNECT_GRACE};
use saiife_daemon::ops::{Ctx, CtxInit};
use saiife_daemon::writer::{self, WriterConfig};
use saiife_ipc::frame::{encode_max, MAX_ANSWER_FRAME};
use saiife_ipc::hookkey::HookKey;
use saiife_ipc::msg::{OP_AUDIT_APPEND, OP_HELLO, OP_HOOK_BEGIN, OP_HOOK_BIND, OP_STATUS, PROTO};
use saiife_policy::{Directory, Fsync};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

fn scratch() -> tempfile::TempDir {
    let base = std::env::var_os("SAIIFE_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    std::fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

struct Daemon {
    ctx: Arc<Ctx>,
    sock: PathBuf,
    audit: PathBuf,
    _tmp: tempfile::TempDir,
}

/// A locked daemon context on a socket in a tempdir, serving every
/// connection as `start.rs` does.
fn daemon() -> Daemon {
    let tmp = scratch();
    let audit = tmp.path().join("audit");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&audit).unwrap();
    std::fs::create_dir_all(&state).unwrap();
    let cw = ChainWriter::open(
        &audit,
        WriterOptions {
            mode: "locked".into(),
            saiife: "test".into(),
            key: None,
        },
    )
    .unwrap();
    let cfg = WriterConfig {
        checkpoint_every: 1000,
        checkpoint_interval: Duration::from_secs(900),
        fsync: Fsync::Always,
    };
    let (handle, _join) = writer::spawn(cw, cfg, None).unwrap();
    let dirs: Arc<dyn Directory + Send + Sync> =
        Arc::new(saiife_policy::FixedDirectory::from_text("", ""));
    let ctx = Arc::new(Ctx::new(CtxInit {
        audit_dir: audit.clone(),
        own_user: "saiife".into(),
        ..CtxInit::minimal(handle, cfg, dirs, &state)
    }));
    let sock = tmp.path().join("s.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let c = Arc::clone(&ctx);
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            tokio::spawn(saiife_daemon::server::connection(s, Arc::clone(&c)));
        }
    });
    Daemon {
        ctx,
        sock,
        audit,
        _tmp: tmp,
    }
}

struct Client {
    s: UnixStream,
    id: u64,
}

impl Client {
    async fn hello(sock: &Path) -> Client {
        let mut c = Client {
            s: UnixStream::connect(sock).await.unwrap(),
            id: 0,
        };
        let a = c.call(OP_HELLO, json!({"proto": PROTO})).await;
        assert_eq!(a["ok"], true, "{a}");
        c
    }

    async fn call(&mut self, op: &str, args: Value) -> Value {
        self.id += 1;
        let mut m = args.as_object().cloned().unwrap_or_default();
        m.insert("id".into(), self.id.into());
        m.insert("op".into(), op.into());
        let frame = encode_max(&Value::Object(m), MAX_ANSWER_FRAME).unwrap();
        self.s.write_all(&frame).await.unwrap();
        let mut h = [0u8; 4];
        self.s.read_exact(&mut h).await.unwrap();
        let mut body = vec![0u8; u32::from_be_bytes(h) as usize];
        self.s.read_exact(&mut body).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }
}

fn key(n: u32) -> HookKey {
    HookKey {
        agent: "claude".into(),
        session: Some("c-1".into()),
        tool_use_id: Some(format!("toolu_{n}")),
        input_sha256: "0f".repeat(32),
    }
}

fn guard_rec(decision: DecisionKind) -> Value {
    let r = Record::new(
        NewRecord {
            agent: "claude",
            project: "/p",
            session: Some("c-1"),
            tool: "Bash",
            input: "ls -la",
            decision,
            pack: None,
            rule: None,
            reason: None,
            mode: "locked",
            policy: None,
            permission_mode: None,
        },
        "test",
    );
    serde_json::to_value(r).unwrap()
}

fn hook_records(audit: &Path) -> Vec<Record> {
    saiife_audit::store::read_all(audit)
        .records
        .into_iter()
        .filter(|r| r.kind() == "hook")
        .collect()
}

/// The `hook` records once `n` are there, within `limit`.
async fn wait_hook_records(audit: &Path, n: usize, limit: Duration) -> Vec<Record> {
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        let got = hook_records(audit);
        if got.len() >= n || tokio::time::Instant::now() >= deadline {
            return got;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn unbound_hook_that_drops_is_recorded() {
    let d = daemon();
    let mut c = Client::hello(&d.sock).await;
    let a = c
        .call(
            OP_HOOK_BEGIN,
            json!({"agent": "codex", "event": "PreToolUse"}),
        )
        .await;
    assert_eq!(a["ok"], true, "{a}");
    drop(c);
    let got = wait_hook_records(&d.audit, 1, Duration::from_secs(5)).await;
    assert_eq!(got.len(), 1, "{got:?}");
    let r = &got[0];
    assert_eq!(r.decision, DecisionKind::NoVerdict);
    assert_eq!(r.agent, "codex");
    assert_eq!(r.uid, Some(rustix::process::getuid().as_raw()));
    assert_eq!(r.reason.as_deref(), Some(NO_VERDICT_REASON));
    assert_eq!(r.extra["event"], "no_verdict");
    assert_eq!(r.extra["bound"], false);
    assert_eq!(r.extra["pid"], std::process::id());
    assert_eq!(r.extra["hook_event"], "PreToolUse");
    let mut cli = Client::hello(&d.sock).await;
    let s = cli.call(OP_STATUS, json!({})).await;
    assert_eq!(s["hooks_no_verdict"]["since_start"], 1, "{s}");
    assert_eq!(
        s["hooks_no_verdict"]["last_ts"].as_str(),
        Some(r.ts.as_str()),
        "{s}"
    );
}

#[tokio::test]
async fn bound_hook_that_drops_is_recorded_after_the_grace() {
    let d = daemon();
    let mut c = Client::hello(&d.sock).await;
    c.call(
        OP_HOOK_BEGIN,
        json!({"agent": "claude", "event": "PreToolUse"}),
    )
    .await;
    let mut args = serde_json::to_value(key(1)).unwrap();
    args["tool"] = "Bash".into();
    let a = c.call(OP_HOOK_BIND, args).await;
    assert_eq!(a["ok"], true, "{a}");
    drop(c);
    let start = tokio::time::Instant::now();
    let until = start + RECONNECT_GRACE + Duration::from_secs(2);
    assert_eq!(d.ctx.hooks.wait(&key(1), until).await, Waited::NoVerdict);
    assert!(start.elapsed() >= RECONNECT_GRACE - Duration::from_millis(100));
    let got = wait_hook_records(&d.audit, 1, Duration::from_secs(5)).await;
    assert_eq!(got.len(), 1, "{got:?}");
    let r = &got[0];
    assert_eq!(r.extra["bound"], true);
    assert_eq!(r.session.as_deref(), Some("c-1"));
    assert_eq!(r.tool, "Bash");
    assert_eq!(r.input, "");
    assert_eq!(r.extra["tool_use_id"], "toolu_1");
    assert_eq!(r.extra["input_sha256"], "0f".repeat(32).as_str());
}

#[tokio::test]
async fn a_verdict_writes_no_hook_record() {
    let d = daemon();
    let mut c = Client::hello(&d.sock).await;
    c.call(OP_HOOK_BEGIN, json!({"agent": "claude"})).await;
    c.call(OP_HOOK_BIND, serde_json::to_value(key(2)).unwrap())
        .await;
    let a = c
        .call(
            OP_AUDIT_APPEND,
            json!({"rec": guard_rec(DecisionKind::Allow)}),
        )
        .await;
    assert_eq!(a["ok"], true, "{a}");
    drop(c);
    let until = tokio::time::Instant::now() + Duration::from_secs(1);
    assert_eq!(d.ctx.hooks.wait(&key(2), until).await, Waited::Allow);
    // A denied call on another connection settles its key as a deny.
    let mut c = Client::hello(&d.sock).await;
    c.call(OP_HOOK_BEGIN, json!({"agent": "claude"})).await;
    c.call(OP_HOOK_BIND, serde_json::to_value(key(3)).unwrap())
        .await;
    c.call(
        OP_AUDIT_APPEND,
        json!({"rec": guard_rec(DecisionKind::Deny)}),
    )
    .await;
    drop(c);
    assert_eq!(d.ctx.hooks.wait(&key(3), until).await, Waited::Deny);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(hook_records(&d.audit).is_empty());
    assert_eq!(d.ctx.hooks.no_verdict_count().0, 0);
}

#[tokio::test]
async fn cli_connections_are_not_tracked_and_ops_are_checked() {
    let d = daemon();
    let mut c = Client::hello(&d.sock).await;
    c.call(OP_STATUS, json!({})).await;
    // No begin: bind is refused.
    let a = c
        .call(OP_HOOK_BIND, serde_json::to_value(key(4)).unwrap())
        .await;
    assert_eq!(a["error"], "bad_request", "{a}");
    drop(c);
    let mut c = Client::hello(&d.sock).await;
    let a = c.call(OP_HOOK_BEGIN, json!({})).await;
    assert_eq!(a["error"], "bad_request", "{a}");
    let a = c.call(OP_HOOK_BEGIN, json!({"agent": "claude"})).await;
    assert_eq!(a["ok"], true, "{a}");
    let a = c.call(OP_HOOK_BEGIN, json!({"agent": "claude"})).await;
    assert_eq!(a["error"], "bad_request", "{a}");
    let mut bad = serde_json::to_value(key(5)).unwrap();
    bad["input_sha256"] = "XYZ".into();
    let a = c.call(OP_HOOK_BIND, bad).await;
    assert_eq!(a["error"], "bad_request", "{a}");
    c.call(
        OP_AUDIT_APPEND,
        json!({"rec": guard_rec(DecisionKind::Allow)}),
    )
    .await;
    drop(c);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(hook_records(&d.audit).is_empty());
}
