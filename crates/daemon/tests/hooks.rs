//! The hook table over the real control socket (plan 20, Task 2): a hook
//! connection that ends without a verdict is a `hook` record with decision
//! `no_verdict`; one with a verdict, and a CLI connection, are not.
#![cfg(unix)]

use saiife_audit::{ChainWriter, DecisionKind, NewRecord, Record, WriterOptions};
use saiife_daemon::hooks::{Outcome, Principal, NO_VERDICT_REASON, RECONNECT_GRACE};
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
    daemon_as(None)
}

/// [`daemon`], with the daemon's own uid set to `own_uid` (the peers here
/// are then not the daemon itself).
fn daemon_as(own_uid: Option<u32>) -> Daemon {
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
    let base = CtxInit::minimal(handle, cfg, dirs, &state);
    let ctx = Arc::new(Ctx::new(CtxInit {
        audit_dir: audit.clone(),
        own_user: "saiife".into(),
        own_uid: own_uid.unwrap_or(base.own_uid),
        ..base
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

/// This test process's principal, which every hook connection here has.
fn me() -> Principal {
    Principal::Uid(rustix::process::getuid().as_raw())
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
    assert_eq!(
        d.ctx
            .hooks
            .wait(&key(1), Some(&me()), None, until)
            .await
            .outcome(),
        Outcome::NoVerdict
    );
    assert!(start.elapsed() >= RECONNECT_GRACE - Duration::from_millis(100));
    let got = wait_hook_records(&d.audit, 1, Duration::from_secs(5)).await;
    assert_eq!(got.len(), 1, "{got:?}");
    let r = &got[0];
    assert_eq!(r.extra["bound"], true);
    assert_eq!(r.session.as_deref(), Some("c-1"));
    assert_eq!(r.tool, "Bash");
    assert_eq!(r.input, "");
    assert_eq!(r.extra["tool_use_id"], "toolu_1");
    assert!(!r.extra.contains_key("input_sha256"), "no plain input hash");
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
    assert_eq!(
        d.ctx
            .hooks
            .wait(&key(2), Some(&me()), None, until)
            .await
            .outcome(),
        Outcome::Allow
    );
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
    assert_eq!(
        d.ctx
            .hooks
            .wait(&key(3), Some(&me()), None, until)
            .await
            .outcome(),
        Outcome::Deny
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(hook_records(&d.audit).is_empty());
    assert_eq!(d.ctx.hooks.no_verdict_count().0, 0);
}

/// `audit.append` args as the managed hook sends them: the record (with
/// the call's id in it) and, beside it, the key's `tool_use_id` and
/// `input_sha256`.
fn append_args(decision: DecisionKind, tool_use_id: &str, input_sha256: &str) -> Value {
    let mut rec = guard_rec(decision);
    rec["tool_use_id"] = tool_use_id.into();
    json!({"rec": rec, "tool_use_id": tool_use_id, "input_sha256": input_sha256})
}

/// Every guard record written, as text.
fn guard_texts(audit: &Path) -> Vec<String> {
    saiife_audit::store::read_all(audit)
        .records
        .into_iter()
        .filter(|r| r.kind() == "guard")
        .map(|r| serde_json::to_string(&r).unwrap())
        .collect()
}

/// An append whose `tool_use_id` or input hash argument is another call's,
/// or malformed, settles nothing; one that names the bound key settles it.
/// The record's own fields of those names count for nothing, and no input
/// hash is ever written.
#[tokio::test]
async fn only_an_append_naming_the_key_settles_it() {
    let d = daemon();
    let short = || tokio::time::Instant::now() + Duration::from_millis(300);
    let h0f = "0f".repeat(32);
    let hcd = "cd".repeat(32);
    let mut lying = append_args(DecisionKind::Allow, "toolu_9", &hcd);
    // A record that names key(8) itself, with arguments for another call.
    lying["rec"]["tool_use_id"] = "toolu_8".into();
    lying["rec"]["input_sha256"] = h0f.clone().into();
    let mut bad_hash = append_args(DecisionKind::Allow, "toolu_7", &h0f);
    bad_hash["input_sha256"] = "XYZ".into();
    let mut long_id = append_args(DecisionKind::Allow, "toolu_10", &h0f);
    long_id["tool_use_id"] = "t".repeat(257).into();
    // Each on its own key, and kept open, so one's end cannot touch the next.
    let mismatched = [
        (5, append_args(DecisionKind::Allow, "toolu_9", &h0f)),
        (6, append_args(DecisionKind::Allow, "toolu_6", &hcd)),
        (7, bad_hash),
        (8, lying),
        (10, long_id),
    ];
    let mut open = Vec::new();
    for (n, args) in mismatched {
        let mut c = Client::hello(&d.sock).await;
        c.call(OP_HOOK_BEGIN, json!({"agent": "claude"})).await;
        let a = c
            .call(OP_HOOK_BIND, serde_json::to_value(key(n)).unwrap())
            .await;
        assert_eq!(a["ok"], true, "{a}");
        let a = c.call(OP_AUDIT_APPEND, args.clone()).await;
        assert_eq!(a["ok"], true, "the record is still written: {a}");
        assert_eq!(
            d.ctx
                .hooks
                .wait(&key(n), Some(&me()), None, short())
                .await
                .outcome(),
            Outcome::Timeout,
            "{args}"
        );
        open.push(c);
    }
    let mut c = Client::hello(&d.sock).await;
    c.call(OP_HOOK_BEGIN, json!({"agent": "claude"})).await;
    c.call(OP_HOOK_BIND, serde_json::to_value(key(4)).unwrap())
        .await;
    let a = c
        .call(
            OP_AUDIT_APPEND,
            append_args(DecisionKind::Allow, "toolu_4", &h0f),
        )
        .await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(
        d.ctx
            .hooks
            .wait(&key(4), Some(&me()), None, short())
            .await
            .outcome(),
        Outcome::Allow
    );
    let written = guard_texts(&d.audit);
    assert_eq!(written.len(), 6);
    for r in &written {
        assert!(!r.contains("input_sha256"), "{r}");
        assert!(!r.contains(&h0f) && !r.contains(&hcd), "{r}");
    }
    assert!(written
        .last()
        .unwrap()
        .contains("\"tool_use_id\":\"toolu_4\""));
}

/// Each refused `hook.bind` says why: no `hook.begin` on the connection,
/// or another key already bound on it.
#[tokio::test]
async fn a_refused_bind_says_why() {
    let d = daemon();
    let bind = |n| serde_json::to_value(key(n)).unwrap();
    let mut c = Client::hello(&d.sock).await;
    let a = c.call(OP_HOOK_BIND, bind(21)).await;
    assert_eq!(a["error"], "bad_request", "{a}");
    assert!(a.to_string().contains("needs hook.begin first"), "{a}");
    c.call(OP_HOOK_BEGIN, json!({"agent": "claude"})).await;
    let a = c.call(OP_HOOK_BIND, bind(21)).await;
    assert_eq!(a["ok"], true, "{a}");
    let a = c.call(OP_HOOK_BIND, bind(22)).await;
    assert_eq!(a["error"], "bad_request", "{a}");
    let msg = a.to_string();
    assert!(msg.contains("already bound another key"), "{a}");
    assert!(!msg.contains("hook.begin"), "{a}");
}

/// A connection binds one key: a second key is refused and adds no slot.
/// A new connection that binds a key clears its old outcome.
#[tokio::test]
async fn one_key_per_connection_and_a_rebind_clears_the_outcome() {
    let d = daemon();
    let short = || tokio::time::Instant::now() + Duration::from_millis(300);
    let h0f = "0f".repeat(32);
    let mut c = Client::hello(&d.sock).await;
    c.call(OP_HOOK_BEGIN, json!({"agent": "claude"})).await;
    let bind = |n| serde_json::to_value(key(n)).unwrap();
    let a = c.call(OP_HOOK_BIND, bind(11)).await;
    assert_eq!(a["ok"], true, "{a}");
    let a = c.call(OP_HOOK_BIND, bind(12)).await;
    assert_eq!(a["error"], "bad_request", "{a}");
    let msg = a.to_string();
    assert!(msg.contains("already bound another key"), "{a}");
    assert!(!msg.contains("hook.begin first"), "{a}");
    let a = c.call(OP_HOOK_BIND, bind(11)).await;
    assert_eq!(a["ok"], true, "the same key again: {a}");
    let a = c
        .call(
            OP_AUDIT_APPEND,
            append_args(DecisionKind::Allow, "toolu_11", &h0f),
        )
        .await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(
        d.ctx
            .hooks
            .wait(&key(11), Some(&me()), None, short())
            .await
            .outcome(),
        Outcome::Allow
    );
    assert_eq!(
        d.ctx
            .hooks
            .wait(&key(12), Some(&me()), None, short())
            .await
            .outcome(),
        Outcome::Timeout
    );
    drop(c);
    let mut c = Client::hello(&d.sock).await;
    c.call(OP_HOOK_BEGIN, json!({"agent": "claude"})).await;
    let a = c.call(OP_HOOK_BIND, bind(11)).await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(
        d.ctx
            .hooks
            .wait(&key(11), Some(&me()), None, short())
            .await
            .outcome(),
        Outcome::Timeout,
        "the old allow no longer answers"
    );
    c.call(
        OP_AUDIT_APPEND,
        append_args(DecisionKind::Deny, "toolu_11", &h0f),
    )
    .await;
    assert_eq!(
        d.ctx
            .hooks
            .wait(&key(11), Some(&me()), None, short())
            .await
            .outcome(),
        Outcome::Deny
    );
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

#[tokio::test]
async fn below_the_disk_floor_no_verdict_is_counted_not_written() {
    // The daemon's own records pass the floor; a hook's peer is never it.
    let d = daemon_as(Some(rustix::process::getuid().as_raw().wrapping_add(1)));
    d.ctx.policy.lock().unwrap().min_free_mb = u64::MAX;
    let mut c = Client::hello(&d.sock).await;
    c.call(OP_HOOK_BEGIN, json!({"agent": "codex"})).await;
    drop(c);
    let mut c = Client::hello(&d.sock).await;
    c.call(OP_HOOK_BEGIN, json!({"agent": "codex"})).await;
    drop(c);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while d.ctx.hooks.no_verdict_count().0 < 2 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(d.ctx.hooks.no_verdict_count().0, 2);
    let low = |a: &Path| {
        saiife_audit::store::read_all(a)
            .records
            .into_iter()
            .filter(|r| r.extra.get("event").and_then(Value::as_str) == Some("low_disk"))
            .count()
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while low(&d.audit) < 1 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(hook_records(&d.audit).is_empty());
    // One notice a minute per uid, however many hooks.
    assert_eq!(low(&d.audit), 1);
}
