//! The Claude Code co-signer over loopback (plan 20, Task 4), against a
//! daemon context whose hooks talk over the real control socket. Raw
//! HTTP/1.1 on a TCP stream, so every byte of the answer is seen.
#![cfg(unix)]

use saiife_audit::{ChainWriter, DecisionKind, NewRecord, Record, WriterOptions};
use saiife_daemon::cosign::{self, deny_body, CosignDeny, Opts, Retry};
use saiife_daemon::hooks::RECONNECT_GRACE;
use saiife_daemon::ops::{Ctx, CtxInit};
use saiife_daemon::rejudge::{Rejudge, RejudgeAnswer, RejudgeRequest};
use saiife_daemon::writer::{self, WriterConfig};
use saiife_ipc::frame::{encode_max, MAX_ANSWER_FRAME};
use saiife_ipc::hookkey::hook_key;
use saiife_ipc::msg::{OP_AUDIT_APPEND, OP_HELLO, OP_HOOK_BEGIN, OP_HOOK_BIND, OP_STATUS, PROTO};
use saiife_policy::{Directory, Fsync};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixListener, UnixStream};
use tokio::time::Instant;

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
    /// The co-signer, when it was started.
    addr: Option<SocketAddr>,
    _tmp: tempfile::TempDir,
}

/// A locked daemon context: control socket in a tempdir, and the co-signer
/// on a free loopback port with `opts`. The service's own judgment allows
/// every call.
async fn daemon(opts: Option<Opts>) -> Daemon {
    daemon_with(
        opts,
        Some(Arc::new(|_: RejudgeRequest| RejudgeAnswer::Allow)),
    )
    .await
}

/// [`daemon`] with `rejudge` as the service's own judgment.
async fn daemon_with(opts: Option<Opts>, rejudge: Option<Arc<dyn Rejudge>>) -> Daemon {
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
    ctx.cosign.lock().unwrap().rejudge = rejudge;
    let sock = tmp.path().join("s.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let c = Arc::clone(&ctx);
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            tokio::spawn(saiife_daemon::server::connection(s, Arc::clone(&c)));
        }
    });
    let addr = match opts {
        Some(o) => {
            let l = cosign::bind_cosign("127.0.0.1:0".parse().unwrap()).unwrap();
            let a = l.local_addr().unwrap();
            tokio::spawn(cosign::serve_cosign_with(l, Arc::clone(&ctx), o));
            Some(a)
        }
        None => None,
    };
    Daemon {
        ctx,
        sock,
        audit,
        addr,
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

    /// A hook connection: `hook.begin`, then `hook.bind` with the key of
    /// `payload`.
    async fn hook(sock: &Path, payload: &str) -> Client {
        let mut c = Client::hello(sock).await;
        let a = c
            .call(
                OP_HOOK_BEGIN,
                json!({"agent": "claude", "event": "PreToolUse"}),
            )
            .await;
        assert_eq!(a["ok"], true, "{a}");
        let mut args = serde_json::to_value(hook_key("claude", payload).unwrap()).unwrap();
        args["tool"] = "Bash".into();
        let a = c.call(OP_HOOK_BIND, args).await;
        assert_eq!(a["ok"], true, "{a}");
        c
    }

    async fn verdict(&mut self, decision: DecisionKind, command: &str) {
        let a = self
            .call(
                OP_AUDIT_APPEND,
                json!({"rec": guard_rec(decision, command)}),
            )
            .await;
        assert_eq!(a["ok"], true, "{a}");
    }
}

fn payload(tool_use_id: &str, command: &str) -> String {
    json!({
        "session_id": "c-1",
        "tool_use_id": tool_use_id,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command, "description": "x"},
    })
    .to_string()
}

fn guard_rec(decision: DecisionKind, command: &str) -> Value {
    let r = Record::new(
        NewRecord {
            agent: "claude",
            project: "/p",
            session: Some("c-1"),
            tool: "Bash",
            input: command,
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

/// One answer: status, headers (lowercase names), body.
#[derive(Debug)]
struct Answer {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Answer {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Send `head` (without the final blank line) and `body`; read the answer
/// to the end (the co-signer closes after each one).
async fn raw(addr: SocketAddr, head: &str, body: &[u8]) -> Answer {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(head.as_bytes()).await.unwrap();
    s.write_all(b"\r\n").await.unwrap();
    // A body refused before it is read may meet a closed socket.
    let _ = s.write_all(body).await;
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out).await;
    let text = String::from_utf8(out).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").expect("an HTTP answer");
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .map(|l| {
            let (n, v) = l.split_once(':').unwrap();
            (n.trim().to_ascii_lowercase(), v.trim().to_string())
        })
        .collect();
    Answer {
        status,
        headers,
        body: body.to_string(),
    }
}

async fn post(addr: SocketAddr, body: String) -> Answer {
    let head = format!(
        "POST /v1/cosign/claude HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    );
    raw(addr, &head, body.as_bytes()).await
}

fn records(audit: &Path, event: &str) -> Vec<Record> {
    saiife_audit::store::read_all(audit)
        .records
        .into_iter()
        .filter(|r| r.extra.get("event").and_then(Value::as_str) == Some(event))
        .collect()
}

async fn wait_records(audit: &Path, event: &str, n: usize) -> Vec<Record> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let got = records(audit, event);
        if got.len() >= n || Instant::now() >= deadline {
            return got;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn assert_deny(a: &Answer, why: CosignDeny) {
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.body, deny_body(why), "{a:?}");
    assert_eq!(a.header("content-type"), Some("application/json"));
}

fn assert_no_opinion(a: &Answer) {
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.body, "", "{a:?}");
    assert_eq!(a.header("content-length"), Some("0"), "{a:?}");
}

fn short(wait: Duration) -> Option<Opts> {
    Some(Opts {
        wait,
        ..Opts::default()
    })
}

#[tokio::test]
async fn recorded_allow_gets_empty_200() {
    let d = daemon(Some(Opts::default())).await;
    let p = payload("toolu_1", "ls -la");
    let mut h = Client::hook(&d.sock, &p).await;
    h.verdict(DecisionKind::Allow, "ls -la").await;
    drop(h);
    // Another formatting of the same call: the same key.
    let reformatted =
        serde_json::to_string_pretty(&serde_json::from_str::<Value>(&p).unwrap()).unwrap();
    let a = post(d.addr.unwrap(), reformatted.clone()).await;
    assert_no_opinion(&a);
    assert!(records(&d.audit, "cosign_denied").is_empty());
}

#[tokio::test]
async fn cosign_waits_for_a_late_verdict() {
    let d = daemon(Some(Opts::default())).await;
    let p = payload("toolu_2", "ls");
    let start = Instant::now();
    let asked = tokio::spawn(post(d.addr.unwrap(), p.clone()));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut h = Client::hook(&d.sock, &p).await;
    h.verdict(DecisionKind::Allow, "ls").await;
    let a = asked.await.unwrap();
    assert_no_opinion(&a);
    assert!(start.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn recorded_deny_gets_deny_body() {
    let d = daemon(Some(Opts::default())).await;
    let p = payload("toolu_3", "rm -rf /");
    let mut h = Client::hook(&d.sock, &p).await;
    h.verdict(DecisionKind::Deny, "rm -rf /").await;
    let a = post(d.addr.unwrap(), p.clone()).await;
    assert_eq!(
        a.body,
        r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"saiife: BLOCKED (fail closed): saiife denied this call"}}"#
    );
    assert_deny(&a, CosignDeny::Denied);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        records(&d.audit, "cosign_denied").is_empty(),
        "the guard record says why"
    );
}

#[tokio::test]
async fn killed_hook_gets_deny_at_once() {
    let d = daemon(Some(Opts::default())).await;
    let p = payload("toolu_4", "ls");
    let h = Client::hook(&d.sock, &p).await;
    let start = Instant::now();
    drop(h);
    let a = post(d.addr.unwrap(), p.clone()).await;
    assert_deny(&a, CosignDeny::NoVerdict);
    assert!(start.elapsed() < RECONNECT_GRACE + Duration::from_secs(1));
    let got = wait_records(&d.audit, "cosign_denied", 1).await;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].reason.as_deref(), Some(CosignDeny::NoVerdict.text()));
    assert_eq!(got[0].kind(), "hook");
    assert_eq!(got[0].decision, DecisionKind::ErrorDenied);
    assert_eq!(got[0].tool, "Bash");
    // The asker's input and session only where it is identified (Linux, macOS).
    assert_eq!(got[0].input, if IDENTIFIED { "ls" } else { "" });
    assert_eq!(got[0].session.as_deref(), IDENTIFIED.then_some("c-1"));
    assert_eq!(got[0].extra["tool_use_id"], "toolu_4");
    assert_eq!(wait_records(&d.audit, "no_verdict", 1).await.len(), 1);
}

#[tokio::test]
async fn other_payload_does_not_match() {
    let d = daemon(short(Duration::from_secs(1))).await;
    let mut h = Client::hook(&d.sock, &payload("toolu_5", "ls -la")).await;
    h.verdict(DecisionKind::Allow, "ls -la").await;
    let a = post(d.addr.unwrap(), payload("toolu_5", "rm -rf /")).await;
    assert_deny(&a, CosignDeny::NoReport);
    let got = wait_records(&d.audit, "cosign_denied", 1).await;
    assert_eq!(got[0].input, if IDENTIFIED { "rm -rf /" } else { "" });
}

/// The co-signer identifies a TCP asker by its uid here (`/proc/net` on
/// Linux, `pcblist_n` on macOS).
const IDENTIFIED: bool = cfg!(any(target_os = "linux", target_os = "macos"));

#[tokio::test]
async fn not_cosignable_without_tool_use_id() {
    let d = daemon(Some(Opts::default())).await;
    let p = json!({"session_id": "c-1", "tool_name": "Bash", "tool_input": {"command": "ls"}})
        .to_string();
    let start = Instant::now();
    let a = post(d.addr.unwrap(), p.clone()).await;
    assert_deny(&a, CosignDeny::NotCosignable);
    assert!(start.elapsed() < Duration::from_secs(2), "at once");
    let a = post(d.addr.unwrap(), "{not json".into()).await;
    assert_deny(&a, CosignDeny::BadJson);
}

#[tokio::test]
async fn origin_header_refused() {
    let d = daemon(Some(Opts::default())).await;
    let p = payload("toolu_6", "ls");
    let head = format!(
        "POST /v1/cosign/claude HTTP/1.1\r\nHost: x\r\nOrigin: http://evil.example\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        p.len()
    );
    let a = raw(d.addr.unwrap(), &head, p.as_bytes()).await;
    assert_eq!(a.status, 403, "{a:?}");
}

#[tokio::test]
async fn wrong_content_type_refused() {
    let d = daemon(Some(Opts::default())).await;
    let p = payload("toolu_7", "ls");
    for ct in ["text/plain", "application/x-www-form-urlencoded"] {
        let head = format!(
            "POST /v1/cosign/claude HTTP/1.1\r\nHost: x\r\nContent-Type: {ct}\r\nContent-Length: {}\r\n",
            p.len()
        );
        let a = raw(d.addr.unwrap(), &head, p.as_bytes()).await;
        assert_eq!(a.status, 415, "{a:?}");
    }
    let head = format!(
        "POST /v1/cosign/claude HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n",
        p.len()
    );
    assert_eq!(raw(d.addr.unwrap(), &head, p.as_bytes()).await.status, 415);
    // Parameters are allowed.
    let mut h = Client::hook(&d.sock, &p).await;
    h.verdict(DecisionKind::Allow, "ls").await;
    let head = format!(
        "POST /v1/cosign/claude HTTP/1.1\r\nHost: x\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\n",
        p.len()
    );
    assert_no_opinion(&raw(d.addr.unwrap(), &head, p.as_bytes()).await);
}

#[tokio::test]
async fn wrong_path_404() {
    let d = daemon(Some(Opts::default())).await;
    let p = payload("toolu_8", "ls");
    for path in ["/v1/cosign/codex", "/", "/v1/cosign/claude/x"] {
        let head = format!(
            "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
            p.len()
        );
        let a = raw(d.addr.unwrap(), &head, p.as_bytes()).await;
        assert_eq!(a.status, 404, "{path}: {a:?}");
    }
}

#[tokio::test]
async fn get_404() {
    let d = daemon(Some(Opts::default())).await;
    let a = raw(
        d.addr.unwrap(),
        "GET /v1/cosign/claude HTTP/1.1\r\nHost: x\r\n",
        b"",
    )
    .await;
    assert_eq!(a.status, 404, "{a:?}");
}

#[tokio::test]
async fn inflight_cap_answers_503() {
    // The global cap, with one uid's share as large as it.
    let d = daemon(Some(Opts {
        wait: Duration::from_secs(3),
        max_inflight_per_uid: cosign::MAX_INFLIGHT,
        ..Opts::default()
    }))
    .await;
    let addr = d.addr.unwrap();
    let held: Vec<_> = (0..16)
        .map(|n| tokio::spawn(post(addr, payload(&format!("toolu_h{n}"), "ls"))))
        .collect();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let a = post(addr, payload("toolu_17", "ls")).await;
    assert_eq!(a.status, 503, "{a:?}");
    for h in held {
        assert_deny(&h.await.unwrap(), CosignDeny::NoReport);
    }
}

#[tokio::test]
async fn oversize_body_denied() {
    let d = daemon(Some(Opts {
        max_body: 1024,
        ..Opts::default()
    }))
    .await;
    let big = payload("toolu_9", &"a".repeat(2048));
    let a = post(d.addr.unwrap(), big.clone()).await;
    assert_deny(&a, CosignDeny::TooLarge);
    // Chunked, with no length: cut at the cap as it comes.
    let head = "POST /v1/cosign/claude HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n";
    let body = format!("{:x}\r\n{big}\r\n0\r\n\r\n", big.len());
    let a = raw(d.addr.unwrap(), head, body.as_bytes()).await;
    assert_deny(&a, CosignDeny::TooLarge);
    let got = wait_records(&d.audit, "cosign_denied", 1).await;
    assert_eq!(got[0].reason.as_deref(), Some(CosignDeny::TooLarge.text()));
}

/// Follow-up of PR #29: over the cap, a cut inside a multibyte character and a
/// tool name past the cap (either spelling) are denied as too large too: the
/// co-signer never parses a body it did not read whole.
#[tokio::test]
async fn oversize_body_denied_wherever_its_tool_is() {
    let d = daemon(Some(Opts {
        max_body: 1024,
        ..Opts::default()
    }))
    .await;
    let head = r#"{"session_id":"c-1","tool_use_id":"toolu_10","tool_input":{"command":""#;
    let cut = format!(
        "{head}{}{}\"}},\"tool_name\":\"Bash\"}}",
        "a".repeat(1024 - head.len()),
        "é".repeat(64)
    );
    assert_eq!(cut.as_bytes()[1024], 0xC3, "the cut is inside a character");
    let camel = format!(r#"{head}{}"}},"toolName":"Bash"}}"#, "a".repeat(2048));
    for body in [cut, camel] {
        let a = post(d.addr.unwrap(), body.clone()).await;
        assert_deny(&a, CosignDeny::TooLarge);
        let chunked = "POST /v1/cosign/claude HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n";
        let framed = format!("{:x}\r\n{body}\r\n0\r\n\r\n", body.len());
        let a = raw(d.addr.unwrap(), chunked, framed.as_bytes()).await;
        assert_deny(&a, CosignDeny::TooLarge);
    }
}

/// A port held by another socket: one record, status shows the error for
/// as long as it lasts, and once the port is free the co-signer binds it
/// with no restart.
#[tokio::test]
async fn port_in_use_is_retried_until_it_binds() {
    let d = daemon(None).await;
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = taken.local_addr().unwrap();
    let retry = Retry {
        first: Duration::from_millis(20),
        max: Duration::from_millis(80),
    };
    let _task = cosign::start_cosign_with(&d.ctx, addr, Opts::default(), retry).await;
    let got = wait_records(&d.audit, "cosign_bind_failed", 1).await;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].kind(), "daemon");
    assert!(got[0].reason.as_deref().is_some_and(|r| !r.is_empty()));
    let mut c = Client::hello(&d.sock).await;
    let a = c
        .call(
            OP_AUDIT_APPEND,
            json!({"rec": guard_rec(DecisionKind::Allow, "ls")}),
        )
        .await;
    assert_eq!(a["ok"], true, "{a}");
    // Several tries fail meanwhile; doctor still sees the error.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let s = c.call(OP_STATUS, json!({})).await;
    assert_eq!(s["cosign"]["addr"], Value::Null, "{s}");
    assert!(s["cosign"]["error"].is_string(), "{s}");
    assert_eq!(
        records(&d.audit, "cosign_bind_failed").len(),
        1,
        "once, not per try"
    );
    // The port comes free: a retry binds it, and status names it.
    drop(taken);
    let deadline = Instant::now() + Duration::from_secs(5);
    let s = loop {
        let s = c.call(OP_STATUS, json!({})).await;
        if s["cosign"]["addr"] == addr.to_string() || Instant::now() > deadline {
            break s;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(s["cosign"]["addr"], addr.to_string(), "{s}");
    assert_eq!(s["cosign"]["error"], Value::Null, "{s}");
    // And it answers: an honest allow is co-signed.
    let p = payload("toolu_rebind", "ls");
    let mut h = Client::hook(&d.sock, &p).await;
    h.verdict(DecisionKind::Allow, "ls").await;
    assert_no_opinion(&post(addr, p).await);
    assert_eq!(records(&d.audit, "cosign_bind_failed").len(), 1);
}

/// After a restart the last daemon's connections sit in `TIME_WAIT` on
/// the port (the co-signer closes first); the bind gets past them.
#[tokio::test]
async fn bind_gets_past_time_wait() {
    let l = cosign::bind_cosign("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = l.local_addr().unwrap();
    let client = TcpStream::connect(addr).await.unwrap();
    let (server, _) = l.accept().await.unwrap();
    // The server end closes first, so it is the one in TIME_WAIT.
    drop(server);
    let mut client = client;
    let mut buf = [0u8; 1];
    assert_eq!(client.read(&mut buf).await.unwrap(), 0);
    drop(client);
    drop(l);
    let again = cosign::bind_cosign(addr).expect("binds over TIME_WAIT");
    assert_eq!(again.local_addr().unwrap(), addr);
}

#[tokio::test]
async fn just_over_the_16_mib_cap_is_too_large() {
    assert_eq!(cosign::MAX_BODY, 16 * 1024 * 1024);
    let d = daemon(Some(Opts::default())).await;
    let pad = cosign::MAX_BODY - payload("toolu_cap", "").len() + 1;
    let p = payload("toolu_cap", &"a".repeat(pad));
    assert_eq!(p.len(), cosign::MAX_BODY + 1);
    let a = post(d.addr.unwrap(), p).await;
    assert_deny(&a, CosignDeny::TooLarge);
}

/// A call whose payload is just under the cap (a large `Write`) is read,
/// parsed and co-signed.
#[tokio::test]
async fn near_the_cap_is_accepted() {
    let d = daemon(Some(Opts::default())).await;
    let pad = cosign::MAX_BODY - payload("toolu_near", "").len() - 64;
    let command = "a".repeat(pad);
    let p = payload("toolu_near", &command);
    assert!(p.len() < cosign::MAX_BODY && p.len() > cosign::MAX_BODY - 128);
    let mut h = Client::hook(&d.sock, &p).await;
    h.verdict(DecisionKind::Allow, "a").await;
    assert_no_opinion(&post(d.addr.unwrap(), p).await);
}

/// An asker whose socket is not found is denied before its body is read.
#[tokio::test]
async fn unidentified_peer_is_denied_without_its_body() {
    let d = daemon(Some(Opts {
        peer_uid: Some(|_| None),
        ..Opts::default()
    }))
    .await;
    let addr = d.addr.unwrap();
    let mut s = TcpStream::connect(addr).await.unwrap();
    let head = "POST /v1/cosign/claude HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n";
    s.write_all(head.as_bytes()).await.unwrap();
    let start = Instant::now();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
    assert!(start.elapsed() < Duration::from_secs(2));
    let text = String::from_utf8(out).unwrap();
    assert!(text.ends_with(&deny_body(CosignDeny::NoReport)), "{text}");
    let got = wait_records(&d.audit, "cosign_denied", 1).await;
    assert_eq!(got[0].session, None);
    assert_eq!(got[0].input, "");
}

/// Linux: one uid's flood of slow bodies takes only its own share of the
/// in-flight cap; another uid's request is answered at once. The uid is
/// the last byte of the client's loopback address here (`peer_uid`), as
/// `/proc/net/tcp` would give it.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn slow_body_flood_from_one_uid_does_not_block_another() {
    async fn from(src: [u8; 4], addr: SocketAddr) -> TcpStream {
        let s = tokio::net::TcpSocket::new_v4().unwrap();
        s.bind(SocketAddr::from((src, 0))).unwrap();
        s.connect(addr).await.unwrap()
    }
    let d = daemon(Some(Opts {
        peer_uid: Some(|peer| match peer.ip() {
            std::net::IpAddr::V4(ip) => Some(10_000 + u32::from(ip.octets()[3])),
            std::net::IpAddr::V6(_) => None,
        }),
        ..Opts::default()
    }))
    .await;
    let addr = d.addr.unwrap();
    let head = "POST /v1/cosign/claude HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{\"a\":";
    // uid 10002: as many slow bodies as the global in-flight cap.
    let mut flood = Vec::new();
    for _ in 0..cosign::MAX_INFLIGHT {
        let mut s = from([127, 0, 0, 2], addr).await;
        s.write_all(head.as_bytes()).await.unwrap();
        flood.push(s);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Those over its own share were answered 503 already.
    let mut busy = 0;
    for s in &mut flood {
        let mut out = Vec::new();
        if let Ok(Ok(_)) =
            tokio::time::timeout(Duration::from_millis(50), s.read_to_end(&mut out)).await
        {
            if String::from_utf8_lossy(&out).starts_with("HTTP/1.1 503") {
                busy += 1;
            }
        }
    }
    // uid 10003, while the flood holds its slots: answered at once.
    let start = Instant::now();
    let mut s = from([127, 0, 0, 3], addr).await;
    let body = b"{not json";
    let req = format!(
        "POST /v1/cosign/claude HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    s.write_all(body).await.unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.ends_with(&deny_body(CosignDeny::BadJson)), "{text}");
    assert!(start.elapsed() < Duration::from_secs(2));
    assert_eq!(busy, cosign::MAX_INFLIGHT - cosign::MAX_INFLIGHT_PER_UID);
    drop(flood);
}

#[tokio::test]
async fn a_second_bind_beside_the_cosigner_fails() {
    let d = daemon(Some(Opts::default())).await;
    assert!(std::net::TcpListener::bind(d.addr.unwrap()).is_err());
    assert!(cosign::bind_cosign(d.addr.unwrap()).is_err());
}

#[test]
fn personal_mode_does_not_bind() {
    assert_eq!(cosign::target(false, false), None);
    assert_eq!(cosign::target(false, true), None);
}

// ------------------------------------------------ plan 21: both must agree

/// A Claude Code fixture body, byte for byte.
fn fixture(name: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../cli/tests/fixtures/claude")
        .join(name);
    std::fs::read_to_string(p).unwrap()
}

/// What a fake re-judge was asked.
type Asked = Arc<std::sync::Mutex<Vec<RejudgeRequest>>>;

/// A re-judge that answers `answer` and keeps every request.
fn fake(answer: RejudgeAnswer) -> (Arc<dyn Rejudge>, Asked) {
    let asked: Asked = Arc::default();
    let a = Arc::clone(&asked);
    let r: Arc<dyn Rejudge> = Arc::new(move |req: RejudgeRequest| {
        a.lock().unwrap().push(req);
        answer.clone()
    });
    (r, asked)
}

fn rule_deny(askable: bool) -> RejudgeAnswer {
    RejudgeAnswer::Deny {
        reason: "rm -rf / removes \"everything\"".into(),
        pack: Some("core.filesystem".into()),
        rule: Some("rm-root".into()),
        input: "rm -rf /".into(),
        askable,
    }
}

const RULE_DENY_REASON: &str = "rm -rf / removes \"everything\"";

fn my_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    saiife_daemon::grants::hex(&Sha256::digest(s.as_bytes()).into())
}

#[tokio::test]
async fn forged_allow_of_a_denied_call_is_denied() {
    let (rj, asked) = fake(rule_deny(false));
    let d = daemon_with(Some(Opts::default()), Some(rj)).await;
    let body = fixture("bash-deny.json");
    // A forger: begin, bind the key of the denied call, append an allow.
    let mut h = Client::hook(&d.sock, &body).await;
    h.verdict(DecisionKind::Allow, "rm -rf /").await;
    let a = post(d.addr.unwrap(), body.clone()).await;
    assert_eq!(
        a.body,
        r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"saiife: BLOCKED (fail closed): the saiife service's own judgment denies this call: rm -rf / removes \"everything\""}}"#
    );
    assert_eq!(a.body, cosign::rejudged_body(RULE_DENY_REASON));
    assert_eq!(a.header("content-type"), Some("application/json"));
    assert_eq!(asked.lock().unwrap().len(), 1);
    let got = wait_records(&d.audit, "rejudge_denied", 1).await;
    assert_eq!(got.len(), 1, "{got:?}");
    let r = &got[0];
    assert_eq!(r.kind(), "hook");
    assert_eq!(r.decision, DecisionKind::Deny);
    assert_eq!(r.agent, "claude");
    assert_eq!(r.tool, "Bash");
    assert_eq!(r.input, "rm -rf /");
    assert_eq!(r.session.as_deref(), Some("c-1"));
    assert_eq!(r.pack.as_deref(), Some("core.filesystem"));
    assert_eq!(r.rule.as_deref(), Some("rm-root"));
    assert_eq!(r.reason.as_deref(), Some(RULE_DENY_REASON));
    assert_eq!(r.uid, Some(my_uid()));
    assert_eq!(r.extra["tool_use_id"], "toolu_01");
    assert_eq!(r.extra["hook_pid"], std::process::id());
    assert!(records(&d.audit, "cosign_denied").is_empty());
    // One record per call (up to 60 a minute per principal).
    let mut h = Client::hook(&d.sock, &body).await;
    h.verdict(DecisionKind::Allow, "rm -rf /").await;
    let a = post(d.addr.unwrap(), body.clone()).await;
    assert_eq!(a.body, cosign::rejudged_body(RULE_DENY_REASON));
    assert_eq!(wait_records(&d.audit, "rejudge_denied", 2).await.len(), 2);
    let mut c = Client::hello(&d.sock).await;
    let st = c.call(OP_STATUS, json!({})).await;
    assert_eq!(st["hooks_rejudge_denied"]["since_start"], 2, "{st}");
    assert!(st["hooks_rejudge_denied"]["last_ts"].is_string(), "{st}");
}

#[tokio::test]
async fn honest_allow_still_gets_empty_200() {
    let (rj, asked) = fake(RejudgeAnswer::Allow);
    let d = daemon_with(Some(Opts::default()), Some(rj)).await;
    let body = fixture("bash-allow.json");
    let mut h = Client::hook(&d.sock, &body).await;
    h.verdict(DecisionKind::Allow, "ls -la").await;
    let a = post(d.addr.unwrap(), body.clone()).await;
    assert_no_opinion(&a);
    {
        let asked = asked.lock().unwrap();
        assert_eq!(asked.len(), 1);
        assert_eq!(
            asked[0].principal,
            saiife_daemon::hooks::Principal::Uid(my_uid())
        );
        assert!(asked[0].groups.is_empty());
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(records(&d.audit, "rejudge_denied").is_empty());
    assert!(records(&d.audit, "rejudge_failed").is_empty());
}

/// The residual, pinned: a forged allow of a call the policy allows anyway
/// is allowed, with no record.
#[tokio::test]
async fn forged_allow_of_an_allowed_call_is_allowed() {
    let d = daemon(Some(Opts::default())).await;
    let body = fixture("bash-allow.json");
    let mut forger = Client::hook(&d.sock, &body).await;
    forger.verdict(DecisionKind::Allow, "anything at all").await;
    assert_no_opinion(&post(d.addr.unwrap(), body).await);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(records(&d.audit, "rejudge_denied").is_empty());
    assert!(records(&d.audit, "cosign_denied").is_empty());
}

/// What a grant was given for: its agent, tool, project root and command.
#[derive(Clone, Copy)]
struct Scope<'a> {
    agent: &'a str,
    tool: &'a str,
    project: &'a str,
    command: &'a str,
}

/// The scope every approved call below is co-signed in: Claude Code's
/// `Bash` in `/p`.
const SCOPE: Scope = Scope {
    agent: "claude",
    tool: "Bash",
    project: "/p",
    command: "rm -rf /",
};

/// A Bash call of `command` run in `cwd`.
fn payload_in(tool_use_id: &str, command: &str, cwd: &str) -> String {
    let mut v: Value = serde_json::from_str(&payload(tool_use_id, command)).unwrap();
    v["cwd"] = cwd.into();
    v.to_string()
}

/// A hook connection that uses up a grant for `scope` (the record the hook
/// sends with `grant.consume` names it, as the hook would) and records the
/// call as `approved`.
async fn approved_hook(d: &Daemon, body: &str, scope: Scope<'_>, approval: u64) -> Client {
    let mut h = Client::hook(&d.sock, body).await;
    let sha = sha256_hex(scope.command);
    let raw: [u8; 32] = saiife_daemon::grants::unhex(&sha).unwrap();
    let key = saiife_daemon::grants::grant_key(
        my_uid(),
        scope.agent,
        scope.project,
        scope.tool,
        scope.command,
        &raw,
    );
    let far = std::time::SystemTime::now() + Duration::from_secs(3600);
    d.ctx.grants.insert(key, approval, far).unwrap();
    let mut asked = guard_rec(DecisionKind::Ask, scope.command);
    asked["agent"] = scope.agent.into();
    asked["tool"] = scope.tool.into();
    asked["project"] = scope.project.into();
    let a = h
        .call(
            saiife_ipc::msg::OP_GRANT_CONSUME,
            json!({"rec": asked, "raw_sha256": sha, "project": scope.project}),
        )
        .await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a["granted"], true, "{a}");
    let mut rec = guard_rec(DecisionKind::Approved, scope.command);
    rec["approval"] = approval.into();
    let a = h.call(OP_AUDIT_APPEND, json!({"rec": rec})).await;
    assert_eq!(a["ok"], true, "{a}");
    h
}

#[tokio::test]
async fn approved_call_passes_only_with_its_grant() {
    let (rj, _) = fake(rule_deny(true));
    let d = daemon_with(Some(Opts::default()), Some(rj)).await;
    let rejudged = cosign::rejudged_body(RULE_DENY_REASON);
    // A grant for this very call: allowed, at the root and below it.
    for (n, cwd) in [(1, "/p"), (2, "/p/sub")] {
        let body = payload_in(&format!("toolu_g{n}"), "rm -rf /", cwd);
        let _h = approved_hook(&d, &body, SCOPE, n).await;
        assert_no_opinion(&post(d.addr.unwrap(), body).await);
    }
    // A grant for another command: the service's deny stands.
    let body = payload_in("toolu_g3", "rm -rf /", "/p");
    let other = Scope {
        command: "rm -rf /tmp/x",
        ..SCOPE
    };
    let _h = approved_hook(&d, &body, other, 3).await;
    assert_eq!(post(d.addr.unwrap(), body).await.body, rejudged);
    // No grant at all.
    let body = payload_in("toolu_g4", "rm -rf /", "/p");
    let mut h = Client::hook(&d.sock, &body).await;
    h.verdict(DecisionKind::Allow, "rm -rf /").await;
    assert_eq!(post(d.addr.unwrap(), body).await.body, rejudged);
    assert_eq!(wait_records(&d.audit, "rejudge_denied", 2).await.len(), 2);
    // A grant does not lift a deny that is not only `ask` rules'.
    let (rj, _) = fake(rule_deny(false));
    d.ctx.cosign.lock().unwrap().rejudge = Some(rj);
    let body = payload_in("toolu_g5", "rm -rf /", "/p");
    let _h = approved_hook(&d, &body, SCOPE, 5).await;
    assert_eq!(post(d.addr.unwrap(), body).await.body, rejudged);
}

/// A grant is for one agent, tool and project: the same command in
/// another scope does not pass on it.
#[tokio::test]
async fn a_grant_passes_only_in_its_own_scope() {
    let (rj, _) = fake(rule_deny(true));
    let d = daemon_with(Some(Opts::default()), Some(rj)).await;
    let rejudged = cosign::rejudged_body(RULE_DENY_REASON);
    let tool = Scope {
        tool: "PowerShell",
        ..SCOPE
    };
    let agent = Scope {
        agent: "codex",
        ..SCOPE
    };
    let project = Scope {
        project: "/q",
        ..SCOPE
    };
    let cases = [
        (1, tool, "/p"),
        (2, agent, "/p"),
        (3, project, "/p"),
        // The grant's project, but the call runs outside it.
        (4, SCOPE, "/elsewhere"),
        (5, SCOPE, "/pq"),
    ];
    for (n, scope, cwd) in cases {
        let body = payload_in(&format!("toolu_s{n}"), "rm -rf /", cwd);
        let _h = approved_hook(&d, &body, scope, n).await;
        let a = post(d.addr.unwrap(), body).await;
        assert_eq!(a.body, rejudged, "case {n}");
    }
    // A body with no cwd names no project.
    let body = payload("toolu_s6", "rm -rf /");
    let _h = approved_hook(&d, &body, SCOPE, 6).await;
    assert_eq!(post(d.addr.unwrap(), body).await.body, rejudged);
    // The matching scope still passes.
    let body = payload_in("toolu_s7", "rm -rf /", "/p");
    let _h = approved_hook(&d, &body, SCOPE, 7).await;
    assert_no_opinion(&post(d.addr.unwrap(), body).await);
}

#[tokio::test]
async fn rejudge_failure_denies_and_records() {
    let (rj, _) = fake(RejudgeAnswer::Failed("the worker crashed".into()));
    let d = daemon_with(Some(Opts::default()), Some(rj)).await;
    let body = fixture("bash-allow.json");
    let mut h = Client::hook(&d.sock, &body).await;
    h.verdict(DecisionKind::Allow, "ls -la").await;
    assert_deny(
        &post(d.addr.unwrap(), body).await,
        CosignDeny::RejudgeFailed,
    );
    let got = wait_records(&d.audit, "rejudge_failed", 1).await;
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0].kind(), "hook");
    assert_eq!(got[0].decision, DecisionKind::ErrorDenied);
    assert_eq!(
        got[0].reason.as_deref(),
        Some(CosignDeny::RejudgeFailed.text())
    );
    assert_eq!(got[0].extra["error"], "the worker crashed");
    assert_eq!(got[0].extra["tool_use_id"], "toolu_02");
    assert!(records(&d.audit, "rejudge_denied").is_empty());
    assert!(records(&d.audit, "cosign_denied").is_empty());
}

/// A re-judge that does not answer by its deadline is a deny, at the
/// deadline (here the co-sign wait, shorter than `REJUDGE_TIMEOUT`).
#[tokio::test]
async fn rejudge_timeout_denies() {
    let rj: Arc<dyn Rejudge> = Arc::new(|_: RejudgeRequest| {
        std::thread::sleep(Duration::from_secs(3));
        RejudgeAnswer::Allow
    });
    let d = daemon_with(short(Duration::from_secs(1)), Some(rj)).await;
    let body = fixture("bash-allow.json");
    let mut h = Client::hook(&d.sock, &body).await;
    h.verdict(DecisionKind::Allow, "ls -la").await;
    let start = Instant::now();
    assert_deny(
        &post(d.addr.unwrap(), body).await,
        CosignDeny::RejudgeFailed,
    );
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(wait_records(&d.audit, "rejudge_failed", 1).await.len(), 1);
}

#[tokio::test]
async fn no_verdict_wins_over_a_running_rejudge() {
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let rx = std::sync::Mutex::new(rx);
    let rj: Arc<dyn Rejudge> = Arc::new(move |_: RejudgeRequest| {
        // Runs until the test has its answer.
        let _ = rx.lock().unwrap().recv_timeout(Duration::from_secs(20));
        RejudgeAnswer::Deny {
            reason: "x".into(),
            pack: None,
            rule: None,
            input: "ls".into(),
            askable: false,
        }
    });
    let d = daemon_with(Some(Opts::default()), Some(rj)).await;
    let body = payload("toolu_nv", "ls");
    let h = Client::hook(&d.sock, &body).await;
    let start = Instant::now();
    drop(h);
    assert_deny(&post(d.addr.unwrap(), body).await, CosignDeny::NoVerdict);
    assert!(start.elapsed() < RECONNECT_GRACE + Duration::from_secs(1));
    tx.send(()).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(records(&d.audit, "rejudge_denied").is_empty());
    assert!(records(&d.audit, "rejudge_failed").is_empty());
}

#[tokio::test]
async fn no_rejudge_configured_denies_everything() {
    let d = daemon_with(Some(Opts::default()), None).await;
    let body = fixture("bash-allow.json");
    let mut h = Client::hook(&d.sock, &body).await;
    h.verdict(DecisionKind::Allow, "ls -la").await;
    assert_deny(
        &post(d.addr.unwrap(), body).await,
        CosignDeny::RejudgeFailed,
    );
    let mut c = Client::hello(&d.sock).await;
    let st = c.call(OP_STATUS, json!({})).await;
    let rj = &st["cosign"]["rejudge"];
    assert_eq!(rj["workers"], 0, "{st}");
    assert_eq!(rj["state"], "unavailable", "{st}");
    assert_eq!(rj["error"], cosign::NO_REJUDGE, "{st}");
    assert_eq!(st["hooks_rejudge_denied"]["since_start"], 0, "{st}");
}

#[tokio::test]
async fn status_shows_the_rejudge_workers() {
    struct Two;
    impl Rejudge for Two {
        fn judge(&self, _: RejudgeRequest) -> RejudgeAnswer {
            RejudgeAnswer::Allow
        }
        fn workers(&self) -> usize {
            2
        }
    }
    let d = daemon_with(None, Some(Arc::new(Two))).await;
    let mut c = Client::hello(&d.sock).await;
    let st = c.call(OP_STATUS, json!({})).await;
    let rj = &st["cosign"]["rejudge"];
    assert_eq!(rj["workers"], 2, "{st}");
    assert_eq!(rj["state"], "ready", "{st}");
    assert_eq!(rj["error"], Value::Null, "{st}");
}

/// The forged append's record says `ls`; the body says something else:
/// the service judges the body, exactly as it arrived.
#[tokio::test]
async fn rejudge_sees_the_body_not_the_record() {
    let (rj, asked) = fake(RejudgeAnswer::Allow);
    let d = daemon_with(Some(Opts::default()), Some(rj)).await;
    let body = serde_json::to_string_pretty(
        &serde_json::from_str::<Value>(&payload("toolu_b", "type secrets.env")).unwrap(),
    )
    .unwrap();
    let mut h = Client::hook(&d.sock, &body).await;
    h.verdict(DecisionKind::Allow, "ls").await;
    assert_no_opinion(&post(d.addr.unwrap(), body.clone()).await);
    let asked = asked.lock().unwrap();
    assert_eq!(asked.len(), 1);
    assert_eq!(&asked[0].payload[..], body.as_bytes());
}
