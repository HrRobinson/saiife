//! The Claude Code co-signer over loopback (plan 20, Task 4), against a
//! daemon context whose hooks talk over the real control socket. Raw
//! HTTP/1.1 on a TCP stream, so every byte of the answer is seen.
#![cfg(unix)]

use saiife_audit::{ChainWriter, DecisionKind, NewRecord, Record, WriterOptions};
use saiife_daemon::cosign::{self, deny_body, CosignDeny, Opts, Retry};
use saiife_daemon::hooks::RECONNECT_GRACE;
use saiife_daemon::ops::{Ctx, CtxInit};
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
/// on a free loopback port with `opts`.
async fn daemon(opts: Option<Opts>) -> Daemon {
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
