//! The real daemon on Windows, end to end in tempdirs as the runner, outside the service
//! manager (plan 19b, Task 5). A debug-build test pipe `\\.\pipe\saiife-test-<random>`,
//! owned by the runner's SID, stands in for W11's. These run in CI's `test` job only: no
//! Windows machine builds this crate locally.
#![cfg(windows)]

use saiife_daemon::approvals::{self, ApprovalType, NewRequest, State, Store};
use saiife_daemon::{run_controlled, DaemonMode, DaemonOptions};
use saiife_ipc::client::{Client, ClientError};
use saiife_ipc::msg::ErrorCode;
use saiife_policy::{Directory, WinDirectory};
use saiife_win::ffi::pipe::{create_server, open_client};
use saiife_win::ffi::service::{Control, ServiceCtl};
use saiife_win::ffi::{account, acl, token};
use saiife_win::pipe::control_sddl;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::Sender;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const FORCE_PUSH: &str = "git push --force origin main";

fn me() -> String {
    token::current().unwrap().sid
}

fn pipe_name(test: &str) -> String {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    format!(r"\\.\pipe\saiife-test-{}-{n}-{test}", std::process::id())
}

/// A state tree only the runner and the system's accounts can use, as W14 gives the
/// service its own. The runner's temp dir has an ACL of its own that this does not trust.
struct Tree {
    _root: tempfile::TempDir,
    state: PathBuf,
    config: PathBuf,
    audit: PathBuf,
}

fn tree() -> Tree {
    let base = std::env::var_os("RUNNER_TEMP")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let root = tempfile::tempdir_in(base).unwrap();
    let me = me();
    let sddl = format!("O:{me}D:PAI(A;OICI;FA;;;{me})(A;OICI;FA;;;SY)");
    let top = root.path().join("t");
    acl::create_dir_with_sddl(&top, &sddl).unwrap();
    let state = top.join("state");
    let audit = top.join("audit");
    for d in [&state, &audit] {
        std::fs::create_dir(d).unwrap();
    }
    let user = account::lookup_sid(&me).unwrap();
    let config = top.join("config.toml");
    let text = format!(
        "version = 2\nlocked = true\n[daemon]\nuser = {user:?}\n[audit]\ndir = {:?}\nmin_free_mb = 0\n",
        audit.display().to_string()
    );
    std::fs::write(&config, text).unwrap();
    Tree {
        _root: root,
        state,
        config,
        audit,
    }
}

fn options(t: &Tree, pipe: &str) -> DaemonOptions {
    DaemonOptions {
        config: t.config.clone(),
        state_dir: t.state.clone(),
        catalog: Vec::new(),
        directory: Box::new(WinDirectory::system()),
        credentials_dir: None,
        mode: DaemonMode::System,
        test_pipe: Some(pipe.to_string()),
    }
}

fn start(t: &Tree, pipe: &str) -> (Sender<Control>, JoinHandle<i32>) {
    let (tx, ctl) = ServiceCtl::detached();
    let opts = options(t, pipe);
    let daemon = std::thread::spawn(move || run_controlled(opts, ctl));
    (tx, daemon)
}

/// Connects once the daemon's first instance is there, with the owner checked.
fn connect(pipe: &str) -> Client {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let per_try = Instant::now() + Duration::from_secs(2);
        match Client::connect_pipe(pipe, &me(), per_try) {
            Ok(c) => return c,
            Err(e) if Instant::now() > deadline => panic!("no daemon on {pipe}: {e}"),
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

fn audit_text(dir: &Path) -> String {
    let mut all = String::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "jsonl") {
            all.push_str(&std::fs::read_to_string(p).unwrap());
        }
    }
    all
}

/// A pending command request of the runner's, created long ago with a minute to live.
fn an_expired_request(t: &Tree) -> u64 {
    let store = Store::open(&approvals::dir_in(&t.state)).unwrap();
    let new = NewRequest {
        uid: 0,
        sid: Some(me()),
        user: "runner".into(),
        session: None,
        agent: "claude".into(),
        project: r"\\?\C:\w".into(),
        kind: ApprovalType::Command,
        service: None,
        operation: None,
        capability: None,
        params: Default::default(),
        input: Some(FORCE_PUSH.into()),
        grant_key: None,
        scope: None,
        ask_rule: None,
        send: Default::default(),
    };
    let long_ago = std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    store
        .create(new, |_| Ok(None), Duration::from_secs(60), long_ago)
        .unwrap()
        .id
}

/// Every file of the approval store, by name, with its bytes.
fn approval_files(t: &Tree) -> Vec<(std::ffi::OsString, Vec<u8>)> {
    let mut all: Vec<_> = std::fs::read_dir(approvals::dir_in(&t.state))
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (e.file_name(), std::fs::read(e.path()).unwrap())
        })
        .collect();
    all.sort();
    all
}

/// W11's review focus: the name is taken, so the daemon says so and exits 1, and a client
/// of the real owner gets nothing from the squatter.
#[tokio::test]
async fn daemon_refuses_existing_pipe() {
    let t = tree();
    let pipe = pipe_name("squat");
    // The test is the squatter, with its own SID as owner.
    let me = me();
    let _squat = create_server(&pipe, &control_sddl(&me), true).unwrap();
    // A request whose expiry has passed: a start that got this far would expire it.
    let rid = an_expired_request(&t);
    let before = approval_files(&t);
    let opts = options(&t, &pipe);
    let (_tx, ctl) = ServiceCtl::detached();
    let code = std::thread::spawn(move || run_controlled(opts, ctl))
        .join()
        .unwrap();
    assert_eq!(code, 1);
    // The restarts every second must not grow the log: nothing is written before the name
    // is ours.
    let text = audit_text(&t.audit);
    assert!(!text.contains("\"start\""), "{text}");
    // Nor is any approval state changed: its `expired` record could not follow.
    assert_eq!(approval_files(&t), before);
    let store = Store::open(&approvals::dir_in(&t.state)).unwrap();
    assert_eq!(store.get(rid).unwrap().state, State::Pending);
    // W11's line is `create_server`'s text, checked in saiife-win; the log is
    // `service_log`'s. Stderr is one per process, so it is not read here.
    // The name is still held, and open_client still opens it: only the owner check,
    // client side, tells them apart. It is covered in saiife-ipc.
    open_client(&pipe).unwrap();
}

/// Starts, answers a hello, stops on the service manager's stop with a clean exit, and
/// the stop record is on file.
#[test]
fn daemon_serves_the_pipe_and_stops_cleanly() {
    let t = tree();
    let pipe = pipe_name("serve");
    let (tx, daemon) = start(&t, &pipe);
    let client = connect(&pipe);
    drop(client);
    tx.send(Control::Stop).unwrap();
    assert_eq!(daemon.join().unwrap(), 0);
    let text = audit_text(&t.audit);
    assert!(text.contains("\"start\""), "{text}");
    assert!(text.contains("\"stop\""), "{text}");
}

/// A reload from the service manager keeps the daemon serving.
#[test]
fn reload_control_keeps_serving() {
    let t = tree();
    let pipe = pipe_name("reload");
    let (tx, daemon) = start(&t, &pipe);
    drop(connect(&pipe));
    tx.send(Control::Reload).unwrap();
    drop(connect(&pipe));
    tx.send(Control::Stop).unwrap();
    assert_eq!(daemon.join().unwrap(), 0);
}

/// Instances keep coming: more clients one after another than one instance could serve.
#[test]
fn one_free_instance_stays_ahead() {
    let t = tree();
    let pipe = pipe_name("ahead");
    let (tx, daemon) = start(&t, &pipe);
    let held: Vec<Client> = (0..8).map(|_| connect(&pipe)).collect();
    drop(held);
    drop(connect(&pipe));
    tx.send(Control::Stop).unwrap();
    assert_eq!(daemon.join().unwrap(), 0);
}

/// `[daemon] user` names someone else: refused before anything is created.
#[test]
fn another_daemon_user_is_refused() {
    let t = tree();
    let pipe = pipe_name("user");
    let text = std::fs::read_to_string(&t.config).unwrap();
    let user = account::lookup_sid(&me()).unwrap();
    std::fs::write(
        &t.config,
        text.replace(&format!("{user:?}"), "\"NT AUTHORITY\\\\NETWORK SERVICE\""),
    )
    .unwrap();
    let (_tx, ctl) = ServiceCtl::detached();
    let opts = options(&t, &pipe);
    let code = std::thread::spawn(move || run_controlled(opts, ctl))
        .join()
        .unwrap();
    assert_eq!(code, 2);
}

/// What a real directory says of the runner: the label is not 0, and the SID is known.
#[test]
fn the_runner_resolves_through_the_directory() {
    let me = me();
    let user = account::lookup_sid(&me).unwrap();
    let dir = WinDirectory::system();
    assert_eq!(dir.sid_of(&user).as_deref(), Some(me.as_str()));
    assert_eq!(dir.name_of_sid(&me).as_deref(), Some(user.as_str()));
}

/// The tree's config with the loopback listener on a free port, a scope for the runner and
/// `extra` (any earlier `[gateway]` and what followed it are replaced).
fn with_tcp(t: &Tree, extra: &str) -> std::net::SocketAddr {
    let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = free.local_addr().unwrap();
    drop(free);
    let user = account::lookup_sid(&me()).unwrap();
    let text = std::fs::read_to_string(&t.config).unwrap();
    let base = text.split("[gateway]").next().unwrap();
    std::fs::write(
        &t.config,
        format!(
            "{base}[gateway]\ntcp = \"{addr}\"\n[[scope]]\nname = \"s\"\nusers = [{user:?}]\nservices = []\n{extra}"
        ),
    )
    .unwrap();
    addr
}

/// One HTTP/1.1 exchange with the loopback listener (W13): the status, the headers (names
/// in lower case) and the body.
fn http(
    addr: std::net::SocketAddr,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let mut head = format!(
        "{method} {uri} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (n, v) in headers {
        head.push_str(&format!("{n}: {v}\r\n"));
    }
    head.push_str("\r\n");
    s.write_all(head.as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut got = Vec::new();
    s.read_to_end(&mut got).unwrap();
    let end = got
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("no response head: {}", String::from_utf8_lossy(&got)));
    let text = String::from_utf8_lossy(&got[..end]).to_string();
    let mut lines = text.lines();
    let status = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("no status line: {text}"));
    let hs: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let rest = &got[end + 4..];
    let chunked = hs
        .iter()
        .any(|(n, v)| n == "transfer-encoding" && v.eq_ignore_ascii_case("chunked"));
    let body = if chunked {
        dechunk(rest)
    } else {
        rest.to_vec()
    };
    (status, hs, body)
}

/// A chunked body, joined.
fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let eol = b
            .windows(2)
            .position(|w| w == b"\r\n")
            .expect("a chunk size line");
        let line = String::from_utf8_lossy(&b[..eol]).to_string();
        let size = usize::from_str_radix(line.split(';').next().unwrap().trim(), 16).unwrap();
        b = &b[eol + 2..];
        if size == 0 {
            return out;
        }
        out.extend_from_slice(&b[..size]);
        b = &b[size + 2..];
    }
}

fn header<'a>(hs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    hs.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
}

/// A token for the runner, through the pipe.
fn token_of(c: &mut Client) -> String {
    call(c, "api.token", json!({}))["token"]
        .as_str()
        .unwrap()
        .to_string()
}

/// The records of `kind` in the audit dir, in order.
fn records(dir: &Path, kind: &str) -> Vec<Value> {
    audit_text(dir)
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|r| r["kind"] == kind)
        .collect()
}

/// W13: on Windows the gateway is loopback TCP and the bearer token, whose SID is what a
/// call runs as. A token comes through the pipe; without one nothing is answered.
#[test]
fn the_gateway_goes_by_the_token_over_tcp() {
    let t = tree();
    let pipe = pipe_name("tcp");
    let addr = with_tcp(&t, "");
    let (tx, join) = start(&t, &pipe);
    let mut c = connect(&pipe);
    let token = token_of(&mut c);
    let bearer = format!("Bearer {token}");

    assert_eq!(http(addr, "GET", "/v1/services", &[], b"").0, 401);
    let wrong = [("authorization", "Bearer wrong")];
    assert_eq!(http(addr, "GET", "/v1/services", &wrong, b"").0, 401);
    let good = [("authorization", bearer.as_str())];
    assert_eq!(http(addr, "GET", "/v1/services", &good, b"").0, 200);

    tx.send(Control::Stop).unwrap();
    assert_eq!(join.join().unwrap(), 0);
}

/// gateway.rs's 401 matrix (Unix only) on the real daemon: every route answers 401 with the
/// same body and `WWW-Authenticate: Bearer` unless the request carries exactly one live token
/// as `Bearer`. Nothing is sent and nothing is recorded as a connector call.
#[test]
fn the_tcp_listener_answers_401_without_one_good_token() {
    let t = tree();
    let pipe = pipe_name("tcp-401");
    let addr = with_tcp(&t, "");
    let (tx, join) = start(&t, &pipe);
    let mut c = connect(&pipe);
    let tok = token_of(&mut c);
    let wrong = format!("Bearer {}", tok.replace("saiife_gw_", "saiife_gw_x"));
    let basic = format!("Basic {tok}");
    let bare = tok.clone();
    let cases: Vec<Vec<(&str, &str)>> = vec![
        vec![],
        vec![("authorization", wrong.as_str())],
        vec![("authorization", basic.as_str())],
        vec![("authorization", bare.as_str())],
        vec![("authorization", "Bearer ")],
        // Who the agent says it is never counts.
        vec![("x-forwarded-user", "runner")],
    ];
    for hdrs in &cases {
        for (m, uri, body) in [
            ("GET", "/v1/services", &b""[..]),
            ("POST", "/v1/api/shop/orders.list", &b"{}"[..]),
            ("GET", "/v1/proxy/shop/orders.json", &b""[..]),
        ] {
            let (st, h, b) = http(addr, m, uri, hdrs, body);
            assert_eq!(st, 401, "{hdrs:?} {uri}");
            assert_eq!(
                serde_json::from_slice::<Value>(&b).unwrap(),
                json!({"error": "token"}),
                "{hdrs:?} {uri}"
            );
            assert_eq!(header(&h, "www-authenticate"), Some("Bearer"), "{h:?}");
        }
    }
    // Two Authorization headers, one good: refused.
    let good = format!("Bearer {tok}");
    let two = [
        ("authorization", good.as_str()),
        ("authorization", "Bearer x"),
    ];
    assert_eq!(http(addr, "GET", "/v1/services", &two, b"").0, 401);
    tx.send(Control::Stop).unwrap();
    assert_eq!(join.join().unwrap(), 0);
    assert!(records(&t.audit, "connector").is_empty());
}

/// gateway.rs's `token_maps_to_uid` on Windows: a call over TCP runs as the token's SID, and
/// its record says it came by token from a loopback address. The issue is in the log; the
/// token is not.
#[test]
fn a_tcp_call_is_recorded_with_its_peer() {
    let t = tree();
    let pipe = pipe_name("tcp-peer");
    let addr = with_tcp(&t, "");
    let (tx, join) = start(&t, &pipe);
    let mut c = connect(&pipe);
    let tok = token_of(&mut c);
    let bearer = format!("Bearer {tok}");
    // No such service: denied, and recorded all the same.
    let (st, _, b) = http(
        addr,
        "POST",
        "/v1/api/shop/orders.list",
        &[("authorization", bearer.as_str())],
        br#"{"params":{"status":"open"}}"#,
    );
    assert_ne!(st, 401, "{}", String::from_utf8_lossy(&b));
    tx.send(Control::Stop).unwrap();
    assert_eq!(join.join().unwrap(), 0);
    let recs = records(&t.audit, "connector");
    assert_eq!(recs.len(), 1, "{recs:?}");
    assert_eq!(recs[0]["sid"], me());
    assert_eq!(recs[0]["via"], "http");
    assert_eq!(recs[0]["peer"]["auth"], "token");
    let from = recs[0]["peer"]["tcp"].as_str().unwrap();
    assert!(from.starts_with("127.0.0.1:"), "{from}");
    let issued: Vec<Value> = audit_text(&t.audit)
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|r| r["event"] == "gateway_token")
        .collect();
    assert_eq!(issued.len(), 1);
    assert_eq!(issued[0]["token_sid"], me());
    assert!(!audit_text(&t.audit).contains(&tok["saiife_gw_".len()..]));
}

/// gateway.rs's `expired_token_401` on the real daemon, without its clock: a token kept
/// across a restart still works, and the same token with an expiry that has passed (as the
/// file says, edited between runs) is a 401 and gone from the file.
#[test]
fn an_expired_token_is_refused_after_a_restart() {
    let t = tree();
    let services = |addr, bearer: &str| {
        http(
            addr,
            "GET",
            "/v1/services",
            &[("authorization", bearer)],
            b"",
        )
    };

    // Issued, and good.
    let addr = with_tcp(&t, "");
    let pipe = pipe_name("expiry-1");
    let (tx, join) = start(&t, &pipe);
    let tok = token_of(&mut connect(&pipe));
    let bearer = format!("Bearer {tok}");
    assert_eq!(services(addr, &bearer).0, 200);
    tx.send(Control::Stop).unwrap();
    assert_eq!(join.join().unwrap(), 0);

    // Kept across a restart: the 401 below is the expiry, not a lost file.
    let addr = with_tcp(&t, "");
    let pipe = pipe_name("expiry-2");
    let (tx, join) = start(&t, &pipe);
    drop(connect(&pipe));
    assert_eq!(services(addr, &bearer).0, 200);
    tx.send(Control::Stop).unwrap();
    assert_eq!(join.join().unwrap(), 0);

    // The file's expiry moved into the past.
    let path = saiife_daemon::tokens::path_in(&t.state);
    let mut stored: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let entries = stored["tokens"].as_array_mut().unwrap();
    assert_eq!(entries.len(), 1, "{entries:?}");
    entries[0]["expires"] = json!(1);
    std::fs::write(&path, serde_json::to_vec(&stored).unwrap()).unwrap();

    let addr = with_tcp(&t, "");
    let pipe = pipe_name("expiry-3");
    let (tx, join) = start(&t, &pipe);
    drop(connect(&pipe));
    let (st, h, b) = services(addr, &bearer);
    assert_eq!(st, 401);
    assert_eq!(
        serde_json::from_slice::<Value>(&b).unwrap(),
        json!({"error": "token"})
    );
    assert_eq!(header(&h, "www-authenticate"), Some("Bearer"), "{h:?}");
    tx.send(Control::Stop).unwrap();
    assert_eq!(join.join().unwrap(), 0);
    // The start dropped it from the file.
    let stored: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(stored["tokens"], json!([]), "{stored}");
}

/// The rule of `[guard] ask` that `approval.create` takes the call under.
const ASK: &str = "[guard]\nask = [\"core.git/force-push\"]\n";

/// What the hook sends with `approval.create` for `FORCE_PUSH`, as `std::fs::canonicalize`
/// spells Windows paths: the cwd `\\?\C:\w\sub` in the project root `\\?\C:\w`. The daemon
/// checks them lexically (no file needs to exist).
fn create_args() -> Value {
    use sha2::Digest;
    let raw: [u8; 32] = sha2::Sha256::digest(FORCE_PUSH.as_bytes()).into();
    let rec = json!({
        "v": 1, "ts": "2026-11-06T00:00:00.000Z", "kind": "guard", "agent": "claude",
        "project": r"\\?\C:\w\sub", "tool": "Bash", "input": FORCE_PUSH, "decision": "deny",
        "pack": "core.git", "rule_id": "force-push", "mode": "locked",
    });
    json!({
        "rec": rec,
        "raw_sha256": saiife_daemon::grants::hex(&raw),
        "project": r"\\?\C:\w",
    })
}

/// §6.10's withdraw, end to end over the pipe: the runner asks, then rejects its own
/// request. No approver and no re-authentication are needed (same-user approval is off on
/// Windows, W16; a withdraw lets nothing through). The request is rejected with the
/// requester's note, and the record names the runner's SID as requester and as decider.
/// That another SID with the same label cannot withdraw it is `approval_ops`'s
/// `another_sid_with_the_same_label_cannot_withdraw`.
#[test]
fn the_requester_withdraws_its_own_request() {
    let t = tree();
    let pipe = pipe_name("withdraw");
    with_tcp(&t, ASK);
    let (tx, join) = start(&t, &pipe);
    let mut c = connect(&pipe);
    let made = call(&mut c, "approval.create", create_args());
    let rid = made["request"].as_u64().unwrap();
    let done = call(
        &mut c,
        "approval.decide",
        json!({"request": rid, "action": "reject"}),
    );
    assert_eq!(done["state"], "rejected", "{done:?}");
    tx.send(Control::Stop).unwrap();
    assert_eq!(join.join().unwrap(), 0);

    let store = Store::open(&approvals::dir_in(&t.state)).unwrap();
    let r = store.get(rid).unwrap();
    assert_eq!(r.state, State::Rejected);
    assert_eq!(
        r.note.as_deref(),
        Some(saiife_daemon::approval_ops::CANCELLED)
    );
    assert_eq!(r.sid.as_deref(), Some(me().as_str()));
    assert_eq!(r.decided_by_sid.as_deref(), Some(me().as_str()));
    let rejected: Vec<Value> = records(&t.audit, "approval")
        .into_iter()
        .filter(|r| r["action"] == "rejected" && r["id"] == rid)
        .collect();
    assert_eq!(rejected.len(), 1, "{rejected:?}");
    assert_eq!(rejected[0]["sid"], me());
    assert_eq!(rejected[0]["by_sid"], me());
    assert_eq!(rejected[0]["note"], saiife_daemon::approval_ops::CANCELLED);
}

fn call(
    c: &mut Client,
    op: &str,
    args: serde_json::Value,
) -> serde_json::Map<String, serde_json::Value> {
    let deadline = Instant::now() + Duration::from_secs(30);
    c.call(op, args.as_object().unwrap().clone(), deadline)
        .unwrap()
}

/// The record's `sid` is the peer's token, whatever the client's record says.
#[test]
fn audit_append_carries_the_sid() {
    let t = tree();
    let pipe = pipe_name("append");
    let (tx, join) = start(&t, &pipe);
    let mut c = connect(&pipe);
    let mut rec = serde_json::to_value(saiife_audit::Record::new(
        saiife_audit::NewRecord {
            agent: "claude",
            project: "C:\\p",
            session: None,
            tool: "Bash",
            input: "git status",
            decision: saiife_audit::DecisionKind::Allow,
            pack: None,
            rule: None,
            reason: None,
            mode: "locked",
            policy: Some("x"),
            permission_mode: None,
        },
        "0",
    ))
    .unwrap();
    let fields = rec.as_object_mut().unwrap();
    fields.remove("ts");
    fields.insert("sid".into(), "S-1-5-21-9-9-9-9".into());
    call(&mut c, "audit.append", serde_json::json!({ "rec": rec }));
    tx.send(Control::Stop).unwrap();
    assert_eq!(join.join().unwrap(), 0);
    let text = audit_text(&t.audit);
    assert!(text.contains(&me()), "{text}");
    assert!(!text.contains("S-1-5-21-9-9-9-9"), "{text}");
}

/// `policy.reload` from an elevated admin; a runner that isn't elevated gets a refusal.
#[test]
fn policy_reload_goes_by_the_token() {
    let t = tree();
    let pipe = pipe_name("reload-op");
    let (tx, join) = start(&t, &pipe);
    let mut c = connect(&pipe);
    let deadline = Instant::now() + Duration::from_secs(30);
    let answer = c.call("policy.reload", serde_json::Map::new(), deadline);
    if token::current().unwrap().elevated_admin {
        answer.unwrap();
    } else {
        match answer {
            Err(ClientError::Refused { code, message }) => {
                assert_eq!(code, ErrorCode::Forbidden.as_str());
                assert_eq!(message, "policy.reload is for root and [admin] groups");
            }
            other => panic!("expected the admin refusal, got {other:?}"),
        }
    }
    tx.send(Control::Stop).unwrap();
    assert_eq!(join.join().unwrap(), 0);
}

/// The start record opens this month's file, in the audit dir, where it can be listed.
#[test]
fn the_start_opens_a_month_file() {
    let t = tree();
    let pipe = pipe_name("month");
    let (tx, join) = start(&t, &pipe);
    tx.send(Control::Stop).unwrap();
    assert_eq!(join.join().unwrap(), 0);
    let months = std::fs::read_dir(&t.audit)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|x| x == "jsonl"))
        .count();
    assert_eq!(months, 1);
}

/// A second daemon run on the same tree reads what the first wrote: the chain's ACL check on
/// real inherited descriptors passes both times.
#[test]
fn a_restart_keeps_the_chain() {
    let t = tree();
    for name in ["chain-1", "chain-2"] {
        let pipe = pipe_name(name);
        let (tx, join) = start(&t, &pipe);
        let _ = connect(&pipe);
        tx.send(Control::Stop).unwrap();
        assert_eq!(join.join().unwrap(), 0);
    }
    assert_eq!(audit_text(&t.audit).matches("\"stop\"").count(), 2);
}
