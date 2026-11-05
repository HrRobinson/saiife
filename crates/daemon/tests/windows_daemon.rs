//! The real daemon on Windows, end to end in tempdirs as the runner, outside the service
//! manager (plan 19b, Task 5). A debug-build test pipe `\\.\pipe\saiife-test-<random>`,
//! owned by the runner's SID, stands in for W11's. These run in CI's `test` job only: no
//! Windows machine builds this crate locally.
#![cfg(windows)]

use saiife_daemon::{run_controlled, DaemonMode, DaemonOptions};
use saiife_ipc::client::Client;
use saiife_policy::{Directory, WinDirectory};
use saiife_win::ffi::pipe::{create_server, open_client};
use saiife_win::ffi::service::{Control, ServiceCtl};
use saiife_win::ffi::{account, acl, token};
use saiife_win::pipe::control_sddl;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::Sender;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

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

/// W11's review focus: the name is taken, so the daemon says so and exits 1, and a client
/// of the real owner gets nothing from the squatter.
#[tokio::test]
async fn daemon_refuses_existing_pipe() {
    let t = tree();
    let pipe = pipe_name("squat");
    // The test is the squatter, with its own SID as owner.
    let me = me();
    let _squat = create_server(&pipe, &control_sddl(&me), true).unwrap();
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

/// What the loopback listener answers `GET /v1/services` with (W13).
fn services_status(addr: std::net::SocketAddr, token: Option<&str>) -> String {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    write!(
        s,
        "GET /v1/services HTTP/1.1\r\nHost: 127.0.0.1\r\n{auth}Connection: close\r\n\r\n"
    )
    .unwrap();
    let mut got = String::new();
    s.read_to_string(&mut got).unwrap();
    got.lines().next().unwrap_or_default().to_string()
}

/// W13: on Windows the gateway is loopback TCP and the bearer token, whose SID is what a
/// call runs as. A token comes through the pipe; without one nothing is answered.
#[test]
fn the_gateway_goes_by_the_token_over_tcp() {
    let t = tree();
    let pipe = pipe_name("tcp");
    let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = free.local_addr().unwrap();
    drop(free);
    let user = account::lookup_sid(&me()).unwrap();
    let text = std::fs::read_to_string(&t.config).unwrap();
    std::fs::write(
        &t.config,
        format!(
            "{text}[gateway]\ntcp = \"{addr}\"\n[[scope]]\nname = \"s\"\nusers = [{user:?}]\nservices = []\n"
        ),
    )
    .unwrap();
    let (tx, join) = start(&t, &pipe);
    let mut c = connect(&pipe);
    let answer = call(&mut c, "api.token", serde_json::json!({}));
    let token = answer["token"].as_str().unwrap().to_string();

    assert!(services_status(addr, None).contains(" 401"));
    assert!(services_status(addr, Some("wrong")).contains(" 401"));
    assert!(services_status(addr, Some(&token)).contains(" 200"));

    tx.send(Control::Stop).unwrap();
    assert_eq!(join.join().unwrap(), 0);
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
        assert!(answer.is_err());
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
