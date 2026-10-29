//! The MCP gateway supervisor (plan 17, Task 6), against
//! `saiife __fake-mcp-server` spawned through `saiife __mcp-spawn`.
//!
//! Two harnesses:
//! - a real `saiife daemon --system` (`TestDaemon`) for the lifecycle,
//!   records, status, reload, stop and the socket peer refusals;
//! - an in-process daemon context with its own `Gateway` for what needs a
//!   `tools/call` (Task 7 adds the op that calls it from a client), with
//!   the gateway's journal lines captured.
//!
//! The fake runs as `/usr/bin/env <saiife> __fake-mcp-server …`: the
//! command must have a root-owned chain, and `/usr/bin/env` does; the test
//! binary's dir is a `read_paths` entry so the sandboxed child may exec
//! it. On a kernel without Landlock the servers run with
//! `sandbox = "off"` (the sandbox itself is Task 5's tests).
#![cfg(target_os = "linux")]

mod common;

use common::daemon::{own_group, own_uid, own_user, wait_for, Opts, TestDaemon};
use saiife_audit::{ChainWriter, WriterOptions};
use saiife_daemon::mcp_gateway::{ChildError, Gateway, GatewaySetup, Log, ToolCaller};
use saiife_daemon::ops::{Ctx, CtxInit, Mode};
use saiife_daemon::vault::{self, Entry, Kind, VaultState};
use saiife_daemon::writer::{self, WriterConfig};
use saiife_policy::{FixedDirectory, Fsync};
use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const BIN: &str = env!("CARGO_BIN_EXE_saiife");
const ENV: &str = "/usr/bin/env";
const BASH: &str = "/usr/bin/bash";
/// A test token, built at run time (no token-shaped literal in the tree).
fn token() -> String {
    concat!("mcp", "-tok-", "a1b2c3d4e5f6").to_string()
}

fn bin_dir() -> String {
    Path::new(BIN).parent().unwrap().display().to_string()
}

fn sandbox_line() -> &'static str {
    if saiife_system::sandbox::landlock_abi() == 0 {
        eprintln!("note: no Landlock on this kernel; the gateway tests run with sandbox = \"off\"");
        "sandbox = \"off\"\n"
    } else {
        ""
    }
}

fn root_owned(p: &str) -> bool {
    saiife_system::fsops::root_owned_chain(Path::new(p)).is_ok()
}

/// The fake's command `/usr/bin/env` passes the gateway's root-owned
/// check. Not in `scripts/test-offline.sh`'s nested user namespace, which
/// maps only the current user (root's files show as the overflow uid):
/// there every test that starts a server is skipped with a note.
fn env_runnable() -> bool {
    let ok = root_owned(ENV);
    if !ok {
        eprintln!("skipped: {ENV} is not root-owned here");
    }
    ok
}

/// `[mcp.<name>]` running the fake with `fake_args`.
fn server(name: &str, fake_args: &[&str], extra: &str) -> String {
    let mut args = vec![BIN.to_string(), "__fake-mcp-server".to_string()];
    args.extend(fake_args.iter().map(|s| s.to_string()));
    format!(
        "[mcp.{name}]\ncommand = {ENV:?}\nargs = {args:?}\nread_paths = [{:?}]\n{}{extra}\n",
        bin_dir(),
        sandbox_line()
    )
}

fn admin() -> String {
    format!("[admin]\ngroups = [{:?}]\n\n", own_group())
}

fn records_in(audit: &Path) -> Vec<Value> {
    let Ok(rd) = fs::read_dir(audit) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = rd
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
        .collect();
    files.sort();
    let mut out = Vec::new();
    for f in files {
        let text = fs::read_to_string(f).unwrap();
        for l in text.split_inclusive('\n').filter(|l| l.ends_with('\n')) {
            out.push(serde_json::from_str(l).unwrap());
        }
    }
    out
}

fn events_of(recs: &[Value], event: &str, srv: &str) -> Vec<Value> {
    recs.iter()
        .filter(|r| r["kind"] == "daemon" && r["event"] == event && r["server"] == srv)
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------
// The real daemon.

fn daemon(extra: &str) -> TestDaemon {
    TestDaemon::start(Opts {
        extra: extra.to_string(),
        ..Opts::default()
    })
}

fn wait_event(d: &TestDaemon, event: &str, srv: &str, n: usize) -> Vec<Value> {
    let ok = wait_for(Duration::from_secs(30), || {
        events_of(&d.records(), event, srv).len() >= n
    });
    assert!(
        ok,
        "no {n} {event} record(s) for {srv}: {:#?}\nstderr: {}",
        d.of_kind("daemon"),
        d.stderr_text()
    );
    events_of(&d.records(), event, srv)
}

fn mcp_status(d: &TestDaemon) -> Vec<Value> {
    d.status()["mcp"].as_array().cloned().unwrap_or_default()
}

fn status_of(d: &TestDaemon, srv: &str) -> Value {
    mcp_status(d)
        .into_iter()
        .find(|s| s["name"] == srv)
        .unwrap_or(Value::Null)
}

fn cli(d: &TestDaemon) -> Command {
    let mut c = Command::new(BIN);
    c.env("HOME", d.path().join("home"))
        .env("XDG_RUNTIME_DIR", d.path().join("no-runtime"))
        .env("PATH", "/usr/bin:/bin")
        .env("SAIIFE_DATA_DIR", d.path().join("data"))
        .env("SAIIFE_AUDIT_DIR", d.audit_dir())
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
        .stdin(Stdio::null());
    c
}

fn add_secret(d: &TestDaemon, name: &str, value: &str, services: &[&str]) -> Output {
    let mut c = cli(d);
    c.arg("secret")
        .arg("--system-config")
        .arg(d.config())
        .args(["add", name, "--kind", "token", "--from-env", "SV"])
        .env("SV", value);
    for s in services {
        c.args(["--service", s]);
    }
    c.output().unwrap()
}

fn reload(d: &TestDaemon, extra: &str) {
    let n = d.of_kind("policy").len();
    d.write_config(&Opts {
        extra: extra.to_string(),
        ..Opts::default()
    });
    d.signal("HUP");
    let ok = wait_for(Duration::from_secs(15), || d.of_kind("policy").len() > n);
    assert!(ok, "no policy record after the reload: {}", d.stderr_text());
}

#[test]
fn starts_initializes_and_caches_tools() {
    if !env_runnable() {
        return;
    }
    let d = daemon(&server("fake", &[], ""));
    let started = wait_event(&d, "mcp_server_started", "fake", 1);
    assert_eq!(started[0]["tools"], 2, "{started:?}");
    let s = status_of(&d, "fake");
    assert_eq!(s["state"], "running", "{s}");
    assert_eq!(s["tools"], 2, "{s}");
    // The handshake reached the fake, in order.
    let err = d.stderr_text();
    let i = err.find("fake-mcp: got initialize").expect(&err);
    let j = err
        .find("fake-mcp: got notifications/initialized")
        .expect(&err);
    let k = err.find("fake-mcp: got tools/list").expect(&err);
    assert!(i < j && j < k, "{err}");
}

#[test]
fn unsupported_version_fails_with_record() {
    if !env_runnable() {
        return;
    }
    let d = daemon(&server("old", &["--version", "2024-11-05"], ""));
    let failed = wait_event(&d, "mcp_server_failed", "old", 1);
    let reason = failed[0]["reason"].as_str().unwrap();
    assert!(reason.starts_with("mcp_version_unsupported"), "{reason}");
    assert!(reason.contains("2024-11-05"), "{reason}");
    // Stopped for good: not restarted.
    std::thread::sleep(Duration::from_secs(3));
    let recs = d.records();
    assert_eq!(events_of(&recs, "mcp_server_failed", "old").len(), 1);
    assert!(events_of(&recs, "mcp_server_started", "old").is_empty());
    let s = status_of(&d, "old");
    assert_eq!(s["state"], "failed", "{s}");
    assert!(s["last_error"]
        .as_str()
        .unwrap()
        .starts_with("mcp_version_unsupported"));
}

#[test]
fn secret_reaches_child_env_only_when_allowed_for_mcp_service() {
    if !env_runnable() {
        return;
    }
    let tok = token();
    let policy = |extra: &str| {
        format!(
            "{}{}{}",
            admin(),
            server(
                "fake",
                &["--echo-env", "FAKE_TOKEN"],
                "env = { FAKE_TOKEN = \"fake-tok\" }\n"
            ),
            extra
        )
    };
    // No secret yet: the server does not start.
    let d = daemon(&policy(""));
    let failed = wait_event(&d, "mcp_server_failed", "fake", 1);
    assert!(
        failed[0]["reason"]
            .as_str()
            .unwrap()
            .starts_with("secret_missing"),
        "{failed:?}"
    );
    // A secret for another service only: still refused.
    let o = add_secret(&d, "fake-tok", &tok, &["mcp:other"]);
    assert_eq!(o.status.code(), Some(0), "{o:?} {}", d.stderr_text());
    reload(&d, &policy(""));
    let failed = wait_event(&d, "mcp_server_failed", "fake", 2);
    let reason = failed[1]["reason"].as_str().unwrap();
    assert!(
        reason.starts_with("secret_not_allowed_for_service"),
        "{reason}"
    );
    assert!(reason.contains("mcp:fake"), "{reason}");
    assert!(events_of(&d.records(), "mcp_server_started", "fake").is_empty());
    // Allowed for mcp:fake: the child gets it in its environment (it echoes
    // it on stderr, masked on the way to the journal).
    let o = cli(&d)
        .arg("secret")
        .arg("--system-config")
        .arg(d.config())
        .args(["remove", "fake-tok"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    let o = add_secret(&d, "fake-tok", &tok, &["mcp:fake"]);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    reload(&d, &policy(""));
    wait_event(&d, "mcp_server_started", "fake", 1);
    let ok = wait_for(Duration::from_secs(10), || {
        d.stderr_text()
            .contains("saiife: mcp fake: fake-mcp: FAKE_TOKEN=[MASKED]")
    });
    assert!(ok, "{}", d.stderr_text());
    // The value is nowhere: journal, records, status.
    assert!(!d.stderr_text().contains(&tok));
    for f in fs::read_dir(d.audit_dir()).unwrap() {
        let text = fs::read_to_string(f.unwrap().path()).unwrap_or_default();
        assert!(!text.contains(&tok), "a secret value in the audit log");
    }
    assert!(!Value::Object(d.status()).to_string().contains(&tok));
}

#[test]
fn child_stderr_is_masked() {
    if !env_runnable() {
        return;
    }
    let tok = token();
    let d = daemon(&format!(
        "{}{}",
        admin(),
        server(
            "fake",
            &["--echo-env", "FAKE_TOKEN"],
            "env = { FAKE_TOKEN = \"fake-tok\" }\n"
        )
    ));
    wait_event(&d, "mcp_server_failed", "fake", 1);
    let o = add_secret(&d, "fake-tok", &tok, &["mcp:fake"]);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    // Changed secrets need a reload: a reload with the same policy picks
    // up the vault.
    reload(
        &d,
        &format!(
            "{}{}",
            admin(),
            server(
                "fake",
                &["--echo-env", "FAKE_TOKEN"],
                "env = { FAKE_TOKEN = \"fake-tok\" }\n"
            )
        ),
    );
    wait_event(&d, "mcp_server_started", "fake", 1);
    let ok = wait_for(Duration::from_secs(10), || {
        d.stderr_text().contains("FAKE_TOKEN=[MASKED]")
    });
    let err = d.stderr_text();
    assert!(ok, "{err}");
    assert!(!err.contains(&tok), "{err}");
    // Every line of the child is prefixed with its server.
    assert!(
        err.contains("saiife: mcp fake: fake-mcp: got initialize"),
        "{err}"
    );
}

#[test]
fn reload_removes_and_adds_servers() {
    if !env_runnable() {
        return;
    }
    let a = server("a", &[], "");
    let b = server("b", &[], "");
    let c = server("c", &[], "");
    let d = daemon(&format!("{a}{b}"));
    wait_event(&d, "mcp_server_started", "a", 1);
    wait_event(&d, "mcp_server_started", "b", 1);
    reload(&d, &format!("{b}{c}"));
    wait_event(&d, "mcp_server_started", "c", 1);
    let exited = wait_event(&d, "mcp_server_exited", "a", 1);
    assert!(
        exited[0]["reason"].as_str().unwrap().starts_with("stopped"),
        "{exited:?}"
    );
    let ok = wait_for(Duration::from_secs(10), || {
        let names: Vec<Value> = mcp_status(&d).iter().map(|s| s["name"].clone()).collect();
        names == [json!("b"), json!("c")]
    });
    assert!(ok, "{:?}", mcp_status(&d));
    // An unchanged server keeps its child.
    let recs = d.records();
    assert_eq!(events_of(&recs, "mcp_server_started", "b").len(), 1);
    assert!(events_of(&recs, "mcp_server_exited", "b").is_empty());
    // A changed one restarts.
    let b2 = server("b", &["--read-file-tool"], "");
    reload(&d, &format!("{b2}{c}"));
    wait_event(&d, "mcp_server_exited", "b", 1);
    let started = wait_event(&d, "mcp_server_started", "b", 2);
    assert_eq!(started[1]["tools"], 3, "{started:?}");
}

#[test]
fn stop_does_not_wait_for_children() {
    if !root_owned(BASH) {
        eprintln!("skipped: {BASH} is not root-owned here");
        return;
    }
    // A server that keeps its pipes open after EOF: the fake answers, then
    // the shell turns into a long sleep holding stdout.
    let extra = format!(
        "[mcp.stubborn]\ncommand = {BASH:?}\nargs = [\"-c\", \"\\\"$0\\\" __fake-mcp-server; exec /usr/bin/sleep 60\", {BIN:?}]\nread_paths = [{:?}]\n{}",
        bin_dir(),
        sandbox_line()
    );
    let mut d = daemon(&extra);
    wait_event(&d, "mcp_server_started", "stubborn", 1);
    let t0 = Instant::now();
    d.signal("TERM");
    let st = d
        .wait_exit(Duration::from_secs(10))
        .expect("the daemon stopped");
    let took = t0.elapsed();
    assert!(st.success(), "{st:?}: {}", d.stderr_text());
    assert!(took < Duration::from_secs(6), "stop took {took:?}");
    let recs = d.records();
    let exited = events_of(&recs, "mcp_server_exited", "stubborn");
    assert_eq!(exited.len(), 1, "{recs:#?}");
    assert!(
        exited[0]["reason"]
            .as_str()
            .unwrap()
            .contains("killed after 2 s"),
        "{exited:?}"
    );
    // The exit record lands before the stop record.
    let stop_at = recs.iter().position(|r| r["event"] == "stop").unwrap();
    let exit_at = recs
        .iter()
        .position(|r| r["event"] == "mcp_server_exited")
        .unwrap();
    assert!(exit_at < stop_at);
}

/// A gateway child connects to a socket of the daemon: closed before it
/// is answered (by pid: the test seam lets the daemon's own uid in, so
/// only the child check can refuse it), with an `mcp_child_peer` record.
fn child_peer_refused_on(flag: &str, sock: &str, label: &str, socket_name: &str) {
    // The socket path is known once the daemon's dir is: prepare, write
    // the config naming it, then start.
    let mut d = TestDaemon::prepare(&Opts::default());
    let path_s = d.socket_dir().join(sock).display().to_string();
    let opts = Opts {
        extra: server("prober", &[flag, &path_s], ""),
        ..Opts::default()
    };
    d.write_config(&opts);
    d.spawn_and_wait();
    wait_event(&d, "mcp_server_started", "prober", 1);
    let ok = wait_for(Duration::from_secs(10), || {
        d.stderr_text().contains(&format!("fake-mcp: {label}: "))
    });
    let err = d.stderr_text();
    assert!(ok, "{err}");
    assert!(
        err.contains(&format!("fake-mcp: {label}: closed")),
        "the child was answered: {err}"
    );
    let ok = wait_for(Duration::from_secs(5), || {
        !d.events("mcp_child_peer").is_empty()
    });
    assert!(ok, "no mcp_child_peer record");
    let rec = &d.events("mcp_child_peer")[0];
    assert!(
        rec["reason"].as_str().unwrap().contains(socket_name),
        "{rec}"
    );
    // The test's own client (same uid, not a child) is still served.
    assert_eq!(d.status()["mode"], "locked");
}

#[test]
fn child_peer_refused_on_control_socket() {
    if !env_runnable() {
        return;
    }
    child_peer_refused_on(
        "--connect-control",
        "saiife.sock",
        "connect-control",
        "control socket",
    );
}

#[test]
fn child_peer_refused_on_gateway_socket() {
    if !env_runnable() {
        return;
    }
    child_peer_refused_on(
        "--connect-gateway",
        "gateway.sock",
        "connect-gateway",
        "gateway socket",
    );
}

/// Without the test seam (as in production), the locked daemon closes
/// every peer of its own uid on both sockets before it is answered.
#[test]
fn own_uid_peer_refused_in_locked_mode() {
    let d = TestDaemon::prepare(&Opts::default());
    let log = fs::File::create(d.stderr_path()).unwrap();
    let mut cmd = d.command();
    cmd.env_remove("SAIIFE_TEST_OWN_UID_PEERS")
        .stdout(Stdio::null())
        .stderr(Stdio::from(log));
    let mut child = cmd.spawn().unwrap();
    let up = wait_for(Duration::from_secs(15), || {
        d.socket().exists() && d.socket_dir().join("gateway.sock").exists()
    });
    assert!(up, "{}", d.stderr_text());
    // Control socket: the connection is closed, no hello answer.
    let mut s = std::os::unix::net::UnixStream::connect(d.socket()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let hello = saiife_ipc::frame::encode_max(
        &json!({"id": 1, "op": "hello", "proto": saiife_ipc::msg::PROTO}),
        4096,
    )
    .unwrap();
    let _ = s.write_all(&hello);
    let mut buf = [0u8; 16];
    assert_eq!(s.read(&mut buf).unwrap_or(0), 0, "answered");
    assert!(d.try_client().is_err());
    // Gateway socket: closed without an HTTP answer.
    let mut g =
        std::os::unix::net::UnixStream::connect(d.socket_dir().join("gateway.sock")).unwrap();
    g.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let _ = g.write_all(b"GET /v1/services HTTP/1.1\r\nHost: saiife\r\n\r\n");
    assert_eq!(g.read(&mut buf).unwrap_or(0), 0, "answered");
    let ok = wait_for(Duration::from_secs(5), || {
        !d.events("mcp_child_peer").is_empty()
    });
    assert!(ok, "no mcp_child_peer record");
    let r = &d.events("mcp_child_peer")[0];
    assert!(
        r["reason"]
            .as_str()
            .unwrap()
            .contains(&format!("uid {}", own_uid())),
        "{r}"
    );
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn command_not_root_owned_fails() {
    let mut d = TestDaemon::prepare(&Opts::default());
    let cmd = common::fake_exe(&d.path().join("home"), "server", "exec /usr/bin/sleep 5");
    let opts = Opts {
        extra: format!(
            "[mcp.mine]\ncommand = {:?}\n{}",
            cmd.display().to_string(),
            sandbox_line()
        ),
        ..Opts::default()
    };
    d.write_config(&opts);
    d.spawn_and_wait();
    let failed = wait_event(&d, "mcp_server_failed", "mine", 1);
    let reason = failed[0]["reason"].as_str().unwrap();
    assert!(reason.starts_with("command_not_root_owned"), "{reason}");
    let s = status_of(&d, "mine");
    assert_eq!(s["state"], "failed", "{s}");
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(
        events_of(&d.records(), "mcp_server_failed", "mine").len(),
        1,
        "retried"
    );
}

#[test]
fn status_lists_servers() {
    if !env_runnable() {
        return;
    }
    let d = daemon(&format!(
        "{}{}",
        server("zeta", &[], ""),
        server("alpha", &["--version", "1999-01-01"], "")
    ));
    wait_event(&d, "mcp_server_started", "zeta", 1);
    wait_event(&d, "mcp_server_failed", "alpha", 1);
    let st = mcp_status(&d);
    assert_eq!(st.len(), 2, "{st:?}");
    assert_eq!(st[0]["name"], "alpha");
    assert_eq!(st[1]["name"], "zeta");
    for s in &st {
        let mut keys: Vec<&String> = s.as_object().unwrap().keys().collect();
        keys.sort();
        assert_eq!(
            keys,
            ["last_error", "name", "since", "state", "tools"],
            "{s}"
        );
        assert!(s["since"].as_str().unwrap().ends_with('Z'), "{s}");
    }
    assert_eq!(st[0]["state"], "failed");
    assert_eq!(st[1]["state"], "running");
    assert_eq!(st[1]["tools"], 2);
    assert_eq!(st[1]["last_error"], Value::Null);
    // `saiife status --json`-free check: the control op is what the CLI
    // reads.
    assert!(d.status().contains_key("mcp"));
}

// ---------------------------------------------------------------------
// In process: the gateway's `call`.

struct World {
    rt: tokio::runtime::Runtime,
    ctx: Arc<Ctx>,
    tmp: tempfile::TempDir,
    log: Arc<Mutex<Vec<String>>>,
}

impl World {
    fn new(servers: &str, secrets: &[(&str, &str, &[&str])]) -> World {
        let tmp = common::tmp::short_tempdir();
        let t = tmp.path().to_path_buf();
        for d in ["etc", "audit", "state", "run"] {
            fs::create_dir_all(t.join(d)).unwrap();
        }
        let config = t.join("etc/config.toml");
        fs::write(
            &config,
            format!(
                "version = 2\nlocked = true\n\n[daemon]\nuser = {:?}\nsocket_dir = {:?}\n\n[audit]\ndir = {:?}\n\n{servers}",
                own_user(),
                t.join("run").display().to_string(),
                t.join("audit").display().to_string(),
            ),
        )
        .unwrap();
        let l = saiife_policy::load_system(&config).unwrap();
        let writer_cfg = WriterConfig {
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
        let (handle, _join) = writer::spawn(cw, writer_cfg, None).unwrap();
        let key_file = t.join("vault-key");
        fs::write(&key_file, [9u8; 32]).unwrap();
        let mut vault = vault::open(&key_file, &t.join("state/vault/vault.bin"));
        let VaultState::Ready(v) = &mut vault else {
            panic!("vault not ready");
        };
        for (name, value, services) in secrets {
            v.put(Entry {
                name: name.to_string(),
                kind: Kind::Token,
                fields: [("token".to_string(), Zeroizing::new(value.to_string()))].into(),
                allowed_services: services.iter().map(|s| s.to_string()).collect(),
                created_by: 0,
                created: "2026-10-29T00:00:00Z".into(),
                last_used: None,
                rotate_after: None,
            })
            .unwrap();
        }
        let log = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&log);
        let gateway = Arc::new(Gateway::new(GatewaySetup {
            helper: PathBuf::from(BIN),
            state_dir: t.join("state"),
            protected: ["state", "audit", "run", "etc"]
                .iter()
                .map(|d| t.join(d))
                .collect(),
            enabled: true,
            log: Log::new(move |l| sink.lock().unwrap().push(l.to_string())),
        }));
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let directory = Arc::new(FixedDirectory::from_text("", ""));
        let ctx = rt.block_on(async {
            let ctx = Arc::new(Ctx::new(CtxInit {
                mode: Mode::Locked,
                own_uid: own_uid(),
                own_user: own_user(),
                audit_dir: t.join("audit"),
                vault,
                mcp: gateway,
                ..CtxInit::minimal(handle, writer_cfg, directory, &t.join("state"))
            }));
            ctx.mcp.attach(Arc::downgrade(&ctx));
            {
                let v = ctx.vault.lock();
                ctx.mcp.reconcile(&l.config, &v);
            }
            ctx
        });
        World { rt, ctx, tmp, log }
    }

    fn gw(&self) -> &Gateway {
        &self.ctx.mcp
    }

    fn records(&self) -> Vec<Value> {
        records_in(&self.tmp.path().join("audit"))
    }

    fn wait_event(&self, event: &str, srv: &str, n: usize) -> Vec<Value> {
        let ok = wait_for(Duration::from_secs(30), || {
            events_of(&self.records(), event, srv).len() >= n
        });
        assert!(ok, "no {n} {event} for {srv}: {:#?}", self.log_text());
        events_of(&self.records(), event, srv)
    }

    fn log_text(&self) -> String {
        self.log.lock().unwrap().join("\n")
    }

    fn wait_log(&self, needle: &str) -> bool {
        wait_for(Duration::from_secs(10), || self.log_text().contains(needle))
    }

    fn call(
        &self,
        srv: &str,
        tool: &str,
        args: Value,
        timeout: Duration,
    ) -> Result<Value, ChildError> {
        self.rt
            .block_on(self.gw().call(srv, tool, args, timeout, 5 * 1024 * 1024))
    }
}

impl Drop for World {
    fn drop(&mut self) {
        let ctx = Arc::clone(&self.ctx);
        self.rt.block_on(async move { ctx.mcp.stop().await });
    }
}

fn text_of(r: &Value) -> String {
    r["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

#[test]
fn in_process_tools_cached_and_names_sent_exactly() {
    if !env_runnable() {
        return;
    }
    let tools = json!([
        {"name": "Weird.Name-1_x", "inputSchema": {"type": "object"}},
        {"name": "Weird Name", "inputSchema": {"type": "object"}},
        {"name": "echo", "description": "Echo.", "inputSchema": {"type": "object"}},
    ])
    .to_string();
    let w = World::new(&server("fake", &["--tools", &tools], ""), &[]);
    w.wait_event("mcp_server_started", "fake", 1);
    let t = w.gw().tools("fake").expect("running");
    let names: Vec<&str> = t.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, ["Weird.Name-1_x", "echo"]);
    assert!(
        w.wait_log("1 tool(s) dropped: the name is not"),
        "{}",
        w.log_text()
    );
    // Through the trait, as Task 7 calls it; the odd name goes as listed.
    let caller: &dyn ToolCaller = w.gw();
    assert_eq!(caller.tools("fake").unwrap().len(), 2);
    let r = w
        .call(
            "fake",
            "Weird.Name-1_x",
            json!({"a": 1}),
            Duration::from_secs(10),
        )
        .unwrap();
    assert_eq!(text_of(&r), r#"{"a":1}"#, "{r}");
    assert_eq!(r["isError"], false);
    assert!(matches!(
        w.call("nope", "echo", json!({}), Duration::from_secs(1)),
        Err(ChildError::NotRunning(_))
    ));
}

#[test]
fn hung_server_times_out_and_is_cancelled() {
    if !env_runnable() {
        return;
    }
    let w = World::new(&server("fake", &["--hang-tool", "slow"], ""), &[]);
    w.wait_event("mcp_server_started", "fake", 1);
    let t0 = Instant::now();
    let r = w.call("fake", "slow", json!({}), Duration::from_secs(1));
    assert_eq!(r, Err(ChildError::Timeout));
    assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
    assert!(
        w.wait_log("fake-mcp: got notifications/cancelled "),
        "{}",
        w.log_text()
    );
    // The child is still up and answers the next call.
    let r = w
        .call("fake", "echo", json!({"x": "y"}), Duration::from_secs(10))
        .unwrap();
    assert_eq!(text_of(&r), r#"{"x":"y"}"#);
}

#[test]
fn oversized_line_stops_child() {
    if !env_runnable() {
        return;
    }
    let w = World::new(
        &server(
            "fake",
            &["--huge-tool", "big"],
            "limits = { max_response_bytes = 100000 }\n",
        ),
        &[],
    );
    w.wait_event("mcp_server_started", "fake", 1);
    // Over the cap but within the line limit: refused, the child stays.
    let r = w.rt.block_on(w.gw().call(
        "fake",
        "big",
        json!({"bytes": 50_000}),
        Duration::from_secs(10),
        10_000,
    ));
    assert_eq!(r, Err(ChildError::TooLarge));
    assert!(events_of(&w.records(), "mcp_server_exited", "fake").is_empty());
    // Over max_response_bytes + 64 KiB: the child is stopped and restarts.
    let r = w.call(
        "fake",
        "big",
        json!({"bytes": 400_000}),
        Duration::from_secs(10),
    );
    assert_eq!(r, Err(ChildError::TooLarge));
    let exited = w.wait_event("mcp_server_exited", "fake", 1);
    let reason = exited[0]["reason"].as_str().unwrap();
    assert!(reason.contains("over 165536 bytes"), "{reason}");
    w.wait_event("mcp_server_started", "fake", 2);
}

#[test]
fn crash_restarts_with_backoff() {
    if !env_runnable() {
        return;
    }
    let w = World::new(&server("fake", &["--crash-after", "1"], ""), &[]);
    w.wait_event("mcp_server_started", "fake", 1);
    let r = w
        .call("fake", "echo", json!({}), Duration::from_secs(10))
        .unwrap();
    assert_eq!(text_of(&r), "{}");
    let exited = w.wait_event("mcp_server_exited", "fake", 1);
    let t_exit = Instant::now();
    assert!(
        exited[0]["reason"]
            .as_str()
            .unwrap()
            .contains("exited with code 3"),
        "{exited:?}"
    );
    w.wait_event("mcp_server_started", "fake", 2);
    let gap = t_exit.elapsed();
    assert!(gap >= Duration::from_millis(800), "restarted after {gap:?}");
    // Again: the second wait is longer (2 s).
    w.call("fake", "echo", json!({}), Duration::from_secs(10))
        .unwrap();
    w.wait_event("mcp_server_exited", "fake", 2);
    let t_exit = Instant::now();
    w.wait_event("mcp_server_started", "fake", 3);
    let gap = t_exit.elapsed();
    assert!(
        gap >= Duration::from_millis(1800),
        "restarted after {gap:?}"
    );
    // Lifecycle order in the log: started, exited, started, exited, started.
    let recs = w.records();
    let seq: Vec<&str> = recs
        .iter()
        .filter(|r| r["server"] == "fake")
        .map(|r| r["event"].as_str().unwrap())
        .collect();
    assert_eq!(
        &seq[..5],
        [
            "mcp_server_started",
            "mcp_server_exited",
            "mcp_server_started",
            "mcp_server_exited",
            "mcp_server_started"
        ]
    );
}

#[test]
fn server_request_answered_method_not_found() {
    if !env_runnable() {
        return;
    }
    let w = World::new(&server("fake", &["--server-request"], ""), &[]);
    w.wait_event("mcp_server_started", "fake", 1);
    assert!(
        w.wait_log("fake-mcp: server request \"srv-1\" answered: error -32601"),
        "{}",
        w.log_text()
    );
}

#[test]
fn list_changed_triggers_relist() {
    if !env_runnable() {
        return;
    }
    let w = World::new(&server("fake", &[], ""), &[]);
    w.wait_event("mcp_server_started", "fake", 1);
    assert_eq!(w.gw().tools("fake").unwrap().len(), 2);
    w.call("fake", "change_tools", json!({}), Duration::from_secs(10))
        .unwrap();
    let ok = wait_for(Duration::from_secs(10), || {
        w.gw()
            .tools("fake")
            .is_some_and(|t| t.iter().any(|t| t.name == "added_tool"))
    });
    assert!(ok, "{}", w.log_text());
    // A second tools/list reached the fake.
    assert_eq!(w.log_text().matches("fake-mcp: got tools/list").count(), 2);
}

#[test]
fn results_and_stderr_masked_with_the_child_secrets() {
    if !env_runnable() {
        return;
    }
    let tok = token();
    let w = World::new(
        &server(
            "fake",
            &["--echo-env", "FAKE_TOKEN"],
            "env = { FAKE_TOKEN = \"fake-tok\" }\n",
        ),
        &[("fake-tok", &tok, &["mcp:fake"])],
    );
    w.wait_event("mcp_server_started", "fake", 1);
    let r = w
        .call("fake", "echo_env", json!({}), Duration::from_secs(10))
        .unwrap();
    assert_eq!(text_of(&r), "[MASKED]", "{r}");
    let r = w
        .call("fake", "echo", json!({"t": tok}), Duration::from_secs(10))
        .unwrap();
    assert!(!r.to_string().contains(&tok), "{r}");
    assert!(w.wait_log("FAKE_TOKEN=[MASKED]"), "{}", w.log_text());
    assert!(!w.log_text().contains(&tok));
    let vals = w.gw().secret_values("fake");
    assert!(vals.iter().any(|v| v.as_str() == tok));
    assert!(!w.gw().status().to_string().contains(&tok));
    for r in w.records() {
        assert!(!r.to_string().contains(&tok), "{r}");
    }
}

// ---------------------------------------------------------------------
// Fix round 1.

fn no_token_anywhere(w: &World, tok: &str) {
    assert!(!w.log_text().contains(tok), "log: {}", w.log_text());
    assert!(!w.gw().status().to_string().contains(tok));
    for r in w.records() {
        assert!(!r.to_string().contains(tok), "{r}");
    }
}

/// A server whose `initialize` error echoes its token: the reason in the
/// record, `status` and the journal (the daemon's stderr) is masked,
/// control-stripped and short.
#[test]
fn initialize_error_text_is_masked_everywhere() {
    if !env_runnable() {
        return;
    }
    let tok = token();
    let d = daemon(&format!(
        "{}{}",
        admin(),
        server(
            "fake",
            &["--echo-env", "FAKE_TOKEN", "--fail-method", "initialize"],
            "env = { FAKE_TOKEN = \"fake-tok\" }\n"
        )
    ));
    wait_event(&d, "mcp_server_failed", "fake", 1);
    // The secret add itself makes the gateway reconcile: no reload.
    let o = add_secret(&d, "fake-tok", &tok, &["mcp:fake"]);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    let failed = wait_event(&d, "mcp_server_failed", "fake", 2);
    let reason = failed[1]["reason"].as_str().unwrap();
    assert!(reason.contains("initialize failed"), "{reason}");
    assert!(reason.contains("FAKE_TOKEN=[MASKED]"), "{reason}");
    assert!(!reason.chars().any(char::is_control), "{reason:?}");
    assert!(reason.len() <= 600, "{}", reason.len());
    let s = status_of(&d, "fake");
    assert!(
        s["last_error"].as_str().unwrap().contains("[MASKED]"),
        "{s}"
    );
    assert!(!Value::Object(d.status()).to_string().contains(&tok));
    assert!(!d.stderr_text().contains(&tok), "{}", d.stderr_text());
    for r in d.records() {
        assert!(!r.to_string().contains(&tok), "{r}");
    }
}

#[test]
fn tools_list_error_text_is_masked() {
    if !env_runnable() {
        return;
    }
    let tok = token();
    let w = World::new(
        &server(
            "fake",
            &["--echo-env", "FAKE_TOKEN", "--fail-method", "tools/list"],
            "env = { FAKE_TOKEN = \"fake-tok\" }\n",
        ),
        &[("fake-tok", &tok, &["mcp:fake"])],
    );
    let failed = w.wait_event("mcp_server_failed", "fake", 1);
    let reason = failed[0]["reason"].as_str().unwrap();
    assert!(reason.starts_with("tools/list failed"), "{reason}");
    assert!(reason.contains("[MASKED]"), "{reason}");
    assert!(!reason.chars().any(char::is_control), "{reason:?}");
    no_token_anywhere(&w, &tok);
}

/// A tool whose name holds the secret is dropped (names are never
/// rewritten), with a masked note.
#[test]
fn tool_named_with_the_secret_is_dropped() {
    if !env_runnable() {
        return;
    }
    let tok = token();
    let tools = json!([
        {"name": format!("leak_{tok}"), "inputSchema": {"type": "object"}},
        {"name": "ok_tool", "inputSchema": {"type": "object"}},
    ])
    .to_string();
    let w = World::new(
        &server(
            "fake",
            &["--tools", &tools],
            "env = { FAKE_TOKEN = \"fake-tok\" }\n",
        ),
        &[("fake-tok", &tok, &["mcp:fake"])],
    );
    let started = w.wait_event("mcp_server_started", "fake", 1);
    assert_eq!(started[0]["tools"], 1);
    let names: Vec<String> = w
        .gw()
        .tools("fake")
        .unwrap()
        .iter()
        .map(|t| t.name.clone())
        .collect();
    assert_eq!(names, ["ok_tool"]);
    assert!(w.wait_log("1 tool(s) dropped"), "{}", w.log_text());
    no_token_anywhere(&w, &tok);
}

/// A server that stops reading its stdin cannot hold a call (or a pool
/// slot) past the call's timeout, however full its pipe gets.
#[test]
fn call_times_out_when_child_stops_reading() {
    if !env_runnable() {
        return;
    }
    let w = World::new(&server("fake", &["--block-tool", "block"], ""), &[]);
    w.wait_event("mcp_server_started", "fake", 1);
    let r = w.call("fake", "block", json!({}), Duration::from_millis(300));
    assert_eq!(r, Err(ChildError::Timeout));
    // Fill the pipe and the queue behind it: every call still ends in time.
    let pad = "p".repeat(100 * 1024);
    for i in 0..80 {
        let t0 = Instant::now();
        let r = w.call(
            "fake",
            "echo",
            json!({"pad": pad}),
            Duration::from_millis(200),
        );
        assert_eq!(r, Err(ChildError::Timeout), "call {i}");
        assert!(
            t0.elapsed() < Duration::from_secs(1),
            "call {i}: {:?}",
            t0.elapsed()
        );
    }
}

/// 1000 list_changed notifications: at most two relists.
#[test]
fn list_changed_flood_is_coalesced() {
    if !env_runnable() {
        return;
    }
    let w = World::new(&server("fake", &[], ""), &[]);
    w.wait_event("mcp_server_started", "fake", 1);
    let lists = |w: &World| w.log_text().matches("fake-mcp: got tools/list").count();
    assert_eq!(lists(&w), 1);
    w.call(
        "fake",
        "spam_list_changed",
        json!({"n": 1000}),
        Duration::from_secs(10),
    )
    .unwrap();
    assert!(wait_for(Duration::from_secs(10), || lists(&w) >= 2));
    std::thread::sleep(Duration::from_secs(2));
    let n = lists(&w);
    assert!((2..=3).contains(&n), "{n} tools/list in all");
}

/// A child that floods notifications past its unsolicited budget is
/// stopped like an over-cap line: the waiting call fails, a masked
/// `mcp_server_exited` record (and journal line) names the reason, and the
/// child restarts.
#[test]
fn unsolicited_flood_stops_child() {
    if !env_runnable() {
        return;
    }
    let w = World::new(&server("fake", &[], ""), &[]);
    w.wait_event("mcp_server_started", "fake", 1);
    let r = w.call(
        "fake",
        "flood",
        json!({"n": 20_000}),
        Duration::from_secs(20),
    );
    assert!(r.is_err(), "{r:?}");
    let exited = w.wait_event("mcp_server_exited", "fake", 1);
    let reason = exited[0]["reason"].as_str().unwrap();
    assert!(reason.contains("unsolicited"), "{reason}");
    assert!(
        w.wait_log("mcp_server_exited: stopped: the server sent over"),
        "{}",
        w.log_text()
    );
    w.wait_event("mcp_server_started", "fake", 2);
}

/// A storm of single list_changed notifications: at most one relist per
/// 5 s (plus the first list at start).
#[test]
fn relist_storm_is_rate_limited() {
    if !env_runnable() {
        return;
    }
    let w = World::new(&server("fake", &[], ""), &[]);
    w.wait_event("mcp_server_started", "fake", 1);
    let lists = |w: &World| w.log_text().matches("fake-mcp: got tools/list").count();
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(6) {
        w.call(
            "fake",
            "spam_list_changed",
            json!({"n": 1}),
            Duration::from_secs(10),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(100));
    }
    let secs = t0.elapsed().as_secs_f64();
    let n = lists(&w);
    // The start's list, one relist at once, one per 5 s after it.
    let most = 2 + (secs / 5.0).floor() as usize;
    assert!(n >= 2, "no relist: {n}");
    assert!(n <= most, "{n} tools/list in {secs:.1} s");
}

/// A stop while the child is still initializing: the pid leaves the set
/// (the cancelled start's reaper).
#[test]
fn stop_during_initialize_clears_children() {
    if !env_runnable() {
        return;
    }
    let w = World::new(&server("fake", &["--init-delay-ms", "20000"], ""), &[]);
    assert!(w.wait_log("fake-mcp: got initialize"), "{}", w.log_text());
    assert!(w.gw().has_children());
    let t0 = Instant::now();
    let ctx = Arc::clone(&w.ctx);
    w.rt.block_on(async move { ctx.mcp.stop().await });
    assert!(t0.elapsed() < Duration::from_secs(5));
    assert!(!w.gw().has_children());
}

/// A crash: the pid leaves the set before the exit record, and what the
/// child started in its group is killed with it.
#[test]
fn crash_clears_children_and_kills_the_group() {
    if !root_owned(BASH) {
        eprintln!("skipped: {BASH} is not root-owned here");
        return;
    }
    let extra = format!(
        "[mcp.grp]\ncommand = {BASH:?}\nargs = [\"-c\", \"/usr/bin/sleep 300 </dev/null >/dev/null 2>&1 & echo bg=$! >&2; exec \\\"$0\\\" __fake-mcp-server --crash-after 1\", {BIN:?}]\nread_paths = [{:?}]\n{}",
        bin_dir(),
        sandbox_line()
    );
    let w = World::new(&extra, &[]);
    w.wait_event("mcp_server_started", "grp", 1);
    assert!(w.wait_log("bg="), "{}", w.log_text());
    let bg: u32 = w
        .log_text()
        .split("bg=")
        .nth(1)
        .unwrap()
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!(w.gw().has_children());
    w.call("grp", "echo", json!({}), Duration::from_secs(10))
        .unwrap();
    w.wait_event("mcp_server_exited", "grp", 1);
    // The backoff before the restart is 1 s: no child now.
    assert!(!w.gw().has_children());
    std::thread::sleep(Duration::from_millis(300));
    let state = fs::read_to_string(format!("/proc/{bg}/stat"))
        .ok()
        .and_then(|s| s.rsplit_once(") ").map(|(_, r)| r.chars().next().unwrap()));
    assert!(
        matches!(state, None | Some('Z') | Some('X')),
        "the background process of the crashed child is still {state:?}"
    );
}

// ---------------------------------------------------------------------
// Task 7: `mcp.list` and `mcp.call` over the control socket.

fn mcp_op(d: &TestDaemon, op: &str, args: Value) -> Value {
    let mut c = d.client();
    match c.call(op, args.as_object().unwrap().clone(), common::daemon::dl()) {
        Ok(m) => Value::Object(m),
        Err(e) => json!({"refused": format!("{e:?}")}),
    }
}

#[test]
fn mcp_call_through_the_daemon_masks_and_records() {
    if !env_runnable() {
        return;
    }
    let tok = token();
    let policy = format!(
        "{}[[scope]]\nname = \"dev\"\nusers = [{:?}]\nservices = [\"mcp:fake\"]\n\n{}",
        admin(),
        own_user(),
        server(
            "fake",
            &["--echo-env", "FAKE_TOKEN"],
            "env = { FAKE_TOKEN = \"fake-tok\" }\nallow = [\"echo\", \"echo_env\"]\nread_tools = [\"echo\"]\n"
        )
    );
    let d = daemon(&policy);
    wait_event(&d, "mcp_server_failed", "fake", 1);
    let o = add_secret(&d, "fake-tok", &tok, &["mcp:fake"]);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    wait_event(&d, "mcp_server_started", "fake", 1);

    // Listed: the scoped server's allowed tools, names as the server gave.
    let l = mcp_op(&d, "mcp.list", json!({}));
    let servers = l["servers"].as_array().unwrap_or_else(|| panic!("{l}"));
    assert_eq!(servers.len(), 1, "{l}");
    assert_eq!(servers[0]["name"], "fake");
    let names: Vec<&str> = servers[0]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"echo") && names.contains(&"echo_env"),
        "{l}"
    );
    assert!(l["tools_hash"].as_str().unwrap().starts_with("sha256:"));

    // The real child echoes its token: masked in the answer.
    let a = mcp_op(
        &d,
        "mcp.call",
        json!({"server": "fake", "tool": "echo_env", "arguments": "{}"}),
    );
    assert_eq!(a["status"], Value::Null, "{a}");
    assert_eq!(a["result"]["content"][0]["text"], "[MASKED]", "{a}");
    // The canonical arguments reach the server.
    let a = mcp_op(
        &d,
        "mcp.call",
        json!({"server": "fake", "tool": "echo", "arguments": "{\"b\":1,\"a\":[2]}"}),
    );
    assert_eq!(
        a["result"]["content"][0]["text"], "{\"a\":[2],\"b\":1}",
        "{a}"
    );
    // Refused before anything is sent: a duplicate key, an unlisted tool.
    let a = mcp_op(
        &d,
        "mcp.call",
        json!({"server": "fake", "tool": "echo", "arguments": "{\"a\":1,\"a\":2}"}),
    );
    assert!(a["refused"].as_str().unwrap().contains("bad_param"), "{a}");
    let a = mcp_op(
        &d,
        "mcp.call",
        json!({"server": "fake", "tool": "introspect", "arguments": "{}"}),
    );
    assert!(
        a["refused"].as_str().unwrap().contains("unknown_operation")
            || a["refused"].as_str().unwrap().contains("default_deny"),
        "{a}"
    );

    // One connector record per call, tool `mcp`, and no secret anywhere.
    let recs: Vec<Value> = d
        .records()
        .into_iter()
        .filter(|r| r["kind"] == "connector")
        .collect();
    assert_eq!(recs.len(), 4, "{recs:#?}");
    assert!(recs.iter().all(|r| r["tool"] == "mcp" && r["via"] == "mcp"));
    assert!(recs.iter().all(|r| r["service"] == "mcp:fake"));
    assert_eq!(recs[0]["operation"], "echo_env");
    assert_eq!(recs[0]["op_kind"], "write");
    assert_eq!(recs[1]["op_kind"], "read");
    assert_eq!(recs[0]["secret"], "fake-tok");
    assert_eq!(recs[2]["rule"], "bad_param");
    for f in fs::read_dir(d.audit_dir()).unwrap() {
        let text = fs::read_to_string(f.unwrap().path()).unwrap_or_default();
        assert!(!text.contains(&tok), "a secret value in the audit log");
    }
    assert!(!d.stderr_text().contains(&tok));
    let v = d.verify();
    assert_eq!(v.status.code(), Some(0), "{v:?}");
}
