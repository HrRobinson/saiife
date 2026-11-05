//! The CLI's locked mode on Windows against the real daemon, unprivileged, in temp dirs
//! (plan 19b, Task 10). A debug-build test pipe `\\.\pipe\saiife-test-<random>`, owned by
//! the runner's SID, stands in for W11's, and `SAIIFE_TEST_TRUST_SID` makes the runner one
//! of the trusted writers, since it owns its own temp dir. These run in CI's `test` job
//! only: no Windows machine runs this file locally.
//!
//! The tree sits below the user's temp folder, whose folders above are the machine's or
//! the user's own. The runner's work drive has no such promise.
#![cfg(windows)]

use assert_cmd::Command;
use predicates::str::contains;
use saiife_win::ffi::pipe::create_server;
use saiife_win::ffi::{account, acl, token};
use saiife_win::pipe::control_sddl;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

const GIT_STATUS: &str =
    r#"{"tool_name":"Bash","tool_input":{"command":"git status"},"cwd":"C:\\"}"#;
const FORCE_PUSH: &str =
    r#"{"tool_name":"Bash","tool_input":{"command":"git push --force origin main"},"cwd":"C:\\"}"#;

fn me() -> String {
    token::current().unwrap().sid
}

fn pipe_name(test: &str) -> String {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    format!(r"\\.\pipe\saiife-test-{}-{n}-{test}", std::process::id())
}

/// A locked config and its daemon's dirs, only the runner and SYSTEM can use them.
struct Tree {
    _root: tempfile::TempDir,
    top: PathBuf,
    config: PathBuf,
    audit: PathBuf,
    state: PathBuf,
}

fn tree() -> Tree {
    let root = tempfile::tempdir_in(std::env::temp_dir()).unwrap();
    let me = me();
    let sddl = format!("O:{me}D:PAI(A;OICI;FA;;;{me})(A;OICI;FA;;;SY)");
    let top = root.path().join("t");
    acl::create_dir_with_sddl(&top, &sddl).unwrap();
    let top = saiife_system::wintrust::plain_path(&std::fs::canonicalize(&top).unwrap());
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
        top,
        config,
        audit,
        state,
    }
}

/// `saiife` as a client of `pipe`, in a profile of its own.
fn client(home: &Path, pipe: &str) -> Command {
    let mut c = Command::cargo_bin("saiife").unwrap();
    c.env("USERPROFILE", home)
        .env("LOCALAPPDATA", home.join("AppData").join("Local"))
        .env("SAIIFE_DATA_DIR", home.join("data"))
        .env("SAIIFE_AUDIT_DIR", home.join("audit"))
        .env("SAIIFE_TEST_PIPE", pipe)
        .env("SAIIFE_TEST_TRUST_SID", me());
    c
}

/// The daemon in a process of its own, killed when this drops.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn daemon(t: &Tree, home: &Path, pipe: &str) -> Daemon {
    let child = std::process::Command::new(assert_cmd::cargo::cargo_bin("saiife"))
        .args(["daemon", "--system", "--config"])
        .arg(&t.config)
        .arg("--state-dir")
        .arg(&t.state)
        .arg("--credentials-dir")
        .arg(t.state.join("keys"))
        .env("USERPROFILE", home)
        .env("SAIIFE_TEST_PIPE", pipe)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let d = Daemon(child);
    // Up once a client gets its answer, with the owner checked.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let per_try = Instant::now() + Duration::from_secs(2);
        match saiife_ipc::client::Client::connect_pipe(pipe, &me(), per_try) {
            Ok(_) => return d,
            Err(e) if Instant::now() > deadline => panic!("no daemon on {pipe}: {e}"),
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

fn hook(c: &mut Command, config: &Path, stdin: &str) {
    c.args(["check", "--managed", "--hook-exit", "--agent", "claude"])
        .arg("--system-config")
        .arg(config)
        .write_stdin(stdin);
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

#[test]
fn hook_allows_and_records_with_the_daemon() {
    let t = tree();
    let home = tempfile::tempdir().unwrap();
    let pipe = pipe_name("allow");
    let _d = daemon(&t, home.path(), &pipe);
    let mut c = client(home.path(), &pipe);
    hook(&mut c, &t.config, GIT_STATUS);
    c.assert().code(0);
    let text = audit_text(&t.audit);
    assert!(text.contains("git status"), "{text}");
    assert!(text.contains("\"allow\""), "{text}");
    // Nothing of the call in the user's own dirs: the daemon is the only writer.
    assert!(!home.path().join("audit").exists());
}

#[test]
fn hook_denies_and_records_with_the_daemon() {
    let t = tree();
    let home = tempfile::tempdir().unwrap();
    let pipe = pipe_name("deny");
    let _d = daemon(&t, home.path(), &pipe);
    let mut c = client(home.path(), &pipe);
    hook(&mut c, &t.config, FORCE_PUSH);
    c.assert().code(2).stderr(contains("BLOCKED by"));
    assert!(audit_text(&t.audit).contains("\"deny\""));
}

/// An agent that moves `USERPROFILE` does not move the worker's home: the worker's comes
/// from the machine's record, or the rule on `~/.ssh` would look elsewhere.
#[test]
fn hook_home_is_not_the_agents() {
    let t = tree();
    let home = tempfile::tempdir().unwrap();
    let pipe = pipe_name("home");
    let _d = daemon(&t, home.path(), &pipe);
    let real = std::env::var_os("USERPROFILE").unwrap();
    let key = Path::new(&real).join(".ssh").join("id_rsa");
    let payload = serde_json::json!({
        "tool_name": "Read",
        "tool_input": {"file_path": key.display().to_string()},
        "cwd": "C:\\",
    });
    let mut c = client(home.path(), &pipe);
    hook(&mut c, &t.config, &payload.to_string());
    c.assert().code(2);
}

#[test]
fn hook_denies_with_no_daemon() {
    let t = tree();
    let home = tempfile::tempdir().unwrap();
    let mut c = client(home.path(), &pipe_name("nobody"));
    hook(&mut c, &t.config, GIT_STATUS);
    c.assert()
        .code(2)
        .stderr(contains("cannot reach the audit daemon"));
}

/// W11, review focus 2: someone else holds the real pipe's name. The owner is not the
/// service, so the hook denies before a byte is sent.
#[test]
fn hook_denies_a_squatted_pipe() {
    let t = tree();
    let home = tempfile::tempdir().unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _guard = rt.enter();
    let _squat = create_server(r"\\.\pipe\saiife", &control_sddl(&me()), true).unwrap();
    let mut c = Command::cargo_bin("saiife").unwrap();
    c.env("USERPROFILE", home.path())
        .env_remove("SAIIFE_TEST_PIPE")
        .env("SAIIFE_TEST_TRUST_SID", me());
    hook(&mut c, &t.config, GIT_STATUS);
    c.assert()
        .code(2)
        .stderr(contains("socket owner check failed"));
}

/// The same file with nobody vouching for the runner, who owns it: not our tree. The hook
/// denies, and says why.
#[test]
fn hook_denies_a_planted_config() {
    let t = tree();
    let home = tempfile::tempdir().unwrap();
    let mut c = Command::cargo_bin("saiife").unwrap();
    c.env("USERPROFILE", home.path())
        .env_remove("SAIIFE_TEST_TRUST_SID");
    hook(&mut c, &t.config, GIT_STATUS);
    c.assert().code(2).stderr(contains("not protected"));
}

/// A planted install record must not silence the developer hook, and a planted config must
/// not make `audit` hide the user's own log.
#[test]
fn planted_files_change_no_mode() {
    let t = tree();
    let home = tempfile::tempdir().unwrap();
    std::fs::write(
        t.top.join("installed.toml"),
        "[[agents]]\nagent = \"claude\"\nsha256 = \"ab\"\n",
    )
    .unwrap();
    let plain = |c: &mut Command| {
        c.env("USERPROFILE", home.path())
            .env("LOCALAPPDATA", home.path().join("AppData").join("Local"))
            .env("SAIIFE_DATA_DIR", home.path().join("data"))
            .env("SAIIFE_AUDIT_DIR", home.path().join("audit"))
            .env_remove("SAIIFE_TEST_TRUST_SID");
    };
    let mut c = Command::cargo_bin("saiife").unwrap();
    plain(&mut c);
    c.args(["check", "--agent", "claude", "--system-config"])
        .arg(&t.config)
        .write_stdin(FORCE_PUSH);
    c.assert().code(2).stderr(contains("not protected"));

    let mut c = Command::cargo_bin("saiife").unwrap();
    plain(&mut c);
    c.args(["audit", "--system-config"]).arg(&t.config);
    c.assert().code(0).stderr(contains("not protected"));
}

#[test]
fn clients_reach_the_daemon_through_the_pipe() {
    let t = tree();
    let home = tempfile::tempdir().unwrap();
    let pipe = pipe_name("clients");
    let _d = daemon(&t, home.path(), &pipe);
    // Not exit 5: each answer came from the daemon, whatever it said.
    let cases: &[&[&str]] = &[
        &["secret", "list", "--system-config"],
        &["api", "--list", "--system-config"],
        &["lockdown", "--system-config"],
    ];
    for args in cases {
        let out = client(home.path(), &pipe)
            .args(*args)
            .arg(&t.config)
            .output()
            .unwrap();
        assert_ne!(out.status.code(), Some(5), "{args:?}: {out:?}");
    }
    let mut c = client(home.path(), &pipe);
    c.args(["policy", "--system-config"])
        .arg(&t.config)
        .arg("reload");
    c.assert().code(0).stdout(contains("loaded"));
}

/// W19. With the seam the runner's tree passes the chain check on both sides, which leaves
/// the daemon to refuse a secret it does not hold. With the seam naming someone else the
/// runner's own files are refused before any daemon is asked.
#[test]
fn run_checks_the_chain_before_any_lease() {
    let t = tree();
    let home = tempfile::tempdir().unwrap();
    let pipe = pipe_name("run");
    let _d = daemon(&t, home.path(), &pipe);
    let tool = t.top.join("tool.exe");
    std::fs::copy(assert_cmd::cargo::cargo_bin("saiife"), &tool).unwrap();
    let text = std::fs::read_to_string(&t.config).unwrap();
    std::fs::write(
        &t.config,
        format!(
            "{text}[secrets.k]\nrun_allow = [{:?}]\n",
            tool.display().to_string()
        ),
    )
    .unwrap();

    let run = |c: &mut Command| {
        c.args(["run", "--secret", "k:TOK", "--system-config"])
            .arg(&t.config)
            .arg("--")
            .arg(&tool)
            .arg("--version");
    };
    let mut c = client(home.path(), &pipe);
    run(&mut c);
    let out = c.output().unwrap();
    let said = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(2), "{said}");
    assert!(!said.contains("not protected"), "{said}");

    let mut c = client(home.path(), &pipe);
    c.env("SAIIFE_TEST_TRUST_SID", "S-1-5-21-9-9-9-9");
    run(&mut c);
    c.assert().code(5).stderr(contains("not protected"));
}
