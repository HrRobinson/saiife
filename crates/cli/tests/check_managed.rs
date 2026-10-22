//! `saiife check --managed`: the locked-mode hook (plan 9a, Task 7). The
//! guard runs in a worker child, the record goes to the daemon, and every
//! error ends in exit 2 (fail closed). Runs as the current user with every
//! path in a temp dir.
#![cfg(target_os = "linux")]

mod common;

use common::daemon::{Opts, TestDaemon};
use saiife_ipc::frame::{read_frame, write_frame};
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture(rel: &str) -> String {
    fs::read_to_string(Path::new(FIXTURES).join(rel)).unwrap()
}

/// Hermetic dirs for one hook call: HOME, data and audit dirs the managed
/// path must never touch.
struct Sandbox {
    dir: tempfile::TempDir,
}

impl Sandbox {
    fn new() -> Sandbox {
        let dir = tempfile::tempdir().unwrap();
        for d in ["home", "data", "audit"] {
            fs::create_dir_all(dir.path().join(d)).unwrap();
        }
        Sandbox { dir }
    }
    fn audit(&self) -> std::path::PathBuf {
        self.dir.path().join("audit")
    }
    fn data(&self) -> std::path::PathBuf {
        self.dir.path().join("data")
    }
    fn is_untouched(&self) -> bool {
        fs::read_dir(self.audit()).unwrap().next().is_none()
            && fs::read_dir(self.data()).unwrap().next().is_none()
    }
}

/// Run `saiife check --managed --system-config <config>` with `stdin`.
fn managed_with(
    config: &Path,
    stdin: &str,
    extra_env: &[(&str, &str)],
    extra_args: &[&str],
) -> (Output, Duration, Sandbox) {
    let sb = Sandbox::new();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_saiife"));
    cmd.args(["check", "--managed", "--agent", "claude", "--system-config"])
        .arg(config)
        .args(extra_args)
        .env("HOME", sb.dir.path().join("home"))
        .env("PATH", "/usr/bin:/bin")
        .env("SAIIFE_DATA_DIR", sb.data())
        .env("SAIIFE_AUDIT_DIR", sb.audit())
        .env_remove("SAIIFE_EVAL_FAULT")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let t = Instant::now();
    let mut child = cmd.spawn().unwrap();
    let mut sin = child.stdin.take().unwrap();
    let data = stdin.as_bytes().to_vec();
    let w = std::thread::spawn(move || {
        let _ = sin.write_all(&data);
    });
    let out = child.wait_with_output().unwrap();
    let elapsed = t.elapsed();
    w.join().unwrap();
    (out, elapsed, sb)
}

fn managed(config: &Path, stdin: &str) -> (Output, Duration, Sandbox) {
    managed_with(config, stdin, &[], &[])
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}
fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

/// A Bash payload for `command` run in `cwd`.
fn bash(cwd: &Path, command: &str) -> String {
    json!({
        "session_id": "s-m",
        "cwd": cwd,
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command}
    })
    .to_string()
}

fn guard_records(d: &TestDaemon) -> Vec<Value> {
    d.of_kind("guard")
}

fn last_guard(d: &TestDaemon) -> Value {
    guard_records(d)
        .pop()
        .unwrap_or_else(|| panic!("no guard record; daemon: {}", d.stderr_text()))
}

fn is_policy_hash(v: &Value) -> bool {
    let s = v.as_str().unwrap_or("");
    s.strip_prefix("sha256:").is_some_and(|h| {
        h.len() == 64
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// A socket dir owned by the test user, 0755, as the client requires.
fn fake_socket_dir(d: &TestDaemon) -> UnixListener {
    let dir = d.socket_dir();
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    UnixListener::bind(d.socket()).unwrap()
}

#[test]
fn managed_allow_is_silent_and_recorded() {
    let d = TestDaemon::start(Opts::default());
    let home = common::FixtureHome::new();
    let (o, _, sb) = managed(&d.config(), &home.real(&fixture("claude/bash-allow.json")));
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert!(
        o.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&o.stdout)
    );
    assert!(o.stderr.is_empty(), "{}", stderr(&o));
    let r = last_guard(&d);
    assert_eq!(r["decision"], "allow");
    assert_eq!(r["mode"], "locked");
    assert!(is_policy_hash(&r["policy"]), "{r}");
    assert_eq!(r["uid"], json!(common::daemon::own_uid()));
    assert!(r["seq"].as_u64().unwrap() >= 1, "{r}");
    assert_eq!(r["input"], "ls -la");
    assert_eq!(r["agent"], "claude");
    assert_eq!(r["tool"], "Bash");
    assert_eq!(r["session"], "c-1");
    assert_eq!(r["permission_mode"], "default");
    assert!(sb.is_untouched());
}

#[test]
fn managed_deny_exit_2() {
    let d = TestDaemon::start(Opts::default());
    let home = common::FixtureHome::new();
    let (o, _, _sb) = managed(&d.config(), &home.real(&fixture("claude/bash-deny.json")));
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(o.stdout.is_empty());
    assert!(
        stderr(&o).starts_with("BLOCKED by core.filesystem"),
        "{}",
        stderr(&o)
    );
    let r = last_guard(&d);
    assert_eq!(r["decision"], "deny");
    assert_eq!(r["pack"], "core.filesystem");
    assert_eq!(r["mode"], "locked");
    assert_eq!(r["input"], "rm -rf /");
}

#[test]
fn daemon_down_denies() {
    let d = TestDaemon::prepare(&Opts::default());
    let home = common::FixtureHome::new();
    let (o, _, sb) = managed(&d.config(), &home.real(&fixture("claude/bash-allow.json")));
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(stderr(&o).contains("fail closed"), "{}", stderr(&o));
    assert!(o.stdout.is_empty());
    assert!(sb.is_untouched());
    assert!(d.records().is_empty());
}

#[test]
fn daemon_not_acking_denies() {
    let d = TestDaemon::prepare(&Opts::default());
    let l = fake_socket_dir(&d);
    std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let h = read_frame(&mut s).unwrap();
        write_frame(
            &mut s,
            &json!({"id": h["id"], "ok": true, "proto": 1, "mode": "locked"}),
        )
        .unwrap();
        // Read the append and never answer it.
        let _ = read_frame(&mut s);
        std::thread::sleep(Duration::from_secs(10));
    });
    let home = common::FixtureHome::new();
    let (o, elapsed, sb) = managed(&d.config(), &home.real(&fixture("claude/bash-allow.json")));
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(stderr(&o).contains("fail closed"), "{}", stderr(&o));
    assert!(
        elapsed >= Duration::from_millis(2000) && elapsed <= Duration::from_millis(3500),
        "{elapsed:?}"
    );
    assert!(sb.is_untouched());
}

#[test]
fn daemon_closes_after_hello_denies() {
    let d = TestDaemon::prepare(&Opts::default());
    let l = fake_socket_dir(&d);
    std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let h = read_frame(&mut s).unwrap();
        write_frame(
            &mut s,
            &json!({"id": h["id"], "ok": true, "proto": 1, "mode": "locked"}),
        )
        .unwrap();
        drop(s);
    });
    let home = common::FixtureHome::new();
    let (o, elapsed, sb) = managed(&d.config(), &home.real(&fixture("claude/bash-allow.json")));
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(stderr(&o).contains("fail closed"), "{}", stderr(&o));
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    assert!(sb.is_untouched());
}

/// A daemon whose hello does not say `mode: "locked"` is not trusted
/// with the call (M6): deny at once, nothing appended.
#[test]
fn hello_without_locked_mode_denies() {
    for hello in [
        json!({"ok": true, "proto": 1}),
        json!({"ok": true, "proto": 1, "mode": "developer"}),
    ] {
        let d = TestDaemon::prepare(&Opts::default());
        let l = fake_socket_dir(&d);
        let appended = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = appended.clone();
        let fake = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let h = read_frame(&mut s).unwrap();
            let mut a = hello.clone();
            a["id"] = h["id"].clone();
            write_frame(&mut s, &a).unwrap();
            if let Ok(m) = read_frame(&mut s) {
                seen.store(true, std::sync::atomic::Ordering::SeqCst);
                let _ = write_frame(&mut s, &json!({"id": m["id"], "ok": true, "seq": 1}));
            }
        });
        let home = common::FixtureHome::new();
        let (o, elapsed, sb) = managed(&d.config(), &home.real(&fixture("claude/bash-allow.json")));
        fake.join().unwrap();
        assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
        let err = stderr(&o);
        assert!(err.contains("fail closed"), "{err}");
        assert!(err.contains("not in locked mode"), "{err}");
        assert!(!appended.load(std::sync::atomic::Ordering::SeqCst));
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
        assert!(sb.is_untouched());
    }
}

/// No watchdog, no overall deadline: deny before reading stdin (I1).
#[test]
fn watchdog_spawn_failure_denies() {
    let d = TestDaemon::start(Opts::default());
    let home = common::FixtureHome::new();
    let (o, elapsed, sb) = managed_with(
        &d.config(),
        &home.real(&fixture("claude/bash-allow.json")),
        &[("SAIIFE_EVAL_FAULT", "watchdog_spawn")],
        &[],
    );
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(
        stderr(&o).contains("saiife: BLOCKED (fail closed): cannot start the watchdog"),
        "{}",
        stderr(&o)
    );
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    assert!(guard_records(&d).is_empty());
    assert!(sb.is_untouched());
}

#[test]
fn socket_owner_mismatch_denies() {
    let d = TestDaemon::prepare(&Opts {
        user: Some("root".into()),
        ..Opts::default()
    });
    let l = fake_socket_dir(&d);
    l.set_nonblocking(true).unwrap();
    let home = common::FixtureHome::new();
    let (o, _, _sb) = managed(&d.config(), &home.real(&fixture("claude/bash-allow.json")));
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    let err = stderr(&o);
    assert!(err.contains("fail closed"), "{err}");
    assert!(err.contains("owner"), "{err}");
    assert!(
        l.accept().is_err(),
        "the hook must not connect to a socket that fails the owner check"
    );
}

fn worker_fault(fault: &str) -> (Output, Duration, TestDaemon) {
    let home = common::FixtureHome::new();
    worker_fault_with(
        fault,
        &home.real(&fixture("claude/bash-allow.json")),
        "ls -la",
    )
}

fn worker_fault_with(fault: &str, payload: &str, input: &str) -> (Output, Duration, TestDaemon) {
    let d = TestDaemon::start(Opts::default());
    let (o, elapsed, _sb) =
        managed_with(&d.config(), payload, &[("SAIIFE_EVAL_FAULT", fault)], &[]);
    assert_eq!(code(&o), 2, "{fault}: stderr: {}", stderr(&o));
    assert!(o.stdout.is_empty());
    let err = stderr(&o);
    assert!(
        err.contains("saiife: BLOCKED (fail closed): guard worker failed"),
        "{fault}: {err}"
    );
    let r = last_guard(&d);
    assert_eq!(r["decision"], "error_denied", "{fault}: {r}");
    assert!(
        r["reason"]
            .as_str()
            .unwrap()
            .starts_with("guard worker failed"),
        "{fault}: {r}"
    );
    assert_eq!(r["input"], input, "{fault}: {r}");
    (o, elapsed, d)
}

#[test]
fn worker_abort_denies() {
    worker_fault("abort");
}

#[test]
fn worker_segv_denies() {
    let (o, _, _) = worker_fault("segv");
    assert!(stderr(&o).contains("signal 11"), "{}", stderr(&o));
}

#[test]
fn worker_overflow_denies() {
    worker_fault("overflow");
}

#[test]
fn worker_hang_denies_after_3s() {
    let (_, elapsed, _) = worker_fault("hang");
    assert!(
        elapsed >= Duration::from_millis(3000) && elapsed <= Duration::from_millis(4500),
        "{elapsed:?}"
    );
}

#[test]
fn managed_ignores_saiife_env() {
    let d = TestDaemon::start(Opts::default());
    let home = common::FixtureHome::new();
    for f in ["claude/bash-allow.json", "claude/bash-deny.json"] {
        let (_, _, sb) = managed(&d.config(), &home.real(&fixture(f)));
        assert!(sb.is_untouched(), "{f}");
        assert!(!sb.audit().join(".chain.lock").exists());
    }
    assert_eq!(guard_records(&d).len(), 2);
}

#[test]
fn managed_large_shell_payload_denies() {
    let d = TestDaemon::start(Opts::default());
    let p = tempfile::tempdir().unwrap();
    let cmd = format!("echo {}", "a".repeat(300 * 1024));
    let (o, _, _sb) = managed(&d.config(), &bash(p.path(), &cmd));
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(stderr(&o).contains("fail closed"), "{}", stderr(&o));
    let r = last_guard(&d);
    assert_eq!(r["decision"], "error_denied", "{r}");
}

fn project_with(config: &str) -> tempfile::TempDir {
    let p = tempfile::tempdir().unwrap();
    common::assert_no_host_config(p.path());
    fs::create_dir(p.path().join(".saiife")).unwrap();
    fs::write(p.path().join(".saiife/config.toml"), config).unwrap();
    p
}

#[test]
fn project_config_is_add_only() {
    let d = TestDaemon::start(Opts::default());
    let p = project_with("version = 1\npacks = []\n");
    let (o, _, _sb) = managed(&d.config(), &bash(p.path(), "rm -rf /"));
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(stderr(&o).starts_with("BLOCKED by core.filesystem"));

    let drop_db = "psql -c 'DROP DATABASE prod'";
    let bare = tempfile::tempdir().unwrap();
    let (o, _, _sb) = managed(&d.config(), &bash(bare.path(), drop_db));
    assert_eq!(code(&o), 0, "db.postgres is opt-in: {}", stderr(&o));

    let p = project_with("version = 1\npacks = [\"db.postgres\"]\n");
    let (o, _, _sb) = managed(&d.config(), &bash(p.path(), drop_db));
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(
        stderr(&o).starts_with("BLOCKED by db.postgres"),
        "{}",
        stderr(&o)
    );
    assert_eq!(last_guard(&d)["decision"], "deny");
}

#[test]
fn invalid_project_config_warns_and_system_policy_applies() {
    let d = TestDaemon::start(Opts::default());
    let p = project_with("packs = [\n");
    let (o, _, _sb) = managed(&d.config(), &bash(p.path(), "rm -rf /"));
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(stderr(&o).contains("BLOCKED by core.filesystem"));
    assert!(stderr(&o).contains("ignored"), "{}", stderr(&o));
    let (o, _, _sb) = managed(&d.config(), &bash(p.path(), "ls"));
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
}

#[test]
fn policy_hash_changes_with_project_deny() {
    let d = TestDaemon::start(Opts::default());
    let a = project_with("version = 1\n[services.x]\ndeny = [\"GET /a\"]\n");
    let b = project_with("version = 1\n[services.x]\ndeny = [\"GET /b\"]\n");
    let (o, _, _sb) = managed(&d.config(), &bash(a.path(), "ls"));
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    let pa = last_guard(&d)["policy"].clone();
    let (o, _, _sb) = managed(&d.config(), &bash(b.path(), "ls"));
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    let pb = last_guard(&d)["policy"].clone();
    assert!(is_policy_hash(&pa) && is_policy_hash(&pb));
    assert_ne!(pa, pb);
    let (_, _, _sb) = managed(&d.config(), &bash(a.path(), "ls -l"));
    assert_eq!(last_guard(&d)["policy"], pa);
}

#[test]
fn unparseable_system_config_denies() {
    let d = TestDaemon::start(Opts::default());
    let bad = d.path().join("etc/bad.toml");
    fs::write(&bad, "version = = 2\n").unwrap();
    let home = common::FixtureHome::new();
    let (o, _, sb) = managed(&bad, &home.real(&fixture("claude/bash-allow.json")));
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    let err = stderr(&o);
    assert!(err.contains("fail closed"), "{err}");
    assert!(err.contains("saiife policy could not be loaded"), "{err}");
    assert!(sb.is_untouched());
}

#[test]
fn unlocked_system_config_denies() {
    let d = TestDaemon::start(Opts::default());
    let text = fs::read_to_string(d.config()).unwrap();
    let unlocked = d.path().join("etc/unlocked.toml");
    fs::write(&unlocked, text.replace("locked = true", "locked = false")).unwrap();
    let home = common::FixtureHome::new();
    let (o, _, _sb) = managed(&unlocked, &home.real(&fixture("claude/bash-allow.json")));
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(
        stderr(&o).contains("saiife policy could not be loaded"),
        "{}",
        stderr(&o)
    );
}

#[test]
fn unusable_payload_is_error_denied() {
    let d = TestDaemon::start(Opts::default());
    let (o, _, _sb) = managed(&d.config(), "this is not json");
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(stderr(&o).contains("fail closed"), "{}", stderr(&o));
    assert_eq!(last_guard(&d)["decision"], "error_denied");
}

#[test]
fn untouched_tool_is_allowed_and_recorded() {
    let d = TestDaemon::start(Opts::default());
    let home = common::FixtureHome::new();
    let (o, _, _sb) = managed(&d.config(), &home.real(&fixture("claude/webfetch.json")));
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    let r = last_guard(&d);
    assert_eq!(r["decision"], "allow");
    assert_eq!(r["reason"], "tool not judged");
}

#[test]
fn bad_arguments_with_managed_fail_closed() {
    let d = TestDaemon::start(Opts::default());
    let home = common::FixtureHome::new();
    let (o, _, sb) = managed_with(
        &d.config(),
        &home.real(&fixture("claude/bash-allow.json")),
        &[],
        &["--no-such-flag"],
    );
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(stderr(&o).contains("fail closed"), "{}", stderr(&o));
    assert!(sb.is_untouched());
    assert_eq!(last_guard(&d)["decision"], "error_denied");
}

#[test]
fn developer_check_untouched() {
    let home = common::FixtureHome::new();
    let sb = Sandbox::new();
    let mut child = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["check", "--hook-exit", "--agent", "claude"])
        .env("HOME", sb.dir.path().join("home"))
        .env("PATH", "/usr/bin:/bin")
        .env("SAIIFE_DATA_DIR", sb.data())
        .env("SAIIFE_AUDIT_DIR", sb.audit())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(home.real(&fixture("claude/bash-deny.json")).as_bytes())
        .unwrap();
    let o = child.wait_with_output().unwrap();
    assert_eq!(code(&o), 2);
    assert!(
        stderr(&o).starts_with("saiife: BLOCKED by core.filesystem"),
        "{}",
        stderr(&o)
    );
    let recs: Vec<_> = saiife_audit::store::read_all(&sb.audit())
        .records
        .into_iter()
        .filter(|r| r.kind() == "guard")
        .collect();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].mode.as_deref(), Some("developer"));
    assert_eq!(recs[0].decision, saiife_audit::DecisionKind::Deny);
}

#[test]
fn worker_flooding_stdout_denies() {
    let (_, elapsed, _) = worker_fault("flood");
    assert!(elapsed <= Duration::from_millis(4500), "{elapsed:?}");
}

#[test]
fn worker_never_reading_stdin_denies() {
    // 8 MiB of content: far more than a pipe buffer holds.
    let p = tempfile::tempdir().unwrap();
    let target = p.path().join("big.txt").display().to_string();
    let payload = json!({
        "session_id": "s-m",
        "cwd": p.path(),
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": target, "content": "x".repeat(8 << 20)}
    })
    .to_string();
    let (_, elapsed, _) = worker_fault_with("noread", &payload, &target);
    assert!(
        elapsed >= Duration::from_millis(3000) && elapsed <= Duration::from_millis(4500),
        "{elapsed:?}"
    );
}

/// The parent's own watchdog: whatever hangs, the hook answers (exit 2)
/// before the agent's 10 s hook timeout.
#[test]
fn parent_hang_is_cut_by_the_watchdog() {
    let d = TestDaemon::start(Opts::default());
    let home = common::FixtureHome::new();
    let (o, elapsed, _sb) = managed_with(
        &d.config(),
        &home.real(&fixture("claude/bash-allow.json")),
        &[("SAIIFE_EVAL_FAULT", "parent_hang")],
        &[],
    );
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(
        stderr(&o).contains("saiife: BLOCKED (fail closed): saiife took too long"),
        "{}",
        stderr(&o)
    );
    assert!(
        elapsed >= Duration::from_millis(7000) && elapsed <= Duration::from_millis(8500),
        "{elapsed:?}"
    );
}

#[test]
fn huge_cwd_is_error_denied_without_filesystem_walk() {
    let d = TestDaemon::start(Opts::default());
    let cwd = format!("/{}", "a/".repeat(256 * 1024));
    let payload = json!({
        "session_id": "s-m",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "/etc/hostname"}
    })
    .to_string();
    let (o, elapsed, _sb) = managed(&d.config(), &payload);
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(stderr(&o).contains("fail closed"), "{}", stderr(&o));
    assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
    let r = last_guard(&d);
    assert_eq!(r["decision"], "error_denied", "{r}");
    assert!(r["reason"].as_str().unwrap().contains("cwd"), "{r}");
}

#[test]
fn oversized_session_is_still_recorded() {
    let d = TestDaemon::start(Opts::default());
    let p = tempfile::tempdir().unwrap();
    let f = p.path().join("notes.txt");
    fs::write(&f, "hi").unwrap();
    let payload = json!({
        "session_id": "s".repeat(1200 * 1024),
        "cwd": p.path(),
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": f}
    })
    .to_string();
    let (o, _, _sb) = managed(&d.config(), &payload);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    let r = last_guard(&d);
    assert_eq!(r["decision"], "allow", "{r}");
    let session = r["session"].as_str().unwrap();
    assert!(session.ends_with("[truncated]"), "{}", session.len());
    assert!(session.len() < 8192);
}

/// The account's home from /etc/passwd, not from HOME.
fn passwd_home() -> String {
    let uid = common::daemon::own_uid().to_string();
    fs::read_to_string("/etc/passwd")
        .unwrap()
        .lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() >= 7 && f[2] == uid).then(|| f[5].to_string())
        })
        .expect("own passwd entry")
}

fn file_call(tool: &str, path: &str) -> String {
    let mut input = json!({ "file_path": path });
    if tool == "Write" {
        input["content"] = json!("x");
    }
    json!({
        "session_id": "s-m",
        "cwd": "/",
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": input
    })
    .to_string()
}

/// An agent started with another HOME must not move the `~` rules off the
/// account's real home (A6/A18). `managed_with` already runs the hook with
/// HOME pointing at a temp dir.
#[test]
fn hook_home_does_not_rebind_home_rules() {
    let d = TestDaemon::start(Opts::default());
    let home = passwd_home();
    for (tool, path, pack) in [
        (
            "Read",
            format!("{home}/.claude/.credentials.json"),
            "core.secrets",
        ),
        ("Read", format!("{home}/.ssh/id_rsa"), "core.secrets"),
    ] {
        let (o, _, _sb) = managed(&d.config(), &file_call(tool, &path));
        assert_eq!(code(&o), 2, "{path}: {}", stderr(&o));
        assert!(
            stderr(&o).starts_with(&format!("BLOCKED by {pack}")),
            "{path}: {}",
            stderr(&o)
        );
    }
}

#[test]
fn agent_config_dir_env_does_not_reach_the_worker() {
    let d = TestDaemon::start(Opts::default());
    let home = passwd_home();
    let elsewhere = tempfile::tempdir().unwrap();
    let elsewhere = elsewhere.path().to_str().unwrap();
    let env = [("CLAUDE_CONFIG_DIR", elsewhere), ("CODEX_HOME", elsewhere)];
    for (tool, path, pack) in [
        (
            "Write",
            format!("{home}/.claude/settings.json"),
            "core.self",
        ),
        (
            "Read",
            format!("{home}/.claude/.credentials.json"),
            "core.secrets",
        ),
    ] {
        let (o, _, _sb) = managed_with(&d.config(), &file_call(tool, &path), &env, &[]);
        assert_eq!(code(&o), 2, "{path}: {}", stderr(&o));
        assert!(
            stderr(&o).starts_with(&format!("BLOCKED by {pack}")),
            "{path}: {}",
            stderr(&o)
        );
    }
}

/// A payload whose fields inflate when serialized (`\u0001` is 6 bytes,
/// a 4-byte UTF-8 char is 4) must still be recorded: the hook shrinks the
/// record to the daemon's `MAX_RECORD_BYTES` instead of having it refused.
fn inflated_payload_is_recorded(fill: &str, session_fill: &str, cwd_fill: &str) {
    let d = TestDaemon::start(Opts::default());
    let n = |s: &str, bytes: usize| s.repeat(bytes / s.len());
    let payload = json!({
        "session_id": n(session_fill, 64 * 1024),
        "cwd": format!("/{}", n(cwd_fill, 4095)),
        "permission_mode": n(fill, 1024),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": n(fill, 64 * 1024)}
    })
    .to_string();
    let before = guard_records(&d).len();
    let (o, _, _sb) = managed(&d.config(), &payload);
    assert!(matches!(code(&o), 0 | 2), "stderr: {}", stderr(&o));
    assert!(
        !stderr(&o).contains("did not record"),
        "stderr: {}",
        stderr(&o)
    );
    let recs = guard_records(&d);
    assert_eq!(recs.len(), before + 1, "daemon: {}", d.stderr_text());
    let r = recs.last().unwrap();
    assert!(
        serde_json::to_vec(r).unwrap().len() <= saiife_ipc::msg::MAX_RECORD_BYTES + 512,
        "the daemon adds only a few fields"
    );
    // Allowed only when the record says so.
    if code(&o) == 0 {
        assert_eq!(r["decision"], "allow", "{r}");
    }
}

#[test]
fn control_char_fields_are_still_recorded() {
    inflated_payload_is_recorded("\u{1}", "\u{1}", "\u{1}");
}

#[test]
fn four_byte_char_fields_are_still_recorded() {
    // 4-byte chars alone cannot pass 64 KiB (3 fields of 4 096 chars at
    // 4 bytes); with control chars in two of the fields they do.
    inflated_payload_is_recorded("\u{1F600}", "\u{1}", "\u{1}");
}
