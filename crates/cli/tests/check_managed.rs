//! `saiife check --managed`: the locked-mode hook (plan 9a, Task 7). The
//! guard runs in a worker child, the record goes to the daemon, and every
//! error ends in exit 2 (fail closed). Runs as the current user with every
//! path in a temp dir.
#![cfg(unix)]

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
    managed_as("claude", config, stdin, extra_env, extra_args)
}

/// `managed_with` for `--agent <agent>`.
fn managed_as(
    agent: &str,
    config: &Path,
    stdin: &str,
    extra_env: &[(&str, &str)],
    extra_args: &[&str],
) -> (Output, Duration, Sandbox) {
    let sb = Sandbox::new();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_saiife"));
    cmd.args(["check", "--managed", "--agent", agent, "--system-config"])
        .arg(config)
        .args(extra_args)
        .env("HOME", sb.dir.path().join("home"))
        .env("PATH", "/usr/bin:/bin")
        .env("SAIIFE_DATA_DIR", sb.data())
        .env("SAIIFE_AUDIT_DIR", sb.audit())
        .env_remove("SAIIFE_EVAL_FAULT")
        .env_remove("SAIIFE_HOOK_TIMING")
        // Never the real /etc drop-in: none, unless a test writes one.
        .env(
            "SAIIFE_TEST_CLAUDE_MCP_DROPIN",
            sb.dir.path().join("no-dropin"),
        )
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

/// The steps of a `SAIIFE_HOOK_TIMING=1` trace of an allowed `agent` call of
/// `rel`, each line checked for its form.
fn timing_steps(agent: &str, rel: &str) -> (Vec<String>, String) {
    let d = TestDaemon::start(Opts::default());
    let home = common::FixtureHome::new();
    let payload = home.real(&fixture(rel));
    let (o, _, _sb) = managed_as(
        agent,
        &d.config(),
        &payload,
        &[("SAIIFE_HOOK_TIMING", "1")],
        &[],
    );
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    let err = stderr(&o);
    let steps = err
        .lines()
        .map(|l| {
            let mut f = l.split(' ');
            assert_eq!(f.next(), Some("saiife-timing"), "{l}");
            let step = f.next().unwrap().to_string();
            let ms: f64 = f.next().unwrap().parse().unwrap();
            assert!(ms >= 0.0, "{l}");
            assert_eq!(f.next(), None, "{l}");
            step
        })
        .collect();
    assert_eq!(last_guard(&d)["decision"], "allow");
    (steps, err)
}

const COMMON_STEPS: [&str; 9] = [
    "config",
    "begin.connect",
    "begin.call",
    "stdin",
    "policy",
    "bind",
    "record",
    "append",
    "total",
];

/// SAIIFE_HOOK_TIMING=1 (debug builds, as the tests and ci-locked are): each
/// step's time on stderr, the judgment in the hook included (Claude Code),
/// and the call as it was. No worker is started.
#[test]
fn hook_timing_names_each_step() {
    let (steps, err) = timing_steps("claude", "claude/bash-allow.json");
    let here = [
        "judge.env",
        "judge.start",
        "judge.run",
        "worker.engine",
        "judge.wait",
    ];
    for want in COMMON_STEPS.iter().chain(&here) {
        assert!(steps.iter().any(|s| s == want), "no {want} in {err}");
    }
    assert!(
        !steps
            .iter()
            .any(|s| s == "worker.start" || s == "worker.started"),
        "{err}"
    );

    // Anything else is no trace.
    let d = TestDaemon::start(Opts::default());
    let payload = common::FixtureHome::new().real(&fixture("claude/bash-allow.json"));
    let (o, _, _sb) = managed_with(&d.config(), &payload, &[("SAIIFE_HOOK_TIMING", "0")], &[]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert!(o.stderr.is_empty(), "{}", stderr(&o));
}

/// The worker's steps, for an agent that keeps it.
#[test]
fn hook_timing_names_the_worker_steps() {
    let (steps, err) = timing_steps("codex", "codex/bash-allow.json");
    let worker = [
        "worker.start",
        "worker.started",
        "worker.request",
        "worker.engine",
        "worker.judge",
        "worker.wait",
    ];
    for want in COMMON_STEPS.iter().chain(&worker) {
        assert!(steps.iter().any(|s| s == want), "no {want} in {err}");
    }
    assert!(!steps.iter().any(|s| s.starts_with("judge.")), "{err}");
}

/// A call with nothing to judge (a cwd with a NUL byte) drops the worker
/// started before the payload was read, unsent, and is denied as before.
/// Codex: Claude Code's calls start no worker.
#[test]
fn an_early_worker_with_nothing_to_judge_is_dropped() {
    let d = TestDaemon::start(Opts::default());
    let payload = json!({
        "session_id": "s-m",
        "cwd": "/tmp/a\u{0}b",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "ls"}
    })
    .to_string();
    let (o, elapsed, _sb) = managed_as("codex", &d.config(), &payload, &[], &[]);
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(stderr(&o).contains("NUL byte"), "{}", stderr(&o));
    assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");
    let r = last_guard(&d);
    assert_eq!(r["decision"], "error_denied");
    assert_eq!(r["input"], "", "{r}");
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
fn managed_write_to_daemon_audit_dir_denied() {
    let d = TestDaemon::start(Opts::default());
    let target = d.audit_dir().join("x.jsonl");
    let (o, _, _sb) = managed(
        &d.config(),
        &file_call("Write", &target.display().to_string()),
    );
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(
        stderr(&o).starts_with("BLOCKED by core.lock"),
        "{}",
        stderr(&o)
    );
    let r = last_guard(&d);
    assert_eq!(r["decision"], "deny");
    assert_eq!(r["pack"], "core.lock");
    assert!(!target.exists());
}

#[test]
fn managed_sudo_denied() {
    let d = TestDaemon::start(Opts::default());
    let cwd = tempfile::tempdir().unwrap();
    let (o, _, _sb) = managed(&d.config(), &bash(cwd.path(), "sudo ls"));
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(
        stderr(&o).starts_with("BLOCKED by core.lock"),
        "{}",
        stderr(&o)
    );
    let r = last_guard(&d);
    assert_eq!(r["decision"], "deny");
    assert_eq!(r["pack"], "core.lock");
    assert_eq!(r["input"], "sudo ls");
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

/// A worker `fault` on a Codex call: Claude Code's calls start no worker.
fn worker_fault(fault: &str) -> (Output, Duration, TestDaemon) {
    let home = common::FixtureHome::new();
    worker_fault_with(
        fault,
        &home.real(&fixture("codex/bash-allow.json")),
        "cargo test",
    )
}

fn worker_fault_with(fault: &str, payload: &str, input: &str) -> (Output, Duration, TestDaemon) {
    let d = TestDaemon::start(Opts::default());
    let (o, elapsed, _sb) = managed_as(
        "codex",
        &d.config(),
        payload,
        &[("SAIIFE_EVAL_FAULT", fault)],
        &[],
    );
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

/// Claude Code's calls are judged in the hook (plan 21, option B): with no
/// worker to be had, they are still judged, allowed and denied as before.
#[test]
fn claude_judges_in_process() {
    let d = TestDaemon::start(Opts::default());
    let home = common::FixtureHome::new();
    let no_worker = [("SAIIFE_EVAL_FAULT", "worker_spawn")];
    let allow = home.real(&fixture("claude/bash-allow.json"));
    let (o, _, _sb) = managed_with(&d.config(), &allow, &no_worker, &[]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert_eq!(last_guard(&d)["decision"], "allow");
    let deny = home.real(&fixture("claude/bash-deny.json"));
    let (o, _, _sb) = managed_with(&d.config(), &deny, &no_worker, &[]);
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(stderr(&o).starts_with("BLOCKED by "), "{}", stderr(&o));
    let r = last_guard(&d);
    assert_eq!(r["decision"], "deny", "{r}");
    assert!(r["rule"].is_string(), "{r}");
}

/// Codex keeps the worker: a dead hook would let its call run.
#[test]
fn codex_still_uses_the_worker() {
    let (o, _, d) = worker_fault("worker_spawn");
    assert!(stderr(&o).contains("could not start"), "{}", stderr(&o));
    assert_eq!(last_guard(&d)["agent"], "codex");
}

/// The in-hook judgment of a Claude Code call that fails, recorded as
/// `error_denied`: `(output, elapsed, daemon, record)`.
fn in_process_fault(fault: &str) -> (Output, Duration, TestDaemon, Value) {
    let d = TestDaemon::start(Opts::default());
    let home = common::FixtureHome::new();
    let payload = home.real(&fixture("claude/bash-allow.json"));
    let (o, elapsed, _sb) =
        managed_with(&d.config(), &payload, &[("SAIIFE_EVAL_FAULT", fault)], &[]);
    assert_eq!(code(&o), 2, "{fault}: stderr: {}", stderr(&o));
    assert!(o.stdout.is_empty());
    assert!(
        stderr(&o).contains("saiife: BLOCKED (fail closed): the guard failed in the hook ("),
        "{fault}: {}",
        stderr(&o)
    );
    let r = last_guard(&d);
    assert_eq!(r["decision"], "error_denied", "{fault}: {r}");
    assert_eq!(r["input"], "ls -la", "{fault}: {r}");
    assert_eq!(r["tool"], "Bash", "{fault}: {r}");
    (o, elapsed, d, r)
}

#[test]
fn claude_in_process_timeout_denies() {
    let (_, elapsed, _, r) = in_process_fault("hang");
    assert_eq!(
        r["reason"],
        "the guard failed in the hook (no answer within 3 s)"
    );
    assert!(
        elapsed >= Duration::from_millis(3000) && elapsed <= Duration::from_millis(4500),
        "{elapsed:?}"
    );
}

#[test]
fn claude_in_process_panic_denies() {
    let (o, elapsed, _, r) = in_process_fault("panic");
    assert_eq!(r["reason"], "the guard failed in the hook (it panicked)");
    // The reason Claude Code shows is the deny alone, as a worker's panic is.
    assert!(stderr(&o).starts_with("saiife: BLOCKED"), "{}", stderr(&o));
    assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");
}

/// A crash of the judgment in the hook kills the hook: no guard record, and
/// the daemon's plan 20 `no_verdict` record of the bound call. Claude Code's
/// `onFailure: "block"` blocks the call, and its co-signer denies it.
#[test]
fn claude_in_process_crash_is_no_verdict() {
    in_process_crash("abort");
}

/// The same for a SIGSEGV in the hook's own judgment: the locked-linux and
/// locked-macos jobs send `SAIIFE_EVAL_FAULT=segv` to a Claude Code hook,
/// which has judged in-process since plan 21 (no worker there to crash).
#[test]
fn claude_in_process_segv_is_no_verdict() {
    use std::os::unix::process::ExitStatusExt;
    let o = in_process_crash("segv");
    assert_eq!(o.status.signal(), Some(11), "SIGSEGV: {o:?}");
}

/// The hook of a Claude Code call with its judgment crashed by `fault`:
/// killed by a signal, a bound `no_verdict` record, and no guard record.
fn in_process_crash(fault: &str) -> Output {
    let d = TestDaemon::start(Opts::default());
    let home = common::FixtureHome::new();
    let payload = home.real(&fixture("claude/bash-allow.json"));
    let (o, _, _sb) = managed_with(&d.config(), &payload, &[("SAIIFE_EVAL_FAULT", fault)], &[]);
    assert_eq!(o.status.code(), None, "{fault}: killed by a signal: {o:?}");
    let until = Instant::now() + Duration::from_secs(15);
    let r = loop {
        if let Some(r) = d.of_kind("hook").pop() {
            break r;
        }
        assert!(
            Instant::now() < until,
            "no hook record: {}",
            d.stderr_text()
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(r["decision"], "no_verdict", "{r}");
    assert_eq!(r["event"], "no_verdict", "{r}");
    assert_eq!(r["bound"], true, "{r}");
    assert_eq!(r["tool"], "Bash", "{r}");
    assert_eq!(r["tool_use_id"], "toolu_02", "{r}");
    assert!(guard_records(&d).is_empty());
    o
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
    // `worker_fault_with` asserts exit 2 and an `error_denied` record whose
    // reason starts `guard worker failed`. Reading and copying 8 MiB on a
    // loaded machine can take a while: the bound that matters is the
    // worker's 3 s deadline below and the parent's 7 s watchdog above.
    let (_, elapsed, _) = worker_fault_with("noread", &payload, &target);
    assert!(
        elapsed >= Duration::from_millis(3000) && elapsed < Duration::from_millis(7000),
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

/// The account's home from the system's entry (/etc/passwd; Directory
/// Services on macOS), as the hook's worker gets it, not from HOME.
fn passwd_home() -> String {
    saiife_ipc::client::system_entry(common::daemon::own_uid())
        .expect("own passwd entry")
        .home
        .display()
        .to_string()
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

/// A ConfigChange payload for `file_path` (spec §6.1.1).
fn config_change(source: &str, file_path: &Path) -> String {
    let mut v: Value = serde_json::from_str(&fixture("claude/config-change.json")).unwrap();
    v["source"] = json!(source);
    v["file_path"] = json!(file_path);
    v["cwd"] = json!("/");
    v.to_string()
}

fn config_change_call(d: &TestDaemon, payload: &str) -> (Output, Sandbox) {
    let (o, _, sb) = managed_with(&d.config(), payload, &[], &["--event", "config-change"]);
    (o, sb)
}

#[test]
fn config_change_touching_hooks_denied_and_recorded() {
    let d = TestDaemon::start(Opts::default());
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("settings.json");
    fs::write(&f, r#"{"hooks":{"PreToolUse":[]},"theme":"dark"}"#).unwrap();
    let (o, sb) = config_change_call(&d, &config_change("user_settings", &f));
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(o.stdout.is_empty());
    assert!(
        stderr(&o).starts_with("BLOCKED by core.self: settings change touches hooks"),
        "{}",
        stderr(&o)
    );
    let r = last_guard(&d);
    assert_eq!(r["tool"], "ConfigChange", "{r}");
    assert_eq!(r["decision"], "deny", "{r}");
    assert_eq!(r["pack"], "core.self", "{r}");
    assert_eq!(r["rule"], "config-change", "{r}");
    assert_eq!(r["input"], format!("user_settings {}", f.display()), "{r}");
    assert_eq!(r["mode"], "locked");
    assert!(sb.is_untouched());
}

#[test]
fn config_change_harmless_allowed_and_recorded() {
    let d = TestDaemon::start(Opts::default());
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("settings.json");
    fs::write(&f, r#"{"theme":"dark"}"#).unwrap();
    let (o, _sb) = config_change_call(&d, &config_change("project_settings", &f));
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert!(o.stdout.is_empty() && o.stderr.is_empty(), "{}", stderr(&o));
    let r = last_guard(&d);
    assert_eq!(r["tool"], "ConfigChange", "{r}");
    assert_eq!(r["decision"], "allow", "{r}");
    assert_eq!(
        r["input"],
        format!("project_settings {}", f.display()),
        "{r}"
    );
}

#[test]
fn config_change_unreadable_settings_denied() {
    let d = TestDaemon::start(Opts::default());
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("settings.json");
    fs::write(&f, "{\"hooks\": ").unwrap();
    let (o, _sb) = config_change_call(&d, &config_change("local_settings", &f));
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(
        stderr(&o).contains("settings change could not be checked"),
        "{}",
        stderr(&o)
    );
    assert_eq!(last_guard(&d)["decision"], "deny");
    // Removed: it cannot be verified.
    fs::remove_file(&f).unwrap();
    let (o, _sb) = config_change_call(&d, &config_change("user_settings", &f));
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(
        stderr(&o).contains("settings file cannot be verified"),
        "{}",
        stderr(&o)
    );
    // A key outside the allowlist.
    fs::write(&f, r#"{"statusLine":{"type":"command","command":"x"}}"#).unwrap();
    let (o, _sb) = config_change_call(&d, &config_change("user_settings", &f));
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(stderr(&o).contains("touches statusLine"), "{}", stderr(&o));
}

/// The MCP tool fixture of `agent`, its server `docs` not listed.
fn mcp_denied(agent: &str, rel: &str) {
    let d = TestDaemon::start(Opts::default());
    let home = common::FixtureHome::new();
    let (o, _, sb) = managed_as(agent, &d.config(), &home.real(&fixture(rel)), &[], &[]);
    assert_eq!(code(&o), 2, "{rel}: stderr: {}", stderr(&o));
    assert!(o.stdout.is_empty());
    assert_eq!(
        stderr(&o).trim_end(),
        "BLOCKED by guard.mcp: MCP server docs is not in [guard.mcp] allow_servers",
        "{rel}"
    );
    let r = last_guard(&d);
    assert_eq!(r["decision"], "deny", "{r}");
    assert_eq!(r["pack"], "guard.mcp", "{r}");
    assert_eq!(r["rule"], "mcp_server_not_allowed", "{r}");
    assert_eq!(r["tool"], "mcp__docs__search", "{r}");
    assert_eq!(r["agent"], agent, "{r}");
    assert!(sb.is_untouched());
}

#[test]
fn unlisted_mcp_server_denied() {
    mcp_denied("codex", "codex/mcp-tool.json");
    mcp_denied("claude", "claude/mcp-tool.json");
}

#[test]
fn listed_mcp_server_allowed_not_judged() {
    let d = TestDaemon::start(Opts {
        extra: "[guard.mcp]\nallow_servers = [\"docs\"]\n".into(),
        ..Opts::default()
    });
    let home = common::FixtureHome::new();
    for (agent, rel) in [
        ("codex", "codex/mcp-tool.json"),
        ("claude", "claude/mcp-tool.json"),
    ] {
        let (o, _, _sb) = managed_as(agent, &d.config(), &home.real(&fixture(rel)), &[], &[]);
        assert_eq!(code(&o), 0, "{rel}: stderr: {}", stderr(&o));
        let r = last_guard(&d);
        assert_eq!(r["decision"], "allow", "{r}");
        assert_eq!(r["reason"], "tool not judged", "{r}");
        assert_eq!(r["tool"], "mcp__docs__search", "{r}");
    }
    // A server named `docs__evil` does not pass as the listed `docs`.
    let mut v: Value = serde_json::from_str(&fixture("claude/mcp-tool.json")).unwrap();
    v["tool_name"] = json!("mcp__docs__evil__search");
    v["cwd"] = json!("/");
    let (o, _, _sb) = managed_as("claude", &d.config(), &v.to_string(), &[], &[]);
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(
        stderr(&o).starts_with("BLOCKED by guard.mcp: MCP server mcp__docs__evil__search"),
        "{}",
        stderr(&o)
    );
    assert_eq!(last_guard(&d)["rule"], "mcp_server_not_allowed");
    // Nor does `docs_` (Claude Code's form of `docs.`).
    v["tool_name"] = json!("mcp__docs___search");
    let (o, _, _sb) = managed_as("claude", &d.config(), &v.to_string(), &[], &[]);
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(
        stderr(&o).starts_with("BLOCKED by guard.mcp: MCP server mcp__docs___search"),
        "{}",
        stderr(&o)
    );
}

/// A claude or codex payload calling `tool`.
fn mcp_payload(agent: &str, tool: &str) -> String {
    let rel = format!("{agent}/mcp-tool.json");
    let mut v: Value = serde_json::from_str(&fixture(&rel)).unwrap();
    v["tool_name"] = json!(tool);
    v["cwd"] = json!("/");
    v.to_string()
}

#[test]
fn saiife_server_allowed_as_brokered() {
    let d = TestDaemon::start(Opts::default());
    let agent = "claude";
    let drop_in = d.path().join("60-saiife-mcp.json");
    std::fs::write(
        &drop_in,
        saiife_agents::claude::managed_mcp_settings(&["linear".into()]),
    )
    .unwrap();
    let seam = drop_in.display().to_string();
    let (o, _, _sb) = managed_as(
        agent,
        &d.config(),
        &mcp_payload(agent, "mcp__saiife__shop_orders_list"),
        &[("SAIIFE_TEST_CLAUDE_MCP_DROPIN", &seam)],
        &[],
    );
    assert_eq!(code(&o), 0, "{agent}: stderr: {}", stderr(&o));
    let r = last_guard(&d);
    assert_eq!(r["decision"], "allow", "{r}");
    assert_eq!(r["pack"], "guard.mcp", "{r}");
    assert_eq!(r["rule"], "mcp_brokered", "{r}");
    assert_eq!(r["reason"], "brokered: judged by the saiife daemon", "{r}");
    assert_eq!(r["tool"], "mcp__saiife__shop_orders_list", "{r}");
    assert_eq!(r["agent"], agent, "{r}");
}

/// Final review I3: on Claude Code `saiife` is brokered only while the
/// managed MCP drop-in pins its command. Missing, or with a wrong pin: a
/// server like any other, denied unless listed.
#[test]
fn claude_saiife_needs_the_pinned_drop_in() {
    let d = TestDaemon::start(Opts::default());
    let payload = mcp_payload("claude", "mcp__saiife__api_call");
    let blocked = "BLOCKED by guard.mcp: MCP server saiife is not in [guard.mcp] allow_servers";
    // Missing (managed_as points the seam at a file that is not there).
    let (o, _, _sb) = managed_as("claude", &d.config(), &payload, &[], &[]);
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert_eq!(stderr(&o).trim_end(), blocked);
    assert_eq!(last_guard(&d)["rule"], "mcp_server_not_allowed");
    // A wrong pin: extra arguments on the command.
    let drop_in = d.path().join("60-saiife-mcp.json");
    std::fs::write(
        &drop_in,
        r#"{"allowedMcpServers": [{"serverCommand": ["/opt/saiife/bin/saiife", "mcp", "--wait", "5m"]}]}"#,
    )
    .unwrap();
    let seam = drop_in.display().to_string();
    let env = [("SAIIFE_TEST_CLAUDE_MCP_DROPIN", seam.as_str())];
    let (o, _, _sb) = managed_as("claude", &d.config(), &payload, &env, &[]);
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert_eq!(stderr(&o).trim_end(), blocked);
    // The good drop-in: brokered.
    std::fs::write(&drop_in, saiife_agents::claude::managed_mcp_settings(&[])).unwrap();
    let (o, _, _sb) = managed_as("claude", &d.config(), &payload, &env, &[]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert_eq!(last_guard(&d)["rule"], "mcp_brokered");
}

/// Controller ruling (T9 follow-up): Codex pins no MCP server command, so
/// a `saiife` server there may be the agent's own. Denied unless listed;
/// listed, it is allowed by name ("tool not judged"), unpinned.
#[test]
fn codex_saiife_server_needs_listing() {
    let d = TestDaemon::start(Opts::default());
    let payload = mcp_payload("codex", "mcp__saiife__api_call");
    let (o, _, sb) = managed_as("codex", &d.config(), &payload, &[], &[]);
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert_eq!(
        stderr(&o).trim_end(),
        "BLOCKED by guard.mcp: MCP server saiife is not in [guard.mcp] allow_servers"
    );
    let r = last_guard(&d);
    assert_eq!(r["decision"], "deny", "{r}");
    assert_eq!(r["rule"], "mcp_server_not_allowed", "{r}");
    assert_eq!(r["agent"], "codex", "{r}");
    assert!(sb.is_untouched());

    let d = TestDaemon::start(Opts {
        extra: "[guard.mcp]\nallow_servers = [\"saiife\"]\n".into(),
        ..Opts::default()
    });
    let (o, _, _sb) = managed_as("codex", &d.config(), &payload, &[], &[]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    let r = last_guard(&d);
    assert_eq!(r["decision"], "allow", "{r}");
    assert_ne!(r["rule"], "mcp_brokered", "{r}");
    assert_eq!(r["reason"], "tool not judged", "{r}");
    assert_eq!(r["tool"], "mcp__saiife__api_call", "{r}");
}

#[test]
fn saiife_lookalike_names_denied() {
    let d = TestDaemon::start(Opts::default());
    for tool in ["mcp__saiife__x__y", "mcp__saiife___x", "mcp__saiife__"] {
        let (o, _, _sb) = managed_as(
            "claude",
            &d.config(),
            &mcp_payload("claude", tool),
            &[],
            &[],
        );
        assert_eq!(code(&o), 2, "{tool}: stderr: {}", stderr(&o));
        assert!(
            stderr(&o).starts_with("BLOCKED by guard.mcp"),
            "{}",
            stderr(&o)
        );
        assert_eq!(last_guard(&d)["rule"], "mcp_server_not_allowed");
    }
}

/// Gemini CLI pins no MCP server command, so `saiife` is never brokered
/// there: it needs both the server identity and a listing.
#[test]
fn gemini_saiife_needs_server_identity() {
    let call = |d: &TestDaemon, ctx: Option<Value>| {
        let mut v = json!({
            "session_id": "g-1",
            "cwd": "/",
            "hook_event_name": "BeforeTool",
            "tool_name": "mcp_saiife_shop_orders_list",
            "tool_input": {}
        });
        if let Some(c) = ctx {
            v["mcp_context"] = c;
        }
        managed_as("gemini", &d.config(), &v.to_string(), &[], &[]).0
    };
    let d = TestDaemon::start(Opts::default());
    let o = call(&d, Some(json!({"server_name": "saiife"})));
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert_eq!(
        stderr(&o).trim_end(),
        "BLOCKED by guard.mcp: MCP server saiife is not in [guard.mcp] allow_servers"
    );
    assert_eq!(last_guard(&d)["rule"], "mcp_server_not_allowed");

    let d = TestDaemon::start(Opts {
        extra: "[guard.mcp]\nallow_servers = [\"saiife\"]\n".into(),
        ..Opts::default()
    });
    let o = call(&d, None);
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    let o = call(&d, Some(json!({"server_name": "saiife_x"})));
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    let o = call(&d, Some(json!({"server_name": "saiife"})));
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    let r = last_guard(&d);
    assert_eq!(r["decision"], "allow", "{r}");
    assert_ne!(r["rule"], "mcp_brokered", "{r}");
}

/// Controller ruling: on Gemini only an explicit server identity in the
/// payload allows an MCP call; `mcp_docs_x` alone could be server `docs_x`.
#[test]
fn gemini_mcp_needs_server_identity() {
    let d = TestDaemon::start(Opts {
        extra: "[guard.mcp]\nallow_servers = [\"docs\"]\n".into(),
        ..Opts::default()
    });
    let call = |ctx: Option<Value>| {
        let mut v = json!({
            "session_id": "g-1",
            "cwd": "/",
            "hook_event_name": "BeforeTool",
            "tool_name": "mcp_docs_search",
            "tool_input": {"query": "hooks"}
        });
        if let Some(c) = ctx {
            v["mcp_context"] = c;
        }
        managed_as("gemini", &d.config(), &v.to_string(), &[], &[]).0
    };
    let o = call(None);
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert_eq!(
        stderr(&o).trim_end(),
        "BLOCKED by guard.mcp: MCP server unknown on Gemini"
    );
    let r = last_guard(&d);
    assert_eq!(r["rule"], "mcp_server_not_allowed", "{r}");
    let o = call(Some(json!({"server_name": "docs_x"})));
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(
        stderr(&o).contains("MCP server docs_x is not in"),
        "{}",
        stderr(&o)
    );
    let o = call(Some(json!({"server_name": "docs", "tool_name": "search"})));
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert_eq!(last_guard(&d)["reason"], "tool not judged");
    // A duplicate `mcp_context` key: the payload does not parse, so the
    // server is unknown (the second key cannot hide the call).
    let o = managed_as(
        "gemini",
        &d.config(),
        r#"{"session_id":"g-1","cwd":"/","hook_event_name":"BeforeTool","tool_name":"search","tool_input":{},"mcp_context":{"server_name":"docs"},"mcp_context":{}}"#,
        &[],
        &[],
    )
    .0;
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert_eq!(
        stderr(&o).trim_end(),
        "BLOCKED by guard.mcp: MCP server unknown on Gemini"
    );
    // A bare tool name with an `mcp_context` but no server: unknown.
    let o = managed_as(
        "gemini",
        &d.config(),
        r#"{"session_id":"g-1","cwd":"/","hook_event_name":"BeforeTool","tool_name":"search","tool_input":{},"mcp_context":{}}"#,
        &[],
        &[],
    )
    .0;
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert_eq!(
        stderr(&o).trim_end(),
        "BLOCKED by guard.mcp: MCP server unknown on Gemini"
    );
}

#[test]
fn event_requires_managed() {
    let sb = Sandbox::new();
    let o = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args([
            "check",
            "--hook-exit",
            "--agent",
            "claude",
            "--event",
            "config-change",
        ])
        .env("HOME", sb.dir.path().join("home"))
        .env("SAIIFE_DATA_DIR", sb.data())
        .env("SAIIFE_AUDIT_DIR", sb.audit())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(stderr(&o).contains("--managed"), "{}", stderr(&o));
    assert!(sb.is_untouched());
}

#[test]
fn unknown_event_with_managed_fails_closed() {
    let d = TestDaemon::start(Opts::default());
    let home = common::FixtureHome::new();
    let (o, _, _sb) = managed_with(
        &d.config(),
        &home.real(&fixture("claude/config-change.json")),
        &[],
        &["--event", "session-start"],
    );
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(stderr(&o).contains("fail closed"), "{}", stderr(&o));
    assert_eq!(last_guard(&d)["decision"], "error_denied");
}

// Plan 20, Task 3: the hook registers with the daemon (`hook.begin`) before
// it reads its input, and names the call (`hook.bind`) once it has.

/// One frame a [`FakeDaemon`] read: the connection's index, the op, its args, and when.
#[derive(Debug, Clone)]
struct Seen {
    conn: usize,
    op: String,
    args: Value,
    at: Instant,
}

/// How a [`FakeDaemon`] answers `hook.begin`.
#[derive(Debug, Clone, Copy)]
enum Begin {
    Answer,
    /// `ok`, this long after it arrived.
    After(Duration),
    /// No answer: the connection is closed.
    Break,
}

/// A locked-mode daemon that answers every op `ok` (an append with a
/// `seq`, `grant.consume` with no grant) and logs what it reads. With
/// `hang_approval`, it never answers `approval.create`.
struct FakeDaemon {
    seen: std::sync::Arc<std::sync::Mutex<Vec<Seen>>>,
    begun: std::sync::mpsc::Receiver<()>,
}

impl FakeDaemon {
    fn start(d: &TestDaemon, hang_approval: bool) -> FakeDaemon {
        FakeDaemon::start_with(d, hang_approval, Begin::Answer)
    }

    fn start_with(d: &TestDaemon, hang_approval: bool, begin: Begin) -> FakeDaemon {
        let l = fake_socket_dir(d);
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Seen>::new()));
        let (tx, begun) = std::sync::mpsc::channel();
        let log = seen.clone();
        std::thread::spawn(move || {
            for (conn, s) in l.incoming().enumerate() {
                let Ok(mut s) = s else { return };
                let log = log.clone();
                let tx = tx.clone();
                std::thread::spawn(move || {
                    while let Ok(mut m) = read_frame(&mut s) {
                        // A request's args sit beside its `id` and `op`.
                        let id = m.remove("id").unwrap_or(Value::Null);
                        let op = m.remove("op");
                        let op = op.as_ref().and_then(Value::as_str).unwrap_or_default();
                        let op = op.to_string();
                        log.lock().unwrap().push(Seen {
                            conn,
                            op: op.clone(),
                            args: Value::Object(m),
                            at: Instant::now(),
                        });
                        if op == "hook.begin" {
                            match begin {
                                Begin::Answer => {}
                                Begin::After(t) => std::thread::sleep(t),
                                Begin::Break => return,
                            }
                        }
                        let ans = match op.as_str() {
                            "hello" => json!({"id": id, "ok": true, "proto": 1, "mode": "locked"}),
                            "audit.append" => json!({"id": id, "ok": true, "seq": 1}),
                            "grant.consume" => json!({"id": id, "ok": true, "granted": false}),
                            "approval.create" if hang_approval => {
                                std::thread::sleep(Duration::from_secs(10));
                                return;
                            }
                            "approval.create" => json!({"id": id, "ok": true, "request": 7}),
                            _ => json!({"id": id, "ok": true}),
                        };
                        if op == "hook.begin" {
                            let _ = tx.send(());
                        }
                        if write_frame(&mut s, &ans).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        FakeDaemon { seen, begun }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn ops(&self) -> Vec<(usize, String)> {
        self.seen().into_iter().map(|s| (s.conn, s.op)).collect()
    }
}

fn ops_of(list: &[(usize, &str)]) -> Vec<(usize, String)> {
    list.iter().map(|(c, o)| (*c, o.to_string())).collect()
}

#[test]
fn begin_comes_before_stdin_is_read() {
    let d = TestDaemon::prepare(&Opts::default());
    let fake = FakeDaemon::start(&d, false);
    let sb = Sandbox::new();
    let mut child = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["check", "--managed", "--agent", "claude", "--system-config"])
        .arg(d.config())
        .env("HOME", sb.dir.path().join("home"))
        .env("PATH", "/usr/bin:/bin")
        .env("SAIIFE_DATA_DIR", sb.data())
        .env("SAIIFE_AUDIT_DIR", sb.audit())
        .env_remove("SAIIFE_EVAL_FAULT")
        .env(
            "SAIIFE_TEST_CLAUDE_MCP_DROPIN",
            sb.dir.path().join("no-dropin"),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Not a byte written yet, stdin still open: the begin must arrive.
    let mut sin = child.stdin.take().unwrap();
    let begun = fake.begun.recv_timeout(common::daemon::HANG_GUARD);
    let before = fake.ops();
    let home = common::FixtureHome::new();
    sin.write_all(home.real(&fixture("claude/bash-allow.json")).as_bytes())
        .unwrap();
    drop(sin);
    let o = child.wait_with_output().unwrap();
    assert!(begun.is_ok(), "no hook.begin; stderr: {}", stderr(&o));
    assert_eq!(before, ops_of(&[(0, "hello"), (0, "hook.begin")]));
    let begin = &fake.seen()[1].args;
    assert_eq!(begin["agent"], "claude");
    assert!(begin["event"].is_null(), "{begin}");
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
}

#[test]
fn begin_names_the_event() {
    let d = TestDaemon::prepare(&Opts::default());
    let fake = FakeDaemon::start(&d, false);
    let home = common::FixtureHome::new();
    let (o, _, _sb) = managed_with(
        &d.config(),
        &home.real(&fixture("claude/config-change.json")),
        &[],
        &["--event", "config-change"],
    );
    let seen = fake.seen();
    let begin = seen.iter().find(|s| s.op == "hook.begin").unwrap();
    assert_eq!(
        begin.args["event"],
        "config-change",
        "stderr: {}",
        stderr(&o)
    );
}

/// The payload is read while the begin is on its way (a helper thread
/// sends it), but nothing acts on it before the begin is answered: a
/// payload larger than a pipe's buffer is taken in whole while the daemon
/// holds the begin, and the bind comes only after the begin's answer.
#[test]
fn payload_is_read_while_the_begin_waits_but_not_acted_on() {
    let hold = Duration::from_millis(800);
    let d = TestDaemon::prepare(&Opts::default());
    let fake = FakeDaemon::start_with(&d, false, Begin::After(hold));
    let sb = Sandbox::new();
    let mut child = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["check", "--managed", "--agent", "claude", "--system-config"])
        .arg(d.config())
        .env("HOME", sb.dir.path().join("home"))
        .env("PATH", "/usr/bin:/bin")
        .env("SAIIFE_DATA_DIR", sb.data())
        .env("SAIIFE_AUDIT_DIR", sb.audit())
        .env_remove("SAIIFE_EVAL_FAULT")
        .env(
            "SAIIFE_TEST_CLAUDE_MCP_DROPIN",
            sb.dir.path().join("no-dropin"),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let home = common::FixtureHome::new();
    let mut v: Value =
        serde_json::from_str(&home.real(&fixture("claude/bash-allow.json"))).unwrap();
    // Over a pipe's 64 KiB buffer, under the 256 KiB a judged call may hold.
    v["padding"] = "p".repeat(200 * 1024).into();
    let data = v.to_string();
    let mut sin = child.stdin.take().unwrap();
    let w = std::thread::spawn(move || {
        sin.write_all(data.as_bytes()).unwrap();
        drop(sin);
        Instant::now()
    });
    let o = child.wait_with_output().unwrap();
    let written = w.join().unwrap();
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    let seen = fake.seen();
    let ops: Vec<(usize, String)> = seen.iter().map(|s| (s.conn, s.op.clone())).collect();
    assert_eq!(
        ops,
        ops_of(&[
            (0, "hello"),
            (0, "hook.begin"),
            (0, "hook.bind"),
            (0, "audit.append")
        ])
    );
    let begin = seen[1].at;
    assert!(
        written < begin + hold,
        "the payload was not read while the begin waited"
    );
    assert!(
        seen[2].at >= begin + hold,
        "the bind came before the begin's answer"
    );
}

/// A begin that breaks the connection fails the call closed, with no
/// record and no bind, though the payload was read meanwhile.
#[test]
fn a_broken_begin_fails_closed() {
    let d = TestDaemon::prepare(&Opts::default());
    let fake = FakeDaemon::start_with(&d, false, Begin::Break);
    let home = common::FixtureHome::new();
    let mut v: Value =
        serde_json::from_str(&home.real(&fixture("claude/bash-allow.json"))).unwrap();
    // Over a pipe's 64 KiB buffer, under the 256 KiB a judged call may hold.
    v["padding"] = "p".repeat(200 * 1024).into();
    let (o, _, _sb) = managed(&d.config(), &v.to_string());
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(
        stderr(&o).starts_with("saiife: BLOCKED (fail closed): cannot reach the audit daemon"),
        "{}",
        stderr(&o)
    );
    assert_eq!(fake.ops(), ops_of(&[(0, "hello"), (0, "hook.begin")]));
}

#[test]
fn bind_carries_the_key() {
    let d = TestDaemon::prepare(&Opts::default());
    let fake = FakeDaemon::start(&d, false);
    let home = common::FixtureHome::new();
    let payload = home.real(&fixture("claude/bash-allow.json"));
    let (o, _, _sb) = managed(&d.config(), &payload);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    let seen = fake.seen();
    let bind = seen.iter().find(|s| s.op == "hook.bind").unwrap();
    let key: saiife_ipc::hookkey::HookKey = serde_json::from_value(bind.args.clone()).unwrap();
    assert_eq!(
        key,
        saiife_ipc::hookkey::hook_key("claude", &payload).unwrap()
    );
    assert_eq!(key.session.as_deref(), Some("c-1"));
    assert_eq!(key.tool_use_id.as_deref(), Some("toolu_02"));
}

/// The append names the bound key beside the record (`tool_use_id`,
/// `input_sha256`), so the daemon settles that key and no other; the
/// record shows the id but never the input hash; the bind names the tool.
#[test]
fn append_names_the_bound_key_beside_the_record() {
    let d = TestDaemon::prepare(&Opts::default());
    let fake = FakeDaemon::start(&d, false);
    let home = common::FixtureHome::new();
    let payload = home.real(&fixture("claude/bash-allow.json"));
    let (o, _, _sb) = managed(&d.config(), &payload);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    let key = saiife_ipc::hookkey::hook_key("claude", &payload).unwrap();
    let seen = fake.seen();
    let bind = seen.iter().find(|s| s.op == "hook.bind").unwrap();
    assert_eq!(bind.args["tool"], "Bash", "{}", bind.args);
    let append = &seen.iter().find(|s| s.op == "audit.append").unwrap().args;
    assert_eq!(append["tool_use_id"], "toolu_02", "{append}");
    assert_eq!(
        append["input_sha256"],
        key.input_sha256.as_str(),
        "{append}"
    );
    let rec = &append["rec"];
    assert_eq!(rec["tool_use_id"], "toolu_02", "{rec}");
    assert!(rec.get("input_sha256").is_none(), "{rec}");
    assert!(!rec.to_string().contains(&key.input_sha256), "{rec}");
}

/// A payload without a tool call id: the append carries the hash only,
/// and neither the append nor the record has an id.
#[test]
fn append_without_tool_use_id_carries_the_hash_only() {
    let d = TestDaemon::prepare(&Opts::default());
    let fake = FakeDaemon::start(&d, false);
    let project = tempfile::tempdir().unwrap();
    let payload = bash(project.path(), "ls");
    let (o, _, _sb) = managed(&d.config(), &payload);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    let key = saiife_ipc::hookkey::hook_key("claude", &payload).unwrap();
    assert!(key.tool_use_id.is_none());
    let seen = fake.seen();
    let append = &seen.iter().find(|s| s.op == "audit.append").unwrap().args;
    assert!(append.get("tool_use_id").is_none(), "{append}");
    assert_eq!(
        append["input_sha256"],
        key.input_sha256.as_str(),
        "{append}"
    );
    let rec = &append["rec"];
    assert!(rec.get("tool_use_id").is_none(), "{rec}");
    assert!(rec.get("input_sha256").is_none(), "{rec}");
}

/// The id in the record is masked and cut to 256 bytes; the append's own
/// argument is the id as bound.
#[test]
fn recorded_tool_use_id_is_masked() {
    let d = TestDaemon::prepare(&Opts::default());
    let fake = FakeDaemon::start(&d, false);
    let project = tempfile::tempdir().unwrap();
    let id = concat!("toolu_ghp_", "abcdefghijklmnopqrstuvwxyz0123456789");
    let mut v: Value = serde_json::from_str(&bash(project.path(), "ls")).unwrap();
    v["tool_use_id"] = id.into();
    let (o, _, _sb) = managed(&d.config(), &v.to_string());
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    let seen = fake.seen();
    let append = &seen.iter().find(|s| s.op == "audit.append").unwrap().args;
    assert_eq!(append["tool_use_id"], id);
    let shown = append["rec"]["tool_use_id"].as_str().unwrap();
    assert!(!shown.contains("abcdefghij"), "{shown}");
}

#[test]
fn bind_precedes_append_on_one_connection() {
    let d = TestDaemon::prepare(&Opts::default());
    let fake = FakeDaemon::start(&d, false);
    let home = common::FixtureHome::new();
    let (o, _, _sb) = managed(&d.config(), &home.real(&fixture("claude/bash-allow.json")));
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert_eq!(
        fake.ops(),
        ops_of(&[
            (0, "hello"),
            (0, "hook.begin"),
            (0, "hook.bind"),
            (0, "audit.append")
        ])
    );
}

/// The approval step times out and poisons the connection: the append goes
/// out on a new one, which registers and binds the same key first.
#[test]
fn poisoned_client_rebinds_on_the_new_connection() {
    let d = TestDaemon::prepare(&Opts {
        extra: "[guard]\nask = [\"core.git/force-push\"]\nbudget_ms = 10000\n".into(),
        ..Opts::default()
    });
    let fake = FakeDaemon::start(&d, true);
    let project = tempfile::tempdir().unwrap();
    let payload = bash(project.path(), "git push --force origin main");
    let (o, _, _sb) = managed(&d.config(), &payload);
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert!(
        stderr(&o).contains("approval step failed"),
        "{}",
        stderr(&o)
    );
    assert_eq!(
        fake.ops(),
        ops_of(&[
            (0, "hello"),
            (0, "hook.begin"),
            (0, "hook.bind"),
            (0, "grant.consume"),
            (0, "approval.create"),
            (1, "hello"),
            (1, "hook.begin"),
            (1, "hook.bind"),
            (1, "audit.append"),
        ])
    );
    let seen = fake.seen();
    let binds: Vec<&Value> = seen
        .iter()
        .filter(|s| s.op == "hook.bind")
        .map(|s| &s.args)
        .collect();
    assert_eq!(binds[0], binds[1]);
    let key = saiife_ipc::hookkey::hook_key("claude", &payload).unwrap();
    let mut want = serde_json::to_value(&key).unwrap();
    want["tool"] = "Bash".into();
    assert_eq!(binds[0], &want);
    let append = seen.iter().find(|s| s.op == "audit.append").unwrap();
    assert_eq!(append.args["rec"]["decision"], "error_denied");
    // The append on the new connection still names the key.
    assert_eq!(append.args["input_sha256"], key.input_sha256.as_str());
    assert!(append.args["rec"].get("input_sha256").is_none());
}

/// A key the daemon's `hook.bind` would refuse (a session over 128 bytes,
/// a tool call id over 256) is neither bound nor named in the append: the
/// call is recorded as unbound, not as a hook without a verdict.
#[test]
fn key_over_the_daemon_limits_is_not_bound() {
    for (session, id) in [
        ("s".repeat(129), "toolu_1".to_string()),
        ("s-m".into(), "t".repeat(257)),
    ] {
        let d = TestDaemon::prepare(&Opts::default());
        let fake = FakeDaemon::start(&d, false);
        let project = tempfile::tempdir().unwrap();
        let mut v: Value = serde_json::from_str(&bash(project.path(), "ls")).unwrap();
        v["session_id"] = session.into();
        v["tool_use_id"] = id.into();
        let (o, _, _sb) = managed(&d.config(), &v.to_string());
        assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
        assert_eq!(
            fake.ops(),
            ops_of(&[(0, "hello"), (0, "hook.begin"), (0, "audit.append")])
        );
        let append = &fake.seen()[2].args;
        assert!(append.get("tool_use_id").is_none(), "{append}");
        assert!(append.get("input_sha256").is_none(), "{append}");
    }
}

#[test]
fn unparseable_payload_still_appends_error_denied_without_bind() {
    let d = TestDaemon::prepare(&Opts::default());
    let fake = FakeDaemon::start(&d, false);
    let (o, _, _sb) = managed(&d.config(), "{nope");
    assert_eq!(code(&o), 2, "stderr: {}", stderr(&o));
    assert_eq!(
        fake.ops(),
        ops_of(&[(0, "hello"), (0, "hook.begin"), (0, "audit.append")])
    );
    let append = &fake.seen()[2].args;
    assert_eq!(append["rec"]["decision"], "error_denied");
}

/// The co-signer's raw answer to `payload`: status line and body.
fn cosign_post(addr: &str, payload: &str) -> (String, String) {
    use std::io::Read;
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    write!(
        s,
        "POST /v1/cosign/claude HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    let (head, body) = out.split_once("\r\n\r\n").unwrap_or((&out, ""));
    (
        head.lines().next().unwrap_or("").to_string(),
        body.to_string(),
    )
}

/// Tasks 3 and 4 together: the hook's append names its key in full, and
/// the real daemon's co-signer then has no objection to that call. The
/// written record has no input hash anywhere.
#[test]
fn an_allowed_call_is_not_denied_by_the_cosigner() {
    let d = TestDaemon::start(Opts::default());
    let s = d.status();
    let addr = s["cosign"]["addr"]
        .as_str()
        .expect("cosign addr")
        .to_string();
    assert!(s["cosign"]["error"].is_null(), "{s:?}");
    let home = common::FixtureHome::new();
    let payload = home.real(&fixture("claude/bash-allow.json"));
    let (o, _, _sb) = managed(&d.config(), &payload);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    let rec = last_guard(&d);
    assert_eq!(rec["tool_use_id"], "toolu_02", "{rec}");
    let key = saiife_ipc::hookkey::hook_key("claude", &payload).unwrap();
    assert!(rec.get("input_sha256").is_none(), "{rec}");
    assert!(!rec.to_string().contains(&key.input_sha256), "{rec}");
    let (status, body) = cosign_post(&addr, &payload);
    assert!(status.contains(" 200 "), "{status}");
    assert!(!body.contains("deny"), "{body}");
}

/// The real daemon, whether it takes the hook ops or refuses them (one
/// that predates them): the call is judged and recorded as before.
#[test]
fn hook_ops_on_the_real_daemon_change_nothing() {
    let d = TestDaemon::start(Opts::default());
    let home = common::FixtureHome::new();
    let (o, _, _sb) = managed(&d.config(), &home.real(&fixture("claude/bash-allow.json")));
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert_eq!(last_guard(&d)["decision"], "allow");
}
