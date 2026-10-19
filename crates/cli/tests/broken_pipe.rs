//! `saiife <cmd> | head -1` closes our stdout early. That must end quietly:
//! no panic message, the work is still done and the real exit code returned.

mod common;

use std::process::{Command, Stdio};

use common::{code, stderr, stdout, Env};

/// Run saiife with the read end of its stdout already closed.
fn run_with_closed_stdout(env: &Env, args: &[&str]) -> (Option<i32>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(args)
        .current_dir(env.root())
        .env("PATH", env.bin.path())
        .env("HOME", env.home.path())
        .env("SAIIFE_DATA_DIR", env.data.path())
        .env("SAIIFE_AUDIT_DIR", env.audit.path())
        .env("SAIIFE_TEST_CLAUDE_MANAGED_DIRS", env.managed.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let out = child.wait_with_output().unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into(),
    )
}

#[test]
fn commands_exit_quietly_when_the_reader_goes_away() {
    let env = Env::new(&["claude"]);
    let out = env.saiife(&["init"]);
    assert_eq!(code(&out), 0, "{}{}", stdout(&out), stderr(&out));
    for args in [
        &["status"][..],
        &["packs"],
        &["audit"],
        &["explain", "git status"],
        &["init"],
    ] {
        let (c, err) = run_with_closed_stdout(&env, args);
        assert!(!err.contains("panicked"), "{args:?}: {err}");
        assert_eq!(c, Some(0), "{args:?}: {err}");
    }
}

#[test]
fn status_still_exits_1_on_problems_with_a_closed_pipe() {
    let env = Env::new(&["claude"]);
    let out = env.saiife(&["init"]);
    assert_eq!(code(&out), 0, "{}{}", stdout(&out), stderr(&out));
    env.write(".claude/settings.json", "{}");
    let (c, err) = run_with_closed_stdout(&env, &["status"]);
    assert!(!err.contains("panicked"), "{err}");
    assert_eq!(c, Some(1), "{err}");
}

#[test]
fn init_still_restores_the_hook_with_a_closed_pipe() {
    let env = Env::new(&["claude"]);
    let out = env.saiife(&["init"]);
    assert_eq!(code(&out), 0, "{}{}", stdout(&out), stderr(&out));
    env.write(".claude/settings.json", "{}");
    let (c, err) = run_with_closed_stdout(&env, &["init"]);
    assert!(!err.contains("panicked"), "{err}");
    assert_eq!(c, Some(0), "{err}");
    assert!(env.read(".claude/settings.json").contains("saiife"));
    let out = env.saiife(&["status"]);
    assert_eq!(code(&out), 0, "{}", stdout(&out));
}

/// JSON mode deny with no stdout to carry it: fail closed (stderr + exit 2).
#[test]
fn json_mode_deny_fails_closed_when_stdout_is_gone() {
    use std::io::Write;
    let env = Env::new(&["claude"]);
    let payload = serde_json::json!({
        "session_id": "s",
        "cwd": env.root(),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "git reset --hard" }
    })
    .to_string();
    let mut child = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["check", "--agent", "claude"])
        .current_dir(env.root())
        .env("PATH", env.bin.path())
        .env("HOME", env.home.path())
        .env("SAIIFE_DATA_DIR", env.data.path())
        .env("SAIIFE_AUDIT_DIR", env.audit.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("BLOCKED"));
}

/// `--hook-exit` deny when the stdout reader is gone (EPIPE): the verdict is
/// exit 2, same as with a reader attached.
#[test]
fn hook_exit_deny_with_broken_stdout_pipe_exits_2() {
    use std::io::Write;
    let env = Env::new(&["claude"]);
    let payload = serde_json::json!({
        "session_id": "s",
        "cwd": env.root(),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "git reset --hard" }
    })
    .to_string();
    let mut child = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["check", "--hook-exit", "--agent", "claude"])
        .current_dir(env.root())
        .env("PATH", env.bin.path())
        .env("HOME", env.home.path())
        .env("SAIIFE_DATA_DIR", env.data.path())
        .env("SAIIFE_AUDIT_DIR", env.audit.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("BLOCKED"));
}

/// `--hook-exit` deny with fd 1 closed outright (`>&-`, so writes fail with
/// EBADF rather than EPIPE): still exit 2. `sh` closes the fd and execs
/// saiife, which keeps the test crate free of `unsafe` `pre_exec`.
#[cfg(unix)]
#[test]
fn hook_exit_deny_with_stdout_fd_closed_exits_2() {
    use std::io::Write;
    let env = Env::new(&["claude"]);
    let payload = serde_json::json!({
        "session_id": "s",
        "cwd": env.root(),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "git reset --hard" }
    })
    .to_string();
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(r#"exec "$0" "$@" >&-"#)
        .arg(env!("CARGO_BIN_EXE_saiife"))
        .args(["check", "--hook-exit", "--agent", "claude"])
        .current_dir(env.root())
        .env("PATH", env.bin.path())
        .env("HOME", env.home.path())
        .env("SAIIFE_DATA_DIR", env.data.path())
        .env("SAIIFE_AUDIT_DIR", env.audit.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.stdout.is_empty(),
        "fd 1 was closed, nothing should reach it"
    );
    assert!(!err.contains("panicked"), "{err}");
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(err.contains("BLOCKED"), "{err}");
}
