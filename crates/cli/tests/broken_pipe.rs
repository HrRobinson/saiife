//! `saiife <cmd> | head -1` closes our stdout early. That must end quietly:
//! no panic message, exit 0.

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
