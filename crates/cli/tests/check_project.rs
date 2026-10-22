//! `saiife check` loads the opt-in packs of the project the agent works in:
//! the nearest `.saiife/config.toml` at or above the payload's `cwd`.

mod common;

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use saiife_audit::store::read_all;
use saiife_audit::DecisionKind;

const DROP: &str = "psql -c 'DROP DATABASE prod'";

fn check(audit: &Path, cwd: &Path, cmd: &str) -> (i32, String) {
    let payload = serde_json::json!({
        "session_id": "s",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": cmd }
    })
    .to_string();
    common::assert_no_host_config(&std::env::temp_dir());
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_saiife"));
    let _sandbox = common::hermetic(&mut cmd, audit);
    let mut child = cmd
        .args(["check", "--hook-exit", "--agent", "claude"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
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
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn project(packs: &str) -> tempfile::TempDir {
    let p = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(p.path().join(".saiife")).unwrap();
    std::fs::create_dir_all(p.path().join("src/deep")).unwrap();
    std::fs::write(
        p.path().join(".saiife/config.toml"),
        format!("version = 1\npacks = [{packs}]\n"),
    )
    .unwrap();
    p
}

#[test]
fn opt_in_pack_from_project_config_applies_in_subdirectories() {
    let audit = tempfile::tempdir().unwrap();
    let p = project("\"core.filesystem\", \"core.git\", \"db.postgres\"");
    let (code, stderr) = check(audit.path(), &p.path().join("src/deep"), DROP);
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("BLOCKED by db.postgres"), "{stderr}");
    let recs = read_all(audit.path()).records;
    let rec = recs.iter().find(|r| !r.is_bookkeeping()).unwrap();
    assert_eq!(rec.decision, DecisionKind::Deny);
    assert_eq!(rec.pack.as_deref(), Some("db.postgres"));
}

#[test]
fn outside_the_project_only_default_packs_apply() {
    let audit = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let (code, _) = check(audit.path(), elsewhere.path(), DROP);
    assert_eq!(code, 0);
}

#[test]
fn unknown_pack_ids_are_warned_about_and_ignored() {
    let audit = tempfile::tempdir().unwrap();
    let p = project("\"db.oracle\", \"db.postgres\"");
    let (code, stderr) = check(audit.path(), p.path(), DROP);
    assert_eq!(code, 2, "known packs still apply");
    assert!(stderr.contains("unknown pack \"db.oracle\""), "{stderr}");
    let (code, _) = check(audit.path(), p.path(), "rm -rf /");
    assert_eq!(code, 2, "default-on packs always apply");
}

#[test]
fn broken_project_config_fails_open_to_default_packs() {
    let audit = tempfile::tempdir().unwrap();
    let p = project("\"db.postgres\"");
    std::fs::write(p.path().join(".saiife/config.toml"), "packs = [\n").unwrap();
    let (code, stderr) = check(audit.path(), p.path(), "rm -rf /");
    assert_eq!(code, 2, "default-on packs still apply");
    assert!(stderr.contains("default packs only"), "{stderr}");
    let (code, _) = check(audit.path(), p.path(), DROP);
    assert_eq!(code, 0);
}

#[test]
fn oversized_project_config_fails_open_to_default_packs() {
    let audit = tempfile::tempdir().unwrap();
    let p = project("\"db.postgres\"");
    let big = format!(
        "# {}\nversion = 1\npacks = [\"db.postgres\"]\n",
        "x".repeat(70 * 1024)
    );
    std::fs::write(p.path().join(".saiife/config.toml"), big).unwrap();
    let (code, stderr) = check(audit.path(), p.path(), "rm -rf /");
    assert_eq!(code, 2, "default-on packs still apply");
    assert!(stderr.contains("default packs only"), "{stderr}");
    let (code, _) = check(audit.path(), p.path(), DROP);
    assert_eq!(code, 0, "opt-in pack from the oversized file is not loaded");
}

/// Run the hook in `cwd`, killing it after 30 s; returns its exit code, how
/// long it took, and the `policy` of the guard record it wrote.
fn timed_check(audit: &Path, cwd: &Path, cmd: &str) -> (i32, std::time::Duration, String) {
    let payload = serde_json::json!({
        "session_id": "s",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": cmd }
    })
    .to_string();
    let mut command = Command::new(env!("CARGO_BIN_EXE_saiife"));
    let _sandbox = common::hermetic(&mut command, audit);
    let start = std::time::Instant::now();
    let mut child = command
        .args(["check", "--hook-exit", "--agent", "claude"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if start.elapsed() > std::time::Duration::from_secs(30) {
            let _ = child.kill();
            break child.wait().unwrap();
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    let took = start.elapsed();
    let policy = read_all(audit)
        .records
        .iter()
        .rev()
        .find(|r| !r.is_bookkeeping())
        .and_then(|r| r.policy.clone())
        .unwrap_or_default();
    (status.code().unwrap_or(-1), took, policy)
}

/// An oversized config is refused by its size before a byte is read (so
/// any size costs the same): the hook answers well inside its budget and
/// still records a policy.
#[test]
fn oversized_config_does_not_delay_hook() {
    let audit = tempfile::tempdir().unwrap();
    let p = tempfile::tempdir().unwrap();
    std::fs::create_dir(p.path().join(".saiife")).unwrap();
    let f = std::fs::File::create(p.path().join(".saiife/config.toml")).unwrap();
    f.set_len(64 * 1024 + 1).unwrap();
    drop(f);
    let (code, took, policy) = timed_check(audit.path(), p.path(), "rm -rf /");
    assert_eq!(code, 2, "default-on packs still deny");
    assert!(
        took < std::time::Duration::from_secs(2),
        "hook took {took:?}"
    );
    assert!(policy.starts_with("sha256:"), "{policy:?}");
}

/// A symlinked config is followed, for the packs and the policy hash
/// alike: the policy is that of a plain file with the target's bytes. A
/// link to an oversized file is refused unread, without delay.
#[cfg(unix)]
#[test]
fn symlinked_config_is_followed_for_policy() {
    let audit = tempfile::tempdir().unwrap();
    let p = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let a = "packs = [\"db.postgres\"]\n";
    std::fs::write(outside.path().join("a.toml"), a).unwrap();
    std::fs::write(outside.path().join("b.toml"), "packs = []\n").unwrap();
    std::fs::create_dir(p.path().join(".saiife")).unwrap();
    let link = p.path().join(".saiife/config.toml");
    std::os::unix::fs::symlink(outside.path().join("a.toml"), &link).unwrap();
    let (code, took, via_a) = timed_check(audit.path(), p.path(), DROP);
    assert_eq!(code, 2, "the linked config's opt-in pack is loaded");
    assert!(
        took < std::time::Duration::from_secs(2),
        "hook took {took:?}"
    );
    assert!(via_a.starts_with("sha256:"), "{via_a:?}");

    std::fs::remove_file(&link).unwrap();
    std::fs::write(&link, a).unwrap();
    let (_, _, plain_a) = timed_check(audit.path(), p.path(), DROP);
    assert_eq!(via_a, plain_a, "the target's bytes are hashed");

    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(outside.path().join("b.toml"), &link).unwrap();
    let (_, _, via_b) = timed_check(audit.path(), p.path(), DROP);
    assert_ne!(via_a, via_b, "another target, another policy");

    let big = outside.path().join("big.toml");
    std::fs::File::create(&big)
        .unwrap()
        .set_len(64 * 1024 + 1)
        .unwrap();
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&big, &link).unwrap();
    let (code, took, via_big) = timed_check(audit.path(), p.path(), DROP);
    assert_eq!(code, 0, "an oversized target is not loaded");
    assert!(
        took < std::time::Duration::from_secs(2),
        "hook took {took:?}"
    );
    std::fs::remove_file(&link).unwrap();
    std::fs::File::create(&link)
        .unwrap()
        .set_len(64 * 1024 + 1)
        .unwrap();
    let (_, _, plain_big) = timed_check(audit.path(), p.path(), DROP);
    assert_eq!(via_big, plain_big, "one marker for every unreadable config");
}
