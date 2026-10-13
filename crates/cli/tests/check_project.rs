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
    let rec = &read_all(audit.path()).records[0];
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
