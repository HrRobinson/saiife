//! CLI acceptance tests — spawn the built binary and assert the contract.

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_deny_exits_1_with_reason() {
    Command::cargo_bin("lfguard")
        .unwrap()
        .args(["test", "git reset --hard"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("BLOCKED"))
        .stderr(predicate::str::contains("uncommitted"));
}

#[test]
fn test_allow_exits_0() {
    Command::cargo_bin("lfguard")
        .unwrap()
        .args(["test", "git status"])
        .assert()
        .success();
}

#[test]
fn explain_prints_pack_rule_reason() {
    Command::cargo_bin("lfguard")
        .unwrap()
        .args(["explain", "git reset --hard"])
        .assert()
        .success()
        .stdout(predicate::str::contains("DENY"))
        .stdout(predicate::str::contains("core.git"))
        .stdout(predicate::str::contains("uncommitted"));
}

#[test]
fn explain_allow_shows_carveout() {
    Command::cargo_bin("lfguard")
        .unwrap()
        .args(["explain", "git push --force-with-lease"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ALLOW"))
        .stdout(predicate::str::contains("core.git"));
}

#[test]
fn check_denies_via_hook_json() {
    Command::cargo_bin("lfguard")
        .unwrap()
        .arg("check")
        .write_stdin(
            r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git reset --hard"}}"#,
        )
        .assert()
        .success()
        .stdout(predicate::str::contains("deny"));
}

#[test]
fn check_fails_open_on_garbage() {
    // Malformed JSON must NOT block — fail open (allow).
    Command::cargo_bin("lfguard")
        .unwrap()
        .arg("check")
        .write_stdin("{not json at all")
        .assert()
        .success()
        .stdout(predicate::str::contains("allow"));
}
