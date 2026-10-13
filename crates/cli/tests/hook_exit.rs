use std::io::Write;
use std::process::{Command, Stdio};

fn run_check(args: &[&str], stdin: &str) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(args)
        .env(
            "SAIIFE_AUDIT_DIR",
            std::env::temp_dir().join(format!("saiife-test-audit-{}", std::process::id())),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

const DENY_JSON: &str =
    r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
const ALLOW_JSON: &str =
    r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"}}"#;

#[test]
fn hook_exit_denies_with_code_2_and_stderr_reason() {
    let (code, _stdout, stderr) = run_check(&["check", "--hook-exit"], DENY_JSON);
    assert_eq!(code, 2, "deny must exit 2");
    assert!(!stderr.is_empty(), "deny reason must be on stderr");
}

/// R2: the hook-deny path is the one a real user/agent actually hits, and
/// must not drop the pack id or the human reason `cmd_test`/`cmd_explain`
/// already surface for the identical `Decision::Deny`. Messaging only — the
/// exit code (2 = deny) is asserted unchanged alongside it.
#[test]
fn hook_exit_deny_message_names_pack_and_reason() {
    let (code, _stdout, stderr) = run_check(&["check", "--hook-exit"], DENY_JSON);
    assert_eq!(code, 2, "deny must still exit 2");
    assert!(
        stderr.contains("BLOCKED by core.filesystem:"),
        "stderr must name the pack that fired, got: {stderr:?}"
    );
    assert!(
        stderr.contains("catastrophic"),
        "stderr must carry the human reason, got: {stderr:?}"
    );
}

/// Regression guard for the invariant this whole change must preserve: the
/// hook-exit deny/allow verdict for a small corpus of commands is IDENTICAL
/// before and after the message enrichment. Compares `check --hook-exit`'s
/// exit code against `test`'s exit code (0 allow / 1 deny -> mapped to the
/// hook's 0/2), proving the message rewrite touched no decision logic.
#[test]
fn hook_exit_verdicts_match_test_subcommand_across_a_corpus() {
    let corpus: &[(&str, &str)] = &[
        ("Bash", "rm -rf /"),
        ("Bash", "ls -la"),
        ("Bash", "git reset --hard"),
        ("Bash", "git status"),
        ("Bash", "git push --force-with-lease"),
    ];
    for (tool, command) in corpus {
        let json = format!(
            r#"{{"hook_event_name":"PreToolUse","tool_name":"{tool}","tool_input":{{"command":{command:?}}}}}"#
        );
        let (hook_code, _o, _e) = run_check(&["check", "--hook-exit"], &json);

        let test_child = Command::new(env!("CARGO_BIN_EXE_saiife"))
            .args(["test", command])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let test_out = test_child.wait_with_output().unwrap();
        let test_code = test_out.status.code().unwrap_or(-1);

        let expected_hook_code = if test_code == 0 { 0 } else { 2 };
        assert_eq!(
            hook_code, expected_hook_code,
            "verdict for {command:?} changed: test exit={test_code}, hook-exit exit={hook_code}"
        );
    }
}

#[test]
fn hook_exit_allows_with_code_0() {
    let (code, _stdout, _stderr) = run_check(&["check", "--hook-exit"], ALLOW_JSON);
    assert_eq!(code, 0, "allow must exit 0");
}

#[test]
fn hook_exit_fails_open_on_garbage() {
    let (code, _stdout, _stderr) = run_check(&["check", "--hook-exit"], "not json");
    assert_eq!(code, 0, "unparseable stdin must fail open (allow)");
}
