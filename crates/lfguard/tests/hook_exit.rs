use std::io::Write;
use std::process::{Command, Stdio};

fn run_check(args: &[&str], stdin: &str) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lfguard"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

const DENY_JSON: &str = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
const ALLOW_JSON: &str = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"}}"#;

#[test]
fn hook_exit_denies_with_code_2_and_stderr_reason() {
    let (code, _stdout, stderr) = run_check(&["check", "--hook-exit"], DENY_JSON);
    assert_eq!(code, 2, "deny must exit 2");
    assert!(!stderr.is_empty(), "deny reason must be on stderr");
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

#[test]
fn audit_log_records_deny_only() {
    let dir = std::env::temp_dir().join(format!("lfg-audit-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("audit.jsonl");
    let log_s = log.to_str().unwrap();

    run_check(&["check", "--hook-exit", "--audit-log", log_s, "--audit-tag", "pane1"], ALLOW_JSON);
    assert!(!log.exists() || std::fs::read_to_string(&log).unwrap().is_empty(),
        "allow writes no audit record");

    run_check(&["check", "--hook-exit", "--audit-log", log_s, "--audit-tag", "pane1"], DENY_JSON);
    let body = std::fs::read_to_string(&log).unwrap();
    assert!(body.contains("\"tag\":\"pane1\""), "deny record carries tag");
    assert!(body.contains("rm -rf /"), "deny record carries command");
    std::fs::remove_dir_all(&dir).ok();
}
