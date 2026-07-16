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

    run_check(
        &[
            "check",
            "--hook-exit",
            "--audit-log",
            log_s,
            "--audit-tag",
            "pane1",
        ],
        ALLOW_JSON,
    );
    assert!(
        !log.exists() || std::fs::read_to_string(&log).unwrap().is_empty(),
        "allow writes no audit record"
    );

    run_check(
        &[
            "check",
            "--hook-exit",
            "--audit-log",
            log_s,
            "--audit-tag",
            "pane1",
        ],
        DENY_JSON,
    );
    let body = std::fs::read_to_string(&log).unwrap();
    assert!(
        body.contains("\"tag\":\"pane1\""),
        "deny record carries tag"
    );
    assert!(body.contains("rm -rf /"), "deny record carries command");
    std::fs::remove_dir_all(&dir).ok();
}

/// A unique scratch dir for one test, cleaned up by the caller.
fn scratch(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "lfg-seen-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    dir
}

#[test]
fn seen_dir_marker_written_on_allow() {
    let dir = scratch("allow");
    let dir_s = dir.to_str().unwrap();
    run_check(
        &[
            "check",
            "--hook-exit",
            "--seen-dir",
            dir_s,
            "--audit-tag",
            "pane1",
        ],
        ALLOW_JSON,
    );
    let marker = dir.join("pane1");
    assert!(marker.exists(), "marker must be written on ALLOW");
    assert!(
        !std::fs::read_to_string(&marker).unwrap().is_empty(),
        "marker is non-empty (carries a timestamp)"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn seen_dir_marker_written_on_deny() {
    let dir = scratch("deny");
    let dir_s = dir.to_str().unwrap();
    let log = dir.join("audit.jsonl");
    // create the dir up-front so the audit log path is writable
    std::fs::create_dir_all(&dir).unwrap();
    let log_s = log.to_str().unwrap();
    let (code, _o, _e) = run_check(
        &[
            "check",
            "--hook-exit",
            "--seen-dir",
            dir_s,
            "--audit-log",
            log_s,
            "--audit-tag",
            "pane1",
        ],
        DENY_JSON,
    );
    assert_eq!(code, 2, "deny still exits 2");
    assert!(dir.join("pane1").exists(), "marker written on DENY too");
    // The deny audit record is independent of the marker.
    let body = std::fs::read_to_string(&log).unwrap();
    assert!(body.contains("rm -rf /"), "deny audit record still lands");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn seen_dir_marker_overwrites_not_appends() {
    let dir = scratch("overwrite");
    let dir_s = dir.to_str().unwrap();
    run_check(
        &[
            "check",
            "--hook-exit",
            "--seen-dir",
            dir_s,
            "--audit-tag",
            "pane1",
        ],
        ALLOW_JSON,
    );
    let size1 = std::fs::metadata(dir.join("pane1")).unwrap().len();
    run_check(
        &[
            "check",
            "--hook-exit",
            "--seen-dir",
            dir_s,
            "--audit-tag",
            "pane1",
        ],
        ALLOW_JSON,
    );
    let size2 = std::fs::metadata(dir.join("pane1")).unwrap().len();
    // A timestamp is a fixed-ish width; overwrite means the file does not grow
    // unboundedly. Assert it stays within one timestamp's width, not appended.
    assert!(size2 <= size1 + 2, "marker overwrites, does not append");
    let entries: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
    assert_eq!(entries.len(), 1, "exactly one marker file for the tag");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn seen_dir_absent_writes_nothing() {
    let dir = scratch("absent");
    // No --seen-dir passed: the dir must never be created.
    run_check(
        &["check", "--hook-exit", "--audit-tag", "pane1"],
        ALLOW_JSON,
    );
    assert!(!dir.exists(), "no marker dir created without --seen-dir");
}

#[test]
fn seen_dir_without_tag_writes_nothing() {
    let dir = scratch("notag");
    let dir_s = dir.to_str().unwrap();
    run_check(&["check", "--hook-exit", "--seen-dir", dir_s], ALLOW_JSON);
    // With no tag there is no filename to write; the dir may be created but
    // must hold no marker file.
    let empty = !dir.exists()
        || std::fs::read_dir(&dir)
            .map(|mut e| e.next().is_none())
            .unwrap_or(true);
    assert!(empty, "no marker file without an --audit-tag");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn seen_dir_rejects_traversal_tag() {
    let dir = scratch("traversal");
    let dir_s = dir.to_str().unwrap();
    let sentinel = dir.parent().unwrap().join("evil");
    std::fs::remove_file(&sentinel).ok();
    run_check(
        &[
            "check",
            "--hook-exit",
            "--seen-dir",
            dir_s,
            "--audit-tag",
            "../evil",
        ],
        ALLOW_JSON,
    );
    assert!(!sentinel.exists(), "traversal tag must not escape seen-dir");
    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_file(&sentinel).ok();
}

#[test]
fn seen_dir_write_failure_still_returns_verdict() {
    // Point --seen-dir at a path whose parent is a FILE, so create_dir_all and
    // write both fail — the verdict must be unaffected (fail-open).
    let file = scratch("blocker");
    std::fs::write(&file, b"x").unwrap();
    let bad_dir = file.join("subdir"); // parent is a regular file → unusable
    let bad_s = bad_dir.to_str().unwrap();
    let (deny_code, _o, _e) = run_check(
        &[
            "check",
            "--hook-exit",
            "--seen-dir",
            bad_s,
            "--audit-tag",
            "pane1",
        ],
        DENY_JSON,
    );
    assert_eq!(
        deny_code, 2,
        "deny verdict still emitted despite marker failure"
    );
    let (allow_code, _o2, _e2) = run_check(
        &[
            "check",
            "--hook-exit",
            "--seen-dir",
            bad_s,
            "--audit-tag",
            "pane1",
        ],
        ALLOW_JSON,
    );
    assert_eq!(
        allow_code, 0,
        "allow verdict still emitted despite marker failure"
    );
    std::fs::remove_file(&file).ok();
}
