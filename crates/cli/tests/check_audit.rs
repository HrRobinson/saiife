//! `saiife check` writes one masked audit record per decision and never lets
//! the audit log change a verdict.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use saiife_audit::store::{read_all, DIR_ENV};
use saiife_audit::DecisionKind;

fn check(audit_dir: &Path, args: &[&str], stdin: &str) -> i32 {
    let mut child = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .arg("check")
        .args(args)
        .env(DIR_ENV, audit_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait().unwrap().code().unwrap_or(-1)
}

fn payload(cmd: &str) -> String {
    serde_json::json!({
        "session_id": "sess-1",
        "cwd": "/home/u/app",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": cmd }
    })
    .to_string()
}

#[test]
fn allow_is_audited_with_context() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        check(
            dir.path(),
            &["--hook-exit", "--agent", "claude"],
            &payload("ls -la")
        ),
        0
    );
    let recs = read_all(dir.path()).records;
    assert_eq!(recs.len(), 1);
    let r = &recs[0];
    assert_eq!(r.decision, DecisionKind::Allow);
    assert_eq!(r.agent, "claude");
    assert_eq!(r.tool, "Bash");
    assert_eq!(r.session.as_deref(), Some("sess-1"));
    assert_eq!(r.project, "/home/u/app");
    assert_eq!(r.input, "ls -la");
    assert_eq!(r.saiife, env!("CARGO_PKG_VERSION"));
}

#[test]
fn deny_is_audited_with_pack_rule_reason() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        check(
            dir.path(),
            &["--hook-exit", "--agent", "codex"],
            &payload("rm -rf /")
        ),
        2
    );
    let r = &read_all(dir.path()).records[0];
    assert_eq!(r.decision, DecisionKind::Deny);
    assert_eq!(r.pack.as_deref(), Some("core.filesystem"));
    assert!(r.rule.is_some());
    assert!(r.reason.is_some());
}

#[test]
fn garbage_payload_is_audited_as_error_allowed() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(check(dir.path(), &["--hook-exit"], "{not json"), 0);
    let r = &read_all(dir.path()).records[0];
    assert_eq!(r.decision, DecisionKind::ErrorAllowed);
    assert_eq!(r.agent, "unknown");
    assert!(r.reason.as_deref().unwrap().contains("payload"));
}

#[test]
fn oversize_payload_is_error_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let big = payload(&format!("echo {}", "a".repeat(300 * 1024)));
    assert_eq!(check(dir.path(), &["--hook-exit"], &big), 0);
    let r = &read_all(dir.path()).records[0];
    assert_eq!(r.decision, DecisionKind::ErrorAllowed);
    assert!(
        r.input.starts_with("echo "),
        "command kept: {:.40}",
        r.input
    );
    assert!(r.input.ends_with("…[truncated]"));
    assert!(r.reason.as_deref().unwrap().contains("payload"));
}

#[test]
fn secrets_never_reach_the_audit_file() {
    let dir = tempfile::tempdir().unwrap();
    let tok = format!("ghp_{}", "z".repeat(36));
    check(
        dir.path(),
        &["--hook-exit"],
        &payload(&format!("GH_TOKEN={tok} gh pr list")),
    );
    let raw: String = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
        .collect();
    assert!(!raw.contains(&tok), "token leaked: {raw}");
    assert!(raw.contains("[MASKED]"));
}

#[test]
fn unwritable_audit_dir_keeps_verdict() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("a-file");
    std::fs::write(&file, "x").unwrap();
    assert_eq!(check(&file, &["--hook-exit"], &payload("rm -rf /")), 2);
    assert_eq!(check(&file, &["--hook-exit"], &payload("ls")), 0);
}

#[test]
fn concurrent_checks_write_whole_lines() {
    let dir = tempfile::tempdir().unwrap();
    let children: Vec<_> = (0..20)
        .map(|i| {
            let mut c = Command::new(env!("CARGO_BIN_EXE_saiife"))
                .args(["check", "--hook-exit", "--agent", "claude"])
                .env(DIR_ENV, dir.path())
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            c.stdin
                .take()
                .unwrap()
                .write_all(payload(&format!("echo {i} {}", "x".repeat(3000))).as_bytes())
                .unwrap();
            c
        })
        .collect();
    for mut c in children {
        c.wait().unwrap();
    }
    let lines: usize = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| {
            std::fs::read_to_string(e.unwrap().path())
                .unwrap()
                .lines()
                .count()
        })
        .sum();
    assert_eq!(lines, 20);
    assert_eq!(read_all(dir.path()).records.len(), 20, "every line parses");
}

/// A FIFO planted at the month file must not hang the hook: the verdict
/// still comes back promptly.
#[cfg(unix)]
#[test]
fn fifo_at_month_path_does_not_block_the_verdict() {
    use std::time::{Duration, Instant};
    let dir = tempfile::tempdir().unwrap();
    let now = time::OffsetDateTime::now_utc();
    for month in [now, now + time::Duration::days(1)] {
        let p = dir.path().join(format!(
            "{:04}-{:02}.jsonl",
            month.year(),
            u8::from(month.month())
        ));
        if !p.exists() {
            assert!(Command::new("mkfifo").arg(&p).status().unwrap().success());
        }
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["check", "--hook-exit"])
        .env(DIR_ENV, dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload("rm -rf /").as_bytes())
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert_eq!(status.code(), Some(2));
            return;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("saiife check blocked on a FIFO audit file");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
