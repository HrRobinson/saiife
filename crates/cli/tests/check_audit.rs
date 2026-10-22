//! `saiife check` writes one masked audit record per decision and never lets
//! the audit log change a verdict.

mod common;

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use saiife_audit::store::read_all;
use saiife_audit::DecisionKind;
use saiife_audit::Record;

/// `stdin` spells the fixture home `/home/u`; it is mapped to a real temp
/// home (`common::FixtureHome`) that lives until `saiife` exits.
fn check(audit_dir: &Path, args: &[&str], stdin: &str) -> i32 {
    let home = common::FixtureHome::new();
    let stdin = home.real(stdin);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_saiife"));
    let _sandbox = common::hermetic(&mut cmd, audit_dir);
    let mut child = cmd
        .arg("check")
        .args(args)
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

/// The guard decisions in `dir`, without the chain's genesis line.
fn guard_records(dir: &Path) -> Vec<Record> {
    read_all(dir)
        .records
        .into_iter()
        .filter(|r| r.kind() == "guard")
        .collect()
}

fn payload(cmd: &str) -> String {
    serde_json::json!({
        "session_id": "sess-1",
        "cwd": common::FIXTURE_CWD,
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
    let recs = guard_records(dir.path());
    assert_eq!(recs.len(), 1);
    let r = &recs[0];
    assert_eq!(r.decision, DecisionKind::Allow);
    assert_eq!(r.agent, "claude");
    assert_eq!(r.tool, "Bash");
    assert_eq!(r.session.as_deref(), Some("sess-1"));
    assert!(r.project.ends_with("/u/app"), "{}", r.project);
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
    let r = &guard_records(dir.path())[0];
    assert_eq!(r.decision, DecisionKind::Deny);
    assert_eq!(r.pack.as_deref(), Some("core.filesystem"));
    assert!(r.rule.is_some());
    assert!(r.reason.is_some());
}

#[test]
fn garbage_payload_is_audited_as_error_allowed() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(check(dir.path(), &["--hook-exit"], "{not json"), 0);
    let r = &guard_records(dir.path())[0];
    assert_eq!(r.decision, DecisionKind::ErrorAllowed);
    assert_eq!(r.agent, "unknown");
    assert!(r.reason.as_deref().unwrap().contains("payload"));
}

#[test]
fn oversize_payload_is_error_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let big = payload(&format!("echo {}", "a".repeat(300 * 1024)));
    assert_eq!(check(dir.path(), &["--hook-exit"], &big), 0);
    let r = &guard_records(dir.path())[0];
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
    let home = common::FixtureHome::new();
    let mut sandboxes = Vec::new();
    let children: Vec<_> = (0..20)
        .map(|i| {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_saiife"));
            sandboxes.push(common::hermetic(&mut cmd, dir.path()));
            let mut c = cmd
                .args(["check", "--hook-exit", "--agent", "claude"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            c.stdin
                .take()
                .unwrap()
                .write_all(
                    home.real(&payload(&format!("echo {i} {}", "🦀".repeat(20_000))))
                        .as_bytes(),
                )
                .unwrap();
            c
        })
        .collect();
    for mut c in children {
        c.wait().unwrap();
    }
    // Read through the store: a short write (e.g. a disk quota) shows up as a
    // skipped line instead of a UTF-8 panic.
    let got = read_all(dir.path());
    assert_eq!(got.skipped_lines, 0, "every line is whole");
    assert_eq!(got.unreadable_files, 0);
    assert_eq!(got.records.len(), 21, "every line parses (20 + genesis)");
    // Records keep 4096 chars of input; 4-byte chars push every line past
    // 16 KB, well beyond PIPE_BUF-sized writes.
    assert!(got
        .records
        .iter()
        .filter(|r| r.kind() == "guard")
        .all(|r| serde_json::to_string(r).unwrap().len() > 16 * 1024));
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
    let home = common::FixtureHome::new();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_saiife"));
    let _sandbox = common::hermetic(&mut cmd, dir.path());
    let mut child = cmd
        .args(["check", "--hook-exit"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(home.real(&payload("rm -rf /")).as_bytes())
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

/// A relative `SAIIFE_AUDIT_DIR` must not make `check` write a log under
/// the hook's working directory (spec §6.1: never inside the project).
#[test]
fn relative_audit_dir_is_ignored() {
    let project = tempfile::tempdir().unwrap();
    let home = common::FixtureHome::new();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_saiife"));
    let audit = tempfile::tempdir().unwrap();
    let _sandbox = common::hermetic(&mut cmd, audit.path());
    let mut child = cmd
        .env("SAIIFE_AUDIT_DIR", "rel-audit")
        .current_dir(project.path())
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
        .write_all(home.real(&payload("ls")).as_bytes())
        .unwrap();
    child.wait().unwrap();
    assert!(!project.path().join("rel-audit").exists());
}

#[cfg(unix)]
#[test]
fn hook_record_is_v2_chained() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        check(
            dir.path(),
            &["--hook-exit", "--agent", "claude"],
            &serde_json::json!({
                "session_id": "s", "cwd": common::FIXTURE_CWD,
                "permission_mode": "plan",
                "hook_event_name": "PreToolUse", "tool_name": "Bash",
                "tool_input": { "command": "ls" }
            })
            .to_string()
        ),
        0
    );
    let file = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "jsonl"))
        .unwrap();
    let body = std::fs::read_to_string(file).unwrap();
    let lines: Vec<serde_json::Value> = body
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["kind"], "genesis");
    let g = &lines[1];
    assert_eq!(g["v"], 2);
    assert_eq!(g["seq"], 1);
    assert_eq!(g["mode"], "developer");
    assert_eq!(g["permission_mode"], "plan");
    assert!(g["uid"].is_number(), "{g}");
    let policy = g["policy"].as_str().unwrap();
    let hex = policy.strip_prefix("sha256:").unwrap();
    assert!(hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()));
}

/// When the chain cannot be continued the record is still written, and the
/// warning says so in plain words.
#[test]
fn unchained_fallback_warning_wording() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(saiife_audit::chain::LOCK_FILE)).unwrap();
    let home = common::FixtureHome::new();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_saiife"));
    let _sandbox = common::hermetic(&mut cmd, dir.path());
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
        .write_all(home.real(&payload("ls")).as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(
            "audit record written without the chain (audit chain lock unavailable); decision unaffected"
        ),
        "{stderr}"
    );
    assert_eq!(guard_records(dir.path()).len(), 1);
}
