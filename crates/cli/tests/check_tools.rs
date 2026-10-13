//! `saiife check` against recorded-shape payloads of every agent and tool
//! (fixtures built from docs/superpowers/research/2026-10-13-*-hooks.md).

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use saiife_audit::store::{read_all, DIR_ENV};
use saiife_audit::{DecisionKind, Record};

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

fn check_bytes(audit_dir: &Path, agent: &str, stdin: &[u8]) -> Out {
    let mut child = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["check", "--hook-exit", "--agent", agent])
        .env(DIR_ENV, audit_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let out = child.wait_with_output().unwrap();
    Out {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

fn fixture(name: &str) -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// Run one fixture in a fresh audit dir; return the output and the single
/// record it wrote.
fn run(name: &str, agent: &str) -> (Out, Record) {
    let dir = tempfile::tempdir().unwrap();
    let out = check_bytes(dir.path(), agent, &fixture(name));
    let mut recs = read_all(dir.path()).records;
    assert_eq!(recs.len(), 1, "{name}: exactly one record");
    (out, recs.remove(0))
}

#[test]
fn shell_fixtures_are_judged() {
    for (name, agent, code, decision, input) in [
        (
            "claude/bash-deny.json",
            "claude",
            2,
            DecisionKind::Deny,
            "rm -rf /",
        ),
        (
            "claude/bash-allow.json",
            "claude",
            0,
            DecisionKind::Allow,
            "ls -la",
        ),
        (
            "codex/bash-deny.json",
            "codex",
            2,
            DecisionKind::Deny,
            "git reset --hard",
        ),
        (
            "codex/bash-allow.json",
            "codex",
            0,
            DecisionKind::Allow,
            "cargo test",
        ),
        (
            "gemini/shell-deny.json",
            "gemini",
            2,
            DecisionKind::Deny,
            "rm -rf /",
        ),
        (
            "gemini/shell-allow.json",
            "gemini",
            0,
            DecisionKind::Allow,
            "git status",
        ),
    ] {
        let (out, rec) = run(name, agent);
        assert_eq!(out.code, code, "{name}: {}", out.stderr);
        assert!(out.stdout.is_empty(), "{name}: stdout must stay empty");
        if code == 2 {
            assert!(out.stderr.contains("BLOCKED by"), "{name}: {}", out.stderr);
        }
        assert_eq!(rec.decision, decision, "{name}");
        assert_eq!(rec.input, input, "{name}");
        assert_eq!(rec.agent, agent, "{name}");
        assert_eq!(rec.project, "/home/u/app", "{name}");
    }
}

#[test]
fn file_tool_fixtures_are_recorded_with_their_paths_and_never_judged() {
    for (name, agent, tool, input) in [
        ("claude/read.json", "claude", "Read", "/home/u/app/.env"),
        ("claude/grep-no-path.json", "claude", "Grep", "/home/u/app"),
        (
            "claude/write.json",
            "claude",
            "Write",
            "/home/u/app/notes.sh",
        ),
        (
            "claude/edit.json",
            "claude",
            "Edit",
            "/home/u/app/src/main.rs",
        ),
        (
            "claude/notebook-edit.json",
            "claude",
            "NotebookEdit",
            "/home/u/app/analysis.ipynb",
        ),
        (
            "codex/apply-patch.json",
            "codex",
            "apply_patch",
            "docs/recovery.md\nscripts/reset.sh",
        ),
        (
            "gemini/read-file.json",
            "gemini",
            "read_file",
            "/home/u/app/.env",
        ),
        (
            "gemini/read-many-files.json",
            "gemini",
            "read_many_files",
            "src/**/*.rs\nREADME.md",
        ),
        (
            "gemini/list-directory.json",
            "gemini",
            "list_directory",
            "/home/u/app/src",
        ),
        (
            "gemini/write-file.json",
            "gemini",
            "write_file",
            "/home/u/app/run.sh",
        ),
        (
            "gemini/replace.json",
            "gemini",
            "replace",
            "/home/u/app/src/main.rs",
        ),
    ] {
        let (out, rec) = run(name, agent);
        assert_eq!(out.code, 0, "{name}: {}", out.stderr);
        assert!(out.stdout.is_empty(), "{name}: stdout must stay empty");
        assert_eq!(rec.decision, DecisionKind::Allow, "{name}");
        assert_eq!(rec.tool, tool, "{name}");
        assert_eq!(rec.input, input, "{name}");
        assert_eq!(
            rec.pack, None,
            "{name}: file tools are not judged by command packs"
        );
    }
}

/// The patch text of `apply_patch` contains `git reset --hard` as file
/// CONTENT (a context line of a script). Feeding it to the shell guard
/// would block a harmless edit.
#[test]
fn apply_patch_text_never_reaches_the_shell_guard() {
    let (out, rec) = run("codex/apply-patch.json", "codex");
    assert_eq!(out.code, 0);
    assert!(out.stderr.is_empty(), "no block message: {}", out.stderr);
    assert_eq!(rec.decision, DecisionKind::Allow);
    assert!(!rec.input.contains("git reset"), "{}", rec.input);
}

#[test]
fn unknown_tools_are_allowed_and_recorded_as_not_guarded() {
    for (name, agent, tool) in [
        ("claude/webfetch.json", "claude", "WebFetch"),
        ("codex/mcp-tool.json", "codex", "mcp__docs__search"),
        ("gemini/web-fetch.json", "gemini", "web_fetch"),
    ] {
        let (out, rec) = run(name, agent);
        assert_eq!(out.code, 0, "{name}");
        assert!(out.stdout.is_empty(), "{name}");
        assert_eq!(rec.decision, DecisionKind::Allow, "{name}");
        assert_eq!(rec.tool, tool, "{name}");
        assert_eq!(rec.reason.as_deref(), Some("tool not guarded"), "{name}");
    }
}

#[test]
fn malformed_fixtures_fail_open_with_error_allowed() {
    for name in [
        "malformed/truncated.json",
        "malformed/not-json.txt",
        "malformed/bash-no-command.json",
    ] {
        let (out, rec) = run(name, "claude");
        assert_eq!(out.code, 0, "{name}");
        assert!(out.stdout.is_empty(), "{name}");
        assert_eq!(rec.decision, DecisionKind::ErrorAllowed, "{name}");
        assert!(rec.reason.as_deref().unwrap().contains("payload"), "{name}");
    }
}

/// Review Focus 1: a `Write` of a file larger than the 256 KiB payload cap
/// is an ordinary file-tool call, not a guard failure.
#[test]
fn large_write_is_recorded_as_allow_with_its_path() {
    let payload = serde_json::json!({
        "session_id": "c-1",
        "cwd": "/home/u/app",
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": { "file_path": "/home/u/app/big.txt", "content": "x".repeat(600 * 1024) }
    })
    .to_string();
    let dir = tempfile::tempdir().unwrap();
    let out = check_bytes(dir.path(), "claude", payload.as_bytes());
    assert_eq!(out.code, 0);
    let rec = &read_all(dir.path()).records[0];
    assert_eq!(rec.decision, DecisionKind::Allow);
    assert_eq!(rec.tool, "Write");
    assert_eq!(rec.input, "/home/u/app/big.txt");
    assert_eq!(rec.session.as_deref(), Some("c-1"));
}
