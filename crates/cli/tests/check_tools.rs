//! `saiife check` against recorded-shape payloads of every agent and tool
//! (fixtures built from docs/superpowers/research/2026-10-13-*-hooks.md).

mod common;

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use saiife_audit::store::read_all;
use saiife_audit::{DecisionKind, Record};

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Run `saiife check` on `stdin` with `/home/u` mapped to a real temp home
/// (see `common::FixtureHome`); return the answer and the audit records in
/// `audit_dir`, both spelled with `/home/u` again.
fn check_bytes(audit_dir: &Path, agent: &str, stdin: &[u8]) -> (Out, Vec<Record>) {
    let home = common::FixtureHome::new();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_saiife"));
    let _sandbox = common::hermetic(&mut cmd, audit_dir);
    let mut child = cmd
        .args(["check", "--hook-exit", "--agent", agent])
        .current_dir(audit_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&home.real_bytes(stdin))
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let out = Out {
        code: out.status.code().unwrap_or(-1),
        stdout: home.spelled(&String::from_utf8_lossy(&out.stdout)),
        stderr: home.spelled(&String::from_utf8_lossy(&out.stderr)),
    };
    let recs = read_all(audit_dir)
        .records
        .into_iter()
        .map(|r| home.spelled_record(r))
        .collect();
    (out, recs)
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
    let (out, mut recs) = check_bytes(dir.path(), agent, &fixture(name));
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
fn file_tool_fixtures_are_judged_by_path_rules() {
    for (name, agent, tool, input, deny) in [
        (
            "claude/read.json",
            "claude",
            "Read",
            "/home/u/app/.env",
            true,
        ),
        (
            "claude/grep-no-path.json",
            "claude",
            "Grep",
            "/home/u/app",
            false,
        ),
        (
            "claude/write.json",
            "claude",
            "Write",
            "/home/u/app/notes.sh",
            false,
        ),
        (
            "claude/edit.json",
            "claude",
            "Edit",
            "/home/u/app/src/main.rs",
            false,
        ),
        (
            "claude/notebook-edit.json",
            "claude",
            "NotebookEdit",
            "/home/u/app/analysis.ipynb",
            false,
        ),
        (
            "codex/apply-patch.json",
            "codex",
            "apply_patch",
            "docs/recovery.md\nscripts/reset.sh",
            false,
        ),
        (
            "gemini/read-file.json",
            "gemini",
            "read_file",
            "/home/u/app/.env",
            true,
        ),
        (
            "gemini/read-many-files.json",
            "gemini",
            "read_many_files",
            "src/**/*.rs\nREADME.md",
            false,
        ),
        (
            "gemini/grep-search-no-path.json",
            "gemini",
            "grep_search",
            "/home/u/app",
            false,
        ),
        (
            "gemini/list-directory.json",
            "gemini",
            "list_directory",
            "/home/u/app/src",
            false,
        ),
        (
            "gemini/write-file.json",
            "gemini",
            "write_file",
            "/home/u/app/run.sh",
            false,
        ),
        (
            "gemini/replace.json",
            "gemini",
            "replace",
            "/home/u/app/src/main.rs",
            false,
        ),
    ] {
        let (out, rec) = run(name, agent);
        assert!(out.stdout.is_empty(), "{name}: stdout must stay empty");
        assert_eq!(rec.tool, tool, "{name}");
        assert_eq!(rec.input, input, "{name}");
        if deny {
            assert_eq!(out.code, 2, "{name}: {}", out.stderr);
            assert!(
                out.stderr.contains("BLOCKED by core.secrets"),
                "{name}: {}",
                out.stderr
            );
            assert_eq!(rec.decision, DecisionKind::Deny, "{name}");
            assert_eq!(rec.pack.as_deref(), Some("core.secrets"), "{name}");
        } else {
            assert_eq!(out.code, 0, "{name}: {}", out.stderr);
            assert_eq!(rec.decision, DecisionKind::Allow, "{name}");
            assert_eq!(rec.pack, None, "{name}");
        }
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
    let (out, recs) = check_bytes(dir.path(), "claude", payload.as_bytes());
    assert_eq!(out.code, 0);
    let rec = &recs[0];
    assert_eq!(rec.decision, DecisionKind::Allow);
    assert_eq!(rec.tool, "Write");
    assert_eq!(rec.input, "/home/u/app/big.txt");
    assert_eq!(rec.session.as_deref(), Some("c-1"));
}

/// A recorded fixture with `edit` applied to its JSON: the same payload
/// shape, another tool input.
fn variant(name: &str, edit: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    let mut v: serde_json::Value = serde_json::from_slice(&fixture(name)).unwrap();
    edit(&mut v);
    v.to_string().into_bytes()
}

fn run_bytes(agent: &str, stdin: &[u8]) -> (Out, Record) {
    let dir = tempfile::tempdir().unwrap();
    let (out, mut recs) = check_bytes(dir.path(), agent, stdin);
    assert_eq!(recs.len(), 1, "exactly one record");
    (out, recs.remove(0))
}

fn shell(name: &str, command: &str) -> Vec<u8> {
    variant(name, |v| v["tool_input"]["command"] = command.into())
}

const CODEX_PATCH: &str = "*** Begin Patch\n*** Update File: .codex/config.toml\n@@\n-[[hooks.PreToolUse]]\n*** End Patch\n";

/// Spec §10 / §12 demo: per agent, reading `.env` and removing the hook
/// are blocked (exit 2 + reason on stderr) and audited as denies.
#[test]
fn secret_reads_and_hook_edits_are_blocked_for_every_agent() {
    let cases: Vec<(&str, Vec<u8>, &str, &str)> = vec![
        (
            "claude",
            fixture("claude/read.json"),
            "core.secrets",
            "/home/u/app/.env",
        ),
        (
            "claude",
            variant("claude/write.json", |v| {
                v["tool_input"]["file_path"] = "/home/u/app/.claude/settings.json".into()
            }),
            "core.self",
            "/home/u/app/.claude/settings.json",
        ),
        (
            "codex",
            shell("codex/bash-allow.json", "cat .env"),
            "core.secrets",
            "cat .env",
        ),
        (
            "codex",
            variant("codex/apply-patch.json", |v| {
                v["tool_input"]["command"] = CODEX_PATCH.into()
            }),
            "core.self",
            ".codex/config.toml",
        ),
        (
            "gemini",
            fixture("gemini/read-file.json"),
            "core.secrets",
            "/home/u/app/.env",
        ),
        (
            "gemini",
            variant("gemini/write-file.json", |v| {
                v["tool_input"]["file_path"] = "/home/u/app/.gemini/settings.json".into()
            }),
            "core.self",
            "/home/u/app/.gemini/settings.json",
        ),
    ];
    for (agent, stdin, pack, input) in cases {
        let (out, rec) = run_bytes(agent, &stdin);
        assert_eq!(out.code, 2, "{agent} {input}: {}", out.stderr);
        assert!(out.stdout.is_empty(), "{agent} {input}");
        assert!(
            out.stderr.contains(&format!("BLOCKED by {pack}")),
            "{agent} {input}: {}",
            out.stderr
        );
        assert_eq!(rec.decision, DecisionKind::Deny, "{agent} {input}");
        assert_eq!(rec.pack.as_deref(), Some(pack), "{agent} {input}");
        assert_eq!(rec.input, input, "{agent}");
        assert_eq!(rec.agent, agent);
    }
}

#[test]
fn init_off_from_an_agent_is_blocked() {
    for (agent, name) in [
        ("claude", "claude/bash-allow.json"),
        ("codex", "codex/bash-allow.json"),
        ("gemini", "gemini/shell-allow.json"),
    ] {
        let (out, rec) = run_bytes(agent, &shell(name, "saiife init --off"));
        assert_eq!(out.code, 2, "{agent}: {}", out.stderr);
        assert!(
            out.stderr.contains("BLOCKED by core.self"),
            "{}",
            out.stderr
        );
        assert!(out.stderr.contains("your own terminal"), "{}", out.stderr);
        assert_eq!(rec.decision, DecisionKind::Deny);
        assert_eq!(rec.input, "saiife init --off");
    }
}

#[test]
fn reading_saiife_and_agent_config_stays_allowed() {
    for path in [
        "/home/u/app/.saiife/config.toml",
        "/home/u/app/.claude/settings.json",
        "/home/u/app/.codex/config.toml",
    ] {
        let stdin = variant("claude/read.json", |v| {
            v["tool_input"]["file_path"] = path.into()
        });
        let (out, rec) = run_bytes("claude", &stdin);
        assert_eq!(out.code, 0, "{path}: {}", out.stderr);
        assert_eq!(rec.decision, DecisionKind::Allow, "{path}");
    }
    let (out, rec) = run_bytes(
        "gemini",
        &shell("gemini/shell-allow.json", "cat .saiife/config.toml"),
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(rec.decision, DecisionKind::Allow);
}

/// Plan 2 carry-over: an `apply_patch` without file headers has nothing to
/// judge: a fail-open, never a silent allow.
#[test]
fn apply_patch_without_headers_is_recorded_as_unjudged() {
    let stdin = variant("codex/apply-patch.json", |v| {
        v["tool_input"]["command"] = "*** Begin Patch\n*** End Patch\n".into()
    });
    let (out, rec) = run_bytes("codex", &stdin);
    assert_eq!(out.code, 0);
    assert!(out.stdout.is_empty());
    assert_eq!(rec.decision, DecisionKind::ErrorAllowed);
    assert_eq!(rec.reason.as_deref(), Some("no path to judge"));
}

/// Controller ruling M1: a search tool with neither `path` nor `cwd`
/// judges the hook's own directory (what it reads), not a fail-open.
#[test]
fn pathless_search_without_cwd_judges_the_hook_directory() {
    let stdin = br#"{"session_id":"c-1","hook_event_name":"PreToolUse","tool_name":"Glob","tool_input":{"pattern":"**/*.rs"}}"#;
    let dir = tempfile::tempdir().unwrap();
    let (out, mut recs) = check_bytes(dir.path(), "claude", stdin);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let rec = recs.remove(0);
    assert_eq!(rec.decision, DecisionKind::Allow);
    let real = std::fs::canonicalize(dir.path()).unwrap();
    assert_eq!(
        std::fs::canonicalize(&rec.input).unwrap(),
        real,
        "judged: {}",
        rec.input
    );
}

#[test]
fn claude_glob_and_ls_are_read_tools() {
    let ls = variant("claude/read.json", |v| {
        v["tool_name"] = "LS".into();
        v["tool_input"] = serde_json::json!({"path": "/home/u/app/src"});
    });
    let (out, rec) = run_bytes("claude", &ls);
    assert_eq!(out.code, 0);
    assert_eq!(rec.tool, "LS");
    assert_eq!(rec.input, "/home/u/app/src");
    assert_eq!(rec.decision, DecisionKind::Allow);
    // A Glob rooted at a secret path is judged like a read of it.
    let glob = variant("claude/read.json", |v| {
        v["tool_name"] = "Glob".into();
        v["tool_input"] = serde_json::json!({"pattern": "*", "path": "/home/u/app/.env"});
    });
    let (out, rec) = run_bytes("claude", &glob);
    assert_eq!(out.code, 2, "{}", out.stderr);
    assert_eq!(rec.pack.as_deref(), Some("core.secrets"));
}

/// Review Focus 3: a Write whose content is over the 256 KiB payload cap is
/// still judged by its path: removing the hook this way is blocked.
#[test]
fn large_write_to_agent_settings_is_denied() {
    let payload = serde_json::json!({
        "session_id": "c-1",
        "cwd": "/home/u/app",
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/home/u/app/.claude/settings.json",
            "content": "x".repeat(600 * 1024)
        }
    })
    .to_string();
    let (out, rec) = run_bytes("claude", payload.as_bytes());
    assert_eq!(out.code, 2, "{}", out.stderr);
    assert_eq!(rec.decision, DecisionKind::Deny);
    assert_eq!(rec.pack.as_deref(), Some("core.self"));
}

/// Review Focus 5: a payload without `cwd` resolves relative paths against
/// the hook's own working directory (the agent starts hooks in the
/// project), so `.env` is still judged, not waved through.
#[test]
fn relative_path_without_cwd_uses_the_hook_directory() {
    let stdin = br#"{"session_id":"g-1","hook_event_name":"BeforeTool","tool_name":"read_many_files","tool_input":{"include":["README.md",".env"]}}"#;
    let (out, rec) = run_bytes("gemini", stdin);
    assert_eq!(out.code, 2, "{}", out.stderr);
    assert_eq!(rec.pack.as_deref(), Some("core.secrets"));
    assert_eq!(rec.input, "README.md\n.env");
}

/// A project directory holding `.env` and `a.rs`, and a payload for
/// `agent`'s search/read tool rooted there.
fn project_with_env() -> tempfile::TempDir {
    let p = tempfile::tempdir().unwrap();
    std::fs::write(p.path().join(".env"), "TOKEN=1\n").unwrap();
    std::fs::write(p.path().join("a.rs"), "fn main() {}\n").unwrap();
    p
}

fn payload(tool: &str, cwd: &Path, input: serde_json::Value) -> Vec<u8> {
    serde_json::json!({
        "session_id": "x-1",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": input
    })
    .to_string()
    .into_bytes()
}

/// Controller ruling C2/I1: patterns are expanded and every match judged.
#[test]
fn glob_patterns_are_expanded_and_every_match_judged() {
    let p = project_with_env();
    for (agent, tool, input) in [
        (
            "claude",
            "Grep",
            serde_json::json!({"pattern": "TOKEN", "path": ".", "glob": ".env*"}),
        ),
        (
            "claude",
            "Grep",
            serde_json::json!({"pattern": "TOKEN", "glob": ".env*"}),
        ),
        (
            "gemini",
            "grep_search",
            serde_json::json!({"pattern": "TOKEN", "include": ".env*"}),
        ),
        (
            "gemini",
            "read_many_files",
            serde_json::json!({"include": [".env*"]}),
        ),
    ] {
        let (out, rec) = run_bytes(agent, &payload(tool, p.path(), input));
        assert_eq!(out.code, 2, "{tool}: {}", out.stderr);
        assert_eq!(rec.decision, DecisionKind::Deny, "{tool}");
        assert_eq!(rec.pack.as_deref(), Some("core.secrets"), "{tool}");
    }
}

#[test]
fn glob_patterns_that_match_nothing_secret_are_allowed() {
    let p = project_with_env();
    for (agent, tool, input) in [
        (
            "claude",
            "Grep",
            serde_json::json!({"pattern": "main", "glob": "*.rs"}),
        ),
        (
            "gemini",
            "read_many_files",
            serde_json::json!({"include": ["*.rs"]}),
        ),
        // Glob and glob_search patterns are listings: only the root is judged.
        (
            "claude",
            "Glob",
            serde_json::json!({"pattern": ".env*", "path": p.path()}),
        ),
    ] {
        let (out, rec) = run_bytes(agent, &payload(tool, p.path(), input));
        assert_eq!(out.code, 0, "{tool}: {}", out.stderr);
        assert_eq!(rec.decision, DecisionKind::Allow, "{tool}");
    }
}

#[test]
fn a_glob_too_large_to_judge_is_a_recorded_fail_open() {
    let p = tempfile::tempdir().unwrap();
    for i in 0..4200 {
        std::fs::write(p.path().join(format!("f{i}.txt")), "").unwrap();
    }
    let (out, rec) = run_bytes(
        "gemini",
        &payload(
            "read_many_files",
            p.path(),
            serde_json::json!({"include": ["*.txt"]}),
        ),
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(rec.decision, DecisionKind::ErrorAllowed);
    assert_eq!(rec.reason.as_deref(), Some("glob too large to judge"));
}

/// Review Important 1: Review Focus 3 holds at any size. A `Write` far
/// above every parse cap is still judged by its path.
#[test]
fn huge_write_is_judged_by_its_path() {
    for tool in ["Write", "Edit", "MultiEdit"] {
        let big = |path: &str| {
            serde_json::json!({
                "session_id": "c-1",
                "cwd": "/home/u/app",
                "hook_event_name": "PreToolUse",
                "tool_name": tool,
                "tool_input": {
                    "file_path": path,
                    "content": "x".repeat(2 * 1024 * 1024 + 5),
                    "new_string": "y".repeat(100),
                    "edits": [{"old_string": "a", "new_string": "b"}]
                }
            })
            .to_string()
        };
        let (out, rec) = run_bytes(
            "claude",
            big("/home/u/app/.claude/settings.json").as_bytes(),
        );
        assert_eq!(out.code, 2, "{tool}: {}", out.stderr);
        assert_eq!(rec.decision, DecisionKind::Deny, "{tool}");
        assert_eq!(rec.pack.as_deref(), Some("core.self"), "{tool}");
        assert_eq!(rec.input, "/home/u/app/.claude/settings.json");
        assert!(!out.stderr.contains("262144"), "{}", out.stderr);
        let (out, rec) = run_bytes("claude", big("/home/u/app/src/big.rs").as_bytes());
        assert_eq!(out.code, 0, "{tool}: {}", out.stderr);
        assert!(out.stdout.is_empty() && out.stderr.is_empty(), "{tool}");
        assert_eq!(rec.decision, DecisionKind::Allow, "{tool}");
        assert_eq!(rec.input, "/home/u/app/src/big.rs");
    }
}

/// A shell command above the payload cap stays a recorded fail-open, and
/// its reason names the real limit.
#[test]
fn oversize_shell_payload_names_its_real_limit() {
    let stdin = serde_json::json!({
        "tool_name": "Bash", "cwd": "/home/u/app",
        "tool_input": {"command": format!("echo {}", "a".repeat(300 * 1024))}
    })
    .to_string();
    let (out, rec) = run_bytes("claude", stdin.as_bytes());
    assert_eq!(out.code, 0);
    assert_eq!(rec.decision, DecisionKind::ErrorAllowed);
    assert!(out.stderr.contains("262144"), "{}", out.stderr);
}

/// Minor 1: a write with no path is not a judged allow of the cwd.
#[test]
fn write_without_a_path_is_a_fail_open() {
    for stdin in [
        br#"{"tool_name":"Write","cwd":"/home/u/app","tool_input":{"content":"x"}}"#.as_slice(),
        br#"{"tool_name":"Edit","tool_input":{"new_string":"x"}}"#.as_slice(),
    ] {
        let (out, rec) = run_bytes("claude", stdin);
        assert_eq!(out.code, 0);
        assert_eq!(rec.decision, DecisionKind::ErrorAllowed);
        assert_eq!(rec.reason.as_deref(), Some("no path to judge"));
    }
}

/// Minor 3: Gemini versions that name the files in `paths`.
#[test]
fn read_many_files_paths_are_judged() {
    let p = project_with_env();
    let (out, rec) = run_bytes(
        "gemini",
        &payload(
            "read_many_files",
            p.path(),
            serde_json::json!({"paths": [".env*"]}),
        ),
    );
    assert_eq!(out.code, 2, "{}", out.stderr);
    assert_eq!(rec.pack.as_deref(), Some("core.secrets"));
}

/// Extra finding 1: a search filter without `/` matches at any depth
/// (ripgrep); one with `/` is relative to the root.
#[test]
fn search_filters_follow_ripgrep_semantics() {
    let p = project_with_env();
    std::fs::create_dir_all(p.path().join("sub/deep")).unwrap();
    std::fs::write(p.path().join("sub/deep/.env.local"), "T=1").unwrap();
    std::fs::remove_file(p.path().join(".env")).unwrap();
    for (tool, key, filter, deny) in [
        ("Grep", "glob", ".env*", true),
        ("grep_search", "include", ".env.local", true),
        ("Grep", "glob", "sub/deep/.env*", true),
        ("Grep", "glob", "sub/.env*", false),
        ("Grep", "glob", "*.rs", false),
    ] {
        let agent = if tool == "Grep" { "claude" } else { "gemini" };
        let mut input = serde_json::json!({"pattern": "T"});
        input[key] = filter.into();
        let (out, rec) = run_bytes(agent, &payload(tool, p.path(), input));
        if deny {
            assert_eq!(out.code, 2, "{filter}: {}", out.stderr);
            assert_eq!(rec.pack.as_deref(), Some("core.secrets"), "{filter}");
        } else {
            assert_eq!(out.code, 0, "{filter}: {}", out.stderr);
        }
    }
}

/// Extra finding 2: on overflow a secret among the entries seen is still
/// denied; otherwise the call is a recorded fail-open.
#[test]
fn overflow_still_denies_what_it_found() {
    let p = tempfile::tempdir().unwrap();
    for i in 0..4200 {
        std::fs::write(p.path().join(format!("f{i}.txt")), "").unwrap();
    }
    std::fs::write(p.path().join(".env"), "T=1").unwrap();
    let (out, rec) = run_bytes(
        "gemini",
        &payload(
            "read_many_files",
            p.path(),
            serde_json::json!({"include": ["*.txt", ".env"]}),
        ),
    );
    assert_eq!(out.code, 2, "{}", out.stderr);
    assert_eq!(rec.decision, DecisionKind::Deny);
}
