//! `saiife status` tamper checks (spec §7.5, §10 "Tamper detection"): each
//! check tampers with one thing and expects a warning, a fix and exit 1; an
//! untouched project exits 0.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use common::{code, fake_exe, stdout, Env};

fn initialized(agents: &[&str]) -> Env {
    let env = Env::new(agents);
    let out = env.saiife(&["init"]);
    assert_eq!(code(&out), 0, "{}", stdout(&out));
    env
}

fn status(env: &Env) -> (i32, String) {
    let out = env.saiife(&["status"]);
    (code(&out), stdout(&out))
}

#[test]
fn untouched_project_passes() {
    let env = initialized(&["claude", "codex", "gemini"]);
    let (c, text) = status(&env);
    assert_eq!(c, 0, "{text}");
    assert!(text.contains("All checks passed."), "{text}");
    for a in ["claude", "codex", "gemini"] {
        assert!(
            text.lines()
                .any(|l| l.contains(a) && l.contains("hooked") && l.contains("no call yet")),
            "{a}: {text}"
        );
    }
    assert!(text.contains("packs   core.filesystem, core.git"), "{text}");
    assert!(text.contains("cannot stop a determined agent"), "{text}");
}

/// Upgrade path (plan 3): a hook written by plan 2's saiife (Claude matcher
/// without Glob/LS) passes its own fingerprint but is out of date; status
/// says so and `saiife init` brings it up to date.
#[test]
fn hook_from_an_older_saiife_is_reported_and_init_updates_it() {
    use saiife_agents::claude::{MATCHER, MATCHER_V1};
    let env = initialized(&["claude"]);
    let old = env
        .read(".claude/settings.json")
        .replace(MATCHER, MATCHER_V1);
    env.write(".claude/settings.json", &old);
    let old_fp = saiife_agents::Agent::Claude.entries(env.root()).unwrap()[0].clone();
    for e in std::fs::read_dir(env.data.path().join("projects")).unwrap() {
        let p = e.unwrap().path();
        let mut v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        v["hooks"]["claude"]["sha256"] = old_fp.clone().into();
        std::fs::write(&p, v.to_string()).unwrap();
    }
    let (c, text) = status(&env);
    assert_eq!(c, 1, "{text}");
    assert!(
        text.contains("was written by an older saiife and does not cover every tool"),
        "{text}"
    );
    assert!(
        text.contains("Fix: run `saiife init` to update it"),
        "{text}"
    );

    let out = env.saiife(&["init"]);
    assert_eq!(code(&out), 0, "{}", stdout(&out));
    assert!(env.read(".claude/settings.json").contains(MATCHER));
    let (c, text) = status(&env);
    assert_eq!(c, 0, "{text}");
}

#[test]
fn not_initialized_fails() {
    let env = Env::new(&["claude"]);
    let (c, text) = status(&env);
    assert_eq!(c, 1);
    assert!(text.contains("not set up for this project"), "{text}");
}

#[test]
fn hook_removed_by_hand_is_reported_with_the_fix() {
    let env = initialized(&["claude"]);
    env.write(".claude/settings.json", "{}\n");
    let (c, text) = status(&env);
    assert_eq!(c, 1);
    assert!(
        text.contains("The saiife hook for Claude Code was removed from .claude/settings.json."),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "Fix: run `saiife init` in {} to restore it",
            std::fs::canonicalize(env.root()).unwrap().display()
        )),
        "{text}"
    );
    // ...and init does restore it.
    assert_eq!(code(&env.saiife(&["init"])), 0);
    assert_eq!(status(&env).0, 0);
}

#[test]
fn hook_changed_is_reported() {
    let env = initialized(&["codex"]);
    let t = env
        .read(".codex/config.toml")
        .replace("^(Bash|apply_patch)$", "^Nothing$");
    env.write(".codex/config.toml", &t);
    let (c, text) = status(&env);
    assert_eq!(c, 1);
    assert!(
        text.contains("The saiife hook for Codex in .codex/config.toml was changed."),
        "{text}"
    );
}

#[test]
fn settings_file_deleted_is_reported() {
    let env = initialized(&["gemini"]);
    std::fs::remove_file(env.root().join(".gemini/settings.json")).unwrap();
    let (c, text) = status(&env);
    assert_eq!(c, 1);
    assert!(
        text.contains("was removed from .gemini/settings.json"),
        "{text}"
    );
}

#[test]
fn config_edited_is_reported() {
    let env = initialized(&["claude"]);
    let t = env
        .read(".saiife/config.toml")
        .replace("\"core.git\"", "\"db.mysql\"");
    env.write(".saiife/config.toml", &t);
    let (c, text) = status(&env);
    assert_eq!(c, 1);
    assert!(
        text.contains(".saiife/config.toml was changed since `saiife init`."),
        "{text}"
    );
}

#[test]
fn config_deleted_is_reported() {
    let env = initialized(&["claude"]);
    std::fs::remove_file(env.root().join(".saiife/config.toml")).unwrap();
    // Without the config the project root is the cwd itself, which is still
    // the project: the record is found by path.
    let (c, text) = status(&env);
    assert_eq!(c, 1);
    assert!(text.contains(".saiife/config.toml was removed."), "{text}");
}

#[test]
fn swapped_binary_on_path_is_reported() {
    let env = initialized(&["claude"]);
    std::fs::remove_file(env.bin.path().join("saiife")).unwrap();
    fake_exe(env.bin.path(), "saiife", "echo 'saiife 0.1.0'");
    let (c, text) = status(&env);
    assert_eq!(c, 1);
    assert!(
        text.contains("is not the one that ran `saiife init`"),
        "{text}"
    );
}

#[test]
fn saiife_missing_from_path_is_reported() {
    let env = initialized(&["claude"]);
    std::fs::remove_file(env.bin.path().join("saiife")).unwrap();
    let (c, text) = status(&env);
    assert_eq!(c, 1);
    assert!(text.contains("`saiife` is not on PATH"), "{text}");
}

#[test]
fn disable_all_hooks_is_reported() {
    let env = initialized(&["claude"]);
    env.write(
        ".claude/settings.local.json",
        "{\"disableAllHooks\": true}\n",
    );
    let (c, text) = status(&env);
    assert_eq!(c, 1);
    assert!(text.contains("sets disableAllHooks"), "{text}");
    // User-level settings count too.
    std::fs::remove_file(env.root().join(".claude/settings.local.json")).unwrap();
    std::fs::create_dir_all(env.home.path().join(".claude")).unwrap();
    std::fs::write(
        env.home.path().join(".claude/settings.json"),
        "{\"disableAllHooks\": true}",
    )
    .unwrap();
    assert_eq!(status(&env).0, 1);
}

#[test]
fn last_hook_call_is_shown_per_agent() {
    let env = initialized(&["claude", "codex"]);
    let payload = serde_json::json!({
        "session_id": "s",
        // Canonical, as an agent reports its cwd (macOS temp dirs sit behind
        // the /var -> /private/var symlink).
        "cwd": env.root().canonicalize().unwrap().join("src"),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "ls" }
    })
    .to_string();
    let mut child = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["check", "--hook-exit", "--agent", "claude"])
        .env("HOME", env.home.path())
        .env("SAIIFE_DATA_DIR", env.data.path())
        .env("SAIIFE_AUDIT_DIR", env.audit.path())
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
    assert_eq!(child.wait().unwrap().code(), Some(0));
    let (c, text) = status(&env);
    assert_eq!(c, 0, "{text}");
    let claude = text
        .lines()
        .find(|l| l.trim_start().starts_with("claude"))
        .unwrap();
    assert!(claude.contains("s ago"), "{claude}");
    let codex = text
        .lines()
        .find(|l| l.trim_start().starts_with("codex"))
        .unwrap();
    assert!(codex.contains("no call yet"), "{codex}");
}

#[test]
fn unreadable_audit_dir_is_a_failed_check() {
    let env = initialized(&["claude"]);
    let file = env.audit.path().join("not-a-dir");
    std::fs::write(&file, "x").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .arg("status")
        .current_dir(env.root())
        .env("PATH", env.bin.path())
        .env("HOME", env.home.path())
        .env("SAIIFE_DATA_DIR", env.data.path())
        .env("SAIIFE_AUDIT_DIR", &file)
        .env("SAIIFE_TEST_CLAUDE_MANAGED_DIRS", env.managed.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains("cannot be read"), "{}", stdout(&out));
}

#[cfg(unix)]
#[test]
fn fifo_in_the_audit_dir_is_a_failed_check() {
    let env = initialized(&["claude"]);
    let fifo = env.audit.path().join("2026-01.jsonl");
    assert!(Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let (c, text) = status(&env);
    assert_eq!(c, 1);
    assert!(text.contains("are not regular files"), "{text}");
}

/// Review Focus 3: the same project reached through a symlink, or status
/// run from a subdirectory, finds the same record.
#[cfg(unix)]
#[test]
fn symlinked_path_and_subdirectory_find_the_same_project() {
    let env = initialized(&["claude"]);
    let link_parent = tempfile::tempdir().unwrap();
    let link = link_parent.path().join("app");
    std::os::unix::fs::symlink(env.root(), &link).unwrap();
    let out = env.saiife_in(&link, &["status"]);
    assert_eq!(code(&out), 0, "{}", stdout(&out));
    let sub = env.root().join("src");
    std::fs::create_dir_all(&sub).unwrap();
    let out = env.saiife_in(&sub, &["status"]);
    assert_eq!(code(&out), 0, "{}", stdout(&out));
}

/// Replace the symlink to the binary under test with a real copy, so the
/// test can later change the file's content in place.
fn with_real_copy(agents: &[&str]) -> Env {
    let env = Env::new(agents);
    let exe = env.bin.path().join("saiife");
    std::fs::remove_file(&exe).unwrap();
    std::fs::copy(env!("CARGO_BIN_EXE_saiife"), &exe).unwrap();
    // Run init through the copy so the record names it.
    let out = Command::new(&exe)
        .arg("init")
        .current_dir(env.root())
        .env("PATH", env.bin.path())
        .env("HOME", env.home.path())
        .env("SAIIFE_DATA_DIR", env.data.path())
        .env("SAIIFE_AUDIT_DIR", env.audit.path())
        .env("SAIIFE_TEST_CLAUDE_MANAGED_DIRS", env.managed.path())
        .output()
        .unwrap();
    assert_eq!(code(&out), 0, "{}", stdout(&out));
    env
}

#[cfg(unix)]
#[test]
fn binary_replaced_in_place_is_reported() {
    let env = with_real_copy(&["claude"]);
    assert_eq!(status(&env).0, 0);
    let exe = env.bin.path().join("saiife");
    // Same path, same permissions, new content that still claims the version.
    std::fs::write(
        &exe,
        format!("#!/bin/sh\necho 'saiife {}'\n", env!("CARGO_PKG_VERSION")),
    )
    .unwrap();
    let (c, text) = status(&env);
    assert_eq!(c, 1);
    assert!(text.contains("was replaced since `saiife init`"), "{text}");
}

/// Absolute path of `sleep`: the fakes run with PATH = the test's bin dir
/// only, where a bare `sleep` would not be found (and no grandchild would
/// hold the pipe).
fn sleep_bin() -> std::path::PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .chain([std::path::PathBuf::from("/bin")])
        .map(|d| d.join("sleep"))
        .find(|p| p.is_file())
        .expect("sleep on PATH")
}

#[cfg(unix)]
#[test]
fn version_probe_does_not_hang_on_a_lingering_grandchild() {
    let env = with_real_copy(&["claude"]);
    let exe = env.bin.path().join("saiife");
    std::fs::write(
        &exe,
        format!(
            "#!/bin/sh\necho 'saiife {}'\n{} 30 &\n",
            env!("CARGO_PKG_VERSION"),
            sleep_bin().display()
        ),
    )
    .unwrap();
    // Pretend an older record without a binary hash, so the probe runs.
    for e in std::fs::read_dir(env.data.path().join("projects")).unwrap() {
        let p = e.unwrap().path();
        let mut v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        v["saiife_sha256"] = "".into();
        std::fs::write(&p, v.to_string()).unwrap();
    }
    let started = std::time::Instant::now();
    let (c, text) = status(&env);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(8),
        "hung"
    );
    assert_eq!(c, 0, "{text}");
}

/// F4: the probe's timeout path. The fake prints its version without a
/// newline and leaves a grandchild holding the pipe, so the first line never
/// completes: status gives up and says so instead of hanging.
#[cfg(unix)]
#[test]
fn version_probe_times_out_without_a_newline() {
    let env = with_real_copy(&["claude"]);
    let exe = env.bin.path().join("saiife");
    std::fs::write(
        &exe,
        format!(
            "#!/bin/sh\nprintf 'saiife {}'\n{} 30 &\n",
            env!("CARGO_PKG_VERSION"),
            sleep_bin().display()
        ),
    )
    .unwrap();
    for e in std::fs::read_dir(env.data.path().join("projects")).unwrap() {
        let p = e.unwrap().path();
        let mut v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        v["saiife_sha256"] = "".into();
        std::fs::write(&p, v.to_string()).unwrap();
    }
    let started = std::time::Instant::now();
    let (c, text) = status(&env);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "hung: {:?}",
        started.elapsed()
    );
    assert_eq!(c, 1, "{text}");
    assert!(text.contains("could not read the version"), "{text}");
}

#[test]
fn unreadable_blocker_input_is_a_failed_check() {
    let env = initialized(&["claude"]);
    env.write(".claude/settings.local.json", "{ not json");
    let (c, text) = status(&env);
    assert_eq!(c, 1);
    assert!(
        text.contains("settings.local.json cannot be read"),
        "{text}"
    );
    assert!(
        text.contains("Fix: make it readable so saiife can check it"),
        "{text}"
    );
}

#[test]
fn managed_allow_managed_hooks_only_is_reported_with_admin_fix() {
    let env = initialized(&["claude"]);
    std::fs::write(
        env.managed.path().join("managed-settings.json"),
        "{\"allowManagedHooksOnly\": true}",
    )
    .unwrap();
    let (c, text) = status(&env);
    assert_eq!(c, 1);
    assert!(text.contains("allowManagedHooksOnly"), "{text}");
    assert!(text.contains("ask your administrator"), "{text}");
}

/// I1: an agent `init` could not set up is a failed check, not "not set up".
#[test]
fn agent_init_could_not_set_up_is_a_failed_check() {
    let env = Env::new(&["claude"]);
    let broken = "{\n  // my comment\n  \"model\": \"opus\"\n}\n";
    env.write(".claude/settings.json", broken);
    let out = env.saiife(&["init", "--agent", "claude"]);
    assert_eq!(code(&out), 1, "{}", stdout(&out));
    assert!(
        !stdout(&out).contains("- Claude Code:"),
        "no next steps for a failed agent: {}",
        stdout(&out)
    );
    let (c, text) = status(&env);
    assert_eq!(c, 1, "{text}");
    assert!(
        text.contains("`saiife init` could not set up Claude Code"),
        "{text}"
    );
    assert!(
        text.contains("repair .claude/settings.json, then run `saiife init`"),
        "{text}"
    );
    assert_eq!(env.read(".claude/settings.json"), broken);
}

/// I1: a record with no hooked agent at all guards nothing.
#[test]
fn record_without_any_hooked_agent_is_a_failed_check() {
    let env = initialized(&["claude"]);
    for e in std::fs::read_dir(env.data.path().join("projects")).unwrap() {
        let p = e.unwrap().path();
        let mut v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        v["hooks"] = serde_json::json!({});
        std::fs::write(&p, v.to_string()).unwrap();
    }
    std::fs::remove_file(env.root().join(".claude/settings.json")).unwrap();
    let (c, text) = status(&env);
    assert_eq!(c, 1, "{text}");
    assert!(text.contains("no agent is hooked"), "{text}");
}

/// A record whose only entries are failed agents still says nothing is
/// protected.
#[test]
fn record_with_only_failed_agents_says_nothing_is_guarded() {
    let env = initialized(&["claude"]);
    for e in std::fs::read_dir(env.data.path().join("projects")).unwrap() {
        let p = e.unwrap().path();
        let mut v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        v["hooks"]["claude"]["sha256"] = "".into();
        v["hooks"]["claude"]["error"] = "disk full".into();
        std::fs::write(&p, v.to_string()).unwrap();
    }
    let (c, text) = status(&env);
    assert_eq!(c, 1, "{text}");
    assert!(text.contains("could not set up Claude Code"), "{text}");
    assert!(text.contains("no agent is hooked"), "{text}");
}

/// M3: an agent that reports its cwd through a symlink to the project
/// still counts as a hook call of this project.
#[cfg(unix)]
#[test]
fn last_hook_call_through_a_symlinked_cwd_is_shown() {
    let env = initialized(&["claude"]);
    let link_parent = tempfile::tempdir().unwrap();
    let link = link_parent.path().join("app");
    std::os::unix::fs::symlink(env.root(), &link).unwrap();
    let payload = serde_json::json!({
        "session_id": "s",
        "cwd": link,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "ls" }
    })
    .to_string();
    let mut child = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["check", "--hook-exit", "--agent", "claude"])
        .env("HOME", env.home.path())
        .env("SAIIFE_DATA_DIR", env.data.path())
        .env("SAIIFE_AUDIT_DIR", env.audit.path())
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
    assert_eq!(child.wait().unwrap().code(), Some(0));
    let (c, text) = status(&env);
    assert_eq!(c, 0, "{text}");
    let claude = text
        .lines()
        .find(|l| l.trim_start().starts_with("claude"))
        .unwrap();
    assert!(claude.contains("s ago"), "{claude}");
}

/// M4: when `init` cannot hash its own binary it warns, and status reports
/// the missing hash as a failed check (not the "older record" note).
#[cfg(unix)]
#[test]
fn unhashable_binary_at_init_is_a_failed_check() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new(&["claude"]);
    let exe = env.bin.path().join("saiife");
    std::fs::remove_file(&exe).unwrap();
    std::fs::copy(env!("CARGO_BIN_EXE_saiife"), &exe).unwrap();
    // Execute-only: runs, but cannot be read (unless we are root).
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o111)).unwrap();
    if std::fs::read(&exe).is_ok() {
        eprintln!("skipped: running as root, the binary stays readable");
        return;
    }
    let out = Command::new(&exe)
        .arg("init")
        .current_dir(env.root())
        .env("PATH", env.bin.path())
        .env("HOME", env.home.path())
        .env("SAIIFE_DATA_DIR", env.data.path())
        .env("SAIIFE_AUDIT_DIR", env.audit.path())
        .env("SAIIFE_TEST_CLAUDE_MANAGED_DIRS", env.managed.path())
        .output()
        .unwrap();
    assert!(
        stdout(&out).contains("WARNING: could not compute the SHA-256"),
        "{}",
        stdout(&out)
    );
    let (c, text) = status(&env);
    assert_eq!(c, 1, "{text}");
    assert!(
        text.contains("could not compute the SHA-256 of the saiife binary"),
        "{text}"
    );
    assert!(!text.contains("made by an older saiife"), "{text}");
}

/// M5: an unreadable managed-settings file is the administrator's to fix.
#[test]
fn unreadable_managed_settings_tell_you_to_ask_the_administrator() {
    let env = initialized(&["claude"]);
    // A directory where the file should be: unreadable even as root.
    std::fs::create_dir(env.managed.path().join("managed-settings.json")).unwrap();
    let (c, text) = status(&env);
    assert_eq!(c, 1, "{text}");
    assert!(
        text.contains("managed-settings.json cannot be read"),
        "{text}"
    );
    assert!(text.contains("Fix: ask your administrator"), "{text}");
    assert!(!text.contains("make it readable so saiife"), "{text}");
}

/// Residual (M3): a relative project path in a record (an odd payload)
/// must not resolve against status's own cwd and count for this project.
#[test]
fn relative_recorded_project_does_not_count_as_a_hook_call() {
    use saiife_audit::{store, DecisionKind, NewRecord, Record};
    let env = initialized(&["claude"]);
    for project in [".", "src", "./"] {
        let rec = Record::new(
            NewRecord {
                agent: "claude",
                project,
                session: None,
                tool: "Bash",
                input: "ls",
                decision: DecisionKind::Allow,
                pack: None,
                rule: None,
                reason: None,
                mode: "developer",
                policy: None,
                permission_mode: None,
            },
            "0.1.0",
        );
        store::append(env.audit.path(), &rec).unwrap();
    }
    std::fs::create_dir_all(env.root().join("src")).unwrap();
    let (c, text) = status(&env);
    assert_eq!(c, 0, "{text}");
    let claude = text
        .lines()
        .find(|l| l.trim_start().starts_with("claude"))
        .unwrap();
    assert!(claude.contains("no call yet"), "{claude}");
}

/// One JSONL audit line for `project` / `agent` at `ts` (RFC 3339 UTC).
fn audit_line(project: &str, agent: &str, ts: &str) -> String {
    format!(
        "{{\"v\":1,\"ts\":\"{ts}\",\"agent\":\"{agent}\",\"project\":\"{project}\",\"tool\":\"Bash\",\
         \"input\":\"ls\",\"decision\":\"allow\",\"saiife\":\"0.1.0\"}}\n"
    )
}

#[test]
fn status_reads_recent_months_only() {
    let env = initialized(&["claude", "codex"]);
    let project = std::fs::canonicalize(env.root()).unwrap();
    let project = project.to_str().unwrap();
    let now = time::OffsetDateTime::now_utc();
    let this_month = format!("{:04}-{:02}", now.year(), u8::from(now.month()));
    let ts = format!(
        "{:04}-{:02}-{:02}T00:00:00.000Z",
        now.year(),
        u8::from(now.month()),
        now.day()
    );
    // The records of the newest month: one recent call per hooked agent.
    let mut recent = String::new();
    for a in ["claude", "codex"] {
        recent.push_str(&audit_line(project, a, &ts));
    }
    std::fs::write(env.audit.path().join(format!("{this_month}.jsonl")), recent).unwrap();
    // 23 older months, 60 000 records in all, from other projects.
    let filler = audit_line("/elsewhere", "claude", "2020-01-01T00:00:00.000Z");
    let body = filler.repeat(60_000 / 23);
    for m in 0..23u32 {
        let name = format!("{:04}-{:02}.jsonl", 2023 + m / 12, 1 + m % 12);
        std::fs::write(env.audit.path().join(name), &body).unwrap();
    }
    // The next-newest month is a directory: opening it would be a failed
    // check, so exit 0 proves status stopped after the newest file instead
    // of scanning the log (deterministic, unlike a wall-clock bound).
    std::fs::create_dir(env.audit.path().join("2025-06.jsonl")).unwrap();
    let (c, text) = status(&env);
    assert_eq!(c, 0, "{text}");
    assert!(!text.contains("audit log"), "{text}");
    for a in ["claude", "codex"] {
        assert!(
            text.lines()
                .any(|l| l.contains(a) && l.contains("hooked") && !l.contains("no call")),
            "{a}: {text}"
        );
    }
}

#[test]
fn status_stops_after_12_months_for_an_unused_agent() {
    let env = initialized(&["claude"]);
    let dir = env.audit.path();
    // 14 month files; the oldest is a directory, so opening it would be a
    // failed check. Only the newest 12 may be opened.
    let filler = audit_line("/elsewhere", "claude", "2020-01-01T00:00:00.000Z");
    for m in 1..=13u32 {
        let name = format!("{:04}-{:02}.jsonl", 2024 + (m - 1) / 12, 1 + (m - 1) % 12);
        std::fs::write(dir.join(name), &filler).unwrap();
    }
    std::fs::create_dir(dir.join("2020-01.jsonl")).unwrap();
    let (c, text) = status(&env);
    assert_eq!(c, 0, "{text}");
    assert!(
        text.lines()
            .any(|l| l.contains("claude") && l.contains("no call in the last 12 months")),
        "{text}"
    );
    assert!(!text.contains("audit log"), "{text}");
}

/// Plan 2 carry-over: with the config removed, `status` run from a
/// subdirectory finds the project through the integrity record.
#[test]
fn status_in_subdir_after_config_removed() {
    let env = initialized(&["claude"]);
    std::fs::create_dir(env.root().join("src")).unwrap();
    std::fs::remove_file(env.root().join(".saiife/config.toml")).unwrap();
    let out = env.saiife_in(&env.root().join("src"), &["status"]);
    let text = stdout(&out);
    assert_eq!(code(&out), 1, "{text}");
    let canonical = std::fs::canonicalize(env.root()).unwrap();
    assert!(
        text.contains(&format!("saiife status for {}", canonical.display()))
            || text.contains(&format!("saiife status for {}", env.root().display())),
        "{text}"
    );
    assert!(text.contains(".saiife/config.toml was removed"), "{text}");
    assert!(!text.contains("not set up for this project"), "{text}");
}

/// A failed agent's error entry is cleared by a later successful init for
/// that agent.
#[test]
fn failed_agent_entry_clears_on_success() {
    let env = initialized(&["claude", "codex"]);
    // Stand in for an earlier failed codex init.
    let rec_dir = env.data.path().join("projects");
    let rec = std::fs::read_dir(&rec_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&rec).unwrap()).unwrap();
    v["hooks"]["codex"]["sha256"] = "".into();
    v["hooks"]["codex"]["error"] = "disk full".into();
    std::fs::write(&rec, v.to_string()).unwrap();
    let (c, text) = status(&env);
    assert_eq!(c, 1, "{text}");
    assert!(text.contains("could not set up Codex"), "{text}");
    let out = env.saiife(&["init", "--agent", "codex"]);
    assert_eq!(code(&out), 0, "{}", stdout(&out));
    let (c, text) = status(&env);
    assert_eq!(c, 0, "{text}");
    assert!(!text.contains("could not set up"), "{text}");
}

#[test]
fn fresh_install_says_no_call_yet() {
    let env = initialized(&["claude"]);
    let (c, text) = status(&env);
    assert_eq!(c, 0, "{text}");
    let claude = text
        .lines()
        .find(|l| l.trim_start().starts_with("claude"))
        .unwrap();
    assert!(claude.contains("no call yet"), "{claude}");
    assert!(!claude.contains("12 months"), "{claude}");
}

#[test]
fn old_log_says_last_12_months() {
    let env = initialized(&["claude"]);
    let project = std::fs::canonicalize(env.root()).unwrap();
    let project = project.to_str().unwrap();
    // 13 month files; only the oldest (never read) holds this project's call.
    for m in 1..=13u32 {
        let name = format!("{:04}-{:02}.jsonl", 2024 + (m - 1) / 12, 1 + (m - 1) % 12);
        let body = if m == 1 {
            audit_line(project, "claude", "2024-01-15T00:00:00.000Z")
        } else {
            String::new()
        };
        std::fs::write(env.audit.path().join(name), body).unwrap();
    }
    let (c, text) = status(&env);
    assert_eq!(c, 0, "{text}");
    let claude = text
        .lines()
        .find(|l| l.trim_start().starts_with("claude"))
        .unwrap();
    assert!(claude.contains("no call in the last 12 months"), "{claude}");
}

/// A nearer `.saiife/` wins over a guarded parent project: its removed
/// config is named instead of the parent's status.
#[test]
fn nearer_project_with_removed_config_is_named() {
    let env = initialized(&["claude"]);
    let child = env.root().join("child");
    // A config of its own makes `child` a project (init works on it, not
    // on the parent).
    std::fs::create_dir_all(child.join(".saiife")).unwrap();
    std::fs::copy(
        env.root().join(".saiife/config.toml"),
        child.join(".saiife/config.toml"),
    )
    .unwrap();
    let out = env.saiife_in(&child, &["init"]);
    assert_eq!(code(&out), 0, "{}", stdout(&out));
    std::fs::remove_file(child.join(".saiife/config.toml")).unwrap();
    assert!(child.join(".saiife").is_dir());
    let out = env.saiife_in(&child, &["status"]);
    let text = stdout(&out);
    assert_eq!(code(&out), 1, "{text}");
    let first = text.lines().next().unwrap();
    assert!(first.ends_with("/child"), "{text}");
    assert!(text.contains(".saiife/config.toml was removed"), "{text}");
}

/// Review I-1: a stray empty `.saiife/` in a subdirectory (no config, no
/// integrity record) does not hide the parent project's tampered config.
#[test]
fn empty_saiife_dir_in_subdir_does_not_hide_parent_tamper() {
    let env = initialized(&["claude"]);
    env.write(".saiife/config.toml", "version = 1\npacks = []\n");
    std::fs::create_dir_all(env.root().join("src/.saiife")).unwrap();
    let out = env.saiife_in(&env.root().join("src"), &["status"]);
    let text = stdout(&out);
    assert_eq!(code(&out), 1, "{text}");
    assert!(
        text.contains(".saiife/config.toml was changed since `saiife init`"),
        "{text}"
    );
    assert!(!text.contains("not set up for this project"), "{text}");
}

#[test]
fn unreadable_audit_dir_says_last_call_unknown() {
    let env = initialized(&["claude"]);
    // A file where the audit directory should be: cannot be listed.
    let audit = env.audit.path().join("audit");
    std::fs::write(&audit, "x").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .arg("status")
        .current_dir(env.root())
        .env("PATH", env.bin.path())
        .env("HOME", env.home.path())
        .env("SAIIFE_DATA_DIR", env.data.path())
        .env("SAIIFE_AUDIT_DIR", &audit)
        .env("SAIIFE_TEST_CLAUDE_MANAGED_DIRS", env.managed.path())
        .output()
        .unwrap();
    let text = stdout(&out);
    assert_eq!(code(&out), 1, "{text}");
    let claude = text
        .lines()
        .find(|l| l.trim_start().starts_with("claude"))
        .unwrap();
    assert!(
        claude.contains("unknown (audit log could not be read)"),
        "{claude}"
    );
    assert!(!claude.contains("no call"), "{claude}");
}

/// Re-review I-2 (nested): outer config tampered, inner `.saiife/` removed.
/// Status from inner names inner and says where to run init; init from
/// inner restores inner (it has a record) and never re-baselines outer's
/// tampered config, so status from outer still fails.
#[test]
fn init_from_inner_with_removed_saiife_restores_inner_not_outer() {
    let env = initialized(&["claude"]);
    let inner = env.root().join("inner");
    std::fs::create_dir_all(inner.join(".saiife")).unwrap();
    std::fs::copy(
        env.root().join(".saiife/config.toml"),
        inner.join(".saiife/config.toml"),
    )
    .unwrap();
    assert_eq!(code(&env.saiife_in(&inner, &["init"])), 0);
    env.write(".saiife/config.toml", "version = 1\npacks = []\n");
    std::fs::remove_dir_all(inner.join(".saiife")).unwrap();

    let out = env.saiife_in(&inner, &["status"]);
    let text = stdout(&out);
    assert_eq!(code(&out), 1, "{text}");
    assert!(text.contains(".saiife/config.toml was removed"), "{text}");
    assert!(
        text.contains(&format!(
            "run `saiife init` in {}",
            std::fs::canonicalize(&inner).unwrap().display()
        )),
        "{text}"
    );

    let out = env.saiife_in(&inner, &["init"]);
    let text = stdout(&out);
    assert_eq!(code(&out), 0, "{text}");
    assert!(!text.contains("Using the saiife project at"), "{text}");
    assert!(inner.join(".saiife/config.toml").is_file());
    assert_eq!(code(&env.saiife_in(&inner, &["status"])), 0);

    let (c, text) = status(&env);
    assert_eq!(c, 1, "{text}");
    assert!(
        text.contains(".saiife/config.toml was changed since `saiife init`"),
        "{text}"
    );
}

/// Re-review I-2 (single): p's config removed; status from p/sub names p
/// in its fix, and init from p/sub restores p instead of starting a new
/// project at p/sub.
#[test]
fn init_from_subdir_after_config_removed_restores_the_project() {
    let env = initialized(&["claude"]);
    let sub = env.root().join("sub");
    std::fs::create_dir(&sub).unwrap();
    std::fs::remove_file(env.root().join(".saiife/config.toml")).unwrap();

    let text = stdout(&env.saiife_in(&sub, &["status"]));
    assert!(
        text.contains(&format!(
            "run `saiife init` in {} to restore it",
            std::fs::canonicalize(env.root()).unwrap().display()
        )),
        "{text}"
    );

    let out = env.saiife_in(&sub, &["init"]);
    let text = stdout(&out);
    assert_eq!(code(&out), 0, "{text}");
    assert!(text.contains("Using the saiife project at"), "{text}");
    assert!(!sub.join(".saiife").exists());
    assert!(env.root().join(".saiife/config.toml").is_file());
    let (c, text) = status(&env);
    assert_eq!(c, 0, "{text}");
}

/// The packs line says where the config came from when that is not the
/// project shown in the header.
#[test]
fn packs_line_names_a_config_from_another_directory() {
    let env = Env::new(&["claude"]);
    let proj = env.root().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let out = env.saiife_in(&proj, &["init"]);
    assert_eq!(code(&out), 0, "{}", stdout(&out));
    std::fs::remove_file(proj.join(".saiife/config.toml")).unwrap();
    env.write(".saiife/config.toml", "packs = []\n");
    let out = env.saiife_in(&proj, &["status"]);
    let text = stdout(&out);
    let root = std::fs::canonicalize(env.root()).unwrap();
    let want = format!("packs (from {}/.saiife/config.toml):", root.display());
    assert!(text.contains(&want), "{text}");
}

/// A `.saiife/config.toml` below the project root that `saiife init` did
/// not set up: hooks run under it use it instead of the project's config.
fn nested_warning(rel: &str) -> String {
    format!(
        "WARNING: {rel}/.saiife/config.toml is a separate saiife config that was not set up with saiife init; hooks run in {rel} use it instead of this project's config.\n  Fix: delete it, or run saiife init in {rel}"
    )
}

#[test]
fn nested_config_without_record_fails_status() {
    let env = initialized(&["claude"]);
    env.write("sub/deep/.saiife/config.toml", "packs = []\n");
    let (c, text) = status(&env);
    assert_eq!(c, 1, "{text}");
    assert!(text.contains(&nested_warning("sub/deep")), "{text}");
    assert!(text.contains("1 check(s) failed."), "{text}");
}

#[test]
fn nested_config_with_record_is_fine() {
    let env = initialized(&["claude"]);
    env.write("sub/.saiife/config.toml", "packs = []\n");
    let out = env.saiife_in(&env.root().join("sub"), &["init"]);
    assert_eq!(code(&out), 0, "{}", stdout(&out));
    let (c, text) = status(&env);
    assert_eq!(c, 0, "{text}");
    assert!(!text.contains("separate saiife config"), "{text}");
}

#[test]
fn scan_skips_node_modules_and_git() {
    let env = initialized(&["claude"]);
    for d in [
        "node_modules/pkg",
        ".git/x",
        "target/debug",
        "a/node_modules",
    ] {
        env.write(&format!("{d}/.saiife/config.toml"), "packs = []\n");
    }
    let (c, text) = status(&env);
    assert_eq!(c, 0, "{text}");
    assert!(!text.contains("separate saiife config"), "{text}");
}

#[test]
fn scan_stops_at_limit() {
    let env = initialized(&["claude"]);
    for i in 0..10 {
        env.write(&format!("a{i:02}.txt"), "x");
    }
    env.write("zz/.saiife/config.toml", "packs = []\n");
    // SAIIFE_SCAN_LIMIT is read only in debug builds (tests run those).
    let out = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .arg("status")
        .current_dir(env.root())
        .env("PATH", env.bin.path())
        .env("HOME", env.home.path())
        .env("SAIIFE_DATA_DIR", env.data.path())
        .env("SAIIFE_AUDIT_DIR", env.audit.path())
        .env("SAIIFE_TEST_CLAUDE_MANAGED_DIRS", env.managed.path())
        .env("SAIIFE_SCAN_LIMIT", "5")
        .output()
        .unwrap();
    let text = stdout(&out);
    assert_eq!(code(&out), 0, "{text}");
    assert!(
        text.contains("Note: nested-config scan stopped after 5 entries"),
        "{text}"
    );
    assert!(!text.contains("separate saiife config"), "{text}");
    // The default limit is not reached in a small project.
    let (c, text) = status(&env);
    assert_eq!(c, 1, "{text}");
    assert!(!text.contains("nested-config scan stopped"), "{text}");
    assert!(text.contains(&nested_warning("zz")), "{text}");
}

#[cfg(unix)]
#[test]
fn symlinked_dir_not_followed() {
    let env = initialized(&["claude"]);
    let outside = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(outside.path().join("x/.saiife")).unwrap();
    std::fs::write(outside.path().join("x/.saiife/config.toml"), "packs = []\n").unwrap();
    std::fs::create_dir_all(outside.path().join(".saiife")).unwrap();
    std::fs::write(outside.path().join(".saiife/config.toml"), "packs = []\n").unwrap();
    std::os::unix::fs::symlink(outside.path(), env.root().join("link")).unwrap();
    let (c, text) = status(&env);
    assert_eq!(c, 0, "{text}");
    assert!(!text.contains("separate saiife config"), "{text}");
}

/// A nested project `saiife init` set up is held to its recorded config
/// hash, like the main project's config.
fn nested_initialized() -> Env {
    let env = initialized(&["claude"]);
    env.write("sub/.saiife/config.toml", "packs = []\n");
    let out = env.saiife_in(&env.root().join("sub"), &["init"]);
    assert_eq!(code(&out), 0, "{}", stdout(&out));
    env
}

#[test]
fn nested_recorded_config_untouched_is_fine() {
    let env = nested_initialized();
    let (c, text) = status(&env);
    assert_eq!(c, 0, "{text}");
    assert!(!text.contains("sub/.saiife/config.toml"), "{text}");
}

#[test]
fn nested_recorded_config_tampered_fails_status() {
    let env = nested_initialized();
    env.write("sub/.saiife/config.toml", "packs = []\n# swapped\n");
    let (c, text) = status(&env);
    assert_eq!(c, 1, "{text}");
    assert!(
        text.contains(
            "WARNING: sub/.saiife/config.toml was changed since `saiife init`.\n  Fix: if you made this change, run `saiife init` in sub to record it; otherwise restore the file and run `saiife init` in sub"
        ),
        "{text}"
    );
    assert!(text.contains("1 check(s) failed."), "{text}");
}

#[test]
fn nested_recorded_config_removed_fails_status() {
    let env = nested_initialized();
    std::fs::remove_file(env.root().join("sub/.saiife/config.toml")).unwrap();
    let (c, text) = status(&env);
    assert_eq!(c, 1, "{text}");
    assert!(
        text.contains(
            "WARNING: sub/.saiife/config.toml was removed.\n  Fix: run `saiife init` in sub to restore it"
        ),
        "{text}"
    );
}

#[test]
fn nested_unreadable_record_fails_status() {
    let env = nested_initialized();
    let sub = std::fs::canonicalize(env.root().join("sub")).unwrap();
    let key = saiife_sha256(sub.as_os_str().as_encoded_bytes());
    let rec = env.data.path().join("projects").join(format!("{key}.json"));
    assert!(rec.is_file(), "{}", rec.display());
    std::fs::write(&rec, "{not json").unwrap();
    let (c, text) = status(&env);
    assert_eq!(c, 1, "{text}");
    assert!(
        text.contains("WARNING: the integrity record for sub cannot be read"),
        "{text}"
    );
    assert!(
        text.contains("Fix: run `saiife init` in sub to restore it"),
        "{text}"
    );
}

fn saiife_sha256(bytes: &[u8]) -> String {
    saiife_agents::fingerprint::sha256_hex(bytes)
}

/// Directory names are attacker-chosen: escapes and newlines in them must
/// not reach the terminal raw.
#[cfg(unix)]
#[test]
fn nested_config_path_is_sanitized() {
    let env = initialized(&["claude"]);
    env.write("evil\x1b[2J\nx/.saiife/config.toml", "packs = []\n");
    let (c, text) = status(&env);
    assert_eq!(c, 1, "{text}");
    assert!(!text.contains('\x1b'), "{text:?}");
    assert!(!text.contains("[2J\n"), "{text:?}");
    assert!(
        text.contains("WARNING: evil\\x1b[2J⏎x/.saiife/config.toml is a separate saiife config"),
        "{text}"
    );
    assert!(
        text.contains("Fix: delete it, or run saiife init in evil\\x1b[2J⏎x"),
        "{text}"
    );
}

/// The project path in the header (and the fix that names it) is printed
/// sanitized too.
#[cfg(unix)]
#[test]
fn header_path_is_sanitized() {
    let env = Env::new(&["claude"]);
    let dir = env.root().join("evil\x1b[2J\nx");
    std::fs::create_dir_all(&dir).unwrap();
    let out = env.saiife_in(&dir, &["status"]);
    let text = stdout(&out);
    assert!(!text.contains('\x1b'), "{text:?}");
    assert!(text.contains("evil\\x1b[2J⏎x"), "{text}");
}

/// Carry-over 2: status reads the config through the bounded reader.
#[test]
fn status_with_oversized_config_reports_it() {
    let env = initialized(&["claude"]);
    let big = format!("# {}\npacks = []\n", "x".repeat(65 * 1024));
    env.write(".saiife/config.toml", &big);
    let (c, text) = status(&env);
    assert_eq!(c, 1, "{text}");
    assert!(text.contains("cannot be read"), "{text}");
    assert!(text.contains("larger than 64 KiB"), "{text}");
}

#[cfg(unix)]
#[test]
fn status_with_fifo_config_does_not_hang() {
    let env = initialized(&["claude"]);
    let cfg = env.root().join(".saiife/config.toml");
    std::fs::remove_file(&cfg).unwrap();
    assert!(Command::new("mkfifo").arg(&cfg).status().unwrap().success());
    let out = env
        .saiife_within(&["status"], std::time::Duration::from_secs(5))
        .expect("saiife status hung on a FIFO config");
    assert_eq!(code(&out), 1, "{}", stdout(&out));
    assert!(stdout(&out).contains("cannot be read"), "{}", stdout(&out));
}

/// Locked mode (plan 9b): `status --root <tree>` against a fake install
/// whose config points at a test daemon. Never the real /etc, /run or /var.
#[cfg(target_os = "linux")]
mod locked {
    use super::common::daemon::{Opts, TestDaemon};
    use super::common::{code, stdout, Env};
    use saiife_policy::installed::{read_installed, write_installed, ManagedAgent};
    use std::path::Path;

    /// A fake install with Claude Code (whole file) and Codex (an entry in
    /// requirements.toml) managed, and `config` as its config.toml.
    fn locked_root(config: &str) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        saiife_system::testing::fake_install(root.path());
        let codex = root.path().join("etc/codex/requirements.toml");
        std::fs::create_dir_all(codex.parent().unwrap()).unwrap();
        saiife_agents::codex::install_managed(&codex).unwrap();
        let fp = saiife_agents::codex::managed_entry(&codex)
            .unwrap()
            .unwrap();
        let installed = root.path().join("etc/saiife/installed.toml");
        let mut i = read_installed(&installed).unwrap().unwrap();
        i.agents.push(ManagedAgent {
            agent: "codex".into(),
            path: "/etc/codex/requirements.toml".into(),
            sha256: fp,
            whole_file: false,
            created_file: true,
        });
        write_installed(&installed, &i).unwrap();
        std::fs::write(root.path().join("etc/saiife/config.toml"), config).unwrap();
        root
    }

    fn status_at(root: &Path) -> (i32, String) {
        let env = Env::new(&["claude"]);
        let out = env.saiife(&["status", "--root", root.to_str().unwrap()]);
        (code(&out), stdout(&out))
    }

    #[test]
    fn status_shows_locked_block_and_labels() {
        let d = TestDaemon::start(Opts::default());
        let root = locked_root(&d.config_text(&Opts::default()));
        let (c, text) = status_at(root.path());
        assert!(text.contains("Locked mode\n"), "{text}");
        assert!(
            text.contains("  mode: locked (installed 2026-10-22T00:00:00Z, saiife "),
            "{text}"
        );
        assert!(text.contains("  daemon: running, chain "), "{text}");
        assert!(text.contains(", head seq "), "{text}");
        assert!(text.contains(", last checkpoint seq "), "{text}");
        assert!(text.contains("  policy: sha256:"), "{text}");
        assert!(
            text.contains("  agent claude: managed hook, lockable\n"),
            "{text}"
        );
        // Unverified: the project hook still judges Codex calls.
        assert!(
            text.contains(
                "  agent codex: managed hook, unverified; its project hook still judges its calls\n"
            ),
            "{text}"
        );
        // The block comes before the v1 checks.
        let block = text.find("Locked mode").unwrap();
        let v1 = text.find("project hooks").unwrap();
        assert!(block < v1, "{text}");
        // Nothing failed: no project hooks are needed under managed ones.
        assert_eq!(c, 0, "{text}");
    }

    #[test]
    fn status_reports_daemon_down() {
        let d = TestDaemon::prepare(&Opts::default());
        let root = locked_root(&d.config_text(&Opts::default()));
        let (c, text) = status_at(root.path());
        assert_eq!(c, 1, "{text}");
        assert!(text.contains("  daemon: not answering ("), "{text}");
        assert!(
            text.contains("): every managed hook call is denied"),
            "{text}"
        );
    }

    #[test]
    fn status_reports_invalid_system_config() {
        let root = locked_root("version = = 2\n");
        let (c, text) = status_at(root.path());
        assert_eq!(c, 1, "{text}");
        assert!(text.contains("  policy: invalid ("), "{text}");
        assert!(
            text.contains("): every managed hook call is denied and nothing is recorded"),
            "{text}"
        );
    }

    #[test]
    fn status_prints_mcp_warning() {
        let opts = Opts {
            extra: "[guard.mcp]\nallow_servers = [\"github\"]\n".into(),
            ..Opts::default()
        };
        let d = TestDaemon::start(Opts::default());
        let root = locked_root(&d.config_text(&opts));
        let (_, text) = status_at(root.path());
        assert!(
            text.contains(
                "MCP server github bypasses saiife: its requests are not brokered or limited\n"
            ),
            "{text}"
        );
    }

    #[test]
    fn status_says_an_unwritten_managed_hook_does_not_guard() {
        let d = TestDaemon::start(Opts::default());
        let root = locked_root(&d.config_text(&Opts::default()));
        let installed = root.path().join("etc/saiife/installed.toml");
        let mut i = read_installed(&installed).unwrap().unwrap();
        for a in &mut i.agents {
            a.sha256 = String::new();
        }
        write_installed(&installed, &i).unwrap();
        let (_, text) = status_at(root.path());
        assert!(
            text.contains(
                "  agent claude: managed hook not written (install did not finish); its project hook still judges its calls\n"
            ),
            "{text}"
        );
        assert!(!text.contains("the managed hooks guard"), "{text}");
    }

    /// Final review I5e: without `saiife init` here, the managed hooks
    /// still read this project's config and nested ones: status checks
    /// them before it returns.
    #[test]
    fn status_without_init_still_checks_project_and_nested_configs() {
        let d = TestDaemon::start(Opts::default());
        let root = locked_root(&d.config_text(&Opts::default()));
        let env = Env::new(&["claude"]);
        env.write(".saiife/config.toml", "packs = [\"no.such-pack\"]\n");
        env.write("sub/.saiife/config.toml", "packs = []\n");
        let out = env.saiife(&["status", "--root", root.path().to_str().unwrap()]);
        let text = stdout(&out);
        assert!(text.contains("project hooks: none"), "{text}");
        assert!(text.contains("no.such-pack"), "{text}");
        assert!(
            text.contains("sub/.saiife/config.toml is a separate saiife config"),
            "{text}"
        );
        assert_eq!(code(&out), 1, "{text}");
    }

    #[test]
    fn status_reports_changed_managed_file() {
        let d = TestDaemon::start(Opts::default());
        let root = locked_root(&d.config_text(&Opts::default()));
        std::fs::write(
            root.path()
                .join("etc/claude-code/managed-settings.d/50-saiife.json"),
            "{}\n",
        )
        .unwrap();
        let (c, text) = status_at(root.path());
        assert_eq!(c, 1, "{text}");
        assert!(
            text.contains(
                "/etc/claude-code/managed-settings.d/50-saiife.json: changed since install"
            ),
            "{text}"
        );
    }
}
