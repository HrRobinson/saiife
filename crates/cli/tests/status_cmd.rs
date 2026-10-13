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
                .any(|l| l.contains(a) && l.contains("hooked") && l.contains("never")),
            "{a}: {text}"
        );
    }
    assert!(text.contains("packs   core.filesystem, core.git"), "{text}");
    assert!(text.contains("cannot stop a determined agent"), "{text}");
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
        text.contains("Fix: run `saiife init` to restore it"),
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
    assert!(codex.contains("never"), "{codex}");
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
