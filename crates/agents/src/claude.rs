//! Claude Code: `PreToolUse` hook in `.claude/settings.json`
//! (contract: docs/superpowers/research/2026-10-13-claude-code-hooks.md).

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::json_hooks::JsonHooks;
use crate::{Agent, AgentError, Change, HookBlocker};

pub const SETTINGS_REL: &str = ".claude/settings.json";

/// Shell, read and write tools (spec §5.2). Only `[A-Za-z0-9_|]`, so Claude
/// Code reads it as an exact list of tool names.
pub const MATCHER: &str = "Bash|Read|Grep|Glob|LS|Write|Edit|MultiEdit|NotebookEdit";

/// The matcher plan 2's saiife wrote. A project hooked by it is upgraded by
/// running `saiife init` again (`status` reports the entry as out of date).
pub const MATCHER_V1: &str = "Bash|Read|Grep|Write|Edit|MultiEdit|NotebookEdit";

/// Seconds. No `onFailure: "block"`: v1 developer mode fails open (spec §1.2
/// rule 4).
pub const TIMEOUT_SECS: u64 = 10;

pub const NEXT_STEP: &str = "Claude Code holds back project hooks until you accept the workspace trust prompt: start `claude` in this folder and accept it. `/hooks` shows the saiife hook.";

/// Managed-settings directories (Linux, macOS). Read-only checks.
pub const MANAGED_DIRS: &[&str] = &[
    "/etc/claude-code",
    "/Library/Application Support/ClaudeCode",
];

fn group() -> Value {
    json!({
        "matcher": MATCHER,
        "hooks": [{
            "type": "command",
            "command": Agent::Claude.hook_command(),
            "timeout": TIMEOUT_SECS,
        }]
    })
}

const HOOKS: JsonHooks = JsonHooks {
    rel: SETTINGS_REL,
    event: "PreToolUse",
    group,
};

pub fn install(project: &Path) -> Result<Change, AgentError> {
    HOOKS.install(project)
}

pub fn remove(project: &Path, delete_if_empty: bool) -> Result<Change, AgentError> {
    HOOKS.remove(project, delete_if_empty)
}

pub fn entries(project: &Path) -> Result<Vec<String>, AgentError> {
    HOOKS.entries(project)
}

pub fn expected_entry() -> String {
    HOOKS.expected()
}

/// Settings that stop the project hook from running: `disableAllHooks: true`
/// in project, local or user settings, and `allowManagedHooksOnly` /
/// `disableAllHooks` in managed settings.
pub fn blockers(project: &Path, home: Option<&Path>) -> Vec<HookBlocker> {
    blockers_in(project, home, &managed_dirs())
}

/// The managed-settings directories. Debug builds (tests) can replace them
/// with `SAIIFE_TEST_CLAUDE_MANAGED_DIRS` (a PATH-style list); a release
/// build ignores it, so it cannot be used to hide a managed lock.
fn managed_dirs() -> Vec<PathBuf> {
    #[cfg(debug_assertions)]
    if let Some(v) = std::env::var_os("SAIIFE_TEST_CLAUDE_MANAGED_DIRS") {
        return std::env::split_paths(&v).collect();
    }
    MANAGED_DIRS.iter().map(PathBuf::from).collect()
}

/// `blockers` with the managed-settings directories given (tests).
pub fn blockers_in(
    project: &Path,
    home: Option<&Path>,
    managed_dirs: &[PathBuf],
) -> Vec<HookBlocker> {
    let mut files = vec![
        project.join(".claude/settings.json"),
        project.join(".claude/settings.local.json"),
    ];
    if let Some(home) = home {
        files.push(home.join(".claude/settings.json"));
    }
    let mut out = Vec::new();
    for f in &files {
        check_flag(&mut out, f, "disableAllHooks", false);
    }
    for dir in managed_dirs {
        let mut managed = vec![dir.join("managed-settings.json")];
        let d = dir.join("managed-settings.d");
        match std::fs::read_dir(&d) {
            Ok(rd) => {
                let mut dropins: Vec<PathBuf> = Vec::new();
                for e in rd {
                    match e {
                        Ok(e) => dropins.push(e.path()),
                        Err(err) => out.push(unreadable(&d, &err, true)),
                    }
                }
                dropins.retain(|p| p.extension().is_some_and(|x| x == "json"));
                dropins.sort();
                managed.extend(dropins);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => out.push(unreadable(&d, &e, true)),
        }
        for f in managed {
            // Read once; report an unreadable file once, not per setting.
            // A managed file that is not a JSON object cannot be read as
            // settings: report it like an unreadable one.
            match read_flags(&f) {
                Ok(v) if !v.is_object() && !(v.is_null() && !f.exists()) => {
                    out.push(unreadable_msg(&f, "not a JSON object".into(), true))
                }
                Ok(v) => {
                    for setting in ["allowManagedHooksOnly", "disableAllHooks"] {
                        if v.get(setting).and_then(Value::as_bool) == Some(true) {
                            out.push(HookBlocker {
                                path: f.clone(),
                                setting,
                                error: None,
                                managed: true,
                            });
                        }
                    }
                }
                Err(e) => out.push(unreadable_msg(&f, e, true)),
            }
        }
    }
    out
}

fn unreadable_msg(path: &Path, error: String, managed: bool) -> HookBlocker {
    HookBlocker {
        path: path.to_path_buf(),
        setting: "",
        error: Some(error),
        managed,
    }
}

fn unreadable(path: &Path, e: &std::io::Error, managed: bool) -> HookBlocker {
    unreadable_msg(path, e.to_string(), managed)
}

/// The JSON of `path`; an absent file is an empty object, an unreadable or
/// unparseable one is an error.
fn read_flags(path: &Path) -> Result<Value, String> {
    match std::fs::read_to_string(path) {
        Ok(t) => serde_json::from_str::<Value>(&t).map_err(|e| format!("not valid JSON: {e}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Value::Null),
        Err(e) => Err(e.to_string()),
    }
}

fn check_flag(out: &mut Vec<HookBlocker>, path: &Path, key: &'static str, managed: bool) {
    match read_flags(path) {
        Ok(v) if v.get(key).and_then(Value::as_bool) == Some(true) => out.push(HookBlocker {
            path: path.to_path_buf(),
            setting: key,
            error: None,
            managed,
        }),
        Ok(_) => {}
        Err(e) => out.push(unreadable_msg(path, e, managed)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// A user settings file with unrelated keys, a user hook in the same
    /// event, and another event — all must survive init and init --off.
    const USER_SETTINGS: &str = r#"{
  "model": "opus",
  "permissions": {
    "allow": [
      "Bash(npm run test:*)"
    ],
    "deny": []
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "./scripts/lint-hook.sh"
          }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "notify-send done"
          }
        ]
      }
    ]
  },
  "env": {
    "FOO": "bar"
  }
}
"#;

    fn project_with(settings: &str) -> tempfile::TempDir {
        let p = tempfile::tempdir().unwrap();
        fs::create_dir(p.path().join(".claude")).unwrap();
        fs::write(p.path().join(SETTINGS_REL), settings).unwrap();
        p
    }

    fn read(p: &Path) -> String {
        fs::read_to_string(p.join(SETTINGS_REL)).unwrap()
    }

    #[test]
    fn install_adds_the_hook_and_keeps_user_settings() {
        let p = project_with(USER_SETTINGS);
        assert_eq!(install(p.path()).unwrap(), Change::Updated);
        let v: Value = serde_json::from_str(&read(p.path())).unwrap();
        let groups = v["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(groups.len(), 2, "user group kept, saiife group added");
        assert_eq!(groups[0]["hooks"][0]["command"], "./scripts/lint-hook.sh");
        assert_eq!(groups[1]["matcher"], MATCHER);
        assert_eq!(
            groups[1]["hooks"][0]["command"],
            "saiife check --hook-exit --agent claude"
        );
        assert_eq!(groups[1]["hooks"][0]["timeout"], 10);
        assert!(groups[1]["hooks"][0].get("onFailure").is_none());
        assert_eq!(v["model"], "opus");
        assert_eq!(v["env"]["FOO"], "bar");
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            ["model", "permissions", "hooks", "env"],
            "key order kept"
        );
        assert_eq!(entries(p.path()).unwrap(), vec![expected_entry()]);
    }

    #[test]
    fn second_install_is_a_no_op() {
        let p = project_with(USER_SETTINGS);
        install(p.path()).unwrap();
        let once = read(p.path());
        assert_eq!(install(p.path()).unwrap(), Change::Unchanged);
        assert_eq!(read(p.path()), once);
    }

    #[test]
    fn remove_restores_the_original_bytes() {
        let p = project_with(USER_SETTINGS);
        install(p.path()).unwrap();
        assert_eq!(remove(p.path(), false).unwrap(), Change::Updated);
        assert_eq!(read(p.path()), USER_SETTINGS);
        assert_eq!(remove(p.path(), false).unwrap(), Change::Unchanged);
    }

    #[test]
    fn four_space_indent_round_trips() {
        let four = "{\n    \"model\": \"opus\"\n}\n";
        let p = project_with(four);
        install(p.path()).unwrap();
        assert!(read(p.path()).contains("\n        \"PreToolUse\""));
        remove(p.path(), false).unwrap();
        assert_eq!(read(p.path()), four);
    }

    /// F2: a CRLF file stays CRLF, and init then --off restores its bytes.
    #[test]
    fn crlf_settings_round_trip() {
        let crlf = USER_SETTINGS.replace('\n', "\r\n");
        let p = project_with(&crlf);
        install(p.path()).unwrap();
        let installed = read(p.path());
        assert!(installed.contains("saiife check"));
        assert_eq!(
            installed.matches('\n').count(),
            installed.matches("\r\n").count(),
            "every line ends in CRLF: {installed:?}"
        );
        assert_eq!(entries(p.path()).unwrap(), vec![expected_entry()]);
        assert_eq!(remove(p.path(), false).unwrap(), Change::Updated);
        assert_eq!(read(p.path()), crlf);
    }

    #[test]
    fn creates_the_file_and_deletes_it_again() {
        let p = tempfile::tempdir().unwrap();
        assert_eq!(
            install(p.path()).unwrap(),
            Change::Created {
                created_dirs: vec![".claude".into()]
            }
        );
        assert_eq!(remove(p.path(), true).unwrap(), Change::Deleted);
        assert!(!p.path().join(SETTINGS_REL).exists());
    }

    #[test]
    fn matcher_covers_read_list_and_write_tools() {
        let tools: Vec<&str> = MATCHER.split('|').collect();
        for t in [
            "Bash",
            "Read",
            "Grep",
            "Glob",
            "LS",
            "Write",
            "Edit",
            "MultiEdit",
            "NotebookEdit",
        ] {
            assert!(tools.contains(&t), "{t}");
        }
    }

    /// The fingerprint `status` compares against the recorded one. Pinned so
    /// a change of the entry is a deliberate act (and an upgrade for users).
    #[test]
    fn expected_entry_fingerprint_is_pinned() {
        assert_eq!(
            expected_entry(),
            "96fb881e404f7fed07a75eff98c42bf1c31553d8678c5e36c7216caadc5e2dca"
        );
    }

    /// An install from plan 2 (old matcher) is upgraded in place.
    #[test]
    fn an_older_entry_is_upgraded_by_install() {
        let p = project_with(USER_SETTINGS);
        install(p.path()).unwrap();
        let old = read(p.path()).replace(MATCHER, MATCHER_V1);
        fs::write(p.path().join(SETTINGS_REL), &old).unwrap();
        assert_eq!(
            entries(p.path()).unwrap(),
            vec!["78ff3176c0d50b70275b537d4f8e7c52ebba6e0ce22f68c03d01d52fd86c5d76".to_string()]
        );
        assert_ne!(entries(p.path()).unwrap(), vec![expected_entry()]);
        assert_eq!(install(p.path()).unwrap(), Change::Updated);
        assert_eq!(entries(p.path()).unwrap(), vec![expected_entry()]);
        assert!(read(p.path()).contains(MATCHER));
    }

    #[test]
    fn a_changed_entry_is_replaced_not_duplicated() {
        let p = project_with(USER_SETTINGS);
        install(p.path()).unwrap();
        let tampered = read(p.path()).replace(MATCHER, "NeverMatches");
        fs::write(p.path().join(SETTINGS_REL), tampered).unwrap();
        assert_eq!(entries(p.path()).unwrap().len(), 1);
        assert_ne!(entries(p.path()).unwrap(), vec![expected_entry()]);
        assert_eq!(install(p.path()).unwrap(), Change::Updated);
        assert_eq!(entries(p.path()).unwrap(), vec![expected_entry()]);
    }

    /// Review Focus 2: a settings file that is not plain JSON is never
    /// rewritten.
    #[test]
    fn unparseable_settings_are_left_byte_identical() {
        for bad in [
            "{\n  // my comment\n  \"model\": \"opus\"\n}\n",
            "{\"model\": \"opus\",}\n",
            "[1, 2]\n",
            "{\"hooks\": {\"PreToolUse\": {\"matcher\": \"Bash\"}}}\n",
            "{\"hooks\": []}\n",
            "{\"hooks\": \"x\"}\n",
        ] {
            let p = project_with(bad);
            assert!(install(p.path()).is_err(), "{bad:?}");
            assert!(
                remove(p.path(), true).is_err() || read(p.path()) == bad,
                "{bad:?}"
            );
            assert_eq!(read(p.path()), bad, "{bad:?}");
        }
    }

    #[test]
    fn blockers_find_disable_all_hooks_and_managed_settings() {
        let p = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let managed = tempfile::tempdir().unwrap();
        assert!(
            blockers_in(p.path(), Some(home.path()), &[managed.path().to_path_buf()]).is_empty()
        );

        fs::create_dir(p.path().join(".claude")).unwrap();
        fs::write(
            p.path().join(".claude/settings.local.json"),
            r#"{"disableAllHooks": true}"#,
        )
        .unwrap();
        fs::create_dir(home.path().join(".claude")).unwrap();
        fs::write(
            home.path().join(".claude/settings.json"),
            r#"{"disableAllHooks": false}"#,
        )
        .unwrap();
        fs::create_dir(managed.path().join("managed-settings.d")).unwrap();
        fs::write(
            managed.path().join("managed-settings.d/10-lock.json"),
            r#"{"allowManagedHooksOnly": true}"#,
        )
        .unwrap();
        let found = blockers_in(p.path(), Some(home.path()), &[managed.path().to_path_buf()]);
        let settings: Vec<&str> = found.iter().map(|b| b.setting).collect();
        assert_eq!(settings, ["disableAllHooks", "allowManagedHooksOnly"]);
        assert!(found[0].path.ends_with(".claude/settings.local.json"));
        assert!(found[1].managed && found[1].error.is_none());
    }

    /// M5: a managed drop-in whose JSON is not an object is reported like an
    /// unreadable file, not silently skipped.
    #[test]
    fn non_object_managed_drop_in_is_reported() {
        let p = tempfile::tempdir().unwrap();
        let managed = tempfile::tempdir().unwrap();
        fs::create_dir(managed.path().join("managed-settings.d")).unwrap();
        for (name, body) in [("a.json", "[1]"), ("b.json", "null"), ("c.json", "\"x\"")] {
            fs::write(managed.path().join("managed-settings.d").join(name), body).unwrap();
        }
        let found = blockers_in(p.path(), None, &[managed.path().to_path_buf()]);
        assert_eq!(found.len(), 3, "{found:?}");
        assert!(found
            .iter()
            .all(|b| b.managed && b.setting.is_empty() && b.error.is_some()));
        assert!(found[0]
            .error
            .as_deref()
            .unwrap()
            .contains("not a JSON object"));
    }

    #[test]
    fn unparseable_or_unreadable_inputs_are_reported_not_ignored() {
        let p = project_with("{ not json");
        let home = tempfile::tempdir().unwrap();
        let managed = tempfile::tempdir().unwrap();
        // A directory where managed-settings.json should be: unreadable even
        // as root.
        fs::create_dir(managed.path().join("managed-settings.json")).unwrap();
        fs::create_dir(managed.path().join("managed-settings.d")).unwrap();
        fs::write(managed.path().join("managed-settings.d/a.json"), "][").unwrap();
        let found = blockers_in(p.path(), Some(home.path()), &[managed.path().to_path_buf()]);
        let errs: Vec<&HookBlocker> = found.iter().filter(|b| b.error.is_some()).collect();
        assert_eq!(errs.len(), 3, "{found:?}");
        assert!(errs[0].path.ends_with(".claude/settings.json"));
        assert!(errs[1].managed && errs[2].managed);
        assert!(found.iter().all(|b| b.setting.is_empty()));
    }
}
