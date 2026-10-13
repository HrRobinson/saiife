//! Claude Code: `PreToolUse` hook in `.claude/settings.json`
//! (contract: docs/superpowers/research/2026-10-13-claude-code-hooks.md).

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::json_hooks::JsonHooks;
use crate::{Agent, AgentError, Change, HookBlocker};

pub const SETTINGS_REL: &str = ".claude/settings.json";

/// Shell, read and write tools (spec §5.2). Only `[A-Za-z0-9_|]`, so Claude
/// Code reads it as an exact list of tool names.
pub const MATCHER: &str = "Bash|Read|Grep|Write|Edit|MultiEdit|NotebookEdit";

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
    let managed: Vec<PathBuf> = MANAGED_DIRS.iter().map(PathBuf::from).collect();
    blockers_in(project, home, &managed)
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
        if flag_set(f, "disableAllHooks") {
            out.push(HookBlocker {
                path: f.clone(),
                setting: "disableAllHooks",
            });
        }
    }
    for dir in managed_dirs {
        let mut managed = vec![dir.join("managed-settings.json")];
        if let Ok(rd) = std::fs::read_dir(dir.join("managed-settings.d")) {
            let mut dropins: Vec<PathBuf> = rd
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "json"))
                .collect();
            dropins.sort();
            managed.extend(dropins);
        }
        for f in managed {
            for setting in ["allowManagedHooksOnly", "disableAllHooks"] {
                if flag_set(&f, setting) {
                    out.push(HookBlocker {
                        path: f.clone(),
                        setting,
                    });
                }
            }
        }
    }
    out
}

/// True when `path` is a JSON object with `key: true`. Missing or unreadable
/// files are not blockers.
fn flag_set(path: &Path, key: &str) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|v| v.get(key).and_then(Value::as_bool))
        == Some(true)
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
    }
}
