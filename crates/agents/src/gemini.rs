//! Gemini CLI: `BeforeTool` hook in `.gemini/settings.json`
//! (contract: docs/superpowers/research/2026-10-13-gemini-hooks.md).

use std::path::Path;

use serde_json::{json, Value};

use crate::json_hooks::JsonHooks;
use crate::{Agent, AgentError, Change};

pub const SETTINGS_REL: &str = ".gemini/settings.json";

/// Regex on the tool name: shell, read, list/search and write tools.
pub const MATCHER: &str =
    "run_shell_command|read_file|read_many_files|list_directory|glob|grep_search|write_file|replace";

/// Milliseconds (Gemini CLI's unit).
pub const TIMEOUT_MS: u64 = 10_000;

pub const NEXT_STEP: &str = "Gemini CLI only loads project hooks in a trusted folder: start `gemini` in this folder and trust it when asked.";

fn group() -> Value {
    json!({
        "matcher": MATCHER,
        "hooks": [{
            "type": "command",
            "command": Agent::Gemini.hook_command(),
            "name": "saiife",
            "timeout": TIMEOUT_MS,
        }]
    })
}

const HOOKS: JsonHooks = JsonHooks {
    rel: SETTINGS_REL,
    event: "BeforeTool",
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const USER_SETTINGS: &str = r#"{
  "theme": "GitHub",
  "general": {
    "vimMode": true
  },
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "write_file",
        "hooks": [
          {
            "type": "command",
            "command": "./fmt-check.sh",
            "name": "fmt"
          }
        ]
      }
    ]
  }
}
"#;

    fn project_with(settings: &str) -> tempfile::TempDir {
        let p = tempfile::tempdir().unwrap();
        fs::create_dir(p.path().join(".gemini")).unwrap();
        fs::write(p.path().join(SETTINGS_REL), settings).unwrap();
        p
    }

    fn read(p: &Path) -> String {
        fs::read_to_string(p.join(SETTINGS_REL)).unwrap()
    }

    /// Spec §5.2: shell, read (incl. list/search) and write tools.
    #[test]
    fn matcher_covers_read_list_and_write_tools() {
        let tools: Vec<&str> = MATCHER.split('|').collect();
        for t in [
            "run_shell_command",
            "read_file",
            "read_many_files",
            "list_directory",
            "glob",
            "grep_search",
            "write_file",
            "replace",
        ] {
            assert!(tools.contains(&t), "{t}");
        }
    }

    #[test]
    fn install_writes_named_handler_with_ms_timeout() {
        let p = project_with(USER_SETTINGS);
        assert_eq!(install(p.path()).unwrap(), Change::Updated);
        let v: Value = serde_json::from_str(&read(p.path())).unwrap();
        let groups = v["hooks"]["BeforeTool"].as_array().unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0]["hooks"][0]["name"], "fmt");
        let h = &groups[1]["hooks"][0];
        assert_eq!(groups[1]["matcher"], MATCHER);
        assert_eq!(h["name"], "saiife");
        assert_eq!(h["command"], "saiife check --hook-exit --agent gemini");
        assert_eq!(h["timeout"], 10000);
        assert_eq!(v["general"]["vimMode"], true);
    }

    #[test]
    fn install_twice_then_remove_restores_bytes() {
        let p = project_with(USER_SETTINGS);
        install(p.path()).unwrap();
        let once = read(p.path());
        assert_eq!(install(p.path()).unwrap(), Change::Unchanged);
        assert_eq!(read(p.path()), once);
        assert_eq!(remove(p.path(), false).unwrap(), Change::Updated);
        assert_eq!(read(p.path()), USER_SETTINGS);
    }

    /// A handler named "saiife" is ours even if its command was edited.
    #[test]
    fn handler_named_saiife_is_recognized_and_removed() {
        let edited = r#"{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "run_shell_command",
        "hooks": [
          {
            "type": "command",
            "command": "true",
            "name": "saiife"
          }
        ]
      }
    ]
  }
}
"#;
        let p = project_with(edited);
        assert_eq!(entries(p.path()).unwrap().len(), 1);
        assert_ne!(entries(p.path()).unwrap(), vec![expected_entry()]);
        assert_eq!(remove(p.path(), true).unwrap(), Change::Deleted);
    }
}
