//! saiife-agents: everything saiife writes into a project, and how it checks
//! that it is still there.
//!
//! - one module per agent (`claude`, `codex`, `gemini`): install the guard
//!   hook into the project's config file, remove only saiife's own entries,
//!   and fingerprint the entry for tamper detection (spec §5.2, §7.5);
//! - `config`: the project config `.saiife/config.toml` (spec §5.1);
//! - `integrity`: the per-project integrity record outside the project.
//!
//! This crate never depends on the guard or the audit crate (spec §4).

#![forbid(unsafe_code)]

pub mod detect;
pub mod fingerprint;
pub mod fsutil;

use std::path::PathBuf;

/// The agents saiife v1 supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Agent {
    Claude,
    Codex,
    Gemini,
}

impl Agent {
    pub const ALL: [Agent; 3] = [Agent::Claude, Agent::Codex, Agent::Gemini];

    /// Short name used on the command line, in hook commands and in the
    /// audit log.
    pub fn name(self) -> &'static str {
        match self {
            Agent::Claude => "claude",
            Agent::Codex => "codex",
            Agent::Gemini => "gemini",
        }
    }

    pub fn from_name(s: &str) -> Option<Agent> {
        Agent::ALL.into_iter().find(|a| a.name() == s)
    }

    /// The executable looked up on `PATH` by `detect`.
    pub fn binary(self) -> &'static str {
        self.name()
    }

    /// Display name for messages.
    pub fn label(self) -> &'static str {
        match self {
            Agent::Claude => "Claude Code",
            Agent::Codex => "Codex",
            Agent::Gemini => "Gemini CLI",
        }
    }

    /// The exact hook command written for this agent. Resolved via `PATH`
    /// so an upgrade never leaves a stale absolute path (spec §5.2).
    pub fn hook_command(self) -> String {
        format!("saiife check --hook-exit --agent {}", self.name())
    }
}

/// What an install or remove did to the config file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// The file already had exactly the wanted content; nothing was written.
    Unchanged,
    /// The file existed and was rewritten.
    Updated,
    /// The file did not exist and was created (`created_dirs`: directories
    /// created for it, relative to the project, outermost first).
    Created { created_dirs: Vec<String> },
    /// saiife's entries were removed and nothing else was left, so the file
    /// was deleted (only ever for a file the caller says saiife created).
    Deleted,
}

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path} is not valid {format} ({detail}); saiife did not change it — fix or remove it, then run `saiife init` again")]
    Parse {
        path: PathBuf,
        format: &'static str,
        detail: String,
    },
    #[error("{path}: {detail}; saiife did not change it")]
    Layout { path: PathBuf, detail: String },
}

/// True when `command` runs `saiife check` (any path to the binary). This is
/// how saiife recognizes its own hook entries.
pub fn is_saiife_command(command: &str) -> bool {
    let mut words = command.split_whitespace();
    let (Some(bin), Some(sub)) = (words.next(), words.next()) else {
        return false;
    };
    let base = bin.rsplit('/').next().unwrap_or(bin);
    base == "saiife" && sub == "check"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for a in Agent::ALL {
            assert_eq!(Agent::from_name(a.name()), Some(a));
        }
        assert_eq!(Agent::from_name("cursor"), None);
    }

    #[test]
    fn hook_commands_use_hook_exit() {
        assert_eq!(
            Agent::Claude.hook_command(),
            "saiife check --hook-exit --agent claude"
        );
        assert_eq!(
            Agent::Gemini.hook_command(),
            "saiife check --hook-exit --agent gemini"
        );
    }

    #[test]
    fn recognizes_saiife_commands_only() {
        assert!(is_saiife_command("saiife check --hook-exit --agent claude"));
        assert!(is_saiife_command(
            "/usr/local/bin/saiife check --agent codex"
        ));
        assert!(is_saiife_command("  saiife   check"));
        assert!(!is_saiife_command("saiife status"));
        assert!(!is_saiife_command("my-saiife check"));
        assert!(!is_saiife_command("echo saiife check"));
        assert!(!is_saiife_command(""));
    }
}
