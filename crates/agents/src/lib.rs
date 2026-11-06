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

use std::path::{Path, PathBuf};

pub mod claude;
pub mod codex;
pub mod config;
pub mod detect;
pub mod fingerprint;
pub mod fsutil;
pub mod gemini;
pub mod integrity;
mod json_hooks;
pub mod lock;

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

    /// The project file `init` writes, relative to the project root.
    pub fn config_rel(self) -> &'static str {
        match self {
            Agent::Claude => claude::SETTINGS_REL,
            Agent::Codex => codex::CONFIG_REL,
            Agent::Gemini => gemini::SETTINGS_REL,
        }
    }

    /// The exact hook command written for this agent. Resolved via `PATH`
    /// so an upgrade never leaves a stale absolute path (spec §5.2).
    pub fn hook_command(self) -> String {
        format!("saiife check --hook-exit --agent {}", self.name())
    }

    /// The hook command in the machine-wide managed config (locked mode,
    /// spec §8.3): the absolute path of the root-owned binary, never `PATH`.
    pub fn managed_command(self) -> String {
        self.managed_command_on(cfg!(windows))
    }

    /// [`Agent::managed_command`] for a given platform. On Windows (spec
    /// W9) it has forward slashes and no spaces, so no shell needs quotes.
    pub fn managed_command_on(self, windows: bool) -> String {
        format!(
            "{} check --managed --hook-exit --agent {}",
            if windows { WINDOWS_BINARY } else { UNIX_BINARY },
            self.name()
        )
    }

    /// What the user still has to do in the agent before the hook runs.
    pub fn next_step(self) -> &'static str {
        match self {
            Agent::Claude => claude::NEXT_STEP,
            Agent::Codex => codex::NEXT_STEP,
            Agent::Gemini => gemini::NEXT_STEP,
        }
    }

    /// Add saiife's hook entry to this agent's project config.
    pub fn install(self, project: &Path) -> Result<Change, AgentError> {
        match self {
            Agent::Claude => claude::install(project),
            Agent::Codex => codex::install(project),
            Agent::Gemini => gemini::install(project),
        }
    }

    /// Remove saiife's hook entries (and only those) from this agent's
    /// project config. With `delete_if_empty` (a file saiife created), a
    /// file left with nothing in it is deleted.
    pub fn remove(self, project: &Path, delete_if_empty: bool) -> Result<Change, AgentError> {
        match self {
            Agent::Claude => claude::remove(project, delete_if_empty),
            Agent::Codex => codex::remove(project, delete_if_empty),
            Agent::Gemini => gemini::remove(project, delete_if_empty),
        }
    }

    /// Fingerprints of every saiife hook entry currently in the config, in
    /// file order. Empty when the file or the entry is missing.
    pub fn entries(self, project: &Path) -> Result<Vec<String>, AgentError> {
        match self {
            Agent::Claude => claude::entries(project),
            Agent::Codex => codex::entries(project),
            Agent::Gemini => gemini::entries(project),
        }
    }

    /// Settings in this agent's project or user config that stop the hook
    /// from running at all. Read-only.
    pub fn blockers(self, project: &Path, home: Option<&Path>) -> Vec<HookBlocker> {
        match self {
            Agent::Claude => claude::blockers(project, home),
            Agent::Codex => codex::blockers(project, home),
            Agent::Gemini => Vec::new(),
        }
    }

    /// Fingerprint of the entry `install` writes.
    pub fn expected_entry(self) -> String {
        match self {
            Agent::Claude => claude::expected_entry(),
            Agent::Codex => codex::expected_entry(),
            Agent::Gemini => gemini::expected_entry(),
        }
    }
}

/// A setting that switches an agent's hooks off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookBlocker {
    pub path: PathBuf,
    pub setting: &'static str,
    /// Set when `path` could not be read or parsed, so it is unknown whether
    /// it switches hooks off (`setting` is then empty). A missing file is
    /// not an error.
    pub error: Option<String>,
    /// The file is a machine-wide managed-settings file (an administrator's).
    pub managed: bool,
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
    /// The config (or a directory on its way) is a symlink that resolves
    /// outside the project, so saiife will not touch it.
    #[error("{path}: it is a symlink to {resolved}, outside the project; saiife only writes inside the project; saiife did not change it")]
    OutsideProject { path: PathBuf, resolved: PathBuf },
}

impl AgentError {
    /// The file this error is about, when it is a symlink out of the
    /// project (the by-hand cleanup case of `init --off`).
    pub fn outside_target(&self) -> Option<&Path> {
        match self {
            AgentError::OutsideProject { resolved, .. } => Some(resolved),
            _ => None,
        }
    }
}

/// The locked binary, as the managed hook names it.
pub(crate) const UNIX_BINARY: &str = "/opt/saiife/bin/saiife";
/// Windows (spec W9): forward slashes, no spaces.
pub const WINDOWS_BINARY: &str = "C:/ProgramData/saiife/bin/saiife.exe";

/// True when `command` runs `saiife check` (any path to the binary). This is
/// how saiife recognizes its own hook entries.
pub fn is_saiife_command(command: &str) -> bool {
    is_saiife_command_on(cfg!(windows), command)
}

/// [`is_saiife_command`] for a platform. Off Windows only the exact W9
/// managed path counts as a `.exe` command (so a Windows-layout write from
/// another OS can replace its own entry). On Windows any `saiife.exe`
/// counts, with `/` or `\` separators; a path with a space is split at the
/// space, so it never counts.
pub(crate) fn is_saiife_command_on(windows: bool, command: &str) -> bool {
    let mut words = command.split_whitespace();
    let (Some(bin), Some(sub)) = (words.next(), words.next()) else {
        return false;
    };
    if sub != "check" {
        return false;
    }
    if bin == WINDOWS_BINARY {
        return true;
    }
    let base = if windows {
        bin.rsplit(['/', '\\']).next().unwrap_or(bin)
    } else {
        bin.rsplit('/').next().unwrap_or(bin)
    };
    base == "saiife" || (windows && base.eq_ignore_ascii_case("saiife.exe"))
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

    /// Upgrading from plan 2: the Codex and Gemini entries (and so the
    /// fingerprints in existing integrity records) are unchanged; only
    /// Claude's entry changed (Glob and LS, then PowerShell, added to the matcher).
    #[test]
    fn entry_fingerprints_across_the_plan_3_upgrade() {
        assert_eq!(
            Agent::Codex.expected_entry(),
            "fa6f54dd98db7026395fb5766d29801222517b6563855b94f93dbcf462755198"
        );
        assert_eq!(
            Agent::Gemini.expected_entry(),
            "d3f7042e8a85f8e053ae3864fdce1921d8e5620f542fb5ca8a1f5e1183eb53fc"
        );
        assert_eq!(
            Agent::Claude.expected_entry(),
            "79bee8986b3cf00133dd2f437b9980d6b199d60e1b1b048a1447165145d758f4"
        );
        // The pre-PowerShell entry (MATCHER_V2) is no longer the expected one.
        assert_ne!(
            Agent::Claude.expected_entry(),
            "96fb881e404f7fed07a75eff98c42bf1c31553d8678c5e36c7216caadc5e2dca"
        );
        assert_ne!(
            Agent::Claude.expected_entry(),
            "78ff3176c0d50b70275b537d4f8e7c52ebba6e0ce22f68c03d01d52fd86c5d76"
        );
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
    fn exe_arm_is_windows_only_and_exact() {
        let w = |c: &str| is_saiife_command_on(true, c);
        let u = |c: &str| is_saiife_command_on(false, c);
        assert!(w("saiife.exe check"));
        assert!(w("C:/ProgramData/saiife/bin/saiife.exe check --managed"));
        assert!(w("SAIIFE.EXE check"));
        // A person may write the backslash form; on Windows it is ours.
        assert!(w(r"C:\x\saiife.exe check"));
        assert!(!u(r"C:\x\saiife.exe check"));
        // Off Windows only the exact managed path counts.
        assert!(!u("saiife.exe check"));
        assert!(!u("/tmp/saiife.exe check"));
        let managed = Agent::Claude.managed_command_on(true);
        assert!(u(&managed));
        for bad in [
            "saiife.exe.bat check",
            "saiife.exe.evil check",
            "evilsaiife.exe check",
            "\"C:/Program Files/saiife.exe\" check",
            "C:/Program Files/saiife.exe check",
            "C:/ProgramData/saiife/bin/saiife.exe.evil check",
            "saiife.exe status",
        ] {
            assert!(!w(bad), "{bad}");
            assert!(!u(bad), "{bad}");
        }
    }

    #[test]
    fn windows_managed_commands() {
        for (a, n) in [
            (Agent::Claude, "claude"),
            (Agent::Codex, "codex"),
            (Agent::Gemini, "gemini"),
        ] {
            assert_eq!(
                a.managed_command_on(true),
                format!(
                    "C:/ProgramData/saiife/bin/saiife.exe check --managed --hook-exit --agent {n}"
                )
            );
            assert!(is_saiife_command(&a.managed_command_on(true)));
            assert_eq!(
                a.managed_command_on(false),
                format!("/opt/saiife/bin/saiife check --managed --hook-exit --agent {n}")
            );
        }
    }

    #[test]
    fn managed_commands_use_the_opt_binary() {
        assert_eq!(
            Agent::Claude.managed_command_on(false),
            "/opt/saiife/bin/saiife check --managed --hook-exit --agent claude"
        );
        assert_eq!(
            Agent::Codex.managed_command_on(false),
            "/opt/saiife/bin/saiife check --managed --hook-exit --agent codex"
        );
        assert_eq!(
            Agent::Gemini.managed_command_on(false),
            "/opt/saiife/bin/saiife check --managed --hook-exit --agent gemini"
        );
    }

    /// What production calls picks the binary of the OS it runs on.
    #[test]
    fn managed_command_follows_the_host() {
        for a in Agent::ALL {
            assert_eq!(a.managed_command(), a.managed_command_on(cfg!(windows)));
        }
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
        assert!(!is_saiife_command("notsaiife check"));
        assert!(!is_saiife_command("/opt/bin/notsaiife check"));
        assert!(!is_saiife_command("saiife-check"));
        assert!(!is_saiife_command("saiife-check --agent claude"));
        assert!(!is_saiife_command("echo saiife check"));
        assert!(!is_saiife_command(""));
    }
}
