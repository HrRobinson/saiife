//! Find executables on `PATH` (agents, and the `saiife` binary itself).

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::Agent;

/// The first executable regular file called `name` in the directories of
/// `path` (a `PATH`-style list). Empty entries are skipped.
pub fn find_in_path(name: &str, path: &OsStr) -> Option<PathBuf> {
    std::env::split_paths(path)
        .filter(|dir| !dir.as_os_str().is_empty())
        .map(|dir| dir.join(name))
        .find(|p| is_executable_file(p))
}

/// Like [`find_in_path`], but `name` may also match with one of the
/// `PATHEXT`-style extensions appended (`claude` finds `claude.cmd`). The
/// exact name is tried first in each directory, then the extensions in
/// order; `exts` entries are matched in lower case (Windows file names are
/// case-insensitive) and an empty entry is skipped. Pure, so Linux tests
/// run the Windows lookup.
pub fn find_in_path_ext(name: &str, path: &OsStr, exts: &str) -> Option<PathBuf> {
    let exts: Vec<String> = exts
        .split(';')
        .map(|e| e.trim().to_ascii_lowercase())
        .filter(|e| !e.is_empty())
        .collect();
    std::env::split_paths(path)
        .filter(|dir| !dir.as_os_str().is_empty())
        .find_map(|dir| {
            std::iter::once(name.to_string())
                .chain(exts.iter().map(|e| format!("{name}{e}")))
                .map(|n| dir.join(n))
                .find(|p| is_executable_file(p))
        })
}

/// `find_in_path` over this process's `PATH`; on Windows also through
/// `PATHEXT`, so `claude.cmd` and `claude.exe` are found as `claude`.
pub fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    if cfg!(windows) {
        let exts = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into());
        find_in_path_ext(name, &path, &exts)
    } else {
        find_in_path(name, &path)
    }
}

/// Where one agent keeps its user settings and what its executable is
/// called on `PATH`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentPath {
    pub agent: Agent,
    /// The agent's directory in the user's profile.
    pub config_dir: PathBuf,
    /// File names to look for on `PATH`, most likely first.
    pub binaries: Vec<String>,
}

/// The per-agent locations for a user whose profile is `home`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentPaths(pub Vec<AgentPath>);

impl AgentPaths {
    pub fn of(&self, agent: Agent) -> Option<&AgentPath> {
        self.0.iter().find(|p| p.agent == agent)
    }
}

/// The agents' locations. `windows`: the profile is `%USERPROFILE%` and the
/// executables carry their extension (`claude.exe`, `codex.cmd`,
/// `gemini.cmd`, with the other of `.cmd`/`.exe` as a fallback); otherwise
/// the bare names. Pure: nothing is read.
pub fn agent_paths(home: &Path, windows: bool) -> AgentPaths {
    AgentPaths(
        Agent::ALL
            .into_iter()
            .map(|agent| AgentPath {
                agent,
                config_dir: home.join(format!(".{}", agent.binary())),
                binaries: agent_binaries(agent, windows),
            })
            .collect(),
    )
}

/// The file names `agent`'s executable goes by on `PATH`, most likely
/// first: the bare name, or on Windows the name with its extension.
pub fn agent_binaries(agent: Agent, windows: bool) -> Vec<String> {
    let name = agent.binary();
    if !windows {
        return vec![name.to_string()];
    }
    let (first, second) = match agent {
        Agent::Claude => ("exe", "cmd"),
        Agent::Codex | Agent::Gemini => ("cmd", "exe"),
    };
    vec![format!("{name}.{first}"), format!("{name}.{second}")]
}

/// Agents whose binary is on this process's `PATH`, in `Agent::ALL` order.
/// Each is looked up by the names [`agent_binaries`] lists (the bare name
/// off Windows, so Linux and macOS look up exactly `a.binary()`).
pub fn detect_agents() -> Vec<Agent> {
    Agent::ALL
        .into_iter()
        .filter(|a| {
            agent_binaries(*a, cfg!(windows))
                .iter()
                .any(|b| which(b).is_some())
        })
        .collect()
}

fn is_executable_file(p: &std::path::Path) -> bool {
    let Ok(meta) = std::fs::metadata(p) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn exe(dir: &std::path::Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, "#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        }
        p
    }

    #[test]
    fn finds_first_match_in_path_order() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        exe(b.path(), "claude");
        let want = exe(a.path(), "claude");
        let path = std::env::join_paths([a.path(), b.path()]).unwrap();
        assert_eq!(find_in_path("claude", &path), Some(want));
    }

    #[cfg(unix)]
    #[test]
    fn skips_non_executable_files_and_directories() {
        let a = tempfile::tempdir().unwrap();
        fs::write(a.path().join("codex"), "not executable").unwrap();
        fs::create_dir(a.path().join("gemini")).unwrap();
        let path = std::env::join_paths([a.path()]).unwrap();
        assert_eq!(find_in_path("codex", &path), None);
        assert_eq!(find_in_path("gemini", &path), None);
    }

    /// The Windows lookup: `claude` is found as `claude.cmd` / `claude.exe`
    /// through `PATHEXT`, in PATH order, with the exact name first.
    #[test]
    fn pathext_finds_cmd_and_exe_shims() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let cmd = exe(a.path(), "claude.cmd");
        exe(b.path(), "claude.exe");
        let exe_only = exe(b.path(), "codex.exe");
        let path = std::env::join_paths([a.path(), b.path()]).unwrap();
        let exts = ".COM;.EXE;.BAT;.CMD";
        // The earlier directory wins even though .exe is listed before .cmd.
        assert_eq!(find_in_path_ext("claude", &path, exts), Some(cmd));
        assert_eq!(find_in_path_ext("codex", &path, exts), Some(exe_only));
        assert_eq!(find_in_path_ext("gemini", &path, exts), None);
        // Without the extension list nothing is guessed.
        assert_eq!(find_in_path_ext("claude", &path, ""), None);
        // Within a directory the exact name beats the extensions.
        let exact = exe(a.path(), "tool");
        exe(a.path(), "tool.exe");
        assert_eq!(find_in_path_ext("tool", &path, exts), Some(exact));
    }

    #[test]
    fn windows_agent_paths() {
        let home = Path::new("home").join("u");
        let w = agent_paths(&home, true);
        let c = w.of(Agent::Claude).unwrap();
        assert_eq!(c.config_dir, home.join(".claude"));
        assert_eq!(c.binaries, ["claude.exe", "claude.cmd"]);
        let x = w.of(Agent::Codex).unwrap();
        assert_eq!(x.config_dir, home.join(".codex"));
        assert_eq!(x.binaries, ["codex.cmd", "codex.exe"]);
        let g = w.of(Agent::Gemini).unwrap();
        assert_eq!(g.config_dir, home.join(".gemini"));
        assert_eq!(g.binaries, ["gemini.cmd", "gemini.exe"]);
        for a in Agent::ALL {
            assert_eq!(agent_binaries(a, true), w.of(a).unwrap().binaries);
        }
        // Elsewhere the executables are the bare names.
        let u = agent_paths(&home, false);
        for a in Agent::ALL {
            assert_eq!(u.of(a).unwrap().binaries, [a.binary()]);
            assert_eq!(u.of(a).unwrap().config_dir, w.of(a).unwrap().config_dir);
        }
    }

    #[test]
    fn empty_path_finds_nothing() {
        assert_eq!(find_in_path("claude", OsStr::new("")), None);
    }
}
