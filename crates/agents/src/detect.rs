//! Find executables on `PATH` (agents, and the `saiife` binary itself).

use std::ffi::OsStr;
use std::path::PathBuf;

use crate::Agent;

/// The first executable regular file called `name` in the directories of
/// `path` (a `PATH`-style list). Empty entries are skipped.
pub fn find_in_path(name: &str, path: &OsStr) -> Option<PathBuf> {
    std::env::split_paths(path)
        .filter(|dir| !dir.as_os_str().is_empty())
        .map(|dir| dir.join(name))
        .find(|p| is_executable_file(p))
}

/// `find_in_path` over this process's `PATH`.
pub fn which(name: &str) -> Option<PathBuf> {
    find_in_path(name, &std::env::var_os("PATH")?)
}

/// Agents whose binary is on this process's `PATH`, in `Agent::ALL` order.
pub fn detect_agents() -> Vec<Agent> {
    Agent::ALL
        .into_iter()
        .filter(|a| which(a.binary()).is_some())
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

    #[test]
    fn empty_path_finds_nothing() {
        assert_eq!(find_in_path("claude", OsStr::new("")), None);
    }
}
