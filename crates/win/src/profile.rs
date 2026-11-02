//! Where the user's home and local data live, for every production lookup
//! (ruling P4, plan 19a). Linux and macOS are `dirs`, unchanged.
//!
//! On Windows `dirs` asks the known-folder API, which ignores the environment.
//! The agents resolve `~` from `USERPROFILE` (Node's `os.homedir()` reads it
//! first), so saiife reads the same variables first: `USERPROFILE` for the home
//! and `LOCALAPPDATA` for the data dir, each falling back to the known folder.
//! Tests can then isolate a child process by setting them.
//!
//! The cost: a process started with a changed `USERPROFILE` moves `~` for
//! saiife too, as a changed `HOME` does on Linux and macOS.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The user's home directory.
pub fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    return from_env_or(std::env::var_os("USERPROFILE"), dirs::home_dir);
    #[cfg(not(windows))]
    dirs::home_dir()
}

/// The base of saiife's per-user data: the local, non-roaming app data on
/// Windows (W3), so a roaming profile never syncs the audit log.
pub fn data_base_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    return from_env_or(std::env::var_os("LOCALAPPDATA"), dirs::data_local_dir);
    #[cfg(not(windows))]
    dirs::data_dir()
}

/// `value` when it is an absolute path, else what `known` finds. An empty or
/// relative value is ignored: it would resolve against the caller's working
/// directory, usually the project.
pub fn from_env_or(
    value: Option<OsString>,
    known: impl FnOnce() -> Option<PathBuf>,
) -> Option<PathBuf> {
    match value {
        Some(v) if Path::new(&v).is_absolute() => Some(PathBuf::from(v)),
        _ => known(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn absolute() -> PathBuf {
        std::env::current_dir().unwrap().join("from-env")
    }

    fn known() -> Option<PathBuf> {
        Some(PathBuf::from("known-folder"))
    }

    #[test]
    fn an_absolute_value_wins_over_the_known_folder() {
        let v = absolute();
        assert_eq!(from_env_or(Some(v.clone().into()), known), Some(v));
    }

    #[test]
    fn no_empty_or_relative_value_is_used() {
        for value in [None, Some(OsString::new()), Some("rel/dir".into())] {
            assert_eq!(from_env_or(value, known), known());
        }
        assert_eq!(from_env_or(Some("rel".into()), || None), None);
    }

    #[cfg(not(windows))]
    #[test]
    fn linux_and_macos_stay_with_dirs() {
        assert_eq!(home_dir(), dirs::home_dir());
        assert_eq!(data_base_dir(), dirs::data_dir());
    }

    // CI-only (windows-latest): the CI step sets LOCALAPPDATA.
    #[cfg(windows)]
    #[test]
    fn windows_reads_the_variables_first() {
        let want =
            |name: &str, known: Option<PathBuf>| from_env_or(std::env::var_os(name), || known);
        assert_eq!(home_dir(), want("USERPROFILE", dirs::home_dir()));
        assert_eq!(
            data_base_dir(),
            want("LOCALAPPDATA", dirs::data_local_dir())
        );
    }
}
