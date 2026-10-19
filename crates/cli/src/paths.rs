//! The directories the guard's path rules are bound to (spec §7.2, §7.4):
//! the working directory relative paths are resolved against, and the
//! values of the rule variables (`~`, `$PROJECT`, `$SAIIFE_DATA_DIR`,
//! `$SAIIFE_AUDIT_DIR`, `$SAIIFE_BIN`, `$CLAUDE_CONFIG_DIR`, `$CODEX_HOME`).

use std::path::{Path, PathBuf};

use saiife_agents::detect::which;
use saiife_agents::integrity;
use saiife_audit::store;
use saiifeguard::canon::PathVars;

/// An agent config dir: `value` when set and absolute, else `default` under
/// `home` (`None` when neither is known).
fn config_dir(
    value: Option<std::ffi::OsString>,
    home: Option<PathBuf>,
    default: &str,
) -> Option<PathBuf> {
    match value {
        Some(d) if Path::new(&d).is_absolute() => Some(PathBuf::from(d)),
        _ => home.map(|h| h.join(default)),
    }
}

/// `cwd`: where relative paths start (the hook payload's `cwd`); `project`:
/// the saiife project root, `cwd` if there is none. Every value the
/// process cannot determine is left out, so rules that need it do not apply.
pub fn path_vars(cwd: Option<&Path>, project: Option<&Path>) -> PathVars {
    let mut v = PathVars::new();
    if let Some(c) = cwd {
        v = v.with_cwd(c);
    }
    if let Some(h) = dirs::home_dir() {
        v = v.with_var("HOME", h);
    }
    // The agents' config dirs: the variable when set (and absolute), else
    // the default under HOME, so the rules naming them are always active.
    for (name, default) in [("CLAUDE_CONFIG_DIR", ".claude"), ("CODEX_HOME", ".codex")] {
        if let Some(d) = config_dir(std::env::var_os(name), dirs::home_dir(), default) {
            v = v.with_var(name, d);
        }
    }
    if let Some(p) = project.or(cwd) {
        v = v.with_var("PROJECT", p);
    }
    if let Some(d) = integrity::data_dir() {
        v = v.with_var("SAIIFE_DATA_DIR", d);
    }
    if let Some(d) = store::default_dir() {
        v = v.with_var("SAIIFE_AUDIT_DIR", d);
    }
    // The binary answering this hook and the `saiife` on PATH (usually
    // the same file once resolved).
    if let Ok(exe) = std::env::current_exe() {
        v = v.with_var("SAIIFE_BIN", exe);
    }
    if let Some(p) = which("saiife") {
        v = v.with_var("SAIIFE_BIN", p);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn config_dir_falls_back_to_the_default_under_home() {
        let home = || Some(PathBuf::from("/home/u"));
        let want = Some(PathBuf::from("/home/u/.claude"));
        assert_eq!(config_dir(None, home(), ".claude"), want);
        assert_eq!(config_dir(Some(OsString::new()), home(), ".claude"), want);
        assert_eq!(config_dir(Some("rel/dir".into()), home(), ".claude"), want);
        assert_eq!(
            config_dir(Some("/opt/claude".into()), home(), ".claude"),
            Some(PathBuf::from("/opt/claude"))
        );
        assert_eq!(config_dir(None, None, ".claude"), None);
    }

    #[test]
    fn binds_cwd_project_and_the_running_binary() {
        let d = tempfile::tempdir().unwrap();
        let real = std::fs::canonicalize(d.path()).unwrap();
        let v = path_vars(Some(d.path()), None);
        assert_eq!(v.cwd(), Some(real.as_path()));
        // Both the spelled and the resolved value are bound (they differ on
        // macOS, where the temp dir is `/var/…` -> `/private/var/…`).
        assert!(v.values("PROJECT").contains(&real.as_path()));
        assert!(v.values("PROJECT").contains(&d.path()));
        let exe = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        assert!(v.values("SAIIFE_BIN").contains(&exe.as_path()));
        assert!(path_vars(None, None).cwd().is_none());
    }
}
