//! The directories the guard's path rules are bound to (spec §7.2, §7.4):
//! the working directory relative paths are resolved against, and the
//! values of the rule variables (`~`, `$PROJECT`, `$SAIIFE_DATA_DIR`,
//! `$SAIIFE_AUDIT_DIR`, `$SAIIFE_BIN`, `$CLAUDE_CONFIG_DIR`, `$CODEX_HOME`,
//! and locked mode's system paths `$SAIIFE_ETC`, `$SAIIFE_STATE`,
//! `$SAIIFE_LOG`, `$SAIIFE_RUN`, `$SAIIFE_OPT`, `$SAIIFE_UNIT`).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

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

/// Locked mode's system paths (spec §5.2), at their defaults. Always bound:
/// only `core.lock` uses them, and it is on only in locked mode (or when a
/// project turns it on).
const SYSTEM_PATHS: [(&str, &str); 6] = [
    ("SAIIFE_ETC", "/etc/saiife"),
    ("SAIIFE_STATE", "/var/lib/saiife"),
    ("SAIIFE_LOG", "/var/log/saiife"),
    ("SAIIFE_RUN", "/run/saiife"),
    ("SAIIFE_OPT", "/opt/saiife"),
    ("SAIIFE_UNIT", "/etc/systemd/system/saiifed.service"),
];

/// Where a locked host's system config puts saiife's paths, when they are
/// not the §5.2 defaults: bound as extra values of the rule variables.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct LockedPaths {
    /// The directory holding the system config (`/etc/saiife`).
    pub etc: PathBuf,
    /// `[audit] dir`.
    pub audit_dir: PathBuf,
    /// `[daemon] socket_dir`.
    pub socket_dir: PathBuf,
}

/// `cwd`: where relative paths start (the hook payload's `cwd`); `project`:
/// the saiife project root, `cwd` if there is none. Every value the
/// process cannot determine is left out, so rules that need it do not apply.
pub fn path_vars(cwd: Option<&Path>, project: Option<&Path>) -> PathVars {
    path_vars_locked(cwd, project, None)
}

/// `path_vars`, plus the paths a locked host's system config names
/// (`locked`) as extra values of `$SAIIFE_ETC`, `$SAIIFE_AUDIT_DIR` and
/// `$SAIIFE_RUN`.
pub fn path_vars_locked(
    cwd: Option<&Path>,
    project: Option<&Path>,
    locked: Option<&LockedPaths>,
) -> PathVars {
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
    for (name, default) in SYSTEM_PATHS {
        v = v.with_var(name, default);
    }
    if let Some(l) = locked {
        v = v
            .with_var("SAIIFE_ETC", &l.etc)
            .with_var("SAIIFE_AUDIT_DIR", &l.audit_dir)
            .with_var("SAIIFE_RUN", &l.socket_dir);
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

    #[test]
    fn locked_paths_add_values() {
        let d = tempfile::tempdir().unwrap();
        let real = std::fs::canonicalize(d.path()).unwrap();
        let locked = LockedPaths {
            etc: real.join("etc"),
            audit_dir: real.join("audit"),
            socket_dir: real.join("run"),
        };
        let v = path_vars_locked(Some(&real), None, Some(&locked));
        let audit = v.values("SAIIFE_AUDIT_DIR");
        assert!(audit.contains(&real.join("audit").as_path()), "{audit:?}");
        if let Some(d) = store::default_dir() {
            assert!(audit.contains(&d.as_path()), "{audit:?}");
        }
        let etc = v.values("SAIIFE_ETC");
        assert!(etc.contains(&Path::new("/etc/saiife")), "{etc:?}");
        assert!(etc.contains(&real.join("etc").as_path()), "{etc:?}");
        let run = v.values("SAIIFE_RUN");
        assert!(run.contains(&Path::new("/run/saiife")), "{run:?}");
        assert!(run.contains(&real.join("run").as_path()), "{run:?}");
    }

    #[test]
    fn system_paths_are_always_bound_to_their_defaults() {
        let v = path_vars(None, None);
        for (name, want) in [
            ("SAIIFE_ETC", "/etc/saiife"),
            ("SAIIFE_STATE", "/var/lib/saiife"),
            ("SAIIFE_LOG", "/var/log/saiife"),
            ("SAIIFE_RUN", "/run/saiife"),
            ("SAIIFE_OPT", "/opt/saiife"),
            ("SAIIFE_UNIT", "/etc/systemd/system/saiifed.service"),
        ] {
            assert!(
                v.values(name).contains(&Path::new(want)),
                "{name}: {:?}",
                v.values(name)
            );
        }
        assert!(v.values("SAIIFE_ETC").len() <= 2);
    }
}
