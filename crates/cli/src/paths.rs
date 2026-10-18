//! The directories the guard's path rules are bound to (spec §7.2, §7.4):
//! the working directory relative paths are resolved against, and the
//! values of the rule variables (`~`, `$PROJECT`, `$SAIIFE_DATA_DIR`,
//! `$SAIIFE_AUDIT_DIR`, `$SAIIFE_BIN`, `$CLAUDE_CONFIG_DIR`, `$CODEX_HOME`).

use std::path::Path;

use saiife_agents::detect::which;
use saiife_agents::integrity;
use saiife_audit::store;
use saiifeguard::canon::PathVars;

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
        match std::env::var_os(name) {
            Some(d) if Path::new(&d).is_absolute() => v = v.with_var(name, d),
            _ => {
                if let Some(h) = dirs::home_dir() {
                    v = v.with_var(name, h.join(default));
                }
            }
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
