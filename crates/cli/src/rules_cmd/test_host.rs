//! Test dirs for the rule checks, in each path style a host can judge.

use saiifeguard::canon::{PathStyle, PathVars};

/// This host's test dirs, in its own form.
pub fn vars() -> PathVars {
    if cfg!(windows) {
        win_vars()
    } else {
        posix_vars()
    }
}

pub fn posix_vars() -> PathVars {
    PathVars::new()
        .with_style(PathStyle::Posix)
        .with_cwd("/saiife-test/project")
        .with_var("PROJECT", "/saiife-test/project")
        .with_var("HOME", "/saiife-test/home")
}

/// A Windows host's dirs: Windows paths are judged as text, so every host
/// runs these.
pub fn win_vars() -> PathVars {
    PathVars::new()
        .with_style(PathStyle::Windows)
        .with_cwd(r"C:\saiife-test\project")
        .with_var("PROJECT", r"C:\saiife-test\project")
        .with_var("USERPROFILE", r"C:\saiife-test\home")
}

/// Each style this host can judge. A Windows host reads `/saiife-test` as
/// relative to its drive, so it runs only the Windows style.
pub fn styles() -> Vec<PathVars> {
    if cfg!(windows) {
        vec![win_vars()]
    } else {
        vec![posix_vars(), win_vars()]
    }
}

pub fn windows(v: &PathVars) -> bool {
    v.style() == PathStyle::Windows
}

/// The hosts file as this host's never-line names it.
pub const HOSTS_TYPED: &str = if cfg!(windows) {
    r"C:\Windows\System32\drivers\etc\hosts"
} else {
    "/etc/hosts"
};

/// Its glob: the guard's canonical form of [`HOSTS_TYPED`].
pub const HOSTS: &str = if cfg!(windows) {
    "c:/Windows/System32/drivers/etc/hosts"
} else {
    "/etc/hosts"
};
