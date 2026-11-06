//! `saiife doctor [--user <name>] [--json]`: checks the machine locked mode
//! relies on (spec §5.6, §6.16). Exit 0 all pass, 1 a warning, 2 a failure.
//! Read-only: it changes nothing on the host.

use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(unix)]
use saiife_policy::{Directory, Getent};
use saiife_system::doctor::{self, DoctorOptions};
use saiife_system::{host_for, Layout};

use crate::text::sanitize;

pub fn run(user: Option<String>, json: bool, root: Option<PathBuf>) -> ExitCode {
    let layout = root.map(Layout::under).unwrap_or_else(Layout::system);
    let host = match host_for(&layout) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("saiife: doctor: {}", sanitize(&e.to_string()));
            return ExitCode::from(2);
        }
    };
    #[cfg(unix)]
    let dir = Getent;
    #[cfg(unix)]
    if let Some(name) = &user {
        let me = dir.name_of(rustix::process::getuid().as_raw());
        if me.as_deref() != Some(name.as_str()) && host.euid() != 0 {
            eprintln!("saiife: --user {} needs root", sanitize(name));
            return ExitCode::from(2);
        }
    }
    #[cfg(unix)]
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|h| h.is_absolute());
    #[cfg(windows)]
    let dir = saiife_policy::WinDirectory::system();
    #[cfg(windows)]
    let user = match windows_user(user, host.elevated()) {
        Ok(u) => u,
        Err(name) => {
            eprintln!(
                "saiife: --user {}: {}",
                sanitize(&name),
                saiife_system::supported::NOT_ELEVATED
            );
            return ExitCode::from(2);
        }
    };
    // The profile comes from the registry by SID: the environment is the caller's.
    #[cfg(windows)]
    let home = None;
    let report = doctor::run(&layout, host.as_ref(), &dir, &DoctorOptions { user, home });
    if json {
        outln!(
            "{}",
            serde_json::to_string_pretty(&report.to_json()).unwrap_or_default()
        );
    } else {
        out!("{}", report.to_text());
    }
    ExitCode::from(report.exit_code())
}

/// The agent user to check on Windows. Elevated: `--user`, or every scoped user when it is
/// `None`. From a plain shell: the caller only, and `--user` may name no one else. `Err`
/// holds a name that needs an elevated terminal.
#[cfg(windows)]
fn windows_user(user: Option<String>, elevated: bool) -> Result<Option<String>, String> {
    use saiife_win::ffi::{account, token};
    if elevated {
        return Ok(user);
    }
    let me = token::current()
        .ok()
        .and_then(|t| account::lookup_sid(&t.sid).ok());
    match user {
        None => Ok(me),
        Some(name) if me.as_deref().is_some_and(|m| same_account(m, &name)) => Ok(Some(name)),
        Some(name) => Err(name),
    }
}

/// `DOMAIN\\name` against `name` or `DOMAIN\\name`, as Windows compares names.
#[cfg(windows)]
fn same_account(me: &str, name: &str) -> bool {
    let bare = |s: &str| {
        s.rsplit_once('\\')
            .map_or(s.to_string(), |(_, n)| n.to_string())
    };
    me.eq_ignore_ascii_case(name) || (!name.contains('\\') && bare(me).eq_ignore_ascii_case(name))
}
