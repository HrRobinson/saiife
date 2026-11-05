//! `saiife doctor` (spec §5.6, §6.16): checks the machine locked mode relies
//! on and reports each finding as pass, warn, fail or info. Doctor only
//! reads: it changes nothing on the host. Programs run through [`Host`]
//! from absolute paths only.
//!
//! A Windows layout goes to [`windows`], on every OS, so Linux tests drive those checks
//! through a fake host. `system`, `host` and `secrets` read Unix owners and modes.

mod common;
/// Per-user host checks.
#[cfg(unix)]
pub mod host;
pub mod report;
#[cfg(unix)]
pub mod secrets;
#[cfg(unix)]
pub mod system;
pub mod windows;

pub use report::{Check, Report, Status};

use crate::host::Host;
use crate::layout::{Layout, Platform, CONFIG, INSTALLED, POLICY_D};
use saiife_policy::installed::{read_installed, Installed};
#[cfg(unix)]
use saiife_policy::load_and_check;
use saiife_policy::{load_and_check_with, Directory, LoadedPolicy};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DoctorOptions {
    /// Check this agent user (`--user`); the caller, or every scoped user
    /// as root, when `None`. Read by the per-user host checks
    /// ([`host::checks`]); the system checks do not depend on it.
    pub user: Option<String>,
    /// The caller's home (`$HOME`) for a self-check. Ignored as root, where
    /// every home comes from `/etc/passwd`.
    pub home: Option<std::path::PathBuf>,
}

/// What every check reads.
pub struct Ctx<'a> {
    pub layout: &'a Layout,
    pub host: &'a dyn Host,
    pub dir: &'a dyn Directory,
    /// `installed.toml`; `None` when missing or unreadable.
    pub installed: Option<Installed>,
    /// Why `installed.toml` could not be read, when it exists but is bad.
    pub installed_error: Option<String>,
    /// `config.toml` + `policy.d`, loaded and scope-checked.
    pub config: Result<LoadedPolicy, String>,
    /// Root, or on Windows an elevated administrator's token ([`Host::elevated`]).
    pub as_root: bool,
    pub opts: &'a DoctorOptions,
}

impl Ctx<'_> {
    /// Locked mode is installed (or its record exists but is unreadable,
    /// which is a failure, not developer mode).
    pub fn locked(&self) -> bool {
        self.installed.is_some() || self.installed_error.is_some()
    }
}

/// Runs every check against the tree under `layout`.
pub fn run(layout: &Layout, host: &dyn Host, dir: &dyn Directory, opts: &DoctorOptions) -> Report {
    let (installed, installed_error) = match read_installed(&layout.at(INSTALLED)) {
        Ok(i) => (i, None),
        Err(e) => (None, Some(e)),
    };
    let windows = layout.platform() == Platform::Windows;
    let config = if windows {
        load_and_check_with(&layout.at(CONFIG), &layout.at(POLICY_D), dir)
    } else {
        unix_config(layout, dir)
    };
    let ctx = Ctx {
        layout,
        host,
        dir,
        installed,
        installed_error,
        config: config.map_err(|e| e.to_string()),
        as_root: if windows {
            host.elevated()
        } else {
            host.euid() == 0
        },
        opts,
    };
    Report {
        checks: if windows {
            windows::checks(&ctx)
        } else {
            unix_checks(&ctx)
        },
    }
}

#[cfg(unix)]
fn unix_config(
    layout: &Layout,
    dir: &dyn Directory,
) -> Result<LoadedPolicy, saiife_policy::PolicyError> {
    load_and_check(&layout.at(CONFIG), dir)
}

#[cfg(unix)]
fn unix_checks(ctx: &Ctx) -> Vec<Check> {
    let mut checks = system::checks(ctx);
    checks.extend(host::checks(ctx));
    checks
}

/// A Windows build reads only Windows layouts: there is no other kind to read.
#[cfg(not(unix))]
fn unix_config(
    layout: &Layout,
    dir: &dyn Directory,
) -> Result<LoadedPolicy, saiife_policy::PolicyError> {
    load_and_check_with(&layout.at(CONFIG), &layout.at(POLICY_D), dir)
}

#[cfg(not(unix))]
fn unix_checks(ctx: &Ctx) -> Vec<Check> {
    windows::checks(ctx)
}
