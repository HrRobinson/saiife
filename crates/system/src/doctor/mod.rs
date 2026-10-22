//! `saiife doctor` (spec §5.6, §6.16): checks the machine locked mode relies
//! on and reports each finding as pass, warn, fail or info. Doctor only
//! reads: it changes nothing on the host. Programs run through [`Host`]
//! from absolute paths only.

/// Per-user host checks: locked mode is Linux-only (macOS in v2.1).
#[cfg(target_os = "linux")]
pub mod host;
pub mod report;
pub mod secrets;
pub mod system;

pub use report::{Check, Report, Status};

use crate::host::Host;
use crate::layout::{Layout, CONFIG, INSTALLED};
use saiife_policy::installed::{read_installed, Installed};
use saiife_policy::{load_and_check, Directory, LoadedPolicy};

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
    let ctx = Ctx {
        layout,
        host,
        dir,
        installed,
        installed_error,
        config: load_and_check(&layout.at(CONFIG), dir).map_err(|e| e.to_string()),
        as_root: host.euid() == 0,
        opts,
    };
    #[allow(unused_mut)]
    let mut checks = system::checks(&ctx);
    #[cfg(target_os = "linux")]
    checks.extend(host::checks(&ctx));
    Report { checks }
}
