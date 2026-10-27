//! saiifed: the locked-mode daemon (spec §4.1, §6.2, §6.3). Control server
//! on `saiife.sock`, the single audit writer, signed checkpoints, policy
//! reload on SIGHUP and a clean stop on SIGTERM/SIGINT. Linux only in this
//! version; elsewhere `run` refuses.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
pub mod api_ops;
#[cfg(target_os = "linux")]
pub mod approval_ops;
#[cfg(target_os = "linux")]
pub mod approvals;
#[cfg(target_os = "linux")]
pub mod approvers;
#[cfg(target_os = "linux")]
pub mod disk;
#[cfg(target_os = "linux")]
pub mod gateway;
#[cfg(target_os = "linux")]
pub mod import_backup;
#[cfg(target_os = "linux")]
pub mod limits;
#[cfg(target_os = "linux")]
pub mod lockdown;
#[cfg(target_os = "linux")]
pub mod notifier;
#[cfg(target_os = "linux")]
pub mod notify;
#[cfg(target_os = "linux")]
pub mod ops;
#[cfg(target_os = "linux")]
pub mod reauth;
#[cfg(target_os = "linux")]
pub mod secret_ops;
#[cfg(target_os = "linux")]
pub mod server;
#[cfg(target_os = "linux")]
pub mod sessions;
#[cfg(target_os = "linux")]
pub mod smtp;
#[cfg(target_os = "linux")]
mod start;
#[cfg(target_os = "linux")]
pub mod tokens;
#[cfg(target_os = "linux")]
pub mod vault;
#[cfg(target_os = "linux")]
pub mod writer;

use saiife_policy::{Directory, PackInfo};
use std::path::PathBuf;
use std::process::ExitCode;

pub struct DaemonOptions {
    /// `config.toml`; `policy.d/` is its sibling directory.
    pub config: PathBuf,
    /// Holds `keys/audit.ed25519`.
    pub state_dir: PathBuf,
    /// The built-in packs, for the policy hash.
    pub catalog: Vec<PackInfo>,
    pub directory: Box<dyn Directory + Send + Sync>,
    /// Holds `vault-key` (systemd `$CREDENTIALS_DIRECTORY`); `None` means no vault key.
    pub credentials_dir: Option<PathBuf>,
}

/// Run the daemon until SIGTERM or SIGINT. Startup refusals print one line
/// and exit 2.
#[cfg(target_os = "linux")]
pub fn run(opts: DaemonOptions) -> ExitCode {
    start::run(opts)
}

#[cfg(not(target_os = "linux"))]
pub fn run(_opts: DaemonOptions) -> ExitCode {
    eprintln!("saiife: locked mode needs Linux in this version (macOS: v2.1)");
    ExitCode::from(2)
}
