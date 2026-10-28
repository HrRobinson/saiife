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
pub mod audit_query;
#[cfg(target_os = "linux")]
pub mod disk;
#[cfg(target_os = "linux")]
pub mod forward_file;
#[cfg(target_os = "linux")]
pub mod forward_https;
#[cfg(target_os = "linux")]
pub mod forward_syslog;
#[cfg(target_os = "linux")]
pub mod forwarder;
#[cfg(target_os = "linux")]
pub mod gateway;
#[cfg(target_os = "linux")]
pub mod grants;
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
pub mod oauth;
#[cfg(target_os = "linux")]
pub mod ops;
#[cfg(target_os = "linux")]
pub mod personal;
#[cfg(target_os = "linux")]
pub mod policy_ops;
#[cfg(target_os = "linux")]
pub mod reauth;
#[cfg(target_os = "linux")]
pub mod secret_ops;
#[cfg(target_os = "linux")]
pub mod server;
#[cfg(target_os = "linux")]
pub mod sessions;
#[cfg(target_os = "linux")]
pub mod signals;
/// The SMTP client lives in the broker's mail transport (plan 14, Task 6);
/// the notifier sends through it.
#[cfg(target_os = "linux")]
pub use saiife_broker::mail::smtp;
#[cfg(target_os = "linux")]
mod start;
#[cfg(target_os = "linux")]
pub mod tokens;
#[cfg(target_os = "linux")]
pub mod vault;
#[cfg(target_os = "linux")]
pub mod writer;

use saiife_policy::{Directory, PackInfo};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// The line `saiife daemon --user` refuses with outside Linux (decision 9).
pub const PERSONAL_NEEDS_LINUX: &str =
    "saiife: the personal broker needs Linux in this version (macOS: with the v2.1 daemon port)";

/// Which daemon to run.
pub enum DaemonMode {
    /// `saiife daemon --system`: the locked system daemon.
    System,
    /// `saiife daemon --user`: the personal broker, as the logged-in user
    /// (plan 16). Not a security boundary.
    Personal {
        /// `$XDG_RUNTIME_DIR/saiife`.
        socket_dir: PathBuf,
        /// `$XDG_DATA_HOME/saiife/broker/audit`.
        audit_dir: PathBuf,
        /// Holds the vault key; read once at start, before the runtime.
        keychain: Box<dyn saiife_keychain::Keychain>,
        /// `/etc/saiife/installed.toml`: when it exists the host is locked
        /// and the personal broker refuses to start.
        locked_marker: PathBuf,
    },
}

pub struct DaemonOptions {
    /// `config.toml`; `policy.d/` is its sibling directory.
    pub config: PathBuf,
    /// Holds `keys/audit.ed25519` (locked), or the personal broker's state.
    pub state_dir: PathBuf,
    /// The built-in packs, for the policy hash.
    pub catalog: Vec<PackInfo>,
    pub directory: Box<dyn Directory + Send + Sync>,
    /// Holds `vault-key` (systemd `$CREDENTIALS_DIRECTORY`); `None` means no
    /// vault key. Always `None` for the personal broker.
    pub credentials_dir: Option<PathBuf>,
    pub mode: DaemonMode,
}

/// A keychain that could not be opened: every call fails with that error,
/// so the personal broker still starts, with the vault unavailable.
pub struct UnavailableKeychain(pub saiife_keychain::KeychainError);

impl saiife_keychain::Keychain for UnavailableKeychain {
    fn get(
        &self,
        _: &saiife_keychain::ItemId,
    ) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, saiife_keychain::KeychainError> {
        Err(self.0.clone())
    }
    fn set(
        &self,
        _: &saiife_keychain::ItemId,
        _: &str,
        _: &[u8],
    ) -> Result<(), saiife_keychain::KeychainError> {
        Err(self.0.clone())
    }
    fn delete(&self, _: &saiife_keychain::ItemId) -> Result<bool, saiife_keychain::KeychainError> {
        Err(self.0.clone())
    }
    fn backend(&self) -> &'static str {
        "unavailable"
    }
}

/// The personal broker's refusals that need nothing opened or created:
/// root, a locked host (`locked_marker` exists), a bad `$XDG_RUNTIME_DIR`
/// (the parent of `socket_dir`) and a config with `locked = true`. The CLI
/// runs this before it opens the keychain; the start runs it again.
#[cfg(target_os = "linux")]
pub fn personal_preflight(
    config: &Path,
    socket_dir: &Path,
    locked_marker: &Path,
) -> Result<(), String> {
    start::personal_preflight(config, socket_dir, locked_marker)
}

#[cfg(not(target_os = "linux"))]
pub fn personal_preflight(
    config: &Path,
    socket_dir: &Path,
    locked_marker: &Path,
) -> Result<(), String> {
    let _ = (config, socket_dir, locked_marker);
    Err(PERSONAL_NEEDS_LINUX
        .trim_start_matches("saiife: ")
        .to_string())
}

/// Run the daemon until SIGTERM or SIGINT. Startup refusals print one line
/// and exit 2.
#[cfg(target_os = "linux")]
pub fn run(opts: DaemonOptions) -> ExitCode {
    start::run(opts)
}

#[cfg(not(target_os = "linux"))]
pub fn run(opts: DaemonOptions) -> ExitCode {
    match opts.mode {
        DaemonMode::System => {
            eprintln!("saiife: locked mode needs Linux in this version (macOS: v2.1)")
        }
        DaemonMode::Personal { .. } => eprintln!("{PERSONAL_NEEDS_LINUX}"),
    }
    ExitCode::from(2)
}
