//! saiifed: the locked-mode daemon (spec §4.1, §6.2, §6.3). Control server
//! on `saiife.sock`, the single audit writer, signed checkpoints, policy
//! reload on SIGHUP and a clean stop on SIGTERM/SIGINT. Linux and macOS (plan 13).
//!
//! On Windows (plan 19b) the control endpoint is a named pipe, a peer is its token's SID,
//! and the service manager stops and reloads it. The personal broker there is Task 11.
#![forbid(unsafe_code)]

pub mod api_ops;
pub mod approval_ops;
pub mod approvals;
pub mod approvers;
pub mod audit_query;
pub mod cloud_ops;
pub mod disk;
pub mod forward_file;
pub mod forward_https;
pub mod forward_syslog;
pub mod forwarder;
pub mod fsx;
pub mod gateway;
pub mod grants;
pub mod import_backup;
pub mod limits;
pub mod lockdown;
pub mod mcp_gateway;
pub mod mcp_ops;
pub mod notifier;
#[cfg(unix)]
pub mod notify;
pub mod oauth;
pub mod ops;
pub mod personal;
#[cfg(windows)]
pub mod pipe_listener;
pub mod policy_ops;
pub mod reauth;
pub mod secret_ops;
pub mod server;
pub mod service_log;
pub mod sessions;
pub mod signals;
/// The SMTP client lives in the broker's mail transport (plan 14, Task 6);
/// the notifier sends through it.
pub use saiife_broker::mail::smtp;
mod start;
pub use start::VAULT_KEY_FILE;
pub mod tokens;
pub mod vault;
pub mod writer;

use saiife_policy::{Directory, PackInfo};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// The line `saiife daemon --user` refuses with outside Linux and macOS.
pub const PERSONAL_UNSUPPORTED: &str = "saiife: the personal broker needs Linux or macOS";

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
    /// A debug build's test: this pipe, owned by this process's SID, instead of W11's.
    /// Release builds of the CLI always pass `None`.
    #[cfg(windows)]
    pub test_pipe: Option<String>,
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
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn personal_preflight(
    config: &Path,
    socket_dir: &Path,
    locked_marker: &Path,
) -> Result<(), String> {
    start::personal_preflight(config, socket_dir, locked_marker)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn personal_preflight(
    config: &Path,
    socket_dir: &Path,
    locked_marker: &Path,
) -> Result<(), String> {
    let _ = (config, socket_dir, locked_marker);
    Err(PERSONAL_UNSUPPORTED
        .trim_start_matches("saiife: ")
        .to_string())
}

/// Run the daemon until SIGTERM or SIGINT. Startup refusals print one line
/// and exit 2.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn run(opts: DaemonOptions) -> ExitCode {
    start::run(opts)
}

/// Run the daemon outside the service manager (the tests): Ctrl+C stops it.
#[cfg(windows)]
pub fn run(opts: DaemonOptions) -> ExitCode {
    start::run(opts, None)
}

/// Run the daemon under the service manager: `ctl` stops and reloads it, and its stderr
/// goes to `log` (W10). The exit code goes to the service manager, and a non-zero one
/// runs the restart actions.
#[cfg(windows)]
pub fn run_service(
    opts: DaemonOptions,
    log: &Path,
    ctl: saiife_win::ffi::service::ServiceCtl,
) -> i32 {
    match service_log::open(log, service_log::MAX_LOG_BYTES)
        .and_then(saiife_win::ffi::process::redirect_stderr)
    {
        Ok(()) => {}
        // Stderr goes nowhere under the service manager: say so where it may be seen.
        Err(e) => eprintln!("saiife: warning: {}: {e}", log.display()),
    }
    run_controlled(opts, ctl)
}

/// [`run_service`] with stderr left alone. Standard error is one per process, so a test
/// process with several daemons must not move it.
#[cfg(windows)]
pub fn run_controlled(opts: DaemonOptions, ctl: saiife_win::ffi::service::ServiceCtl) -> i32 {
    let code = start::run(opts, Some(ctl));
    if code == ExitCode::SUCCESS {
        0
    } else if code == ExitCode::from(1) {
        1
    } else {
        2
    }
}

#[cfg(not(any(unix, windows)))]
pub fn run(opts: DaemonOptions) -> ExitCode {
    match opts.mode {
        DaemonMode::System => {
            eprintln!("saiife: locked mode needs Linux, macOS or Windows")
        }
        DaemonMode::Personal { .. } => eprintln!("{PERSONAL_UNSUPPORTED}"),
    }
    ExitCode::from(2)
}
