//! saiife-system — locked mode on Linux (spec §5).
//!
//! - `layout`: every system path, under a root prefix so tests never touch
//!   the real `/etc`, `/opt`, `/var` or `/run`;
//! - `host`: every privileged action (users, groups, chown, systemctl,
//!   systemd-creds) behind the [`Host`] trait, with [`RealHost`] for the
//!   machine and [`FakeHost`] for tests and `--root`;
//! - `supported`: which systems locked mode supports (§0 decision 8);
//! - `unit`: the systemd unit text (§5.4.1).
//!
//! - `winacl`: the Windows ACL table (§5.3a.3), pure, on every OS.
//!
//! - `install_win`: `system install` and `system uninstall` on Windows, behind `Host`,
//!   on every OS, so Linux tests drive them.
//!
//! On Windows `fsops`, `polkit` and `testing` do not exist: they use Unix owners, modes or
//! rustix. `doctor` does, with its Windows checks only.
//!
//! No tokio: the CLI links this crate.

#![forbid(unsafe_code)]

pub mod authright;
pub mod binary;
pub mod default_config;
#[cfg(any(unix, windows))]
pub mod doctor;
pub mod fleet;
#[cfg(unix)]
pub mod fsops;
#[cfg(any(unix, windows))]
pub mod host;
pub mod install;
mod install_win;
pub mod launchd;
pub mod layout;
#[cfg(any(unix, windows))]
pub mod personal;
#[cfg(unix)]
pub mod polkit;
#[cfg(target_os = "linux")]
pub mod sandbox;
pub mod sip;
pub mod supported;
#[doc(hidden)]
#[cfg(unix)]
pub mod testing;
pub mod uninstall;
pub mod unit;
pub mod user_unit;
pub mod winacl;
pub mod winservice;
pub mod wintrust;

#[cfg(any(unix, windows))]
pub use host::{
    host_for, host_kind, Chown, CmdOutput, FakeHost, FakeState, Host, HostKind, RealHost, RegValue,
    ReloadAnswer, UserInfo, WinBuild, CONTAINER_UNKNOWN,
};
pub use layout::Layout;
pub use supported::{check_supported, refusal_line, Support, NOT_SUPPORTED_OS};
pub use unit::{unit_text, vault_key_mode};
