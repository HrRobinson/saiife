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
//! On Windows `layout`, `host`, `supported`, `sip`, `binary`, `winservice` and `winacl`
//! exist: every other module still uses Unix owners, modes or rustix, until the
//! rest of plan 19b.
//!
//! No tokio: the CLI links this crate.

#![forbid(unsafe_code)]

pub mod authright;
pub mod binary;
#[cfg(unix)]
pub mod default_config;
#[cfg(unix)]
pub mod doctor;
#[cfg(unix)]
pub mod fleet;
#[cfg(unix)]
pub mod fsops;
#[cfg(any(unix, windows))]
pub mod host;
#[cfg(unix)]
pub mod install;
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
#[cfg(unix)]
pub mod uninstall;
pub mod unit;
pub mod user_unit;
pub mod winacl;
pub mod winservice;

#[cfg(any(unix, windows))]
pub use host::{
    host_for, host_kind, Chown, CmdOutput, FakeHost, FakeState, Host, HostKind, RealHost, RegValue,
    ReloadAnswer, UserInfo, WinBuild, CONTAINER_UNKNOWN,
};
pub use layout::Layout;
pub use supported::{check_supported, refusal_line, Support, NOT_SUPPORTED_OS};
pub use unit::{unit_text, vault_key_mode};
