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
//! No tokio: the CLI links this crate.

#![forbid(unsafe_code)]

pub mod host;
pub mod layout;
pub mod supported;
pub mod unit;

pub use host::{
    host_for, host_kind, Chown, CmdOutput, FakeHost, FakeState, Host, HostKind, RealHost, UserInfo,
    CONTAINER_UNKNOWN,
};
pub use layout::Layout;
pub use supported::{check_supported, refusal_line, Support, NOT_LINUX};
pub use unit::{unit_text, vault_key_mode};
