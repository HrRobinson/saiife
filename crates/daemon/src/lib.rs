//! saiifed: the locked-mode daemon (spec §4.1, §6.2, §6.3). Control server
//! on `saiife.sock`, the single audit writer, signed checkpoints, policy
//! reload on SIGHUP and a clean stop on SIGTERM/SIGINT. Linux only in this
//! version; elsewhere `run` refuses.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
pub mod disk;
#[cfg(target_os = "linux")]
pub mod limits;
#[cfg(target_os = "linux")]
pub mod notify;
#[cfg(target_os = "linux")]
pub mod writer;
