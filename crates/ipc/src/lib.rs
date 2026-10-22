//! Control-socket protocol for saiife locked mode. No async runtime here: the
//! managed hook path links this crate and must stay small and fast.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
pub mod client;
pub mod frame;
pub mod msg;
#[cfg(target_os = "linux")]
pub mod peer;
