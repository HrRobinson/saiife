//! Control-socket protocol for saiife locked mode. No async runtime here: the
//! managed hook path links this crate and must stay small and fast.
#![forbid(unsafe_code)]

pub mod client;
pub mod frame;
pub mod hookkey;
pub mod msg;
pub mod peer;
