//! The box guest protocol shared by the host and the guest agent. Tokio-free by design.
#![forbid(unsafe_code)]

pub mod delta;
pub mod frame;
pub mod manifest;
pub mod msg;
pub mod ports;

/// Protocol identifier carried in the hello exchange.
pub const PROTO: &str = "saiife-guest/1";
