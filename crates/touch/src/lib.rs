//! saiife touch approvals: action-bound FIDO2 and WebAuthn assertions, verified on ring.
//! Tokio-free: the hook path may link this crate.

#![forbid(unsafe_code)]

pub mod action;
pub mod authdata;
pub(crate) mod cbor;
pub mod client;
pub mod cose;
pub mod error;
#[cfg(any(test, feature = "soft"))]
pub mod soft;
pub mod store;
pub mod verify;

pub use cose::CoseKey;
pub use error::TouchError;
pub use store::CoseAlg;

/// The relying party id of local (CTAP2) touches.
pub const LOCAL_RP_ID: &str = "saiife.local";
/// The relying party name shown on the device.
pub const RP_NAME: &str = "saiife";
/// How long an issued challenge lives.
pub const CHALLENGE_TTL_SECS: u64 = 300;
/// How long the device prompt waits for a touch.
pub const PROMPT_TIMEOUT_SECS: u64 = 120;
