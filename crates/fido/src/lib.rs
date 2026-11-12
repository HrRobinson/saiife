//! The FIDO helper's shared parts (plan 41): the line protocol, the CTAP
//! error table and, with `hid`, the CTAP calls. No tokio, no printing.

pub mod errors;
#[cfg(feature = "fake")]
pub mod fake;
pub mod helper;
#[cfg(feature = "hid")]
pub mod hid;
pub mod proto;
