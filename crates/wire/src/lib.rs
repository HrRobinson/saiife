//! saiife Workspace wire: signed frames, access levels, pairing, sealing and the box source seam.
#![forbid(unsafe_code)]

pub mod b64;
#[cfg(feature = "fake")]
pub mod conformance;
pub mod device;
#[cfg(feature = "fake")]
pub mod fake;
pub mod frame;
pub mod level;
pub mod pair;
pub mod seal;
pub mod sig;
pub mod source;
pub mod verify;

mod error;
pub use error::WireError;
pub use source::BoxSource;
