//! saiife dev: compose stacks on one local proxy, by name instead of port.
#![forbid(unsafe_code)]

pub mod certs;
pub mod compose;
pub mod docker;
pub mod labels;
pub mod paths;
pub mod project;
pub mod proxy;
pub mod quirks;
pub mod rewrite;

mod error;
pub use error::DevError;
