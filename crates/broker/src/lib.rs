//! saiife-broker — connector manifests, parameter validation and operation
//! resolution (spec §6.7.1 steps 4–5, §6.8, §8.4).
//!
//! This crate never touches the network: it turns a request (a named
//! operation or a proxy path) into a validated operation plus parameters.
//! The gateway (later tasks) sends the upstream request.

#![forbid(unsafe_code)]

pub mod amount;
pub mod catalog;
pub mod limits;
pub mod manifest;
pub mod params;
pub mod resolve;

pub use catalog::Catalog;
pub use manifest::{builtin, Manifest, Operation};

/// Everything that can go wrong before a request is sent. Messages name
/// parameters and paths, never parameter values.
#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    #[error("connector manifest {0:?} has the id of a built-in connector")]
    ShadowsBuiltin(String),
    #[error("unknown parameter {0:?}")]
    UnknownParam(String),
    #[error("parameter {0:?} is fixed by the policy and cannot be set")]
    FixedParam(String),
    #[error("bad value for parameter {name:?}: {reason}")]
    BadValue { name: String, reason: String },
    #[error("path refused: {0}")]
    BadPath(String),
    #[error("no operation matches {0}")]
    UnknownOperation(String),
    #[error("manifest: {0}")]
    Manifest(String),
    #[error("unknown connector {0:?}")]
    UnknownConnector(String),
    #[error("missing required parameter {0:?}")]
    MissingParam(String),
    #[error("bad amount: {0}")]
    BadAmount(String),
}
