//! saiife-broker — connector manifests, parameter validation and operation
//! resolution (spec §6.7.1 steps 4–5, §6.8, §8.4).
//!
//! Steps 4–5 never touch the network: they turn a request (a named
//! operation or a proxy path) into a validated operation plus parameters.
//! [`request`] builds the upstream request and [`upstream`] sends it over
//! pinned TLS (step 9).

#![forbid(unsafe_code)]

pub mod amount;
pub mod catalog;
pub mod judge;
pub mod limits;
pub mod mail;
pub mod manifest;
pub mod mask;
pub mod oauth2;
pub mod params;
pub mod pipeline;
pub mod redact;
pub mod request;
pub mod resolve;
pub mod tool_schema;
pub mod upstream;

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
    #[error("{0}")]
    UnknownScopeEntry(String),
    #[error("missing required parameter {0:?}")]
    MissingParam(String),
    #[error("bad amount: {0}")]
    BadAmount(String),
    #[error("the upstream host is not one of the connector's hosts")]
    HostNotAllowed,
    #[error("redirect refused (only same-origin redirects, at most 3, are followed)")]
    RedirectRefused,
    #[error("upstream timeout")]
    Timeout,
    /// A transport or TLS failure. The message never holds a header or body.
    #[error("upstream: {0}")]
    Upstream(String),
    /// The service has `redact` fields but the upstream answer is not JSON,
    /// so it is withheld (decision 5, `rule = "redact_non_json"`).
    #[error("response withheld: the service redacts fields but the response is not JSON")]
    RedactNonJson,
    /// The upstream says the body is JSON but it is not valid UTF-8.
    #[error("upstream response is labelled JSON but is not valid UTF-8")]
    BadResponseEncoding,
}
