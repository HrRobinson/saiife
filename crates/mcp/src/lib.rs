//! JSON-RPC 2.0 and the subset of the Model Context Protocol that saiife
//! speaks: `saiife mcp` (a stdio server for agents) and the daemon's
//! gateway (a stdio client of third-party servers).
//!
//! Hand-rolled on serde (plan 17, decision 3). Both peers are untrusted,
//! so [`codec`] bounds every input: a line cap, a nesting cap
//! ([`codec::MAX_DEPTH`]), duplicate keys refused, batches refused, and no
//! panics on any input. The crate stays tokio-free.
#![forbid(unsafe_code)]

pub mod codec;
pub mod jsonrpc;
pub mod types;
pub mod version;
