//! MCP protocol version negotiation (plan 17, decision 1).

/// The version saiife prefers, and the one it sends as a client.
pub const PREFERRED: &str = "2025-11-25";

/// Every version saiife accepts. `2025-03-26` is left out: it requires
/// JSON-RPC batches, which saiife never accepts.
pub const SUPPORTED: [&str; 2] = ["2025-11-25", "2025-06-18"];

/// The MCP rule: echo a supported version the client asked for, otherwise
/// answer [`PREFERRED`] (the client then decides whether to go on).
pub fn negotiate(asked: &str) -> &'static str {
    SUPPORTED
        .iter()
        .copied()
        .find(|v| *v == asked)
        .unwrap_or(PREFERRED)
}

/// Whether a version a server answered is one saiife can speak.
pub fn is_supported(v: &str) -> bool {
    SUPPORTED.contains(&v)
}
