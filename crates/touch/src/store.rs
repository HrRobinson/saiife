//! Credential store types.

use serde::{Deserialize, Serialize};

/// A COSE signature algorithm saiife accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CoseAlg {
    /// ECDSA P-256 with SHA-256 (COSE -7).
    Es256,
    /// EdDSA over Ed25519 (COSE -8).
    Ed25519,
}
