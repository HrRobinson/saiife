//! Cloud connectors (plan 15): AWS SigV4 signing, and later the GCP and
//! Azure token mints and AWS STS.

pub mod jwt;
pub mod session_policy;
pub mod sigv4;
pub mod sts;
pub mod token;

use crate::BrokerError;

/// What can go wrong when signing for, or minting from, a cloud. Messages
/// name what failed and never hold a key, a token or any other value: the
/// `String`s are descriptions, `code` is a sanitized error code
/// (`[A-Za-z0-9_.]{1,64}`) and `pattern` is a policy pattern.
#[derive(Debug, thiserror::Error)]
pub enum CloudError {
    /// The vault entry cannot be used as a cloud credential.
    #[error("cloud credential: {0}")]
    Key(String),
    /// A token or STS endpoint refused, with its sanitized error code.
    #[error("the cloud endpoint refused the request ({code})")]
    Endpoint { code: String },
    /// An endpoint answer that cannot be read.
    #[error("cloud endpoint answer: {0}")]
    Response(String),
    #[error(transparent)]
    Transport(#[from] BrokerError),
    /// A policy pattern that an IAM session policy cannot express exactly.
    #[error("pattern {pattern:?} cannot be expressed as an IAM session policy: {why}")]
    Unrepresentable { pattern: String, why: &'static str },
    /// An answer or a session policy over its size cap.
    #[error("cloud answer or session policy too large")]
    TooLarge,
}

/// Wipes an endpoint answer that held credentials or a token (`sts`,
/// `token`), when nothing else shares its buffer.
pub(crate) fn wipe(b: bytes::Bytes) {
    drop(zeroed(b));
}

/// `b`'s buffer, zeroed; `None` when another handle shares it (it is then
/// left to the last owner).
fn zeroed(b: bytes::Bytes) -> Option<bytes::BytesMut> {
    use zeroize::Zeroize;
    let mut m = b.try_into_mut().ok()?;
    m.as_mut().zeroize();
    Some(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_unique_answer_is_zeroed() {
        let b = bytes::Bytes::from(b"{\"access_token\":\"value\"}".to_vec());
        let m = zeroed(b).expect("a unique buffer is wiped");
        assert!(!m.is_empty() && m.iter().all(|&x| x == 0));
        // A shared one is left to its last owner.
        let b = bytes::Bytes::from(b"shared".to_vec());
        let other = b.clone();
        assert!(zeroed(b).is_none());
        assert_eq!(&other[..], b"shared");
    }
}
