//! Credential store types.

use serde::{Deserialize, Serialize};

use crate::cose::CoseKey;

/// A COSE signature algorithm saiife accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CoseAlg {
    /// ECDSA P-256 with SHA-256 (COSE -7).
    Es256,
    /// EdDSA over Ed25519 (COSE -8).
    Ed25519,
}

/// An enrolled credential. Bytes are base64url in JSON; the public key is
/// base64url of its COSE encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    #[serde(with = "crate::codec::b64")]
    pub id: Vec<u8>,
    #[serde(with = "crate::codec::cose_b64")]
    pub public_key: CoseKey,
    /// `"fido2"` or `"webauthn"`.
    pub kind: String,
    pub rp_id: String,
    /// The browser origins a WebAuthn credential may sign for.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub origins: Vec<String>,
    pub label: String,
    pub owner_uid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_sid: Option<String>,
    pub sign_count: u32,
    pub created: String,
    /// Hex.
    pub aaguid: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred() -> Credential {
        Credential {
            id: vec![0xfb, 0xff, 1],
            public_key: CoseKey::Ed25519 { x: [3; 32] },
            kind: "fido2".into(),
            rp_id: "saiife.local".into(),
            origins: vec![],
            label: "key".into(),
            owner_uid: 1000,
            owner_sid: None,
            sign_count: 7,
            created: "2026-01-01T00:00:00.000Z".into(),
            aaguid: "00".repeat(16),
        }
    }

    #[test]
    fn credential_json_shape() {
        let c = cred();
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["id"], "-_8B");
        assert_eq!(v["public_key"], crate::codec::b64(&c.public_key.to_cose()));
        assert!(v.get("origins").is_none() && v.get("owner_sid").is_none());
        assert_eq!(serde_json::from_value::<Credential>(v.clone()).unwrap(), c);
        let mut extra = v.clone();
        extra["bogus"] = 1.into();
        assert!(serde_json::from_value::<Credential>(extra).is_err());
        let mut bad_key = v;
        bad_key["public_key"] = crate::codec::b64(&[0xa0]).into();
        assert!(serde_json::from_value::<Credential>(bad_key).is_err());
    }
}
