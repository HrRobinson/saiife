//! The touch client: what asks a device (or a browser) for an assertion.

use serde::{Deserialize, Serialize};

use crate::verify::Assertion;
use crate::TouchError;

/// One assertion request: the answer of `touch.begin`.
/// `challenge` is hex in JSON and `allow` a list of base64url ids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TouchRequest {
    pub rp_id: String,
    #[serde(with = "crate::codec::hex32")]
    pub challenge: [u8; 32],
    #[serde(with = "crate::codec::b64_list")]
    pub allow: Vec<Vec<u8>>,
    pub uv: bool,
    pub summary: String,
    pub short_code: String,
}

/// One enrolment (make-credential) request. Same encodings as `TouchRequest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrolRequest {
    pub rp_id: String,
    pub rp_name: String,
    #[serde(with = "crate::codec::b64")]
    pub user_id: Vec<u8>,
    pub user_name: String,
    #[serde(with = "crate::codec::hex32")]
    pub challenge: [u8; 32],
    #[serde(with = "crate::codec::b64_list")]
    pub exclude: Vec<Vec<u8>>,
}

/// A source of touches: a CTAP2 key, or a test double.
pub trait Touch: Send + Sync {
    /// One assertion over `r.challenge` (signed as `authData ‖ SHA-256(challenge)`, D1).
    fn request(&self, r: &TouchRequest) -> Result<Assertion, TouchError>;
    /// A new credential; returns the raw attestation authData, with AT set.
    fn enrol(&self, r: &EnrolRequest) -> Result<Vec<u8>, TouchError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_json_shape() {
        let r = TouchRequest {
            rp_id: crate::LOCAL_RP_ID.into(),
            challenge: [0xab; 32],
            allow: vec![vec![0xfb, 0xff]],
            uv: true,
            summary: "#1 land".into(),
            short_code: "123456".into(),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["challenge"], "ab".repeat(32));
        assert_eq!(v["allow"], serde_json::json!(["-_8"]));
        assert_eq!(serde_json::from_value::<TouchRequest>(v).unwrap(), r);

        let e = EnrolRequest {
            rp_id: crate::LOCAL_RP_ID.into(),
            rp_name: crate::RP_NAME.into(),
            user_id: vec![1, 2, 3],
            user_name: "jo".into(),
            challenge: [1; 32],
            exclude: vec![],
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["user_id"], "AQID");
        assert_eq!(v["challenge"], "01".repeat(32));
        assert_eq!(serde_json::from_value::<EnrolRequest>(v).unwrap(), e);
    }
}
