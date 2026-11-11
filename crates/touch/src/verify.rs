//! The assertion verifier: one pure check for CTAP2 and WebAuthn assertions
//! against an action record (§8.3, D1, D4, D5), on ring.

use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ED25519};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::action::{challenge, sha256, ActionRecord};
use crate::authdata::{self, AuthData, UP, UV};
use crate::codec::{b64, hex};
use crate::cose::CoseKey;
use crate::store::Credential;
use crate::TouchError;

/// A device's answer to a touch request. This JSON is the `touch` argument of
/// `approval.decide`: bytes are base64url, `client_data_hash` hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Assertion {
    /// A local CTAP2 key (ctap-hid-fido2).
    #[serde(rename = "fido2")]
    Ctap2 {
        #[serde(with = "crate::codec::b64")]
        credential_id: Vec<u8>,
        #[serde(with = "crate::codec::b64")]
        auth_data: Vec<u8>,
        #[serde(with = "crate::codec::b64")]
        signature: Vec<u8>,
        #[serde(with = "crate::codec::hex32")]
        client_data_hash: [u8; 32],
    },
    /// A browser (`navigator.credentials.get`).
    #[serde(rename = "webauthn")]
    WebAuthn {
        #[serde(with = "crate::codec::b64")]
        credential_id: Vec<u8>,
        #[serde(with = "crate::codec::b64")]
        auth_data: Vec<u8>,
        #[serde(with = "crate::codec::b64")]
        signature: Vec<u8>,
        #[serde(with = "crate::codec::b64")]
        client_data_json: Vec<u8>,
        origin: String,
    },
}

/// What a verified touch proves, for the audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TouchEvidence {
    /// base64url.
    pub credential_id: String,
    /// `"fido2"` or `"webauthn"`.
    pub kind: &'static str,
    pub user_verified: bool,
    /// The new counter, to store.
    pub sign_count: u32,
    pub challenge_hex: String,
    pub label: String,
    /// `"local"` (fido2) or `"web"` (webauthn).
    pub via: &'static str,
    pub flags: u8,
    pub auth_data: Vec<u8>,
    /// The `clientDataJSON` (WebAuthn only).
    pub client_data: Option<Vec<u8>>,
    pub client_data_hash: [u8; 32],
    pub signature: Vec<u8>,
    pub preimage_hex: String,
    /// `canonical_action()`.
    pub action: String,
}

impl TouchEvidence {
    /// The audit form: bytes base64url, hashes hex (R3; `reverify` reads it back).
    pub fn to_audit(&self) -> serde_json::Value {
        let mut v = json!({
            "via": self.via,
            "kind": self.kind,
            "cred_id": self.credential_id,
            "label": self.label,
            "flags": self.flags,
            "uv": self.user_verified,
            "sign_count": self.sign_count,
            "auth_data": b64(&self.auth_data),
            "client_data_hash": hex(&self.client_data_hash),
            "signature": b64(&self.signature),
            "challenge": self.challenge_hex,
            "preimage": self.preimage_hex,
            "action": self.action,
        });
        if let Some(cd) = &self.client_data {
            v["client_data"] = b64(cd).into();
        }
        v
    }
}

/// Byte caps (Global Constraints).
const MAX_CREDENTIAL_ID: usize = 1023;
const MAX_AUTH_DATA: usize = 1024;
const MAX_SIGNATURE: usize = 256;
const MAX_CLIENT_DATA_JSON: usize = 2048;

impl Assertion {
    pub fn credential_id(&self) -> &[u8] {
        match self {
            Self::Ctap2 { credential_id, .. } | Self::WebAuthn { credential_id, .. } => {
                credential_id
            }
        }
    }

    pub fn auth_data(&self) -> &[u8] {
        match self {
            Self::Ctap2 { auth_data, .. } | Self::WebAuthn { auth_data, .. } => auth_data,
        }
    }

    pub fn signature(&self) -> &[u8] {
        match self {
            Self::Ctap2 { signature, .. } | Self::WebAuthn { signature, .. } => signature,
        }
    }

    /// `"fido2"` or `"webauthn"`.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Ctap2 { .. } => "fido2",
            Self::WebAuthn { .. } => "webauthn",
        }
    }
}

/// Steps 1 and 2: the size caps, then the authData parse.
fn precheck(asr: &Assertion) -> Result<AuthData<'_>, TouchError> {
    let cdj_ok = match asr {
        Assertion::WebAuthn {
            client_data_json, ..
        } => client_data_json.len() <= MAX_CLIENT_DATA_JSON,
        Assertion::Ctap2 { .. } => true,
    };
    if !cdj_ok
        || asr.credential_id().len() > MAX_CREDENTIAL_ID
        || asr.auth_data().len() > MAX_AUTH_DATA
        || asr.signature().len() > MAX_SIGNATURE
    {
        return Err(TouchError::Malformed);
    }
    authdata::parse(asr.auth_data())
}

/// Step 5 (D1): checks the client data against `expected` and returns the
/// client data hash the verifier computed itself.
fn client_hash(
    cred: &Credential,
    asr: &Assertion,
    expected: &[u8],
) -> Result<[u8; 32], TouchError> {
    match asr {
        Assertion::Ctap2 {
            client_data_hash, ..
        } => {
            let want = sha256(expected);
            if *client_data_hash != want {
                return Err(TouchError::Mismatch);
            }
            Ok(want)
        }
        Assertion::WebAuthn {
            client_data_json,
            origin,
            ..
        } => {
            let v: serde_json::Value =
                serde_json::from_slice(client_data_json).map_err(|_| TouchError::Malformed)?;
            let obj = v.as_object().ok_or(TouchError::Malformed)?;
            if obj.get("type").and_then(|t| t.as_str()) != Some("webauthn.get") {
                return Err(TouchError::Malformed);
            }
            if obj.get("challenge").and_then(|c| c.as_str()) != Some(b64(expected).as_str()) {
                return Err(TouchError::Mismatch);
            }
            let json_origin = obj.get("origin").and_then(|o| o.as_str());
            if json_origin != Some(origin.as_str()) || !cred.origins.contains(origin) {
                return Err(TouchError::Mismatch);
            }
            if obj.get("crossOrigin") == Some(&serde_json::Value::Bool(true)) {
                return Err(TouchError::Mismatch);
            }
            Ok(sha256(client_data_json))
        }
    }
}

/// Step 7: the signature over `auth_data ‖ hash`.
fn check_signature(key: &CoseKey, auth_data: &[u8], hash: &[u8; 32], sig: &[u8]) -> bool {
    let mut msg = Vec::with_capacity(auth_data.len() + 32);
    msg.extend_from_slice(auth_data);
    msg.extend_from_slice(hash);
    match key {
        CoseKey::Es256 { x, y } => {
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(x);
            point.extend_from_slice(y);
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point)
                .verify(&msg, sig)
                .is_ok()
        }
        CoseKey::Ed25519 { x } => UnparsedPublicKey::new(&ED25519, x)
            .verify(&msg, sig)
            .is_ok(),
    }
}

/// Steps 1-3 and 5-9 of [`verify`] against one credential, with a raw
/// expected challenge: the Ctap2 branch compares `client_data_hash` with
/// `SHA-256(expected_challenge)`, the WebAuthn branch compares
/// `clientDataJSON.challenge` with base64url(`expected_challenge`).
///
/// `need_uv` is honoured as passed: the caller decides. (`verify` passes true
/// for every WebAuthn assertion, D4; a published vector without UV passes
/// false.) Returns the authData flags and the new sign counter.
pub fn verify_parts(
    cred: &Credential,
    asr: &Assertion,
    rp_id: &str,
    expected_challenge: &[u8],
    need_uv: bool,
) -> Result<(u8, u32), TouchError> {
    let ad = precheck(asr)?;
    if cred.id != asr.credential_id() {
        return Err(TouchError::UnknownCredential);
    }
    if cred.rp_id != rp_id {
        return Err(TouchError::Mismatch);
    }
    let hash = client_hash(cred, asr, expected_challenge)?;
    if ad.rp_id_hash != sha256(rp_id.as_bytes()) {
        return Err(TouchError::Mismatch);
    }
    if !check_signature(&cred.public_key, asr.auth_data(), &hash, asr.signature()) {
        return Err(TouchError::BadSignature);
    }
    if ad.flags & UP == 0 {
        return Err(TouchError::NotPresent);
    }
    if need_uv && ad.flags & UV == 0 {
        return Err(TouchError::NotVerified);
    }
    let (old, new) = (cred.sign_count, ad.sign_count);
    if (old != 0 || new != 0) && new <= old {
        return Err(TouchError::Replayed);
    }
    Ok((ad.flags, new))
}

/// Verifies `asr` as a touch for the action `a`, against the caller's
/// enrolled credentials. Pure: the caller stores the new counter and spends
/// the challenge. Checks, in order: the size caps, the authData parse, the
/// credential and its rp id, the expiry, the client data (D1), the rp id
/// hash, the signature, UP then UV (D4), and the counter (D5).
pub fn verify(
    creds: &[Credential],
    a: &ActionRecord,
    asr: &Assertion,
    rp_id: &str,
    now: u64,
) -> Result<TouchEvidence, TouchError> {
    precheck(asr)?;
    let cred = creds
        .iter()
        .find(|c| c.id == asr.credential_id())
        .ok_or(TouchError::UnknownCredential)?;
    if cred.rp_id != rp_id {
        return Err(TouchError::Mismatch);
    }
    if now > a.expires_at {
        return Err(TouchError::Expired);
    }
    let c = challenge(a);
    let web = matches!(asr, Assertion::WebAuthn { .. });
    let (flags, sign_count) = verify_parts(cred, asr, rp_id, &c, a.class.needs_uv() || web)?;
    let (client_data, client_data_hash) = match asr {
        Assertion::Ctap2 { .. } => (None, sha256(&c)),
        Assertion::WebAuthn {
            client_data_json, ..
        } => (Some(client_data_json.clone()), sha256(client_data_json)),
    };
    Ok(TouchEvidence {
        credential_id: b64(&cred.id),
        kind: asr.kind(),
        user_verified: flags & UV != 0,
        sign_count,
        challenge_hex: hex(&c),
        label: cred.label.clone(),
        via: if web { "web" } else { "local" },
        flags,
        auth_data: asr.auth_data().to_vec(),
        client_data,
        client_data_hash,
        signature: asr.signature().to_vec(),
        preimage_hex: hex(&a.preimage()),
        action: a.canonical_action(),
    })
}

#[cfg(test)]
mod tests;
