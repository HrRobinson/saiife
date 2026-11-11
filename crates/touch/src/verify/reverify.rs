//! Offline re-verification of an audit `touch` object (R3).

use serde_json::Value;

use super::check_signature;
use crate::action::sha256;
use crate::codec::{b64, unb64, unhex};
use crate::cose::CoseKey;
use crate::TouchError;

fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str, TouchError> {
    v.get(k)
        .and_then(Value::as_str)
        .ok_or(TouchError::Malformed)
}

fn bytes(v: &Value, k: &str) -> Result<Vec<u8>, TouchError> {
    unb64(text(v, k)?).ok_or(TouchError::Malformed)
}

fn hex32(v: &Value, k: &str) -> Result<[u8; 32], TouchError> {
    unhex::<32>(text(v, k)?).ok_or(TouchError::Malformed)
}

/// Re-checks the `touch` object of an audit record against the `public_key`
/// of its credential's `touch_enrolled` record, with no state: what an
/// auditor runs. The encodings are those of `TouchEvidence::to_audit`
/// (bytes base64url, hashes hex, `action` the canonical JSON).
///
/// A missing key, a wrong type or a bad encoding is `Malformed`. Then:
/// `challenge != sha256(preimage)`, a preimage whose last 32 bytes are not
/// `sha256(action)`, a `client_data_hash` that is not `sha256(challenge)`
/// (fido2) or `sha256(client_data)` (webauthn), or a webauthn
/// `client_data.challenge` that is not `base64url(challenge)` are each
/// `Mismatch`; a signature over `auth_data ‖ client_data_hash` that does not
/// verify is `BadSignature`.
pub fn reverify(touch: &Value, key: &CoseKey) -> Result<(), TouchError> {
    let web = match text(touch, "kind")? {
        "fido2" => false,
        "webauthn" => true,
        _ => return Err(TouchError::Malformed),
    };
    let auth_data = bytes(touch, "auth_data")?;
    let signature = bytes(touch, "signature")?;
    let client_data = if web {
        Some(bytes(touch, "client_data")?)
    } else {
        None
    };
    bytes(touch, "cred_id")?;
    let chash = hex32(touch, "client_data_hash")?;
    let challenge = hex32(touch, "challenge")?;
    let preimage = unhex_vec(text(touch, "preimage")?)?;
    let action = text(touch, "action")?;

    if sha256(&preimage) != challenge {
        return Err(TouchError::Mismatch);
    }
    let tail = preimage
        .len()
        .checked_sub(32)
        .ok_or(TouchError::Malformed)?;
    if preimage[tail..] != sha256(action.as_bytes()) {
        return Err(TouchError::Mismatch);
    }
    match &client_data {
        None => {
            if chash != sha256(&challenge) {
                return Err(TouchError::Mismatch);
            }
        }
        Some(cd) => {
            if chash != sha256(cd) {
                return Err(TouchError::Mismatch);
            }
            let v: Value = serde_json::from_slice(cd).map_err(|_| TouchError::Malformed)?;
            if v.get("challenge").and_then(Value::as_str) != Some(b64(&challenge).as_str()) {
                return Err(TouchError::Mismatch);
            }
        }
    }
    if !check_signature(key, &auth_data, &chash, &signature) {
        return Err(TouchError::BadSignature);
    }
    Ok(())
}

/// Hex of any even length.
fn unhex_vec(s: &str) -> Result<Vec<u8>, TouchError> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return Err(TouchError::Malformed);
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| TouchError::Malformed))
        .collect()
}
