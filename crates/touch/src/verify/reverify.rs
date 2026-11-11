//! Offline re-verification of an audit `touch` object (R3, R6).

use serde_json::Value;

use super::{verify_parts, Assertion};
use crate::action::{sha256, TouchClass};
use crate::authdata::UV;
use crate::codec::{unb64, unhex, unhex_vec};
use crate::cose::CoseKey;
use crate::store::Credential;
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

fn number(v: &Value, k: &str) -> Result<u64, TouchError> {
    v.get(k)
        .and_then(Value::as_u64)
        .ok_or(TouchError::Malformed)
}

/// Re-checks the `touch` object of an audit record, with no state: what an
/// auditor runs. `key`, `rp_id` and `origins` come from the credential's
/// `touch_enrolled` record (for a `fido2` credential `origins` may be empty).
/// The encodings are those of `TouchEvidence::to_audit` (bytes base64url,
/// hashes hex, `action` the canonical JSON).
///
/// A missing key, a wrong type, a bad encoding, an unknown `kind` or a
/// WebAuthn record without a usable `client_data` is `Malformed`. Then:
/// - `challenge != sha256(preimage)`, or a preimage whose last 32 bytes are
///   not `sha256(action)`, is `Mismatch`;
/// - the rest is the verifier's own core ([`verify_parts`]) on a transient
///   credential, so both paths share every check: caps, authData parse, the
///   kind binding, rp id hash, UP, UV (needed for the action's class, for
///   webauthn, or when the record says `uv`), the clientDataJSON type,
///   origin (in `origins`) and `crossOrigin`, the client data hash rules and
///   the signature (`BadSignature`). The sign counter is not compared with
///   an earlier one (no history);
/// - for webauthn, a recorded `client_data_hash != sha256(client_data)` is
///   `Mismatch`;
/// - finally the recorded `flags`, `uv` and `sign_count` must equal what the
///   signed authData says, else `Mismatch`.
pub fn reverify(
    touch: &Value,
    key: &CoseKey,
    rp_id: &str,
    origins: &[String],
) -> Result<(), TouchError> {
    let kind = text(touch, "kind")?;
    let web = match kind {
        "fido2" => false,
        "webauthn" => true,
        _ => return Err(TouchError::Malformed),
    };
    let auth_data = bytes(touch, "auth_data")?;
    let signature = bytes(touch, "signature")?;
    let cred_id = bytes(touch, "cred_id")?;
    let chash = hex32(touch, "client_data_hash")?;
    let challenge = hex32(touch, "challenge")?;
    let preimage = unhex_vec(text(touch, "preimage")?).ok_or(TouchError::Malformed)?;
    let action = text(touch, "action")?;
    let (flags, uv, count) = (
        number(touch, "flags")?,
        touch
            .get("uv")
            .and_then(Value::as_bool)
            .ok_or(TouchError::Malformed)?,
        number(touch, "sign_count")?,
    );

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

    let asr = if web {
        let client_data_json = bytes(touch, "client_data")?;
        let cd: Value =
            serde_json::from_slice(&client_data_json).map_err(|_| TouchError::Malformed)?;
        let origin = text(&cd, "origin")?.to_string();
        if chash != sha256(&client_data_json) {
            return Err(TouchError::Mismatch);
        }
        Assertion::WebAuthn {
            credential_id: cred_id.clone(),
            auth_data,
            signature,
            client_data_json,
            origin,
        }
    } else {
        Assertion::Ctap2 {
            credential_id: cred_id.clone(),
            auth_data,
            signature,
            client_data_hash: chash,
        }
    };

    let cred = Credential {
        id: cred_id,
        public_key: key.clone(),
        kind: kind.to_string(),
        rp_id: rp_id.to_string(),
        origins: origins.to_vec(),
        label: String::new(),
        owner_uid: 0,
        owner_sid: None,
        sign_count: 0,
        created: String::new(),
        aaguid: String::new(),
    };
    // A missing or unknown class needs UV, as does webauthn or a recorded uv.
    let class_uv = serde_json::from_str::<Value>(action)
        .ok()
        .and_then(|a| {
            a.get("class")
                .and_then(Value::as_str)
                .and_then(TouchClass::from_name)
        })
        .is_none_or(|c| c.needs_uv());
    let need_uv = class_uv || web || uv;
    let (real_flags, real_count) = verify_parts(&cred, &asr, rp_id, &challenge, need_uv)?;
    if flags != u64::from(real_flags)
        || uv != (real_flags & UV != 0)
        || count != u64::from(real_count)
    {
        return Err(TouchError::Mismatch);
    }
    Ok(())
}
