//! Offline re-verification of an audit `touch` object (R3, R6).

use serde_json::Value;

use super::{verify_parts, Assertion};
use crate::action::{sha256, TouchClass};
use crate::authdata::UV;
use crate::codec::{unb64, unhex, unhex_vec};
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

/// Re-checks the `touch` object of an audit record against `enrolled`, with
/// no state: what an auditor runs.
///
/// `enrolled` is the trust anchor and must come from a trusted source (the
/// `touch_enrolled` record, or the credential store). It alone supplies the
/// credential id, kind, public key, rp id and origins. From the record only
/// the assertion bytes (`auth_data`, `signature`, `client_data` or
/// `client_data_hash`), `challenge`, `preimage` and `action` are read as
/// data; `cred_id`, `kind`, `flags`, `uv` and `sign_count` are claims that
/// are compared, never used as inputs. The encodings are those of
/// `TouchEvidence::to_audit` (bytes base64url, hashes hex).
///
/// A missing key, a wrong type or a bad encoding is `Malformed`. Then:
/// - a `cred_id` other than `enrolled.id` is `UnknownCredential`, and a
///   `kind` other than `enrolled.kind` is `Mismatch` (both before any
///   signature work);
/// - `challenge != sha256(preimage)`, or a preimage whose last 32 bytes are
///   not `sha256(action)`, is `Mismatch`;
/// - the rest is [`verify_parts`] on a copy of `enrolled` with the counter at
///   0, so both paths share every check (caps, authData parse, kind binding,
///   rp id hash, UP, UV, clientDataJSON type, origin in `enrolled.origins`,
///   `crossOrigin`, client data hash rules, `BadSignature`). The assertion
///   variant follows `enrolled.kind`. UV is needed as in `verify`: for the
///   action's class (missing or unknown means yes), for WebAuthn, or for a
///   `webauthn` credential;
/// - for webauthn, a recorded `client_data_hash != sha256(client_data)` is
///   `Mismatch`;
/// - the recorded `flags`, `uv` and `sign_count` must equal the signed
///   authData's, else `Mismatch`.
///
/// This checks one record, not counter progression across records.
pub fn reverify(touch: &Value, enrolled: &Credential) -> Result<(), TouchError> {
    let kind = text(touch, "kind")?;
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

    if cred_id != enrolled.id {
        return Err(TouchError::UnknownCredential);
    }
    if kind != enrolled.kind {
        return Err(TouchError::Mismatch);
    }
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

    let asr = match enrolled.kind.as_str() {
        "webauthn" => {
            let client_data_json = bytes(touch, "client_data")?;
            let cd: Value =
                serde_json::from_slice(&client_data_json).map_err(|_| TouchError::Malformed)?;
            let origin = text(&cd, "origin")?.to_string();
            if chash != sha256(&client_data_json) {
                return Err(TouchError::Mismatch);
            }
            Assertion::WebAuthn {
                credential_id: cred_id,
                auth_data,
                signature,
                client_data_json,
                origin,
            }
        }
        "fido2" => Assertion::Ctap2 {
            credential_id: cred_id,
            auth_data,
            signature,
            client_data_hash: chash,
        },
        _ => return Err(TouchError::Mismatch),
    };

    let cred = Credential {
        sign_count: 0,
        ..enrolled.clone()
    };
    // As in `verify`: a missing or unknown class needs UV, as does WebAuthn.
    let class_uv = serde_json::from_str::<Value>(action)
        .ok()
        .and_then(|a| {
            a.get("class")
                .and_then(Value::as_str)
                .and_then(TouchClass::from_name)
        })
        .is_none_or(|c| c.needs_uv());
    let need_uv = class_uv || matches!(asr, Assertion::WebAuthn { .. }) || cred.kind == "webauthn";
    let (real_flags, real_count) = verify_parts(&cred, &asr, &cred.rp_id, &challenge, need_uv)?;
    if flags != u64::from(real_flags)
        || uv != (real_flags & UV != 0)
        || count != u64::from(real_count)
    {
        return Err(TouchError::Mismatch);
    }
    Ok(())
}
