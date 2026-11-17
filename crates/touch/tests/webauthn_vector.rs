//! The published W3C WebAuthn Level 3 test vector (§16.2, ES256, no
//! attestation) through `verify_parts`. Its assertion has UV unset (flags
//! 0x19: UP, BE, BS), so the test passes `need_uv = false`.

use saiife_touch::authdata;
use saiife_touch::{verify_parts, Assertion, Credential, TouchError};

const VECTOR: &str = include_str!("vectors/webauthn-l3-es256.json");

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

struct Vector {
    cred: Credential,
    asr: Assertion,
    rp_id: String,
    challenge: Vec<u8>,
}

fn load() -> Vector {
    let v: serde_json::Value = serde_json::from_str(VECTOR).unwrap();
    let field = |k: &str| v[k].as_str().unwrap().to_string();
    let reg = unhex(&field("registration_auth_data"));
    let att = authdata::parse(&reg).unwrap().attested.unwrap();
    assert_eq!(att.credential_id, unhex(&field("credential_id")));
    let cred = Credential {
        id: att.credential_id.clone(),
        public_key: att.public_key,
        kind: "webauthn".into(),
        rp_id: field("rp_id"),
        origins: vec![field("origin")],
        label: "w3c".into(),
        owner_uid: 1000,
        owner_sid: None,
        sign_count: 0,
        created: "2026-01-01T00:00:00.000Z".into(),
        aaguid: "8446ccb9ab1db374750b2367ff6f3a1f".into(),
    };
    let asr = Assertion::WebAuthn {
        credential_id: att.credential_id,
        auth_data: unhex(&field("authenticator_data")),
        signature: unhex(&field("signature")),
        client_data_json: unhex(&field("client_data_json")),
        origin: field("origin"),
    };
    Vector {
        cred,
        asr,
        rp_id: field("rp_id"),
        challenge: unhex(&field("challenge")),
    }
}

#[test]
fn l3_es256_assertion_verifies() {
    let v = load();
    assert_eq!(
        verify_parts(&v.cred, &v.asr, &v.rp_id, &v.challenge, false),
        Ok((0x19, 0))
    );
    // UV is unset in the vector: a caller that needs UV refuses it (D4).
    assert_eq!(
        saiife_touch::verify::verify_parts(&v.cred, &v.asr, &v.rp_id, &v.challenge, true),
        Err(TouchError::NotVerified)
    );
}

#[test]
fn l3_vector_flipped_bit_fails() {
    let v = load();
    let flip = |f: &dyn Fn(&mut Assertion)| {
        let mut a = v.asr.clone();
        f(&mut a);
        verify_parts(&v.cred, &a, &v.rp_id, &v.challenge, false)
    };
    // The signature's last byte (inside s).
    assert_eq!(
        flip(&|a| if let Assertion::WebAuthn { signature, .. } = a {
            let n = signature.len() - 1;
            signature[n] ^= 0x01;
        }),
        Err(TouchError::BadSignature)
    );
    // The counter byte of authData.
    assert_eq!(
        flip(&|a| if let Assertion::WebAuthn { auth_data, .. } = a {
            auth_data[36] ^= 0x01;
        }),
        Err(TouchError::BadSignature)
    );
    // The expected challenge.
    let mut c = v.challenge.clone();
    c[0] ^= 0x01;
    assert_eq!(
        verify_parts(&v.cred, &v.asr, &v.rp_id, &c, false),
        Err(TouchError::Mismatch)
    );
}

#[test]
fn l3_vector_with_fido2_kind_is_mismatch() {
    let mut v = load();
    v.cred.kind = "fido2".into();
    assert_eq!(
        verify_parts(&v.cred, &v.asr, &v.rp_id, &v.challenge, false),
        Err(TouchError::Mismatch)
    );
}
