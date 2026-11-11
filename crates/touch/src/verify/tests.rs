use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::action::{challenge, hex, sha256, TouchClass};
use crate::soft::SoftAuthenticator;
use crate::LOCAL_RP_ID as RP;

const NOW: u64 = 1_800_000_000;
const ORIGIN: &str = "https://app.saiife.com";

fn action(class: TouchClass) -> ActionRecord {
    let mut fields = BTreeMap::new();
    fields.insert("service".to_string(), "erp".to_string());
    fields.insert("body_sha256".to_string(), "0".repeat(64));
    fields.insert("operation".to_string(), "payments.create".to_string());
    ActionRecord {
        instance_id: [0x11; 16],
        request_id: 42,
        class,
        summary: "#42 erp payments.create".to_string(),
        fields,
        nonce: [0x22; 32],
        expires_at: NOW + 300,
    }
}

fn fixture() -> ActionRecord {
    action(TouchClass::Deploy)
}

fn ctap(s: &SoftAuthenticator, a: &ActionRecord) -> Result<TouchEvidence, TouchError> {
    verify(
        &[s.credential(RP, 1000, "key")],
        a,
        &s.assert_ctap(RP, &challenge(a)),
        RP,
        NOW,
    )
}

fn web(s: &SoftAuthenticator, a: &ActionRecord) -> Result<TouchEvidence, TouchError> {
    let asr = s.assert_webauthn(RP, ORIGIN, &challenge(a));
    verify(&[s.web_credential(RP, ORIGIN, 1000)], a, &asr, RP, NOW)
}

/// Rewrites one byte field of an assertion.
fn with(mut asr: Assertion, f: impl FnOnce(&mut Assertion)) -> Assertion {
    f(&mut asr);
    asr
}

fn sig_mut(a: &mut Assertion) -> &mut Vec<u8> {
    match a {
        Assertion::Ctap2 { signature, .. } | Assertion::WebAuthn { signature, .. } => signature,
    }
}

fn ad_mut(a: &mut Assertion) -> &mut Vec<u8> {
    match a {
        Assertion::Ctap2 { auth_data, .. } | Assertion::WebAuthn { auth_data, .. } => auth_data,
    }
}

fn cdj_mut(a: &mut Assertion) -> &mut Vec<u8> {
    match a {
        Assertion::WebAuthn {
            client_data_json, ..
        } => client_data_json,
        Assertion::Ctap2 { .. } => panic!("not a WebAuthn assertion"),
    }
}

fn round_trip(s: SoftAuthenticator) {
    let a = fixture();
    let ev = ctap(&s, &a).unwrap();
    assert_eq!(ev.kind, "fido2");
    assert_eq!(ev.via, "local");
    assert!(ev.user_verified);
    assert_eq!(ev.sign_count, 1);
    assert_eq!(ev.challenge_hex, hex(&challenge(&a)));
    assert_eq!(ev.preimage_hex.len(), 222);
    assert_eq!(ev.client_data, None);
    assert_eq!(ev.client_data_hash, sha256(&challenge(&a)));
    assert_eq!(ev.label, "key");
    assert_eq!(ev.action, a.canonical_action());
    assert_eq!(ev.credential_id, crate::codec::b64(&s.credential_id()));
}

#[test]
fn ctap_round_trip_es256() {
    round_trip(SoftAuthenticator::new_es256());
}

#[test]
fn ctap_round_trip_ed25519() {
    round_trip(SoftAuthenticator::new_ed25519());
}

#[test]
fn webauthn_round_trip() {
    let s = SoftAuthenticator::new_es256();
    let a = fixture();
    let asr = s.assert_webauthn(RP, ORIGIN, &challenge(&a));
    let ev = verify(&[s.web_credential(RP, ORIGIN, 1000)], &a, &asr, RP, NOW).unwrap();
    assert_eq!(ev.kind, "webauthn");
    assert_eq!(ev.via, "web");
    let Assertion::WebAuthn {
        client_data_json, ..
    } = &asr
    else {
        unreachable!()
    };
    assert_eq!(ev.client_data.as_deref(), Some(&client_data_json[..]));
    assert_eq!(ev.client_data_hash, sha256(client_data_json));
    let want = format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"{ORIGIN}\",\"crossOrigin\":false}}",
        crate::codec::b64(&challenge(&a))
    );
    assert_eq!(client_data_json, want.as_bytes());
    assert!(web(&SoftAuthenticator::new_ed25519(), &a).is_ok());
}

#[test]
fn assertion_for_another_action_is_mismatch() {
    let s = SoftAuthenticator::new_es256();
    let a = fixture();
    let creds = [s.credential(RP, 1000, "key")];
    let wcreds = [s.web_credential(RP, ORIGIN, 1000)];
    let mut others = Vec::new();
    let mut b = fixture();
    b.request_id = 43;
    others.push(b);
    let mut b = fixture();
    b.instance_id = [0x12; 16];
    others.push(b);
    let mut b = fixture();
    b.fields
        .insert("operation".into(), "payments.delete".into());
    others.push(b);
    let mut b = fixture();
    b.summary.push('!');
    others.push(b);
    for b in &others {
        let asr = s.assert_ctap(RP, &challenge(&a));
        assert_eq!(verify(&creds, b, &asr, RP, NOW), Err(TouchError::Mismatch));
        let asr = s.assert_webauthn(RP, ORIGIN, &challenge(&a));
        assert_eq!(verify(&wcreds, b, &asr, RP, NOW), Err(TouchError::Mismatch));
    }
}

#[test]
fn wrong_rp_is_mismatch() {
    let a = fixture();
    let mut s = SoftAuthenticator::new_es256();
    s.rp_override = Some("evil.example".into());
    assert_eq!(ctap(&s, &a), Err(TouchError::Mismatch));
    assert_eq!(web(&s, &a), Err(TouchError::Mismatch));
    let s = SoftAuthenticator::new_es256();
    let asr = s.assert_ctap(RP, &challenge(&a));
    let other = s.credential("other", 1000, "key");
    assert_eq!(
        verify(&[other], &a, &asr, RP, NOW),
        Err(TouchError::Mismatch)
    );
}

#[test]
fn unknown_credential() {
    let a = fixture();
    let s = SoftAuthenticator::new_es256();
    let t = SoftAuthenticator::new_es256();
    let asr = t.assert_ctap(RP, &challenge(&a));
    assert_eq!(
        verify(&[s.credential(RP, 1000, "key")], &a, &asr, RP, NOW),
        Err(TouchError::UnknownCredential)
    );
    assert_eq!(
        verify(&[], &a, &asr, RP, NOW),
        Err(TouchError::UnknownCredential)
    );
}

#[test]
fn tampered_signature_and_auth_data() {
    let a = fixture();
    for s in [
        SoftAuthenticator::new_es256(),
        SoftAuthenticator::new_ed25519(),
    ] {
        let creds = [s.credential(RP, 1000, "key")];
        let good = s.assert_ctap(RP, &challenge(&a));
        let bad_sig = with(good.clone(), |x| {
            let sig = sig_mut(x);
            let n = sig.len() - 5;
            sig[n] ^= 0x01;
        });
        assert_eq!(
            verify(&creds, &a, &bad_sig, RP, NOW),
            Err(TouchError::BadSignature)
        );
        let bad_ad = with(good, |x| ad_mut(x)[33] ^= 0x01);
        assert_eq!(
            verify(&creds, &a, &bad_ad, RP, NOW),
            Err(TouchError::BadSignature)
        );
    }
}

#[test]
fn client_hash_not_trusted() {
    let a = fixture();
    let s = SoftAuthenticator::new_es256();
    let asr = s.assert_ctap(RP, &[0x77; 32]);
    let asr = with(asr, |x| {
        if let Assertion::Ctap2 {
            client_data_hash, ..
        } = x
        {
            *client_data_hash = sha256(&challenge(&a));
        }
    });
    assert_eq!(
        verify(&[s.credential(RP, 1000, "key")], &a, &asr, RP, NOW),
        Err(TouchError::BadSignature)
    );
}

#[test]
fn flags_checked() {
    let a = fixture();
    let mut s = SoftAuthenticator::new_es256();
    s.up = false;
    assert_eq!(ctap(&s, &a), Err(TouchError::NotPresent));
    let mut s = SoftAuthenticator::new_es256();
    s.uv = false;
    assert_eq!(ctap(&s, &a), Err(TouchError::NotVerified));
    let ext = action(TouchClass::EgressExternal);
    let ev = ctap(&s, &ext).unwrap();
    assert!(!ev.user_verified);
    assert_eq!(web(&s, &ext), Err(TouchError::NotVerified));
}

#[test]
fn counter_rules() {
    let a = fixture();
    let base = SoftAuthenticator::new_es256();
    let (alg, pkcs8, id, _) = base.parts();
    let run = |stored: u32, saved: u32, step: u32| {
        let mut s = SoftAuthenticator::from_parts(alg, &pkcs8, id.clone(), saved).unwrap();
        s.counter_step = step;
        let mut cred = s.credential(RP, 1000, "key");
        cred.sign_count = stored;
        verify(&[cred], &a, &s.assert_ctap(RP, &challenge(&a)), RP, NOW)
    };
    assert_eq!(run(5, 4, 1), Err(TouchError::Replayed));
    assert_eq!(run(5, 5, 1).unwrap().sign_count, 6);
    assert_eq!(run(0, 0, 0).unwrap().sign_count, 0);
    assert_eq!(run(5, 0, 0), Err(TouchError::Replayed));
}

#[test]
fn expired() {
    let a = fixture();
    let s = SoftAuthenticator::new_es256();
    let creds = [s.credential(RP, 1000, "key")];
    let asr = s.assert_ctap(RP, &challenge(&a));
    assert_eq!(
        verify(&creds, &a, &asr, RP, a.expires_at + 1),
        Err(TouchError::Expired)
    );
    assert!(verify(&creds, &a, &asr, RP, a.expires_at).is_ok());
}

#[test]
fn webauthn_client_data_rules() {
    let a = fixture();
    let c = challenge(&a);
    let mut s = SoftAuthenticator::new_es256();
    let creds = [s.web_credential(RP, ORIGIN, 1000)];
    s.type_override = Some("webauthn.create".into());
    let asr = s.assert_webauthn(RP, ORIGIN, &c);
    assert_eq!(
        verify(&creds, &a, &asr, RP, NOW),
        Err(TouchError::Malformed)
    );
    s.type_override = None;

    let asr = s.assert_webauthn(RP, "https://evil.example", &c);
    assert_eq!(verify(&creds, &a, &asr, RP, NOW), Err(TouchError::Mismatch));

    let asr = with(s.assert_webauthn(RP, ORIGIN, &c), |x| {
        if let Assertion::WebAuthn { origin, .. } = x {
            *origin = "https://other.saiife.com".into();
        }
    });
    assert_eq!(verify(&creds, &a, &asr, RP, NOW), Err(TouchError::Mismatch));

    let asr = with(s.assert_webauthn(RP, ORIGIN, &c), |x| {
        let j = cdj_mut(x);
        let t = String::from_utf8(j.clone()).unwrap();
        *j = t
            .replace("\"crossOrigin\":false", "\"crossOrigin\":true")
            .into_bytes();
    });
    assert_eq!(verify(&creds, &a, &asr, RP, NOW), Err(TouchError::Mismatch));

    let asr = with(s.assert_webauthn(RP, ORIGIN, &c), |x| {
        *cdj_mut(x) = b"not json".to_vec()
    });
    assert_eq!(
        verify(&creds, &a, &asr, RP, NOW),
        Err(TouchError::Malformed)
    );
    let asr = with(s.assert_webauthn(RP, ORIGIN, &c), |x| {
        *cdj_mut(x) = b"[1]".to_vec()
    });
    assert_eq!(
        verify(&creds, &a, &asr, RP, NOW),
        Err(TouchError::Malformed)
    );
}

#[test]
fn oversized_fields_are_malformed() {
    let a = fixture();
    let s = SoftAuthenticator::new_es256();
    let creds = [s.web_credential(RP, ORIGIN, 1000)];
    let good = s.assert_webauthn(RP, ORIGIN, &challenge(&a));
    let cases = [
        with(good.clone(), |x| *cdj_mut(x) = vec![b' '; 70_000]),
        with(good.clone(), |x| ad_mut(x).resize(1025, 0)),
        with(good.clone(), |x| sig_mut(x).resize(257, 0)),
        with(good, |x| {
            if let Assertion::WebAuthn { credential_id, .. } = x {
                *credential_id = vec![1; 1024];
            }
        }),
    ];
    for asr in cases {
        assert_eq!(
            verify(&creds, &a, &asr, RP, NOW),
            Err(TouchError::Malformed)
        );
    }
}

#[test]
fn assertion_json_shape() {
    let a = fixture();
    let s = SoftAuthenticator::new_es256();
    let asr = s.assert_ctap(RP, &challenge(&a));
    let v = serde_json::to_value(&asr).unwrap();
    let keys: BTreeSet<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "kind",
            "credential_id",
            "auth_data",
            "signature",
            "client_data_hash"
        ])
    );
    assert_eq!(v["kind"], "fido2");
    assert_eq!(v["credential_id"], crate::codec::b64(&s.credential_id()));
    assert_eq!(v["client_data_hash"], hex(&sha256(&challenge(&a))));
    assert_eq!(serde_json::from_value::<Assertion>(v.clone()).unwrap(), asr);
    let mut extra = v;
    extra["bogus"] = 1.into();
    assert!(serde_json::from_value::<Assertion>(extra).is_err());

    let w = s.assert_webauthn(RP, ORIGIN, &challenge(&a));
    let v = serde_json::to_value(&w).unwrap();
    assert_eq!(v["kind"], "webauthn");
    assert_eq!(v["origin"], ORIGIN);
    assert_eq!(serde_json::from_value::<Assertion>(v).unwrap(), w);
}

#[test]
fn to_audit_keys() {
    let a = fixture();
    let s = SoftAuthenticator::new_es256();
    let keys = |v: serde_json::Value| -> BTreeSet<String> {
        v.as_object().unwrap().keys().cloned().collect()
    };
    let want = [
        "via",
        "kind",
        "cred_id",
        "label",
        "flags",
        "uv",
        "sign_count",
        "auth_data",
        "client_data_hash",
        "signature",
        "challenge",
        "preimage",
        "action",
    ];
    let ev = ctap(&s, &a).unwrap();
    let v = ev.to_audit();
    assert_eq!(
        keys(v.clone()),
        want.iter().map(|k| k.to_string()).collect()
    );
    assert_eq!(v["via"], "local");
    assert_eq!(v["kind"], "fido2");
    assert_eq!(v["cred_id"], ev.credential_id);
    assert_eq!(v["flags"], 0x05);
    assert_eq!(v["uv"], true);
    assert_eq!(v["sign_count"], 1);
    assert_eq!(v["auth_data"], crate::codec::b64(&ev.auth_data));
    assert_eq!(v["client_data_hash"], hex(&ev.client_data_hash));
    assert_eq!(v["signature"], crate::codec::b64(&ev.signature));
    assert_eq!(v["challenge"], ev.challenge_hex);
    assert_eq!(v["preimage"], hex(&a.preimage()));
    assert_eq!(v["action"], a.canonical_action());

    let ev = web(&s, &a).unwrap();
    let v = ev.to_audit();
    let mut want_web: BTreeSet<String> = want.iter().map(|k| k.to_string()).collect();
    want_web.insert("client_data".into());
    assert_eq!(keys(v.clone()), want_web);
    assert_eq!(
        v["client_data"],
        crate::codec::b64(ev.client_data.as_deref().unwrap())
    );
}

#[test]
fn soft_parts_round_trip() {
    let a = fixture();
    for s in [
        SoftAuthenticator::new_es256(),
        SoftAuthenticator::new_ed25519(),
    ] {
        let cred = s.credential(RP, 1000, "key");
        s.assert_ctap(RP, &[0; 32]);
        s.assert_ctap(RP, &[0; 32]);
        let (alg, pkcs8, id, count) = s.parts();
        assert_eq!(count, 2);
        let t = SoftAuthenticator::from_parts(alg, &pkcs8, id, count).unwrap();
        assert_eq!(t.public_key(), s.public_key());
        let ev = verify(&[cred], &a, &t.assert_ctap(RP, &challenge(&a)), RP, NOW).unwrap();
        assert_eq!(ev.sign_count, 3);
    }
    assert_eq!(
        SoftAuthenticator::from_parts(crate::CoseAlg::Es256, b"junk", vec![1], 0).err(),
        Some(TouchError::Malformed)
    );
}

#[test]
fn verify_parts_with_a_raw_challenge() {
    let s = SoftAuthenticator::new_es256();
    let cred = s.credential(RP, 1000, "key");
    let c = [0x42; 32];
    let asr = s.assert_ctap(RP, &c);
    assert_eq!(verify_parts(&cred, &asr, RP, &c, true), Ok((0x05, 1)));
    assert_eq!(
        verify_parts(&cred, &asr, RP, &[0x43; 32], true),
        Err(TouchError::Mismatch)
    );
    let other = SoftAuthenticator::new_es256().credential(RP, 1000, "key");
    assert_eq!(
        verify_parts(&other, &asr, RP, &c, true),
        Err(TouchError::UnknownCredential)
    );
}

#[test]
fn credential_kind_binds_assertion_kind() {
    let a = fixture();
    let c = challenge(&a);
    let s = SoftAuthenticator::new_es256();
    // (a) a webauthn credential cannot be used through a Ctap2 assertion.
    let asr = s.assert_ctap(RP, &c);
    assert_eq!(
        verify(&[s.web_credential(RP, ORIGIN, 1000)], &a, &asr, RP, NOW),
        Err(TouchError::Mismatch)
    );
    // (b) a fido2 credential cannot be used through a WebAuthn assertion, even
    // with its origin listed: only the kind check fails.
    let mut cred = s.credential(RP, 1000, "key");
    cred.origins = vec![ORIGIN.into()];
    let asr = s.assert_webauthn(RP, ORIGIN, &c);
    assert_eq!(
        verify(&[cred.clone()], &a, &asr, RP, NOW),
        Err(TouchError::Mismatch)
    );
    cred.kind = "webauthn".into();
    assert!(verify(&[cred.clone()], &a, &asr, RP, NOW).is_ok());
    // An unknown kind fails closed for both assertion kinds.
    cred.kind = "u2f".into();
    assert_eq!(
        verify(&[cred.clone()], &a, &asr, RP, NOW),
        Err(TouchError::Mismatch)
    );
    let asr = s.assert_ctap(RP, &c);
    assert_eq!(
        verify(&[cred], &a, &asr, RP, NOW),
        Err(TouchError::Mismatch)
    );
}

#[test]
fn uv_rule_follows_kind() {
    // (c) class EgressExternal does not need UV itself.
    let a = action(TouchClass::EgressExternal);
    let mut s = SoftAuthenticator::new_es256();
    s.uv = false;
    let asr = s.assert_webauthn(RP, ORIGIN, &challenge(&a));
    assert_eq!(
        verify(&[s.web_credential(RP, ORIGIN, 1000)], &a, &asr, RP, NOW),
        Err(TouchError::NotVerified)
    );
    assert!(ctap(&s, &a).is_ok());
}

#[test]
fn verify_parts_kind_mismatch() {
    // (d)
    let s = SoftAuthenticator::new_ed25519();
    let c = [0x42; 32];
    let web_cred = s.web_credential(RP, ORIGIN, 1000);
    let asr = s.assert_ctap(RP, &c);
    assert_eq!(
        verify_parts(&web_cred, &asr, RP, &c, false),
        Err(TouchError::Mismatch)
    );
    let asr = s.assert_webauthn(RP, ORIGIN, &c);
    let mut cred = s.credential(RP, 1000, "key");
    cred.origins = vec![ORIGIN.into()];
    assert_eq!(
        verify_parts(&cred, &asr, RP, &c, false),
        Err(TouchError::Mismatch)
    );
    assert_eq!(verify_parts(&web_cred, &asr, RP, &c, false), Ok((0x05, 2)));
}

#[test]
fn reverify_from_audit() {
    let a = fixture();
    for (s, web_kind) in [
        (SoftAuthenticator::new_es256(), false),
        (SoftAuthenticator::new_ed25519(), false),
        (SoftAuthenticator::new_es256(), true),
    ] {
        let ev = if web_kind { web(&s, &a) } else { ctap(&s, &a) }.unwrap();
        let audit = ev.to_audit();
        assert_eq!(reverify(&audit, &s.public_key()), Ok(()));
        let flip = |k: &str| {
            let mut v = audit.clone();
            let t = v[k].as_str().unwrap().to_string();
            let mut b = t.into_bytes();
            let i = b.len() / 2;
            b[i] = if b[i] == b'A' { b'B' } else { b'A' };
            v[k] = String::from_utf8(b).unwrap().into();
            v
        };
        for k in ["action", "preimage", "signature", "auth_data"] {
            assert!(reverify(&flip(k), &s.public_key()).is_err(), "{k}");
        }
        let other = SoftAuthenticator::new_es256().public_key();
        assert_eq!(reverify(&audit, &other), Err(TouchError::BadSignature));
        let mut missing = audit.clone();
        missing.as_object_mut().unwrap().remove("challenge");
        assert_eq!(
            reverify(&missing, &s.public_key()),
            Err(TouchError::Malformed)
        );
        let mut wrong = audit.clone();
        wrong["kind"] = "nope".into();
        assert_eq!(
            reverify(&wrong, &s.public_key()),
            Err(TouchError::Malformed)
        );
        assert_eq!(
            reverify(&serde_json::json!([]), &s.public_key()),
            Err(TouchError::Malformed)
        );
    }
}
