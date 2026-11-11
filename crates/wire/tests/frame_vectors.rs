//! The frozen vectors (frame, pair, machine hello). Plan 30's `node --test` checks the same files.

use saiife_wire::b64;
use saiife_wire::frame::parse_body;
use saiife_wire::sig::{device_id_of, machine_id_of, verify_p256};

fn s(v: &serde_json::Value, k: &str) -> String {
    v[k].as_str().unwrap().to_string()
}

#[test]
fn frozen_vector_verifies() {
    let v: serde_json::Value = serde_json::from_str(include_str!("vectors/frame-v1.json")).unwrap();
    let pk = b64::dec_n::<65>(&s(&v, "public_raw_b64u")).unwrap();
    let body = s(&v, "body");
    let sig = b64::dec_n::<64>(&s(&v, "sig_b64u")).unwrap();
    let bad = b64::dec_n::<64>(&s(&v, "bad_sig_b64u")).unwrap();
    assert!(verify_p256(&pk, body.as_bytes(), &sig));
    assert!(!verify_p256(&pk, body.as_bytes(), &bad));
    let f = parse_body(body.as_bytes()).unwrap();
    assert_eq!(f.device_id, s(&v, "device_id"));
    assert_eq!(device_id_of(&pk), s(&v, "device_id"));
    assert_eq!(machine_id_of(&pk), s(&v, "machine_id"));
}

#[test]
fn frozen_pair_vector() {
    use saiife_wire::pair::{proof, short_code};
    let v: serde_json::Value = serde_json::from_str(include_str!("vectors/pair-v1.json")).unwrap();
    let secret = b64::dec_n::<32>(&s(&v, "secret_b64u")).unwrap();
    assert_eq!(secret, std::array::from_fn::<u8, 32, _>(|i| i as u8));
    let m = b64::dec_n::<65>(&s(&v, "machine_pub_b64u")).unwrap();
    let d = b64::dec_n::<65>(&s(&v, "device_pub_b64u")).unwrap();
    let id = s(&v, "pair_id");
    assert_eq!(b64::enc(&proof(&secret, &id, &d)), s(&v, "proof_b64u"));
    assert_eq!(short_code(&m, &d, &secret), s(&v, "short_code"));
}

/// The frozen machine-hello vector (plan 29): the bytes the machine key
/// signs for a seal handshake (both bindings) and for the hub hello. The
/// stored signatures were made once by a throwaway key; ECDSA signatures are
/// randomized, so they are verified, never regenerated and compared.
#[test]
fn frozen_machine_hello_vector() {
    use saiife_wire::seal::{
        hub_hello_msg, machine_hello_msg, SealBinding, HUB_HELLO_DOMAIN, MACHINE_HELLO_DOMAIN,
    };
    use saiife_wire::sig::verify_p256_domain;
    let v: serde_json::Value =
        serde_json::from_str(include_str!("vectors/machine-hello-v1.json")).unwrap();
    assert_eq!(
        s(&v, "machine_hello_domain").as_bytes(),
        MACHINE_HELLO_DOMAIN
    );
    assert_eq!(s(&v, "hub_hello_domain").as_bytes(), HUB_HELLO_DOMAIN);
    let pk = b64::dec_n::<65>(&s(&v, "machine_pub_b64u")).unwrap();
    assert_eq!(machine_id_of(&pk), s(&v, "machine_id"));
    let sid = b64::dec_n::<16>(&s(&v, "session_id_b64u")).unwrap();
    let eph = b64::dec_n::<65>(&s(&v, "machine_eph_b64u")).unwrap();
    let sig = |k: &str| b64::dec_n::<64>(&s(&v, k)).unwrap();
    for (b, hex_key, sig_key) in [
        (
            SealBinding::Device(s(&v, "device_id")),
            "machine_hello_device_hex",
            "machine_hello_device_sig_b64u",
        ),
        (
            SealBinding::Pair(s(&v, "pair_id")),
            "machine_hello_pair_hex",
            "machine_hello_pair_sig_b64u",
        ),
    ] {
        let msg = machine_hello_msg(&sid, &eph, &b);
        assert_eq!(b64::hex(&msg), s(&v, hex_key), "{b:?}");
        assert!(verify_p256_domain(
            &pk,
            MACHINE_HELLO_DOMAIN,
            &msg,
            &sig(sig_key)
        ));
        assert!(!verify_p256_domain(
            &pk,
            HUB_HELLO_DOMAIN,
            &msg,
            &sig(sig_key)
        ));
    }
    // A device signature does not open a pairing session, nor the reverse.
    let pair_msg = machine_hello_msg(&sid, &eph, &SealBinding::Pair(s(&v, "pair_id")));
    assert!(!verify_p256_domain(
        &pk,
        MACHINE_HELLO_DOMAIN,
        &pair_msg,
        &sig("machine_hello_device_sig_b64u")
    ));
    let nonce = b64::dec(&s(&v, "hub_nonce_b64u")).unwrap();
    let hh = hub_hello_msg(&nonce, &s(&v, "machine_id"));
    assert_eq!(b64::hex(&hh), s(&v, "hub_hello_hex"));
    assert!(verify_p256_domain(
        &pk,
        HUB_HELLO_DOMAIN,
        &hh,
        &sig("hub_hello_sig_b64u")
    ));
    assert!(!verify_p256_domain(
        &pk,
        MACHINE_HELLO_DOMAIN,
        &hh,
        &sig("hub_hello_sig_b64u")
    ));
}
