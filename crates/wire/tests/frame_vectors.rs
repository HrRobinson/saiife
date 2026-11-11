//! The frozen frame vector. Plan 30's `node --test` checks the same file.

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
