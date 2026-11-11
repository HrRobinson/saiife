//! P-256 signatures over frames, and the ids derived from public keys.

use crate::{b64, WireError};
use ring::rand::SecureRandom;
use ring::signature::{
    EcdsaKeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_FIXED,
    ECDSA_P256_SHA256_FIXED_SIGNING,
};
use sha2::{Digest, Sha256};

/// The signed message of a frame is `SIG_DOMAIN || body bytes`.
pub const SIG_DOMAIN: &[u8] = b"saiife-wire-v1\n";

/// Verifies a raw (r || s) P-256 signature over `domain || msg`.
pub fn verify_p256_domain(
    public_raw: &[u8; 65],
    domain: &[u8],
    msg: &[u8],
    sig_raw: &[u8; 64],
) -> bool {
    let mut m = Vec::with_capacity(domain.len() + msg.len());
    m.extend_from_slice(domain);
    m.extend_from_slice(msg);
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_raw.as_slice())
        .verify(&m, sig_raw)
        .is_ok()
}

/// Verifies a frame body signature (domain `SIG_DOMAIN`).
pub fn verify_p256(public_raw: &[u8; 65], body: &[u8], sig_raw: &[u8; 64]) -> bool {
    verify_p256_domain(public_raw, SIG_DOMAIN, body, sig_raw)
}

pub struct MachineKey {
    pair: EcdsaKeyPair,
}

impl MachineKey {
    /// A fresh key and its PKCS#8 encoding.
    pub fn generate(rng: &dyn SecureRandom) -> Result<(MachineKey, Vec<u8>), WireError> {
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, rng)
            .map_err(|_| WireError::Store("key generation failed".into()))?;
        let pkcs8 = doc.as_ref().to_vec();
        let key = MachineKey::from_pkcs8(&pkcs8, rng)?;
        Ok((key, pkcs8))
    }

    pub fn from_pkcs8(pkcs8: &[u8], rng: &dyn SecureRandom) -> Result<MachineKey, WireError> {
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8, rng)
            .map(|pair| MachineKey { pair })
            .map_err(|_| WireError::Store("invalid P-256 key".into()))
    }

    pub fn public_raw(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out.copy_from_slice(self.pair.public_key().as_ref());
        out
    }

    pub fn machine_id(&self) -> String {
        machine_id_of(&self.public_raw())
    }

    /// Signs `domain || msg`.
    pub fn sign(&self, domain: &[u8], msg: &[u8], rng: &dyn SecureRandom) -> [u8; 64] {
        let mut m = Vec::with_capacity(domain.len() + msg.len());
        m.extend_from_slice(domain);
        m.extend_from_slice(msg);
        let sig = self
            .pair
            .sign(rng, &m)
            .expect("P-256 signing cannot fail for a valid key");
        let mut out = [0u8; 64];
        out.copy_from_slice(sig.as_ref());
        out
    }
}

/// First 32 hex chars of SHA-256(machine public key).
pub fn machine_id_of(public_raw: &[u8; 65]) -> String {
    b64::hex(&Sha256::digest(public_raw)[..16])
}

/// `"d-"` plus the first 16 hex chars of SHA-256(device public key).
pub fn device_id_of(public_raw: &[u8; 65]) -> String {
    format!("d-{}", b64::hex(&Sha256::digest(public_raw)[..8]))
}

/// A browser stand-in for tests and fakes.
#[cfg(any(test, feature = "fake"))]
pub struct TestDevice {
    key: MachineKey,
    rng: ring::rand::SystemRandom,
}

#[cfg(any(test, feature = "fake"))]
impl TestDevice {
    pub fn generate() -> TestDevice {
        let rng = ring::rand::SystemRandom::new();
        let (key, _) = MachineKey::generate(&rng).expect("test key generation");
        TestDevice { key, rng }
    }

    pub fn public_raw(&self) -> [u8; 65] {
        self.key.public_raw()
    }

    pub fn device_id(&self) -> String {
        device_id_of(&self.public_raw())
    }

    /// b64u of the 64-byte signature over `SIG_DOMAIN || body`.
    pub fn sign_body(&self, body: &str) -> String {
        b64::enc(&self.key.sign(SIG_DOMAIN, body.as_bytes(), &self.rng))
    }

    /// body = `serde_json::to_string(f)`.
    pub fn frame(&self, f: &crate::frame::Frame) -> crate::frame::SignedFrame {
        let body = serde_json::to_string(f).expect("frame serializes");
        let sig = self.sign_body(&body);
        crate::frame::SignedFrame {
            body,
            sig,
            touch: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::Frame;

    fn frame() -> Frame {
        Frame {
            v: 1,
            machine_id: "m".into(),
            epoch: "e".into(),
            device_id: "d".into(),
            action: "box.list".into(),
            args: serde_json::Map::new(),
            nonce: crate::b64::enc(&[2u8; 16]),
            issued_at: 10,
            expires_at: 20,
        }
    }

    #[test]
    fn signature_roundtrip() {
        let d = TestDevice::generate();
        let sf = d.frame(&frame());
        let sig = crate::b64::dec_n::<64>(&sf.sig).unwrap();
        assert!(verify_p256(&d.public_raw(), sf.body.as_bytes(), &sig));
    }

    #[test]
    fn signature_over_other_body_fails() {
        let d = TestDevice::generate();
        let sf = d.frame(&frame());
        let sig = crate::b64::dec_n::<64>(&sf.sig).unwrap();
        assert!(!verify_p256(&d.public_raw(), b"{}", &sig));
        let other = TestDevice::generate();
        assert!(!verify_p256(&other.public_raw(), sf.body.as_bytes(), &sig));
    }

    #[test]
    fn signature_without_domain_fails() {
        let rng = ring::rand::SystemRandom::new();
        let (k, _) = MachineKey::generate(&rng).unwrap();
        let sig = k.sign(b"", b"body", &rng);
        assert!(!verify_p256(&k.public_raw(), b"body", &sig));
        let sig = k.sign(SIG_DOMAIN, b"body", &rng);
        assert!(verify_p256(&k.public_raw(), b"body", &sig));
        assert!(!verify_p256_domain(
            &k.public_raw(),
            b"other\n",
            b"body",
            &sig
        ));
    }

    #[test]
    fn pkcs8_roundtrip_keeps_the_key() {
        let rng = ring::rand::SystemRandom::new();
        let (k, p8) = MachineKey::generate(&rng).unwrap();
        let k2 = MachineKey::from_pkcs8(&p8, &rng).unwrap();
        assert_eq!(k.public_raw(), k2.public_raw());
        assert!(MachineKey::from_pkcs8(b"junk", &rng).is_err());
    }

    #[test]
    fn ids_are_derived() {
        let d = TestDevice::generate();
        let m = machine_id_of(&d.public_raw());
        assert_eq!(m.len(), 32);
        assert!(m
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        let id = device_id_of(&d.public_raw());
        assert!(id.starts_with("d-"));
        assert_eq!(id.len(), 18);
        assert_eq!(id, d.device_id());
    }
}
