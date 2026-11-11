//! A software authenticator for tests (and plan 27's test seam): it signs
//! exactly as a CTAP2 key driven by ctap-hid-fido2 does (D1), or as a browser.

use std::sync::atomic::{AtomicU32, Ordering};

use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

use crate::action::sha256;
use crate::authdata::{AT, UP, UV};
use crate::client::{EnrolRequest, Touch, TouchRequest};
use crate::codec::{b64, hex};
use crate::cose::CoseKey;
use crate::store::{CoseAlg, Credential};
use crate::verify::Assertion;
use crate::TouchError;

enum Key {
    Es256(EcdsaKeyPair),
    Ed25519(Ed25519KeyPair),
}

/// A soft FIDO2 key. The knobs are public: flip them to make bad touches.
pub struct SoftAuthenticator {
    key: Key,
    pkcs8: Vec<u8>,
    id: Vec<u8>,
    counter: AtomicU32,
    rng: SystemRandom,
    /// Report user presence (default true).
    pub up: bool,
    /// Report user verification (default true).
    pub uv: bool,
    /// Counter increment per assertion (default 1; 0 freezes it).
    pub counter_step: u32,
    /// Sign as this rp id instead of the requested one.
    pub rp_override: Option<String>,
    /// The WebAuthn clientDataJSON `type` (default `webauthn.get`).
    pub type_override: Option<String>,
}

impl SoftAuthenticator {
    /// A new P-256 key with a random 16-byte credential id.
    pub fn new_es256() -> Self {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("P-256 key generation");
        Self::from_parts(CoseAlg::Es256, doc.as_ref(), random_id(&rng), 0)
            .expect("a fresh PKCS#8 document parses")
    }

    /// A new Ed25519 key with a random 16-byte credential id.
    pub fn new_ed25519() -> Self {
        let rng = SystemRandom::new();
        let doc = Ed25519KeyPair::generate_pkcs8(&rng).expect("Ed25519 key generation");
        Self::from_parts(CoseAlg::Ed25519, doc.as_ref(), random_id(&rng), 0)
            .expect("a fresh PKCS#8 document parses")
    }

    /// Rebuilds a key saved with `parts()`.
    pub fn from_parts(
        alg: CoseAlg,
        pkcs8: &[u8],
        credential_id: Vec<u8>,
        counter: u32,
    ) -> Result<Self, TouchError> {
        let rng = SystemRandom::new();
        let key = match alg {
            CoseAlg::Es256 => Key::Es256(
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8, &rng)
                    .map_err(|_| TouchError::Malformed)?,
            ),
            CoseAlg::Ed25519 => {
                Key::Ed25519(Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| TouchError::Malformed)?)
            }
        };
        Ok(Self {
            key,
            pkcs8: pkcs8.to_vec(),
            id: credential_id,
            counter: AtomicU32::new(counter),
            rng,
            up: true,
            uv: true,
            counter_step: 1,
            rp_override: None,
            type_override: None,
        })
    }

    /// `(alg, pkcs8, credential id, counter)`.
    pub fn parts(&self) -> (CoseAlg, Vec<u8>, Vec<u8>, u32) {
        let alg = match self.key {
            Key::Es256(_) => CoseAlg::Es256,
            Key::Ed25519(_) => CoseAlg::Ed25519,
        };
        (
            alg,
            self.pkcs8.clone(),
            self.id.clone(),
            self.counter.load(Ordering::SeqCst),
        )
    }

    pub fn credential_id(&self) -> Vec<u8> {
        self.id.clone()
    }

    pub fn public_key(&self) -> CoseKey {
        match &self.key {
            Key::Es256(k) => {
                let p = k.public_key().as_ref();
                let mut x = [0u8; 32];
                let mut y = [0u8; 32];
                x.copy_from_slice(&p[1..33]);
                y.copy_from_slice(&p[33..65]);
                CoseKey::Es256 { x, y }
            }
            Key::Ed25519(k) => {
                let mut x = [0u8; 32];
                x.copy_from_slice(k.public_key().as_ref());
                CoseKey::Ed25519 { x }
            }
        }
    }

    /// A local (`fido2`) credential for this key, counter 0.
    pub fn credential(&self, rp_id: &str, owner_uid: u32, label: &str) -> Credential {
        Credential {
            id: self.id.clone(),
            public_key: self.public_key(),
            kind: "fido2".into(),
            rp_id: rp_id.into(),
            origins: Vec::new(),
            label: label.into(),
            owner_uid,
            owner_sid: None,
            sign_count: 0,
            created: "2026-01-01T00:00:00.000Z".into(),
            aaguid: hex(&[0u8; 16]),
        }
    }

    /// A browser (`webauthn`) credential for this key, allowed on `origin`.
    pub fn web_credential(&self, rp_id: &str, origin: &str, owner_uid: u32) -> Credential {
        Credential {
            kind: "webauthn".into(),
            origins: vec![origin.into()],
            ..self.credential(rp_id, owner_uid, "web")
        }
    }

    /// A CTAP2 assertion over `challenge`: signs `authData ‖ SHA-256(challenge)` (D1).
    pub fn assert_ctap(&self, rp_id: &str, challenge: &[u8; 32]) -> Assertion {
        let auth_data = self.auth_data(rp_id);
        let client_data_hash = sha256(challenge);
        let signature = self.sign(&auth_data, &client_data_hash);
        Assertion::Ctap2 {
            credential_id: self.id.clone(),
            auth_data,
            signature,
            client_data_hash,
        }
    }

    /// A browser assertion: `clientDataJSON` carries base64url(challenge).
    pub fn assert_webauthn(&self, rp_id: &str, origin: &str, challenge: &[u8; 32]) -> Assertion {
        let ty = self.type_override.as_deref().unwrap_or("webauthn.get");
        let json = |s: &str| serde_json::to_string(s).expect("a string serialises");
        let client_data_json = format!(
            "{{\"type\":{},\"challenge\":\"{}\",\"origin\":{},\"crossOrigin\":false}}",
            json(ty),
            b64(challenge),
            json(origin)
        )
        .into_bytes();
        let auth_data = self.auth_data(rp_id);
        let signature = self.sign(&auth_data, &sha256(&client_data_json));
        Assertion::WebAuthn {
            credential_id: self.id.clone(),
            auth_data,
            signature,
            client_data_json,
            origin: origin.into(),
        }
    }

    fn rp_hash(&self, rp_id: &str) -> [u8; 32] {
        sha256(self.rp_override.as_deref().unwrap_or(rp_id).as_bytes())
    }

    /// `rpIdHash ‖ flags ‖ counter`, advancing the counter by `counter_step`.
    fn auth_data(&self, rp_id: &str) -> Vec<u8> {
        let step = self.counter_step;
        let count = self
            .counter
            .fetch_add(step, Ordering::SeqCst)
            .wrapping_add(step);
        let mut flags = 0;
        if self.up {
            flags |= UP;
        }
        if self.uv {
            flags |= UV;
        }
        let mut v = self.rp_hash(rp_id).to_vec();
        v.push(flags);
        v.extend(count.to_be_bytes());
        v
    }

    fn sign(&self, auth_data: &[u8], hash: &[u8; 32]) -> Vec<u8> {
        let mut msg = auth_data.to_vec();
        msg.extend(hash);
        match &self.key {
            Key::Es256(k) => k
                .sign(&self.rng, &msg)
                .expect("P-256 signing")
                .as_ref()
                .to_vec(),
            Key::Ed25519(k) => k.sign(&msg).as_ref().to_vec(),
        }
    }
}

fn random_id(rng: &SystemRandom) -> Vec<u8> {
    let mut id = vec![0u8; 16];
    rng.fill(&mut id).expect("system randomness");
    id
}

impl Touch for SoftAuthenticator {
    fn request(&self, r: &TouchRequest) -> Result<Assertion, TouchError> {
        if !r.allow.is_empty() && !r.allow.contains(&self.id) {
            return Err(TouchError::UnknownCredential);
        }
        Ok(self.assert_ctap(&r.rp_id, &r.challenge))
    }

    /// Attestation authData: `rpIdHash ‖ 0x45 ‖ counter ‖ aaguid ‖ len ‖ id ‖ COSE key`.
    fn enrol(&self, r: &EnrolRequest) -> Result<Vec<u8>, TouchError> {
        let mut v = self.rp_hash(&r.rp_id).to_vec();
        v.push(UP | UV | AT);
        v.extend(self.counter.load(Ordering::SeqCst).to_be_bytes());
        v.extend([0u8; 16]);
        let len = u16::try_from(self.id.len()).map_err(|_| TouchError::Malformed)?;
        v.extend(len.to_be_bytes());
        v.extend(&self.id);
        v.extend(self.public_key().to_cose());
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authdata;

    fn treq(allow: Vec<Vec<u8>>) -> TouchRequest {
        TouchRequest {
            rp_id: crate::LOCAL_RP_ID.into(),
            challenge: [5; 32],
            allow,
            uv: true,
            summary: "#1".into(),
            short_code: "000000".into(),
        }
    }

    #[test]
    fn soft_touch_trait() {
        let s = SoftAuthenticator::new_es256();
        assert!(s.request(&treq(vec![])).is_ok());
        assert!(s.request(&treq(vec![s.credential_id()])).is_ok());
        assert_eq!(
            s.request(&treq(vec![vec![9; 16]])).unwrap_err(),
            TouchError::UnknownCredential
        );
        let e = EnrolRequest {
            rp_id: crate::LOCAL_RP_ID.into(),
            rp_name: crate::RP_NAME.into(),
            user_id: vec![1],
            user_name: "jo".into(),
            challenge: [5; 32],
            exclude: vec![],
        };
        for s in [s, SoftAuthenticator::new_ed25519()] {
            let raw = s.enrol(&e).unwrap();
            let ad = authdata::parse(&raw).unwrap();
            assert_eq!(ad.flags, 0x45);
            assert_eq!(ad.rp_id_hash, sha256(crate::LOCAL_RP_ID.as_bytes()));
            let att = ad.attested.unwrap();
            assert_eq!(att.credential_id, s.credential_id());
            assert_eq!(att.public_key, s.public_key());
        }
    }
}
