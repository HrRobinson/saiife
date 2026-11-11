//! End-to-end seal for Workspace frames that cross the hub:
//! ECDH P-256 + HKDF-SHA256 + AES-256-GCM, one key per direction.

use crate::sig::verify_p256_domain;
use crate::WireError;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, ECDH_P256};
use ring::hkdf::{KeyType, Salt, HKDF_SHA256};
use ring::rand::SecureRandom;

/// Domain of the device key's handshake signature (session_id ‖
/// machine_eph ‖ browser_eph).
pub const HANDSHAKE_DOMAIN: &[u8] = b"saiife-seal-v1 hello\n";
/// Domain of the machine key's handshake signature, over
/// [`machine_hello_msg`]: it binds the session to one device or one
/// pairing offer, so a signature made for one cannot open a session as
/// another.
pub const MACHINE_HELLO_DOMAIN: &[u8] = b"saiife-seal-v1 machine\n";

/// What a sealed session is for: a paired device (its id), or a pairing
/// offer (its pair_id) for a pairing-only session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealBinding {
    Device(String),
    Pair(String),
}

/// What the machine key signs (domain [`MACHINE_HELLO_DOMAIN`]):
/// session_id ‖ machine_eph ‖ (`d:` device_id | `p:` pair_id), ASCII.
pub fn machine_hello_msg(
    session_id: &[u8; 16],
    machine_eph: &[u8; 65],
    b: &SealBinding,
) -> Vec<u8> {
    let (tag, id) = match b {
        SealBinding::Device(d) => (b"d:", d),
        SealBinding::Pair(p) => (b"p:", p),
    };
    let mut v = Vec::with_capacity(16 + 65 + 2 + id.len());
    v.extend_from_slice(session_id);
    v.extend_from_slice(machine_eph);
    v.extend_from_slice(tag);
    v.extend_from_slice(id.as_bytes());
    v
}
/// HKDF salt.
pub const SEAL_SALT: &[u8] = b"saiife-seal-v1";
const KEYS_INFO: &[u8] = b"saiife-seal-v1 keys";
const AAD_PREFIX: &[u8] = b"saiife-seal-v1 ";
const MAX_PLAINTEXT: usize = 1024 * 1024;
const TAG_LEN: usize = 16;
const DIR_B2M: u8 = b'b';
const DIR_M2B: u8 = b'm';

struct Len64;
impl KeyType for Len64 {
    fn len(&self) -> usize {
        64
    }
}

fn keys_from_shared(
    shared: &[u8],
    machine_eph: &[u8; 65],
    browser_eph: &[u8; 65],
    session_id: &[u8; 16],
) -> Result<[u8; 64], WireError> {
    let prk = Salt::new(HKDF_SHA256, SEAL_SALT).extract(shared);
    let info: [&[u8]; 4] = [KEYS_INFO, machine_eph, browser_eph, session_id];
    let okm = prk
        .expand(&info, Len64)
        .map_err(|_| WireError::Seal("key derivation failed".into()))?;
    let mut out = [0u8; 64];
    okm.fill(&mut out)
        .map_err(|_| WireError::Seal("key derivation failed".into()))?;
    Ok(out)
}

fn aead_key(k: &[u8]) -> Result<LessSafeKey, WireError> {
    UnboundKey::new(&AES_256_GCM, k)
        .map(LessSafeKey::new)
        .map_err(|_| WireError::Seal("bad key".into()))
}

/// One end of a sealed channel; the machine and browser ends differ only in
/// which half of the derived keys is used for which direction.
struct Core {
    rx: LessSafeKey,
    tx: LessSafeKey,
    rx_dir: u8,
    tx_dir: u8,
    next_rx: u64,
    next_tx: u64,
    dead: bool,
}

fn nonce_for(counter: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_be_bytes());
    Nonce::assume_unique_for_key(n)
}

fn aad_for(dir: u8) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[..15].copy_from_slice(AAD_PREFIX);
    a[15] = dir;
    a
}

impl Core {
    fn new(keys: &[u8; 64], machine_side: bool) -> Result<Core, WireError> {
        let b2m = aead_key(&keys[..32])?;
        let m2b = aead_key(&keys[32..])?;
        Ok(if machine_side {
            Core {
                rx: b2m,
                tx: m2b,
                rx_dir: DIR_B2M,
                tx_dir: DIR_M2B,
                next_rx: 0,
                next_tx: 0,
                dead: false,
            }
        } else {
            Core {
                rx: m2b,
                tx: b2m,
                rx_dir: DIR_M2B,
                tx_dir: DIR_B2M,
                next_rx: 0,
                next_tx: 0,
                dead: false,
            }
        })
    }

    fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, WireError> {
        if self.dead {
            return Err(WireError::Seal("channel closed".into()));
        }
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(WireError::Seal("too large".into()));
        }
        let counter = self.next_tx;
        let next = counter
            .checked_add(1)
            .ok_or_else(|| WireError::Seal("counter exhausted".into()))?;
        let mut buf = plaintext.to_vec();
        self.tx
            .seal_in_place_append_tag(
                nonce_for(counter),
                Aad::from(aad_for(self.tx_dir)),
                &mut buf,
            )
            .map_err(|_| WireError::Seal("seal failed".into()))?;
        self.next_tx = next;
        let mut out = Vec::with_capacity(8 + buf.len());
        out.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&buf);
        Ok(out)
    }

    fn open(&mut self, sealed: &[u8]) -> Result<Vec<u8>, WireError> {
        if self.dead {
            return Err(WireError::Seal("channel closed".into()));
        }
        let r = self.open_inner(sealed);
        if r.is_err() {
            self.dead = true;
        }
        r
    }

    fn open_inner(&mut self, sealed: &[u8]) -> Result<Vec<u8>, WireError> {
        if sealed.len() < 8 + TAG_LEN {
            return Err(WireError::Seal("too short".into()));
        }
        if sealed.len() > 8 + MAX_PLAINTEXT + TAG_LEN {
            return Err(WireError::Seal("too large".into()));
        }
        let mut c = [0u8; 8];
        c.copy_from_slice(&sealed[..8]);
        let counter = u64::from_be_bytes(c);
        if counter != self.next_rx {
            return Err(WireError::Seal("out of order".into()));
        }
        let mut buf = sealed[8..].to_vec();
        let plain_len = self
            .rx
            .open_in_place(
                nonce_for(counter),
                Aad::from(aad_for(self.rx_dir)),
                &mut buf,
            )
            .map_err(|_| WireError::Seal("authentication failed".into()))?
            .len();
        buf.truncate(plain_len);
        self.next_rx = counter + 1;
        Ok(buf)
    }
}

/// Machine side of one hub session. Link holds it (plan 29); the daemon
/// signs `to_sign(binding)` with the machine key (domain
/// [`MACHINE_HELLO_DOMAIN`]) so the browser, which knows `machine_pub` from
/// the QR code, can check it and that it is for its own device or offer.
pub struct MachineHandshake {
    private: EphemeralPrivateKey,
    eph_pub: [u8; 65],
    session_id: [u8; 16],
}

impl MachineHandshake {
    pub fn new(rng: &dyn SecureRandom) -> Result<MachineHandshake, WireError> {
        let private = EphemeralPrivateKey::generate(&ECDH_P256, rng)
            .map_err(|_| WireError::Seal("key generation failed".into()))?;
        let mut eph_pub = [0u8; 65];
        eph_pub.copy_from_slice(
            private
                .compute_public_key()
                .map_err(|_| WireError::Seal("key generation failed".into()))?
                .as_ref(),
        );
        let mut session_id = [0u8; 16];
        rng.fill(&mut session_id)
            .map_err(|_| WireError::Seal("random failed".into()))?;
        Ok(MachineHandshake {
            private,
            eph_pub,
            session_id,
        })
    }

    pub fn eph_pub(&self) -> [u8; 65] {
        self.eph_pub
    }

    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }

    /// The bytes the machine key signs (domain [`MACHINE_HELLO_DOMAIN`]):
    /// [`machine_hello_msg`] of this session for `b`.
    pub fn to_sign(&self, b: &SealBinding) -> Vec<u8> {
        machine_hello_msg(&self.session_id, &self.eph_pub, b)
    }

    /// `browser_sig` is the device key's signature (`HANDSHAKE_DOMAIN`) over
    /// session_id ‖ machine_eph ‖ browser_eph; `device_pub = None` (with no
    /// signature) only for a pairing session, which may carry `pair`
    /// messages and nothing else.
    pub fn finish(
        self,
        browser_eph: &[u8; 65],
        browser_sig: Option<&[u8; 64]>,
        device_pub: Option<&[u8; 65]>,
    ) -> Result<Channel, WireError> {
        let pairing_only = match (browser_sig, device_pub) {
            (Some(sig), Some(pk)) => {
                let msg = handshake_msg(&self.session_id, &self.eph_pub, browser_eph);
                if !verify_p256_domain(pk, HANDSHAKE_DOMAIN, &msg, sig) {
                    return Err(WireError::Seal("bad handshake signature".into()));
                }
                false
            }
            (None, None) => true,
            _ => {
                return Err(WireError::Seal(
                    "signature and device key go together".into(),
                ))
            }
        };
        let shared = agree_ephemeral(
            self.private,
            &UnparsedPublicKey::new(&ECDH_P256, browser_eph.as_slice()),
            |s| s.to_vec(),
        )
        .map_err(|_| WireError::Seal("bad browser key".into()))?;
        let keys = keys_from_shared(&shared, &self.eph_pub, browser_eph, &self.session_id)?;
        Channel::from_keys(&keys, pairing_only)
    }
}

fn handshake_msg(session_id: &[u8; 16], machine_eph: &[u8; 65], browser_eph: &[u8; 65]) -> Vec<u8> {
    let mut v = Vec::with_capacity(146);
    v.extend_from_slice(session_id);
    v.extend_from_slice(machine_eph);
    v.extend_from_slice(browser_eph);
    v
}

/// The machine end of a sealed session.
pub struct Channel {
    core: Core,
    pairing_only: bool,
}

impl Channel {
    fn from_keys(keys: &[u8; 64], pairing_only: bool) -> Result<Channel, WireError> {
        Ok(Channel {
            core: Core::new(keys, true)?,
            pairing_only,
        })
    }

    /// u64 BE counter ‖ ciphertext ‖ tag. `Seal("too large")` above 1 MiB.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, WireError> {
        self.core.seal(plaintext)
    }

    /// The counter must equal the next expected one; any failure closes the
    /// channel for good.
    pub fn open(&mut self, sealed: &[u8]) -> Result<Vec<u8>, WireError> {
        self.core.open(sealed)
    }

    pub fn pairing_only(&self) -> bool {
        self.pairing_only
    }
}

/// The browser half, for tests and the fake hub of plan 29.
#[cfg(any(test, feature = "fake"))]
pub struct TestBrowserEnd<'a> {
    private: EphemeralPrivateKey,
    eph_pub: [u8; 65],
    device: Option<&'a crate::sig::TestDevice>,
}

#[cfg(any(test, feature = "fake"))]
impl<'a> TestBrowserEnd<'a> {
    pub fn new(device: Option<&'a crate::sig::TestDevice>) -> TestBrowserEnd<'a> {
        let rng = ring::rand::SystemRandom::new();
        let private = EphemeralPrivateKey::generate(&ECDH_P256, &rng).expect("ephemeral key");
        let mut eph_pub = [0u8; 65];
        eph_pub.copy_from_slice(private.compute_public_key().expect("public key").as_ref());
        TestBrowserEnd {
            private,
            eph_pub,
            device,
        }
    }

    pub fn eph_pub(&self) -> [u8; 65] {
        self.eph_pub
    }

    /// The device key's handshake signature; `None` for a pairing session.
    pub fn sign_handshake(
        &self,
        session_id: &[u8; 16],
        machine_eph: &[u8; 65],
    ) -> Option<[u8; 64]> {
        self.device.map(|d| {
            d.sign_domain(
                HANDSHAKE_DOMAIN,
                &handshake_msg(session_id, machine_eph, &self.eph_pub),
            )
        })
    }

    /// Checks the machine's handshake signature, made for `expect` (this
    /// browser's device, or the offer it pairs with), and derives the
    /// channel.
    pub fn finish(
        self,
        machine_eph: &[u8; 65],
        session_id: &[u8; 16],
        machine_sig: &[u8; 64],
        machine_pub: &[u8; 65],
        expect: &SealBinding,
    ) -> Result<BrowserChannel, WireError> {
        let msg = machine_hello_msg(session_id, machine_eph, expect);
        if !verify_p256_domain(machine_pub, MACHINE_HELLO_DOMAIN, &msg, machine_sig) {
            return Err(WireError::Seal("bad handshake signature".into()));
        }
        let shared = agree_ephemeral(
            self.private,
            &UnparsedPublicKey::new(&ECDH_P256, machine_eph.as_slice()),
            |s| s.to_vec(),
        )
        .map_err(|_| WireError::Seal("bad machine key".into()))?;
        let keys = keys_from_shared(&shared, machine_eph, &self.eph_pub, session_id)?;
        Ok(BrowserChannel(Core::new(&keys, false)?))
    }
}

/// The browser end of a sealed session (direction `b` out, `m` in).
#[cfg(any(test, feature = "fake"))]
pub struct BrowserChannel(Core);

#[cfg(any(test, feature = "fake"))]
impl BrowserChannel {
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, WireError> {
        self.0.seal(plaintext)
    }

    pub fn open(&mut self, sealed: &[u8]) -> Result<Vec<u8>, WireError> {
        self.0.open(sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sig::{MachineKey, TestDevice};

    fn rng() -> ring::rand::SystemRandom {
        ring::rand::SystemRandom::new()
    }

    /// Full handshake; returns both ends.
    fn session(device: Option<&TestDevice>) -> (Channel, BrowserChannel) {
        let r = rng();
        let (mk, _) = MachineKey::generate(&r).unwrap();
        let mh = MachineHandshake::new(&r).unwrap();
        let binding = match device {
            Some(d) => SealBinding::Device(d.device_id()),
            None => SealBinding::Pair("p-1".into()),
        };
        let machine_sig = mk.sign(MACHINE_HELLO_DOMAIN, &mh.to_sign(&binding), &r);
        let be = TestBrowserEnd::new(device);
        let bsig = be.sign_handshake(&mh.session_id(), &mh.eph_pub());
        let beph = be.eph_pub();
        let (meph, sid) = (mh.eph_pub(), mh.session_id());
        let pk = device.map(|d| d.public_raw());
        let ch = mh.finish(&beph, bsig.as_ref(), pk.as_ref()).unwrap();
        let bc = be
            .finish(&meph, &sid, &machine_sig, &mk.public_raw(), &binding)
            .unwrap();
        (ch, bc)
    }

    #[test]
    fn handshake_and_roundtrip() {
        let d = TestDevice::generate();
        let (mut m, mut b) = session(Some(&d));
        assert!(!m.pairing_only());
        let s = b.seal(b"hello machine").unwrap();
        assert_eq!(m.open(&s).unwrap(), b"hello machine");
        let s = m.seal(b"hello browser").unwrap();
        assert_eq!(b.open(&s).unwrap(), b"hello browser");
        let s = b.seal(b"").unwrap();
        assert_eq!(s.len(), 8 + 16);
        assert_eq!(m.open(&s).unwrap(), b"");
    }

    #[test]
    fn wrong_device_signature_is_refused() {
        let r = rng();
        let d = TestDevice::generate();
        let other = TestDevice::generate();
        let mh = MachineHandshake::new(&r).unwrap();
        let be = TestBrowserEnd::new(Some(&d));
        let sig = be.sign_handshake(&mh.session_id(), &mh.eph_pub()).unwrap();
        let e = mh
            .finish(&be.eph_pub(), Some(&sig), Some(&other.public_raw()))
            .err()
            .unwrap();
        assert_eq!(e, WireError::Seal("bad handshake signature".into()));
    }

    #[test]
    fn signature_over_another_session_is_refused() {
        let r = rng();
        let d = TestDevice::generate();
        let mh = MachineHandshake::new(&r).unwrap();
        let be = TestBrowserEnd::new(Some(&d));
        let sig = be.sign_handshake(&[9u8; 16], &mh.eph_pub()).unwrap();
        assert!(mh
            .finish(&be.eph_pub(), Some(&sig), Some(&d.public_raw()))
            .is_err());
    }

    #[test]
    fn mismatched_signature_and_key_is_refused() {
        let r = rng();
        let d = TestDevice::generate();
        let be = TestBrowserEnd::new(Some(&d));
        let mh = MachineHandshake::new(&r).unwrap();
        let sig = be.sign_handshake(&mh.session_id(), &mh.eph_pub()).unwrap();
        assert!(mh.finish(&be.eph_pub(), Some(&sig), None).is_err());
        let mh = MachineHandshake::new(&r).unwrap();
        assert!(mh
            .finish(&be.eph_pub(), None, Some(&d.public_raw()))
            .is_err());
    }

    #[test]
    fn invalid_browser_point_is_refused() {
        let r = rng();
        let mh = MachineHandshake::new(&r).unwrap();
        assert!(mh.finish(&[4u8; 65], None, None).is_err());
        let mh = MachineHandshake::new(&r).unwrap();
        assert!(mh.finish(&[0u8; 65], None, None).is_err());
    }

    #[test]
    fn wrong_machine_signature_is_refused_by_the_browser() {
        let r = rng();
        let (mk, _) = MachineKey::generate(&r).unwrap();
        let (other, _) = MachineKey::generate(&r).unwrap();
        let mh = MachineHandshake::new(&r).unwrap();
        let b = SealBinding::Pair("p-1".into());
        let sig = mk.sign(MACHINE_HELLO_DOMAIN, &mh.to_sign(&b), &r);
        let be = TestBrowserEnd::new(None);
        let e = be
            .finish(
                &mh.eph_pub(),
                &mh.session_id(),
                &sig,
                &other.public_raw(),
                &b,
            )
            .err()
            .unwrap();
        assert_eq!(e, WireError::Seal("bad handshake signature".into()));
    }

    #[test]
    fn machine_signature_is_bound_to_its_device_or_offer() {
        let r = rng();
        let (mk, _) = MachineKey::generate(&r).unwrap();
        let (a, b) = (TestDevice::generate(), TestDevice::generate());
        let for_a = SealBinding::Device(a.device_id());
        let try_as = [
            SealBinding::Device(b.device_id()),
            SealBinding::Pair(a.device_id()),
            SealBinding::Pair("p-1".into()),
        ];
        for other in &try_as {
            let mh = MachineHandshake::new(&r).unwrap();
            let sig = mk.sign(MACHINE_HELLO_DOMAIN, &mh.to_sign(&for_a), &r);
            let be = TestBrowserEnd::new(Some(&b));
            let e = be
                .finish(
                    &mh.eph_pub(),
                    &mh.session_id(),
                    &sig,
                    &mk.public_raw(),
                    other,
                )
                .err()
                .unwrap();
            assert_eq!(
                e,
                WireError::Seal("bad handshake signature".into()),
                "{other:?}"
            );
        }
        // The same signature under the device domain does not verify either.
        let mh = MachineHandshake::new(&r).unwrap();
        let sig = mk.sign(HANDSHAKE_DOMAIN, &mh.to_sign(&for_a), &r);
        let be = TestBrowserEnd::new(Some(&a));
        assert!(be
            .finish(
                &mh.eph_pub(),
                &mh.session_id(),
                &sig,
                &mk.public_raw(),
                &for_a
            )
            .is_err());
        // And for A it does.
        let mh = MachineHandshake::new(&r).unwrap();
        let sig = mk.sign(MACHINE_HELLO_DOMAIN, &mh.to_sign(&for_a), &r);
        let be = TestBrowserEnd::new(Some(&a));
        assert!(be
            .finish(
                &mh.eph_pub(),
                &mh.session_id(),
                &sig,
                &mk.public_raw(),
                &for_a
            )
            .is_ok());
    }

    #[test]
    fn machine_hello_msg_shape() {
        let m = machine_hello_msg(&[1; 16], &[4; 65], &SealBinding::Device("d-ab".into()));
        assert_eq!(m.len(), 16 + 65 + 6);
        assert!(m.ends_with(b"d:d-ab"));
        let p = machine_hello_msg(&[1; 16], &[4; 65], &SealBinding::Pair("x".into()));
        assert!(p.ends_with(b"p:x"));
    }

    #[test]
    fn replayed_message_kills_the_channel() {
        let d = TestDevice::generate();
        let (mut m, mut b) = session(Some(&d));
        let s0 = b.seal(b"one").unwrap();
        let s1 = b.seal(b"two").unwrap();
        m.open(&s0).unwrap();
        assert_eq!(
            m.open(&s0).unwrap_err(),
            WireError::Seal("out of order".into())
        );
        assert!(m.open(&s1).is_err());
    }

    #[test]
    fn reordered_message_is_refused() {
        let d = TestDevice::generate();
        let (mut m, mut b) = session(Some(&d));
        let _s0 = b.seal(b"one").unwrap();
        let s1 = b.seal(b"two").unwrap();
        assert_eq!(
            m.open(&s1).unwrap_err(),
            WireError::Seal("out of order".into())
        );
    }

    #[test]
    fn flipped_bit_is_refused() {
        let d = TestDevice::generate();
        let (mut m, mut b) = session(Some(&d));
        let mut s = b.seal(b"payload").unwrap();
        s[9] ^= 1;
        assert!(m.open(&s).is_err());
        let good = b.seal(b"next").unwrap();
        assert!(m.open(&good).is_err(), "channel is dead");
    }

    #[test]
    fn short_and_oversize_input_is_refused() {
        let d = TestDevice::generate();
        let (mut m, mut b) = session(Some(&d));
        assert!(m.open(&[0u8; 23]).is_err());
        assert!(m.open(&b.seal(b"x").unwrap()).is_err(), "dead");
        let (mut m, mut b) = session(Some(&d));
        assert_eq!(
            b.seal(&vec![0u8; MAX_PLAINTEXT + 1]).unwrap_err(),
            WireError::Seal("too large".into())
        );
        let big = b.seal(&vec![7u8; MAX_PLAINTEXT]).unwrap();
        assert_eq!(m.open(&big).unwrap().len(), MAX_PLAINTEXT);
        assert!(m.seal(&vec![0u8; MAX_PLAINTEXT + 1]).is_err());
        assert!(m.open(&vec![0u8; MAX_PLAINTEXT + 8 + 17]).is_err());
    }

    #[test]
    fn directions_use_different_keys() {
        let d = TestDevice::generate();
        let (mut m, mut b) = session(Some(&d));
        let s = m.seal(b"to browser").unwrap();
        assert!(m.open(&s).is_err(), "own direction fed back");
        let (_, mut b2) = session(Some(&d));
        let s = b2.seal(b"x").unwrap();
        assert!(b2.open(&s).is_err());
        let (mut m3, _) = session(Some(&d));
        let s = b.seal(b"x").unwrap();
        assert!(m3.open(&s).is_err(), "other session, other keys");
    }

    #[test]
    fn pairing_session_is_flagged() {
        let (mut m, mut b) = session(None);
        assert!(m.pairing_only());
        let s = b.seal(b"pair").unwrap();
        assert_eq!(m.open(&s).unwrap(), b"pair");
    }

    #[test]
    fn frozen_seal_vector() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../tests/vectors/seal-v1.json")).unwrap();
        let s = |k: &str| v[k].as_str().unwrap().to_string();
        let shared = hex_dec(&s("shared_secret_hex"));
        let meph = crate::b64::dec_n::<65>(&s("machine_eph")).unwrap();
        let beph = crate::b64::dec_n::<65>(&s("browser_eph")).unwrap();
        let sid = crate::b64::dec_n::<16>(&s("session_id")).unwrap();
        let keys = keys_from_shared(&shared, &meph, &beph, &sid).unwrap();
        assert_eq!(crate::b64::hex(&keys), s("keys_hex"));
        let mut m = Channel::from_keys(&keys, false).unwrap();
        let mut b = BrowserChannel(Core::new(&keys, false).unwrap());
        for msg in v["messages"].as_array().unwrap() {
            let plain = msg["plaintext"].as_str().unwrap().as_bytes();
            let sealed = crate::b64::dec(msg["sealed_b64u"].as_str().unwrap()).unwrap();
            assert_eq!(
                u64::from_be_bytes(sealed[..8].try_into().unwrap()),
                msg["counter"].as_u64().unwrap()
            );
            match msg["dir"].as_str().unwrap() {
                "b" => {
                    assert_eq!(b.seal(plain).unwrap(), sealed);
                    assert_eq!(m.open(&sealed).unwrap(), plain);
                }
                "m" => {
                    assert_eq!(m.seal(plain).unwrap(), sealed);
                    assert_eq!(b.open(&sealed).unwrap(), plain);
                }
                other => panic!("dir {other}"),
            }
        }
    }

    fn hex_dec(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }
}
