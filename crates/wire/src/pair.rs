//! Pairing offers: the QR fragment, the proof, the short code and the
//! offer book. A browser proves it saw the QR (HMAC over the secret); the
//! owner then confirms on the machine by comparing the short codes.

use crate::device::{Device, DeviceList, DeviceState};
use crate::sig::{device_id_of, machine_id_of, MachineKey};
use crate::{b64, frame::strict_json, WireError};
use ring::rand::SecureRandom;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const OFFER_TTL_SECS: u64 = 300;
pub const MAX_OPEN_OFFERS: usize = 4;
pub const PAIR_PROOF_DOMAIN: &[u8] = b"saiife-pair-v1\n";
pub const SHORT_CODE_DOMAIN: &[u8] = b"saiife-pair-code-v1\n";
const MAX_LABEL_CHARS: usize = 40;

#[derive(Clone)]
pub struct PairOffer {
    /// 8 random bytes, b64u.
    pub pair_id: String,
    pub secret: [u8; 32],
    pub machine_id: String,
    pub machine_pub: [u8; 65],
    pub expires_at: u64,
    pub owner_user: String,
    pub label_hint: Option<String>,
}

impl std::fmt::Debug for PairOffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairOffer")
            .field("pair_id", &self.pair_id)
            .field("secret", &"<redacted>")
            .field("machine_id", &self.machine_id)
            .field("expires_at", &self.expires_at)
            .field("owner_user", &self.owner_user)
            .field("label_hint", &self.label_hint)
            .finish_non_exhaustive()
    }
}

/// The URL fragment payload: b64u of compact JSON.
pub fn fragment(o: &PairOffer) -> String {
    let j = serde_json::json!({
        "v": 1,
        "pair_id": o.pair_id,
        "secret": b64::enc(&o.secret),
        "machine_id": o.machine_id,
        "machine_pub": b64::enc(&o.machine_pub),
    });
    b64::enc(j.to_string().as_bytes())
}

/// Strict inverse of `fragment`: (pair_id, secret, machine_id, machine_pub).
pub fn parse_fragment(s: &str) -> Result<(String, [u8; 32], String, [u8; 65]), WireError> {
    let bad = |m: &str| WireError::Malformed(format!("pairing fragment: {m}"));
    let raw = b64::dec(s)?;
    let v = strict_json(&raw).ok_or_else(|| bad("not strict JSON"))?;
    let o = v.as_object().ok_or_else(|| bad("not an object"))?;
    if o.len() != 5 || o.get("v").and_then(|x| x.as_u64()) != Some(1) {
        return Err(bad("wrong fields or version"));
    }
    let get = |k: &str| {
        o.get(k)
            .and_then(|x| x.as_str())
            .ok_or_else(|| bad("missing field"))
    };
    let pair_id = get("pair_id")?.to_string();
    if b64::dec_n::<8>(&pair_id).is_err() {
        return Err(bad("pair_id"));
    }
    let secret = b64::dec_n::<32>(get("secret")?)?;
    let machine_id = get("machine_id")?.to_string();
    let machine_pub = b64::dec_n::<65>(get("machine_pub")?)?;
    if machine_id_of(&machine_pub) != machine_id {
        return Err(bad("machine_id does not match machine_pub"));
    }
    Ok((pair_id, secret, machine_id, machine_pub))
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairRequest {
    pub pair_id: String,
    pub device_pub: String,
    pub label: String,
    pub proof: String,
}

fn hmac_key(secret: &[u8; 32]) -> ring::hmac::Key {
    ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret)
}

fn proof_msg(pair_id: &str, device_pub: &[u8; 65]) -> Vec<u8> {
    let mut m = Vec::with_capacity(PAIR_PROOF_DOMAIN.len() + pair_id.len() + 65);
    m.extend_from_slice(PAIR_PROOF_DOMAIN);
    m.extend_from_slice(pair_id.as_bytes());
    m.extend_from_slice(device_pub);
    m
}

/// HMAC-SHA256(secret, domain || pair_id ASCII || device_pub raw).
pub fn proof(secret: &[u8; 32], pair_id: &str, device_pub: &[u8; 65]) -> [u8; 32] {
    let tag = ring::hmac::sign(&hmac_key(secret), &proof_msg(pair_id, device_pub));
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// "NNN NNN", both screens compute it independently.
pub fn short_code(machine_pub: &[u8; 65], device_pub: &[u8; 65], secret: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(SHORT_CODE_DOMAIN);
    h.update(machine_pub);
    h.update(device_pub);
    h.update(secret);
    let d = h.finalize();
    let n = u32::from_be_bytes([d[0], d[1], d[2], d[3]]) % 1_000_000;
    format!("{:03} {:03}", n / 1000, n % 1000)
}

fn check_label(l: &str) -> Result<(), WireError> {
    if l.chars().count() > MAX_LABEL_CHARS {
        return Err(WireError::Malformed("a label is 1 to 40 characters".into()));
    }
    saiife_touch::check_label(l).map_err(WireError::Malformed)
}

/// 65 bytes, 0x04 prefix, and ring accepts it as a P-256 point.
fn check_device_pub(p: &[u8; 65]) -> Result<(), WireError> {
    if crate::sig::is_p256_point(p) {
        Ok(())
    } else {
        Err(WireError::Malformed(
            "device_pub is not a P-256 point".into(),
        ))
    }
}

struct Entry {
    offer: PairOffer,
    requested: Option<Requested>,
}

struct Requested {
    device: Device,
    short_code: String,
}

pub struct Offers {
    by_id: HashMap<String, Entry>,
}

impl Default for Offers {
    fn default() -> Self {
        Offers::new()
    }
}

impl Offers {
    pub fn new() -> Offers {
        Offers {
            by_id: HashMap::new(),
        }
    }

    fn live(&self, id: &str, now: u64) -> Option<&Entry> {
        self.by_id.get(id).filter(|e| now < e.offer.expires_at)
    }

    pub fn open(
        &mut self,
        machine: &MachineKey,
        owner_user: &str,
        label_hint: Option<String>,
        rng: &dyn SecureRandom,
        now: u64,
    ) -> Result<PairOffer, WireError> {
        self.by_id.retain(|_, e| now < e.offer.expires_at);
        if self.by_id.len() >= MAX_OPEN_OFFERS {
            return Err(WireError::PairFull);
        }
        let mut id = [0u8; 8];
        let mut secret = [0u8; 32];
        rng.fill(&mut id)
            .and_then(|_| rng.fill(&mut secret))
            .map_err(|_| WireError::Store("random source failed".into()))?;
        let machine_pub = machine.public_raw();
        let offer = PairOffer {
            pair_id: b64::enc(&id),
            secret,
            machine_id: machine_id_of(&machine_pub),
            machine_pub,
            expires_at: now + OFFER_TTL_SECS,
            owner_user: owner_user.to_string(),
            label_hint,
        };
        self.by_id.insert(
            offer.pair_id.clone(),
            Entry {
                offer: offer.clone(),
                requested: None,
            },
        );
        Ok(offer)
    }

    /// A wrong proof does NOT burn the offer: otherwise anyone on the path
    /// who knows a pair_id (it is sent in the clear) could kill every
    /// offer. Only a valid proof moves the offer to "requested".
    pub fn request(
        &mut self,
        req: &PairRequest,
        known: &DeviceList,
        now: u64,
    ) -> Result<Device, WireError> {
        let entry = match self.by_id.get_mut(&req.pair_id) {
            Some(e) if now < e.offer.expires_at && e.requested.is_none() => e,
            _ => return Err(WireError::PairExpired),
        };
        check_label(&req.label)?;
        let pubkey = b64::dec_n::<65>(&req.device_pub)?;
        check_device_pub(&pubkey)?;
        let tag = b64::dec_n::<32>(&req.proof).map_err(|_| WireError::PairProof)?;
        ring::hmac::verify(
            &hmac_key(&entry.offer.secret),
            &proof_msg(&req.pair_id, &pubkey),
            &tag,
        )
        .map_err(|_| WireError::PairProof)?;
        let id = device_id_of(&pubkey);
        if known
            .get(&id)
            .is_some_and(|d| matches!(d.state, DeviceState::Active | DeviceState::Pending))
        {
            return Err(WireError::Malformed("device already paired".into()));
        }
        let device = Device {
            id,
            label: req.label.clone(),
            owner_user: entry.offer.owner_user.clone(),
            public_key: req.device_pub.clone(),
            state: DeviceState::Pending,
            added_at: now,
            touch_credentials: vec![],
        };
        entry.requested = Some(Requested {
            device: device.clone(),
            short_code: short_code(&entry.offer.machine_pub, &pubkey, &entry.offer.secret),
        });
        Ok(device)
    }

    pub fn status(&self, pair_id: &str, now: u64) -> PairStatus {
        match self.live(pair_id, now) {
            None => PairStatus::Expired,
            Some(Entry {
                requested: None, ..
            }) => PairStatus::Waiting,
            Some(Entry {
                requested: Some(r), ..
            }) => PairStatus::Requested {
                short_code: r.short_code.clone(),
                label: r.device.label.clone(),
                device_id: r.device.id.clone(),
            },
        }
    }

    /// The requested device, once; the offer is removed.
    pub fn take(&mut self, pair_id: &str, now: u64) -> Option<Device> {
        self.live(pair_id, now)?.requested.as_ref()?;
        self.by_id
            .remove(pair_id)
            .and_then(|e| e.requested)
            .map(|r| r.device)
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PairStatus {
    Waiting,
    Requested {
        short_code: String,
        label: String,
        device_id: String,
    },
    Expired,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sig::TestDevice;
    use ring::rand::SystemRandom;

    struct Fx {
        rng: SystemRandom,
        machine: MachineKey,
        offers: Offers,
    }

    fn fx() -> Fx {
        let rng = SystemRandom::new();
        let (machine, _) = MachineKey::generate(&rng).unwrap();
        Fx {
            rng,
            machine,
            offers: Offers::new(),
        }
    }

    fn open(f: &mut Fx, now: u64) -> PairOffer {
        f.offers
            .open(&f.machine, "alice", None, &f.rng, now)
            .unwrap()
    }

    fn req(o: &PairOffer, d: &TestDevice, label: &str) -> PairRequest {
        PairRequest {
            pair_id: o.pair_id.clone(),
            device_pub: b64::enc(&d.public_raw()),
            label: label.into(),
            proof: b64::enc(&proof(&o.secret, &o.pair_id, &d.public_raw())),
        }
    }

    #[test]
    fn fragment_roundtrip() {
        let mut f = fx();
        let o = open(&mut f, 100);
        let (id, secret, mid, mpub) = parse_fragment(&fragment(&o)).unwrap();
        assert_eq!(id, o.pair_id);
        assert_eq!(secret, o.secret);
        assert_eq!(mid, o.machine_id);
        assert_eq!(mpub, o.machine_pub);
        assert!(parse_fragment("!!").is_err());
        assert!(parse_fragment(&b64::enc(br#"{"v":2}"#)).is_err());
        let dup = format!(r#"{{"v":1,"v":1,"pair_id":"{}"}}"#, o.pair_id);
        assert!(parse_fragment(&b64::enc(dup.as_bytes())).is_err());
    }

    #[test]
    fn debug_hides_the_secret() {
        let mut f = fx();
        let o = open(&mut f, 100);
        let s = format!("{o:?}");
        assert!(!s.contains(&b64::enc(&o.secret)));
        assert!(s.contains("redacted"));
    }

    #[test]
    fn good_proof_gives_a_pending_device() {
        let mut f = fx();
        let o = open(&mut f, 100);
        let d = TestDevice::generate();
        let dev = f
            .offers
            .request(&req(&o, &d, "my phone"), &DeviceList::default(), 101)
            .unwrap();
        assert_eq!(dev.state, DeviceState::Pending);
        assert_eq!(dev.id, d.device_id());
        assert_eq!(dev.owner_user, "alice");
        assert_eq!(dev.added_at, 101);
        match f.offers.status(&o.pair_id, 102) {
            PairStatus::Requested {
                short_code: c,
                label,
                device_id,
            } => {
                assert_eq!(c, short_code(&o.machine_pub, &d.public_raw(), &o.secret));
                assert_eq!(label, "my phone");
                assert_eq!(device_id, d.device_id());
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(f.offers.take(&o.pair_id, 103), Some(dev));
        assert_eq!(f.offers.take(&o.pair_id, 103), None);
        assert_eq!(f.offers.status(&o.pair_id, 103), PairStatus::Expired);
    }

    #[test]
    fn bad_proof_is_refused_and_does_not_burn_the_offer() {
        let mut f = fx();
        let o = open(&mut f, 100);
        let d = TestDevice::generate();
        let mut r = req(&o, &d, "x");
        r.proof = b64::enc(&[0u8; 32]);
        let known = DeviceList::default();
        assert_eq!(
            f.offers.request(&r, &known, 101).unwrap_err(),
            WireError::PairProof
        );
        assert_eq!(f.offers.status(&o.pair_id, 101), PairStatus::Waiting);
        // proof bound to another device key
        let other = TestDevice::generate();
        let mut r2 = req(&o, &d, "x");
        r2.proof = req(&o, &other, "x").proof;
        assert_eq!(
            f.offers.request(&r2, &known, 101).unwrap_err(),
            WireError::PairProof
        );
        assert!(f.offers.request(&req(&o, &d, "x"), &known, 102).is_ok());
    }

    #[test]
    fn offer_is_single_use() {
        let mut f = fx();
        let o = open(&mut f, 100);
        let d = TestDevice::generate();
        let known = DeviceList::default();
        f.offers.request(&req(&o, &d, "a"), &known, 101).unwrap();
        let d2 = TestDevice::generate();
        assert_eq!(
            f.offers
                .request(&req(&o, &d2, "b"), &known, 102)
                .unwrap_err(),
            WireError::PairExpired
        );
        assert_eq!(
            f.offers
                .request(&req(&o, &d, "a"), &known, 102)
                .unwrap_err(),
            WireError::PairExpired
        );
    }

    #[test]
    fn expired_offer_is_refused() {
        let mut f = fx();
        let o = open(&mut f, 100);
        assert_eq!(o.expires_at, 400);
        let d = TestDevice::generate();
        let known = DeviceList::default();
        assert_eq!(
            f.offers
                .request(&req(&o, &d, "a"), &known, 400)
                .unwrap_err(),
            WireError::PairExpired
        );
        assert_eq!(f.offers.status(&o.pair_id, 400), PairStatus::Expired);
        assert_eq!(f.offers.status("nope", 100), PairStatus::Expired);
        assert!(f.offers.request(&req(&o, &d, "a"), &known, 399).is_ok());
        assert_eq!(f.offers.take(&o.pair_id, 400), None);
    }

    #[test]
    fn fifth_open_offer_is_refused() {
        let mut f = fx();
        for _ in 0..MAX_OPEN_OFFERS {
            open(&mut f, 100);
        }
        assert_eq!(
            f.offers
                .open(&f.machine, "a", None, &f.rng, 101)
                .unwrap_err(),
            WireError::PairFull
        );
        // all expired at 400: a slot frees up
        assert!(f.offers.open(&f.machine, "a", None, &f.rng, 400).is_ok());
    }

    #[test]
    fn swapped_device_key_changes_the_code() {
        let mut f = fx();
        let o = open(&mut f, 100);
        let a = TestDevice::generate();
        let b = TestDevice::generate();
        assert_ne!(
            short_code(&o.machine_pub, &a.public_raw(), &o.secret),
            short_code(&o.machine_pub, &b.public_raw(), &o.secret)
        );
    }

    #[test]
    fn code_format() {
        let re = |s: &str| {
            s.len() == 7
                && s.as_bytes()[3] == b' '
                && s.bytes()
                    .enumerate()
                    .all(|(i, c)| i == 3 || c.is_ascii_digit())
        };
        let mut f = fx();
        let o = open(&mut f, 100);
        let mut leading_zero = false;
        for _ in 0..400 {
            let d = TestDevice::generate();
            let c = short_code(&o.machine_pub, &d.public_raw(), &o.secret);
            assert!(re(&c), "{c}");
            leading_zero |= c.starts_with('0');
        }
        assert!(leading_zero, "leading zeros are kept");
    }

    #[test]
    fn hostile_label_is_refused() {
        let mut f = fx();
        let known = DeviceList::default();
        let long = "a".repeat(41);
        let o = open(&mut f, 100);
        for bad in ["a\u{202e}b", "x\n", "", long.as_str()] {
            let d = TestDevice::generate();
            assert!(
                matches!(
                    f.offers.request(&req(&o, &d, bad), &known, 101),
                    Err(WireError::Malformed(_))
                ),
                "{bad:?}"
            );
        }
        let d = TestDevice::generate();
        let ok = "é".repeat(40);
        assert!(f.offers.request(&req(&o, &d, &ok), &known, 101).is_ok());
    }

    #[test]
    fn bad_device_pub_is_malformed() {
        let mut f = fx();
        let known = DeviceList::default();
        let o = open(&mut f, 100);
        let d = TestDevice::generate();
        let mut off_curve = d.public_raw();
        off_curve[64] ^= 1;
        let mut compressed = d.public_raw();
        compressed[0] = 0x02;
        for p in [off_curve, compressed, [0u8; 65]] {
            let r = PairRequest {
                pair_id: o.pair_id.clone(),
                device_pub: b64::enc(&p),
                label: "x".into(),
                proof: b64::enc(&proof(&o.secret, &o.pair_id, &p)),
            };
            assert!(matches!(
                f.offers.request(&r, &known, 101),
                Err(WireError::Malformed(_))
            ));
        }
        let r = PairRequest {
            pair_id: o.pair_id.clone(),
            device_pub: b64::enc(&[4u8; 10]),
            label: "x".into(),
            proof: b64::enc(&[0u8; 32]),
        };
        assert!(matches!(
            f.offers.request(&r, &known, 101),
            Err(WireError::Malformed(_))
        ));
        assert_eq!(f.offers.status(&o.pair_id, 101), PairStatus::Waiting);
    }

    #[test]
    fn already_paired_device_is_refused() {
        let mut f = fx();
        let d = TestDevice::generate();
        for state in [DeviceState::Active, DeviceState::Pending] {
            let o = open(&mut f, 100);
            let mut known = DeviceList::default();
            known.upsert(Device {
                id: d.device_id(),
                label: "old".into(),
                owner_user: "alice".into(),
                public_key: b64::enc(&d.public_raw()),
                state,
                added_at: 1,
                touch_credentials: vec![],
            });
            assert_eq!(
                f.offers
                    .request(&req(&o, &d, "x"), &known, 101)
                    .unwrap_err(),
                WireError::Malformed("device already paired".into())
            );
        }
        // a revoked tombstone may pair again
        let o = open(&mut f, 100);
        let mut known = DeviceList::default();
        known.upsert(Device {
            id: d.device_id(),
            label: "old".into(),
            owner_user: "alice".into(),
            public_key: b64::enc(&d.public_raw()),
            state: DeviceState::Revoked,
            added_at: 1,
            touch_credentials: vec![],
        });
        assert!(f.offers.request(&req(&o, &d, "x"), &known, 101).is_ok());
    }
}
