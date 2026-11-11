//! The gate every Workspace frame passes: device, signature, machine, epoch,
//! time, access level, and last of all the replay cache.

use std::collections::BTreeMap;

use crate::device::{Device, DeviceState};
use crate::frame::{parse_body, Frame, SignedFrame, SKEW_SECS};
use crate::level::{level_for, Level};
use crate::sig::{device_id_of, verify_p256};
use crate::{b64, WireError};

/// Live nonces kept; when full, new frames are refused, never evicted early.
pub const REPLAY_CAP: usize = 8192;

/// Burned `(device_id, nonce)` pairs with the frame's `expires_at`.
pub struct ReplayCache {
    seen: BTreeMap<(String, String), u64>,
    cap: usize,
}

impl ReplayCache {
    pub fn new(cap: usize) -> ReplayCache {
        ReplayCache {
            seen: BTreeMap::new(),
            cap,
        }
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

pub struct Verifier {
    pub machine_id: String,
    pub epoch: String,
    pub replay: ReplayCache,
}

/// The outcome of [`Verifier::check`]: the frame is authentic, fresh and the
/// device may use its action's level. The caller still has duties `check`
/// cannot do for it:
/// - `Level::Touch` means the caller must verify `SignedFrame.touch` with
///   `saiife_touch` (against the pending action it created) before acting.
/// - `box.spawn`'s level here is only the base level; the caller must raise
///   it with `level::spawn_level(template)` once the template is known.
/// - A `pairing_only` seal channel may carry only pair messages; the caller
///   must refuse every other action on it.
#[derive(Debug, Clone)]
pub struct Verified {
    pub frame: Frame,
    pub device_id: String,
    pub owner_user: String,
    pub level: Level,
}

impl Verifier {
    pub fn new(machine_id: String, epoch: String) -> Verifier {
        Verifier {
            machine_id,
            epoch,
            replay: ReplayCache::new(REPLAY_CAP),
        }
    }

    /// Order: body parse -> device lookup -> signature -> device pending ->
    /// machine id -> epoch -> time -> level (None/MachineOnly refused) ->
    /// nonce burned last. Nothing before the last step touches the cache.
    pub fn check(
        &mut self,
        sf: &SignedFrame,
        devices: &dyn Fn(&str) -> Option<Device>,
        now: u64,
    ) -> Result<Verified, WireError> {
        let frame = parse_body(sf.body.as_bytes())?;
        let sig = b64::dec_n::<64>(&sf.sig)?;

        let device = match devices(&frame.device_id) {
            Some(d) if d.state != DeviceState::Revoked => d,
            _ => return Err(WireError::UnknownDevice),
        };
        let key = device.public_raw().map_err(|_| WireError::UnknownDevice)?;
        if device.id != frame.device_id || device_id_of(&key) != device.id {
            return Err(WireError::UnknownDevice);
        }

        if !verify_p256(&key, sf.body.as_bytes(), &sig) {
            return Err(WireError::BadSignature);
        }
        if device.state == DeviceState::Pending {
            return Err(WireError::DevicePending);
        }
        if frame.machine_id != self.machine_id {
            return Err(WireError::WrongMachine);
        }
        if frame.epoch != self.epoch {
            return Err(WireError::StaleEpoch);
        }
        if now >= frame.expires_at {
            return Err(WireError::Expired);
        }
        if frame.issued_at > now.saturating_add(SKEW_SECS) {
            return Err(WireError::NotYetValid);
        }
        let level = match level_for(&frame.action) {
            None => return Err(WireError::UnknownAction(frame.action.clone())),
            Some(Level::MachineOnly) => return Err(WireError::MachineOnly(frame.action.clone())),
            Some(l) => l,
        };

        self.replay.seen.retain(|_, exp| *exp > now);
        let k = (frame.device_id.clone(), frame.nonce.clone());
        if self.replay.seen.contains_key(&k) {
            return Err(WireError::Replayed);
        }
        if self.replay.seen.len() >= self.replay.cap {
            return Err(WireError::Busy);
        }
        self.replay.seen.insert(k, frame.expires_at);

        Ok(Verified {
            device_id: frame.device_id.clone(),
            owner_user: device.owner_user,
            level,
            frame,
        })
    }
}

/// 16 random bytes, b64u. The daemon draws one at start.
///
/// Panics if the system random source fails (the daemon cannot run safely
/// without one).
pub fn new_epoch(rng: &dyn ring::rand::SecureRandom) -> String {
    let mut b = [0u8; 16];
    rng.fill(&mut b)
        .expect("system random source failed while drawing the epoch");
    b64::enc(&b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sig::TestDevice;
    use serde_json::Map;

    const M: &str = "m-1";
    const E: &str = "e-1";
    const NOW: u64 = 1000;

    fn dev_for(t: &TestDevice, state: DeviceState) -> Device {
        Device {
            id: t.device_id(),
            label: "phone".into(),
            owner_user: "alice".into(),
            public_key: b64::enc(&t.public_raw()),
            state,
            added_at: 1,
            touch_credentials: vec![],
        }
    }

    fn frame(t: &TestDevice, action: &str, nonce: u8, issued: u64, expires: u64) -> Frame {
        Frame {
            v: 1,
            machine_id: M.into(),
            epoch: E.into(),
            device_id: t.device_id(),
            action: action.into(),
            args: Map::new(),
            nonce: b64::enc(&[nonce; 16]),
            issued_at: issued,
            expires_at: expires,
        }
    }

    fn ok_frame(t: &TestDevice, nonce: u8) -> Frame {
        frame(t, "box.list", nonce, NOW, NOW + 100)
    }

    fn v() -> Verifier {
        Verifier::new(M.into(), E.into())
    }

    fn run(
        vf: &mut Verifier,
        sf: &SignedFrame,
        list: Vec<Device>,
        now: u64,
    ) -> Result<Verified, WireError> {
        vf.check(sf, &|id| list.iter().find(|d| d.id == id).cloned(), now)
    }

    #[test]
    fn valid_frame_verifies() {
        let t = TestDevice::generate();
        let sf = t.frame(&ok_frame(&t, 1));
        let r = run(&mut v(), &sf, vec![dev_for(&t, DeviceState::Active)], NOW).unwrap();
        assert_eq!(r.level, Level::Signed);
        assert_eq!(r.device_id, t.device_id());
        assert_eq!(r.owner_user, "alice");
        assert_eq!(r.frame.action, "box.list");
    }

    #[test]
    fn unknown_device() {
        let t = TestDevice::generate();
        let sf = t.frame(&ok_frame(&t, 1));
        let mut vf = v();
        assert_eq!(
            run(&mut vf, &sf, vec![], NOW).unwrap_err(),
            WireError::UnknownDevice
        );
        assert_eq!(vf.replay.len(), 0);
    }

    #[test]
    fn pending_device_is_refused() {
        let t = TestDevice::generate();
        let sf = t.frame(&ok_frame(&t, 1));
        let mut vf = v();
        assert_eq!(
            run(&mut vf, &sf, vec![dev_for(&t, DeviceState::Pending)], NOW).unwrap_err(),
            WireError::DevicePending
        );
        assert_eq!(vf.replay.len(), 0);
    }

    #[test]
    fn pending_device_with_bad_signature_is_bad_signature() {
        let t = TestDevice::generate();
        let mut sf = t.frame(&ok_frame(&t, 1));
        sf.sig = b64::enc(&[7u8; 64]);
        assert_eq!(
            run(&mut v(), &sf, vec![dev_for(&t, DeviceState::Pending)], NOW).unwrap_err(),
            WireError::BadSignature
        );
    }

    #[test]
    fn revoked_device_is_unknown() {
        let t = TestDevice::generate();
        let sf = t.frame(&ok_frame(&t, 1));
        assert_eq!(
            run(&mut v(), &sf, vec![dev_for(&t, DeviceState::Revoked)], NOW).unwrap_err(),
            WireError::UnknownDevice
        );
    }

    #[test]
    fn bad_signature_does_not_burn_the_nonce() {
        let t = TestDevice::generate();
        let list = vec![dev_for(&t, DeviceState::Active)];
        let good = t.frame(&ok_frame(&t, 1));
        let mut bad = good.clone();
        bad.sig = b64::enc(&[9u8; 64]);
        let mut vf = v();
        assert_eq!(
            run(&mut vf, &bad, list.clone(), NOW).unwrap_err(),
            WireError::BadSignature
        );
        assert_eq!(vf.replay.len(), 0);
        assert!(run(&mut vf, &good, list, NOW).is_ok());
        assert_eq!(vf.replay.len(), 1);
    }

    #[test]
    fn malformed_body_and_signature() {
        let t = TestDevice::generate();
        let list = vec![dev_for(&t, DeviceState::Active)];
        let mut sf = t.frame(&ok_frame(&t, 1));
        sf.sig = "short".into();
        assert!(matches!(
            run(&mut v(), &sf, list.clone(), NOW),
            Err(WireError::Malformed(_))
        ));
        let sf = SignedFrame {
            body: "{}".into(),
            sig: b64::enc(&[0u8; 64]),
            touch: None,
        };
        assert!(matches!(
            run(&mut v(), &sf, list, NOW),
            Err(WireError::Malformed(_))
        ));
    }

    #[test]
    fn a_key_that_is_not_the_stored_devices_is_refused_and_burns_nothing() {
        let a = TestDevice::generate();
        let b = TestDevice::generate();
        // Frame claims A's id but is signed by B; A is stored with A's key.
        let f = ok_frame(&a, 1);
        let body = serde_json::to_string(&f).unwrap();
        let sf = SignedFrame {
            sig: b.sign_body(&body),
            body,
            touch: None,
        };
        let mut vf = v();
        assert_eq!(
            run(&mut vf, &sf, vec![dev_for(&a, DeviceState::Active)], NOW).unwrap_err(),
            WireError::BadSignature
        );
        assert_eq!(vf.replay.len(), 0);
        // Stored under A's id but holding B's key: the id does not match the key.
        let mut swapped = dev_for(&a, DeviceState::Active);
        swapped.public_key = b64::enc(&b.public_raw());
        let sf = b.frame(&f);
        assert_eq!(
            run(&mut vf, &sf, vec![swapped], NOW).unwrap_err(),
            WireError::UnknownDevice
        );
        assert_eq!(vf.replay.len(), 0);
    }

    #[test]
    fn wrong_machine() {
        let t = TestDevice::generate();
        let mut f = ok_frame(&t, 1);
        f.machine_id = "other".into();
        assert_eq!(
            run(
                &mut v(),
                &t.frame(&f),
                vec![dev_for(&t, DeviceState::Active)],
                NOW
            )
            .unwrap_err(),
            WireError::WrongMachine
        );
    }

    #[test]
    fn old_epoch_is_stale() {
        let t = TestDevice::generate();
        let mut f = ok_frame(&t, 1);
        f.epoch = "e-0".into();
        assert_eq!(
            run(
                &mut v(),
                &t.frame(&f),
                vec![dev_for(&t, DeviceState::Active)],
                NOW
            )
            .unwrap_err(),
            WireError::StaleEpoch
        );
    }

    #[test]
    fn expired_at_boundary() {
        let t = TestDevice::generate();
        let list = vec![dev_for(&t, DeviceState::Active)];
        let sf = t.frame(&frame(&t, "box.list", 1, NOW - 50, NOW));
        let mut vf = v();
        assert_eq!(
            run(&mut vf, &sf, list.clone(), NOW).unwrap_err(),
            WireError::Expired
        );
        assert_eq!(vf.replay.len(), 0);
        assert!(run(&mut vf, &sf, list, NOW - 1).is_ok());
    }

    #[test]
    fn future_beyond_skew() {
        let t = TestDevice::generate();
        let list = vec![dev_for(&t, DeviceState::Active)];
        let late = t.frame(&frame(&t, "box.list", 1, NOW + 61, NOW + 100));
        assert_eq!(
            run(&mut v(), &late, list.clone(), NOW).unwrap_err(),
            WireError::NotYetValid
        );
        let edge = t.frame(&frame(&t, "box.list", 2, NOW + 60, NOW + 100));
        assert!(run(&mut v(), &edge, list, NOW).is_ok());
    }

    #[test]
    fn replay_is_refused() {
        let t = TestDevice::generate();
        let list = vec![dev_for(&t, DeviceState::Active)];
        let sf = t.frame(&ok_frame(&t, 1));
        let mut vf = v();
        assert!(run(&mut vf, &sf, list.clone(), NOW).is_ok());
        assert_eq!(
            run(&mut vf, &sf, list, NOW + 1).unwrap_err(),
            WireError::Replayed
        );
    }

    #[test]
    fn same_nonce_other_device_is_fine() {
        let a = TestDevice::generate();
        let b = TestDevice::generate();
        let list = vec![
            dev_for(&a, DeviceState::Active),
            dev_for(&b, DeviceState::Active),
        ];
        let mut vf = v();
        assert!(run(&mut vf, &a.frame(&ok_frame(&a, 1)), list.clone(), NOW).is_ok());
        assert!(run(&mut vf, &b.frame(&ok_frame(&b, 1)), list, NOW).is_ok());
        assert_eq!(vf.replay.len(), 2);
    }

    #[test]
    fn full_cache_refuses_instead_of_evicting() {
        let t = TestDevice::generate();
        let list = vec![dev_for(&t, DeviceState::Active)];
        let mut vf = v();
        vf.replay = ReplayCache::new(2);
        let f = |n| t.frame(&frame(&t, "box.list", n, NOW, NOW + 100));
        assert!(run(&mut vf, &f(1), list.clone(), NOW).is_ok());
        assert!(run(&mut vf, &f(2), list.clone(), NOW).is_ok());
        assert_eq!(
            run(&mut vf, &f(3), list.clone(), NOW).unwrap_err(),
            WireError::Busy
        );
        assert_eq!(vf.replay.len(), 2);
        // The first two are still remembered while live.
        assert_eq!(
            run(&mut vf, &f(1), list.clone(), NOW + 1).unwrap_err(),
            WireError::Replayed
        );
        // Frame 3 is valid at a later time once the first two have expired.
        let late = t.frame(&frame(&t, "box.list", 3, NOW + 100, NOW + 200));
        assert!(run(&mut vf, &late, list, NOW + 100).is_ok());
        assert_eq!(vf.replay.len(), 1);
    }

    #[test]
    fn machine_only_action_is_refused_after_signature() {
        let t = TestDevice::generate();
        let list = vec![dev_for(&t, DeviceState::Active)];
        let mut vf = v();
        let sf = t.frame(&frame(&t, "policy.reload", 1, NOW, NOW + 100));
        assert_eq!(
            run(&mut vf, &sf, list.clone(), NOW).unwrap_err(),
            WireError::MachineOnly("policy.reload".into())
        );
        assert_eq!(vf.replay.len(), 0);
        for a in ["lockdown.off", "workspace.revoke"] {
            let sf = t.frame(&frame(&t, a, 2, NOW, NOW + 100));
            assert_eq!(
                run(&mut vf, &sf, list.clone(), NOW).unwrap_err(),
                WireError::MachineOnly(a.into())
            );
        }
        assert_eq!(vf.replay.len(), 0);
    }

    #[test]
    fn unknown_action_is_refused() {
        let t = TestDevice::generate();
        let list = vec![dev_for(&t, DeviceState::Active)];
        let mut vf = v();
        for a in ["nope.nothing", "box.stopp", "box"] {
            let sf = t.frame(&frame(&t, a, 1, NOW, NOW + 100));
            assert_eq!(
                run(&mut vf, &sf, list.clone(), NOW).unwrap_err(),
                WireError::UnknownAction(a.into())
            );
        }
        // Near-miss names the body parser already refuses never reach the table.
        for a in ["box.stop ", ""] {
            let sf = t.frame(&frame(&t, a, 2, NOW, NOW + 100));
            assert!(matches!(
                run(&mut vf, &sf, list.clone(), NOW),
                Err(WireError::Malformed(_))
            ));
        }
        assert_eq!(vf.replay.len(), 0);
    }

    #[test]
    fn new_epoch_is_22_chars_and_differs() {
        let rng = ring::rand::SystemRandom::new();
        let (a, b) = (new_epoch(&rng), new_epoch(&rng));
        assert_eq!(a.len(), 22);
        assert_ne!(a, b);
    }
}
