//! The Workspace link's state in the daemon (plan 29): the machine key, the
//! paired devices, the open pairing offers and the frame verifier.
//!
//! Files, under `<state_dir>/state/workspace/` (mode 0600 in a 0700 dir):
//! - `machine.p256`: the machine's P-256 key, PKCS#8. Created once with
//!   `O_EXCL`; an existing file is never overwritten, not even when it does
//!   not parse.
//! - `devices.json`: the paired devices, replaced atomically.
//!
//! A file that cannot be used leaves the Workspace *locked*: no device is
//! trusted, pairing is refused and nothing is written, so the file the owner
//! may want to repair is kept as it is.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use ring::rand::SystemRandom;
use saiife_wire::device::{Device, DeviceList, DeviceState};
use saiife_wire::frame::{SignedFrame, FRAME_VERSION};
use saiife_wire::pair::{Offers, PairOffer, PairRequest, PairStatus};
use saiife_wire::sig::MachineKey;
use saiife_wire::verify::{new_epoch, Verified, Verifier};
use saiife_wire::{b64, WireError};

pub const KEY_FILE: &str = "machine.p256";
pub const DEVICES_FILE: &str = "devices.json";
/// Far more than a person's devices; a larger file is not ours.
const MAX_FILE_BYTES: u64 = 1024 * 1024;
/// Domain of the signature a machine gives a hub on connect.
pub const HUB_HELLO_DOMAIN: &[u8] = b"saiife-hub-hello-v1\n";

/// `<state_dir>/state/workspace`.
pub fn dir_in(state_dir: &Path) -> PathBuf {
    state_dir.join("state").join("workspace")
}

/// Seconds since the epoch (the daemon's clock, including a debug build's
/// `SAIIFE_DAEMON_NOW`).
pub fn now_secs() -> u64 {
    crate::import_backup::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// What the machine key is asked to sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignPurpose {
    /// The seal handshake (`saiife_wire::seal::HANDSHAKE_DOMAIN`).
    Seal,
    /// The hub hello (`b"saiife-hub-hello-v1\n"`).
    HubHello,
}

impl SignPurpose {
    fn domain(self) -> &'static [u8] {
        match self {
            SignPurpose::Seal => saiife_wire::seal::HANDSHAKE_DOMAIN,
            SignPurpose::HubHello => HUB_HELLO_DOMAIN,
        }
    }
}

struct Inner {
    devices: DeviceList,
    offers: Offers,
    verifier: Verifier,
    /// A revocation is in effect in memory but `devices.json` does not have
    /// it yet; the next successful save (any write, or a retried revoke)
    /// clears it.
    dirty: bool,
    /// Who began each open offer: `pair_id -> (owner_user, expires_at)`.
    owners: std::collections::HashMap<String, (String, u64)>,
}

pub struct Workspace {
    machine: MachineKey,
    rng: SystemRandom,
    inner: Mutex<Inner>,
    /// Where the state lives; `None` for [`Workspace::memory`].
    dir: Option<PathBuf>,
    /// Why this Workspace trusts no device and writes nothing.
    locked: Option<String>,
    /// Frames refused before their signature verified (never recorded;
    /// `status` shows the count as `workspace.refused_unsigned`).
    unsigned: AtomicU64,
    /// Tests: replaces [`now_secs`] for this Workspace.
    clock: Option<Clock>,
}

/// A replacement clock, seconds since the epoch.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

impl Workspace {
    /// Loads or creates the machine key and loads `devices.json`. A file that
    /// cannot be used is kept untouched and returned as the warning; the
    /// Workspace then trusts no device, refuses pairing and writes nothing
    /// (a bad key file is served by an ephemeral in-memory key, so no frame
    /// verifies against it).
    pub fn open(dir: PathBuf) -> (Workspace, Option<String>) {
        let rng = SystemRandom::new();
        let mut locked = None;
        let machine = match load_or_create_key(&dir, &rng) {
            Ok(k) => k,
            Err(why) => {
                locked = Some(why);
                MachineKey::generate(&rng)
                    .expect("system random source failed while generating a key")
                    .0
            }
        };
        let mut devices = DeviceList::default();
        if locked.is_none() {
            match load_devices(&dir.join(DEVICES_FILE)) {
                Ok(d) => devices = d,
                Err(why) => locked = Some(why),
            }
        }
        let ws = Workspace::build(machine, rng, devices, Some(dir), locked.clone());
        (ws, locked)
    }

    /// No files: a fresh key and no devices. For tests.
    pub fn memory() -> Workspace {
        let rng = SystemRandom::new();
        let machine = MachineKey::generate(&rng)
            .expect("system random source failed while generating a key")
            .0;
        Workspace::build(machine, rng, DeviceList::default(), None, None)
    }

    fn build(
        machine: MachineKey,
        rng: SystemRandom,
        devices: DeviceList,
        dir: Option<PathBuf>,
        locked: Option<String>,
    ) -> Workspace {
        let verifier = Verifier::new(machine.machine_id(), new_epoch(&rng));
        Workspace {
            machine,
            rng,
            inner: Mutex::new(Inner {
                devices,
                offers: Offers::new(),
                verifier,
                dirty: false,
                owners: Default::default(),
            }),
            dir,
            locked,
            unsigned: AtomicU64::new(0),
            clock: None,
        }
    }

    /// This Workspace reads the time from `clock` (tests).
    pub fn with_clock(mut self, clock: Clock) -> Workspace {
        self.clock = Some(clock);
        self
    }

    /// The time the Workspace ops use: [`now_secs`], or the test clock.
    pub fn now(&self) -> u64 {
        match &self.clock {
            Some(c) => c(),
            None => now_secs(),
        }
    }

    /// Counts a frame refused before its signature verified.
    pub fn note_unsigned(&self) {
        self.unsigned.fetch_add(1, Ordering::Relaxed);
    }

    /// Frames refused before their signature verified, since this opened.
    pub fn refused_unsigned(&self) -> u64 {
        self.unsigned.load(Ordering::Relaxed)
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn machine_id(&self) -> String {
        self.machine.machine_id()
    }

    /// `{machine_id, machine_pub, epoch, frame_version}` (the key as b64u).
    pub fn hello(&self) -> serde_json::Value {
        serde_json::json!({
            "machine_id": self.machine.machine_id(),
            "machine_pub": b64::enc(&self.machine.public_raw()),
            "epoch": self.inner().verifier.epoch,
            "frame_version": FRAME_VERSION,
        })
    }

    pub fn device(&self, id: &str) -> Option<Device> {
        self.inner().devices.get(id).cloned()
    }

    pub fn devices(&self) -> Vec<Device> {
        let mut v = self.inner().devices.devices.clone();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    }

    fn unlocked(&self) -> Result<(), WireError> {
        match &self.locked {
            Some(why) => Err(WireError::Store(format!("the Workspace is locked: {why}"))),
            None => Ok(()),
        }
    }

    /// Opens a pairing offer owned by `owner_user` (the peer that asked for
    /// it; the link never names an owner).
    pub fn begin_pair(
        &self,
        owner_user: &str,
        label: Option<String>,
        now: u64,
    ) -> Result<PairOffer, WireError> {
        self.unlocked()?;
        let mut g = self.inner();
        let offer = g
            .offers
            .open(&self.machine, owner_user, label, &self.rng, now)?;
        g.owners.retain(|_, (_, exp)| now < *exp);
        g.owners.insert(
            offer.pair_id.clone(),
            (owner_user.to_string(), offer.expires_at),
        );
        Ok(offer)
    }

    /// Who began the offer `pair_id`, while it is open.
    pub fn offer_owner(&self, pair_id: &str, now: u64) -> Option<String> {
        self.inner()
            .owners
            .get(pair_id)
            .filter(|(_, exp)| now < *exp)
            .map(|(o, _)| o.clone())
    }

    /// A device answers an offer. The device is Pending (not in the list)
    /// until [`Workspace::confirm_pair`] accepts it; the short code is shown
    /// on both screens.
    pub fn finish_pair(&self, req: &PairRequest, now: u64) -> Result<(Device, String), WireError> {
        self.unlocked()?;
        let mut g = self.inner();
        let Inner {
            devices, offers, ..
        } = &mut *g;
        // A revoked key never comes back (the tombstone must stay): the
        // browser makes a new key. `Offers::request` only knows Active and
        // Pending.
        let key = b64::dec_n::<65>(&req.device_pub)?;
        if devices
            .get(&saiife_wire::sig::device_id_of(&key))
            .is_some_and(|d| d.state == DeviceState::Revoked)
        {
            return Err(WireError::Malformed(
                "this device key was revoked; make a new key".into(),
            ));
        }
        let device = offers.request(req, devices, now)?;
        match offers.status(&req.pair_id, now) {
            PairStatus::Requested { short_code, .. } => Ok((device, short_code)),
            _ => Err(WireError::PairExpired),
        }
    }

    pub fn pair_status(&self, pair_id: &str, now: u64) -> PairStatus {
        self.inner().offers.status(pair_id, now)
    }

    /// The owner's decision on a requested device. Accept: the device becomes
    /// Active and `devices.json` is saved (on a failed save the list does not
    /// change and the offer is spent). Reject: the offer is dropped. `Ok(None)` when
    /// there is no requested device under `pair_id` or it was rejected.
    pub fn confirm_pair(
        &self,
        pair_id: &str,
        accept: bool,
        now: u64,
    ) -> io::Result<Option<Device>> {
        let mut g = self.inner();
        if !matches!(g.offers.status(pair_id, now), PairStatus::Requested { .. }) {
            return Ok(None);
        }
        if !accept {
            let _ = g.offers.take(pair_id, now);
            return Ok(None);
        }
        self.unlocked().map_err(io::Error::other)?;
        let Some(mut device) = g.offers.take(pair_id, now) else {
            return Ok(None);
        };
        device.state = DeviceState::Active;
        let mut next = g.devices.clone();
        next.upsert(device.clone());
        // A failed save leaves the list as it was; the offer is spent, so
        // the device pairs again.
        // `next` carries any unsaved revocation too, so this save persists it.
        self.save(&next)?;
        g.devices = next;
        g.dirty = false;
        Ok(Some(device))
    }

    /// Marks a device Revoked (the tombstone stays), in memory first and
    /// unconditionally (frames from it are refused at once, even when the
    /// Workspace is locked or the save fails), then saves the whole list.
    ///
    /// Returns `Ok(true)` when it revoked the device or saved a revocation
    /// that an earlier call could not write (a retry), `Ok(false)` when the
    /// device is unknown or already revoked and saved. If the save fails the
    /// error says the revocation is in effect now but not saved, and the
    /// next successful write (or a retry) persists it.
    pub fn revoke(&self, id: &str) -> io::Result<bool> {
        let mut g = self.inner();
        let changed = g.devices.revoke(id);
        let retry = !changed
            && g.dirty
            && g.devices
                .get(id)
                .is_some_and(|d| d.state == DeviceState::Revoked);
        if !changed && !retry {
            return Ok(false);
        }
        g.dirty = true;
        let saved = self
            .unlocked()
            .map_err(|e| io::Error::other(e.to_string()))
            .and_then(|()| self.save(&g.devices));
        match saved {
            Ok(()) => {
                g.dirty = false;
                Ok(true)
            }
            Err(e) => Err(io::Error::other(format!(
                "device {id} is revoked now, but the revocation is NOT saved and will \
                 come back after a daemon restart; run `saiife workspace revoke {id}` \
                 again once the problem is fixed ({e})"
            ))),
        }
    }

    /// Whether `id` is revoked and nothing about it waits to be saved (a
    /// revoke of it changes nothing).
    pub fn revoked_and_saved(&self, id: &str) -> bool {
        let g = self.inner();
        !g.dirty
            && g.devices
                .get(id)
                .is_some_and(|d| d.state == DeviceState::Revoked)
    }

    /// The gate every frame passes (`saiife_wire::verify::Verifier::check`).
    pub fn check(&self, sf: &SignedFrame, now: u64) -> Result<Verified, WireError> {
        let mut g = self.inner();
        let Inner {
            devices, verifier, ..
        } = &mut *g;
        verifier.check(sf, &|id| devices.get(id).cloned(), now)
    }

    /// Whether a bad file keeps this Workspace from trusting anything. A
    /// locked Workspace has only a throwaway key: it refuses to sign.
    pub fn locked(&self) -> bool {
        self.locked.is_some()
    }

    /// The raw signing primitive: `domain(purpose) || data` signed with the
    /// machine key. What may be signed is the caller's rule. Refused with
    /// `WireError::Store` ("the Workspace is locked") while [`locked`]
    /// (`Workspace::locked`).
    pub fn sign(&self, purpose: SignPurpose, data: &[u8]) -> Result<[u8; 64], WireError> {
        self.unlocked()?;
        Ok(self.machine.sign(purpose.domain(), data, &self.rng))
    }

    fn save(&self, list: &DeviceList) -> io::Result<()> {
        match &self.dir {
            Some(dir) => write_atomic(dir, DEVICES_FILE, &list.to_bytes()),
            None => Ok(()),
        }
    }
}

fn load_or_create_key(dir: &Path, rng: &SystemRandom) -> Result<MachineKey, String> {
    let path = dir.join(KEY_FILE);
    for _ in 0..2 {
        key_file_ok(&path)?;
        match read_capped(&path) {
            Ok(bytes) => {
                return MachineKey::from_pkcs8(&bytes, rng).map_err(|_| {
                    format!(
                        "{} is not a PKCS#8 P-256 key (kept as it is)",
                        path.display()
                    )
                });
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        }
        let (key, pkcs8) = MachineKey::generate(rng).map_err(|e| e.to_string())?;
        crate::fsx::create_private_dirs(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        match write_new(&path, &pkcs8) {
            Ok(()) => return Ok(key),
            // Another opener won the race: read its key.
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(format!("cannot write {}: {e}", path.display())),
        }
    }
    Err(format!("cannot settle on a key in {}", path.display()))
}

/// An existing key file must be a regular file (not a link) and, on Unix,
/// no broader than 0600. A missing file is fine (it is created).
fn key_file_ok(path: &Path) -> Result<(), String> {
    let md = match std::fs::symlink_metadata(path) {
        Ok(md) => md,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    if !md.file_type().is_file() {
        return Err(format!(
            "{} is not a regular file (kept as it is)",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if md.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "{} is readable by others, its mode is broader than 0600 (kept as it is)",
                path.display()
            ));
        }
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = crate::fsx::new_private_file(path)?;
    let done = f.write_all(bytes).and_then(|_| f.sync_all());
    if let Err(e) = done {
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    drop(f);
    path.parent().map_or(Ok(()), crate::fsx::sync_dir)
}

fn read_capped(path: &Path) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let f = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    f.take(MAX_FILE_BYTES + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_FILE_BYTES {
        return Err(io::Error::other("file too large"));
    }
    Ok(buf)
}

fn load_devices(path: &Path) -> Result<DeviceList, String> {
    match read_capped(path) {
        Ok(bytes) => DeviceList::parse(&bytes)
            .map_err(|e| format!("{} is not usable ({e}; kept as it is)", path.display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(DeviceList::default()),
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

/// Temp file in the same directory (new, 0600), then rename over `name`.
fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    crate::fsx::create_private_dirs(dir)?;
    let tmp = dir.join(format!(".{name}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let staged = (|| {
        let mut f = crate::fsx::new_private_file(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, dir.join(name))
    })();
    if let Err(e) = staged {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    crate::fsx::sync_dir(dir)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use saiife_wire::pair::proof;
    use saiife_wire::sig::TestDevice;
    use std::os::unix::fs::PermissionsExt;

    const NOW: u64 = 1_000;

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    fn request(o: &PairOffer, d: &TestDevice, label: &str) -> PairRequest {
        let pubkey = d.public_raw();
        PairRequest {
            pair_id: o.pair_id.clone(),
            device_pub: b64::enc(&pubkey),
            label: label.into(),
            proof: b64::enc(&proof(&o.secret, &o.pair_id, &pubkey)),
        }
    }

    fn pair(ws: &Workspace, d: &TestDevice) -> (PairOffer, String) {
        let o = ws.begin_pair("alice", None, NOW).unwrap();
        let (dev, code) = ws.finish_pair(&request(&o, d, "phone"), NOW).unwrap();
        assert_eq!(dev.state, DeviceState::Pending);
        (o, code)
    }

    #[test]
    fn creates_key_once() {
        let t = tempfile::tempdir().unwrap();
        let dir = dir_in(t.path());
        let (a, w) = Workspace::open(dir.clone());
        assert!(w.is_none());
        assert_eq!(mode(&dir.join(KEY_FILE)), 0o600);
        let (b, w) = Workspace::open(dir);
        assert!(w.is_none());
        assert_eq!(a.machine_id(), b.machine_id());
    }

    #[test]
    fn does_not_overwrite_a_key() {
        let t = tempfile::tempdir().unwrap();
        let dir = dir_in(t.path());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(KEY_FILE), b"not a key").unwrap();
        std::fs::set_permissions(dir.join(KEY_FILE), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        // A valid device list next to the bad key: still trusted by nobody.
        let d = TestDevice::generate();
        let list = DeviceList {
            v: 1,
            devices: vec![Device {
                id: d.device_id(),
                label: "phone".into(),
                owner_user: "alice".into(),
                public_key: b64::enc(&d.public_raw()),
                state: DeviceState::Active,
                added_at: 1,
                touch_credentials: vec![],
            }],
        };
        std::fs::write(dir.join(DEVICES_FILE), list.to_bytes()).unwrap();
        let (ws, warning) = Workspace::open(dir.clone());
        assert!(warning.unwrap().contains("PKCS#8"));
        assert_eq!(std::fs::read(dir.join(KEY_FILE)).unwrap(), b"not a key");
        assert!(ws.devices().is_empty());
        assert!(ws.device(&d.device_id()).is_none());
        assert!(ws.locked());
        assert!(matches!(
            ws.sign(SignPurpose::HubHello, b"x"),
            Err(WireError::Store(_))
        ));
        let e = ws.begin_pair("alice", None, NOW).unwrap_err();
        assert!(matches!(e, WireError::Store(_)));
    }

    #[test]
    fn epoch_changes_on_open() {
        let t = tempfile::tempdir().unwrap();
        let dir = dir_in(t.path());
        let (a, _) = Workspace::open(dir.clone());
        let (b, _) = Workspace::open(dir);
        assert_ne!(a.hello()["epoch"], b.hello()["epoch"]);
        assert_eq!(a.hello()["machine_id"], b.hello()["machine_id"]);
        assert_eq!(a.hello()["frame_version"], 1);
    }

    #[test]
    fn pair_flow_persists() {
        let t = tempfile::tempdir().unwrap();
        let dir = dir_in(t.path());
        let (ws, _) = Workspace::open(dir.clone());
        let d = TestDevice::generate();
        let (o, code) = pair(&ws, &d);
        assert_eq!(code.len(), 7);
        assert!(ws.devices().is_empty(), "pending is not trusted");
        let dev = ws.confirm_pair(&o.pair_id, true, NOW).unwrap().unwrap();
        assert_eq!(dev.owner_user, "alice");
        assert_eq!(dev.state, DeviceState::Active);
        assert_eq!(mode(&dir.join(DEVICES_FILE)), 0o600);
        let (again, w) = Workspace::open(dir);
        assert!(w.is_none());
        assert_eq!(
            again.device(&d.device_id()).unwrap().state,
            DeviceState::Active
        );
    }

    #[test]
    fn reject_leaves_no_device() {
        let t = tempfile::tempdir().unwrap();
        let dir = dir_in(t.path());
        let (ws, _) = Workspace::open(dir.clone());
        let d = TestDevice::generate();
        let (o, _) = pair(&ws, &d);
        assert!(ws.confirm_pair(&o.pair_id, false, NOW).unwrap().is_none());
        assert!(ws.devices().is_empty());
        assert_eq!(ws.pair_status(&o.pair_id, NOW), PairStatus::Expired);
        assert!(!dir.join(DEVICES_FILE).exists());
    }

    #[test]
    fn revoke_persists() {
        let t = tempfile::tempdir().unwrap();
        let dir = dir_in(t.path());
        let (ws, _) = Workspace::open(dir.clone());
        let d = TestDevice::generate();
        let (o, _) = pair(&ws, &d);
        ws.confirm_pair(&o.pair_id, true, NOW).unwrap();
        assert!(ws.revoke(&d.device_id()).unwrap());
        assert!(!ws.revoke(&d.device_id()).unwrap());
        assert!(!ws.revoke("d-unknown").unwrap());
        let (again, _) = Workspace::open(dir);
        assert_eq!(
            again.device(&d.device_id()).unwrap().state,
            DeviceState::Revoked
        );
    }

    #[test]
    fn bad_devices_file_trusts_nobody() {
        let t = tempfile::tempdir().unwrap();
        let dir = dir_in(t.path());
        let (ws, _) = Workspace::open(dir.clone());
        let d = TestDevice::generate();
        let (o, _) = pair(&ws, &d);
        ws.confirm_pair(&o.pair_id, true, NOW).unwrap();
        drop(ws);
        std::fs::write(dir.join(DEVICES_FILE), b"{ not json").unwrap();
        let (again, warning) = Workspace::open(dir.clone());
        assert!(warning.unwrap().contains(DEVICES_FILE));
        assert!(again.devices().is_empty());
        assert!(again.device(&d.device_id()).is_none());
        assert!(again.begin_pair("alice", None, NOW).is_err());
        assert_eq!(
            std::fs::read(dir.join(DEVICES_FILE)).unwrap(),
            b"{ not json"
        );
    }

    #[test]
    fn paired_device_passes_check_and_revoked_does_not() {
        let t = tempfile::tempdir().unwrap();
        let (ws, _) = Workspace::open(dir_in(t.path()));
        let d = TestDevice::generate();
        let (o, _) = pair(&ws, &d);
        ws.confirm_pair(&o.pair_id, true, NOW).unwrap();
        let h = ws.hello();
        let f = saiife_wire::frame::Frame {
            v: 1,
            machine_id: h["machine_id"].as_str().unwrap().into(),
            epoch: h["epoch"].as_str().unwrap().into(),
            device_id: d.device_id(),
            action: "box.list".into(),
            args: Default::default(),
            nonce: b64::enc(&[7; 16]),
            issued_at: NOW,
            expires_at: NOW + 100,
        };
        let v = ws.check(&d.frame(&f), NOW).unwrap();
        assert_eq!(v.owner_user, "alice");
        ws.revoke(&d.device_id()).unwrap();
        let mut g = f.clone();
        g.nonce = b64::enc(&[8; 16]);
        assert!(matches!(
            ws.check(&d.frame(&g), NOW),
            Err(WireError::UnknownDevice)
        ));
    }

    #[test]
    fn sign_uses_the_purpose_domain() {
        let ws = Workspace::memory();
        let h = ws.hello();
        let pubkey = b64::dec_n::<65>(h["machine_pub"].as_str().unwrap()).unwrap();
        let sig = ws.sign(SignPurpose::HubHello, b"x").unwrap();
        assert!(saiife_wire::sig::verify_p256_domain(
            &pubkey,
            HUB_HELLO_DOMAIN,
            b"x",
            &sig
        ));
        let sig = ws.sign(SignPurpose::Seal, b"x").unwrap();
        assert!(saiife_wire::sig::verify_p256_domain(
            &pubkey,
            saiife_wire::seal::HANDSHAKE_DOMAIN,
            b"x",
            &sig
        ));
        assert!(!saiife_wire::sig::verify_p256_domain(
            &pubkey,
            HUB_HELLO_DOMAIN,
            b"x",
            &sig
        ));
    }

    fn active(ws: &Workspace, d: &TestDevice) {
        let (o, _) = pair(ws, d);
        ws.confirm_pair(&o.pair_id, true, NOW).unwrap();
    }

    fn frame_of(ws: &Workspace, d: &TestDevice, nonce: u8) -> SignedFrame {
        let h = ws.hello();
        d.frame(&saiife_wire::frame::Frame {
            v: 1,
            machine_id: h["machine_id"].as_str().unwrap().into(),
            epoch: h["epoch"].as_str().unwrap().into(),
            device_id: d.device_id(),
            action: "box.list".into(),
            args: Default::default(),
            nonce: b64::enc(&[nonce; 16]),
            issued_at: NOW,
            expires_at: NOW + 100,
        })
    }

    #[test]
    fn a_failed_save_still_revokes() {
        let t = tempfile::tempdir().unwrap();
        let dir = dir_in(t.path());
        let (ws, _) = Workspace::open(dir.clone());
        let d = TestDevice::generate();
        active(&ws, &d);
        ws.check(&frame_of(&ws, &d, 1), NOW).unwrap();
        // A directory where the temp file goes: the save cannot be staged.
        let blocker = dir.join(format!(".{DEVICES_FILE}.tmp"));
        std::fs::create_dir(&blocker).unwrap();
        let e = ws.revoke(&d.device_id()).unwrap_err().to_string();
        assert!(e.contains("revoked now") && e.contains("NOT saved"), "{e}");
        assert!(
            e.contains("restart") && e.contains("saiife workspace revoke"),
            "{e}"
        );
        // In effect at once.
        assert!(matches!(
            ws.check(&frame_of(&ws, &d, 2), NOW),
            Err(WireError::UnknownDevice)
        ));
        assert_eq!(
            ws.device(&d.device_id()).unwrap().state,
            DeviceState::Revoked
        );
        // The file still has the old state; a retry persists it.
        let (old, _) = Workspace::open(dir.clone());
        assert_eq!(
            old.device(&d.device_id()).unwrap().state,
            DeviceState::Active
        );
        assert!(ws.revoke(&d.device_id()).is_err());
        std::fs::remove_dir(&blocker).unwrap();
        assert!(ws.revoke(&d.device_id()).unwrap(), "the retry saved it");
        assert!(
            !ws.revoke(&d.device_id()).unwrap(),
            "now nothing is pending"
        );
        let (again, _) = Workspace::open(dir);
        assert_eq!(
            again.device(&d.device_id()).unwrap().state,
            DeviceState::Revoked
        );
    }

    #[test]
    fn a_later_write_persists_an_unsaved_revocation() {
        let t = tempfile::tempdir().unwrap();
        let dir = dir_in(t.path());
        let (ws, _) = Workspace::open(dir.clone());
        let (a, b) = (TestDevice::generate(), TestDevice::generate());
        active(&ws, &a);
        let blocker = dir.join(format!(".{DEVICES_FILE}.tmp"));
        std::fs::create_dir(&blocker).unwrap();
        assert!(ws.revoke(&a.device_id()).is_err());
        std::fs::remove_dir(&blocker).unwrap();
        active(&ws, &b);
        let (again, _) = Workspace::open(dir);
        assert_eq!(
            again.device(&a.device_id()).unwrap().state,
            DeviceState::Revoked
        );
        assert_eq!(
            again.device(&b.device_id()).unwrap().state,
            DeviceState::Active
        );
    }

    #[test]
    fn revoked_key_cannot_pair_again() {
        let t = tempfile::tempdir().unwrap();
        let (ws, _) = Workspace::open(dir_in(t.path()));
        let d = TestDevice::generate();
        active(&ws, &d);
        ws.revoke(&d.device_id()).unwrap();
        let o = ws.begin_pair("alice", None, NOW).unwrap();
        let e = ws.finish_pair(&request(&o, &d, "phone"), NOW).unwrap_err();
        assert!(matches!(e, WireError::Malformed(_)), "{e:?}");
        assert_eq!(
            ws.device(&d.device_id()).unwrap().state,
            DeviceState::Revoked
        );
        // The offer was not burned; a new key can use it.
        let n = TestDevice::generate();
        ws.finish_pair(&request(&o, &n, "new"), NOW).unwrap();
    }

    #[test]
    fn a_key_file_open_to_others_locks() {
        let t = tempfile::tempdir().unwrap();
        let dir = dir_in(t.path());
        let (a, _) = Workspace::open(dir.clone());
        drop(a);
        let p = dir.join(KEY_FILE);
        let before = std::fs::read(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let (ws, warning) = Workspace::open(dir.clone());
        assert!(warning.unwrap().contains("0600"));
        assert!(ws.locked());
        assert_eq!(std::fs::read(&p).unwrap(), before);
    }

    #[test]
    fn a_key_symlink_locks() {
        let t = tempfile::tempdir().unwrap();
        let dir = dir_in(t.path());
        let (a, _) = Workspace::open(dir.clone());
        drop(a);
        let real = dir.join("real.p256");
        std::fs::rename(dir.join(KEY_FILE), &real).unwrap();
        std::os::unix::fs::symlink(&real, dir.join(KEY_FILE)).unwrap();
        let (ws, warning) = Workspace::open(dir);
        assert!(warning.unwrap().contains("regular file"));
        assert!(ws.locked());
    }
}
