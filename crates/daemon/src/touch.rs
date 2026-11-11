//! The daemon's touch state (plan 26, Task 7): the instance id, the enrolled
//! credentials and the live single-use challenges.
//!
//! Files live in `<state>/state/touch/` (0700): `instance_id` (16 random
//! bytes, 0600, made on first start, so a browser assertion for one machine
//! never verifies on another) and `credentials.json`. An unreadable
//! credentials file means no credentials at all (every touch is
//! `touch_unavailable`) and, for as long as it stays unreadable, `add`,
//! `remove` and the counter save refuse to write, so the file is never
//! overwritten.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use ring::rand::{SecureRandom, SystemRandom};
use saiife_touch::{
    verify, ActionRecord, Assertion, Credential, CredentialFile, TouchClass, TouchError,
    TouchEvidence, CHALLENGE_TTL_SECS,
};

const DIR: &str = "touch";
const ID_FILE: &str = "instance_id";
const CREDS_FILE: &str = "credentials.json";
/// Live challenges in all, and per uid.
const MAX_LIVE: usize = 32;
const MAX_PER_UID: usize = 4;

/// Unix seconds now, from the daemon's clock (so a faked clock applies).
pub fn unix_now() -> u64 {
    crate::import_backup::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// What a challenge was issued for. The uid in the last three is the peer's.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum IssueKey {
    Approve(u64),
    Enrol(u32),
    Remove(u32),
    Test(u32),
}

/// One live challenge.
#[derive(Debug, Clone)]
pub struct Issued {
    pub uid: u32,
    pub class: TouchClass,
    pub nonce: [u8; 32],
    pub expires_at: u64,
    pub summary: String,
    pub fields: BTreeMap<String, String>,
}

pub struct TouchState {
    dir: PathBuf,
    instance_id: [u8; 16],
    /// Why the touch files could not be used: then nothing is written.
    unreadable: Option<String>,
    creds: Mutex<CredentialFile>,
    issued: Mutex<BTreeMap<IssueKey, Issued>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    // The system RNG failing is not recoverable.
    SystemRandom::new()
        .fill(&mut b)
        .expect("the system random source failed");
    b
}

fn make_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// Reads the instance id, or makes it (0600) the first time.
fn load_instance_id(path: &Path) -> io::Result<[u8; 16]> {
    use std::io::Write as _;
    match std::fs::read(path) {
        Ok(b) if b.len() == 16 => {
            let mut id = [0u8; 16];
            id.copy_from_slice(&b);
            return Ok(id);
        }
        Ok(_) => {} // Damaged: make a new one below.
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let id = random::<16>();
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(&id)?;
    f.sync_all()?;
    Ok(id)
}

impl TouchState {
    /// Opens (making it if need be) `<state_dir>/state/touch`. `Some(why)`
    /// when the directory or the credentials could not be used: there are
    /// then no credentials (fail closed) and nothing is written.
    pub fn open(state_dir: &Path) -> (TouchState, Option<String>) {
        let dir = state_dir.join("state").join(DIR);
        let mut unreadable = None;
        let mut creds = CredentialFile::default();
        let id = match make_dir(&dir).and_then(|()| load_instance_id(&dir.join(ID_FILE))) {
            Ok(id) => {
                match CredentialFile::load(&dir.join(CREDS_FILE)) {
                    Ok(f) => creds = f,
                    Err(e) => unreadable = Some(format!("touch credentials unreadable: {e}")),
                }
                id
            }
            Err(e) => {
                unreadable = Some(format!(
                    "{}: cannot use the touch directory: {e}",
                    dir.display()
                ));
                random()
            }
        };
        (
            TouchState {
                dir,
                instance_id: id,
                unreadable: unreadable.clone(),
                creds: Mutex::new(creds),
                issued: Mutex::new(BTreeMap::new()),
            },
            unreadable,
        )
    }

    pub fn instance_id(&self) -> [u8; 16] {
        self.instance_id
    }

    fn creds_path(&self) -> PathBuf {
        self.dir.join(CREDS_FILE)
    }

    /// The credentials of `uid`. Waits on the credentials lock, which a
    /// save holds across its fsync: call it from `spawn_blocking`.
    pub fn credentials_of(&self, uid: u32) -> Vec<Credential> {
        lock(&self.creds).of_uid(uid)
    }

    /// Every credential; blocks as [`TouchState::credentials_of`] does.
    pub fn all(&self) -> Vec<Credential> {
        lock(&self.creds).credentials.clone()
    }

    fn writable(&self) -> Result<(), String> {
        match &self.unreadable {
            Some(w) => Err(format!("touch devices are unavailable: {w}")),
            None => Ok(()),
        }
    }

    /// Issues a challenge for `key`, replacing one with the same key. The
    /// caps are counted without that entry, and a refused issue leaves it
    /// as it was.
    ///
    /// Callers on the runtime use `spawn_blocking`, as for every other
    /// method here (R14).
    pub fn issue(
        &self,
        key: IssueKey,
        uid: u32,
        class: TouchClass,
        summary: String,
        fields: BTreeMap<String, String>,
        now: u64,
    ) -> Result<Issued, String> {
        let mut m = lock(&self.issued);
        m.retain(|_, v| v.expires_at >= now);
        let others = || m.iter().filter(|(k, _)| **k != key).map(|(_, v)| v);
        if others().count() >= MAX_LIVE || others().filter(|v| v.uid == uid).count() >= MAX_PER_UID
        {
            return Err("too many touches in progress".into());
        }
        let it = Issued {
            uid,
            class,
            nonce: random(),
            expires_at: now.saturating_add(CHALLENGE_TTL_SECS),
            summary,
            fields,
        };
        m.insert(key, it.clone());
        Ok(it)
    }

    /// Spends the challenge of `key` and verifies `asr` against it and the
    /// credentials of `uid`. The entry is burned whatever the outcome. In
    /// order: no live entry or one past its expiry is `Expired`, another
    /// uid's is `Mismatch`, unwritable touch files are `Unavailable` (the
    /// counter could not be saved), then the verify. On success the new
    /// counter is saved before returning; a save failure refuses (fail
    /// closed).
    ///
    /// Blocks (the credentials lock is held across the fsync): call it from
    /// `spawn_blocking`.
    pub fn consume(
        &self,
        key: &IssueKey,
        uid: u32,
        build: impl FnOnce(&Issued) -> ActionRecord,
        asr: &Assertion,
        rp_id: &str,
        now: u64,
    ) -> Result<(TouchEvidence, ActionRecord), TouchError> {
        let entry = lock(&self.issued).remove(key).ok_or(TouchError::Expired)?;
        if entry.expires_at < now {
            return Err(TouchError::Expired);
        }
        if entry.uid != uid {
            return Err(TouchError::Mismatch);
        }
        self.writable().map_err(|_| TouchError::Unavailable)?;
        let record = build(&entry);
        // Held across the verify and the save: no lost counter update.
        let mut f = lock(&self.creds);
        let ev = verify(&f.of_uid(uid), &record, asr, rp_id, now)?;
        f.set_count(asr.credential_id(), ev.sign_count);
        f.save(&self.creds_path())
            .map_err(|_| TouchError::Unavailable)?;
        Ok((ev, record))
    }

    pub fn add(&self, c: Credential) -> Result<(), String> {
        self.writable()?;
        let mut f = lock(&self.creds);
        let mut next = f.clone();
        next.add(c)?;
        next.save(&self.creds_path())
            .map_err(|e| format!("cannot save the touch devices: {e}"))?;
        *f = next;
        Ok(())
    }

    pub fn remove(&self, id: &[u8]) -> Result<Option<Credential>, String> {
        self.writable()?;
        let mut f = lock(&self.creds);
        let mut next = f.clone();
        let gone = next.remove(id);
        if gone.is_some() {
            next.save(&self.creds_path())
                .map_err(|e| format!("cannot save the touch devices: {e}"))?;
            *f = next;
        }
        Ok(gone)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use saiife_touch::soft::SoftAuthenticator;
    use saiife_touch::{challenge, TouchClass, TouchError, LOCAL_RP_ID as RP};
    use std::collections::BTreeMap;

    const NOW: u64 = 1_800_000_000;

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn issue(t: &TouchState, key: IssueKey, uid: u32, now: u64) -> Result<Issued, String> {
        t.issue(key, uid, TouchClass::Land, "s".into(), BTreeMap::new(), now)
    }

    fn record(t: &TouchState) -> impl Fn(&Issued) -> ActionRecord {
        let id = t.instance_id();
        move |i: &Issued| ActionRecord {
            instance_id: id,
            request_id: 1,
            class: i.class,
            summary: i.summary.clone(),
            fields: i.fields.clone(),
            nonce: i.nonce,
            expires_at: i.expires_at,
        }
    }

    #[test]
    fn instance_id_is_stable() {
        let (a, b) = (dir(), dir());
        let (s1, n1) = TouchState::open(a.path());
        let (s2, _) = TouchState::open(a.path());
        let (s3, _) = TouchState::open(b.path());
        assert!(n1.is_none());
        assert_eq!(s1.instance_id(), s2.instance_id());
        assert_ne!(s1.instance_id(), s3.instance_id());
    }

    #[test]
    fn unreadable_credentials_fail_closed() {
        let d = dir();
        let (_, _) = TouchState::open(d.path());
        let f = d.path().join("state/touch/credentials.json");
        std::fs::write(&f, "{").unwrap();
        let (t, why) = TouchState::open(d.path());
        assert!(why.is_some());
        assert!(t.credentials_of(1000).is_empty());
        let s = SoftAuthenticator::new_es256();
        assert!(t.add(s.credential(RP, 1000, "k")).is_err());
        assert!(t.remove(b"x").is_err());
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "{");
    }

    #[test]
    fn issue_caps() {
        let d = dir();
        let (t, _) = TouchState::open(d.path());
        for i in 0..4 {
            issue(&t, IssueKey::Approve(i), 1000, NOW).unwrap();
        }
        assert!(issue(&t, IssueKey::Approve(4), 1000, NOW).is_err());
        // The same key replaces.
        issue(&t, IssueKey::Approve(0), 1000, NOW).unwrap();
        // Expired ones drop.
        issue(&t, IssueKey::Approve(5), 1000, NOW + 301).unwrap();
        // 32 in all over 9 uids.
        let (t, _) = TouchState::open(d.path());
        let mut n = 0u64;
        for uid in 0..8u32 {
            for _ in 0..4 {
                issue(&t, IssueKey::Approve(n), uid, NOW).unwrap();
                n += 1;
            }
        }
        let e = issue(&t, IssueKey::Approve(n), 8, NOW).unwrap_err();
        assert_eq!(e, "too many touches in progress");
    }

    #[test]
    fn consume_burns_even_on_failure() {
        let d = dir();
        let (t, _) = TouchState::open(d.path());
        let s = SoftAuthenticator::new_es256();
        t.add(s.credential(RP, 1000, "k")).unwrap();
        let k = IssueKey::Approve(1);
        let it = issue(&t, k.clone(), 1000, NOW).unwrap();
        let a = record(&t)(&it);
        let mut asr = s.assert_ctap(RP, &challenge(&a));
        match &mut asr {
            saiife_touch::Assertion::Ctap2 { signature, .. } => signature[5] ^= 1,
            _ => unreachable!(),
        }
        let r = t.consume(&k, 1000, record(&t), &asr, RP, NOW);
        assert_eq!(r.unwrap_err(), TouchError::BadSignature);
        let good = s.assert_ctap(RP, &challenge(&a));
        let r = t.consume(&k, 1000, record(&t), &good, RP, NOW);
        assert_eq!(r.unwrap_err(), TouchError::Expired);
    }

    #[test]
    fn consume_checks_the_uid() {
        let d = dir();
        let (t, _) = TouchState::open(d.path());
        let s = SoftAuthenticator::new_es256();
        t.add(s.credential(RP, 1001, "k")).unwrap();
        let k = IssueKey::Approve(1);
        let it = issue(&t, k.clone(), 1000, NOW).unwrap();
        let a = record(&t)(&it);
        let asr = s.assert_ctap(RP, &challenge(&a));
        let r = t.consume(&k, 1001, record(&t), &asr, RP, NOW);
        assert_eq!(r.unwrap_err(), TouchError::Mismatch);
        // Burned.
        let r = t.consume(&k, 1000, record(&t), &asr, RP, NOW);
        assert_eq!(r.unwrap_err(), TouchError::Expired);
    }

    /// R14.1: an unwritable credentials file refuses before any verify,
    /// right after the uid check.
    #[test]
    fn consume_with_unwritable_credentials_is_unavailable() {
        let d = dir();
        let (_, _) = TouchState::open(d.path());
        std::fs::write(d.path().join("state/touch/credentials.json"), "{").unwrap();
        let (t, why) = TouchState::open(d.path());
        assert!(why.is_some());
        let s = SoftAuthenticator::new_es256();
        let k = IssueKey::Approve(1);
        let it = issue(&t, k.clone(), 1000, NOW).unwrap();
        let asr = s.assert_ctap(RP, &challenge(&record(&t)(&it)));
        let r = t.consume(&k, 1000, record(&t), &asr, RP, NOW);
        assert_eq!(r.unwrap_err(), TouchError::Unavailable);
        // The uid check still comes first.
        let it = issue(&t, k.clone(), 1000, NOW).unwrap();
        let asr = s.assert_ctap(RP, &challenge(&record(&t)(&it)));
        let r = t.consume(&k, 1001, record(&t), &asr, RP, NOW);
        assert_eq!(r.unwrap_err(), TouchError::Mismatch);
    }

    /// R14.2: `consume` itself refuses a challenge past its expiry, before
    /// the record is even built.
    #[test]
    fn consume_refuses_an_expired_entry() {
        let d = dir();
        let (t, _) = TouchState::open(d.path());
        let s = SoftAuthenticator::new_es256();
        t.add(s.credential(RP, 1000, "k")).unwrap();
        let k = IssueKey::Approve(1);
        let it = issue(&t, k.clone(), 1000, NOW).unwrap();
        let asr = s.assert_ctap(RP, &challenge(&record(&t)(&it)));
        let built = std::cell::Cell::new(false);
        let r = t.consume(
            &k,
            1000,
            |i| {
                built.set(true);
                record(&t)(i)
            },
            &asr,
            RP,
            it.expires_at + 1,
        );
        assert_eq!(r.unwrap_err(), TouchError::Expired);
        assert!(!built.get(), "the record was built for an expired entry");
        // At the expiry second itself it is still live.
        let it = issue(&t, k.clone(), 1000, NOW).unwrap();
        let asr = s.assert_ctap(RP, &challenge(&record(&t)(&it)));
        assert!(t
            .consume(&k, 1000, record(&t), &asr, RP, it.expires_at)
            .is_ok());
    }

    /// R14.3: the expiry saturates instead of overflowing.
    #[test]
    fn issue_expiry_saturates() {
        let d = dir();
        let (t, _) = TouchState::open(d.path());
        let it = issue(&t, IssueKey::Approve(1), 1000, u64::MAX - 10).unwrap();
        assert_eq!(it.expires_at, u64::MAX);
    }

    /// R14.5: the caps are checked without the same-key entry, and a
    /// refused issue leaves that entry as it was.
    #[test]
    fn refused_issue_keeps_the_existing_entry() {
        let d = dir();
        let (t, _) = TouchState::open(d.path());
        let s = SoftAuthenticator::new_es256();
        t.add(s.credential(RP, 1000, "k")).unwrap();
        let k = IssueKey::Approve(1);
        let first = issue(&t, k.clone(), 1000, NOW).unwrap();
        // Another uid at its own cap asks for the same key: refused.
        for i in 10..14 {
            issue(&t, IssueKey::Approve(i), 2000, NOW).unwrap();
        }
        let e = issue(&t, k.clone(), 2000, NOW).unwrap_err();
        assert_eq!(e, "too many touches in progress");
        // The first entry is intact: its challenge still verifies.
        let asr = s.assert_ctap(RP, &challenge(&record(&t)(&first)));
        assert!(t.consume(&k, 1000, record(&t), &asr, RP, NOW).is_ok());
        // A uid at its cap may still replace its own entry (it is excluded).
        for i in 20..24 {
            issue(&t, IssueKey::Approve(i), 3000, NOW).unwrap();
        }
        issue(&t, IssueKey::Approve(20), 3000, NOW).unwrap();
        // The global cap counts without the replaced entry too: 32 live.
        let (t, _) = TouchState::open(d.path());
        let mut n = 0u64;
        for uid in 0..8u32 {
            for _ in 0..4 {
                issue(&t, IssueKey::Approve(n), uid, NOW).unwrap();
                n += 1;
            }
        }
        issue(&t, IssueKey::Approve(0), 0, NOW).unwrap();
    }

    #[test]
    fn consume_saves_the_counter() {
        let d = dir();
        let (t, _) = TouchState::open(d.path());
        let s = SoftAuthenticator::new_es256();
        t.add(s.credential(RP, 1000, "k")).unwrap();
        let k = IssueKey::Approve(1);
        let it = issue(&t, k.clone(), 1000, NOW).unwrap();
        let a = record(&t)(&it);
        let asr = s.assert_ctap(RP, &challenge(&a));
        let (ev, rec) = t.consume(&k, 1000, record(&t), &asr, RP, NOW).unwrap();
        assert_eq!(ev.sign_count, 1);
        assert_eq!(rec, a);
        let (t2, _) = TouchState::open(d.path());
        assert_eq!(t2.credentials_of(1000)[0].sign_count, 1);
        assert_eq!(t2.all().len(), 1);
    }
}
