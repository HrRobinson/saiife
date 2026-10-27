//! One-use command grants (spec §6.10.4): approving a command request
//! (`[guard] ask`) leaves a grant keyed by
//! SHA-256(uid, agent, project, tool, input); the next hook call with
//! exactly that key uses it up and is allowed once.
//!
//! The **daemon** computes the key, from the peer uid and the fields of the
//! record the hook sends (`grant.consume`, `approval.create`); a client
//! never names a key. `input` is the record's input: masked and cut as the
//! record shows it. Two commands that differ only inside a masked span (a
//! token's value) therefore share a key. That is accepted: masking hides
//! secrets, not commands, so what the approver saw is what runs.
//!
//! Grants live in memory and in `<state>/state/grants.json` (0600, written
//! atomically; the dir is checked like lockdown's: ours, not group- or
//! world-writable), so a restart keeps them. Expired grants are dropped on
//! load and at every consume. An unreadable file is no grants (fail
//! closed: the command needs approval again).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const FILE_NAME: &str = "grants.json";
/// Far more than 20 pending requests per uid can ever leave.
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// `<state_dir>/state/grants.json`.
pub fn path_in(state_dir: &Path) -> PathBuf {
    state_dir.join("state").join(FILE_NAME)
}

/// SHA-256 over `uid` (4 bytes, big-endian), `agent`, `project`, `tool` and
/// `input` (UTF-8), each prefixed by its length as a u32 big-endian, in
/// that order.
pub fn grant_key(uid: u32, agent: &str, project: &str, tool: &str, input: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    let uid = uid.to_be_bytes();
    for part in [
        &uid[..],
        agent.as_bytes(),
        project.as_bytes(),
        tool.as_bytes(),
        input.as_bytes(),
    ] {
        // Every part is far below 4 GiB (records are at most 64 KiB).
        h.update((part.len() as u32).to_be_bytes());
        h.update(part);
    }
    h.finalize().into()
}

/// Lowercase hex, as the key is stored (`grant_key` of a request).
pub fn hex(key: &[u8; 32]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

/// [`hex`] read back.
pub fn unhex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Grant {
    approval: u64,
    /// Unix seconds; the grant is good while `now < expires`.
    expires: u64,
}

#[derive(Serialize, Deserialize)]
struct FileGrant {
    key: String,
    approval: u64,
    expires: u64,
}

#[derive(Serialize, Deserialize)]
struct File {
    v: u32,
    grants: Vec<FileGrant>,
}

/// The grants in memory and (unless [`Grants::memory`]) on disk.
pub struct Grants {
    path: Option<PathBuf>,
    /// Held across a change and its write: file and memory move together.
    cur: Mutex<HashMap<[u8; 32], Grant>>,
    /// Every `consume`, granted or not (for tests and `status`).
    consumes: AtomicU64,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Grants {
    /// No file: tests that never restart.
    pub fn memory() -> Grants {
        Grants {
            path: None,
            cur: Mutex::new(HashMap::new()),
            consumes: AtomicU64::new(0),
        }
    }

    /// Reads the file, dropping grants expired at `now`. Missing is none;
    /// an unreadable file or an unsafe dir is none too, and the second
    /// value says why (for a stderr line and the start record).
    pub fn open(path: PathBuf, now: SystemTime) -> (Grants, Option<String>) {
        let (cur, why) = match crate::lockdown::check_parent(&path).and_then(|()| read(&path)) {
            Ok(mut m) => {
                let t = secs(now);
                m.retain(|_, g| g.expires > t);
                (m, None)
            }
            Err(e) => (HashMap::new(), Some(format!("grants file unusable: {e}"))),
        };
        (
            Grants {
                path: Some(path),
                cur: Mutex::new(cur),
                consumes: AtomicU64::new(0),
            },
            why,
        )
    }

    /// Keep a grant for `key` from approval `approval` until `expires`. A
    /// grant already there for the key is replaced. `Err`: it could not be
    /// saved, and it is not kept.
    pub fn insert(&self, key: [u8; 32], approval: u64, expires: SystemTime) -> io::Result<()> {
        let mut cur = lock(&self.cur);
        let mut next = cur.clone();
        next.insert(
            key,
            Grant {
                approval,
                expires: secs(expires),
            },
        );
        self.save(&next)?;
        *cur = next;
        Ok(())
    }

    /// Use up the grant for `key` if one is good at `now`: its approval
    /// id. Expired grants are dropped on the way. `Err`: the use could not
    /// be saved; the grant is gone from memory all the same and the call
    /// is not allowed (a grant is never good twice).
    pub fn consume(&self, key: &[u8; 32], now: SystemTime) -> io::Result<Option<u64>> {
        self.consumes.fetch_add(1, Ordering::Relaxed);
        let t = secs(now);
        let mut cur = lock(&self.cur);
        let before = cur.len();
        cur.retain(|_, g| g.expires > t);
        let hit = cur.remove(key);
        if hit.is_none() && cur.len() == before {
            return Ok(None);
        }
        self.save(&cur)?;
        Ok(hit.map(|g| g.approval))
    }

    /// How many `consume` calls were made since start.
    pub fn consume_count(&self) -> u64 {
        self.consumes.load(Ordering::Relaxed)
    }

    /// The grants held now (expired ones included until the next consume).
    pub fn len(&self) -> usize {
        lock(&self.cur).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn save(&self, m: &HashMap<[u8; 32], Grant>) -> io::Result<()> {
        match &self.path {
            None => Ok(()),
            Some(p) => write(p, m),
        }
    }
}

fn read(path: &Path) -> io::Result<HashMap<[u8; 32], Grant>> {
    let f = match crate::vault::open_regular(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(e),
    };
    let mut b = Vec::new();
    f.take(MAX_FILE_BYTES + 1).read_to_end(&mut b)?;
    if b.len() as u64 > MAX_FILE_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "too large"));
    }
    let file: File = serde_json::from_slice(&b)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("corrupt: {e}")))?;
    if file.v != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown version {}", file.v),
        ));
    }
    let mut out = HashMap::new();
    for g in file.grants {
        let key = unhex(&g.key)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "corrupt: a bad key"))?;
        out.insert(
            key,
            Grant {
                approval: g.approval,
                expires: g.expires,
            },
        );
    }
    Ok(out)
}

fn write(file: &Path, m: &HashMap<[u8; 32], Grant>) -> io::Result<()> {
    let dir = file
        .parent()
        .ok_or_else(|| io::Error::other("the grants file has no directory"))?;
    crate::vault::check_dir(dir, true)?;
    let mut grants: Vec<FileGrant> = m
        .iter()
        .map(|(k, g)| FileGrant {
            key: hex(k),
            approval: g.approval,
            expires: g.expires,
        })
        .collect();
    grants.sort_by_key(|g| g.approval);
    let bytes = serde_json::to_vec(&File { v: 1, grants }).map_err(io::Error::other)?;
    let tmp = dir.join(format!(".{FILE_NAME}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let staged = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, file)
    })();
    if let Err(e) = staged {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const UID: u32 = 1001;
    const CMD: &str = "git push --force origin main";

    fn t0() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_800_000_000)
    }

    fn key(uid: u32, input: &str) -> [u8; 32] {
        grant_key(uid, "claude", "/srv/p", "Bash", input)
    }

    fn ttl() -> Duration {
        saiife_policy::ApprovalCfg::default().grant_ttl
    }

    #[test]
    fn grant_used_once() {
        let g = Grants::memory();
        g.insert(key(UID, CMD), 42, t0() + ttl()).unwrap();
        assert_eq!(g.consume(&key(UID, CMD), t0()).unwrap(), Some(42));
        assert_eq!(g.consume(&key(UID, CMD), t0()).unwrap(), None);
        assert_eq!(g.consume_count(), 2);
    }

    #[test]
    fn grant_other_uid_no_match() {
        let g = Grants::memory();
        g.insert(key(UID, CMD), 42, t0() + ttl()).unwrap();
        assert_ne!(key(UID, CMD), key(UID + 1, CMD));
        assert_eq!(g.consume(&key(UID + 1, CMD), t0()).unwrap(), None);
        // Still there for its own uid.
        assert_eq!(g.consume(&key(UID, CMD), t0()).unwrap(), Some(42));
    }

    #[test]
    fn grant_trailing_space_is_other_key() {
        let g = Grants::memory();
        g.insert(key(UID, CMD), 42, t0() + ttl()).unwrap();
        let spaced = format!("{CMD} ");
        assert_ne!(key(UID, CMD), key(UID, &spaced));
        assert_eq!(g.consume(&key(UID, &spaced), t0()).unwrap(), None);
        assert_eq!(g.consume(&key(UID, CMD), t0()).unwrap(), Some(42));
    }

    #[test]
    fn fields_are_length_prefixed() {
        // Moving a byte from one field to the next changes the key.
        let a = grant_key(UID, "ab", "c", "Bash", CMD);
        let b = grant_key(UID, "a", "bc", "Bash", CMD);
        assert_ne!(a, b);
        // The spec's layout, spelled out.
        let mut h = Sha256::new();
        for part in [
            &UID.to_be_bytes()[..],
            b"claude",
            b"/srv/p",
            b"Bash",
            CMD.as_bytes(),
        ] {
            h.update((part.len() as u32).to_be_bytes());
            h.update(part);
        }
        let want: [u8; 32] = h.finalize().into();
        assert_eq!(key(UID, CMD), want);
        assert_eq!(unhex(&hex(&want)), Some(want));
    }

    #[test]
    fn grant_expires_after_ttl() {
        let g = Grants::memory();
        g.insert(key(UID, CMD), 42, t0() + ttl()).unwrap();
        let late = t0() + ttl();
        assert_eq!(g.consume(&key(UID, CMD), late).unwrap(), None);
        assert!(g.is_empty(), "the expired grant is pruned");
        // Just inside the TTL it is good.
        g.insert(key(UID, CMD), 43, t0() + ttl()).unwrap();
        let inside = t0() + ttl() - Duration::from_secs(1);
        assert_eq!(g.consume(&key(UID, CMD), inside).unwrap(), Some(43));
    }

    #[test]
    fn grants_survive_restart() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = path_in(d.path());
        let (g, why) = Grants::open(p.clone(), t0());
        assert!(why.is_none() && g.is_empty());
        g.insert(key(UID, CMD), 42, t0() + ttl()).unwrap();
        g.insert(key(UID, "git push -f"), 43, t0() + Duration::from_secs(5))
            .unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        drop(g);
        // After a restart past the second grant's expiry: only the first.
        let (g, why) = Grants::open(p.clone(), t0() + Duration::from_secs(10));
        assert!(why.is_none(), "{why:?}");
        assert_eq!(g.len(), 1);
        assert_eq!(
            g.consume(&key(UID, CMD), t0() + Duration::from_secs(10))
                .unwrap(),
            Some(42)
        );
        // The use is saved too.
        let (g, _) = Grants::open(p, t0() + Duration::from_secs(11));
        assert!(g.is_empty());
    }

    #[test]
    fn unreadable_file_is_no_grants() {
        let d = tempfile::tempdir().unwrap();
        let p = path_in(d.path());
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, b"{not json").unwrap();
        let (g, why) = Grants::open(p, t0());
        assert!(g.is_empty());
        assert!(why.unwrap().contains("corrupt"));
    }

    #[test]
    fn unsafe_dir_is_no_grants() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = path_in(d.path());
        let (g, _) = Grants::open(p.clone(), t0());
        g.insert(key(UID, CMD), 42, t0() + ttl()).unwrap();
        std::fs::set_permissions(p.parent().unwrap(), std::fs::Permissions::from_mode(0o777))
            .unwrap();
        let (g, why) = Grants::open(p.clone(), t0());
        assert!(g.is_empty());
        assert!(why.is_some());
        std::fs::set_permissions(p.parent().unwrap(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
    }
}
