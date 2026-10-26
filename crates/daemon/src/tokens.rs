//! Bearer tokens for the loopback TCP listener of the gateway (spec §6.3):
//! `saiife api token` issues one, bound to the caller's uid and valid for
//! 12 h. A token is `saiife_gw_` and 32 random bytes as base64url (no
//! padding). The daemon keeps only `sha256(token) → (uid, expires)`, in
//! memory and in `<state>/state/gateway-tokens.json` (0600, written to a
//! temp file, fsynced, renamed). At most 16 live tokens per uid: the
//! oldest goes when a 17th is issued.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

pub const PREFIX: &str = "saiife_gw_";
/// How long a token is valid.
pub const TTL_SECS: u64 = 12 * 3600;
/// Live tokens per uid; issuing one more evicts the oldest.
pub const MAX_PER_UID: usize = 16;
/// The file, under `<state>/state/`.
pub const FILE_NAME: &str = "gateway-tokens.json";
/// A larger token file is not read (16 tokens per uid of a few hundred
/// users is far below this).
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
const FILE_VERSION: u32 = 1;

/// Seconds since the Unix epoch; the tests inject their own.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

pub fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    })
}

/// `<state_dir>/state/gateway-tokens.json`.
pub fn path_in(state_dir: &Path) -> PathBuf {
    state_dir.join("state").join(FILE_NAME)
}

#[derive(Clone, PartialEq, Eq)]
struct Entry {
    hash: [u8; 32],
    uid: u32,
    expires: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEntry {
    sha256: String,
    uid: u32,
    expires: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    version: u32,
    tokens: Vec<StoredEntry>,
}

/// A newly issued token: the only time its value exists in the daemon.
pub struct Issued {
    pub token: Zeroizing<String>,
    /// Seconds since the epoch.
    pub expires: u64,
}

impl std::fmt::Debug for Issued {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issued")
            .field("expires", &self.expires)
            .finish_non_exhaustive()
    }
}

pub struct Tokens {
    /// `None`: in memory only.
    path: Option<PathBuf>,
    clock: Clock,
    entries: Mutex<Vec<Entry>>,
    /// Held across clone, write and commit, so two writers never race;
    /// `entries` is locked only briefly (a lookup never waits on a disk
    /// write).
    write: Mutex<()>,
}

impl std::fmt::Debug for Tokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tokens")
            .field("path", &self.path)
            .field("live", &lock(&self.entries).len())
            .finish()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn sha256(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// Equal in time independent of where the bytes differ.
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let d = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(d) == 0
}

impl Tokens {
    /// No file, the system clock (tests and a daemon without a state dir).
    pub fn memory() -> Tokens {
        Tokens::memory_with_clock(system_clock())
    }

    pub fn memory_with_clock(clock: Clock) -> Tokens {
        Tokens {
            path: None,
            clock,
            entries: Mutex::new(Vec::new()),
            write: Mutex::new(()),
        }
    }

    /// The tokens in `path`, expired ones dropped. A missing file is no
    /// tokens. An unreadable or corrupt one is no tokens too, and the
    /// reason comes back for a `tokens_reset` record; the next write
    /// replaces the file.
    pub fn open(path: PathBuf, clock: Clock) -> (Tokens, Option<String>) {
        let (entries, reset) = match read(&path) {
            Ok(e) => (e, None),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (Vec::new(), None),
            Err(e) => (Vec::new(), Some(format!("{}: {e}", path.display()))),
        };
        let t = Tokens {
            path: Some(path),
            clock,
            entries: Mutex::new(entries),
            write: Mutex::new(()),
        };
        if let Err(e) = t.purge() {
            eprintln!("saiife: warning: cannot write the gateway tokens: {e}");
        }
        (t, reset)
    }

    pub fn now(&self) -> u64 {
        (self.clock)()
    }

    /// Live tokens of `uid`.
    pub fn live_for(&self, uid: u32) -> usize {
        let now = self.now();
        lock(&self.entries)
            .iter()
            .filter(|e| e.uid == uid && e.expires > now)
            .count()
    }

    /// A new token for `uid`, valid [`TTL_SECS`]. Expired tokens go; past
    /// [`MAX_PER_UID`] live ones, the oldest of `uid`'s goes. Nothing is
    /// issued unless the file was written.
    pub fn issue(&self, uid: u32) -> io::Result<Issued> {
        let mut raw = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut raw[..]).map_err(|e| io::Error::other(e.to_string()))?;
        let token = Zeroizing::new(format!(
            "{PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&raw[..])
        ));
        let now = self.now();
        let expires = now.saturating_add(TTL_SECS);
        let _w = lock(&self.write);
        let mut next: Vec<Entry> = lock(&self.entries)
            .iter()
            .filter(|e| e.expires > now)
            .cloned()
            .collect();
        while next.iter().filter(|e| e.uid == uid).count() >= MAX_PER_UID {
            // Every token lives the same TTL: the soonest to expire is the
            // oldest.
            let oldest = next
                .iter()
                .enumerate()
                .filter(|(_, e)| e.uid == uid)
                .min_by_key(|(_, e)| e.expires)
                .map(|(i, _)| i);
            match oldest {
                Some(i) => {
                    next.remove(i);
                }
                None => break,
            }
        }
        next.push(Entry {
            hash: sha256(&token),
            uid,
            expires,
        });
        self.save(&next)?;
        *lock(&self.entries) = next;
        Ok(Issued { token, expires })
    }

    /// The uid of a live `token`, or `None` (missing, expired, unknown).
    /// Every stored hash is compared, each in constant time.
    pub fn verify(&self, token: &str) -> Option<u32> {
        if !token.starts_with(PREFIX) {
            return None;
        }
        let h = sha256(token);
        let now = self.now();
        let mut found = None;
        for e in lock(&self.entries).iter() {
            // An expiry past now + TTL (a clock that went back, an edited
            // file) is not trusted.
            if ct_eq(&e.hash, &h) && e.expires > now && e.expires <= now.saturating_add(TTL_SECS) {
                found = Some(e.uid);
            }
        }
        found
    }

    /// Drop expired tokens (at start and hourly); `true` when any went.
    pub fn purge(&self) -> io::Result<bool> {
        let now = self.now();
        let _w = lock(&self.write);
        let cur = lock(&self.entries).clone();
        let next: Vec<Entry> = cur.iter().filter(|e| e.expires > now).cloned().collect();
        if next.len() == cur.len() {
            return Ok(false);
        }
        // Memory drops them whatever the disk does: an expired token is
        // refused either way.
        *lock(&self.entries) = next.clone();
        self.save(&next)?;
        Ok(true)
    }

    fn save(&self, entries: &[Entry]) -> io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let stored = Stored {
            version: FILE_VERSION,
            tokens: entries
                .iter()
                .map(|e| StoredEntry {
                    sha256: hex(&e.hash),
                    uid: e.uid,
                    expires: e.expires,
                })
                .collect(),
        };
        let bytes = serde_json::to_vec(&stored).map_err(io::Error::other)?;
        write_atomic(path, &bytes)
    }
}

fn read(path: &Path) -> io::Result<Vec<Entry>> {
    let f = crate::vault::open_regular(path)?;
    let mut b = Vec::new();
    f.take(MAX_FILE_BYTES + 1).read_to_end(&mut b)?;
    if b.len() as u64 > MAX_FILE_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "too large"));
    }
    let s: Stored = serde_json::from_slice(&b)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("corrupt: {e}")))?;
    if s.version != FILE_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown version {}", s.version),
        ));
    }
    s.tokens
        .into_iter()
        .map(|t| {
            Ok(Entry {
                hash: unhex(&t.sha256).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "corrupt: a bad sha256")
                })?,
                uid: t.uid,
                expires: t.expires,
            })
        })
        .collect()
}

/// The dir (0700, made when missing), then a temp file beside the target
/// (0600), fsync, rename, fsync of the dir.
fn write_atomic(file: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = file
        .parent()
        .ok_or_else(|| io::Error::other("the token file has no directory"))?;
    crate::vault::check_dir(dir, true)?;
    let tmp = dir.join(format!(".{FILE_NAME}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let staged = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, file)
    })();
    if let Err(e) = staged {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    std::fs::File::open(dir)?.sync_all()
}

/// [`Tokens::issue`] off the runtime thread (it writes and fsyncs).
pub async fn issue_blocking(tokens: Arc<Tokens>, uid: u32) -> io::Result<Issued> {
    tokio::task::spawn_blocking(move || tokens.issue(uid))
        .await
        .unwrap_or_else(|e| Err(io::Error::other(e.to_string())))
}

/// Seconds since the epoch in the record format (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn rfc3339(secs: u64) -> String {
    const F: &[time::format_description::FormatItem<'static>] =
        time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    time::OffsetDateTime::from_unix_timestamp(i64::try_from(secs).unwrap_or(i64::MAX))
        .ok()
        .and_then(|t| t.format(F).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn clock(at: &Arc<AtomicU64>) -> Clock {
        let at = Arc::clone(at);
        Arc::new(move || at.load(Ordering::SeqCst))
    }

    fn scratch() -> tempfile::TempDir {
        let base = std::env::var_os("SAIIFE_TEST_TMP")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../target/test-tmp"
                ))
            });
        std::fs::create_dir_all(&base).unwrap();
        tempfile::tempdir_in(base).unwrap()
    }

    #[test]
    fn token_shape_and_uid() {
        let t = Tokens::memory();
        let i = t.issue(1001).unwrap();
        let rest = i.token.strip_prefix(PREFIX).unwrap();
        assert_eq!(rest.len(), 43);
        assert!(rest
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'));
        assert_eq!(t.verify(&i.token), Some(1001));
        assert_eq!(t.verify("saiife_gw_nope"), None);
        assert_eq!(t.verify(rest), None);
        assert_ne!(t.issue(1001).unwrap().token, i.token);
        // The token is caught by the record masking.
        assert_eq!(saiife_audit::mask::mask(&i.token), saiife_audit::mask::MASK);
        assert!(!format!("{i:?}").contains(rest));
    }

    #[test]
    fn expires_after_12h() {
        let at = Arc::new(AtomicU64::new(1_000_000));
        let t = Tokens::memory_with_clock(clock(&at));
        let i = t.issue(7).unwrap();
        assert_eq!(i.expires, 1_000_000 + 12 * 3600);
        at.store(1_000_000 + 12 * 3600 - 1, Ordering::SeqCst);
        assert_eq!(t.verify(&i.token), Some(7));
        at.store(1_000_000 + 12 * 3600, Ordering::SeqCst);
        assert_eq!(t.verify(&i.token), None);
        assert!(t.purge().unwrap());
        assert_eq!(t.live_for(7), 0);
    }

    #[test]
    fn at_most_16_per_uid_oldest_evicted() {
        let at = Arc::new(AtomicU64::new(100));
        let t = Tokens::memory_with_clock(clock(&at));
        let mut issued = Vec::new();
        for i in 0..16 {
            at.store(100 + i, Ordering::SeqCst);
            issued.push(t.issue(5).unwrap());
        }
        let other = t.issue(6).unwrap();
        assert_eq!(t.live_for(5), 16);
        at.store(200, Ordering::SeqCst);
        let newest = t.issue(5).unwrap();
        assert_eq!(t.live_for(5), 16);
        assert_eq!(t.verify(&issued[0].token), None);
        assert_eq!(t.verify(&issued[1].token), Some(5));
        assert_eq!(t.verify(&newest.token), Some(5));
        assert_eq!(t.verify(&other.token), Some(6));
    }

    #[test]
    fn token_hashed_on_disk() {
        let d = scratch();
        let path = path_in(d.path());
        let (t, reset) = Tokens::open(path.clone(), system_clock());
        assert!(reset.is_none());
        let i = t.issue(42).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let rest = i.token.strip_prefix(PREFIX).unwrap();
        assert!(!text.contains(rest), "{text}");
        assert!(text.contains(&hex(&sha256(&i.token))), "{text}");
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        assert!(!path.with_file_name(format!(".{FILE_NAME}.tmp")).exists());
        // A restart keeps it.
        let (again, reset) = Tokens::open(path.clone(), system_clock());
        assert!(reset.is_none());
        assert_eq!(again.verify(&i.token), Some(42));
    }

    #[test]
    fn expired_dropped_at_open() {
        let d = scratch();
        let path = path_in(d.path());
        let at = Arc::new(AtomicU64::new(1_000));
        let (t, _) = Tokens::open(path.clone(), clock(&at));
        let i = t.issue(1).unwrap();
        at.store(1_000 + TTL_SECS + 1, Ordering::SeqCst);
        let (t2, reset) = Tokens::open(path.clone(), clock(&at));
        assert!(reset.is_none());
        assert_eq!(t2.verify(&i.token), None);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains(&hex(&sha256(&i.token))), "{text}");
    }

    #[test]
    fn corrupt_file_resets() {
        let d = scratch();
        let path = path_in(d.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        for bad in [
            &b"not json"[..],
            br#"{"version":1,"tokens":[{"sha256":"xy","uid":1,"expires":9999999999}]}"#,
            br#"{"version":2,"tokens":[]}"#,
        ] {
            std::fs::write(&path, bad).unwrap();
            let (t, reset) = Tokens::open(path.clone(), system_clock());
            assert!(reset.is_some());
            assert_eq!(t.live_for(1), 0);
            // The next issue replaces the file.
            t.issue(1).unwrap();
            assert!(Tokens::open(path.clone(), system_clock()).1.is_none());
        }
        // A symlink is not followed.
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(d.path().join("elsewhere"), &path).unwrap();
        assert!(Tokens::open(path.clone(), system_clock()).1.is_some());
    }

    #[test]
    fn expiry_beyond_ttl_is_refused() {
        let at = Arc::new(AtomicU64::new(1_000_000));
        let t = Tokens::memory_with_clock(clock(&at));
        let i = t.issue(3).unwrap();
        // The clock went back a minute: the expiry is now more than 12 h
        // away, which no issued token can be.
        at.store(1_000_000 - 60, Ordering::SeqCst);
        assert_eq!(t.verify(&i.token), None);
        at.store(1_000_000, Ordering::SeqCst);
        assert_eq!(t.verify(&i.token), Some(3));
        // An edited file with a far expiry is refused the same way.
        let d = scratch();
        let path = path_in(d.path());
        let (t, _) = Tokens::open(path.clone(), clock(&at));
        let i = t.issue(4).unwrap();
        let text = std::fs::read_to_string(&path)
            .unwrap()
            .replace(&i.expires.to_string(), "99999999999");
        std::fs::write(&path, text).unwrap();
        let (t2, reset) = Tokens::open(path, clock(&at));
        assert!(reset.is_none());
        assert_eq!(t2.verify(&i.token), None);
    }

    #[test]
    fn rfc3339_format() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_793_000_000), "2026-10-26T07:33:20Z");
    }
}
