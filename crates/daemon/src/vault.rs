//! The credential vault file (spec §6.6, §8.9): `magic "SAIIFEV1" || u8
//! version (1) || 24-byte nonce || XChaCha20-Poly1305(key, nonce, aad =
//! magic || version, JSON)`, at `<state>/vault/vault.bin`, 0600 in a 0700
//! dir. Every write goes to a temp file, is fsynced, renamed, and the dir is
//! fsynced, with a new nonce each time. Secret bytes live in `Zeroizing`
//! buffers and never reach `Debug` output.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const MAGIC: &[u8; 8] = b"SAIIFEV1";
pub const VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Token,
    Basic,
    Header,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub kind: Kind,
    pub fields: BTreeMap<String, Zeroizing<String>>,
    pub allowed_services: Vec<String>,
    pub created_by: u32,
    pub created: String,
    pub last_used: Option<String>,
    pub rotate_after: Option<String>,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("fields", &self.fields.keys().collect::<Vec<_>>())
            .field("allowed_services", &self.allowed_services)
            .field("created_by", &self.created_by)
            .field("created", &self.created)
            .field("last_used", &self.last_used)
            .field("rotate_after", &self.rotate_after)
            .finish()
    }
}

/// An entry without its values, for `secret list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    pub name: String,
    pub kind: Kind,
    pub allowed_services: Vec<String>,
    pub created_by: u32,
    pub created: String,
    pub last_used: Option<String>,
    pub rotate_after: Option<String>,
}

pub enum VaultState {
    Ready(Vault),
    Unavailable(String),
}

/// Flushes of `last_used` happen at most this often.
const FLUSH_EVERY: Duration = Duration::from_secs(60);
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 8 + 1 + NONCE_LEN;
/// A vault file larger than this is not read.
const MAX_VAULT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Deserialize)]
struct Body {
    entries: Vec<Entry>,
}

#[derive(Serialize)]
struct BodyRef<'a> {
    entries: Vec<&'a Entry>,
}

pub struct Vault {
    key: Zeroizing<[u8; 32]>,
    file: PathBuf,
    entries: BTreeMap<String, Entry>,
    /// `last_used` changed in memory since the last write.
    dirty: bool,
    last_write: Option<Instant>,
    /// The fsync of the dir after the rename (a seam for tests).
    dir_sync: fn(&Path) -> io::Result<()>,
}

fn real_dir_sync(dir: &Path) -> io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

/// Open a regular file without following a symlink and without blocking on
/// a FIFO; anything else is `InvalidData`.
pub(crate) fn open_regular(path: &Path) -> io::Result<std::fs::File> {
    use rustix::fs::{Mode, OFlags};
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let f = std::fs::File::from(fd);
    if !f.metadata()?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a regular file",
        ));
    }
    Ok(f)
}

/// The vault dir must be a real directory (no symlink) owned by the euid,
/// mode 0700 (fixed when it is not). With `create`, a missing dir is made;
/// otherwise a missing dir is `NotFound`.
pub(crate) fn check_dir(dir: &Path, create: bool) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let md = match std::fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound && create => {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
            std::fs::symlink_metadata(dir)?
        }
        Err(e) => return Err(e),
    };
    if !md.file_type().is_dir() {
        return Err(io::Error::other("the vault dir is not a directory"));
    }
    if md.uid() != rustix::process::geteuid().as_raw() {
        return Err(io::Error::other("the vault dir is not owned by this user"));
    }
    if md.permissions().mode() & 0o7777 != 0o700 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Where a write failed: before the rename the old file is intact; after it
/// the new file is already the vault.
enum WriteErr {
    Before(io::Error),
    After(io::Error),
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("file", &self.file)
            .field("entries", &self.entries.len())
            .finish()
    }
}

/// `^[a-z0-9][a-z0-9._-]{0,63}$`
pub fn valid_name(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b[1..].iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        })
}

fn read_key(key_file: &Path) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let f = open_regular(key_file).map_err(|_| "no vault key")?;
    let mut buf = Zeroizing::new(Vec::with_capacity(64));
    f.take(33)
        .read_to_end(&mut buf)
        .map_err(|_| "no vault key")?;
    if buf.len() != 32 {
        return Err("vault key is not 32 bytes");
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&buf);
    Ok(key)
}

fn cipher(key: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(key.into())
}

fn not_a_vault() -> VaultState {
    VaultState::Unavailable("vault file is not a saiife vault".into())
}

/// Open the vault. A missing `vault_file` with a good key is an empty vault.
pub fn open(key_file: &Path, vault_file: &Path) -> VaultState {
    let key = match read_key(key_file) {
        Ok(k) => k,
        Err(r) => return VaultState::Unavailable(r.into()),
    };
    let mut v = Vault {
        key,
        file: vault_file.to_path_buf(),
        entries: BTreeMap::new(),
        dirty: false,
        last_write: None,
        dir_sync: real_dir_sync,
    };
    if let Some(dir) = vault_file.parent() {
        match check_dir(dir, false) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return VaultState::Ready(v),
            Err(_) => return not_a_vault(),
        }
    }
    let raw = match open_regular(vault_file) {
        Ok(f) => {
            let mut raw = Vec::new();
            if f.take(MAX_VAULT_BYTES + 1).read_to_end(&mut raw).is_err()
                || raw.len() as u64 > MAX_VAULT_BYTES
            {
                return not_a_vault();
            }
            raw
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => return VaultState::Ready(v),
        Err(_) => return not_a_vault(),
    };
    // The version byte is not checked on its own: the AAD binds it, so a
    // flipped one fails to decrypt.
    if raw.len() < HEADER_LEN + 16 || &raw[..8] != MAGIC {
        return not_a_vault();
    }
    let mut n = [0u8; NONCE_LEN];
    n.copy_from_slice(&raw[9..HEADER_LEN]);
    let nonce = XNonce::from(n);
    let plain = match cipher(&v.key).decrypt(
        &nonce,
        Payload {
            msg: &raw[HEADER_LEN..],
            aad: &raw[..9],
        },
    ) {
        Ok(p) => Zeroizing::new(p),
        Err(_) => return VaultState::Unavailable("vault cannot be decrypted".into()),
    };
    match serde_json::from_slice::<Body>(&plain) {
        Ok(b) => {
            for e in b.entries {
                v.entries.insert(e.name.clone(), e);
            }
            VaultState::Ready(v)
        }
        Err(_) => VaultState::Unavailable("vault cannot be decrypted".into()),
    }
}

/// The rename succeeded and the dir fsync did not: the change is on disk,
/// so `put`/`remove` count it as done (memory stays ahead, never behind the
/// file) and report `Ok`; the only trace is this one stderr line.
fn warn_committed(e: &io::Error) {
    eprintln!("saiife: warning: vault written but the directory sync failed: {e}");
}

fn finish(r: Result<(), WriteErr>) -> io::Result<()> {
    r.map_err(|e| match e {
        WriteErr::Before(e) | WriteErr::After(e) => e,
    })
}

impl Vault {
    pub fn get(&self, name: &str) -> Option<&Entry> {
        self.entries.get(name)
    }

    /// Insert or replace, then write. On a write error the in-memory vault
    /// is left as it was.
    pub fn put(&mut self, e: Entry) -> io::Result<()> {
        if !valid_name(&e.name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid secret name",
            ));
        }
        let name = e.name.clone();
        let old = self.entries.insert(name.clone(), e);
        match self.write(Instant::now()) {
            Ok(()) => {}
            Err(WriteErr::Before(err)) => {
                match old {
                    Some(o) => self.entries.insert(name, o),
                    None => self.entries.remove(&name),
                };
                return Err(err);
            }
            Err(WriteErr::After(err)) => warn_committed(&err),
        }
        Ok(())
    }

    /// Remove and write; `false` when there was no such entry.
    pub fn remove(&mut self, name: &str) -> io::Result<bool> {
        let Some(old) = self.entries.remove(name) else {
            return Ok(false);
        };
        match self.write(Instant::now()) {
            Ok(()) => {}
            Err(WriteErr::Before(err)) => {
                self.entries.insert(name.to_string(), old);
                return Err(err);
            }
            Err(WriteErr::After(err)) => warn_committed(&err),
        }
        Ok(true)
    }

    pub fn list(&self) -> Vec<Meta> {
        self.entries
            .values()
            .map(|e| Meta {
                name: e.name.clone(),
                kind: e.kind,
                allowed_services: e.allowed_services.clone(),
                created_by: e.created_by,
                created: e.created.clone(),
                last_used: e.last_used.clone(),
                rotate_after: e.rotate_after.clone(),
            })
            .collect()
    }

    /// Set `last_used` in memory only; `flush_if_due` or `flush` writes it.
    pub fn touch(&mut self, name: &str, ts: &str) {
        if let Some(e) = self.entries.get_mut(name) {
            e.last_used = Some(ts.to_string());
            self.dirty = true;
        }
    }

    /// Write pending `last_used` changes when the last write is a minute
    /// old. `true` when it wrote.
    pub fn flush_if_due(&mut self, now: Instant) -> io::Result<bool> {
        if !self.dirty {
            return Ok(false);
        }
        if let Some(t) = self.last_write {
            if now.saturating_duration_since(t) < FLUSH_EVERY {
                return Ok(false);
            }
        }
        match self.write(now) {
            Ok(()) => {}
            Err(WriteErr::Before(e)) => return Err(e),
            Err(WriteErr::After(e)) => warn_committed(&e),
        }
        Ok(true)
    }

    /// Write pending changes now (on stop).
    pub fn flush(&mut self) -> io::Result<()> {
        if self.dirty {
            finish(self.write(Instant::now()))?;
        }
        Ok(())
    }

    fn write(&mut self, now: Instant) -> Result<(), WriteErr> {
        // Reserved up front so growth does not leave plaintext copies in
        // freed memory for typical vault sizes.
        let mut plain = Zeroizing::new(Vec::with_capacity(64 * 1024));
        let body = BodyRef {
            entries: self.entries.values().collect(),
        };
        serde_json::to_writer(&mut *plain, &body)
            .map_err(|e| WriteErr::Before(io::Error::other(e)))?;
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce)
            .map_err(|e| WriteErr::Before(io::Error::other(e.to_string())))?;
        let mut head = [0u8; 9];
        head[..8].copy_from_slice(MAGIC);
        head[8] = VERSION;
        let ct = cipher(&self.key)
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &plain,
                    aad: &head,
                },
            )
            .map_err(|_| WriteErr::Before(io::Error::other("cannot encrypt the vault")))?;
        let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
        out.extend_from_slice(&head);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        let r = write_atomic(&self.file, &out, self.dir_sync);
        if !matches!(r, Err(WriteErr::Before(_))) {
            // On disk (an After failure counts as written).
            self.dirty = false;
            self.last_write = Some(now);
        }
        r
    }
}

/// Check the dir, then: temp file in the same dir (0600), fsync, rename,
/// fsync the dir. A failure before the rename removes the temp file and
/// leaves the old file as it was; one after it is `After`.
fn write_atomic(
    file: &Path,
    bytes: &[u8],
    dir_sync: fn(&Path) -> io::Result<()>,
) -> Result<(), WriteErr> {
    let dir = file
        .parent()
        .ok_or_else(|| WriteErr::Before(io::Error::other("vault path has no directory")))?;
    check_dir(dir, true).map_err(WriteErr::Before)?;
    let tmp = dir.join(".vault.bin.tmp");
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
        return Err(WriteErr::Before(e));
    }
    dir_sync(dir).map_err(WriteErr::After)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const KEY: [u8; 32] = [7; 32];

    fn entry(name: &str, value: &str) -> Entry {
        let mut fields = BTreeMap::new();
        fields.insert("token".to_string(), Zeroizing::new(value.to_string()));
        Entry {
            name: name.into(),
            kind: Kind::Token,
            fields,
            allowed_services: vec!["github".into()],
            created_by: 1000,
            created: "2026-10-26T10:00:00Z".into(),
            last_used: None,
            rotate_after: None,
        }
    }

    struct Env {
        _t: tempfile::TempDir,
        key: PathBuf,
        file: PathBuf,
    }

    fn env() -> Env {
        let t = tempfile::tempdir().unwrap();
        let key = t.path().join("vault-key");
        std::fs::write(&key, KEY).unwrap();
        let file = t.path().join("vault").join("vault.bin");
        Env { _t: t, key, file }
    }

    fn ready(e: &Env) -> Vault {
        match open(&e.key, &e.file) {
            VaultState::Ready(v) => v,
            VaultState::Unavailable(r) => panic!("unavailable: {r}"),
        }
    }

    fn reason(e: &Env) -> String {
        match open(&e.key, &e.file) {
            VaultState::Ready(_) => panic!("ready"),
            VaultState::Unavailable(r) => r,
        }
    }

    #[test]
    fn round_trip_put_reopen() {
        let e = env();
        let mut v = ready(&e);
        v.put(entry("gh", "s3cret-value")).unwrap();
        drop(v);
        let v = ready(&e);
        let got = v.get("gh").unwrap();
        assert_eq!(got.fields["token"].as_str(), "s3cret-value");
        assert_eq!(got.allowed_services, vec!["github".to_string()]);
        assert_eq!(v.list().len(), 1);
        let raw = std::fs::read(&e.file).unwrap();
        assert!(!raw.windows(12).any(|w| w == b"s3cret-value"));
        assert_eq!(&raw[..8], MAGIC);
        assert_eq!(raw[8], VERSION);
    }

    #[test]
    fn new_nonce_every_write() {
        let e = env();
        let mut v = ready(&e);
        v.put(entry("gh", "x")).unwrap();
        let a = std::fs::read(&e.file).unwrap();
        v.put(entry("gh", "x")).unwrap();
        let b = std::fs::read(&e.file).unwrap();
        assert_ne!(a[9..33], b[9..33]);
    }

    #[test]
    fn aad_binds_magic_and_version() {
        let e = env();
        ready(&e).put(entry("gh", "x")).unwrap();
        let mut raw = std::fs::read(&e.file).unwrap();
        raw[8] ^= 1;
        std::fs::write(&e.file, &raw).unwrap();
        assert_eq!(reason(&e), "vault cannot be decrypted");
        raw[8] ^= 1;
        raw[0] ^= 1;
        std::fs::write(&e.file, &raw).unwrap();
        assert_eq!(reason(&e), "vault file is not a saiife vault");
        std::fs::write(&e.file, b"short").unwrap();
        assert_eq!(reason(&e), "vault file is not a saiife vault");
    }

    #[test]
    fn wrong_key_is_unavailable() {
        let e = env();
        ready(&e).put(entry("gh", "x")).unwrap();
        std::fs::write(&e.key, [8u8; 32]).unwrap();
        assert_eq!(reason(&e), "vault cannot be decrypted");
    }

    #[test]
    fn short_key_is_unavailable() {
        let e = env();
        std::fs::write(&e.key, [7u8; 31]).unwrap();
        assert_eq!(reason(&e), "vault key is not 32 bytes");
        std::fs::write(&e.key, [7u8; 33]).unwrap();
        assert_eq!(reason(&e), "vault key is not 32 bytes");
        std::fs::remove_file(&e.key).unwrap();
        assert_eq!(reason(&e), "no vault key");
    }

    #[test]
    fn missing_vault_with_good_key_is_empty() {
        let e = env();
        let v = ready(&e);
        assert!(v.list().is_empty());
        assert!(!e.file.exists());
    }

    #[test]
    fn atomic_write_leaves_no_temp_on_success() {
        let e = env();
        let mut v = ready(&e);
        v.put(entry("gh", "x")).unwrap();
        v.remove("gh").unwrap();
        let names: Vec<_> = std::fs::read_dir(e.file.parent().unwrap())
            .unwrap()
            .map(|d| d.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("vault.bin")]);
    }

    #[test]
    fn failed_rename_keeps_old_vault() {
        let e = env();
        let mut v = ready(&e);
        v.put(entry("gh", "old")).unwrap();
        let before = std::fs::read(&e.file).unwrap();
        // Seam: the target becomes a non-empty dir, so the rename fails
        // after the temp file was written.
        let moved = e.file.with_file_name("moved.bin");
        std::fs::rename(&e.file, &moved).unwrap();
        std::fs::create_dir(&e.file).unwrap();
        std::fs::write(e.file.join("x"), b"x").unwrap();
        let r = v.put(entry("gh", "new"));
        assert!(r.is_err());
        std::fs::remove_dir_all(&e.file).unwrap();
        std::fs::rename(&moved, &e.file).unwrap();
        assert_eq!(std::fs::read(&e.file).unwrap(), before);
        // The in-memory view did not move ahead of the file.
        assert_eq!(v.get("gh").unwrap().fields["token"].as_str(), "old");
        assert_eq!(
            std::fs::read_dir(e.file.parent().unwrap()).unwrap().count(),
            1
        );
    }

    #[test]
    fn file_and_dir_modes_0600_0700() {
        let e = env();
        ready(&e).put(entry("gh", "x")).unwrap();
        let f = std::fs::metadata(&e.file).unwrap().permissions().mode() & 0o777;
        let d = std::fs::metadata(e.file.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!((f, d), (0o600, 0o700));
    }

    #[test]
    fn debug_never_prints_values() {
        let en = entry("gh", "very-secret-value");
        let s = format!("{en:?}");
        assert!(!s.contains("very-secret-value"), "{s}");
        assert!(s.contains("token"));
    }

    #[test]
    fn add_refuses_when_vault_undecryptable() {
        let e = env();
        ready(&e).put(entry("gh", "x")).unwrap();
        std::fs::write(&e.key, [9u8; 32]).unwrap();
        // There is no `Vault` to call `put` on: only a reason.
        assert!(matches!(open(&e.key, &e.file), VaultState::Unavailable(_)));
    }

    #[test]
    fn names_are_checked() {
        let e = env();
        let mut v = ready(&e);
        for bad in ["", "A", "-a", "a/b", "a b", &"a".repeat(65)] {
            assert!(v.put(entry(bad, "x")).is_err(), "{bad}");
        }
        for ok in ["a", "0a", "gh.prod_1-x", &"a".repeat(64)] {
            v.put(entry(ok, "x")).unwrap();
        }
    }

    #[test]
    fn remove_reports_presence() {
        let e = env();
        let mut v = ready(&e);
        v.put(entry("gh", "x")).unwrap();
        assert!(v.remove("gh").unwrap());
        assert!(!v.remove("gh").unwrap());
        assert!(ready(&e).get("gh").is_none());
    }

    #[test]
    fn last_used_flushed_at_most_once_per_minute() {
        let e = env();
        let mut v = ready(&e);
        v.put(entry("gh", "x")).unwrap();
        let t0 = Instant::now();
        v.touch("gh", "2026-10-26T10:01:00Z");
        // A put just wrote; a flush inside the minute does nothing.
        assert!(!v.flush_if_due(t0 + Duration::from_secs(10)).unwrap());
        assert_eq!(ready(&e).get("gh").unwrap().last_used, None);
        assert!(v.flush_if_due(t0 + Duration::from_secs(61)).unwrap());
        assert_eq!(
            ready(&e).get("gh").unwrap().last_used.as_deref(),
            Some("2026-10-26T10:01:00Z")
        );
        // Nothing dirty: no write. A new touch inside the minute waits.
        assert!(!v.flush_if_due(t0 + Duration::from_secs(200)).unwrap());
        v.touch("gh", "2026-10-26T10:05:00Z");
        assert!(!v.flush_if_due(t0 + Duration::from_secs(100)).unwrap());
        v.flush().unwrap();
        assert_eq!(
            ready(&e).get("gh").unwrap().last_used.as_deref(),
            Some("2026-10-26T10:05:00Z")
        );
    }

    #[test]
    fn existing_dir_is_fixed_to_0700_and_symlinked_dir_refused() {
        let e = env();
        let dir = e.file.parent().unwrap().to_path_buf();
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Open fixes it too.
        let _ = ready(&e);
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        ready(&e).put(entry("gh", "x")).unwrap();
        assert_eq!(mode(&dir), 0o700);
        // A symlinked vault dir is refused at open and at write.
        let other = e.file.parent().unwrap().parent().unwrap().join("elsewhere");
        std::fs::create_dir(&other).unwrap();
        let mut v = ready(&e);
        std::fs::remove_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink(&other, &dir).unwrap();
        assert!(v.put(entry("gh", "y")).is_err());
        assert_eq!(std::fs::read_dir(&other).unwrap().count(), 0);
        assert_eq!(reason(&e), "vault file is not a saiife vault");
    }

    #[test]
    fn failure_after_rename_counts_as_committed() {
        let e = env();
        let mut v = ready(&e);
        v.put(entry("gh", "x")).unwrap();
        v.dir_sync = |_| Err(io::Error::other("injected"));
        v.put(entry("gh2", "y")).unwrap();
        assert!(v.get("gh2").is_some());
        assert!(v.remove("gh").unwrap());
        assert!(v.get("gh").is_none());
        // The file agrees with memory: the removed secret is not back.
        let on_disk = ready(&e);
        assert!(on_disk.get("gh").is_none());
        assert!(on_disk.get("gh2").is_some());
    }

    #[test]
    fn fifo_or_symlinked_key_is_unavailable_without_blocking() {
        let e = env();
        std::fs::remove_file(&e.key).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &e.key,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        let t = Instant::now();
        assert_eq!(reason(&e), "no vault key");
        assert!(t.elapsed() < Duration::from_secs(1));
        std::fs::remove_file(&e.key).unwrap();
        let real = e.key.with_file_name("real-key");
        std::fs::write(&real, KEY).unwrap();
        std::os::unix::fs::symlink(&real, &e.key).unwrap();
        assert_eq!(reason(&e), "no vault key");
    }

    #[test]
    fn fifo_or_symlinked_vault_file_is_unavailable() {
        let e = env();
        ready(&e).put(entry("gh", "x")).unwrap();
        let real = e.file.with_file_name("real.bin");
        std::fs::rename(&e.file, &real).unwrap();
        std::os::unix::fs::symlink(&real, &e.file).unwrap();
        assert_eq!(reason(&e), "vault file is not a saiife vault");
        std::fs::remove_file(&e.file).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &e.file,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        let t = Instant::now();
        assert_eq!(reason(&e), "vault file is not a saiife vault");
        assert!(t.elapsed() < Duration::from_secs(1));
    }
}
