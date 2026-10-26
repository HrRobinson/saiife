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
    let f = std::fs::File::open(key_file).map_err(|_| "no vault key")?;
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
    };
    let raw = match std::fs::File::open(vault_file) {
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
        if let Err(err) = self.write(Instant::now()) {
            match old {
                Some(o) => self.entries.insert(name, o),
                None => self.entries.remove(&name),
            };
            return Err(err);
        }
        Ok(())
    }

    /// Remove and write; `false` when there was no such entry.
    pub fn remove(&mut self, name: &str) -> io::Result<bool> {
        let Some(old) = self.entries.remove(name) else {
            return Ok(false);
        };
        if let Err(err) = self.write(Instant::now()) {
            self.entries.insert(name.to_string(), old);
            return Err(err);
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
        self.write(now)?;
        Ok(true)
    }

    /// Write pending changes now (on stop).
    pub fn flush(&mut self) -> io::Result<()> {
        if self.dirty {
            self.write(Instant::now())?;
        }
        Ok(())
    }

    fn write(&mut self, now: Instant) -> io::Result<()> {
        // Reserved up front so growth does not leave plaintext copies in
        // freed memory for typical vault sizes.
        let mut plain = Zeroizing::new(Vec::with_capacity(64 * 1024));
        let body = BodyRef {
            entries: self.entries.values().collect(),
        };
        serde_json::to_writer(&mut *plain, &body).map_err(io::Error::other)?;
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|e| io::Error::other(e.to_string()))?;
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
            .map_err(|_| io::Error::other("cannot encrypt the vault"))?;
        let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
        out.extend_from_slice(&head);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        write_atomic(&self.file, &out)?;
        self.dirty = false;
        self.last_write = Some(now);
        Ok(())
    }
}

/// Temp file in the same dir (0600), fsync, rename, fsync the dir. The dir
/// is created 0700. A failure removes the temp file and leaves the old
/// file as it was.
fn write_atomic(file: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = file
        .parent()
        .ok_or_else(|| io::Error::other("vault path has no directory"))?;
    if !dir.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    let tmp = dir.join(".vault.bin.tmp");
    let _ = std::fs::remove_file(&tmp);
    let res = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, file)?;
        std::fs::File::open(dir)?.sync_all()
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
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
        let dir = e.file.parent().unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let r = v.put(entry("gh", "new"));
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(r.is_err());
        assert_eq!(std::fs::read(&e.file).unwrap(), before);
        // The in-memory view did not move ahead of the file.
        assert_eq!(v.get("gh").unwrap().fields["token"].as_str(), "old");
        assert_eq!(std::fs::read_dir(dir).unwrap().count(), 1);
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
}
