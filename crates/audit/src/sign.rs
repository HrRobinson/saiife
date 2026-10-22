//! Ed25519 signing key of the locked-mode audit chain (spec §6.4.2, §8.6).
//!
//! The genesis `key` (and a `key_rotate`'s `new_key`) is the public key as
//! `ed25519:` + base64 of its SubjectPublicKeyInfo DER; checkpoints name the
//! key by its fingerprint, `ed25519:` + the SHA-256 hex of the raw public key.
//! The key file holds the 32-byte seed, mode 0600, and is never followed
//! through a symlink or silently replaced.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::chain::sha256_hex;

/// DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410); the 32-byte
/// public key follows it.
const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const KEY_PREFIX: &str = "ed25519:";
const SEED_LEN: u64 = 32;

/// The daemon's checkpoint signing key. The secret is zeroized when the key
/// drops (`ed25519-dalek` with `zeroize`); `Debug` shows the fingerprint only.
pub struct AuditKey {
    key: SigningKey,
}

impl std::fmt::Debug for AuditKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AuditKey({})", self.fingerprint())
    }
}

impl AuditKey {
    /// A new key from a 32-byte seed from the OS RNG.
    pub fn generate() -> io::Result<AuditKey> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut seed[..]).map_err(|e| io::Error::other(e.to_string()))?;
        Ok(AuditKey {
            key: SigningKey::from_bytes(&seed),
        })
    }

    /// Load the key at `path`, or create it when there is no file there.
    /// Returns the key and whether it was created.
    ///
    /// The file must be exactly 32 bytes, a regular file, mode 0600, and not
    /// a symlink (it is opened with `O_NOFOLLOW`). Anything else is an error
    /// naming the path and the problem, and the file is left as it is. A new
    /// key is created with `O_EXCL`, in a parent dir created 0700 if missing.
    pub fn load_or_create(path: &Path) -> io::Result<(AuditKey, bool)> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            create_key_dir(parent)?;
        }
        // Twice: a key created by someone else between our open and our
        // create is then loaded, never overwritten.
        for _ in 0..2 {
            match open_existing(path) {
                Ok(file) => return Ok((read_key(path, file)?, false)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            let key = AuditKey::generate()?;
            match create_new(path) {
                Ok(mut file) => {
                    let seed = Zeroizing::new(key.key.to_bytes());
                    file.write_all(&seed[..])
                        .and_then(|()| set_mode(&file, 0o600))
                        .and_then(|()| file.sync_all())
                        .map_err(|e| problem(path, &format!("cannot write the new key: {e}")))?;
                    sync_parent(path);
                    return Ok((key, true));
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(open_error(path, e)),
            }
        }
        Err(problem(path, "the key file keeps changing"))
    }

    /// Write `key` to `path` for key rotation: a 0600 temp file next to it,
    /// synced, then renamed over `path`.
    pub fn save_new(path: &Path, key: &AuditKey) -> io::Result<()> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        create_key_dir(parent)?;
        let name = path
            .file_name()
            .ok_or_else(|| problem(path, "not a file path"))?;
        let tmp = parent.join(format!(".{}.new", name.to_string_lossy()));
        // A temp file left by a crash: remove it (never follows a symlink).
        match fs::remove_file(&tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(problem(&tmp, &format!("cannot remove: {e}"))),
        }
        let written = (|| {
            let mut file = create_new(&tmp)?;
            let seed = Zeroizing::new(key.key.to_bytes());
            file.write_all(&seed[..])?;
            set_mode(&file, 0o600)?;
            file.sync_all()?;
            fs::rename(&tmp, path)
        })();
        if let Err(e) = written {
            let _ = fs::remove_file(&tmp);
            return Err(problem(path, &format!("cannot save the new key: {e}")));
        }
        sync_parent(path);
        Ok(())
    }

    /// `ed25519:` + base64 of the SubjectPublicKeyInfo DER (starts
    /// `MCowBQYDK2VwAyEA`): the genesis `key` and a rotation's `new_key`.
    pub fn spki(&self) -> String {
        let mut der = SPKI_PREFIX.to_vec();
        der.extend_from_slice(self.key.verifying_key().as_bytes());
        format!("{KEY_PREFIX}{}", B64.encode(der))
    }

    /// `ed25519:` + SHA-256 hex of the raw public key: a checkpoint's `key`.
    pub fn fingerprint(&self) -> String {
        format!(
            "{KEY_PREFIX}{}",
            sha256_hex(self.key.verifying_key().as_bytes())
        )
    }

    /// Base64 of the 64-byte Ed25519 signature of `msg`.
    pub fn sign_b64(&self, msg: &[u8]) -> String {
        B64.encode(self.key.sign(msg).to_bytes())
    }
}

/// The raw public key of an `ed25519:<spki b64>` string.
fn public_key_of(spki: &str) -> Option<[u8; 32]> {
    let der = B64.decode(spki.strip_prefix(KEY_PREFIX)?).ok()?;
    let pk = der.strip_prefix(&SPKI_PREFIX[..])?;
    pk.try_into().ok()
}

/// The fingerprint of an `ed25519:<spki b64>` public key; `None` if it is
/// not one.
pub fn fingerprint_of(spki: &str) -> Option<String> {
    public_key_of(spki).map(|pk| format!("{KEY_PREFIX}{}", sha256_hex(&pk)))
}

/// Whether `sig_b64` is a valid signature of `msg` by the key `spki`
/// (strict verification: no small-order keys, no malleable signatures).
pub fn verify_b64(spki: &str, msg: &[u8], sig_b64: &str) -> bool {
    let Some(pk) = public_key_of(spki) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    let Some(sig) = B64
        .decode(sig_b64)
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b.as_slice()).ok())
    else {
        return false;
    };
    vk.verify_strict(msg, &Signature::from_bytes(&sig)).is_ok()
}

/// The message a checkpoint signs (spec §6.4.2), without a final newline.
pub fn checkpoint_message(chain: &str, head_seq: u64, head: &str, ts: &str) -> String {
    format!("saiife-checkpoint-v1\n{chain}\n{head_seq}\n{head}\n{ts}")
}

/// The message a `key_rotate` signs with the old key, without a final newline.
pub fn key_rotate_message(
    chain: &str,
    head_seq: u64,
    head: &str,
    new_key: &str,
    ts: &str,
) -> String {
    format!("saiife-key-rotate-v1\n{chain}\n{head_seq}\n{head}\n{new_key}\n{ts}")
}

fn problem(path: &Path, what: &str) -> io::Error {
    io::Error::other(format!("audit key {}: {what}", path.display()))
}

/// The error of opening `path`, with a symlink named as such.
fn open_error(path: &Path, e: io::Error) -> io::Error {
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return problem(path, "is a symlink, refusing to follow it");
    }
    #[cfg(unix)]
    if e.raw_os_error() == Some(libc::ELOOP) {
        return problem(path, "is a symlink, refusing to follow it");
    }
    problem(path, &format!("cannot open: {e}"))
}

/// `path` opened for reading without following a symlink. `NotFound` is
/// passed through as is (the caller creates the key then).
fn open_existing(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    match opts.open(path) {
        Ok(f) => Ok(f),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // A dangling symlink also opens as NotFound: never create through it.
            if fs::symlink_metadata(path).is_ok() {
                return Err(open_error(path, e));
            }
            Err(e)
        }
        Err(e) => Err(open_error(path, e)),
    }
}

/// A new file at `path`, 0600, `O_EXCL` (and `O_NOFOLLOW`).
fn create_new(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path)
}

/// The key in an opened key file, after checking its type, mode and size.
fn read_key(path: &Path, mut file: File) -> io::Result<AuditKey> {
    let md = file
        .metadata()
        .map_err(|e| problem(path, &format!("cannot stat: {e}")))?;
    if !md.is_file() {
        return Err(problem(path, "is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = md.permissions().mode() & 0o7777;
        if mode != 0o600 {
            return Err(problem(path, &format!("has mode {mode:04o}, must be 0600")));
        }
    }
    if md.len() != SEED_LEN {
        return Err(problem(
            path,
            &format!("is {} bytes, must be exactly 32 bytes", md.len()),
        ));
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    file.read_exact(&mut seed[..])
        .map_err(|e| problem(path, &format!("cannot read: {e}")))?;
    // The file must not have grown between the stat and the read.
    let mut extra = [0u8; 1];
    if file
        .read(&mut extra)
        .map_err(|e| problem(path, &e.to_string()))?
        != 0
    {
        return Err(problem(path, "must be exactly 32 bytes"));
    }
    Ok(AuditKey {
        key: SigningKey::from_bytes(&seed),
    })
}

/// The key dir: created 0700 when missing; an existing one must be a
/// directory (it keeps its mode).
fn create_key_dir(dir: &Path) -> io::Result<()> {
    match fs::metadata(dir) {
        Ok(md) if md.is_dir() => return Ok(()),
        Ok(_) => return Err(problem(dir, "is not a directory")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(problem(dir, &format!("cannot stat: {e}"))),
    }
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
        .map_err(|e| problem(dir, &format!("cannot create the key dir: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| problem(dir, &format!("cannot chmod the key dir: {e}")))?;
    }
    Ok(())
}

fn set_mode(file: &File, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = (file, mode);
        Ok(())
    }
}

/// Best-effort fsync of the dir holding `path`, so a new name survives a crash.
fn sync_parent(path: &Path) {
    #[cfg(unix)]
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if let Ok(d) = File::open(parent) {
            let _ = d.sync_all();
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use std::fs;

    #[test]
    fn checkpoint_message_is_exact() {
        assert_eq!(
            checkpoint_message("c", 5, "ab", "2026-11-02T08:30:00.000Z"),
            "saiife-checkpoint-v1\nc\n5\nab\n2026-11-02T08:30:00.000Z"
        );
        assert_eq!(
            key_rotate_message("c", 5, "ab", "ed25519:K", "2026-11-02T08:30:00.000Z"),
            "saiife-key-rotate-v1\nc\n5\nab\ned25519:K\n2026-11-02T08:30:00.000Z"
        );
    }

    #[test]
    fn spki_has_spec_prefix() {
        let k = AuditKey::generate().unwrap();
        let spki = k.spki();
        assert!(spki.starts_with("ed25519:MCowBQYDK2VwAyEA"), "{spki}");
        let der = base64::engine::general_purpose::STANDARD
            .decode(spki.strip_prefix("ed25519:").unwrap())
            .unwrap();
        assert_eq!(der.len(), 44);
        let fp = k.fingerprint();
        assert!(fp.starts_with("ed25519:") && fp.len() == 8 + 64, "{fp}");
        assert_eq!(fingerprint_of(&spki), Some(fp));
        assert_eq!(fingerprint_of("ed25519:AAAA"), None);
        assert_eq!(fingerprint_of("nope"), None);
    }

    #[test]
    fn sign_verify_round_trip_and_tamper() {
        let k = AuditKey::generate().unwrap();
        let other = AuditKey::generate().unwrap();
        let msg = checkpoint_message("c", 5, "ab", "2026-11-02T08:30:00.000Z");
        let sig = k.sign_b64(msg.as_bytes());
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&sig)
            .unwrap();
        assert_eq!(raw.len(), 64);
        assert!(verify_b64(&k.spki(), msg.as_bytes(), &sig));
        assert!(!verify_b64(&k.spki(), b"other message", &sig));
        assert!(!verify_b64(&other.spki(), msg.as_bytes(), &sig));
        let mut bad = sig.clone().into_bytes();
        bad[0] = if bad[0] == b'A' { b'B' } else { b'A' };
        let bad = String::from_utf8(bad).unwrap();
        assert!(!verify_b64(&k.spki(), msg.as_bytes(), &bad));
        assert!(!verify_b64(&k.spki(), msg.as_bytes(), "not base64!"));
        assert!(!verify_b64("ed25519:AAAA", msg.as_bytes(), &sig));
    }

    #[cfg(unix)]
    fn mode(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(p).unwrap().permissions().mode() & 0o7777
    }

    #[cfg(unix)]
    #[test]
    fn key_file_is_0600_32_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys/audit.ed25519");
        let (k, created) = AuditKey::load_or_create(&path).unwrap();
        assert!(created);
        assert_eq!(fs::metadata(&path).unwrap().len(), 32);
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&dir.path().join("keys")), 0o700);
        let (again, created) = AuditKey::load_or_create(&path).unwrap();
        assert!(!created);
        assert_eq!(again.spki(), k.spki());

        let next = AuditKey::generate().unwrap();
        AuditKey::save_new(&path, &next).unwrap();
        assert_eq!(mode(&path), 0o600);
        let (loaded, created) = AuditKey::load_or_create(&path).unwrap();
        assert!(!created);
        assert_eq!(loaded.spki(), next.spki());
        let names: Vec<_> = fs::read_dir(dir.path().join("keys"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["audit.ed25519"], "no temp file is left behind");
    }

    #[cfg(unix)]
    #[test]
    fn key_file_wrong_mode_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.ed25519");
        AuditKey::load_or_create(&path).unwrap();
        let before = fs::read(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let err = AuditKey::load_or_create(&path).unwrap_err().to_string();
        assert!(err.contains(&path.display().to_string()), "{err}");
        assert!(err.contains("0644"), "{err}");
        assert_eq!(fs::read(&path).unwrap(), before, "never replaced");
    }

    #[test]
    fn key_file_wrong_size_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.ed25519");
        for len in [0usize, 31, 33, 64] {
            fs::write(&path, vec![7u8; len]).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            let err = AuditKey::load_or_create(&path).unwrap_err().to_string();
            assert!(err.contains(&path.display().to_string()), "{err}");
            assert!(err.contains("32 bytes"), "{err}");
            assert_eq!(fs::read(&path).unwrap().len(), len, "never replaced");
        }
    }

    #[cfg(unix)]
    #[test]
    fn key_file_symlink_refused() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.ed25519");
        AuditKey::load_or_create(&real).unwrap();
        let link = dir.path().join("audit.ed25519");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = AuditKey::load_or_create(&link).unwrap_err().to_string();
        assert!(err.contains(&link.display().to_string()), "{err}");
        assert!(err.contains("symlink"), "{err}");
        // A dangling link is not followed to create a key elsewhere.
        let dangling = dir.path().join("dangling.ed25519");
        std::os::unix::fs::symlink(dir.path().join("elsewhere"), &dangling).unwrap();
        assert!(AuditKey::load_or_create(&dangling).is_err());
        assert!(!dir.path().join("elsewhere").exists());
    }
}
