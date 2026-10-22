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

    /// Load the key at `path`, or create it, for the effective uid: see
    /// `load_or_create_owned`.
    #[cfg(unix)]
    pub fn load_or_create(path: &Path) -> io::Result<(AuditKey, bool)> {
        load_or_create_owned(path, rustix::process::geteuid().as_raw())
    }

    /// The key file's owner and mode checks need Unix.
    #[cfg(not(unix))]
    pub fn load_or_create(path: &Path) -> io::Result<(AuditKey, bool)> {
        Err(problem(path, "the audit signing key needs a Unix system"))
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

/// Load the key at `path`, or create it when there is no file there,
/// checking that `owner` owns it. Returns the key and whether it was created.
///
/// - The state dir (the key dir's parent) must not be a symlink nor
///   writable by group or others; it is created 0700 when missing.
/// - The key dir (`keys/`) must be a real directory owned by `owner` with
///   no group or other access; it is created 0700 (`mkdirat` in the state
///   dir, opened `O_NOFOLLOW`) when missing.
/// - The key file is opened `O_NOFOLLOW` and must be a regular file owned
///   by `owner`, mode 0600, exactly 32 bytes.
///
/// Anything else is an error naming the path and what was wanted and
/// found, and nothing is changed. The first key is created crash-safe: a
/// synced 0600 `.audit.ed25519.tmp` (`O_EXCL`) is hard-linked to the final
/// name and then removed, so the key file never exists half-written.
/// Creators hold the key dir's flock, so a temp file seen under it is a
/// crash's leftover and is removed (`unlinkat`, which never follows). A link
/// that finds the name taken loads the key that won.
#[cfg(unix)]
pub fn load_or_create_owned(path: &Path, owner: u32) -> io::Result<(AuditKey, bool)> {
    let name = path
        .file_name()
        .ok_or_else(|| problem(path, "not a file path"))?;
    let keys_path = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let keys = unix::open_key_dir(keys_path, owner)?;
    if let Some(k) = unix::load_at(&keys, path, name, owner)? {
        return Ok((k, false));
    }
    keys.lock()
        .map_err(|e| problem(keys_path, &format!("cannot lock the key dir: {e}")))?;
    // Under the lock: a key another creator made meanwhile is loaded.
    if let Some(k) = unix::load_at(&keys, path, name, owner)? {
        return Ok((k, false));
    }
    let mut tmp = std::ffi::OsString::from(".");
    tmp.push(name);
    tmp.push(".tmp");
    let tmp = Path::new(&tmp);
    unix::remove_at(&keys, tmp).map_err(|e| {
        problem(
            &keys_path.join(tmp),
            &format!("cannot remove a temp file left by a crash: {e}"),
        )
    })?;
    let key = AuditKey::generate()?;
    if let Err(e) = unix::write_new_at(&keys, tmp, &key) {
        let _ = unix::remove_at(&keys, tmp);
        return Err(problem(path, &format!("cannot write the new key: {e}")));
    }
    let linked = rustix::fs::linkat(&keys, tmp, &keys, name, rustix::fs::AtFlags::empty());
    // A temp name left behind is only a second link to the same 0600 key
    // inside the checked 0700 dir: not worth failing the start for.
    let _ = unix::remove_at(&keys, tmp);
    match linked {
        Ok(()) => {
            let _ = keys.sync_all();
            Ok((key, true))
        }
        // Someone not holding the lock won the race: theirs is the key.
        Err(rustix::io::Errno::EXIST) => match unix::load_at(&keys, path, name, owner)? {
            Some(k) => Ok((k, false)),
            None => Err(problem(path, "the key file keeps changing")),
        },
        Err(e) => Err(problem(
            path,
            &format!("cannot link the new key into place: {e}"),
        )),
    }
}

/// What `judge` checks a path as.
#[cfg(unix)]
#[derive(Debug, Clone, Copy)]
enum Kind {
    /// The key dir's parent: a directory not writable by group or others.
    StateDir,
    /// `keys/`: a directory of the owner, no group or other access.
    KeyDir,
    /// The key file: a regular file of the owner, mode 0600.
    KeyFile,
}

/// Whether a `kind` with this `uid` and `st_mode` is acceptable for
/// `owner`: a pure decision, so the owner checks can be tested for owners
/// a test cannot be. The error names the path, and what was wanted and
/// found.
#[cfg(unix)]
fn judge(path: &Path, kind: Kind, uid: u32, mode: u32, owner: u32) -> io::Result<()> {
    const S_IFMT: u32 = 0o170000;
    const S_IFDIR: u32 = 0o040000;
    const S_IFREG: u32 = 0o100000;
    const S_IFLNK: u32 = 0o120000;
    let ty = mode & S_IFMT;
    let perm = mode & 0o7777;
    if ty == S_IFLNK {
        return Err(problem(path, "is a symlink, refusing to follow it"));
    }
    let want_ty = match kind {
        Kind::StateDir | Kind::KeyDir => S_IFDIR,
        Kind::KeyFile => S_IFREG,
    };
    if ty != want_ty {
        return Err(problem(
            path,
            match kind {
                Kind::KeyFile => "is not a regular file",
                _ => "is not a directory",
            },
        ));
    }
    if !matches!(kind, Kind::StateDir) && uid != owner {
        return Err(problem(
            path,
            &format!("is owned by uid {uid}, must be owned by uid {owner}"),
        ));
    }
    match kind {
        Kind::StateDir if perm & 0o022 != 0 => Err(problem(
            path,
            &format!("has mode {perm:04o}, must not be writable by group or others"),
        )),
        Kind::KeyDir if perm & 0o077 != 0 => Err(problem(
            path,
            &format!("has mode {perm:04o}, must be 0700 (no group or other access)"),
        )),
        Kind::KeyFile if perm != 0o600 => {
            Err(problem(path, &format!("has mode {perm:04o}, must be 0600")))
        }
        _ => Ok(()),
    }
}

/// The fd-relative steps of `load_or_create_owned`.
#[cfg(unix)]
mod unix {
    use super::{judge, problem, read_key, AuditKey, Kind};
    use rustix::fs::{Mode, OFlags};
    use rustix::io::Errno;
    use std::fs::{self, File};
    use std::io::{self, Write};
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use zeroize::Zeroizing;

    const DIR_FLAGS: OFlags = OFlags::DIRECTORY
        .union(OFlags::NOFOLLOW)
        .union(OFlags::RDONLY)
        .union(OFlags::CLOEXEC);

    /// The error of opening the dir `path` `O_NOFOLLOW`, with a symlink
    /// named as such.
    fn dir_error(path: &Path, e: Errno) -> io::Error {
        match fs::symlink_metadata(path) {
            Ok(m) if m.file_type().is_symlink() => {
                problem(path, "is a symlink, refusing to follow it")
            }
            Ok(m) if !m.is_dir() => problem(path, "is not a directory"),
            _ => problem(path, &format!("cannot open: {e}")),
        }
    }

    fn check(path: &Path, f: &File, kind: Kind, owner: u32) -> io::Result<()> {
        let md = f
            .metadata()
            .map_err(|e| problem(path, &format!("cannot stat: {e}")))?;
        judge(path, kind, md.uid(), md.mode(), owner)
    }

    /// The key dir, opened and checked (see `load_or_create_owned`).
    pub(super) fn open_key_dir(keys_path: &Path, owner: u32) -> io::Result<File> {
        let state_path = keys_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let keys_name = keys_path
            .file_name()
            .ok_or_else(|| problem(keys_path, "not a key dir path"))?;
        if fs::symlink_metadata(state_path).is_err_and(|e| e.kind() == io::ErrorKind::NotFound) {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(state_path)
                .map_err(|e| problem(state_path, &format!("cannot create: {e}")))?;
        }
        let state = File::from(
            rustix::fs::open(state_path, DIR_FLAGS, Mode::empty())
                .map_err(|e| dir_error(state_path, e))?,
        );
        check(state_path, &state, Kind::StateDir, owner)?;
        let open = || rustix::fs::openat(&state, keys_name, DIR_FLAGS, Mode::empty());
        let fd = match open() {
            Err(Errno::NOENT) => {
                match rustix::fs::mkdirat(&state, keys_name, Mode::RWXU) {
                    Ok(()) | Err(Errno::EXIST) => {}
                    Err(e) => {
                        return Err(problem(
                            keys_path,
                            &format!("cannot create the key dir: {e}"),
                        ))
                    }
                }
                open()
            }
            r => r,
        }
        .map_err(|e| dir_error(keys_path, e))?;
        let keys = File::from(fd);
        check(keys_path, &keys, Kind::KeyDir, owner)?;
        Ok(keys)
    }

    /// The key `name` in `keys`, checked; `None` when there is none.
    pub(super) fn load_at(
        keys: &File,
        path: &Path,
        name: &std::ffi::OsStr,
        owner: u32,
    ) -> io::Result<Option<AuditKey>> {
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        match rustix::fs::openat(keys, name, flags, Mode::empty()) {
            Ok(fd) => read_key(path, File::from(fd), owner).map(Some),
            Err(Errno::NOENT) => Ok(None),
            Err(Errno::LOOP) => Err(problem(path, "is a symlink, refusing to follow it")),
            Err(e) => Err(problem(path, &format!("cannot open: {e}"))),
        }
    }

    /// `unlinkat`, a missing name being fine.
    pub(super) fn remove_at(keys: &File, name: &Path) -> io::Result<()> {
        match rustix::fs::unlinkat(keys, name, rustix::fs::AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// `key`'s seed in a new file `name` in `keys`: `O_EXCL`, 0600, synced.
    pub(super) fn write_new_at(keys: &File, name: &Path, key: &AuditKey) -> io::Result<()> {
        let flags =
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut f = File::from(rustix::fs::openat(
            keys,
            name,
            flags,
            Mode::RUSR | Mode::WUSR,
        )?);
        let seed = Zeroizing::new(key.key.to_bytes());
        f.write_all(&seed[..])?;
        super::set_mode(&f, 0o600)?;
        f.sync_all()
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

/// The key in an opened key file, after checking (`fstat`) its type, owner,
/// mode and size.
#[cfg(unix)]
fn read_key(path: &Path, mut file: File, owner: u32) -> io::Result<AuditKey> {
    use std::os::unix::fs::MetadataExt;
    let md = file
        .metadata()
        .map_err(|e| problem(path, &format!("cannot stat: {e}")))?;
    judge(path, Kind::KeyFile, md.uid(), md.mode(), owner)?;
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

    /// `dir/keys`, 0700: a key dir that passes the owner and mode checks
    /// whatever the temp root is (`/tmp` is world-writable).
    #[cfg(unix)]
    fn keys(dir: &Path) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let k = dir.join("keys");
        fs::create_dir_all(&k).unwrap();
        fs::set_permissions(&k, fs::Permissions::from_mode(0o700)).unwrap();
        k
    }

    #[cfg(unix)]
    #[test]
    fn key_file_wrong_mode_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = keys(dir.path()).join("audit.ed25519");
        AuditKey::load_or_create(&path).unwrap();
        let before = fs::read(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let err = AuditKey::load_or_create(&path).unwrap_err().to_string();
        assert!(err.contains(&path.display().to_string()), "{err}");
        assert!(err.contains("0644"), "{err}");
        assert_eq!(fs::read(&path).unwrap(), before, "never replaced");
    }

    #[cfg(unix)]
    #[test]
    fn key_file_wrong_size_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = keys(dir.path()).join("audit.ed25519");
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
        let keys = keys(dir.path());
        let real = keys.join("real.ed25519");
        AuditKey::load_or_create(&real).unwrap();
        let link = keys.join("audit.ed25519");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = AuditKey::load_or_create(&link).unwrap_err().to_string();
        assert!(err.contains(&link.display().to_string()), "{err}");
        assert!(err.contains("symlink"), "{err}");
        // A dangling link is not followed to create a key elsewhere.
        let dangling = keys.join("dangling.ed25519");
        std::os::unix::fs::symlink(keys.join("elsewhere"), &dangling).unwrap();
        assert!(AuditKey::load_or_create(&dangling).is_err());
        assert!(!keys.join("elsewhere").exists());
    }

    #[cfg(unix)]
    fn chmod(p: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    fn me() -> u32 {
        rustix::process::getuid().as_raw()
    }

    #[cfg(unix)]
    #[test]
    fn key_dir_wrong_owner_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = keys(dir.path()).join("audit.ed25519");
        let err = load_or_create_owned(&path, me() + 1)
            .unwrap_err()
            .to_string();
        assert!(err.contains("owned by uid"), "{err}");
        assert!(err.contains(&format!("uid {}", me())), "{err}");
        assert!(err.contains(&format!("uid {}", me() + 1)), "{err}");
        assert!(
            err.contains(&dir.path().join("keys").display().to_string()),
            "{err}"
        );
        assert!(!path.exists(), "no key is created");
    }

    #[cfg(unix)]
    #[test]
    fn key_dir_group_readable_refused() {
        let dir = tempfile::tempdir().unwrap();
        let keys = keys(dir.path());
        chmod(&keys, 0o750);
        let err = AuditKey::load_or_create(&keys.join("audit.ed25519"))
            .unwrap_err()
            .to_string();
        assert!(err.contains(&keys.display().to_string()), "{err}");
        assert!(err.contains("0750") && err.contains("0700"), "{err}");
        assert!(!keys.join("audit.ed25519").exists());
    }

    #[cfg(unix)]
    #[test]
    fn key_dir_symlink_refused() {
        let dir = tempfile::tempdir().unwrap();
        let other = dir.path().join("other");
        fs::create_dir(&other).unwrap();
        chmod(&other, 0o700);
        let keys = dir.path().join("keys");
        std::os::unix::fs::symlink(&other, &keys).unwrap();
        let err = AuditKey::load_or_create(&keys.join("audit.ed25519"))
            .unwrap_err()
            .to_string();
        assert!(err.contains(&keys.display().to_string()), "{err}");
        assert!(err.contains("symlink"), "{err}");
        assert_eq!(fs::read_dir(&other).unwrap().count(), 0, "nothing created");
    }

    #[cfg(unix)]
    #[test]
    fn state_dir_world_writable_refused() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        fs::create_dir(&state).unwrap();
        chmod(&state, 0o777);
        let err = AuditKey::load_or_create(&state.join("keys/audit.ed25519"))
            .unwrap_err()
            .to_string();
        assert!(err.contains(&state.display().to_string()), "{err}");
        assert!(err.contains("0777"), "{err}");
        assert!(!state.join("keys").exists(), "no key dir is created");
        // A symlinked state dir is refused too.
        chmod(&state, 0o700);
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&state, &link).unwrap();
        let err = AuditKey::load_or_create(&link.join("keys/audit.ed25519"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("symlink"), "{err}");
        assert!(!state.join("keys").exists());
    }

    #[cfg(unix)]
    #[test]
    fn key_file_wrong_owner_refused() {
        let p = Path::new("/s/keys/audit.ed25519");
        let err = judge(p, Kind::KeyFile, 1001, 0o100600, 1000)
            .unwrap_err()
            .to_string();
        assert!(err.contains("owned by uid 1001"), "{err}");
        assert!(err.contains("uid 1000"), "{err}");
        assert!(err.contains("/s/keys/audit.ed25519"), "{err}");
        judge(p, Kind::KeyFile, 1000, 0o100600, 1000).unwrap();
        let err = judge(p, Kind::KeyFile, 1000, 0o100640, 1000)
            .unwrap_err()
            .to_string();
        assert!(err.contains("0640") && err.contains("0600"), "{err}");
        assert!(judge(p, Kind::KeyFile, 1000, 0o040600, 1000).is_err());
        // The key dir and state dir rules, for owners a test cannot be.
        let k = Path::new("/s/keys");
        judge(k, Kind::KeyDir, 0, 0o040700, 0).unwrap();
        judge(k, Kind::KeyDir, 0, 0o040500, 0).unwrap();
        let err = judge(k, Kind::KeyDir, 0, 0o040700, 998)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("owned by uid 0") && err.contains("uid 998"),
            "{err}"
        );
        assert!(judge(k, Kind::KeyDir, 998, 0o040701, 998).is_err());
        assert!(judge(k, Kind::KeyDir, 998, 0o120700, 998).is_err());
        let s = Path::new("/s");
        judge(s, Kind::StateDir, 0, 0o040755, 998).unwrap();
        assert!(judge(s, Kind::StateDir, 998, 0o040770, 998).is_err());
        assert!(judge(s, Kind::StateDir, 998, 0o040702, 998).is_err());
        assert!(judge(s, Kind::StateDir, 998, 0o100700, 998).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn crash_leftover_tmp_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let keys = keys(dir.path());
        let tmp = keys.join(".audit.ed25519.tmp");
        fs::write(&tmp, [1u8; 5]).unwrap();
        let path = keys.join("audit.ed25519");
        let (k, created) = AuditKey::load_or_create(&path).unwrap();
        assert!(created);
        assert_eq!(fs::metadata(&path).unwrap().len(), 32);
        assert_eq!(mode(&path), 0o600);
        assert!(!tmp.exists(), "the temp file is gone");
        let (again, _) = AuditKey::load_or_create(&path).unwrap();
        assert_eq!(again.spki(), k.spki());
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_create_yields_one_key() {
        for _ in 0..20 {
            let dir = tempfile::tempdir().unwrap();
            let path = keys(dir.path()).join("audit.ed25519");
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    let p = path.clone();
                    let b = std::sync::Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        b.wait();
                        AuditKey::load_or_create(&p).unwrap()
                    })
                })
                .collect();
            let got: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            assert_eq!(got[0].0.spki(), got[1].0.spki());
            assert_eq!(got.iter().filter(|(_, c)| *c).count(), 1, "one creator");
            assert_eq!(fs::read_dir(dir.path().join("keys")).unwrap().count(), 1);
        }
    }
}
