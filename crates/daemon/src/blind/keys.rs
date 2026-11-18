//! The dataset key store (R47-1, R47-2): each dataset's `KeySet` sealed
//! with the vault key into `<blind>/datasets/<name>/keys.sealed` (0600),
//! AAD `b"saiife-blind-keys-v1\0" ‖ name`. Not a `vault.bin` entry: no
//! `secret` op and no connector sees it. An unavailable vault refuses (fail
//! closed); nothing here falls back to unkeyed stand-ins. Keys never leave
//! the daemon. No op records here (ruling P47-4): the callers do.

use super::{lock, Refusal};
use crate::ops::Ctx;
use crate::vault::{VaultError, VaultState};
use saiife_ipc::msg::ErrorCode;
use saiife_shield::index::{BLOOM_FILE, INDEX_FILE};
use saiife_shield::schema::DatasetName;
use saiife_shield::standin::KeySet;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// The sealed key file in a dataset's dir.
pub const KEYS_FILE: &str = "keys.sealed";
/// How long a retired stand-in key is kept (R47-2).
pub const RETIRED_DAYS: u32 = 30;
const AAD_PREFIX: &[u8] = b"saiife-blind-keys-v1\0";
/// Larger than any key file: 30 days of daily rotations is a few KiB.
const MAX_SEALED_BYTES: u64 = 1 << 20;

/// Why a key store call failed. Never holds key bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// The vault key is not loaded.
    VaultUnavailable,
    /// `keys.sealed` does not open (altered, short, another vault key or
    /// another dataset's file).
    Damaged,
    /// The dataset has no keys.
    Missing,
    /// `create` found keys already there.
    Exists,
    /// The file could not be read or written.
    Io(String),
}

impl KeyError {
    /// What an op answers for this error.
    pub fn refusal(&self, ds: &DatasetName) -> Refusal {
        match self {
            KeyError::VaultUnavailable => {
                Refusal::new(ErrorCode::Unavailable, "the vault is unavailable")
            }
            KeyError::Damaged => Refusal::new(
                ErrorCode::Unavailable,
                format!(
                    "the dataset keys cannot be opened: saiife blind keys delete --dataset {ds} starts over"
                ),
            ),
            KeyError::Missing => Refusal::new(
                ErrorCode::Unavailable,
                format!("{ds} has no keys: saiife blind data refresh --dataset {ds}"),
            ),
            KeyError::Exists => {
                Refusal::new(ErrorCode::BadRequest, format!("{ds} already has keys"))
            }
            KeyError::Io(e) => Refusal::new(
                ErrorCode::Unavailable,
                format!("the keys of {ds} cannot be stored: {e}"),
            ),
        }
    }
}

fn io_err(e: io::Error) -> KeyError {
    KeyError::Io(e.kind().to_string())
}

fn aad(ds: &DatasetName) -> Vec<u8> {
    let mut a = AAD_PREFIX.to_vec();
    a.extend_from_slice(ds.as_str().as_bytes());
    a
}

fn path_of(ctx: &Ctx, ds: &DatasetName) -> PathBuf {
    ctx.blind.dataset_dir(ds).root.join(KEYS_FILE)
}

fn vault_ready(ctx: &Ctx) -> Result<(), KeyError> {
    match &*ctx.vault.lock() {
        VaultState::Ready(_) => Ok(()),
        VaultState::Unavailable(_) => Err(KeyError::VaultUnavailable),
    }
}

/// Now, RFC 3339 UTC (what `KeySet::purge_retired` reads back).
fn now() -> (String, u64) {
    let secs = crate::workspace::now_secs();
    (crate::tokens::rfc3339(secs), secs)
}

/// The sealed bytes at `p`, never through a link, at most
/// [`MAX_SEALED_BYTES`].
fn read_sealed(p: &Path) -> Result<Vec<u8>, KeyError> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(p);
    let f = match f {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(KeyError::Missing),
        // A link where the file should be: not ours.
        Err(e) if e.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) => {
            return Err(KeyError::Damaged)
        }
        Err(e) => return Err(io_err(e)),
    };
    let mut b = Vec::new();
    f.take(MAX_SEALED_BYTES + 1)
        .read_to_end(&mut b)
        .map_err(io_err)?;
    if b.len() as u64 > MAX_SEALED_BYTES {
        return Err(KeyError::Damaged);
    }
    Ok(b)
}

fn open(ctx: &Ctx, ds: &DatasetName, sealed: &[u8]) -> Result<KeySet, KeyError> {
    let plain = ctx
        .vault
        .open_sealed(&aad(ds), sealed)
        .map_err(|e| match e {
            VaultError::Unavailable => KeyError::VaultUnavailable,
            VaultError::Random | VaultError::Crypto => KeyError::Damaged,
        })?;
    KeySet::from_bytes(&plain).map_err(|_| KeyError::Damaged)
}

fn store(ctx: &Ctx, ds: &DatasetName, keys: &KeySet) -> Result<(), KeyError> {
    let sealed = ctx
        .vault
        .seal(&aad(ds), &keys.to_bytes())
        .map_err(|e| match e {
            VaultError::Unavailable => KeyError::VaultUnavailable,
            VaultError::Random | VaultError::Crypto => KeyError::Io(e.to_string()),
        })?;
    super::private_dir(&ctx.blind.root).map_err(io_err)?;
    super::write_private(&path_of(ctx, ds), &sealed).map_err(io_err)
}

/// The dataset's keys.
pub fn load(ctx: &Ctx, ds: &DatasetName) -> Result<KeySet, KeyError> {
    vault_ready(ctx)?;
    let sealed = read_sealed(&path_of(ctx, ds))?;
    open(ctx, ds, &sealed)
}

/// New keys for a dataset that has none; refuses ([`KeyError::Exists`])
/// when `keys.sealed` is there, damaged or not.
pub fn create(ctx: &Ctx, ds: &DatasetName) -> Result<KeySet, KeyError> {
    let _g = ctx.blind.keys_lock();
    vault_ready(ctx)?;
    let p = path_of(ctx, ds);
    match std::fs::symlink_metadata(&p) {
        Ok(_) => return Err(KeyError::Exists),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_err(e)),
    }
    let keys = KeySet::generate(&now().0).map_err(|e| KeyError::Io(e.to_string()))?;
    store(ctx, ds, &keys)?;
    Ok(keys)
}

/// A new stand-in key; the old one stays sealed as retired for
/// [`RETIRED_DAYS`] (older retired keys are purged now), and the
/// dataset's sessions are dropped. The index key is kept. The new version.
pub fn rotate(ctx: &Ctx, ds: &DatasetName) -> Result<u32, KeyError> {
    let _g = ctx.blind.keys_lock();
    let mut keys = load(ctx, ds)?;
    let (text, secs) = now();
    keys.rotate(&text)
        .map_err(|e| KeyError::Io(e.to_string()))?;
    keys.purge_retired(secs, RETIRED_DAYS);
    store(ctx, ds, &keys)?;
    lock(&ctx.blind.sessions).drop_dataset(ds);
    Ok(keys.version)
}

/// Crypto-shredding (R47-2): `keys.sealed` overwritten once with zeros,
/// fsynced and unlinked; every session of the dataset dropped; the index
/// built with the old index key removed; the dataset marked needs-refresh
/// (the next refresh makes new keys). Needs no vault. Nothing to remove is
/// not an error.
pub fn shred(ctx: &Ctx, ds: &DatasetName) -> Result<(), KeyError> {
    let _g = ctx.blind.keys_lock();
    let dir = ctx.blind.dataset_dir(ds);
    let p = dir.root.join(KEYS_FILE);
    // Sessions first: no ask derives from the old key after this point.
    lock(&ctx.blind.sessions).drop_dataset(ds);
    ctx.blind.set_state(
        ds,
        super::DatasetState::NeedsRefresh(format!(
            "the keys of {ds} were deleted: saiife blind data refresh --dataset {ds}"
        )),
    );
    match std::fs::symlink_metadata(&p) {
        Ok(md) if md.is_file() => {
            zero_fill(&p, md.len()).map_err(io_err)?;
            std::fs::remove_file(&p).map_err(io_err)?;
        }
        // Not a regular file (a link): unlinked, its target never touched.
        Ok(_) => std::fs::remove_file(&p).map_err(io_err)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_err(e)),
    }
    for f in [INDEX_FILE, BLOOM_FILE] {
        match std::fs::remove_file(dir.live().join(f)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(io_err(e)),
            _ => {}
        }
    }
    if dir.root.exists() {
        crate::fsx::sync_dir(&dir.root).map_err(io_err)?;
    }
    if dir.live().exists() {
        crate::fsx::sync_dir(&dir.live()).map_err(io_err)?;
    }
    Ok(())
}

/// Overwrites the first `len` bytes of `p` with zeros, in place, and fsyncs.
fn zero_fill(p: &Path, len: u64) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(p)?;
    let zeros = [0u8; 4096];
    let mut left = len;
    while left > 0 {
        let n = left.min(zeros.len() as u64) as usize;
        f.write_all(&zeros[..n])?;
        left -= n as u64;
    }
    f.sync_all()
}
