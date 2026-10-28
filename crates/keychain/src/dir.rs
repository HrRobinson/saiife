//! The debug-only test seam: one 0600 file per item in a 0700 dir.
//!
//! Selected by `SAIIFE_TEST_KEYCHAIN=<dir>` in debug builds (see
//! [`crate::from_env`]). It is not compiled into release builds.

use crate::{ItemId, Keychain, KeychainError};
use std::fs::{self, OpenOptions, Permissions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// A [`Keychain`] kept as files: `<dir>/<service>.<account>`, mode 0600, in
/// a 0700 dir. Symlinked items and a symlinked dir are refused.
#[derive(Debug)]
pub struct DirKeychain {
    dir: PathBuf,
}

impl DirKeychain {
    /// Open `dir`, creating it if missing, and set it to 0700.
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self, KeychainError> {
        let dir = dir.into();
        let unavailable = |what: &str| {
            KeychainError::Unavailable(format!("test keychain {}: {what}", dir.display()))
        };
        match fs::symlink_metadata(&dir) {
            Ok(m) if m.file_type().is_symlink() => return Err(unavailable("is a symlink")),
            Ok(m) if !m.is_dir() => return Err(unavailable("is not a directory")),
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {
                fs::create_dir_all(&dir).map_err(|e| unavailable(&e.to_string()))?;
            }
            Err(e) => return Err(unavailable(&e.to_string())),
        }
        fs::set_permissions(&dir, Permissions::from_mode(0o700))
            .map_err(|e| unavailable(&e.to_string()))?;
        Ok(Self { dir })
    }

    fn item(&self, id: &ItemId) -> PathBuf {
        self.dir.join(format!("{}.{}", id.service, id.account))
    }

    /// `true` when the item exists as a plain file; an error for a symlink
    /// or anything else that is not a regular file.
    fn present(path: &Path) -> Result<bool, KeychainError> {
        match fs::symlink_metadata(path) {
            Ok(m) if m.file_type().is_symlink() => Err(other(path, "is a symlink")),
            Ok(m) if !m.is_file() => Err(other(path, "is not a regular file")),
            Ok(_) => Ok(true),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(e) => Err(other(path, &e.to_string())),
        }
    }
}

fn other(path: &Path, what: &str) -> KeychainError {
    KeychainError::Other(format!("test keychain item {}: {what}", path.display()))
}

impl Keychain for DirKeychain {
    fn get(&self, id: &ItemId) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
        let path = self.item(id);
        if !Self::present(&path)? {
            return Ok(None);
        }
        match fs::read(&path) {
            Ok(b) => Ok(Some(Zeroizing::new(b))),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(other(&path, &e.to_string())),
        }
    }

    fn set(&self, id: &ItemId, _label: &str, secret: &[u8]) -> Result<(), KeychainError> {
        let path = self.item(id);
        Self::present(&path)?;
        let tmp = self.dir.join(format!(".{}.{}.tmp", id.service, id.account));
        let _ = fs::remove_file(&tmp);
        let write = || -> std::io::Result<()> {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            f.set_permissions(Permissions::from_mode(0o600))?;
            f.write_all(secret)?;
            f.sync_all()?;
            fs::rename(&tmp, &path)
        };
        write().map_err(|e| {
            let _ = fs::remove_file(&tmp);
            other(&path, &e.to_string())
        })
    }

    fn delete(&self, id: &ItemId) -> Result<bool, KeychainError> {
        let path = self.item(id);
        if !Self::present(&path)? {
            return Ok(false);
        }
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(e) => Err(other(&path, &e.to_string())),
        }
    }

    fn backend(&self) -> &'static str {
        "dir"
    }
}
