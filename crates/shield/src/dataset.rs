//! Plan 43: dataset (filled in by Task 7 of plan 43).
//!
//! The private-file helpers (Task 3 fix round, S1) live here so the snapshot,
//! the lexicon, the index, the Bloom filter, the allow list and the manifest
//! all write their files the same way: inside a directory that is ours and
//! 0700, as new 0600 files that never follow a symlink, then sealed 0400.

use crate::error::ShieldError;
use std::fs::File;
use std::path::Path;

fn io(why: &str) -> ShieldError {
    ShieldError::Io(why.to_string())
}

/// Makes `dir` (and any missing parents) 0700 at creation; an existing `dir`
/// must be a real directory (not a symlink) owned by us, and is tightened to
/// 0700 if group or other bits are set.
pub(crate) fn ensure_private_dir(dir: &Path) -> Result<(), ShieldError> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    match std::fs::symlink_metadata(dir) {
        Ok(md) if md.file_type().is_symlink() => {
            return Err(io("the dataset directory is a symlink"))
        }
        Ok(md) if !md.is_dir() => return Err(io("the dataset directory is not a directory")),
        Ok(_) => {}
        Err(_) => b
            .create(dir)
            .map_err(|_| io("could not make the dataset directory"))?,
    }
    // Check again after creating: what is there now must be ours.
    let md =
        std::fs::symlink_metadata(dir).map_err(|_| io("could not read the dataset directory"))?;
    if md.file_type().is_symlink() || !md.is_dir() {
        return Err(io("the dataset directory is not a directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if md.uid() != rustix::process::geteuid().as_raw() {
            return Err(io("the dataset directory belongs to another user"));
        }
        if md.mode() & 0o077 != 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| io("could not make the dataset directory private"))?;
        }
    }
    Ok(())
}

/// Creates a new file: `create_new`, 0600, never following a symlink. The
/// caller has made its directory private with [`ensure_private_dir`].
pub(crate) fn create_private_file(path: &Path) -> Result<File, ShieldError> {
    let mut o = std::fs::OpenOptions::new();
    o.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    let f = o
        .open(path)
        .map_err(|_| io("could not create a private file"))?;
    let md = f
        .metadata()
        .map_err(|_| io("could not create a private file"))?;
    if !md.is_file() {
        return Err(io("could not create a private file"));
    }
    Ok(f)
}

/// Flushes `f` to disk and makes it read-only (0400 on unix).
pub(crate) fn seal_file(f: &File) -> Result<(), ShieldError> {
    f.sync_all().map_err(|_| io("could not seal a file"))?;
    #[cfg(unix)]
    let perm = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::Permissions::from_mode(0o400)
    };
    #[cfg(not(unix))]
    let perm = {
        let mut p = f
            .metadata()
            .map_err(|_| io("could not seal a file"))?
            .permissions();
        p.set_readonly(true);
        p
    };
    f.set_permissions(perm)
        .map_err(|_| io("could not seal a file"))
}

/// Fsyncs a directory after a rename into it (unix; a no-op elsewhere).
pub(crate) fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(p: &Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn private_dir_and_file() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("x").join("y");
        ensure_private_dir(&d).unwrap();
        assert_eq!(mode(&d), 0o700);
        assert_eq!(mode(&t.path().join("x")), 0o700);
        let f = create_private_file(&d.join("f")).unwrap();
        assert_eq!(mode(&d.join("f")), 0o600);
        assert!(create_private_file(&d.join("f")).is_err());
        seal_file(&f).unwrap();
        assert_eq!(mode(&d.join("f")), 0o400);
        std::os::unix::fs::symlink(d.join("f"), d.join("l")).unwrap();
        assert!(ensure_private_dir(&d.join("l")).is_err());
        assert!(create_private_file(&d.join("l")).is_err());
    }
}
