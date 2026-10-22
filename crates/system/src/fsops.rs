//! File helpers for `system install` and `uninstall`. Every open uses
//! `O_NOFOLLOW` and a symlink at a target path is refused, never followed.
//! Modes are set on the open handle (`fchmod`), never by path afterwards.

use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

fn nofollow() -> i32 {
    rustix::fs::OFlags::NOFOLLOW.bits() as i32
}

fn symlink_refused(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "{} is a symlink; saiife does not follow symlinks here",
            path.display()
        ),
    )
}

/// What is at `path` without following a symlink: `None` when nothing is,
/// an error for a symlink.
pub fn lstat(path: &Path) -> io::Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Err(symlink_refused(path)),
        Ok(m) => Ok(Some(m)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(with_path(path, e)),
    }
}

fn with_path(path: &Path, e: io::Error) -> io::Error {
    io::Error::new(e.kind(), format!("{}: {e}", path.display()))
}

/// Creates the directory `path` with `mode` (set with `fchmod`, so the umask
/// does not matter). True when it was created; false when a directory is
/// already there (its mode is left alone). A symlink or a non-directory is
/// an error.
pub fn create_dir_mode(path: &Path, mode: u32) -> io::Result<bool> {
    match lstat(path)? {
        Some(m) if m.is_dir() => return Ok(false),
        Some(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a directory", path.display()),
            ))
        }
        None => {}
    }
    fs::DirBuilder::new()
        .mode(mode)
        .create(path)
        .map_err(|e| with_path(path, e))?;
    set_dir_mode(path, mode)?;
    Ok(true)
}

/// Sets the mode of the directory `path` through an `O_NOFOLLOW` handle.
pub fn set_dir_mode(path: &Path, mode: u32) -> io::Result<()> {
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nofollow() | rustix::fs::OFlags::DIRECTORY.bits() as i32)
        .open(path)
        .map_err(|e| refine(path, e))?;
    f.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|e| with_path(path, e))
}

/// Sets the mode of the regular file `path` through an `O_NOFOLLOW` handle.
pub fn set_file_mode(path: &Path, mode: u32) -> io::Result<()> {
    let f = open_regular(path)?;
    f.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|e| with_path(path, e))
}

/// The permission bits (with setgid and sticky) of `path` itself.
pub fn mode_of(path: &Path) -> io::Result<Option<u32>> {
    Ok(lstat(path)?.map(|m| m.permissions().mode() & 0o7777))
}

/// An `ELOOP` from `O_NOFOLLOW` names the symlink.
fn refine(path: &Path, e: io::Error) -> io::Error {
    if e.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) {
        return symlink_refused(path);
    }
    with_path(path, e)
}

fn open_regular(path: &Path) -> io::Result<fs::File> {
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nofollow() | rustix::fs::OFlags::NONBLOCK.bits() as i32)
        .open(path)
        .map_err(|e| refine(path, e))?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    Ok(f)
}

/// Lower-case hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// SHA-256 of the regular file `path`; `None` when it does not exist.
pub fn sha256_file(path: &Path) -> io::Result<Option<String>> {
    if lstat(path)?.is_none() {
        return Ok(None);
    }
    let mut f = open_regular(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|e| with_path(path, e))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(Some(
        h.finalize().iter().map(|b| format!("{b:02x}")).collect(),
    ))
}

/// `.<name>.tmp.<16 random hex>` next to `path`.
fn temp_path(path: &Path) -> io::Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
    let mut rnd = [0u8; 8];
    getrandom::fill(&mut rnd).map_err(|e| io::Error::other(e.to_string()))?;
    let mut tmp = std::ffi::OsString::from(".");
    tmp.push(name);
    tmp.push(format!(".tmp.{}", sha256_hex(&rnd)[..16].to_owned()));
    Ok(parent_of(path).join(tmp))
}

fn parent_of(path: &Path) -> &Path {
    match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    }
}

fn create_new(path: &Path, mode: u32) -> io::Result<fs::File> {
    let f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(nofollow())
        .open(path)
        .map_err(|e| refine(path, e))?;
    f.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|e| with_path(path, e))?;
    Ok(f)
}

/// Writes `bytes` to `path`: a temp file next to it (`O_EXCL`, mode set with
/// `fchmod`), synced, renamed over `path`, then the directory synced. A
/// symlink or a non-file at `path` is refused.
pub fn write_file_atomic(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    if let Some(m) = lstat(path)? {
        if !m.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a regular file", path.display()),
            ));
        }
    }
    let tmp = temp_path(path)?;
    let res = (|| {
        let mut f = create_new(&tmp, mode)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, path).map_err(|e| with_path(path, e))
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res?;
    fs::File::open(parent_of(path))?.sync_all()
}

/// Writes `bytes` to a new file `path` (`O_EXCL`, so an existing file or a
/// planted symlink fails), mode set with `fchmod`, synced.
pub fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let mut f = create_new(path, mode)?;
    let res = f.write_all(bytes).and_then(|_| f.sync_all());
    if res.is_err() {
        let _ = fs::remove_file(path);
    }
    res.map_err(|e| with_path(path, e))?;
    fs::File::open(parent_of(path))?.sync_all()
}

/// Removes a path `install` listed: a file, or a directory when it is empty
/// (a non-empty one is kept and gives false). A missing path is skipped
/// (false); a symlink is refused.
pub fn remove_if_listed(path: &Path) -> io::Result<bool> {
    let Some(m) = lstat(path)? else {
        return Ok(false);
    };
    if m.is_dir() {
        return match fs::remove_dir(path) {
            Ok(()) => Ok(true),
            Err(e) if e.raw_os_error() == Some(rustix::io::Errno::NOTEMPTY.raw_os_error()) => {
                Ok(false)
            }
            Err(e) => Err(with_path(path, e)),
        };
    }
    fs::remove_file(path).map_err(|e| with_path(path, e))?;
    Ok(true)
}

/// Removes the directory tree `path` (`--purge` of the state and audit
/// dirs). Symlinks inside are removed, not followed; a symlink at `path`
/// is refused. A missing path gives false.
pub fn remove_tree(path: &Path) -> io::Result<bool> {
    let Some(m) = lstat(path)? else {
        return Ok(false);
    };
    if !m.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a directory", path.display()),
        ));
    }
    fs::remove_dir_all(path).map_err(|e| with_path(path, e))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(p: &Path) -> u32 {
        mode_of(p).unwrap().unwrap()
    }

    #[test]
    fn create_dir_mode_ignores_the_umask_and_refuses_symlinks() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a");
        assert!(create_dir_mode(&p, 0o700).unwrap());
        assert_eq!(mode(&p), 0o700);
        assert!(!create_dir_mode(&p, 0o755).unwrap());
        assert_eq!(mode(&p), 0o700, "an existing dir keeps its mode");
        let link = d.path().join("l");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(create_dir_mode(&link, 0o755).is_err());
        assert!(set_dir_mode(&link, 0o777).is_err());
        assert_eq!(mode(&p), 0o700);
    }

    #[test]
    fn write_file_atomic_sets_mode_and_refuses_symlinks() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        write_file_atomic(&p, b"one", 0o755).unwrap();
        assert_eq!(mode(&p), 0o755);
        write_file_atomic(&p, b"two", 0o644).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        assert_eq!(mode(&p), 0o644);
        assert_eq!(sha256_file(&p).unwrap().unwrap(), sha256_hex(b"two"));
        let target = d.path().join("target");
        fs::write(&target, "keep").unwrap();
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(write_file_atomic(&link, b"x", 0o644).is_err());
        assert!(sha256_file(&link).is_err());
        assert!(set_file_mode(&link, 0o600).is_err());
        assert!(remove_if_listed(&link).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "keep");
        // Only the two files and the link: no temp file left.
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 3);
    }

    #[test]
    fn write_new_file_is_exclusive() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("k");
        write_new_file(&p, &[1; 32], 0o640).unwrap();
        assert_eq!(mode(&p), 0o640);
        assert!(write_new_file(&p, &[2; 32], 0o640).is_err());
        assert_eq!(fs::read(&p).unwrap(), vec![1; 32]);
    }

    #[test]
    fn remove_if_listed_skips_missing_and_full_dirs() {
        let d = tempfile::tempdir().unwrap();
        assert!(!remove_if_listed(&d.path().join("gone")).unwrap());
        let dir = d.path().join("dir");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("x"), "").unwrap();
        assert!(!remove_if_listed(&dir).unwrap());
        assert!(remove_if_listed(&dir.join("x")).unwrap());
        assert!(remove_if_listed(&dir).unwrap());
        assert!(!dir.exists());
    }
}
