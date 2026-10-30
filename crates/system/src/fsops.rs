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
/// (false); a symlink is unlinked, never followed.
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

// ------------------------------------------------ fd-relative removal

use rustix::fs::{AtFlags, Mode, OFlags};
use std::ffi::{CString, OsStr};
use std::os::fd::OwnedFd;
use std::path::Component;

pub use rustix::fs::Stat;

/// How a directory below the root is opened: never through a symlink.
fn dir_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

/// The deepest tree [`remove_tree_at`] descends into.
const MAX_TREE_DEPTH: usize = 64;

fn errno_at(shown: &Path, e: rustix::io::Errno) -> io::Error {
    refine(shown, io::Error::from(e))
}

/// Opens the directory `rel` below `root` one component at a time
/// (`openat` with `O_NOFOLLOW | O_DIRECTORY` from the previous one), so no
/// symlink on the way is followed and the modes of the ancestors do not
/// matter: each step is relative to the directory already open. `None`
/// when a component is missing. `rel` holds plain components only.
pub fn open_dir_beneath(root: &Path, rel: &Path) -> io::Result<Option<OwnedFd>> {
    let mut fd = rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| errno_at(root, e))?;
    let mut shown = root.to_path_buf();
    for c in rel.components() {
        match c {
            Component::Normal(name) => {
                shown.push(name);
                fd = match rustix::fs::openat(&fd, name, dir_flags(), Mode::empty()) {
                    Ok(f) => f,
                    Err(rustix::io::Errno::NOENT) => return Ok(None),
                    Err(e) => return Err(errno_at(&shown, e)),
                };
            }
            Component::RootDir | Component::CurDir => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{}: only plain components are allowed", rel.display()),
                ))
            }
        }
    }
    Ok(Some(fd))
}

/// `fstatat(dir, name, AT_SYMLINK_NOFOLLOW)`; `None` when it is missing.
pub fn stat_at(dir: &OwnedFd, name: &OsStr) -> io::Result<Option<Stat>> {
    match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => Ok(Some(st)),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// The `fstat` of an open directory.
pub fn stat_fd(fd: &OwnedFd) -> io::Result<Stat> {
    rustix::fs::fstat(fd).map_err(Into::into)
}

/// Owner, permission bits (with setgid and sticky) and whether it is a
/// directory, from a [`Stat`].
#[allow(clippy::unnecessary_cast)] // st_mode is u16 on macOS
pub fn stat_owner_mode(st: &Stat) -> (u32, u32, bool) {
    let mode = st.st_mode as u32;
    let is_dir = rustix::fs::FileType::from_raw_mode(st.st_mode) == rustix::fs::FileType::Directory;
    (st.st_uid, mode & 0o7777, is_dir)
}

/// Removes the directory tree `name` in the open directory `dir`,
/// fd-relative throughout: every directory is opened with `O_NOFOLLOW`
/// from its parent's descriptor, every entry removed with `unlinkat`, so a
/// symlink inside is removed, never followed, and a renamed ancestor cannot
/// redirect the removal. `expect` is the `stat` the caller checked: the
/// directory opened must be that one (same device and inode).
pub fn remove_tree_at(dir: &OwnedFd, name: &OsStr, expect: &Stat) -> io::Result<()> {
    let shown = Path::new(name);
    let fd = rustix::fs::openat(dir, name, dir_flags(), Mode::empty())
        .map_err(|e| errno_at(shown, e))?;
    let st = stat_fd(&fd)?;
    if (st.st_dev, st.st_ino) != (expect.st_dev, expect.st_ino) {
        return Err(io::Error::other(format!(
            "{} changed while it was being removed",
            shown.display()
        )));
    }
    remove_contents(&fd, 0)?;
    rustix::fs::unlinkat(dir, name, AtFlags::REMOVEDIR).map_err(|e| errno_at(shown, e))
}

fn remove_contents(dir: &OwnedFd, depth: usize) -> io::Result<()> {
    if depth > MAX_TREE_DEPTH {
        return Err(io::Error::other(format!(
            "tree deeper than {MAX_TREE_DEPTH} levels"
        )));
    }
    let mut names: Vec<CString> = Vec::new();
    for e in rustix::fs::Dir::read_from(dir)? {
        let e = e?;
        let n = e.file_name();
        if n.to_bytes() != b"." && n.to_bytes() != b".." {
            names.push(n.to_owned());
        }
    }
    for n in names {
        let st = match rustix::fs::statat(dir, n.as_c_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => st,
            Err(rustix::io::Errno::NOENT) => continue,
            Err(e) => return Err(e.into()),
        };
        if stat_owner_mode(&st).2 {
            let child = rustix::fs::openat(dir, n.as_c_str(), dir_flags(), Mode::empty())?;
            remove_contents(&child, depth + 1)?;
            rustix::fs::unlinkat(dir, n.as_c_str(), AtFlags::REMOVEDIR)?;
        } else {
            rustix::fs::unlinkat(dir, n.as_c_str(), AtFlags::empty())?;
        }
    }
    Ok(())
}

/// Removes the directory `name` in `dir` when it is empty. False when it is
/// missing or not empty.
pub fn remove_empty_dir_at(dir: &OwnedFd, name: &OsStr) -> io::Result<bool> {
    match rustix::fs::unlinkat(dir, name, AtFlags::REMOVEDIR) {
        Ok(()) => Ok(true),
        Err(rustix::io::Errno::NOENT | rustix::io::Errno::NOTEMPTY | rustix::io::Errno::EXIST) => {
            Ok(false)
        }
        Err(e) => Err(errno_at(Path::new(name), e)),
    }
}

/// What is wrong with `m` as a root-owned, tamper-proof path component:
/// not owned by `root_uid`, or writable by group or others. Empty when it
/// is fine. Shared by `saiife doctor` and the daemon's `secret.lease`.
pub fn root_owned_problems(m: &std::fs::Metadata, root_uid: u32) -> Vec<String> {
    use std::os::unix::fs::MetadataExt;
    let mut out = Vec::new();
    if m.uid() != root_uid {
        out.push(format!("owned by uid {}, not root", m.uid()));
    }
    let perm = m.mode() & 0o7777;
    if perm & 0o022 != 0 {
        out.push(format!("mode {perm:04o} is writable by group or others"));
    }
    out
}

/// The system links macOS ships: `/etc`, `/var` and `/tmp`, each pointing
/// at `private/<same name>`. The only symlinks a root-owned path may pass
/// through (and only when root owns the link).
const TRUSTED_SYSTEM_LINKS: [&str; 3] = ["etc", "var", "tmp"];

/// True only when `link` is `/etc`, `/var` or `/tmp` and `target` (the
/// link's text) is `private/<same name>`. Every other link is untrusted.
pub fn trusted_link_target(link: &Path, target: &Path) -> bool {
    let mut parts = link.components();
    if parts.next() != Some(Component::RootDir) {
        return false;
    }
    let (Some(Component::Normal(name)), None) = (parts.next(), parts.next()) else {
        return false;
    };
    let Some(name) = name.to_str() else {
        return false;
    };
    TRUSTED_SYSTEM_LINKS.contains(&name) && target == Path::new("private").join(name)
}

/// When `p` is a trusted system link ([`trusted_link_target`]) owned by
/// uid 0, the directory it points at (`/private/<name>`).
fn trusted_link_dir(p: &Path, m: &std::fs::Metadata) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    if !m.file_type().is_symlink() || m.uid() != 0 {
        return None;
    }
    let target = std::fs::read_link(p).ok()?;
    trusted_link_target(p, &target).then(|| Path::new("/").join(target))
}

/// `path` (absolute) and every parent down from `/`: no symlink, owned by
/// uid 0, not writable by group or others. `Err` names the first fault.
/// The one exception is a root-owned trusted system link (`/etc`, `/var`,
/// `/tmp` on macOS): the walk goes on through its target instead.
pub fn root_owned_chain(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("{}: not an absolute path", path.display()));
    }
    let mut path = path.to_path_buf();
    // Each trusted link is a top-level name, so a walk restarts at most
    // once per name; the bound keeps a looping tree from spinning.
    'walk: for _ in 0..=TRUSTED_SYSTEM_LINKS.len() {
        let mut chain: Vec<&Path> = path.ancestors().collect();
        chain.reverse();
        for p in chain {
            let m = std::fs::symlink_metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
            if let Some(dir) = trusted_link_dir(p, &m) {
                let rest = path.strip_prefix(p).unwrap_or(Path::new(""));
                path = dir.join(rest);
                continue 'walk;
            }
            if m.file_type().is_symlink() {
                return Err(format!("{}: is a symlink", p.display()));
            }
            if let Some(prob) = root_owned_problems(&m, 0).into_iter().next() {
                return Err(format!("{}: {prob}", p.display()));
            }
        }
        return Ok(());
    }
    Err(format!("{}: too many system links", path.display()))
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
    fn trusted_system_links_only_the_three() {
        let t = |l: &str, to: &str| trusted_link_target(Path::new(l), Path::new(to));
        assert!(t("/etc", "private/etc"));
        assert!(t("/var", "private/var"));
        assert!(t("/tmp", "private/tmp"));
        assert!(!t("/etc", "/tmp/x"));
        assert!(!t("/opt", "private/opt"));
        assert!(!t("/var", "private/etc"));
        assert!(!t("/etc", "/private/etc"));
        assert!(!t("/etc", "private/etc/.."));
        assert!(!t("/x/etc", "private/etc"));
        assert!(!t("etc", "private/etc"));
    }

    #[test]
    fn root_owned_chain_refuses_a_tempdir_symlink() {
        let d = tempfile::tempdir().unwrap();
        let link = d.path().join("l");
        std::os::unix::fs::symlink("/usr", &link).unwrap();
        assert!(root_owned_chain(&link.join("bin")).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn root_owned_chain_accepts_private_etc() {
        assert_eq!(root_owned_chain(Path::new("/etc/hosts")), Ok(()));
        let d = tempfile::tempdir().unwrap();
        let link = d.path().join("l");
        std::os::unix::fs::symlink("/etc", &link).unwrap();
        assert!(root_owned_chain(&link.join("hosts")).is_err());
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
