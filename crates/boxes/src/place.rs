//! A box's repo disk into its dir, and the sweep of `.incoming` (plan 37).
//!
//! The daemon copies the disk and the base manifest a CLI passed into
//! `<root>/.incoming/<16 hex>/`; spawn moves them into the box dir before
//! admission. A box dir is a path the VMM can write, so every step here is
//! relative to directory descriptors opened `O_NOFOLLOW`, a rename never
//! replaces what is there, and the sweep never follows a symlink. Nothing
//! here runs under the manager's lock.

use std::ffi::OsStr;
use std::io;
use std::path::Path;

/// Where the daemon stages what a CLI passed, under the store root.
pub const INCOMING: &str = ".incoming";
/// An `.incoming` entry older than this (mtime) is a leftover: gc removes it.
pub const INCOMING_MAX_AGE_SECS: u64 = 3600;

/// The deepest a sweep goes below an `.incoming` entry.
#[cfg(unix)]
const SWEEP_DEPTH: u32 = 4;

#[cfg(unix)]
mod imp {
    use super::*;
    use rustix::fs::{openat, statat, AtFlags, Dir, FileType, Mode, OFlags, CWD};
    use rustix::io::Errno;
    use std::os::fd::OwnedFd;

    fn dir_flags() -> OFlags {
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
    }

    fn open_dir(at: impl rustix::fd::AsFd, name: impl rustix::path::Arg) -> io::Result<OwnedFd> {
        Ok(openat(at, name, dir_flags(), Mode::empty())?)
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn rename_new(src: &OwnedFd, from: &OsStr, dst: &OwnedFd, to: &str) -> io::Result<()> {
        use rustix::fs::{renameat_with, RenameFlags};
        Ok(renameat_with(src, from, dst, to, RenameFlags::NOREPLACE)?)
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn rename_new(src: &OwnedFd, from: &OsStr, dst: &OwnedFd, to: &str) -> io::Result<()> {
        match statat(dst, to, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => return Err(io::ErrorKind::AlreadyExists.into()),
            Err(Errno::NOENT) => {}
            Err(e) => return Err(e.into()),
        }
        Ok(rustix::fs::renameat(src, from, dst, to)?)
    }

    pub fn place(root: &Path, id: &str, sub: &OsStr, moves: &[(&OsStr, &str)]) -> io::Result<()> {
        let root = open_dir(CWD, root)?;
        let dst = open_dir(&root, id)?;
        let inc = open_dir(&root, INCOMING)?;
        let src = open_dir(&inc, sub)?;
        for (from, to) in moves {
            let st = statat(&src, *from, AtFlags::SYMLINK_NOFOLLOW)?;
            if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{} is not a regular file", Path::new(from).display()),
                ));
            }
            rename_new(&src, from, &dst, to)?;
        }
        drop(src);
        // Now empty; a leftover is the sweep's.
        let _ = rustix::fs::unlinkat(&inc, sub, AtFlags::REMOVEDIR);
        Ok(())
    }

    /// The entry names of `dir`, `.` and `..` left out.
    fn names(dir: &OwnedFd) -> io::Result<Vec<std::ffi::OsString>> {
        use std::os::unix::ffi::OsStrExt;
        let mut out = Vec::new();
        for e in Dir::read_from(dir)? {
            let e = e?;
            let n = e.file_name().to_bytes();
            if n != b"." && n != b".." {
                out.push(OsStr::from_bytes(n).to_os_string());
            }
        }
        Ok(out)
    }

    /// Remove `name` in `at`: a directory with what it holds (never
    /// through a symlink), anything else unlinked. Goes on past an entry it
    /// cannot remove; the first error is returned.
    fn remove_at(at: &OwnedFd, name: &OsStr, depth: u32) -> io::Result<()> {
        let st = statat(at, name, AtFlags::SYMLINK_NOFOLLOW)?;
        if FileType::from_raw_mode(st.st_mode) != FileType::Directory {
            return Ok(rustix::fs::unlinkat(at, name, AtFlags::empty())?);
        }
        if depth == 0 {
            return Err(io::Error::other("too deep"));
        }
        let d = open_dir(at, name)?;
        let mut first = None;
        for n in names(&d)? {
            if let Err(e) = remove_at(&d, &n, depth - 1) {
                first.get_or_insert(e);
            }
        }
        drop(d);
        if let Some(e) = first {
            return Err(e);
        }
        Ok(rustix::fs::unlinkat(at, name, AtFlags::REMOVEDIR)?)
    }

    pub fn sweep(root: &Path, now: u64, max_age: u64) -> Vec<String> {
        let mut errs = Vec::new();
        let at = |e: io::Error, what: &str| format!("{}: {e}", root.join(what).display());
        let root_fd = match open_dir(CWD, root) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return errs,
            Err(e) => return vec![at(e, "")],
        };
        let inc = match open_dir(&root_fd, INCOMING) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return errs,
            Err(e) => return vec![at(e, INCOMING)],
        };
        let owner = rustix::fs::fstat(&root_fd).map(|s| s.st_uid);
        match (rustix::fs::fstat(&inc), owner) {
            (Ok(s), Ok(uid)) if s.st_uid == uid => {}
            (Ok(_), Ok(_)) => {
                return vec![format!(
                    "{}: not owned by the box store's owner, left alone",
                    root.join(INCOMING).display()
                )]
            }
            (Err(e), _) | (_, Err(e)) => return vec![at(e.into(), INCOMING)],
        }
        let list = match names(&inc) {
            Ok(l) => l,
            Err(e) => return vec![at(e, INCOMING)],
        };
        for n in list {
            let st = match statat(&inc, &n, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(s) => s,
                Err(Errno::NOENT) => continue,
                Err(e) => {
                    errs.push(at(e.into(), INCOMING));
                    continue;
                }
            };
            #[allow(clippy::unnecessary_cast)]
            let mtime = u64::try_from(st.st_mtime as i64).unwrap_or(0);
            if now.saturating_sub(mtime) < max_age {
                continue;
            }
            if let Err(e) = remove_at(&inc, &n, SWEEP_DEPTH) {
                let p = Path::new(INCOMING).join(&n);
                errs.push(format!("{}: {e}", root.join(p).display()));
            }
        }
        errs
    }
}

#[cfg(not(unix))]
mod imp {
    use super::*;

    pub fn place(root: &Path, id: &str, sub: &OsStr, moves: &[(&OsStr, &str)]) -> io::Result<()> {
        let src = root.join(INCOMING).join(sub);
        let dst = root.join(id);
        for (from, to) in moves {
            let to = dst.join(to);
            if std::fs::symlink_metadata(&to).is_ok() {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            std::fs::rename(src.join(from), to)?;
        }
        let _ = std::fs::remove_dir(&src);
        Ok(())
    }

    pub fn sweep(root: &Path, now: u64, max_age: u64) -> Vec<String> {
        let inc = root.join(INCOMING);
        let Ok(rd) = std::fs::read_dir(&inc) else {
            return Vec::new();
        };
        let mut errs = Vec::new();
        for e in rd.flatten() {
            let p = e.path();
            let Ok(md) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            let mtime = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs());
            if now.saturating_sub(mtime) < max_age {
                continue;
            }
            let r = if md.is_dir() {
                std::fs::remove_dir_all(&p)
            } else {
                std::fs::remove_file(&p)
            };
            if let Err(e) = r {
                errs.push(format!("{}: {e}", p.display()));
            }
        }
        errs
    }
}

/// Move each `(from, to)` of `<root>/.incoming/<sub>/` into the box dir
/// `<root>/<id>/`, never replacing an entry there; `from` must be a regular
/// file. Then the emptied `sub` goes (best effort).
pub fn place(root: &Path, id: &str, sub: &OsStr, moves: &[(&OsStr, &str)]) -> io::Result<()> {
    imp::place(root, id, sub, moves)
}

/// Remove every entry of `<root>/.incoming/` whose mtime is `max_age` or
/// more before `now` (Unix seconds). Never follows a symlink; goes on past
/// an entry it cannot remove. The errors, one per entry.
pub fn sweep_incoming(root: &Path, now: u64, max_age: u64) -> Vec<String> {
    imp::sweep(root, now, max_age)
}
