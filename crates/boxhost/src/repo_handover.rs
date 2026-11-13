//! The repo disk's move from the box's record dir to its runtime dir
//! (plan 35 R37/R40, plan 37). Spawn places `repo.img` and `base.json` in
//! the daemon-only record dir; `ChVmm::create` hands `repo.img` to the
//! runtime dir the VMM opens. `base.json` never leaves the records.
//!
//! The source is opened `O_NOFOLLOW` and must be a regular file of the
//! daemon's euid with one link. It is renamed between the two dir fds; on
//! `EXDEV` it is copied (holes kept) to a temporary name in the runtime dir,
//! renamed into place and only then unlinked from the records. Locked: the
//! runtime copy is group-owned by the runtime dir's group (`saiife-box`,
//! the dir is setgid) and 0660, so the VMM user reads and writes it.

use std::fs::File;
use std::os::fd::OwnedFd;
use std::path::Path;

use rustix::fs::{Mode, OFlags, CWD};
use rustix::io::Errno;

use crate::paths::REPO_DISK;

/// The copy's name while it is written (the `EXDEV` path).
const PART: &str = ".repo.img.part";

/// How the disk moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Moved {
    /// No repo disk in the record dir (none was passed, or an earlier
    /// create moved it).
    Nothing,
    Renamed,
    Copied,
}

fn dir_fd(p: &Path) -> Result<OwnedFd, String> {
    rustix::fs::openat(
        CWD,
        p,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| format!("{}: {e}", p.display()))
}

/// Moves `<record_dir>/repo.img` to `<runtime_dir>/repo.img` (see the
/// module doc). `force_copy` takes the `EXDEV` path (tests).
pub fn take_repo_disk(
    record_dir: &Path,
    runtime_dir: &Path,
    locked: bool,
    force_copy: bool,
) -> Result<Moved, String> {
    let rec = dir_fd(record_dir)?;
    let src = match rustix::fs::openat(
        &rec,
        REPO_DISK,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(Moved::Nothing),
        Err(e) => return Err(format!("the repo disk in the box record: {e}")),
    };
    let st = rustix::fs::fstat(&src).map_err(|e| format!("the repo disk: {e}"))?;
    let me = rustix::process::geteuid().as_raw();
    if rustix::fs::FileType::from_raw_mode(st.st_mode) != rustix::fs::FileType::RegularFile
        || st.st_nlink != 1
        || st.st_uid != me
    {
        return Err(
            "the repo disk in the box record is not a plain file of the daemon".to_string(),
        );
    }
    let rt = dir_fd(runtime_dir)?;
    let gid = if locked {
        let d = rustix::fs::fstat(&rt).map_err(|e| format!("{}: {e}", runtime_dir.display()))?;
        Some(rustix::fs::Gid::from_raw(d.st_gid))
    } else {
        None
    };
    let make_shared = |fd: &OwnedFd| -> Result<(), String> {
        if let Some(g) = gid {
            rustix::fs::fchown(fd, None, Some(g)).map_err(|e| format!("the repo disk: {e}"))?;
            rustix::fs::fchmod(fd, Mode::from_raw_mode(0o660))
                .map_err(|e| format!("the repo disk: {e}"))?;
        }
        Ok(())
    };
    if !force_copy {
        make_shared(&src)?;
        match rustix::fs::renameat(&rec, REPO_DISK, &rt, REPO_DISK) {
            Ok(()) => return Ok(Moved::Renamed),
            Err(Errno::XDEV) => {}
            Err(e) => return Err(format!("cannot move the repo disk into the box: {e}")),
        }
    }
    // a part left by an earlier failed copy
    match rustix::fs::unlinkat(&rt, PART, rustix::fs::AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(e) => return Err(format!("cannot copy the repo disk into the box: {e}")),
    }
    let dst = rustix::fs::openat(
        &rt,
        PART,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|e| format!("cannot copy the repo disk into the box: {e}"))?;
    let copied = (|| -> Result<(), String> {
        make_shared(&dst)?;
        let (s, d) = (File::from(src), File::from(dst));
        crate::disk::copy_sparse_upto(&s, &d, st.st_size as u64)
            .and_then(|_| d.sync_all())
            .map_err(|e| format!("cannot copy the repo disk into the box: {e}"))?;
        rustix::fs::renameat(&rt, PART, &rt, REPO_DISK)
            .map_err(|e| format!("cannot copy the repo disk into the box: {e}"))
    })();
    if let Err(e) = copied {
        let _ = rustix::fs::unlinkat(&rt, PART, rustix::fs::AtFlags::empty());
        return Err(e);
    }
    rustix::fs::unlinkat(&rec, REPO_DISK, rustix::fs::AtFlags::empty())
        .map_err(|e| format!("the repo disk was copied but not removed from the record: {e}"))?;
    Ok(Moved::Copied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::BASE_MANIFEST;
    use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};

    fn dirs() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let (rec, rt) = (t.path().join("rec"), t.path().join("rt"));
        std::fs::create_dir(&rec).unwrap();
        std::fs::create_dir(&rt).unwrap();
        (t, rec, rt)
    }

    /// A sparse disk with data at 1 MiB, and a manifest beside it.
    fn plant(rec: &Path) {
        let f = File::create(rec.join(REPO_DISK)).unwrap();
        f.set_len(8 << 20).unwrap();
        f.write_all_at(b"repo data", 1 << 20).unwrap();
        std::fs::write(rec.join(BASE_MANIFEST), "{}").unwrap();
    }

    fn check_moved(rec: &Path, rt: &Path) {
        assert!(!rec.join(REPO_DISK).exists(), "the record keeps no disk");
        assert!(rec.join(BASE_MANIFEST).exists(), "base.json stays");
        assert!(!rt.join(BASE_MANIFEST).exists());
        assert!(!rt.join(PART).exists());
        let d = std::fs::read(rt.join(REPO_DISK)).unwrap();
        assert_eq!(d.len(), 8 << 20);
        assert_eq!(&d[1 << 20..(1 << 20) + 9], b"repo data");
    }

    #[test]
    fn renames_the_disk_and_keeps_the_manifest() {
        let (_t, rec, rt) = dirs();
        plant(&rec);
        assert_eq!(take_repo_disk(&rec, &rt, false, false), Ok(Moved::Renamed));
        check_moved(&rec, &rt);
        // a second create finds nothing to move and keeps the runtime disk
        assert_eq!(take_repo_disk(&rec, &rt, false, false), Ok(Moved::Nothing));
        assert!(rt.join(REPO_DISK).exists());
    }

    #[test]
    fn copies_across_devices_keeping_holes() {
        let (_t, rec, rt) = dirs();
        plant(&rec);
        std::fs::write(rt.join(PART), "stale").unwrap();
        assert_eq!(take_repo_disk(&rec, &rt, false, true), Ok(Moved::Copied));
        check_moved(&rec, &rt);
        let m = std::fs::metadata(rt.join(REPO_DISK)).unwrap();
        assert!(
            m.blocks() * 512 < 8 << 20,
            "holes kept: {} blocks",
            m.blocks()
        );
    }

    #[test]
    fn locked_disk_is_group_shared() {
        for copy in [false, true] {
            let (_t, rec, rt) = dirs();
            plant(&rec);
            std::fs::set_permissions(rec.join(REPO_DISK), PermissionsExt::from_mode(0o600))
                .unwrap();
            take_repo_disk(&rec, &rt, true, copy).unwrap();
            let m = std::fs::metadata(rt.join(REPO_DISK)).unwrap();
            assert_eq!(m.mode() & 0o777, 0o660, "copy={copy}");
            assert_eq!(
                m.gid(),
                std::fs::metadata(&rt).unwrap().gid(),
                "copy={copy}"
            );
            check_moved(&rec, &rt);
        }
    }

    #[test]
    fn refuses_what_is_no_plain_file() {
        let (t, rec, rt) = dirs();
        // a symlink
        let far = t.path().join("far.img");
        std::fs::write(&far, "x").unwrap();
        std::os::unix::fs::symlink(&far, rec.join(REPO_DISK)).unwrap();
        assert!(take_repo_disk(&rec, &rt, false, false).is_err());
        std::fs::remove_file(rec.join(REPO_DISK)).unwrap();
        // a second link
        std::fs::hard_link(&far, rec.join(REPO_DISK)).unwrap();
        let e = take_repo_disk(&rec, &rt, false, false).unwrap_err();
        assert!(e.contains("not a plain file"), "{e}");
        std::fs::remove_file(rec.join(REPO_DISK)).unwrap();
        // a dir
        std::fs::create_dir(rec.join(REPO_DISK)).unwrap();
        assert!(take_repo_disk(&rec, &rt, false, false).is_err());
        assert!(!rt.join(REPO_DISK).exists());
        assert!(far.exists());
    }

    #[test]
    fn a_symlinked_dir_is_refused() {
        let (t, rec, rt) = dirs();
        plant(&rec);
        let link = t.path().join("rt-link");
        std::os::unix::fs::symlink(&rt, &link).unwrap();
        assert!(take_repo_disk(&rec, &link, false, false).is_err());
        assert!(rec.join(REPO_DISK).exists(), "nothing moved");
    }
}
