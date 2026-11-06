//! Files and dirs only the daemon may use, on each OS.
//!
//! On Linux and macOS that is a mode (0600, 0700), an owner uid and `O_NOFOLLOW`. On
//! Windows a new file or dir takes its ACL from its parent, which W14 protects, and
//! what is checked is the descriptor: see [`saiife_win::sddl::private_problem`].

use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::path::Path;

/// A new file only the daemon can use, opened for writing. It never follows or
/// replaces anything already at `path`.
pub(crate) fn new_private_file(path: &Path) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    o.open(path)
}

/// `dir` and its missing parents: 0700 on Unix, the parent's ACL on Windows.
pub(crate) fn create_private_dirs(dir: &Path) -> io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
}

/// Makes a new or renamed name in `dir` durable. Windows cannot flush a directory
/// handle; NTFS journals its metadata, so there is nothing to do there.
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Whether this is a link of any kind. On Windows that takes in junctions, mount points
/// and every other reparse point, which `is_symlink` does not all report.
pub(crate) fn is_link(md: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        md.file_type().is_symlink()
    }
}

/// The SID this process runs as (the identity; its uid is only a label).
#[cfg(windows)]
pub(crate) fn own_sid() -> io::Result<String> {
    static OWN: std::sync::OnceLock<Result<String, String>> = std::sync::OnceLock::new();
    OWN.get_or_init(|| {
        saiife_win::ffi::token::current()
            .map(|t| t.sid)
            .map_err(|e| e.to_string())
    })
    .clone()
    .map_err(io::Error::other)
}

/// This process's uid label.
pub(crate) fn process_uid() -> u32 {
    #[cfg(unix)]
    {
        rustix::process::getuid().as_raw()
    }
    #[cfg(windows)]
    {
        own_sid().map_or(crate::ops::UNKNOWN_UID, |s| {
            saiife_win::sid::uid_of(&s, false)
        })
    }
}

/// A real directory only SYSTEM, Administrators, TrustedInstaller and this process may
/// change. Nothing is created or repaired: an ACL someone else set is theirs to explain.
#[cfg(windows)]
pub(crate) fn check_private_dir(dir: &Path) -> io::Result<()> {
    let md = std::fs::symlink_metadata(dir)?;
    if is_link(&md) || !md.is_dir() {
        return Err(io::Error::other(format!(
            "{} is not a directory (links are not followed)",
            dir.display()
        )));
    }
    let text = saiife_win::ffi::acl::get_sddl(dir)?;
    match saiife_win::sddl::private_problem(&text, &own_sid()?, false) {
        None => Ok(()),
        Some(why) => Err(io::Error::other(format!("{}: {why}", dir.display()))),
    }
}

/// A scratch dir the daemon's private-dir checks accept, for tests. On Unix it is a
/// plain tempdir (`check_dir` sets 0700). On Windows a temp dir inherits the runner
/// temp's ACL, which lets Users write, so the dir is a child made with a protected
/// descriptor naming only this process and SYSTEM, as W14 gives the service's state.
#[cfg(test)]
pub(crate) struct TestDir {
    _root: tempfile::TempDir,
    path: std::path::PathBuf,
}

#[cfg(test)]
impl TestDir {
    /// A private scratch dir in the system temp dir.
    pub(crate) fn new() -> TestDir {
        TestDir::new_in(&std::env::temp_dir())
    }

    /// A private scratch dir in `base`.
    pub(crate) fn new_in(base: &Path) -> TestDir {
        let root = tempfile::tempdir_in(base).unwrap();
        #[cfg(windows)]
        let path = {
            let me = own_sid().unwrap();
            let sddl = format!("O:{me}D:PAI(A;OICI;FA;;;{me})(A;OICI;FA;;;SY)");
            let p = root.path().join("t");
            saiife_win::ffi::acl::create_dir_with_sddl(&p, &sddl).unwrap();
            p
        };
        #[cfg(not(windows))]
        let path = root.path().to_path_buf();
        TestDir { _root: root, path }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_private_file_refuses_what_is_there() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        new_private_file(&p).unwrap();
        let e = new_private_file(&p).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn sync_dir_of_a_real_dir_is_fine() {
        let d = tempfile::tempdir().unwrap();
        sync_dir(d.path()).unwrap();
    }

    #[test]
    fn a_plain_dir_is_no_link() {
        let d = tempfile::tempdir().unwrap();
        create_private_dirs(&d.path().join("a").join("b")).unwrap();
        let md = std::fs::symlink_metadata(d.path().join("a")).unwrap();
        assert!(!is_link(&md));
    }
}
