//! Per-box disks. The root disk is a qcow2 overlay on the read-only raw base
//! image (spec §7.3, the spike layout): the base is never written, each box
//! gets its own copy-on-write layer.

use crate::paths::BoxPaths;
use crate::tools::{Tool, ToolError, Tools};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// What a box dir holds on the host's disk, as allocated bytes
/// (`st_blocks` x 512), not apparent size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DiskUsage {
    pub root_bytes: u64,
    pub repo_bytes: u64,
    pub snapshot_bytes: u64,
}

impl DiskUsage {
    pub fn total(&self) -> u64 {
        self.root_bytes
            .saturating_add(self.repo_bytes)
            .saturating_add(self.snapshot_bytes)
    }
}

/// Allocated bytes of the regular files a box dir holds, never following a
/// link. The box dir is VMM-writable (a VMM can swap `snapshot/`, or the
/// box dir itself, for a symlink), so on Unix every name is looked up
/// relative to a directory descriptor opened `O_DIRECTORY|O_NOFOLLOW`, with
/// `fstatat(AT_SYMLINK_NOFOLLOW)`, and nothing is opened but directories: a
/// symlink (to a file or a dir), FIFO, socket, directory or a missing name
/// counts 0.
#[cfg(unix)]
mod at {
    use rustix::fs::{openat, statat, AtFlags, FileType, Mode, OFlags, CWD};
    use std::os::fd::OwnedFd;
    use std::path::Path;

    /// `p` as a real directory: its last component is never followed.
    pub fn open_dir(at: impl rustix::fd::AsFd, p: &Path) -> Option<OwnedFd> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        openat(at, p, flags, Mode::empty()).ok()
    }

    /// Allocated bytes of `name` in `dir` when it is a regular file.
    pub fn allocated_at(dir: &OwnedFd, name: &std::ffi::OsStr) -> u64 {
        match statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) if FileType::from_raw_mode(st.st_mode) == FileType::RegularFile => {
                #[allow(clippy::unnecessary_cast)]
                let blocks = st.st_blocks as u64;
                blocks.saturating_mul(512)
            }
            _ => 0,
        }
    }

    /// Allocated bytes of the regular file `p`, looked up relative to its
    /// parent dir.
    pub fn allocated(p: &Path) -> u64 {
        let (Some(parent), Some(name)) = (p.parent(), p.file_name()) else {
            return 0;
        };
        open_dir(CWD, parent).map_or(0, |d| allocated_at(&d, name))
    }

    /// The sum over `names` in the dir `p` (itself never followed).
    pub fn allocated_in(p: &Path, names: &[&str]) -> u64 {
        let (Some(parent), Some(name)) = (p.parent(), p.file_name()) else {
            return 0;
        };
        let Some(d) = open_dir(CWD, parent).and_then(|up| open_dir(&up, Path::new(name))) else {
            return 0;
        };
        names
            .iter()
            .map(|n| allocated_at(&d, n.as_ref()))
            .fold(0, u64::saturating_add)
    }
}

#[cfg(not(unix))]
mod at {
    use std::path::Path;

    pub fn allocated(p: &Path) -> u64 {
        match std::fs::symlink_metadata(p) {
            Ok(m) if m.file_type().is_file() => m.len(),
            _ => 0,
        }
    }

    pub fn allocated_in(p: &Path, names: &[&str]) -> u64 {
        match std::fs::symlink_metadata(p) {
            Ok(m) if m.is_dir() => names
                .iter()
                .map(|n| allocated(&p.join(n)))
                .fold(0, u64::saturating_add),
            _ => 0,
        }
    }
}

/// The disk a box dir uses: `root.qcow2`, `repo.img` and the snapshot files
/// ([`crate::snapshot::NAMES`] in `snapshot/`, named, never listed). A
/// symlinked box dir or `snapshot/` counts 0 (see [`at`]).
pub fn usage(paths: &BoxPaths) -> DiskUsage {
    DiskUsage {
        root_bytes: at::allocated(&paths.root_disk()),
        repo_bytes: at::allocated(&paths.repo_disk()),
        snapshot_bytes: at::allocated_in(&paths.snapshot_dir(), crate::snapshot::NAMES),
    }
}

const QEMU_IMG_TIMEOUT: Duration = Duration::from_secs(60);

fn unsafe_for_qemu(s: &str) -> bool {
    s.contains([',', ':']) || s.chars().any(char::is_whitespace)
}

fn checked<'a>(what: &str, p: &'a Path) -> Result<&'a str, String> {
    let s = p
        .to_str()
        .ok_or_else(|| format!("{what} path is not valid UTF-8"))?;
    if unsafe_for_qemu(s) {
        return Err(format!(
            "{what} path {s:?} contains ',', ':' or whitespace (qemu option syntax)"
        ));
    }
    Ok(s)
}

/// Create `out` as a `virtual_gib` GiB qcow2 overlay backed by the raw `base`.
/// Writes `<out>.tmp` and renames it, so `out` never exists half-made. On a
/// failure the tmp is removed and the tool's stderr is returned.
pub fn make_overlay(
    tools: &Tools,
    base: &Path,
    out: &Path,
    virtual_gib: u64,
) -> Result<(), String> {
    if !base.is_absolute() {
        return Err(format!("base {} is not an absolute path", base.display()));
    }
    checked("base", base)?;
    let out_s = checked("out", out)?;
    // symlink_metadata: a dangling or live symlink at `out` also counts.
    if std::fs::symlink_metadata(out).is_ok() {
        return Err(format!("{} already exists", out.display()));
    }
    let tmp = PathBuf::from(format!("{out_s}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let size = OsString::from(format!("{virtual_gib}G"));
    let args: [&std::ffi::OsStr; 10] = [
        "create".as_ref(),
        "-q".as_ref(),
        "-f".as_ref(),
        "qcow2".as_ref(),
        "-F".as_ref(),
        "raw".as_ref(),
        "-b".as_ref(),
        base.as_os_str(),
        tmp.as_os_str(),
        &size,
    ];
    let fail = |tmp: &Path, msg: String| {
        let _ = std::fs::remove_file(tmp);
        msg
    };
    match tools.run(Tool::QemuImg, &args[..], QEMU_IMG_TIMEOUT) {
        Ok(_) => {}
        Err(ToolError::Failed { stderr, .. }) => return Err(fail(&tmp, stderr)),
        Err(e) => return Err(fail(&tmp, format!("qemu-img: {e:?}"))),
    }
    std::fs::rename(&tmp, out).map_err(|e| fail(&tmp, format!("rename overlay: {e}")))
}

/// Copies the regular file `src` into the regular file `dst`, keeping its
/// holes: `dst` is emptied and set to `src`'s length, taken once at the
/// start, then only `src`'s data runs (`SEEK_DATA` / `SEEK_HOLE`) are read
/// and written, at their own offsets. Returns the bytes copied.
///
/// Reads and writes are positional, so neither file's offset matters to the
/// copy; the data search does move `src`'s offset (a passed descriptor's
/// offset is shared with its sender). A filesystem that cannot answer the
/// search is copied whole. A source that shrinks meanwhile is an error.
#[cfg(unix)]
pub fn copy_sparse(src: &std::fs::File, dst: &std::fs::File) -> std::io::Result<u64> {
    copy_sparse_upto(src, dst, u64::MAX)
}

/// [`copy_sparse`] of a source at most `max` bytes long (its length as the
/// copy's own `fstat` reads it): a longer one is refused before a byte is
/// written, so a sender that grows a passed file after it was checked
/// cannot make the copy bigger than the check allowed.
#[cfg(unix)]
pub fn copy_sparse_upto(
    src: &std::fs::File,
    dst: &std::fs::File,
    max: u64,
) -> std::io::Result<u64> {
    use std::io::{Error, ErrorKind};
    use std::os::unix::fs::{FileExt, MetadataExt};
    // fstat, never a path: these may be descriptors passed in.
    for (what, f) in [("source", src), ("target", dst)] {
        if !f.metadata()?.file_type().is_file() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("the {what} is not a regular file"),
            ));
        }
    }
    let (sm, dm) = (src.metadata()?, dst.metadata()?);
    if (sm.dev(), sm.ino()) == (dm.dev(), dm.ino()) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "the source and the target are the same file",
        ));
    }
    let len = sm.len();
    if len > max {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("the source is {len} bytes, more than {max}"),
        ));
    }
    // Emptied first: stale bytes of `dst` would otherwise show in its holes.
    dst.set_len(0)?;
    dst.set_len(len)?;
    let mut buf = vec![0u8; COPY_CHUNK];
    let mut copied = 0u64;
    let mut off = 0u64;
    while off < len {
        let Some(start) = next_data(src, off, len)? else {
            break;
        };
        if start >= len {
            break;
        }
        let end = next_hole(src, start, len)?.min(len);
        let mut pos = start;
        while pos < end {
            let want = (end - pos).min(buf.len() as u64) as usize;
            let n = match src.read_at(&mut buf[..want], pos) {
                Ok(0) => {
                    return Err(Error::new(
                        ErrorKind::UnexpectedEof,
                        "the source shrank while it was copied",
                    ))
                }
                Ok(n) => n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            dst.write_all_at(&buf[..n], pos)?;
            pos += n as u64;
            copied += n as u64;
        }
        off = end.max(start + 1);
    }
    Ok(copied)
}

/// One read and write of [`copy_sparse`].
#[cfg(unix)]
const COPY_CHUNK: usize = 1 << 20;

/// The next data offset at or after `off`; `None` when only a hole is left
/// (`ENXIO`). A filesystem without the search (`EINVAL`) is all data.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd"
))]
fn next_data(f: &std::fs::File, off: u64, _len: u64) -> std::io::Result<Option<u64>> {
    use rustix::io::Errno;
    match rustix::fs::seek(f, rustix::fs::SeekFrom::Data(off)) {
        Ok(p) => Ok(Some(p)),
        Err(Errno::NXIO) => Ok(None),
        Err(Errno::INVAL) => Ok(Some(off)),
        Err(e) => Err(e.into()),
    }
}

/// The next hole at or after `off`, the end counting as one. A filesystem
/// without the search (`EINVAL`) has none before `len`.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd"
))]
fn next_hole(f: &std::fs::File, off: u64, len: u64) -> std::io::Result<u64> {
    use rustix::io::Errno;
    match rustix::fs::seek(f, rustix::fs::SeekFrom::Hole(off)) {
        Ok(p) => Ok(p),
        Err(Errno::INVAL | Errno::NXIO) => Ok(len),
        Err(e) => Err(e.into()),
    }
}

/// No data search on this system: the whole file is data.
#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd"
    ))
))]
fn next_data(_f: &std::fs::File, off: u64, _len: u64) -> std::io::Result<Option<u64>> {
    Ok(Some(off))
}

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd"
    ))
))]
fn next_hole(_f: &std::fs::File, _off: u64, len: u64) -> std::io::Result<u64> {
    Ok(len)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;

    fn world(body: &str) -> (tempfile::TempDir, Tools) {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("qemu-img.sh");
        let text = format!(
            "#!/bin/sh\nfor a in \"$@\"; do echo \"$a\" >> '{d}/argv'; done\n{body}\n",
            d = dir.path().display()
        );
        std::fs::write(&fake, text).unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let env = move |k: &str| -> Option<OsString> {
            (k == "SAIIFE_TOOL_QEMU_IMG").then(|| fake.clone().into_os_string())
        };
        let tools = Tools::system(dir.path()).with_env(&env);
        (dir, tools)
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn usage_counts_allocated_bytes() {
        use std::os::unix::fs::symlink;
        let d = tempfile::tempdir().unwrap();
        let paths = BoxPaths::new(d.path().to_path_buf());
        assert_eq!(usage(&paths), DiskUsage::default());
        // 1 MiB of real data: allocated, at least that.
        std::fs::write(paths.root_disk(), vec![1u8; 1 << 20]).unwrap();
        // A sparse file: big apparent size, almost nothing allocated.
        let f = std::fs::File::create(paths.repo_disk()).unwrap();
        f.set_len(1 << 30).unwrap();
        std::fs::create_dir(paths.snapshot_dir()).unwrap();
        std::fs::write(paths.snapshot_dir().join("state.json"), b"{}").unwrap();
        // A symlink to a big file and a FIFO count 0.
        let big = d.path().join("big");
        std::fs::write(&big, vec![1u8; 1 << 20]).unwrap();
        symlink(&big, paths.snapshot_dir().join("config.json")).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            paths.snapshot_dir().join("memory-ranges"),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        let u = usage(&paths);
        assert!(u.root_bytes >= 1 << 20 && u.root_bytes < 2 << 20, "{u:?}");
        assert!(u.repo_bytes < 1 << 20, "sparse: {u:?}");
        assert!(u.snapshot_bytes > 0 && u.snapshot_bytes <= 8192, "{u:?}");
        assert_eq!(u.total(), u.root_bytes + u.repo_bytes + u.snapshot_bytes);
        // The symlinked root counts 0 too.
        std::fs::remove_file(paths.root_disk()).unwrap();
        symlink(&big, paths.root_disk()).unwrap();
        assert_eq!(usage(&paths).root_bytes, 0);
    }

    #[test]
    fn usage_never_follows_a_symlinked_dir() {
        use std::os::unix::fs::symlink;
        let d = tempfile::tempdir().unwrap();
        // A real snapshot dir elsewhere, full of data.
        let far = d.path().join("far");
        std::fs::create_dir(&far).unwrap();
        for n in crate::snapshot::NAMES {
            std::fs::write(far.join(n), vec![1u8; 1 << 20]).unwrap();
        }
        std::fs::write(far.join("root.qcow2"), vec![1u8; 1 << 20]).unwrap();
        // The VMM swapped `snapshot/` for a symlink: it counts 0.
        let boxdir = d.path().join("b1");
        std::fs::create_dir(&boxdir).unwrap();
        let paths = BoxPaths::new(boxdir.clone());
        symlink(&far, paths.snapshot_dir()).unwrap();
        assert_eq!(usage(&paths).snapshot_bytes, 0);
        // A symlinked box dir: nothing in it is counted.
        let linked = BoxPaths::new(d.path().join("b2"));
        symlink(&far, &linked.dir).unwrap();
        assert_eq!(usage(&linked), DiskUsage::default());
    }

    // Writes the last-but-one argument (the tmp path).
    const WRITE_TMP: &str = "for a in \"$@\"; do prev=$last; last=$a; done\necho qcow > \"$prev\"";

    #[test]
    fn overlay_argv_is_pinned() {
        let (d, tools) = world(WRITE_TMP);
        let out = d.path().join("root.qcow2");
        make_overlay(&tools, Path::new("/base/root.raw"), &out, 20).unwrap();
        let argv = std::fs::read_to_string(d.path().join("argv")).unwrap();
        let want = format!(
            "create\n-q\n-f\nqcow2\n-F\nraw\n-b\n/base/root.raw\n{}.tmp\n20G\n",
            out.display()
        );
        assert_eq!(argv, want);
        assert!(out.exists());
        assert!(!d.path().join("root.qcow2.tmp").exists());
    }

    #[test]
    fn overlay_refuses_unsafe_paths() {
        let (d, tools) = world(WRITE_TMP);
        let out = d.path().join("o.qcow2");
        for base in [
            "rel/base.raw",
            "/b,ase.raw",
            "/b:ase.raw",
            "/b ase.raw",
            "/b\tase",
        ] {
            assert!(
                make_overlay(&tools, Path::new(base), &out, 10).is_err(),
                "{base}"
            );
        }
        for bad in ["a,b", "a:b", "a b"] {
            let o = d.path().join(bad);
            assert!(
                make_overlay(&tools, Path::new("/base.raw"), &o, 10).is_err(),
                "{bad}"
            );
        }
        assert!(!d.path().join("argv").exists(), "tool must not have run");
    }

    #[test]
    fn overlay_refuses_existing_out() {
        let (d, tools) = world(WRITE_TMP);
        let out = d.path().join("o.qcow2");
        std::fs::write(&out, "mine").unwrap();
        assert!(make_overlay(&tools, Path::new("/base.raw"), &out, 10).is_err());
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "mine");
        let link = d.path().join("link.qcow2");
        std::os::unix::fs::symlink(d.path().join("nowhere"), &link).unwrap();
        assert!(make_overlay(&tools, Path::new("/base.raw"), &link, 10).is_err());
        assert!(!d.path().join("argv").exists());
    }

    #[test]
    fn overlay_failure_leaves_nothing() {
        let body = format!("{WRITE_TMP}\necho 'qemu-img: bad base' >&2\nexit 1");
        let (d, tools) = world(&body);
        let out = d.path().join("o.qcow2");
        let e = make_overlay(&tools, Path::new("/base.raw"), &out, 10).unwrap_err();
        assert!(e.contains("bad base"), "{e}");
        assert!(!out.exists());
        assert!(!d.path().join("o.qcow2.tmp").exists());
    }

    fn blank(dir: &Path, name: &str) -> std::fs::File {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(dir.join(name))
            .unwrap()
    }

    /// Whether the two files read the same, in chunks.
    fn same_bytes(a: &std::fs::File, b: &std::fs::File) -> bool {
        use std::os::unix::fs::FileExt;
        let len = a.metadata().unwrap().len();
        if b.metadata().unwrap().len() != len {
            return false;
        }
        let (mut x, mut y) = (vec![0u8; 4 << 20], vec![0u8; 4 << 20]);
        let mut off = 0;
        while off < len {
            let n = (len - off).min(x.len() as u64) as usize;
            a.read_exact_at(&mut x[..n], off).unwrap();
            b.read_exact_at(&mut y[..n], off).unwrap();
            if x[..n] != y[..n] {
                return false;
            }
            off += n as u64;
        }
        true
    }

    #[test]
    fn copy_sparse_keeps_holes() {
        use std::os::unix::fs::{FileExt, MetadataExt};
        let d = tempfile::tempdir().unwrap();
        let src = blank(d.path(), "src");
        src.set_len(1 << 30).unwrap();
        src.write_all_at(&[0xa5; 4096], 0).unwrap();
        src.write_all_at(&[0x5a; 4096], 512 << 20).unwrap();
        let dst = blank(d.path(), "dst");
        // Stale bytes in dst must not survive in its holes.
        dst.write_all_at(&[0xff; 4096], 256 << 20).unwrap();
        let copied = copy_sparse(&src, &dst).unwrap();
        assert!((8192..1 << 20).contains(&copied), "{copied}");
        assert_eq!(dst.metadata().unwrap().len(), 1 << 30);
        assert!(same_bytes(&src, &dst));
        let blocks = dst.metadata().unwrap().blocks();
        assert!(blocks * 512 < 1 << 20, "{blocks} blocks");
    }

    #[test]
    fn copy_sparse_upto_refuses_a_longer_source() {
        use std::os::unix::fs::FileExt;
        let d = tempfile::tempdir().unwrap();
        let src = blank(d.path(), "src");
        src.write_all_at(&[7; 100], 0).unwrap();
        let dst = blank(d.path(), "dst");
        dst.write_all_at(&[1; 10], 0).unwrap();
        let e = copy_sparse_upto(&src, &dst, 99).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{e}");
        assert_eq!(dst.metadata().unwrap().len(), 10, "dst untouched");
        assert_eq!(copy_sparse_upto(&src, &dst, 100).unwrap(), 100);
        assert!(same_bytes(&src, &dst));
    }

    #[test]
    fn copy_sparse_of_dense_file() {
        use std::os::unix::fs::FileExt;
        let d = tempfile::tempdir().unwrap();
        let src = blank(d.path(), "src");
        let body: Vec<u8> = (0..(3 << 20) + 17).map(|i| (i % 251) as u8).collect();
        src.write_all_at(&body, 0).unwrap();
        let dst = blank(d.path(), "dst");
        assert_eq!(copy_sparse(&src, &dst).unwrap(), body.len() as u64);
        assert!(same_bytes(&src, &dst));
        // An empty source gives an empty copy.
        let empty = blank(d.path(), "empty");
        assert_eq!(copy_sparse(&empty, &dst).unwrap(), 0);
        assert_eq!(dst.metadata().unwrap().len(), 0);
    }

    #[test]
    fn copy_sparse_refuses_a_directory() {
        let d = tempfile::tempdir().unwrap();
        let dir = std::fs::File::open(d.path()).unwrap();
        let dst = blank(d.path(), "dst");
        let e = copy_sparse(&dir, &dst).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{e}");
        // Nor onto itself, which emptying would destroy.
        std::fs::write(d.path().join("self"), "keep").unwrap();
        let a = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(d.path().join("self"))
            .unwrap();
        let e = copy_sparse(&a, &a).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{e}");
        assert_eq!(
            std::fs::read_to_string(d.path().join("self")).unwrap(),
            "keep"
        );
    }
}
