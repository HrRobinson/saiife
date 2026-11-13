//! The intake of a box's repo disk (plan 37, spec §7.5 In): the CLI passes
//! the disk image and its base manifest as two descriptors with
//! `box.spawn`; the daemon copies both into a fresh
//! `<boxes>/.incoming/<16 hex>/` and checks its own copies, so a CLI that
//! changes a file after passing it changes nothing the daemon checked.
//! The box manager then moves the copies into the box dir before admission
//! (`saiife_boxes::place`).
//!
//! Every step is relative to directory descriptors opened `O_NOFOLLOW`;
//! the destination files are created `O_CREAT|O_EXCL|O_NOFOLLOW` and written
//! with positional writes only. Any failure removes the incoming dir. A
//! daemon that dies midway leaves it for gc, which sweeps `.incoming`
//! entries older than an hour.
//!
//! Every path comes from the layout helpers (`saiife_boxhost::layout`,
//! `saiife_boxhost::paths`). What the daemon trusts (a base manifest,
//! anything in `.incoming`) it reads only through [`read_trusted`]: opened
//! `O_NOFOLLOW|O_NONBLOCK` relative to its dir (itself opened
//! `O_DIRECTORY|O_NOFOLLOW`), and fstat'd for type, owner and size.

use saiife_boxhost::layout::incoming_in;
use saiife_boxhost::paths::{BoxPaths, BASE_MANIFEST, REPO_DISK};
use saiife_boxproto::manifest::{BaseManifest, REPO_MAX_BYTES};
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use rustix::fs::{mkdirat, openat, AtFlags, FileType, Mode, OFlags, CWD};
use rustix::io::Errno;

/// The largest repo disk taken: D4's image of a repo at `REPO_MAX_BYTES`.
pub const IMAGE_MAX_BYTES: u64 = 2 * REPO_MAX_BYTES + (256 << 20);
/// The largest base manifest taken.
pub const MANIFEST_MAX_BYTES: u64 = 64 << 20;
/// The ext4 superblock magic, little-endian `0xEF53` at offset 1024 + 56.
const EXT4_MAGIC_AT: u64 = 1080;
const EXT4_MAGIC: [u8; 2] = [0x53, 0xEF];

fn dir_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

pub(crate) fn open_dir(
    at: impl rustix::fd::AsFd,
    name: impl rustix::path::Arg,
) -> io::Result<OwnedFd> {
    Ok(openat(at, name, dir_flags(), Mode::empty())?)
}

/// `p`'s parent dir, opened `O_NOFOLLOW`, and `p`'s last component.
fn open_parent(p: &Path) -> io::Result<(OwnedFd, &OsStr)> {
    match (p.parent(), p.file_name()) {
        (Some(up), Some(name)) => Ok((open_dir(CWD, up)?, name)),
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "no parent dir")),
    }
}

/// The incoming dir of `boxes_root` ([`incoming_in`]), opened; with
/// `make`, made 0700 if missing. It must be a real directory (not a
/// symlink) owned by this process's uid.
pub(crate) fn incoming_dir(boxes_root: &Path, make: bool) -> Result<OwnedFd, String> {
    let inc = incoming_in(boxes_root);
    let shown = inc.display();
    let (up, name) = open_parent(&inc).map_err(|e| format!("cannot open {shown}: {e}"))?;
    if make {
        match mkdirat(&up, name, Mode::from_raw_mode(0o700)) {
            Ok(()) | Err(Errno::EXIST) => {}
            Err(e) => return Err(format!("cannot make {shown}: {e}")),
        }
    }
    let d = open_dir(&up, name).map_err(|e| format!("cannot open {shown}: {e}"))?;
    let st = rustix::fs::fstat(&d).map_err(|e| format!("{shown}: {e}"))?;
    if st.st_uid != rustix::process::geteuid().as_raw() {
        return Err(format!("{shown} is not the daemon's own"));
    }
    if make && st.st_mode & 0o077 != 0 {
        rustix::fs::fchmod(&d, Mode::from_raw_mode(0o700)).map_err(|e| format!("{shown}: {e}"))?;
    }
    Ok(d)
}

/// The bytes of a file the daemon trusts, read through `f` itself: it must
/// be a regular file owned by this process's euid, of at most `max` bytes.
fn read_fd(f: &File, what: &str, max: u64) -> Result<Vec<u8>, String> {
    let st = rustix::fs::fstat(f).map_err(|e| format!("the {what}: {e}"))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(format!("the {what} is not a regular file"));
    }
    if st.st_uid != rustix::process::geteuid().as_raw() {
        return Err(format!("the {what} is not the daemon's own"));
    }
    let len = u64::try_from(st.st_size).unwrap_or(u64::MAX);
    if len > max {
        return Err(format!(
            "the {what} is {len} bytes, more than the {max} taken"
        ));
    }
    // Positional reads from 0, bounded even if it grows meanwhile.
    let mut out = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
    let mut buf = vec![0u8; 64 << 10];
    let mut at = 0u64;
    loop {
        let n = match f.read_at(&mut buf, at) {
            Ok(0) => return Ok(out),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("cannot read the {what}: {e}")),
        };
        at = at.saturating_add(n as u64);
        if at > max {
            return Err(format!("the {what} grew past the {max} bytes taken"));
        }
        out.extend_from_slice(&buf[..n]);
    }
}

/// Read a file the daemon trusts at `path` (a base manifest, anything in
/// `.incoming`): its dir opened `O_DIRECTORY|O_NOFOLLOW`, the file
/// `O_RDONLY|O_NOFOLLOW|O_NONBLOCK` relative to it (a symlink fails, a
/// FIFO never blocks), then [`read_fd`]'s checks through that descriptor.
pub fn read_trusted(path: &Path, what: &str, max: u64) -> Result<Vec<u8>, String> {
    let (up, name) = open_parent(path).map_err(|e| format!("the {what}: {e}"))?;
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd = openat(&up, name, flags, Mode::empty()).map_err(|e| format!("the {what}: {e}"))?;
    read_fd(&File::from(fd), what, max)
}

/// A box's base manifest ([`BoxPaths::base_manifest`], daemon-trusted),
/// read with [`read_trusted`] and parsed.
pub fn read_base_manifest(paths: &BoxPaths) -> Result<BaseManifest, String> {
    let text = read_trusted(&paths.base_manifest(), "base manifest", MANIFEST_MAX_BYTES)?;
    let text = String::from_utf8(text).map_err(|_| "the base manifest is not UTF-8")?;
    BaseManifest::parse(&text)
}

pub(crate) fn random_hex() -> Result<String, String> {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).map_err(|e| format!("no randomness for the incoming dir: {e}"))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// The passed descriptor as a regular file of at most `max` bytes; its
/// length.
pub(crate) fn regular(f: &File, what: &str, max: u64) -> Result<u64, String> {
    let st = rustix::fs::fstat(f).map_err(|e| format!("the {what}: {e}"))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(format!("the {what} is not a regular file"));
    }
    let len = u64::try_from(st.st_size).unwrap_or(u64::MAX);
    if len > max {
        return Err(format!(
            "the {what} is {len} bytes, more than the {max} taken"
        ));
    }
    Ok(len)
}

/// A new file `name` in `dir` with `mode`, never through a symlink, and
/// `src` copied into it (at most `len` bytes, the length checked); the
/// copy, open for reading.
pub(crate) fn copy_in(
    dir: &OwnedFd,
    name: &str,
    mode: u32,
    src: &File,
    len: u64,
) -> Result<File, String> {
    let flags = OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let fd = openat(dir, name, flags, Mode::from_raw_mode(mode))
        .map_err(|e| format!("cannot make {name}: {e}"))?;
    // The umask may have taken bits: the mode is set as asked.
    rustix::fs::fchmod(&fd, Mode::from_raw_mode(mode)).map_err(|e| format!("{name}: {e}"))?;
    let dst = File::from(fd);
    saiife_boxhost::disk::copy_sparse_upto(src, &dst, len)
        .map_err(|e| format!("cannot copy {name}: {e}"))?;
    let got = dst.metadata().map_err(|e| format!("{name}: {e}"))?.len();
    if got != len {
        return Err(format!("{name} changed while it was copied"));
    }
    Ok(dst)
}

/// The files [`intake`] makes in its incoming dir.
const INTAKE_FILES: &[&str] = &[REPO_DISK, BASE_MANIFEST];

/// Remove `<.incoming>/<sub>` and the files `names` in it (an intake's
/// own: [`INTAKE_FILES`] here, the image import's in `crate::box_images`).
pub(crate) fn remove_sub(inc: &OwnedFd, sub: &str, names: &[&str]) {
    if let Ok(d) = open_dir(inc, sub) {
        for n in names {
            let _ = rustix::fs::unlinkat(&d, *n, AtFlags::empty());
        }
    }
    let _ = rustix::fs::unlinkat(inc, sub, AtFlags::REMOVEDIR);
}

/// Take the two descriptors `box.spawn` was passed (the repo disk, then
/// its base manifest) into a fresh `<incoming>/<16 hex>/` ([`incoming_in`]):
/// exactly two, each a regular file, the disk at most [`IMAGE_MAX_BYTES`]
/// and the manifest at most [`MANIFEST_MAX_BYTES`]; both copied (the disk
/// 0640 keeping its holes, the manifest 0600); then the copy of the disk
/// must carry the ext4 magic and the copy of the manifest must parse.
/// Returns the copies' paths and the parsed manifest. On any failure
/// nothing stays in `.incoming`.
pub fn intake(
    boxes_root: &Path,
    fds: Vec<OwnedFd>,
) -> Result<(PathBuf, PathBuf, BaseManifest), String> {
    if fds.len() != 2 {
        return Err(format!(
            "box.spawn takes two descriptors (the repo disk and its base manifest), not {}",
            fds.len()
        ));
    }
    let mut it = fds.into_iter().map(File::from);
    let (Some(image), Some(manifest)) = (it.next(), it.next()) else {
        return Err("box.spawn takes two descriptors".into());
    };
    let image_len = regular(&image, "repo disk", IMAGE_MAX_BYTES)?;
    let manifest_len = regular(&manifest, "base manifest", MANIFEST_MAX_BYTES)?;
    let inc = incoming_dir(boxes_root, true)?;
    let dir = incoming_in(boxes_root).join(random_hex()?);
    let sub = dir.file_name().and_then(OsStr::to_str).unwrap_or_default();
    mkdirat(&inc, sub, Mode::from_raw_mode(0o700))
        .map_err(|e| format!("cannot make {}: {e}", dir.display()))?;
    let made = (|| {
        let d = open_dir(&inc, sub).map_err(|e| format!("{}: {e}", dir.display()))?;
        let img = copy_in(&d, REPO_DISK, 0o640, &image, image_len)?;
        let mut magic = [0u8; 2];
        let ext4 = matches!(img.read_at(&mut magic, EXT4_MAGIC_AT), Ok(2)) && magic == EXT4_MAGIC;
        if !ext4 {
            return Err("the repo disk is not an ext4 image".to_string());
        }
        let man = copy_in(&d, BASE_MANIFEST, 0o600, &manifest, manifest_len)?;
        // Read through the copy's own descriptor, with the trusted checks.
        let text = read_fd(&man, "base manifest", MANIFEST_MAX_BYTES)?;
        let text = String::from_utf8(text).map_err(|_| "the base manifest is not UTF-8")?;
        BaseManifest::parse(&text)
    })();
    match made {
        Ok(m) => Ok((dir.join(REPO_DISK), dir.join(BASE_MANIFEST), m)),
        Err(e) => {
            remove_sub(&inc, sub, INTAKE_FILES);
            Err(e)
        }
    }
}

/// Remove the incoming dir [`intake`] made for `image` (best effort): the
/// spawn is over, and whatever the manager did not move in goes. Only a
/// dir right under [`incoming_in`] of `boxes_root` is touched.
pub fn discard(boxes_root: &Path, image: &Path) {
    let Some(sub) = image
        .parent()
        .filter(|d| d.parent() == Some(incoming_in(boxes_root).as_path()))
        .and_then(Path::file_name)
        .and_then(OsStr::to_str)
    else {
        return;
    };
    if let Ok(inc) = incoming_dir(boxes_root, false) {
        remove_sub(&inc, sub, INTAKE_FILES);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use saiife_boxes::place::INCOMING;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    /// A sparse file with the ext4 magic where the superblock has it.
    pub(crate) fn ext4_file(p: &Path, len: u64) -> File {
        let f = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(p)
            .unwrap();
        f.set_len(len).unwrap();
        f.write_all_at(&EXT4_MAGIC, EXT4_MAGIC_AT).unwrap();
        f
    }

    pub(crate) fn manifest_text() -> String {
        format!(
            "{{\"version\":1,\"repo\":\"shop\",\"base_commit\":null,\
             \"snapshot_commit\":\"{}\",\"files\":0,\"bytes\":0,\"entries\":{{}}}}",
            "a".repeat(40)
        )
    }

    fn fd(f: File) -> OwnedFd {
        OwnedFd::from(f)
    }

    fn incoming_left(root: &Path) -> Vec<PathBuf> {
        match std::fs::read_dir(root.join(INCOMING)) {
            Ok(rd) => rd.map(|e| e.unwrap().path()).collect(),
            Err(_) => Vec::new(),
        }
    }

    #[test]
    fn intake_copies_into_incoming() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("boxes");
        std::fs::create_dir(&root).unwrap();
        let img = ext4_file(&t.path().join("src.img"), 64 << 20);
        img.write_all_at(b"payload", 32 << 20).unwrap();
        let man_path = t.path().join("base.json");
        std::fs::write(&man_path, manifest_text()).unwrap();
        let man = File::open(&man_path).unwrap();
        let (i, m, parsed) = intake(&root, vec![fd(img), fd(man)]).unwrap();
        assert_eq!(parsed.repo, "shop");
        let sub = i.parent().unwrap();
        assert_eq!(sub.parent().unwrap(), root.join(INCOMING));
        let name = sub.file_name().unwrap().to_str().unwrap();
        assert_eq!(name.len(), 16, "{name}");
        assert!(name.bytes().all(|b| b.is_ascii_hexdigit()), "{name}");
        assert_eq!(m.parent().unwrap(), sub);
        let mode = |p: &Path| std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(&root.join(INCOMING)), 0o700);
        assert_eq!(mode(sub), 0o700);
        assert_eq!(mode(&i), 0o640);
        assert_eq!(mode(&m), 0o600);
        // The daemon's own copies: same bytes, holes kept.
        let copy = File::open(&i).unwrap();
        assert_eq!(copy.metadata().unwrap().len(), 64 << 20);
        let mut b = [0u8; 7];
        copy.read_exact_at(&mut b, 32 << 20).unwrap();
        assert_eq!(&b, b"payload");
        assert!(copy.metadata().unwrap().blocks() * 512 < 8 << 20);
        assert_eq!(std::fs::read_to_string(&m).unwrap(), manifest_text());
        // Removed with `discard`, and only that dir.
        discard(&root, &i);
        assert!(incoming_left(&root).is_empty());
        assert!(root.join(INCOMING).is_dir());
    }

    #[test]
    fn intake_refusals_leave_nothing() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("boxes");
        std::fs::create_dir(&root).unwrap();
        let good_img = |n: &str| fd(ext4_file(&t.path().join(n), 1 << 20));
        let good_man = |n: &str| {
            let p = t.path().join(n);
            std::fs::write(&p, manifest_text()).unwrap();
            fd(File::open(&p).unwrap())
        };
        let refused = |fds: Vec<OwnedFd>, want: &str| {
            let e = intake(&root, fds).unwrap_err();
            assert!(e.contains(want), "{e}");
            assert!(incoming_left(&root).is_empty(), "{e}");
        };
        // Counts.
        refused(vec![good_img("a1")], "not 1");
        refused(
            vec![good_img("a2"), good_man("m2"), good_man("m3")],
            "not 3",
        );
        // A directory and a socket.
        let dir = fd(File::open(t.path()).unwrap());
        refused(vec![dir, good_man("m4")], "not a regular file");
        let (sock, _far) = std::os::unix::net::UnixStream::pair().unwrap();
        refused(
            vec![good_img("a5"), OwnedFd::from(sock)],
            "not a regular file",
        );
        // No ext4 magic.
        let plain = t.path().join("plain.img");
        std::fs::write(&plain, vec![0u8; 4096]).unwrap();
        refused(
            vec![fd(File::open(&plain).unwrap()), good_man("m6")],
            "not an ext4 image",
        );
        let short = t.path().join("short.img");
        std::fs::write(&short, b"x").unwrap();
        refused(
            vec![fd(File::open(&short).unwrap()), good_man("m7")],
            "not an ext4 image",
        );
        // A manifest that does not parse, or is no UTF-8.
        let bad = t.path().join("bad.json");
        std::fs::write(&bad, "{\"version\": 2}").unwrap();
        refused(
            vec![good_img("a8"), fd(File::open(&bad).unwrap())],
            "base manifest",
        );
        std::fs::write(&bad, [0xff, 0xfe]).unwrap();
        refused(
            vec![good_img("a9"), fd(File::open(&bad).unwrap())],
            "not UTF-8",
        );
        // Over the size caps (sparse, so nothing is written).
        let big = ext4_file(&t.path().join("big.img"), IMAGE_MAX_BYTES + 1);
        refused(vec![fd(big), good_man("m10")], "more than");
        let bigm = File::options()
            .write(true)
            .create_new(true)
            .open(t.path().join("big.json"))
            .unwrap();
        bigm.set_len(MANIFEST_MAX_BYTES + 1).unwrap();
        refused(vec![good_img("a11"), fd(bigm)], "more than");
    }

    #[test]
    fn incoming_must_be_a_real_dir() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("boxes");
        std::fs::create_dir(&root).unwrap();
        let elsewhere = t.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, root.join(INCOMING)).unwrap();
        let img = fd(ext4_file(&t.path().join("i"), 1 << 20));
        let p = t.path().join("m");
        std::fs::write(&p, manifest_text()).unwrap();
        let e = intake(&root, vec![img, fd(File::open(&p).unwrap())]).unwrap_err();
        assert!(e.contains(INCOMING), "{e}");
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
    }

    fn box_with_manifest(t: &Path) -> saiife_boxhost::paths::BoxPaths {
        let paths = saiife_boxhost::paths::BoxPaths::new(t.join("b1"));
        std::fs::create_dir(&paths.dir).unwrap();
        std::fs::write(paths.base_manifest(), manifest_text()).unwrap();
        paths
    }

    #[test]
    fn base_manifest_read_refuses_a_symlink() {
        let t = tempfile::tempdir().unwrap();
        let paths = box_with_manifest(t.path());
        assert_eq!(read_base_manifest(&paths).unwrap().repo, "shop");
        // The manifest swapped for a link to a good one: refused.
        let far = t.path().join("far.json");
        std::fs::write(&far, manifest_text()).unwrap();
        std::fs::remove_file(paths.base_manifest()).unwrap();
        std::os::unix::fs::symlink(&far, paths.base_manifest()).unwrap();
        let e = read_base_manifest(&paths).unwrap_err();
        assert!(e.contains("base manifest"), "{e}");
        // The box dir swapped for a link to a dir with a good one: refused.
        let x = t.path().join("x");
        std::fs::create_dir(&x).unwrap();
        let other = box_with_manifest(&x);
        let linked = saiife_boxhost::paths::BoxPaths::new(t.path().join("b2"));
        std::os::unix::fs::symlink(&other.dir, &linked.dir).unwrap();
        assert!(read_base_manifest(&linked).is_err());
    }

    #[test]
    fn base_manifest_read_refuses_what_is_no_plain_file() {
        let t = tempfile::tempdir().unwrap();
        let paths = box_with_manifest(t.path());
        // A FIFO: refused, and the open does not block.
        std::fs::remove_file(paths.base_manifest()).unwrap();
        rustix::fs::mknodat(
            CWD,
            paths.base_manifest(),
            FileType::Fifo,
            Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        let e = read_base_manifest(&paths).unwrap_err();
        assert!(e.contains("not a regular file"), "{e}");
        // A directory.
        std::fs::remove_file(paths.base_manifest()).unwrap();
        std::fs::create_dir(paths.base_manifest()).unwrap();
        let e = read_base_manifest(&paths).unwrap_err();
        assert!(e.contains("not a regular file"), "{e}");
        // Over the cap (sparse).
        std::fs::remove_dir(paths.base_manifest()).unwrap();
        let f = File::create(paths.base_manifest()).unwrap();
        f.set_len(MANIFEST_MAX_BYTES + 1).unwrap();
        let e = read_base_manifest(&paths).unwrap_err();
        assert!(e.contains("more than"), "{e}");
        // Missing.
        std::fs::remove_file(paths.base_manifest()).unwrap();
        assert!(read_base_manifest(&paths).is_err());
    }
}
