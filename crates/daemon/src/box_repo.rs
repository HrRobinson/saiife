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

use saiife_boxes::place::INCOMING;
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
/// The copies' names in the incoming dir.
pub const IMAGE_NAME: &str = "repo.img";
pub const MANIFEST_NAME: &str = "base.json";
/// The ext4 superblock magic, little-endian `0xEF53` at offset 1024 + 56.
const EXT4_MAGIC_AT: u64 = 1080;
const EXT4_MAGIC: [u8; 2] = [0x53, 0xEF];

fn dir_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn open_dir(at: impl rustix::fd::AsFd, name: impl rustix::path::Arg) -> io::Result<OwnedFd> {
    Ok(openat(at, name, dir_flags(), Mode::empty())?)
}

/// `<boxes>/.incoming`, made 0700 if missing; it must be a real directory
/// (not a symlink) owned by this process's uid.
fn incoming_dir(root: &OwnedFd) -> Result<OwnedFd, String> {
    match mkdirat(root, INCOMING, Mode::from_raw_mode(0o700)) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(e) => return Err(format!("cannot make {INCOMING}: {e}")),
    }
    let d = open_dir(root, INCOMING).map_err(|e| format!("cannot open {INCOMING}: {e}"))?;
    let st = rustix::fs::fstat(&d).map_err(|e| format!("{INCOMING}: {e}"))?;
    if st.st_uid != rustix::process::geteuid().as_raw() {
        return Err(format!("{INCOMING} is not the daemon's own"));
    }
    if st.st_mode & 0o077 != 0 {
        rustix::fs::fchmod(&d, Mode::from_raw_mode(0o700))
            .map_err(|e| format!("{INCOMING}: {e}"))?;
    }
    Ok(d)
}

fn random_hex() -> Result<String, String> {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).map_err(|e| format!("no randomness for the incoming dir: {e}"))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// The passed descriptor as a regular file of at most `max` bytes; its
/// length.
fn regular(f: &File, what: &str, max: u64) -> Result<u64, String> {
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
fn copy_in(dir: &OwnedFd, name: &str, mode: u32, src: &File, len: u64) -> Result<File, String> {
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

/// Remove `<.incoming>/<sub>` and the files [`intake`] makes in it.
fn remove_sub(inc: &OwnedFd, sub: &str) {
    if let Ok(d) = open_dir(inc, sub) {
        for n in [IMAGE_NAME, MANIFEST_NAME] {
            let _ = rustix::fs::unlinkat(&d, n, AtFlags::empty());
        }
    }
    let _ = rustix::fs::unlinkat(inc, sub, AtFlags::REMOVEDIR);
}

/// Take the two descriptors `box.spawn` was passed (the repo disk, then
/// its base manifest) into a fresh `<boxes_root>/.incoming/<16 hex>/`:
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
    let root = open_dir(CWD, boxes_root)
        .map_err(|e| format!("cannot open {}: {e}", boxes_root.display()))?;
    let inc = incoming_dir(&root)?;
    let sub = random_hex()?;
    mkdirat(&inc, sub.as_str(), Mode::from_raw_mode(0o700))
        .map_err(|e| format!("cannot make {INCOMING}/{sub}: {e}"))?;
    let made = (|| {
        let d = open_dir(&inc, sub.as_str()).map_err(|e| format!("{INCOMING}/{sub}: {e}"))?;
        let img = copy_in(&d, IMAGE_NAME, 0o640, &image, image_len)?;
        let mut magic = [0u8; 2];
        let ext4 = matches!(img.read_at(&mut magic, EXT4_MAGIC_AT), Ok(2)) && magic == EXT4_MAGIC;
        if !ext4 {
            return Err("the repo disk is not an ext4 image".to_string());
        }
        let man = copy_in(&d, MANIFEST_NAME, 0o600, &manifest, manifest_len)?;
        let mut text = vec![0u8; usize::try_from(manifest_len).unwrap_or(0)];
        man.read_exact_at(&mut text, 0)
            .map_err(|e| format!("cannot read the base manifest: {e}"))?;
        let text = String::from_utf8(text).map_err(|_| "the base manifest is not UTF-8")?;
        BaseManifest::parse(&text)
    })();
    match made {
        Ok(m) => {
            let dir = boxes_root.join(INCOMING).join(&sub);
            Ok((dir.join(IMAGE_NAME), dir.join(MANIFEST_NAME), m))
        }
        Err(e) => {
            remove_sub(&inc, &sub);
            Err(e)
        }
    }
}

/// Remove the incoming dir [`intake`] made for `image` (best effort): the
/// spawn is over, and whatever the manager did not move in goes. Only a
/// dir right under `<boxes_root>/.incoming` is touched.
pub fn discard(boxes_root: &Path, image: &Path) {
    let Some(sub) = image
        .parent()
        .filter(|d| d.parent() == Some(boxes_root.join(INCOMING).as_path()))
        .and_then(Path::file_name)
        .and_then(OsStr::to_str)
    else {
        return;
    };
    let Ok(root) = open_dir(CWD, boxes_root) else {
        return;
    };
    if let Ok(inc) = open_dir(&root, INCOMING) {
        remove_sub(&inc, sub);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
