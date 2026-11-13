//! The box's repo disk (plan 37 Task 3, spec §7.5 In): the work-tree
//! snapshot, its base manifest, the snapshot commit and the `mke2fs -d`
//! image, against real `git` in tempdir repos (HOME at a tempdir, no global
//! or system git config) and a fake `mke2fs` that records its argv. Nothing
//! here runs the real mke2fs.
#![cfg(target_os = "linux")]

#[path = "../src/box_repo.rs"]
#[allow(dead_code)]
mod box_repo;

use box_repo::{
    make_repo_image, repo_image_mib, set_base_ref, snapshot, snapshot_commit, Snapshot,
};
use saiife_boxhost::tools::Tools;
use saiife_boxproto::manifest::{BaseManifest, Entry, EntryKind};
use saiife_wire::source::BoxId;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Once;

/// The file cap every test in this binary runs under (the debug-only
/// `SAIIFE_TEST_REPO_MAX_FILES`); only the oversized fixture crosses it.
const TEST_MAX_FILES: usize = 50;

/// One process-wide environment for the git the tests and the code run:
/// set once, before any git runs, to the same values for every test.
fn env() {
    static ONCE: Once = Once::new();
    // The child of `snapshot_commit_without_identity_is_saiife` gets its
    // environment from its parent, whole.
    if std::env::var_os(NO_IDENT_CHILD).is_some() {
        return;
    }
    ONCE.call_once(|| {
        let base = std::env::var_os("SAIIFE_TEST_TMP")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let home = base.join(format!("p37-t3-home-{}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        let vars: [(&str, &OsStr); 9] = [
            ("HOME", home.as_os_str()),
            ("GIT_CONFIG_GLOBAL", OsStr::new("/dev/null")),
            ("GIT_CONFIG_NOSYSTEM", OsStr::new("1")),
            ("GIT_AUTHOR_NAME", OsStr::new("Test")),
            ("GIT_AUTHOR_EMAIL", OsStr::new("test@example.invalid")),
            ("GIT_COMMITTER_NAME", OsStr::new("Test")),
            ("GIT_COMMITTER_EMAIL", OsStr::new("test@example.invalid")),
            ("XDG_CONFIG_HOME", home.as_os_str()),
            (
                "SAIIFE_TEST_REPO_MAX_FILES",
                OsStr::new(Box::leak(TEST_MAX_FILES.to_string().into_boxed_str())),
            ),
        ];
        for (k, v) in vars {
            std::env::set_var(k, v);
        }
    });
}

struct W {
    _d: tempfile::TempDir,
    repo: PathBuf,
    cache: PathBuf,
    bin: PathBuf,
    tools: Tools,
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn exec(p: &Path, body: &str) {
    std::fs::write(p, body).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A fake mke2fs: records its argv (one per line) next to itself and
/// writes a marker to the image path (the next-to-last argument); `fail`
/// exits 1 instead.
fn world_with(fail: bool) -> W {
    env();
    let d = tempfile::tempdir().unwrap();
    let repo = d.path().join("demo");
    let cache = d.path().join("cache").join("saiife");
    let bin = d.path().join("bin");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&bin).unwrap();
    let body = if fail {
        "#!/bin/sh\necho 'mke2fs: no space' >&2\nexit 1\n".to_string()
    } else {
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n\
             for a; do img=$last; last=$a; done\nprintf 'fake-ext4' > \"$img\"\n",
            bin.join("argv").display()
        )
    };
    exec(&bin.join("mke2fs"), &body);
    let fake = bin.join("mke2fs").into_os_string();
    let tools = Tools::system(&bin)
        .with_env(&move |k: &str| (k == "SAIIFE_TOOL_MKE2FS").then(|| fake.clone()));
    git(&repo, &["init", "-q", "-b", "main"]);
    W {
        _d: d,
        repo,
        cache,
        bin,
        tools,
    }
}

fn world() -> W {
    world_with(false)
}

impl W {
    fn write(&self, rel: &str, body: &[u8]) {
        let p = self.repo.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }
    fn commit(&self, msg: &str) -> String {
        git(&self.repo, &["add", "-A"]);
        git(&self.repo, &["commit", "-q", "-m", msg]);
        git(&self.repo, &["rev-parse", "HEAD"]).trim().to_string()
    }
    /// The staging dirs left under `<cache>/box-spawn`.
    fn left(&self) -> Vec<PathBuf> {
        match std::fs::read_dir(self.cache.join("box-spawn")) {
            Ok(rd) => rd.map(|e| e.unwrap().path()).collect(),
            Err(_) => Vec::new(),
        }
    }
}

fn sha(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

fn mode(p: &Path) -> u32 {
    std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
}

#[test]
fn snapshot_copies_tracked_untracked_and_edits() {
    let w = world();
    w.write(".gitignore", b"ignored.txt\n");
    w.write("a.txt", b"one\n");
    w.write("src/lib.rs", b"// lib\n");
    let head = w.commit("first");
    w.write("a.txt", b"two\n");
    w.write("new.txt", b"untracked\n");
    w.write("ignored.txt", b"nope\n");

    let s = snapshot(&w.tools, &w.repo, &w.cache).unwrap();
    assert_eq!(s.manifest.base_commit.as_deref(), Some(head.as_str()));
    assert_eq!(s.manifest.version, 1);
    assert_eq!(s.manifest.repo, "demo");
    assert_eq!(std::fs::read(s.staging.join("a.txt")).unwrap(), b"two\n");
    assert_eq!(
        std::fs::read(s.staging.join("new.txt")).unwrap(),
        b"untracked\n"
    );
    assert_eq!(
        std::fs::read(s.staging.join("src/lib.rs")).unwrap(),
        b"// lib\n"
    );
    assert!(!s.staging.join("ignored.txt").exists());
    let keys: Vec<&str> = s.manifest.entries.keys().map(String::as_str).collect();
    assert_eq!(keys, [".gitignore", "a.txt", "new.txt", "src/lib.rs"]);
    assert!(s.warnings.is_empty(), "{:?}", s.warnings);

    // <cache>/box-spawn/<16 hex>/tree, the hex dir 0700.
    assert_eq!(s.staging.file_name().unwrap(), "tree");
    let hexdir = s.staging.parent().unwrap();
    assert_eq!(hexdir.parent().unwrap(), w.cache.join("box-spawn"));
    let name = hexdir.file_name().unwrap().to_str().unwrap();
    assert_eq!(name.len(), 16);
    assert!(name.bytes().all(|b| b.is_ascii_hexdigit()), "{name}");
    assert_eq!(mode(hexdir), 0o700);
    assert_eq!(mode(&s.staging.join("src")), 0o755);

    s.remove();
    assert!(w.left().is_empty());
}

#[test]
fn odd_entries() {
    let w = world();
    let outside = w._d.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("f.txt"), b"secret\n").unwrap();
    w.write("keep.txt", b"k\n");
    w.write("del.txt", b"gone\n");
    w.write("d/f.txt", b"tracked\n");
    w.write("new\nline.txt", b"nl\n");
    w.write("pipe", b"was a file\n");
    w.commit("first");
    // A submodule: a gitlink whose work tree is a directory.
    let sub = w._d.path().join("subsrc");
    std::fs::create_dir_all(&sub).unwrap();
    git(&sub, &["init", "-q"]);
    std::fs::write(sub.join("s.txt"), b"s\n").unwrap();
    git(&sub, &["add", "s.txt"]);
    git(&sub, &["commit", "-q", "-m", "s"]);
    let sub_head = git(&sub, &["rev-parse", "HEAD"]).trim().to_string();
    git(
        &w.repo,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{sub_head},sub"),
        ],
    );
    w.write("sub/s.txt", b"s\n");
    // An untracked nested repo.
    w.write("nested/n.txt", b"n\n");
    git(&w.repo.join("nested"), &["init", "-q"]);
    // Deleted but tracked.
    std::fs::remove_file(w.repo.join("del.txt")).unwrap();
    // A symlink to /etc/passwd: its target is data.
    symlink("/etc/passwd", w.repo.join("pw")).unwrap();
    // A FIFO (git lists only the tracked one): never opened blocking.
    std::fs::remove_file(w.repo.join("pipe")).unwrap();
    let made = Command::new("mkfifo")
        .arg(w.repo.join("pipe"))
        .status()
        .unwrap();
    assert!(made.success());
    // A tracked d/f.txt whose parent d is now a symlink to elsewhere.
    std::fs::remove_dir_all(w.repo.join("d")).unwrap();
    symlink(&outside, w.repo.join("d")).unwrap();

    let s = snapshot(&w.tools, &w.repo, &w.cache).unwrap();
    let keys: Vec<&str> = s.manifest.entries.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        ["d", "keep.txt", "new\nline.txt", "pw"],
        "{:?}",
        s.warnings
    );

    let pw = &s.manifest.entries["pw"];
    assert_eq!(pw.kind, EntryKind::Symlink);
    assert_eq!(pw.mode, 0);
    assert_eq!(pw.size, 11);
    assert_eq!(pw.sha256, sha(b"/etc/passwd"));
    assert_eq!(
        std::fs::read_link(s.staging.join("pw")).unwrap(),
        Path::new("/etc/passwd")
    );
    assert_eq!(
        std::fs::read_link(s.staging.join("d")).unwrap(),
        outside.as_path()
    );
    assert_eq!(
        std::fs::read(s.staging.join("new\nline.txt")).unwrap(),
        b"nl\n"
    );
    assert!(!s.staging.join("del.txt").exists());
    assert!(std::fs::symlink_metadata(s.staging.join("pipe")).is_err());
    assert!(std::fs::symlink_metadata(s.staging.join("sub")).is_err());
    assert!(std::fs::symlink_metadata(s.staging.join("nested")).is_err());
    // Nothing was read or written through the symlinked parent.
    let names: Vec<_> = std::fs::read_dir(&outside).unwrap().collect();
    assert_eq!(names.len(), 1);
    assert_eq!(std::fs::read(outside.join("f.txt")).unwrap(), b"secret\n");

    let warned = |what: &str| s.warnings.iter().any(|x| x.contains(what));
    for what in ["pipe", "sub", "nested", "d/f.txt"] {
        assert!(warned(what), "no warning for {what}: {:?}", s.warnings);
    }
    assert!(!warned("del.txt"), "{:?}", s.warnings);
    assert_eq!(s.warnings.len(), 4, "{:?}", s.warnings);
    s.remove();

    // A name that is not UTF-8 is refused, its bytes escaped.
    let w = world();
    w.write("ok.txt", b"ok\n");
    let bad = w.repo.join(OsStr::from_bytes(b"bad\xffname"));
    std::fs::write(&bad, b"x").unwrap();
    let e = snapshot(&w.tools, &w.repo, &w.cache).err().unwrap();
    assert!(e.contains("bad\\xffname"), "{e}");
    assert!(e.contains("UTF-8"), "{e}");
    assert!(w.left().is_empty());
}

#[test]
fn manifest_hashes_and_modes() {
    let w = world();
    w.write("x.sh", b"#!/bin/sh\n");
    w.write("y.txt", b"hello");
    w.write("p/rw.txt", b"private");
    w.write("p/rx", b"bin");
    std::fs::set_permissions(w.repo.join("x.sh"), PermissionsExt::from_mode(0o755)).unwrap();
    std::fs::set_permissions(w.repo.join("p/rw.txt"), PermissionsExt::from_mode(0o600)).unwrap();
    std::fs::set_permissions(w.repo.join("p/rx"), PermissionsExt::from_mode(0o700)).unwrap();
    symlink("y.txt", w.repo.join("link")).unwrap();

    let s = snapshot(&w.tools, &w.repo, &w.cache).unwrap();
    let e = &s.manifest.entries;
    let file = |m: u32, b: &[u8]| Entry {
        kind: EntryKind::File,
        mode: m,
        size: b.len() as u64,
        sha256: sha(b),
    };
    assert_eq!(e["x.sh"], file(0o755, b"#!/bin/sh\n"));
    assert_eq!(e["y.txt"], file(0o644, b"hello"));
    assert_eq!(e["p/rw.txt"], file(0o644, b"private"));
    assert_eq!(e["p/rx"], file(0o755, b"bin"));
    assert_eq!(
        e["link"],
        Entry {
            kind: EntryKind::Symlink,
            mode: 0,
            size: 5,
            sha256: sha(b"y.txt"),
        }
    );
    assert_eq!(s.manifest.files, 5);
    assert_eq!(s.manifest.bytes, 10 + 5 + 7 + 3 + 5);
    assert_eq!(s.manifest.base_commit, None);
    assert_eq!(mode(&s.staging.join("x.sh")), 0o755);
    assert_eq!(mode(&s.staging.join("y.txt")), 0o644);
    assert_eq!(mode(&s.staging.join("p/rw.txt")), 0o644);
    assert_eq!(mode(&s.staging.join("p/rx")), 0o755);
    s.remove();
}

fn fixture(sizes: &[(&str, EntryKind, u64)]) -> BaseManifest {
    let mut entries = BTreeMap::new();
    for (p, k, size) in sizes {
        entries.insert(
            p.to_string(),
            Entry {
                kind: k.clone(),
                mode: if *k == EntryKind::File { 0o644 } else { 0 },
                size: *size,
                sha256: "0".repeat(64),
            },
        );
    }
    BaseManifest {
        version: 1,
        repo: "demo".into(),
        base_commit: None,
        snapshot_commit: String::new(),
        files: entries.len() as u64,
        bytes: sizes.iter().map(|s| s.2).sum(),
        entries,
    }
}

#[test]
fn image_size_formula() {
    // bytes = 4096 + 4096 + 8192 + 0 (files rounded up to 4096)
    //       + 4096 (one symlink) + 2 × 4096 (two dirs) = 28672
    // mib = ceil((2 × 28672 + 256 MiB) / 1 MiB) = 257
    let m = fixture(&[
        ("a/one", EntryKind::File, 1),
        ("a/b/page", EntryKind::File, 4096),
        ("over", EntryKind::File, 4097),
        ("empty", EntryKind::File, 0),
        ("link", EntryKind::Symlink, 30),
    ]);
    assert_eq!(repo_image_mib(&m, 2), 257);
    assert_eq!(repo_image_mib(&fixture(&[]), 0), 256);
    // Exactly 1 GiB of file: 2 GiB + 256 MiB, no rounding.
    let g = fixture(&[("big", EntryKind::File, 1 << 30)]);
    assert_eq!(repo_image_mib(&g, 0), 2304);
    // 2 × bytes exactly 1 MiB stays 257; one directory more crosses it.
    let edge = fixture(&[("f", EntryKind::File, 524288 - 3 * 4096)]);
    assert_eq!(repo_image_mib(&edge, 3), 257);
    assert_eq!(repo_image_mib(&edge, 4), 258);

    // The dirs make_repo_image counts exclude the staging root: a/ and a/b/
    // here, so 512000 + 4096 + 2 × 4096 = 524288 bytes, exactly 257 MiB
    // (with the root counted it would be 258).
    let w = world();
    w.write("a/b/c.bin", &vec![7u8; 512000]);
    w.write("x.txt", b"x");
    let s = snapshot(&w.tools, &w.repo, &w.cache).unwrap();
    assert_eq!(repo_image_mib(&s.manifest, 2), 257);
    assert_eq!(repo_image_mib(&s.manifest, 3), 258);
    make_repo_image(&w.tools, &s).unwrap();
    let argv = std::fs::read_to_string(w.bin.join("argv")).unwrap();
    assert_eq!(argv.lines().last(), Some("257M"));
    s.remove();
}

#[test]
fn mke2fs_argv_is_pinned() {
    let w = world();
    w.write("README", b"hi\n");
    let s = snapshot(&w.tools, &w.repo, &w.cache).unwrap();
    let img = make_repo_image(&w.tools, &s).unwrap();
    assert_eq!(img, s.staging.parent().unwrap().join("repo.img"));
    assert_eq!(std::fs::read(&img).unwrap(), b"fake-ext4");
    let argv = std::fs::read_to_string(w.bin.join("argv")).unwrap();
    // R24: `-i 4096` (one inode per 4 KiB of image) before `-d`.
    let want = format!(
        "-q\n-t\next4\n-L\nrepo\n-i\n4096\n-d\n{}\n{}\n257M\n",
        s.staging.display(),
        img.display()
    );
    assert_eq!(argv, want);
    s.remove();
    assert!(w.left().is_empty());
}

/// R21: a spawn the user interrupted leaves its staging dir; the next
/// snapshot removes `box-spawn` entries over an hour old, never following a
/// link, and keeps younger ones.
#[test]
fn interrupted_staging_is_swept() {
    use std::time::{Duration, SystemTime};
    let w = world();
    w.write("README", b"hi\n");
    let spawn = w.cache.join("box-spawn");
    let back = SystemTime::now() - Duration::from_secs(2 * 3600);
    // utimensat with AT_SYMLINK_NOFOLLOW: a link's own times, not its
    // target's.
    let age = |p: &Path| {
        let at = rustix::fs::Timespec {
            tv_sec: back
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as _,
            tv_nsec: 0,
        };
        let t = rustix::fs::Timestamps {
            last_access: at,
            last_modification: at,
        };
        rustix::fs::utimensat(
            rustix::fs::CWD,
            p,
            &t,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .unwrap();
    };
    // Outside the cache: a dir and a file the old entries link to.
    let far = w.repo.parent().unwrap().join("far");
    std::fs::create_dir_all(far.join("d")).unwrap();
    std::fs::write(far.join("d/keep"), b"keep").unwrap();
    std::fs::write(far.join("f"), b"f").unwrap();
    // An old staging dir, as an interrupted spawn leaves it, with a link
    // out of it.
    let old = spawn.join("0000000000000000");
    std::fs::create_dir_all(old.join("tree/src")).unwrap();
    std::fs::write(old.join("tree/src/main.rs"), b"m").unwrap();
    std::fs::write(old.join("repo.img"), b"img").unwrap();
    symlink(far.join("d"), old.join("tree/out")).unwrap();
    // Old links in box-spawn itself, to a dir and to a file outside.
    symlink(far.join("d"), spawn.join("1111111111111111")).unwrap();
    symlink(far.join("f"), spawn.join("stray-link")).unwrap();
    std::fs::write(spawn.join("stray"), b"s").unwrap();
    // A young one (another spawn running now).
    let young = spawn.join("2222222222222222");
    std::fs::create_dir_all(young.join("tree")).unwrap();
    for p in [
        old.as_path(),
        &spawn.join("1111111111111111"),
        &spawn.join("stray-link"),
        &spawn.join("stray"),
    ] {
        age(p);
    }
    let s = snapshot(&w.tools, &w.repo, &w.cache).unwrap();
    let name = |p: &Path| p.file_name().unwrap().to_owned();
    let mut left: Vec<OsString> = w.left().iter().map(|p| name(p)).collect();
    left.sort();
    let mut want = vec![name(&young), name(s.dir())];
    want.sort();
    assert_eq!(left, want);
    // Nothing a link named was touched.
    assert_eq!(std::fs::read(far.join("d/keep")).unwrap(), b"keep");
    assert_eq!(std::fs::read(far.join("f")).unwrap(), b"f");
    assert!(young.join("tree").is_dir());
    s.remove();
}

#[test]
fn oversized_repo_is_refused_with_top_dirs() {
    // Too many files: a build-output dir with no ignore rule.
    let w = world();
    for i in 0..TEST_MAX_FILES {
        w.write(&format!("target/debug/o{i}.o"), b"obj");
    }
    w.write("src/main.rs", b"fn main() {}\n");
    w.write("docs/a.md", b"a\n");
    w.write("docs/b.md", b"b\n");
    let e = snapshot(&w.tools, &w.repo, &w.cache).err().unwrap();
    assert!(
        e.contains(&format!("more than {TEST_MAX_FILES} files")),
        "{e}"
    );
    assert!(e.contains("target/ (50 files"), "{e}");
    let t = e.find("target/").unwrap();
    let d = e.find("docs/ (2 files").expect(&e);
    assert!(t < d, "biggest first: {e}");
    assert!(e.contains("ignore"), "{e}");
    assert!(w.left().is_empty(), "{:?}", w.left());

    // One huge file (sparse: nothing is written or read).
    let w = world();
    w.write("src/main.rs", b"fn main() {}\n");
    let f = std::fs::File::create(w.repo.join("video.mp4")).unwrap();
    f.set_len(9 << 30).unwrap();
    drop(f);
    let e = snapshot(&w.tools, &w.repo, &w.cache).err().unwrap();
    assert!(e.contains("8 GiB"), "{e}");
    assert!(e.contains("video.mp4 (1 file, 9.0 GiB)"), "{e}");
    assert!(w.left().is_empty(), "{:?}", w.left());
    // No image was built.
    assert!(!w.bin.join("argv").exists());
}

#[test]
fn staging_is_removed_on_failure() {
    // A name that is not UTF-8, found after the staging dir exists.
    let w = world();
    w.write("a.txt", b"a\n");
    std::fs::write(w.repo.join(OsStr::from_bytes(b"z\xfe")), b"z").unwrap();
    assert!(snapshot(&w.tools, &w.repo, &w.cache).is_err());
    assert!(w.left().is_empty(), "{:?}", w.left());

    // A path check_path refuses (a backslash).
    let w = world();
    w.write("a.txt", b"a\n");
    w.write("win\\dows.txt", b"w\n");
    let e = snapshot(&w.tools, &w.repo, &w.cache).err().unwrap();
    assert!(e.contains("backslash"), "{e}");
    assert!(w.left().is_empty(), "{:?}", w.left());

    // Over the file cap mid-walk.
    let w = world();
    for i in 0..=TEST_MAX_FILES {
        w.write(&format!("f{i:03}"), b"x");
    }
    assert!(snapshot(&w.tools, &w.repo, &w.cache).is_err());
    assert!(w.left().is_empty(), "{:?}", w.left());

    // An unreadable file (chmod 000) fails the copy.
    let w = world();
    w.write("a.txt", b"a\n");
    w.write("locked", b"l\n");
    std::fs::set_permissions(w.repo.join("locked"), PermissionsExt::from_mode(0o000)).unwrap();
    let r = snapshot(&w.tools, &w.repo, &w.cache);
    std::fs::set_permissions(w.repo.join("locked"), PermissionsExt::from_mode(0o644)).unwrap();
    assert!(r.is_err(), "{:?}", r.map(|s| s.staging));
    assert!(w.left().is_empty(), "{:?}", w.left());

    // Not a git repo at all.
    let w = world();
    std::fs::remove_dir_all(w.repo.join(".git")).unwrap();
    assert!(snapshot(&w.tools, &w.repo, &w.cache).is_err());
    assert!(w.left().is_empty());

    // mke2fs fails: the whole staging dir goes, not only the image.
    let w = world_with(true);
    w.write("a.txt", b"a\n");
    let s = snapshot(&w.tools, &w.repo, &w.cache).unwrap();
    let e = make_repo_image(&w.tools, &s).err().unwrap();
    assert!(e.contains("no space"), "{e}");
    assert!(w.left().is_empty(), "{:?}", w.left());

    // mke2fs missing.
    let w = world();
    w.write("a.txt", b"a\n");
    std::fs::remove_file(w.bin.join("mke2fs")).unwrap();
    let s = snapshot(&w.tools, &w.repo, &w.cache).unwrap();
    assert!(make_repo_image(&w.tools, &s).is_err());
    assert!(w.left().is_empty(), "{:?}", w.left());
}

/// `git ls-tree -r -z`: path → (mode, oid).
fn ls_tree(repo: &Path, commit: &str) -> BTreeMap<String, (String, String)> {
    let out = git(repo, &["ls-tree", "-r", "-z", commit]);
    out.split('\0')
        .filter(|l| !l.is_empty())
        .map(|l| {
            let (meta, path) = l.split_once('\t').unwrap();
            let f: Vec<&str> = meta.split(' ').collect();
            (path.to_string(), (f[0].to_string(), f[2].to_string()))
        })
        .collect()
}

fn blob(repo: &Path, oid: &str) -> Vec<u8> {
    let out = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(repo)
        .args(["cat-file", "blob", oid])
        .output()
        .unwrap();
    assert!(out.status.success());
    out.stdout
}

#[test]
fn snapshot_commit_tree_matches_staging() {
    let w = world();
    w.write("a.txt", b"one\n");
    w.write("deep/er/x.sh", b"#!/bin/sh\n");
    std::fs::set_permissions(
        w.repo.join("deep/er/x.sh"),
        PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    let head = w.commit("first");
    w.write("a.txt", b"two\n");
    w.write("new\nline.txt", b"nl\n");
    w.write("\"quoted\".txt", b"q\n");
    w.write("tab\there", b"t\n");
    git(&w.repo, &["add", "tab\there"]);
    symlink("a.txt", w.repo.join("link")).unwrap();
    let hooks = w.repo.join(".git/hooks");
    let marker = w._d.path().join("hook-ran");
    for h in [
        "pre-commit",
        "commit-msg",
        "post-commit",
        "reference-transaction",
    ] {
        exec(
            &hooks.join(h),
            &format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
        );
    }
    let index_before = std::fs::read(w.repo.join(".git/index")).unwrap();

    let mut s = snapshot(&w.tools, &w.repo, &w.cache).unwrap();
    let c = snapshot_commit(&w.tools, &w.repo, &mut s).unwrap();
    assert_eq!(s.manifest.snapshot_commit, c);
    assert_eq!(c.len(), 40);

    let tree = ls_tree(&w.repo, &c);
    let keys: Vec<&String> = tree.keys().collect();
    let want: Vec<&String> = s.manifest.entries.keys().collect();
    assert_eq!(keys, want);
    for (p, e) in &s.manifest.entries {
        let (m, oid) = &tree[p];
        let wm = match (&e.kind, e.mode) {
            (EntryKind::Symlink, _) => "120000",
            (EntryKind::File, 0o755) => "100755",
            _ => "100644",
        };
        assert_eq!(m, wm, "{p:?}");
        assert_eq!(sha(&blob(&w.repo, oid)), e.sha256, "{p:?}");
    }
    assert_eq!(tree["deep/er/x.sh"].0, "100755");
    assert_eq!(blob(&w.repo, &tree["a.txt"].1), b"two\n");

    let body = git(&w.repo, &["cat-file", "commit", &c]);
    assert!(body.contains(&format!("\nparent {head}\n")), "{body}");
    let msg = body.split_once("\n\n").unwrap().1;
    assert_eq!(
        msg,
        format!(
            "saiife box snapshot\n\nSaiife-Box-Snapshot: {}\n",
            s.manifest.sha256()
        )
    );

    // HEAD, the index and the work tree as they were; no hook ran.
    assert_eq!(git(&w.repo, &["rev-parse", "HEAD"]).trim(), head);
    assert_eq!(
        std::fs::read(w.repo.join(".git/index")).unwrap(),
        index_before
    );
    assert_eq!(std::fs::read(w.repo.join("a.txt")).unwrap(), b"two\n");
    assert!(!marker.exists(), "a hook ran");

    // The filled manifest passes the daemon-side parse.
    let text = serde_json::to_string(&s.manifest).unwrap();
    assert_eq!(BaseManifest::parse(&text).as_ref(), Ok(&s.manifest));
    s.remove();
}

#[test]
fn unborn_repo_has_no_parent() {
    let w = world();
    w.write("a.txt", b"a\n");
    let mut s = snapshot(&w.tools, &w.repo, &w.cache).unwrap();
    assert_eq!(s.manifest.base_commit, None);
    let c = snapshot_commit(&w.tools, &w.repo, &mut s).unwrap();
    let body = git(&w.repo, &["cat-file", "commit", &c]);
    assert!(!body.contains("\nparent "), "{body}");
    assert!(body.starts_with("tree "), "{body}");
    // Still unborn.
    let out = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(&w.repo)
        .args(["rev-parse", "--verify", "-q", "HEAD"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    s.remove();
}

#[test]
fn subdir_is_refused() {
    let w = world();
    w.write("sub/a.txt", b"a\n");
    let e = snapshot(&w.tools, &w.repo.join("sub"), &w.cache)
        .err()
        .unwrap();
    let top = w.repo.canonicalize().unwrap();
    assert!(e.contains(&top.display().to_string()), "{e}");
    assert!(e.contains("top"), "{e}");
    assert!(w.left().is_empty());
}

#[test]
fn base_ref_can_be_recreated() {
    let w = world();
    w.write("a.txt", b"a\n");
    let one = w.commit("one");
    w.write("a.txt", b"b\n");
    let two = w.commit("two");
    let id = BoxId::parse("b1").unwrap();
    set_base_ref(&w.tools, &w.repo, &id, &one).unwrap();
    let r = "refs/saiife/box-b1/base";
    assert_eq!(git(&w.repo, &["rev-parse", r]).trim(), one);
    // Again with the same commit (plan 39 recreating it): fine.
    set_base_ref(&w.tools, &w.repo, &id, &one).unwrap();
    // Pointing elsewhere: refused, and left alone.
    let e = set_base_ref(&w.tools, &w.repo, &id, &two).err().unwrap();
    assert!(e.contains(r), "{e}");
    assert_eq!(git(&w.repo, &["rev-parse", r]).trim(), one);
    // Not a commit id.
    assert!(set_base_ref(&w.tools, &w.repo, &id, "HEAD").is_err());
}

/// Set in the child run of `snapshot_commit_without_identity_is_saiife`.
const NO_IDENT_CHILD: &str = "SAIIFE_P37_NO_IDENT_CHILD";

/// R13: with no git identity (no user.email, no EMAIL, no GIT_* names,
/// HOME empty, no global or system config, auto-detection off) the snapshot
/// commit is still written, as `saiife <saiife@localhost>`. The work runs
/// in a child of this test binary, so the cleared environment is its own.
#[test]
fn snapshot_commit_without_identity_is_saiife() {
    if std::env::var_os(NO_IDENT_CHILD).is_none() {
        env();
        let d = tempfile::tempdir().unwrap();
        let home = d.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let mut c = Command::new(std::env::current_exe().unwrap());
        c.args([
            "--exact",
            "snapshot_commit_without_identity_is_saiife",
            "--test-threads=1",
        ])
        .env(NO_IDENT_CHILD, "1")
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &home)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        // Git's own auto-detection (user@host) off: no identity at all.
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "user.useConfigOnly")
        .env("GIT_CONFIG_VALUE_0", "true")
        .env("SAIIFE_TEST_REPO_MAX_FILES", TEST_MAX_FILES.to_string());
        for v in [
            "EMAIL",
            "GIT_AUTHOR_NAME",
            "GIT_AUTHOR_EMAIL",
            "GIT_COMMITTER_NAME",
            "GIT_COMMITTER_EMAIL",
        ] {
            c.env_remove(v);
        }
        let out = c.output().unwrap();
        assert!(
            out.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("1 passed"),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
        return;
    }
    let w = world();
    w.write("a.txt", b"a\n");
    let mut s = snapshot(&w.tools, &w.repo, &w.cache).unwrap();
    let c = snapshot_commit(&w.tools, &w.repo, &mut s).unwrap();
    let body = git(&w.repo, &["cat-file", "commit", &c]);
    assert!(
        body.contains("\nauthor saiife <saiife@localhost> "),
        "{body}"
    );
    assert!(
        body.contains("\ncommitter saiife <saiife@localhost> "),
        "{body}"
    );
    s.remove();
}

/// `Snapshot` is a plain value the caller removes.
#[allow(dead_code)]
fn _shape(s: Snapshot) -> (PathBuf, BaseManifest, Vec<String>, OsString) {
    (s.staging, s.manifest, s.warnings, OsString::new())
}
