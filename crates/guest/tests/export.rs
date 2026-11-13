//! The guest's export and advance (plan 39 Task 2) against real git, with a
//! tempdir root; every delta is read back through the host's validator.
#![cfg(target_os = "linux")]

use saiife_boxproto::delta::{BlobSink, EntryHead, Limits, Op, Reader, Valid};
use saiife_boxproto::frame::read_frame;
use saiife_boxproto::manifest::{BaseManifest, Entry, EntryKind};
use saiife_guest::export::{advance, export, export_within, init_base, BASE_GIT};
use saiife_guest::{GuestEnv, GuestTools, Timing};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The real git, found on PATH.
fn real_git() -> PathBuf {
    let path = std::env::var_os("PATH").expect("PATH");
    std::env::split_paths(&path)
        .map(|d| d.join("git"))
        .find(|p| p.is_file())
        .expect("git on PATH")
}

struct World {
    _dir: tempfile::TempDir,
    env: GuestEnv,
}

impl World {
    fn new() -> World {
        let dir = tempfile::Builder::new().prefix("p39t2").tempdir().unwrap();
        let root = dir.path().join("g");
        std::fs::create_dir_all(root.join("work")).unwrap();
        std::fs::create_dir_all(root.join("var/lib/saiife-guest")).unwrap();
        // The agent is this test's own user: the untracked listing runs as it.
        std::fs::create_dir_all(root.join("etc")).unwrap();
        let (uid, gid) = (
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw(),
        );
        std::fs::write(
            root.join("etc/passwd"),
            format!("root:x:0:0::/root:/bin/sh\nagent:x:{uid}:{gid}::/home/agent:/bin/sh\n"),
        )
        .unwrap();
        let none = PathBuf::from("/nonexistent");
        let env = GuestEnv {
            root,
            tools: GuestTools {
                setsid: none.clone(),
                runuser: none.clone(),
                systemctl: none.clone(),
                chown: none,
                git: real_git(),
            },
            version: "test-1".into(),
            timing: Timing::default(),
        };
        World { _dir: dir, env }
    }

    fn work(&self, rel: &str) -> PathBuf {
        self.env.path("/work").join(rel)
    }

    fn put(&self, rel: &str, bytes: &[u8]) {
        let p = self.work(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }

    fn chmod(&self, rel: &str, mode: u32) {
        std::fs::set_permissions(self.work(rel), std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn link(&self, rel: &str, target: &str) {
        let p = self.work(rel);
        let _ = std::fs::remove_file(&p);
        std::os::unix::fs::symlink(target, p).unwrap();
    }

    fn rm(&self, rel: &str) {
        std::fs::remove_file(self.work(rel)).unwrap();
    }

    fn base_dir(&self) -> PathBuf {
        self.env.path(BASE_GIT)
    }

    /// The test's own git, read-only on the base repo, isolated.
    fn git(&self, args: &[&str]) -> Vec<u8> {
        let home = self.env.root.join("home-t");
        std::fs::create_dir_all(&home).unwrap();
        let out = Command::new(&self.env.tools.git)
            .env_clear()
            .env("GIT_DIR", self.base_dir())
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", &home)
            .args(["-c", "core.hooksPath=/dev/null"])
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    }

    fn rev(&self, r: &str) -> String {
        String::from_utf8(self.git(&["rev-parse", r]))
            .unwrap()
            .trim()
            .to_string()
    }

    /// The base manifest of `refs/base`, as the host would hold it.
    fn manifest(&self) -> BaseManifest {
        let ls = self.git(&["ls-tree", "-r", "-z", "--full-tree", "refs/base"]);
        let mut entries = BTreeMap::new();
        for rec in ls.split(|&b| b == 0).filter(|r| !r.is_empty()) {
            let tab = rec.iter().position(|&b| b == b'\t').unwrap();
            let meta = String::from_utf8(rec[..tab].to_vec()).unwrap();
            let path = String::from_utf8(rec[tab + 1..].to_vec()).unwrap();
            let f: Vec<&str> = meta.split(' ').collect();
            let content = self.git(&["cat-file", "blob", f[2]]);
            let (kind, mode) = match f[0] {
                "100644" => (EntryKind::File, 0o644),
                "100755" => (EntryKind::File, 0o755),
                "120000" => (EntryKind::Symlink, 0),
                m => panic!("mode {m} in the base ({path})"),
            };
            entries.insert(
                path,
                Entry {
                    kind,
                    mode,
                    size: content.len() as u64,
                    sha256: sha(&content),
                },
            );
        }
        BaseManifest {
            version: 1,
            repo: "t".into(),
            base_commit: None,
            snapshot_commit: self.rev("refs/base"),
            files: entries.len() as u64,
            bytes: entries.values().map(|e| e.size).sum(),
            entries,
        }
    }

    /// Exports `n` and validates it against the base, as the host does.
    fn export(&self, n: u32) -> (Valid, HashMap<String, Vec<u8>>) {
        let m = self.manifest();
        let mut buf = Vec::new();
        export(&self.env, n, &mut buf).unwrap();
        let mut sink = Blobs::default();
        let valid = {
            let mut r = Reader::new(&m, Limits::default(), &mut sink);
            let mut src = &buf[..];
            while let Some(f) = read_frame(&mut src).unwrap() {
                r.push(f).unwrap();
            }
            r.finish().unwrap()
        };
        assert_eq!(valid.n, n);
        (valid, sink.done)
    }
}

fn sha(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

#[derive(Default)]
struct Blobs {
    cur: Vec<u8>,
    done: HashMap<String, Vec<u8>>,
}

impl BlobSink for Blobs {
    fn begin(&mut self) -> io::Result<()> {
        self.cur.clear();
        Ok(())
    }
    fn write(&mut self, b: &[u8]) -> io::Result<()> {
        self.cur.extend_from_slice(b);
        Ok(())
    }
    fn finish(&mut self, sha256: &str) -> io::Result<()> {
        self.done
            .insert(sha256.to_string(), std::mem::take(&mut self.cur));
        Ok(())
    }
}

fn paths(v: &Valid) -> Vec<(&str, Op)> {
    v.entries.iter().map(|e| (e.path.as_str(), e.op)).collect()
}

fn entry<'a>(v: &'a Valid, p: &str) -> &'a EntryHead {
    v.entries.iter().find(|e| e.path == p).unwrap()
}

/// The new content of `p` in the export.
fn content<'a>(v: &Valid, blobs: &'a HashMap<String, Vec<u8>>, p: &str) -> &'a [u8] {
    &blobs[&entry(v, p).sha256]
}

#[test]
fn init_base_commits_work() {
    let w = World::new();
    w.put("a.txt", b"one\n");
    w.put("dir/b.txt", b"two\n");
    w.put("ignored.log", b"tracked anyway\n");
    w.put(".gitignore", b"*.log\n");
    init_base(&w.env).unwrap();
    let m = w.manifest();
    let keys: Vec<&str> = m.entries.keys().map(String::as_str).collect();
    assert_eq!(keys, [".gitignore", "a.txt", "dir/b.txt", "ignored.log"]);
    assert_eq!(m.entries["a.txt"].sha256, sha(b"one\n"));
    let attrs = std::fs::read_to_string(w.base_dir().join("info/attributes")).unwrap();
    assert_eq!(
        attrs,
        "* -text -filter -ident -eol -diff -merge -working-tree-encoding\n"
    );
    assert_eq!(
        std::fs::read_to_string(w.base_dir().join("info/exclude")).unwrap(),
        ".git\n"
    );
    // No template hooks.
    assert!(!w.base_dir().join("hooks").exists());
    // Nothing changed yet: an empty delta.
    let (v, _) = w.export(1);
    assert!(v.entries.is_empty());
}

#[test]
fn export_lists_add_modify_delete() {
    let w = World::new();
    w.put("a", b"a\n");
    w.put("b", b"b\n");
    w.put("c/c", b"c\n");
    init_base(&w.env).unwrap();
    w.put("b", b"b2\n");
    w.rm("c/c");
    w.put("d/e", b"new\n");
    let (v, blobs) = w.export(1);
    assert_eq!(
        paths(&v),
        [("b", Op::Modify), ("c/c", Op::Delete), ("d/e", Op::Add)]
    );
    assert_eq!(content(&v, &blobs, "b"), b"b2\n");
    assert_eq!(content(&v, &blobs, "d/e"), b"new\n");
    let d = entry(&v, "c/c");
    assert_eq!((d.mode, d.size, d.sha256.as_str()), (0, 0, ""));
    assert_eq!(d.old_sha256.as_deref(), Some(sha(b"c\n").as_str()));
    assert_eq!(w.rev("refs/exports/1").len(), 40);
}

#[test]
fn export_sorts_by_path_bytes() {
    let w = World::new();
    w.put("keep", b"k\n");
    init_base(&w.env).unwrap();
    // Names around `/` (0x2f): the delta is sorted by path bytes, whatever
    // order git lists them in.
    for p in ["a0", "a/x", "a.c", "a-b", "a b"] {
        w.put(p, b"x");
    }
    let (v, _) = w.export(1);
    let got: Vec<&str> = v.entries.iter().map(|e| e.path.as_str()).collect();
    let mut want = got.clone();
    want.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    assert_eq!(got, want);
    assert_eq!(got.len(), 5);
}

#[test]
fn export_includes_untracked_and_skips_ignored() {
    let w = World::new();
    w.put(".gitignore", b"*.log\nbuild/\n");
    w.put("kept.log", b"was in the base\n");
    init_base(&w.env).unwrap();
    w.put("new.txt", b"untracked\n");
    w.put("debug.log", b"ignored\n");
    w.put("build/out.bin", b"ignored\n");
    w.put("kept.log", b"changed\n");
    let (v, blobs) = w.export(1);
    assert_eq!(paths(&v), [("kept.log", Op::Modify), ("new.txt", Op::Add)]);
    assert_eq!(content(&v, &blobs, "new.txt"), b"untracked\n");
}

#[test]
fn export_skips_nested_dot_git() {
    let w = World::new();
    w.put("top", b"t\n");
    w.put("known/f", b"tracked by the base\n");
    init_base(&w.env).unwrap();
    let home = w.env.root.join("home-agent");
    std::fs::create_dir_all(&home).unwrap();
    let agent_init = |dir: &str| {
        let st = Command::new(&w.env.tools.git)
            .env_clear()
            .env("HOME", &home)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .args(["init", "-q"])
            .current_dir(w.work(dir))
            .status()
            .unwrap();
        assert!(st.success());
        assert!(w.work(&format!("{dir}/.git/HEAD")).is_file());
    };
    // The agent makes a repository inside /work/sub (no commit in it), and
    // one over files the base tracks.
    w.put("sub/f", b"in a nested repo\n");
    agent_init("sub");
    agent_init("known");
    w.put("known/f", b"edited\n");
    w.put("known/new", b"untracked in a nested repo\n");
    // A stray .git file, NTFS aliases of .git, and an ordinary sibling.
    w.put("other/.git", b"gitdir: /elsewhere\n");
    w.put("other/kept", b"k\n");
    w.put("plain/kept", b"k\n");
    w.put("x/.GIT/config", b"[core]\n");
    w.put("y/git~1/hooks/pre-commit", b"#!/bin/sh\n");
    w.put("z/.git. /a", b"a\n");
    let (v, _) = w.export(1);
    // `other` holds a `.git` file pointing nowhere valid (git would take it
    // for a plain directory): any `.git` entry makes a nested repository,
    // so it is skipped too. In `known` the tracked file stays tracked; its
    // untracked one is skipped. `plain` (no `.git`) is exported.
    assert_eq!(
        paths(&v),
        [("known/f", Op::Modify), ("plain/kept", Op::Add)]
    );
    assert!(v.entries.iter().all(|e| !e.path.contains(".git")));
    // The base never learns the nested repo either.
    advance(&w.env, 1, None).unwrap();
    let ls = String::from_utf8(w.git(&["ls-tree", "-r", "--name-only", "refs/base"])).unwrap();
    assert_eq!(ls, "known/f\nplain/kept\ntop\n");
}

#[test]
fn export_symlink_and_mode_change() {
    let w = World::new();
    w.put("run.sh", b"#!/bin/sh\n");
    w.chmod("run.sh", 0o644);
    w.put("t1", b"1");
    w.put("t2", b"2");
    w.link("l", "t1");
    w.put("f", b"becomes a link\n");
    init_base(&w.env).unwrap();
    w.chmod("run.sh", 0o755);
    w.link("l", "t2");
    w.link("new", "t1");
    w.rm("f");
    w.link("f", "t2");
    let (v, blobs) = w.export(1);
    assert_eq!(
        paths(&v),
        [
            ("f", Op::Modify),
            ("l", Op::Modify),
            ("new", Op::Add),
            ("run.sh", Op::Modify)
        ]
    );
    let r = entry(&v, "run.sh");
    assert_eq!((r.mode, r.kind.clone()), (0o755, EntryKind::File));
    assert_eq!(r.sha256, r.old_sha256.clone().unwrap());
    let l = entry(&v, "l");
    assert_eq!((l.kind.clone(), l.mode, l.size), (EntryKind::Symlink, 0, 2));
    assert_eq!(content(&v, &blobs, "l"), b"t2");
    assert_eq!(content(&v, &blobs, "new"), b"t1");
    let f = entry(&v, "f");
    assert_eq!(
        (f.kind.clone(), f.old_kind.clone()),
        (EntryKind::Symlink, Some(EntryKind::File))
    );
}

/// Deterministic noise with NULs, CRs and LFs.
fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed;
    (0..n)
        .map(|i| {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            match i % 97 {
                0 => 0,
                1 => b'\r',
                2 => b'\n',
                _ => (x >> 33) as u8,
            }
        })
        .collect()
}

#[test]
fn export_is_binary_safe() {
    let w = World::new();
    let old = noise(300_000, 1);
    w.put("blob.bin", &old);
    w.put("text.txt", b"a\r\nb\r\n");
    init_base(&w.env).unwrap();
    // Over one frame (1 MiB), with NULs: split into several Bytes frames.
    let new = noise(2_500_000, 2);
    w.put("blob.bin", &new);
    w.put("empty", b"");
    w.put("nul.txt", b"x\0y\r\n\r\n");
    let (v, blobs) = w.export(1);
    assert_eq!(content(&v, &blobs, "blob.bin"), &new[..]);
    assert_eq!(entry(&v, "blob.bin").old_size, Some(old.len() as u64));
    assert_eq!(content(&v, &blobs, "empty"), b"");
    assert_eq!(content(&v, &blobs, "nul.txt"), b"x\0y\r\n\r\n");
}

#[test]
fn export_ignores_work_gitattributes() {
    let w = World::new();
    w.put("keep", b"k\n");
    init_base(&w.env).unwrap();
    // R-T2a: /work's attributes must not change the stored bytes.
    w.put(
        ".gitattributes",
        b"* text eol=crlf\n*.txt filter=evil ident\n*.enc working-tree-encoding=UTF-16\n",
    );
    w.put("lf.txt", b"one\ntwo\n$Id$\n");
    w.put("crlf.dat", b"one\r\ntwo\r\n");
    w.put("u.enc", b"\xff\xfeh\0i\0");
    let (v, blobs) = w.export(1);
    assert_eq!(content(&v, &blobs, "lf.txt"), b"one\ntwo\n$Id$\n");
    assert_eq!(content(&v, &blobs, "crlf.dat"), b"one\r\ntwo\r\n");
    assert_eq!(content(&v, &blobs, "u.enc"), b"\xff\xfeh\0i\0");
}

#[test]
fn advance_all_then_empty_export() {
    let w = World::new();
    w.put("a", b"a\n");
    init_base(&w.env).unwrap();
    w.put("a", b"a2\n");
    w.put("b", b"b\n");
    let (v, _) = w.export(1);
    assert_eq!(v.entries.len(), 2);
    advance(&w.env, 1, None).unwrap();
    assert_eq!(w.rev("refs/base"), w.rev("refs/exports/1"));
    let (v, _) = w.export(2);
    assert!(v.entries.is_empty(), "{:?}", v.entries);
}

#[test]
fn advance_some_paths_keeps_the_rest() {
    let w = World::new();
    w.put("a", b"a\n");
    w.put("b", b"b\n");
    w.put("gone", b"g\n");
    w.put("dir", b"file then dir\n");
    init_base(&w.env).unwrap();
    w.put("a", b"a2\n");
    w.put("b", b"b2\n");
    w.rm("gone");
    w.rm("dir");
    w.put("dir/x", b"x\n");
    let (v, _) = w.export(1);
    assert_eq!(v.entries.len(), 5);
    let only: Vec<String> = ["a", "gone", "dir", "dir/x"].map(String::from).to_vec();
    advance(&w.env, 1, Some(&only)).unwrap();
    let ls = String::from_utf8(w.git(&["ls-tree", "-r", "--name-only", "refs/base"])).unwrap();
    assert_eq!(ls, "a\nb\ndir/x\n");
    // Only b is left, as its base side was kept.
    let (v, blobs) = w.export(2);
    assert_eq!(paths(&v), [("b", Op::Modify)]);
    assert_eq!(content(&v, &blobs, "b"), b"b2\n");
    assert_eq!(
        entry(&v, "b").old_sha256.as_deref(),
        Some(sha(b"b\n").as_str())
    );
    // An unknown export is refused; the base stays.
    let base = w.rev("refs/base");
    assert!(advance(&w.env, 9, None).is_err());
    assert!(advance(&w.env, 2, Some(&["../x".to_string()])).is_err());
    assert_eq!(w.rev("refs/base"), base);
}

#[test]
fn export_refuses_over_caps() {
    let w = World::new();
    w.put("a", b"a\n");
    init_base(&w.env).unwrap();
    w.put("b", b"1234");
    w.put("c", b"5678");
    let run = |limits: Limits| {
        let mut buf = Vec::new();
        let r = export_within(&w.env, 1, limits, &mut buf);
        assert!(buf.is_empty(), "nothing is written past a cap");
        r.unwrap_err()
    };
    let d = Limits::default();
    let e = run(Limits { entries: 1, ..d });
    assert!(e.contains("2 changed paths"), "{e}");
    let e = run(Limits { file_bytes: 3, ..d });
    assert!(e.contains("over the export's limit"), "{e}");
    let e = run(Limits {
        total_bytes: 7,
        ..d
    });
    assert!(e.contains("limit of 7"), "{e}");
    // Within the caps it goes through.
    let mut buf = Vec::new();
    export_within(
        &w.env,
        1,
        Limits {
            entries: 2,
            file_bytes: 4,
            total_bytes: 8,
        },
        &mut buf,
    )
    .unwrap();
    assert!(!buf.is_empty());
}

#[test]
fn no_hook_runs() {
    let w = World::new();
    w.put("a", b"a\n");
    let marker = w.env.root.join("hook-ran");
    let hook = format!("#!/bin/sh\necho \"$0\" >> '{}'\n", marker.display());
    let plant = |dir: &Path| {
        std::fs::create_dir_all(dir).unwrap();
        for name in [
            "pre-commit",
            "post-commit",
            "post-index-change",
            "reference-transaction",
            "post-checkout",
            "pre-auto-gc",
            "fsmonitor-watchman",
        ] {
            let p = dir.join(name);
            std::fs::write(&p, &hook).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    };
    // Hooks where /work could put them, before the base exists...
    plant(&w.work(".git/hooks"));
    plant(&w.work(".githooks"));
    w.put(
        ".git/config",
        b"[core]\n\thooksPath = .githooks\n\tfsmonitor = true\n",
    );
    init_base(&w.env).unwrap();
    // ...and in the base itself.
    plant(&w.base_dir().join("hooks"));
    w.put("a", b"a2\n");
    w.put("b", b"b\n");
    let (v, _) = w.export(1);
    assert_eq!(paths(&v), [("a", Op::Modify), ("b", Op::Add)]);
    advance(&w.env, 1, Some(&["a".to_string()])).unwrap();
    advance(&w.env, 1, None).unwrap();
    assert!(
        !marker.exists(),
        "a hook ran: {:?}",
        std::fs::read_to_string(&marker)
    );
}

// R-T2d: root reads /work without following anything the agent planted.

const SECRET: &[u8] = b"p39-root-only-secret-bytes";

fn has_secret(buf: &[u8]) -> bool {
    buf.windows(SECRET.len()).any(|w| w == SECRET)
}

impl World {
    /// A directory outside /work holding the secret as `a.txt`.
    fn outside(&self) -> PathBuf {
        let d = self._dir.path().join("outside");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("a.txt"), SECRET).unwrap();
        d
    }

    /// The raw export and the entry headers in it.
    fn export_raw(&self, n: u32) -> (Vec<u8>, Vec<serde_json::Value>) {
        let mut buf = Vec::new();
        export(&self.env, n, &mut buf).unwrap();
        let mut heads = Vec::new();
        let mut src = &buf[..];
        while let Some(f) = read_frame(&mut src).unwrap() {
            if let saiife_boxproto::frame::Frame::Json(v) = f {
                if v["t"] == "entry" {
                    heads.push(v);
                }
            }
        }
        (buf, heads)
    }

    /// The host validator's verdict on a raw export against the base.
    fn validate(&self, buf: &[u8]) -> Result<Valid, saiife_boxproto::delta::DeltaError> {
        let m = self.manifest();
        let mut sink = Blobs::default();
        let mut r = Reader::new(&m, Limits::default(), &mut sink);
        let mut src = buf;
        while let Some(f) = read_frame(&mut src).unwrap() {
            r.push(f)?;
        }
        r.finish()
    }
}

fn head_of<'a>(heads: &'a [serde_json::Value], p: &str) -> &'a serde_json::Value {
    heads.iter().find(|h| h["path"] == p).unwrap()
}

#[test]
fn symlink_to_outside_file_is_not_followed() {
    let w = World::new();
    w.put("keep", b"k\n");
    init_base(&w.env).unwrap();
    let target = w.outside().join("a.txt");
    w.link("leak", target.to_str().unwrap());
    let (buf, heads) = w.export_raw(1);
    assert!(!has_secret(&buf), "the secret was read");
    let h = head_of(&heads, "leak");
    assert_eq!(
        (h["op"].as_str(), h["kind"].as_str()),
        (Some("add"), Some("symlink"))
    );
    assert_eq!(h["size"], target.as_os_str().len() as u64);
    // The host refuses the escaping link.
    let e = w.validate(&buf).unwrap_err();
    assert_eq!(e.path.as_deref(), Some("leak"), "{e}");
}

#[test]
fn hard_link_to_outside_file_is_refused() {
    let w = World::new();
    w.put("keep", b"k\n");
    init_base(&w.env).unwrap();
    let target = w.outside().join("a.txt");
    std::fs::hard_link(&target, w.work("hl")).unwrap();
    let mut buf = Vec::new();
    let e = export(&w.env, 1, &mut buf).unwrap_err();
    assert!(e.contains("\"hl\"") && e.contains("hard link"), "{e}");
    assert!(buf.is_empty() && !has_secret(&buf));
    // A tracked file hard-linked later is refused the same way.
    std::fs::remove_file(w.work("hl")).unwrap();
    std::fs::hard_link(w.work("keep"), w._dir.path().join("keep-twin")).unwrap();
    let e = export(&w.env, 2, &mut buf).unwrap_err();
    assert!(e.contains("\"keep\""), "{e}");
    // Escaped in the message: no raw control char reaches the host.
    std::fs::remove_file(w._dir.path().join("keep-twin")).unwrap();
    std::fs::hard_link(&target, w.work("x\u{1b}[2J\u{202e}")).unwrap();
    let e = export(&w.env, 3, &mut buf).unwrap_err();
    assert!(!e.contains('\u{1b}') && !e.contains('\u{202e}'), "{e:?}");
    assert!(e.contains("\\u{202e}"), "{e:?}");
}

#[test]
fn dir_swapped_for_symlink_is_not_followed() {
    let w = World::new();
    w.put("d/a.txt", b"mine\n");
    init_base(&w.env).unwrap();
    let out = w.outside();
    std::fs::remove_dir_all(w.work("d")).unwrap();
    std::os::unix::fs::symlink(&out, w.work("d")).unwrap();
    let (buf, heads) = w.export_raw(1);
    assert!(!has_secret(&buf), "a file below the swapped dir was read");
    let got: Vec<(&str, &str, &str)> = heads
        .iter()
        .map(|h| {
            (
                h["path"].as_str().unwrap(),
                h["op"].as_str().unwrap(),
                h["kind"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        got,
        [("d", "add", "symlink"), ("d/a.txt", "delete", "file")]
    );
    // The host refuses the absolute link.
    let e = w.validate(&buf).unwrap_err();
    assert_eq!(e.path.as_deref(), Some("d"), "{e}");
}

#[test]
fn advance_some_paths_refuses_file_dir_conflict() {
    let w = World::new();
    w.put("dir", b"a file in the base\n");
    w.put("a/x", b"a file below a\n");
    init_base(&w.env).unwrap();
    // The export turns the file `dir` into a directory and the directory
    // `a` into a file.
    w.rm("dir");
    w.put("dir/x", b"x\n");
    std::fs::remove_dir_all(w.work("a")).unwrap();
    w.put("a", b"now a file\n");
    let (v, _) = w.export(1);
    assert_eq!(v.entries.len(), 4);
    let base = w.rev("refs/base");
    let only = |ps: &[&str]| ps.iter().map(|p| p.to_string()).collect::<Vec<_>>();
    // A new path below a base file that is kept.
    let e = advance(&w.env, 1, Some(&only(&["dir/x"]))).unwrap_err();
    assert!(e.contains("both a file and a directory"), "{e}");
    // A new file over a base directory whose files are kept.
    let e = advance(&w.env, 1, Some(&only(&["a"]))).unwrap_err();
    assert!(e.contains("both a file and a directory"), "{e}");
    assert_eq!(w.rev("refs/base"), base, "a refusal changes nothing");
    // With the deletes selected too, both go through.
    advance(&w.env, 1, Some(&only(&["dir", "dir/x", "a/x", "a"]))).unwrap();
    let ls = String::from_utf8(w.git(&["ls-tree", "-r", "--name-only", "refs/base"])).unwrap();
    assert_eq!(ls, "a\ndir/x\n");
}

#[test]
fn advance_some_paths_refuses_a_path_not_in_the_export() {
    let w = World::new();
    w.put("a", b"a\n");
    w.put("same", b"unchanged\n");
    init_base(&w.env).unwrap();
    w.put("a", b"a2\n");
    let (v, _) = w.export(1);
    assert_eq!(paths(&v), [("a", Op::Modify)]);
    let base = w.rev("refs/base");
    for p in ["nope", "same"] {
        let e = advance(&w.env, 1, Some(&[p.to_string()])).unwrap_err();
        assert!(e.contains("is not a change of export 1"), "{e}");
    }
    // One bad path refuses the whole list.
    assert!(advance(&w.env, 1, Some(&["a".to_string(), "nope".to_string()])).is_err());
    assert_eq!(w.rev("refs/base"), base);
}

/// I-2: an agent-made FIFO named `.gitignore` blocks git's open of it; the
/// export's deadline kills that git, the export fails saying so, and the
/// next export (FIFO gone) works.
#[test]
fn fifo_gitignore_does_not_wedge_export() {
    let mut w = World::new();
    w.env.timing.export_deadline = std::time::Duration::from_secs(2);
    w.put("keep", b"k\n");
    init_base(&w.env).unwrap();
    w.put("sub/f", b"new\n");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        w.work("sub/.gitignore"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o644),
        0,
    )
    .unwrap();
    let t = std::time::Instant::now();
    let mut buf = Vec::new();
    let e = export(&w.env, 1, &mut buf).unwrap_err();
    assert!(
        t.elapsed() < std::time::Duration::from_secs(30),
        "{:?}",
        t.elapsed()
    );
    assert!(e.contains("took longer than 2 s"), "{e}");
    assert!(buf.is_empty());
    std::fs::remove_file(w.work("sub/.gitignore")).unwrap();
    let (v, _) = w.export(2);
    assert_eq!(paths(&v), [("sub/f", Op::Add)]);
}

/// I-2: a `.gitignore` hard-linked to a file outside `/work` is refused,
/// naming it; and one the agent cannot read is not read for it (the
/// listing runs with the agent's rights), so its patterns, which would hide
/// the ignore file itself, do not apply and the export still refuses it.
#[test]
fn hardlinked_gitignore_is_refused() {
    if rustix::process::getuid().is_root() {
        // Root reads a 0o000 file anyway; the test needs an unprivileged agent.
        return;
    }
    let w = World::new();
    w.put("keep", b"k\n");
    init_base(&w.env).unwrap();
    let d = w._dir.path().join("outside");
    std::fs::create_dir_all(&d).unwrap();
    let rules = d.join("rules");
    std::fs::write(&rules, b"hidden.txt\n").unwrap();
    std::fs::hard_link(&rules, w.work(".gitignore")).unwrap();
    w.put("hidden.txt", b"listed only when the rules were not read\n");
    let mut buf = Vec::new();
    let e = export(&w.env, 1, &mut buf).unwrap_err();
    assert!(
        e.contains("\".gitignore\"") && e.contains("hard link"),
        "{e}"
    );
    assert!(buf.is_empty());
    // A root-only file: its rules would hide `.gitignore` itself; unread,
    // they do not, and the export refuses the file it cannot read.
    std::fs::write(&rules, b"/.gitignore\nhidden.txt\n").unwrap();
    std::fs::set_permissions(&rules, std::fs::Permissions::from_mode(0o000)).unwrap();
    let e = export(&w.env, 2, &mut buf).unwrap_err();
    assert!(e.starts_with("\".gitignore\""), "{e}");
    assert!(buf.is_empty());
    // Gone, the export lists what the unreadable rules would have hidden.
    std::fs::remove_file(w.work(".gitignore")).unwrap();
    let (v, _) = w.export(3);
    assert_eq!(paths(&v), [("hidden.txt", Op::Add)]);
}

/// I-2: the untracked listing switches to the agent's uid; an unprivileged
/// test cannot switch to another one, so the export fails at that git.
#[test]
fn untracked_listing_runs_as_the_agent() {
    if rustix::process::getuid().is_root() {
        return;
    }
    let w = World::new();
    w.put("keep", b"k\n");
    init_base(&w.env).unwrap();
    let uid = rustix::process::getuid().as_raw() + 1;
    let gid = rustix::process::getgid().as_raw();
    std::fs::write(
        w.env.path("/etc/passwd"),
        format!("agent:x:{uid}:{gid}::/home/agent:/bin/sh\n"),
    )
    .unwrap();
    let mut buf = Vec::new();
    let e = export(&w.env, 1, &mut buf).unwrap_err();
    assert!(e.starts_with("git ls-files"), "{e}");
    // The listing repository is world-readable and holds only the exclude.
    let list = w.env.path(saiife_guest::export::LIST_GIT);
    let mode = std::fs::metadata(&list).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o755);
    assert_eq!(
        std::fs::read_to_string(list.join("info/exclude")).unwrap(),
        ".git\n"
    );
}
