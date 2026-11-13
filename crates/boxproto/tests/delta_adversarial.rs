//! Plan 39 Task 1: the delta validator treats the guest as hostile.

use saiife_boxproto::delta::{
    apply_manifest, fold_path, is_git_alias, normalize_component, write_delta, BlobSink,
    DeltaError, DeltaItem, EntryHead, Limits, Op, Reader, Valid, BASE_MISMATCH, MAX_DEPTH,
    MAX_ENTRIES, MAX_FILE_BYTES, MAX_HEAD_BYTES, MAX_TOTAL_BYTES,
};
use saiife_boxproto::frame::{read_frame, Frame};
use saiife_boxproto::manifest::{BaseManifest, Entry, EntryKind};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Cursor};

fn sha(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The fixture's ten paths: (path, kind, mode, content).
const FIXTURE: &[(&str, EntryKind, u32, &[u8])] = &[
    ("README.md", EntryKind::File, 0o644, b"hello\n"),
    ("docs/a", EntryKind::File, 0o644, b"doc a\n"),
    ("docs/b", EntryKind::File, 0o644, b"doc b\n"),
    ("ln", EntryKind::Symlink, 0, b"docs"),
    ("run.sh", EntryKind::File, 0o755, b"#!/bin/sh\n"),
    ("src/lib.rs", EntryKind::File, 0o644, b"pub fn f() {}\n"),
    ("src/main.rs", EntryKind::File, 0o644, b"fn main() {}\n"),
    ("src/util/mod.rs", EntryKind::File, 0o644, b"// util\n"),
    ("tests/t.rs", EntryKind::File, 0o644, b"#[test] fn t() {}\n"),
    ("z.txt", EntryKind::File, 0o644, b"zzz\n"),
];

fn base() -> BaseManifest {
    let mut entries = BTreeMap::new();
    for (p, kind, mode, content) in FIXTURE {
        entries.insert(
            p.to_string(),
            Entry {
                kind: kind.clone(),
                mode: *mode,
                size: content.len() as u64,
                sha256: sha(content),
            },
        );
    }
    let bytes = entries.values().map(|e| e.size).sum();
    let m = BaseManifest {
        version: 1,
        repo: "demo".into(),
        base_commit: Some("c".repeat(40)),
        snapshot_commit: "d".repeat(40),
        files: entries.len() as u64,
        bytes,
        entries,
    };
    // The fixture itself is a valid manifest.
    BaseManifest::parse(&serde_json::to_string(&m).unwrap()).unwrap()
}

fn old_of(p: &str) -> &'static [u8] {
    FIXTURE.iter().find(|f| f.0 == p).unwrap().3
}

#[derive(Default)]
struct Sink {
    blobs: BTreeMap<String, Vec<u8>>,
    cur: Option<Vec<u8>>,
}

impl BlobSink for Sink {
    fn begin(&mut self) -> io::Result<()> {
        assert!(self.cur.is_none(), "begin while a blob is open");
        self.cur = Some(Vec::new());
        Ok(())
    }
    fn write(&mut self, b: &[u8]) -> io::Result<()> {
        self.cur
            .as_mut()
            .expect("write before begin")
            .extend_from_slice(b);
        Ok(())
    }
    fn finish(&mut self, sha256: &str) -> io::Result<()> {
        let b = self.cur.take().expect("finish before begin");
        assert_eq!(sha(&b), sha256, "finish called with an unverified hash");
        self.blobs.insert(sha256.to_string(), b);
        Ok(())
    }
}

type Item = (EntryHead, Option<Vec<u8>>, Option<Vec<u8>>);

fn head(p: &str, op: Op, kind: EntryKind, mode: u32, content: &[u8]) -> EntryHead {
    EntryHead {
        path: p.into(),
        op,
        kind,
        mode,
        size: content.len() as u64,
        sha256: sha(content),
        old_kind: None,
        old_size: None,
        old_sha256: None,
    }
}

fn add(p: &str, content: &[u8]) -> Item {
    (
        head(p, Op::Add, EntryKind::File, 0o644, content),
        None,
        Some(content.to_vec()),
    )
}

fn add_link(p: &str, target: &str) -> Item {
    (
        head(p, Op::Add, EntryKind::Symlink, 0, target.as_bytes()),
        None,
        Some(target.as_bytes().to_vec()),
    )
}

fn with_old(mut h: EntryHead, p: &str) -> EntryHead {
    let e = &base().entries[p];
    h.old_kind = Some(e.kind.clone());
    h.old_size = Some(e.size);
    h.old_sha256 = Some(e.sha256.clone());
    h
}

fn modify(p: &str, content: &[u8]) -> Item {
    let h = with_old(head(p, Op::Modify, EntryKind::File, 0o644, content), p);
    (h, Some(old_of(p).to_vec()), Some(content.to_vec()))
}

fn delete(p: &str) -> Item {
    let kind = base().entries[p].kind.clone();
    let mut h = with_old(head(p, Op::Delete, kind, 0, b""), p);
    h.sha256 = String::new();
    (h, None, None)
}

fn encode(items: &[Item]) -> Vec<u8> {
    let refs: Vec<DeltaItem> = items
        .iter()
        .map(|(h, o, n)| (h.clone(), o.as_deref(), n.as_deref()))
        .collect();
    let mut buf = Vec::new();
    write_delta(&mut buf, 7, &refs).unwrap();
    buf
}

fn frames(buf: &[u8]) -> Vec<Frame> {
    let mut r = Cursor::new(buf);
    let mut out = Vec::new();
    while let Some(f) = read_frame(&mut r).unwrap() {
        out.push(f);
    }
    out
}

/// Feeds frames to a reader (with the fixture base, or `paths_only`) and
/// finishes it.
fn feed(
    with_base: bool,
    limits: Limits,
    fs: Vec<Frame>,
    sink: &mut Sink,
) -> Result<Valid, DeltaError> {
    let b = base();
    let mut r = if with_base {
        Reader::new(&b, limits, sink)
    } else {
        Reader::paths_only(limits, sink)
    };
    for f in fs {
        r.push(f)?;
    }
    r.finish()
}

fn run(items: &[Item]) -> Result<Valid, DeltaError> {
    feed(
        true,
        Limits::default(),
        frames(&encode(items)),
        &mut Sink::default(),
    )
}

fn refused(items: &[Item]) -> DeltaError {
    run(items).expect_err("the delta was accepted")
}

fn assert_refused(items: &[Item], path: &str, needle: &str) {
    let e = refused(items);
    assert_eq!(e.path.as_deref(), Some(path), "{e}");
    assert!(e.reason.contains(needle), "{e:?} lacks {needle:?}");
}

#[test]
fn default_limits_are_the_plan_caps() {
    let l = Limits::default();
    assert_eq!(l.entries, 20_000);
    assert_eq!(l.file_bytes, 64 << 20);
    assert_eq!(l.total_bytes, 512 << 20);
    assert_eq!(
        (MAX_ENTRIES, MAX_FILE_BYTES, MAX_TOTAL_BYTES),
        (20_000, 64 << 20, 512 << 20)
    );
    assert_eq!(MAX_DEPTH, 64);
}

#[test]
fn traversal_is_refused() {
    for p in ["../x", "a/../b", "docs/..", "./a"] {
        assert_refused(&[add(p, b"x")], p, ". or ..");
    }
}

#[test]
fn absolute_is_refused() {
    assert_refused(&[add("/etc/passwd", b"x")], "/etc/passwd", "absolute");
}

#[test]
fn dot_git_any_case_any_depth() {
    for p in [
        ".git/config",
        ".GIT/HEAD",
        "x/.GiT/hooks/pre-commit",
        "a/b/.Git",
        "src/.git",
    ] {
        assert_refused(&[add(p, b"x")], p, ".git");
    }
    // A delete or modify of a .git path is refused the same way (never flagged).
    let mut d = delete("z.txt");
    d.0.path = ".git/index".into();
    assert_refused(&[d], ".git/index", ".git");
    // A look-alike is fine.
    run(&[add(".gitignore", b"x"), add("a.git/b", b"y")]).unwrap();
}

#[test]
fn symlink_escape_is_refused() {
    for (p, t, needle) in [
        ("esc", "../out", "leaves the repo"),
        ("docs/e", "../../x", "leaves the repo"),
        ("abs", "/etc", "absolute"),
        ("back", "docs/../..", ".. after a name"),
        ("updown", "docs/../README.md", ".. after a name"),
        ("gitlink", ".git/config", ".git"),
        ("gitlink2", "docs/.GIT", ".git"),
        ("gitlink3", "docs/.git./x", ".git"),
        ("gitlink4", "GIT~1/config", ".git"),
        ("bs", "..\\x", "backslash"),
    ] {
        let mut sink = Sink::default();
        let e = feed(
            true,
            Limits::default(),
            frames(&encode(&[add_link(p, t)])),
            &mut sink,
        )
        .unwrap_err();
        assert_eq!(e.path.as_deref(), Some(p), "{e}");
        assert!(e.reason.contains(needle), "{e:?} lacks {needle:?}");
        // The hash passed but the target did not: nothing was finished.
        assert!(
            sink.blobs.is_empty(),
            "{p}: a refused link reached the sink"
        );
    }
    // An empty target and a NUL.
    assert_refused(&[add_link("empty", "")], "empty", "empty");
    assert_refused(&[add_link("nul", "a\0b")], "nul", "NUL");
}

#[test]
fn symlink_inside_is_ok() {
    let v = run(&[add_link("ln2", "docs/a")]).unwrap();
    assert_eq!(v.entries.len(), 1);
    run(&[add_link("docs/up", "../README.md")]).unwrap();
    run(&[add_link("src/util/up", "../../docs/./a")]).unwrap();
    run(&[add_link("root", ".")]).unwrap();
}

#[test]
fn write_through_symlink_in_delta() {
    let e = refused(&[add_link("l2", "docs"), add("l2/x", b"x")]);
    assert_eq!(e.path.as_deref(), Some("l2/x"));
    assert!(e.reason.contains("symlink in the delta"), "{e:?}");
}

#[test]
fn write_through_symlink_in_base() {
    assert_refused(&[add("ln/x", b"x")], "ln/x", "symlink in the base");
    // Even when the link is deleted in the same delta.
    let e = refused(&[delete("ln"), add("ln/x", b"x")]);
    assert!(e.reason.contains("symlink"), "{e:?}");
}

#[test]
fn file_dir_conflict() {
    // A base file becomes a directory.
    assert_refused(
        &[add("z.txt/inner", b"x")],
        "z.txt/inner",
        "both a file and a directory",
    );
    // A base directory becomes a file.
    assert_refused(&[add("src", b"x")], "src", "both a file and a directory");
    // Within the delta.
    let e = refused(&[add("q", b"x"), add("q/r", b"y")]);
    assert!(e.reason.contains("both a file and a directory"), "{e:?}");
    // Deleting everything under a directory frees the name.
    // ("docs" sorts before "docs/a", so this order is unsorted.)
    let e = refused(&[
        delete("docs/a"),
        delete("docs/b"),
        add("docs", b"now a file"),
    ]);
    assert!(e.reason.contains("not sorted"), "{e:?}");
    let v = run(&[
        add("docs", b"now a file"),
        delete("docs/a"),
        delete("docs/b"),
    ])
    .unwrap();
    assert_eq!(v.entries.len(), 3);
    // Deleting a file frees the name for a directory.
    run(&[delete("z.txt"), add("z.txt/inner", b"x")])
        .map(|_| ())
        .unwrap();
}

#[test]
fn duplicate_path() {
    assert_refused(&[add("new", b"a"), add("new", b"b")], "new", "duplicate");
}

#[test]
fn unsorted_entries() {
    assert_refused(&[add("b", b"a"), add("a", b"b")], "a", "not sorted");
    // Byte order, not char order: "Z" (0x5a) sorts before "a".
    run(&[add("Z", b"1"), add("a", b"2")]).unwrap();
}

#[test]
fn old_hash_must_match_manifest() {
    // The declared old hash differs from the manifest.
    let mut m = modify("README.md", b"new\n");
    m.0.old_sha256 = Some(sha(b"something else"));
    assert_refused(&[m], "README.md", BASE_MISMATCH);
    // Declared old size or kind differs.
    let mut m = modify("README.md", b"new\n");
    m.0.old_size = Some(1);
    assert_refused(&[m], "README.md", BASE_MISMATCH);
    let mut m = modify("README.md", b"new\n");
    m.0.old_kind = Some(EntryKind::Symlink);
    assert_refused(&[m], "README.md", BASE_MISMATCH);
    // Declared right, but the old bytes sent are not the base's.
    let mut m = modify("README.md", b"new\n");
    m.1 = Some(b"HELLO\n".to_vec());
    assert_refused(&[m], "README.md", BASE_MISMATCH);
    // A delete with a stale old hash.
    let mut d = delete("z.txt");
    d.0.old_sha256 = Some(sha(b"stale"));
    assert_refused(&[d], "z.txt", BASE_MISMATCH);
    // A modify missing its old fields.
    let mut m = modify("README.md", b"new\n");
    m.0.old_sha256 = None;
    assert_refused(&[m], "README.md", BASE_MISMATCH);
}

#[test]
fn add_of_existing_is_refused() {
    assert_refused(&[add("README.md", b"x")], "README.md", "already has");
    let mut a = add("new", b"x");
    a.0.old_size = Some(0);
    assert_refused(&[a], "new", "an add carries");
}

#[test]
fn delete_of_missing_is_refused() {
    let mut d = delete("z.txt");
    d.0.path = "zz.txt".into();
    assert_refused(&[d], "zz.txt", "does not have");
    let mut m = modify("z.txt", b"x");
    m.0.path = "zz.txt".into();
    assert_refused(&[m], "zz.txt", "does not have");
    // A delete must describe nothing new.
    let mut d = delete("z.txt");
    d.0.size = 4;
    assert_refused(&[d], "z.txt", "a delete must have");
}

#[test]
fn file_too_large() {
    let mut sink = Sink::default();
    let limits = Limits {
        file_bytes: 8,
        ..Limits::default()
    };
    let e = feed(
        true,
        limits,
        frames(&encode(&[add("big", b"123456789")])),
        &mut sink,
    )
    .unwrap_err();
    assert_eq!(e.path.as_deref(), Some("big"));
    assert!(e.reason.contains("MAX_FILE_BYTES"), "{e:?}");
    assert!(
        sink.cur.is_none() && sink.blobs.is_empty(),
        "bytes were read"
    );

    // Refused from the header alone: no byte frame needed.
    let mut sink = Sink::default();
    let mut h = head("huge", Op::Add, EntryKind::File, 0o644, b"");
    h.size = MAX_FILE_BYTES + 1;
    let b = base();
    let mut r = Reader::new(&b, Limits::default(), &mut sink);
    r.push(Frame::Json(json!({"t": "delta", "n": 1, "entries": 1})))
        .unwrap();
    let mut v = serde_json::to_value(&h).unwrap();
    v["t"] = "entry".into();
    let e = r.push(Frame::Json(v)).unwrap_err();
    assert!(e.reason.contains("MAX_FILE_BYTES"), "{e:?}");
    // The old side is capped too.
    let mut m = modify("README.md", b"x");
    m.0.old_size = Some(MAX_FILE_BYTES + 1);
    m.1 = None;
    assert_refused(&[m], "README.md", "MAX_FILE_BYTES");
    // A symlink target over LINK_MAX.
    let long = "a".repeat(4096);
    assert_refused(&[add_link("l", &long)], "l", "symlink target of 4096 bytes");
}

#[test]
fn too_many_entries() {
    let mut sink = Sink::default();
    let b = base();
    let mut r = Reader::new(&b, Limits::default(), &mut sink);
    let e = r
        .push(Frame::Json(
            json!({"t": "delta", "n": 1, "entries": MAX_ENTRIES + 1}),
        ))
        .unwrap_err();
    assert!(e.reason.contains("MAX_ENTRIES"), "{e:?}");

    let limits = Limits {
        entries: 2,
        ..Limits::default()
    };
    let items = [add("a", b"1"), add("b", b"2"), add("c", b"3")];
    let e = feed(true, limits, frames(&encode(&items)), &mut Sink::default()).unwrap_err();
    assert!(e.reason.contains("MAX_ENTRIES"), "{e:?}");

    // More entries than the header declared.
    let mut fs = frames(&encode(&[add("a", b"1"), add("b", b"2")]));
    fs[0] = Frame::Json(json!({"t": "delta", "n": 1, "entries": 1}));
    let e = feed(true, Limits::default(), fs, &mut Sink::default()).unwrap_err();
    assert!(e.reason.contains("more entries"), "{e:?}");
}

#[test]
fn total_too_large() {
    let limits = Limits {
        total_bytes: 10,
        ..Limits::default()
    };
    let items = [add("a", b"123456"), add("b", b"123456")];
    let mut sink = Sink::default();
    let e = feed(true, limits, frames(&encode(&items)), &mut sink).unwrap_err();
    assert_eq!(e.path.as_deref(), Some("b"));
    assert!(e.reason.contains("MAX_TOTAL_BYTES"), "{e:?}");
    // "b"'s bytes were never read.
    assert_eq!(sink.blobs.len(), 1);
}

#[test]
fn truncated_stream() {
    let fs = frames(&encode(&[add("a", b"1"), add("b", b"2")]));
    // Without the end frame.
    let e = feed(
        true,
        Limits::default(),
        fs[..fs.len() - 1].to_vec(),
        &mut Sink::default(),
    )
    .unwrap_err();
    assert!(e.reason.contains("truncated"), "{e:?}");
    // In the middle of content.
    let fs = frames(&encode(&[add("a", b"hello")]));
    let mut cut = fs[..1].to_vec();
    cut.push(fs[1].clone());
    cut.push(Frame::Bytes(b"he".to_vec()));
    let e = feed(true, Limits::default(), cut, &mut Sink::default()).unwrap_err();
    assert!(e.reason.contains("truncated"), "{e:?}");
    assert_eq!(e.path.as_deref(), Some("a"));
    // Nothing at all.
    let e = feed(true, Limits::default(), vec![], &mut Sink::default()).unwrap_err();
    assert!(e.reason.contains("truncated"), "{e:?}");
}

#[test]
fn size_mismatch() {
    // Too many bytes.
    let mut a = add("a", b"12345");
    a.2 = Some(b"123456".to_vec());
    assert_refused(&[a], "a", "more content bytes");
    // Too few, then the next entry.
    let mut a = add("a", b"12345");
    a.2 = Some(b"1234".to_vec());
    assert_refused(&[a, add("b", b"x")], "a", "fewer content bytes");
    // Too few, then the end.
    let mut a = add("a", b"12345");
    a.2 = Some(b"1234".to_vec());
    assert_refused(&[a], "a", "fewer content bytes");
    // Bytes for a delete.
    let mut d = delete("z.txt");
    d.2 = Some(b"x".to_vec());
    assert_refused(&[d], "z.txt", "more content bytes");
    // Bytes before any entry.
    let mut fs = frames(&encode(&[]));
    fs.insert(1, Frame::Bytes(vec![1]));
    let e = feed(true, Limits::default(), fs, &mut Sink::default()).unwrap_err();
    assert!(e.reason.contains("more content bytes"), "{e:?}");
}

#[test]
fn sha_mismatch() {
    let mut a = add("a", b"12345");
    a.2 = Some(b"12346".to_vec());
    let mut sink = Sink::default();
    let e = feed(true, Limits::default(), frames(&encode(&[a])), &mut sink).unwrap_err();
    assert_eq!(e.path.as_deref(), Some("a"));
    assert!(e.reason.contains("sha256"), "{e:?}");
    assert!(sink.blobs.is_empty(), "an unverified blob was finished");
    // A sha256 that is not hex.
    let mut a = add("a", b"1");
    a.0.sha256 = "Z".repeat(64);
    assert_refused(&[a], "a", "64 lowercase hex");
}

#[test]
fn bad_mode() {
    for (kind, mode, needle) in [
        (EntryKind::File, 0o600, "not 0o644 or 0o755"),
        (EntryKind::File, 0o777, "not 0o644 or 0o755"),
        (EntryKind::File, 0, "not 0o644 or 0o755"),
        (EntryKind::Symlink, 0o644, "symlink mode"),
        (EntryKind::File, 0o104755, "setuid"),
        (EntryKind::File, 0o4755, "setuid"),
        (EntryKind::File, 0o2755, "setgid"),
        (EntryKind::File, 0o1755, "sticky"),
        (EntryKind::File, 0o20644, "file-type bits"),
        (EntryKind::File, 0o10644, "file-type bits"),
        (EntryKind::File, 0o100644, "file-type bits"),
    ] {
        let content: &[u8] = b"docs";
        let item = (
            head("m", Op::Add, kind, mode, content),
            None,
            Some(content.to_vec()),
        );
        assert_refused(&[item], "m", needle);
    }
    // A delete's mode is 0.
    let mut d = delete("run.sh");
    d.0.mode = 0o755;
    assert_refused(&[d], "run.sh", "a delete must have");
}

#[test]
fn unknown_kind_is_refused() {
    for kind in ["device", "fifo", "dir", "socket"] {
        let mut v = serde_json::to_value(add("dev", b"x").0).unwrap();
        v["kind"] = kind.into();
        v["t"] = "entry".into();
        let fs = vec![
            Frame::Json(json!({"t": "delta", "n": 1, "entries": 1})),
            Frame::Json(v),
        ];
        let e = feed(true, Limits::default(), fs, &mut Sink::default()).unwrap_err();
        assert!(e.reason.contains("bad entry header"), "{e:?}");
        assert!(e.reason.contains(kind), "{e:?}");
    }
}

#[test]
fn unknown_field_is_refused() {
    let mut v = serde_json::to_value(add("a", b"x").0).unwrap();
    v["t"] = "entry".into();
    v["exec"] = true.into();
    let fs = vec![
        Frame::Json(json!({"t": "delta", "n": 1, "entries": 1})),
        Frame::Json(v),
    ];
    let e = feed(true, Limits::default(), fs, &mut Sink::default()).unwrap_err();
    assert!(e.reason.contains("exec"), "{e:?}");
    // In the delta header and the end frame too.
    let fs = vec![Frame::Json(
        json!({"t": "delta", "n": 1, "entries": 0, "x": 1}),
    )];
    assert!(feed(true, Limits::default(), fs, &mut Sink::default()).is_err());
    let fs = vec![
        Frame::Json(json!({"t": "delta", "n": 1, "entries": 0})),
        Frame::Json(json!({"t": "end", "entries": 0, "x": 1})),
    ];
    assert!(feed(true, Limits::default(), fs, &mut Sink::default()).is_err());
    // An unknown tag.
    let fs = vec![
        Frame::Json(json!({"t": "delta", "n": 1, "entries": 0})),
        Frame::Json(json!({"t": "chmod"})),
    ];
    assert!(feed(true, Limits::default(), fs, &mut Sink::default()).is_err());
}

#[test]
fn oversized_head_is_refused() {
    let mut v = serde_json::to_value(add("a", b"x").0).unwrap();
    v["t"] = "entry".into();
    v["path"] = "p".repeat(MAX_HEAD_BYTES).into();
    let fs = vec![
        Frame::Json(json!({"t": "delta", "n": 1, "entries": 1})),
        Frame::Json(v),
    ];
    let e = feed(true, Limits::default(), fs, &mut Sink::default()).unwrap_err();
    assert!(e.reason.contains("larger than"), "{e:?}");
}

#[test]
fn unsafe_chars_in_path_are_refused() {
    for p in [
        "a\u{202e}txt.exe",
        "a\nb",
        "zero\u{200b}width",
        "esc\u{1b}[31m",
    ] {
        assert_refused(&[add(p, b"x")], p, "unsafe character");
    }
    // In a symlink target too.
    assert_refused(&[add_link("l", "docs/\u{202e}a")], "l", "unsafe character");
    assert_refused(&[add_link("l", "docs\na")], "l", "unsafe character");
}

#[test]
fn depth_over_64_is_refused() {
    let ok = vec!["d"; MAX_DEPTH].join("/");
    run(&[add(&ok, b"x")]).unwrap();
    let deep = vec!["d"; MAX_DEPTH + 1].join("/");
    assert_refused(&[add(&deep, b"x")], &deep, "MAX_DEPTH");
}

#[test]
fn end_count_mismatch() {
    let mut fs = frames(&encode(&[add("a", b"1"), add("b", b"2")]));
    let last = fs.len() - 1;
    fs[last] = Frame::Json(json!({"t": "end", "entries": 3}));
    let e = feed(true, Limits::default(), fs, &mut Sink::default()).unwrap_err();
    assert!(e.reason.contains("entry count mismatch"), "{e:?}");
    // The header promised more than was sent.
    let mut fs = frames(&encode(&[add("a", b"1")]));
    fs[0] = Frame::Json(json!({"t": "delta", "n": 1, "entries": 2}));
    let last = fs.len() - 1;
    fs[last] = Frame::Json(json!({"t": "end", "entries": 2}));
    let e = feed(true, Limits::default(), fs, &mut Sink::default()).unwrap_err();
    assert!(e.reason.contains("entry count mismatch"), "{e:?}");
}

#[test]
fn frames_after_end_and_errors_stick() {
    let mut sink = Sink::default();
    let b = base();
    let mut r = Reader::new(&b, Limits::default(), &mut sink);
    let fs = frames(&encode(&[add("a", b"1")]));
    let n = fs.len();
    for (i, f) in fs.into_iter().enumerate() {
        assert_eq!(r.push(f).unwrap(), i == n - 1);
    }
    let e = r.push(Frame::Bytes(vec![1])).unwrap_err();
    assert!(e.reason.contains("after the end"), "{e:?}");
    // Once failed, always failed.
    let e2 = r
        .push(Frame::Json(json!({"t": "end", "entries": 1})))
        .unwrap_err();
    assert_eq!(e, e2);
    assert_eq!(r.finish().unwrap_err(), e);
}

#[test]
fn good_delta_roundtrip() {
    let big = vec![7u8; (1 << 20) + 10]; // two Bytes frames
    let items = [
        add("README.md.bak", b"hello\n"),
        modify("README.md", b"hello, world\n"),
        add("big.bin", &big),
        add_link("docs/link", "a"),
        add("empty", b""),
        delete("ln"),
        modify("run.sh", b"#!/bin/sh\necho hi\n"),
        delete("z.txt"),
    ];
    let mut sorted = items.to_vec();
    sorted.sort_by(|a, b| a.0.path.as_bytes().cmp(b.0.path.as_bytes()));
    let mut sink = Sink::default();
    let v = feed(true, Limits::default(), frames(&encode(&sorted)), &mut sink).unwrap();
    assert_eq!(v.n, 7);
    assert_eq!(
        v.entries,
        sorted.iter().map(|i| i.0.clone()).collect::<Vec<_>>()
    );
    // Every new content is in the sink under its hash; old content is not.
    for (h, _, new) in &sorted {
        if let Some(n) = new {
            assert_eq!(sink.blobs.get(&h.sha256), Some(n), "{}", h.path);
        }
    }
    assert!(!sink.blobs.contains_key(&sha(b"#!/bin/sh\n")));
    assert!(!sink.blobs.contains_key(&sha(b"zzz\n")));
    assert!(sink.cur.is_none());
}

#[test]
fn paths_only_checks_without_manifest() {
    // A modify whose old side matches nothing is accepted (old_* ignored)...
    let mut m = modify("README.md", b"new\n");
    m.0.old_sha256 = Some(sha(b"other"));
    m.1 = Some(b"not the base".to_vec());
    m.0.old_size = Some(12);
    let mut sink = Sink::default();
    let v = feed(
        false,
        Limits::default(),
        frames(&encode(&[m.clone()])),
        &mut sink,
    )
    .unwrap();
    assert_eq!(v.entries.len(), 1);
    assert!(sink.blobs.contains_key(&sha(b"new\n")));
    // ...but the old bytes are still counted.
    let mut short = m.clone();
    short.1 = Some(b"not".to_vec());
    let e = feed(
        false,
        Limits::default(),
        frames(&encode(&[short])),
        &mut Sink::default(),
    )
    .unwrap_err();
    assert!(e.reason.contains("fewer content bytes"), "{e:?}");
    // An add over a path the (absent) base has is fine; path, symlink, mode
    // and hash rules still apply.
    let ok = [add("README.md", b"x")];
    feed(
        false,
        Limits::default(),
        frames(&encode(&ok)),
        &mut Sink::default(),
    )
    .unwrap();
    for bad in [
        vec![add(".git/config", b"x")],
        vec![add_link("l", "../x")],
        vec![add_link("l", "docs"), add("l/x", b"x")],
        vec![add("q", b"x"), add("q/r", b"y")],
        vec![(
            head("m", Op::Add, EntryKind::File, 0o4755, b"x"),
            None,
            Some(b"x".to_vec()),
        )],
        vec![{
            let mut a = add("a", b"12345");
            a.2 = Some(b"12346".to_vec());
            a
        }],
    ] {
        let r = feed(
            false,
            Limits::default(),
            frames(&encode(&bad)),
            &mut Sink::default(),
        );
        assert!(r.is_err(), "{:?} passed", bad[0].0.path);
    }
}

#[test]
fn apply_manifest_full_and_partial() {
    let b = base();
    let items = [
        modify("README.md", b"hello, world\n"),
        add("new.txt", b"new\n"),
        delete("z.txt"),
    ];
    let v = run(&items).unwrap();

    let full = apply_manifest(&b, &v, None);
    assert_eq!(full.entries["README.md"].sha256, sha(b"hello, world\n"));
    assert_eq!(full.entries["new.txt"].size, 4);
    assert!(!full.entries.contains_key("z.txt"));
    assert_eq!(full.files, 10);
    assert_eq!(
        full.bytes,
        full.entries.values().map(|e| e.size).sum::<u64>()
    );
    assert_eq!(full.snapshot_commit, b.snapshot_commit);
    // The result is still a valid manifest.
    BaseManifest::parse(&serde_json::to_string(&full).unwrap()).unwrap();

    let only: BTreeSet<String> = ["new.txt".to_string()].into();
    let part = apply_manifest(&b, &v, Some(&only));
    assert_eq!(part.entries["README.md"], b.entries["README.md"]);
    assert!(part.entries.contains_key("z.txt"));
    assert!(part.entries.contains_key("new.txt"));
    assert_eq!(part.files, 11);
    BaseManifest::parse(&serde_json::to_string(&part).unwrap()).unwrap();

    let none = apply_manifest(&b, &v, Some(&BTreeSet::new()));
    assert_eq!(none, b);
}

/// No reason or Display may carry an unsafe char, whatever the guest sent.
fn assert_clean(e: &DeltaError) {
    let unsafe_in = |s: &str| s.chars().any(saiife_wire::text::is_unsafe_char);
    assert!(
        !unsafe_in(&e.reason),
        "unsafe char in reason {:?}",
        e.reason
    );
    assert!(
        !unsafe_in(&e.to_string()),
        "unsafe char in Display {:?}",
        e.to_string()
    );
}

#[test]
fn guest_text_in_reasons_is_escaped() {
    let evil = ["\u{1b}[31mred", "a\u{202e}b", "x\ny"];
    for name in evil {
        // An unknown field: serde echoes its name.
        let mut v = serde_json::to_value(add("a", b"x").0).unwrap();
        v["t"] = "entry".into();
        v[name] = 1.into();
        let fs = vec![
            Frame::Json(json!({"t": "delta", "n": 1, "entries": 1})),
            Frame::Json(v),
        ];
        let e = feed(true, Limits::default(), fs, &mut Sink::default()).unwrap_err();
        assert!(e.reason.contains("bad entry header"), "{e:?}");
        assert_clean(&e);
        // An unknown variant.
        let mut v = serde_json::to_value(add("a", b"x").0).unwrap();
        v["t"] = "entry".into();
        v["kind"] = name.into();
        let fs = vec![
            Frame::Json(json!({"t": "delta", "n": 1, "entries": 1})),
            Frame::Json(v),
        ];
        let e = feed(true, Limits::default(), fs, &mut Sink::default()).unwrap_err();
        assert_clean(&e);
        // The delta header, the end frame and the tag.
        let mut h = json!({"t": "delta", "n": 1, "entries": 0});
        h[name] = 1.into();
        let e = feed(
            true,
            Limits::default(),
            vec![Frame::Json(h)],
            &mut Sink::default(),
        )
        .unwrap_err();
        assert_clean(&e);
        let mut end = json!({"t": "end", "entries": 0});
        end[name] = 1.into();
        let fs = vec![
            Frame::Json(json!({"t": "delta", "n": 1, "entries": 0})),
            Frame::Json(end),
        ];
        let e = feed(true, Limits::default(), fs, &mut Sink::default()).unwrap_err();
        assert_clean(&e);
        let e = feed(
            true,
            Limits::default(),
            vec![Frame::Json(json!({"t": name}))],
            &mut Sink::default(),
        )
        .unwrap_err();
        assert_clean(&e);
        // A path and a symlink target.
        let e = refused(&[add(&format!("p{name}"), b"x")]);
        assert_clean(&e);
        let e = refused(&[add_link("l", &format!("../{name}"))]);
        assert_clean(&e);
    }
    // An unsorted pair whose earlier path is echoed.
    let e = refused(&[add("b\u{202e}", b"x"), add("a", b"y")]);
    assert_clean(&e);
}

#[test]
fn git_ntfs_aliases_are_refused() {
    for p in [
        ".git.",
        ".GIT ",
        ".git. .",
        "x/.Git./y",
        ".git../hooks/x",
        "GIT~1/config",
        "git~12",
        "a/Git~1/b",
        "GIT~1. ",
    ] {
        assert_refused(&[add(p, b"x")], p, ".git");
    }
    // Unicode spellings a normalising host folds to `.git` (R-T3i).
    for p in [".g\u{131}t", ".G\u{130}T/x", ".gi\u{301}t", "a/.git\u{301}"] {
        assert_refused(&[add(p, b"x")], p, ".git");
    }
    // Look-alikes stay fine; case-only collisions are not refused here.
    run(&[
        add("Readme.md", b"x"),
        add("git~", b"z"),
        add("git~1a", b"w"),
        add("x.git", b"v"),
    ])
    .unwrap();
}

#[test]
fn host_respellings_are_refused() {
    // R-T3h: names Windows or macOS would read as another name.
    for (p, why) in [
        ("CLAUDE.md.", "ends with a dot or a space"),
        ("claude.md ", "ends with a dot or a space"),
        ("sub/notes.", "ends with a dot or a space"),
        ("x.git.", "ends with a dot or a space"),
        ("CLAUDE~1.MD", "8.3 short name"),
        ("progra~12/x", "8.3 short name"),
        ("a~1", "8.3 short name"),
        (".claude::$DATA", "Windows does not allow"),
        ("a:b", "Windows does not allow"),
        ("a<b", "Windows does not allow"),
        ("x?", "Windows does not allow"),
        ("d/e*f", "Windows does not allow"),
        ("q\"", "Windows does not allow"),
        ("p|q", "Windows does not allow"),
        ("g>h", "Windows does not allow"),
    ] {
        assert_refused(&[add(p, b"x")], p, why);
    }
    // The same in a symlink target's named components.
    for t in ["docs.", "CLAUDE~1.MD", "a:b", "../x?"] {
        let e = refused(&[add_link("l2", t)]);
        assert_eq!(e.path.as_deref(), Some("l2"), "{t}");
        assert!(e.reason.contains("symlink target"), "{t}: {e:?}");
    }
    // Ordinary names, a leading `..` in a target, and `~` names not 8.3.
    run(&[
        add("a~b.txt", b"1"),
        add("backup~", b"2"),
        add("sub/claude-notes.md", b"3"),
        add_link("sub/up", "../README.md"),
        add("toolong~1.txt", b"4"),
    ])
    .unwrap();
}

#[test]
fn write_through_symlink_case_folded() {
    for p in ["LN/x", "Ln/x", "lN/deep/x"] {
        assert_refused(&[add(p, b"x")], p, "symlink in the base");
    }
    let e = refused(&[add("L2/x", b"x"), add_link("l2", "docs")]);
    assert_eq!(e.path.as_deref(), Some("L2/x"));
    assert!(e.reason.contains("symlink in the delta"), "{e:?}");
    // R-T3i: Unicode look-alikes fold too, through a delta symlink.
    let e = refused(&[add_link("docs2", "docs"), add("doc\u{17F}2/x", b"x")]);
    assert_eq!(e.path.as_deref(), Some("doc\u{17F}2/x"));
    assert!(e.reason.contains("symlink in the delta"), "{e:?}");
    // R-T3l: a Kelvin-sign link name is not NFC, so it is refused itself.
    let e = refused(&[add("link/x", b"x"), add_link("lin\u{212A}", "docs")]);
    assert_eq!(e.path.as_deref(), Some("lin\u{212A}"));
    assert!(e.reason.contains("not in Unicode NFC form"), "{e:?}");
}

#[test]
fn write_through_symlink_unicode_fold_in_base() {
    // R-T3i: base symlinks `docs2` and `links`; Unicode spellings of them
    // resolve to the links on a case-insensitive, normalising host.
    let mut b = base();
    for name in ["docs2", "links"] {
        b.entries.insert(
            name.into(),
            Entry {
                kind: EntryKind::Symlink,
                mode: 0,
                size: 4,
                sha256: sha(b"docs"),
            },
        );
    }
    for p in [
        "doc\u{17F}2/x",
        "lin\u{212A}s/x",
        "LIN\u{212A}\u{17F}/deep/x",
        "l\u{0301}inks/x",
        "l\u{0301}n/x",
    ] {
        let e = refused_on(&b, &[add(p, b"x")]);
        assert_eq!(e.path.as_deref(), Some(p), "{e:?}");
        // R-T3l: the Kelvin sign and decomposed spellings are not NFC, so
        // they are refused before the symlink check sees them.
        assert!(
            e.reason.contains("symlink in the base") || e.reason.contains("not in Unicode NFC"),
            "{p}: {e:?}"
        );
    }
}

/// Runs `items` against base `b` through `finish`, expecting a refusal.
fn refused_on(b: &BaseManifest, items: &[Item]) -> DeltaError {
    let mut sink = Sink::default();
    let mut r = Reader::new(b, Limits::default(), &mut sink);
    for f in frames(&encode(items)) {
        if let Err(e) = r.push(f) {
            return e;
        }
    }
    r.finish().expect_err("refused")
}

fn with_links(names: &[&str]) -> BaseManifest {
    let mut b = base();
    for name in names {
        b.entries.insert(
            name.to_string(),
            Entry {
                kind: EntryKind::Symlink,
                mode: 0,
                size: 4,
                sha256: sha(b"docs"),
            },
        );
    }
    b
}

#[test]
fn non_nfc_components_are_refused() {
    // R-T3l: a component that is not already NFC, in a path or a symlink
    // target's named component.
    for p in [
        "Do\u{301}cs/x",
        "re\u{301}sume\u{301}.md",
        "sub/\u{212A}elvin",
        "\u{212B}ngstrom",
        "\u{30D5}\u{309A}.txt",
    ] {
        assert_refused(&[add(p, b"x")], p, "not in Unicode NFC form");
    }
    for t in ["Do\u{301}cs", "sub/\u{212A}it"] {
        let e = refused(&[add_link("l2", t)]);
        assert_eq!(e.path.as_deref(), Some("l2"), "{t}");
        assert!(e.reason.contains("symlink target"), "{t}: {e:?}");
        assert!(e.reason.contains("not in Unicode NFC form"), "{t}: {e:?}");
    }
    // The guest text in the reason is escaped like every other.
    let e = refused(&[add("Do\u{301}cs", b"x")]);
    assert!(!e.reason.contains('\u{301}'), "{e:?}");
}

#[test]
fn nfc_i18n_names_are_accepted() {
    let mut items = vec![
        add("na\u{EF}ve/\u{FC}ber.txt", b"1"),
        add("r\u{E9}sum\u{E9}.md", b"2"),
        add(
            "\u{65E5}\u{672C}\u{8A9E}/\u{30D5}\u{30A1}\u{30A4}\u{30EB}.txt",
            b"3",
        ),
        add("\u{3A3}\u{3C3}\u{3C2}.txt", b"4"),
        add("stra\u{DF}e.md", b"5"),
        add_link("l\u{E9}", "r\u{E9}sum\u{E9}.md"),
    ];
    items.sort_by(|a, b| a.0.path.cmp(&b.0.path));
    let v = run(&items).unwrap();
    assert_eq!(v.entries.len(), 6);
}

#[test]
fn write_through_symlink_full_case_fold() {
    // R-T3l: base symlinks `Docs`, `kit`, `strasse`, `\u{3C3}\u{3C3}` and a
    // decomposed (macOS-committed, unchecked) `Cafe\u{301}`. Every spelling
    // a case-insensitive, normalising host resolves to one of them is
    // refused: as non-NFC, or as going through the symlink.
    let b = with_links(&["Docs", "kit", "strasse", "\u{3C3}\u{3C3}", "Cafe\u{301}"]);
    for (p, why) in [
        ("docs/x", "symlink in the base"),
        ("DOCS/x", "symlink in the base"),
        ("dOcS/deep/x", "symlink in the base"),
        ("Do\u{301}cs/x", "not in Unicode NFC form"),
        ("\u{212A}it/x", "not in Unicode NFC form"),
        ("KIT/x", "symlink in the base"),
        ("stra\u{DF}e/x", "symlink in the base"),
        ("STRA\u{1E9E}E/x", "symlink in the base"),
        ("\u{3C3}\u{3C2}/x", "symlink in the base"),
        ("\u{3A3}\u{3A3}/x", "symlink in the base"),
        ("Caf\u{E9}/x", "symlink in the base"),
        ("CAF\u{C9}/x", "symlink in the base"),
    ] {
        let e = refused_on(&b, &[add(p, b"x")]);
        assert_eq!(e.path.as_deref(), Some(p), "{e:?}");
        assert!(e.reason.contains(why), "{p}: {e:?}");
    }
    // The same through symlinks the delta adds.
    for (link, p) in [
        ("strasse2", "stra\u{DF}e2/x"),
        ("\u{3C3}\u{3C3}2", "\u{3C3}\u{3C2}2/x"),
        ("Docs2", "docs2/x"),
    ] {
        let mut items = vec![add_link(link, "docs"), add(p, b"x")];
        items.sort_by(|a, b| a.0.path.cmp(&b.0.path));
        let e = refused(&items);
        assert_eq!(e.path.as_deref(), Some(p), "{e:?}");
        assert!(e.reason.contains("symlink in the delta"), "{p}: {e:?}");
    }
}

#[test]
fn one_comparison_key() {
    // R-T3l: fold_path and is_git_alias both go through normalize_component.
    for (a, b) in [
        ("STRA\u{1E9E}E", "strasse"),
        ("stra\u{DF}e", "strasse"),
        ("\u{3C3}\u{3C2}", "\u{3C3}\u{3C3}"),
        ("\u{212A}it", "kit"),
        ("\u{17F}rc", "src"),
        ("\u{130}NDEX", "index"),
        ("\u{131}ndex", "index"),
        ("\u{212B}ngstr\u{F6}m", "angstrom"),
        ("Caf\u{E9}", "cafe"),
        ("Cafe\u{301}", "cafe"),
        ("\u{1E9B}", "s"),
    ] {
        assert_eq!(normalize_component(a), normalize_component(b), "{a}");
        assert_eq!(normalize_component(a), b, "{a}");
    }
    assert_eq!(
        fold_path("Docs/STRA\u{1E9E}E/\u{3A3}\u{3C2}.md"),
        "docs/strasse/\u{3C3}\u{3C3}.md"
    );
    for c in [
        ".G\u{130}T",
        ".g\u{131}t",
        ".GI\u{301}T",
        ".G\u{CD}T",
        "G\u{CD}T~1",
    ] {
        assert!(is_git_alias(c), "{c}");
    }
    assert!(!is_git_alias(".gist"));
    // `.G\u{130}T` is NFC, so it reaches the alias check and is refused
    // there.
    assert_refused(
        &[add(".G\u{130}T/config", b"x")],
        ".G\u{130}T/config",
        ".git",
    );
    assert_refused(&[add(".G\u{CD}T", b"x")], ".G\u{CD}T", ".git");
}

#[test]
fn old_total_too_large() {
    let limits = Limits {
        total_bytes: 10,
        ..Limits::default()
    };
    // README.md (6) + run.sh (10) of old content: 16 > 10; new content 2.
    let items = [modify("README.md", b"a"), modify("run.sh", b"b")];
    let e = feed(true, limits, frames(&encode(&items)), &mut Sink::default()).unwrap_err();
    assert_eq!(e.path.as_deref(), Some("run.sh"));
    assert!(e.reason.contains("old content"), "{e:?}");
    assert!(e.reason.contains("MAX_TOTAL_BYTES"), "{e:?}");
}
