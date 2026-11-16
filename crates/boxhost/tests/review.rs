//! The host review (plan 39 Task 3): receive over a fake guest (plan 38's
//! test multiplexer serving canned exports made with `write_delta`),
//! validate, store, render, flag, hash, write the land files.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use saiife_boxhost::guest::{SetupSource, VsockGuest};
use saiife_boxhost::paths::{BoxPaths, RecordPaths};
use saiife_boxhost::review::{
    check_subset, git_config, protected, receive, receive_within, render, review, write_land_files,
    Flag, Review,
};
use saiife_boxhost::vmm::VmHooks;
use saiife_boxproto::delta::{
    apply_manifest, write_delta, BlobSink, DeltaItem, EntryHead, Limits, Op, Reader, Valid,
    BASE_MISMATCH,
};
use saiife_boxproto::frame::{read_frame, read_msg, write_frame, write_msg, Frame};
use saiife_boxproto::manifest::{BaseManifest, Entry, EntryKind};
use saiife_boxproto::msg::{AgentSpec, Event, HostReply, Reply, Request, Setup};
use saiife_boxproto::{ports, PROTO};
use saiife_wire::source::{BoxId, FileStatus, MAX_DIFF_BYTES};

const T: Duration = Duration::from_secs(10);

fn me() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn b1() -> BoxId {
    BoxId::parse("b1").unwrap()
}

fn sha(b: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, b)
        .as_ref()
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

// ---- the fake guest (plan 38's multiplexer, as in tests/vsock_guest.rs) ----

struct Setups;
impl SetupSource for Setups {
    fn setup_for(&self, _id: &BoxId) -> Result<Setup, String> {
        Ok(Setup {
            agent: AgentSpec {
                command: vec!["claude".into()],
                user: "agent".into(),
                cwd: "/work".into(),
            },
            env: vec![],
            files: vec![],
            rows: 40,
            cols: 120,
        })
    }
}

type Handler = dyn Fn(Request, &mut UnixStream) + Send + Sync;

/// What the guest answers to `Export { n }`.
#[derive(Clone)]
enum Answer {
    Bytes(Vec<u8>),
    Err(String),
    /// A valid start, then one byte every `gap`, never finishing.
    Drip(Duration),
}

struct World {
    _t: tempfile::TempDir,
    /// The box's record dir (R37): the land files, apart from the
    /// runtime dir the vsock sockets are in.
    paths: RecordPaths,
    answers: Arc<Mutex<BTreeMap<u32, Answer>>>,
    requests: Arc<Mutex<Vec<Request>>>,
    stop: Arc<AtomicBool>,
    guest: Arc<VsockGuest>,
    _events: UnixStream,
}

impl Drop for World {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.guest.after_off(&b1());
    }
}

fn serve_export(a: Option<Answer>, n: u32, s: &mut UnixStream) {
    match a {
        Some(Answer::Bytes(b)) => {
            let _ = s.write_all(&b);
        }
        Some(Answer::Err(why)) => {
            let _ = write_msg(s, &Reply::Err { why });
        }
        Some(Answer::Drip(gap)) => {
            let head = serde_json::json!({"t": "delta", "n": n, "entries": 1});
            let content = vec![b'x'; 1000];
            let mut e = serde_json::to_value(add_head("drip.txt", &C::f(&content))).unwrap();
            e["t"] = "entry".into();
            if write_frame(s, &Frame::Json(head)).is_err()
                || write_frame(s, &Frame::Json(e)).is_err()
            {
                return;
            }
            for _ in 0..1000 {
                thread::sleep(gap);
                if write_frame(s, &Frame::Bytes(vec![b'x'])).is_err() {
                    return;
                }
            }
        }
        None => {
            let _ = write_msg(
                s,
                &Reply::Err {
                    why: "no such export".into(),
                },
            );
        }
    }
}

impl World {
    fn new() -> World {
        let base = std::env::var_os("TMPDIR").map_or_else(std::env::temp_dir, PathBuf::from);
        let t = tempfile::Builder::new()
            .prefix("r")
            .tempdir_in(base)
            .unwrap();
        let dir = t.path().join("b1");
        std::fs::create_dir(&dir).unwrap();
        let rt = BoxPaths::new(dir);
        let paths = RecordPaths::new(t.path().join("records").join("b1"));
        std::fs::create_dir_all(&paths.dir).unwrap();
        let answers: Arc<Mutex<BTreeMap<u32, Answer>>> = Arc::default();
        let requests: Arc<Mutex<Vec<Request>>> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let ans = answers.clone();
        let handler: Arc<Handler> = Arc::new(move |r, s| match r {
            Request::Export { n } => {
                let a = ans.lock().unwrap().get(&n).cloned();
                serve_export(a, n, s);
            }
            _ => {
                let _ = write_msg(s, &Reply::Ok);
            }
        });
        let l = UnixListener::bind(rt.vsock()).unwrap();
        l.set_nonblocking(true).unwrap();
        let (reqs, st) = (requests.clone(), stop.clone());
        thread::spawn(move || {
            while !st.load(Ordering::SeqCst) {
                let s = match l.accept() {
                    Ok((s, _)) => s,
                    Err(_) => {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                };
                let (reqs, h) = (reqs.clone(), handler.clone());
                thread::spawn(move || mux_conn(s, reqs, h));
            }
        });
        let guest = VsockGuest::new(Arc::new(Setups), false, me());
        guest.before_boot(&b1(), &rt).unwrap();
        let mut ev = UnixStream::connect(rt.vsock_port(ports::EVENTS)).unwrap();
        ev.set_read_timeout(Some(T)).unwrap();
        write_msg(
            &mut ev,
            &Event::Hello {
                proto: PROTO.into(),
                guest: "0.1".into(),
                uptime_ms: 5,
                set_up: false,
            },
        )
        .unwrap();
        let r: HostReply = read_msg(&mut ev).unwrap().unwrap();
        assert_eq!(
            r,
            HostReply::Welcome {
                proto: PROTO.into()
            }
        );
        let end = Instant::now() + T;
        while requests.lock().unwrap().is_empty() {
            assert!(Instant::now() < end, "no setup request");
            thread::sleep(Duration::from_millis(20));
        }
        World {
            _t: t,
            paths,
            answers,
            requests,
            stop,
            guest,
            _events: ev,
        }
    }

    fn answer(&self, n: u32, a: Answer) {
        self.answers.lock().unwrap().insert(n, a);
    }

    fn receive(
        &self,
        base: &BaseManifest,
        n: u32,
    ) -> Result<Valid, saiife_boxproto::delta::DeltaError> {
        receive(&self.guest, &b1(), &self.paths, base, n)
    }

    /// Serves `old → new` as export `n` and receives it against `base`.
    fn land(&self, base: &BaseManifest, n: u32, old: &Tree, new: &Tree) -> Valid {
        self.answer(n, Answer::Bytes(export(n, old, new)));
        self.receive(base, n).unwrap()
    }

    fn blobs(&self, n: u32) -> PathBuf {
        self.paths.land_blobs(n)
    }
}

/// One multiplexer connection: `CONNECT 1024\n` → `OK 1\n`, then one request.
fn mux_conn(mut s: UnixStream, reqs: Arc<Mutex<Vec<Request>>>, h: Arc<Handler>) {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    while line.len() < 32 {
        if s.read(&mut b).unwrap_or(0) == 0 {
            return;
        }
        line.push(b[0]);
        if b[0] == b'\n' {
            break;
        }
    }
    if line != b"CONNECT 1024\n" {
        return;
    }
    s.write_all(b"OK 1\n").unwrap();
    let req: Request = match read_msg(&mut s) {
        Ok(Some(r)) => r,
        _ => return,
    };
    reqs.lock().unwrap().push(req.clone());
    h(req, &mut s);
}

// ---- a tree model: manifests and canned exports ----

#[derive(Clone, Debug, PartialEq)]
enum C {
    F(Vec<u8>, u32),
    L(String),
}

impl C {
    fn f(b: &[u8]) -> C {
        C::F(b.to_vec(), 0o644)
    }
    fn x(b: &[u8]) -> C {
        C::F(b.to_vec(), 0o755)
    }
    fn l(t: &str) -> C {
        C::L(t.into())
    }
    fn bytes(&self) -> &[u8] {
        match self {
            C::F(b, _) => b,
            C::L(t) => t.as_bytes(),
        }
    }
    fn kind(&self) -> EntryKind {
        match self {
            C::F(..) => EntryKind::File,
            C::L(_) => EntryKind::Symlink,
        }
    }
    fn mode(&self) -> u32 {
        match self {
            C::F(_, m) => *m,
            C::L(_) => 0,
        }
    }
}

type Tree = BTreeMap<String, C>;

fn tree(items: &[(&str, C)]) -> Tree {
    items
        .iter()
        .map(|(p, c)| (p.to_string(), c.clone()))
        .collect()
}

fn with(t: &Tree, changes: &[(&str, Option<C>)]) -> Tree {
    let mut t = t.clone();
    for (p, c) in changes {
        match c {
            Some(c) => t.insert(p.to_string(), c.clone()),
            None => t.remove(*p),
        };
    }
    t
}

fn manifest(t: &Tree) -> BaseManifest {
    let entries: BTreeMap<String, Entry> = t
        .iter()
        .map(|(p, c)| {
            (
                p.clone(),
                Entry {
                    kind: c.kind(),
                    mode: c.mode(),
                    size: c.bytes().len() as u64,
                    sha256: sha(c.bytes()),
                },
            )
        })
        .collect();
    BaseManifest {
        version: 1,
        repo: "demo".into(),
        base_commit: Some("a".repeat(40)),
        snapshot_commit: "b".repeat(40),
        files: entries.len() as u64,
        bytes: entries.values().map(|e| e.size).sum(),
        entries,
    }
}

fn add_head(p: &str, c: &C) -> EntryHead {
    EntryHead {
        path: p.into(),
        op: Op::Add,
        kind: c.kind(),
        mode: c.mode(),
        size: c.bytes().len() as u64,
        sha256: sha(c.bytes()),
        old_kind: None,
        old_size: None,
        old_sha256: None,
    }
}

/// The heads and contents of `old → new`, sorted by path.
/// An entry head with its old and new content.
type Item = (EntryHead, Option<Vec<u8>>, Option<Vec<u8>>);

fn items(old: &Tree, new: &Tree) -> Vec<Item> {
    let keys: BTreeSet<&String> = old.keys().chain(new.keys()).collect();
    let mut out = Vec::new();
    for k in keys {
        match (old.get(k), new.get(k)) {
            (None, Some(n)) => out.push((add_head(k, n), None, Some(n.bytes().to_vec()))),
            (Some(o), None) => out.push((
                EntryHead {
                    path: k.clone(),
                    op: Op::Delete,
                    kind: o.kind(),
                    mode: 0,
                    size: 0,
                    sha256: String::new(),
                    old_kind: Some(o.kind()),
                    old_size: Some(o.bytes().len() as u64),
                    old_sha256: Some(sha(o.bytes())),
                },
                None,
                None,
            )),
            (Some(o), Some(n)) if o != n => {
                let mut h = add_head(k, n);
                h.op = Op::Modify;
                h.old_kind = Some(o.kind());
                h.old_size = Some(o.bytes().len() as u64);
                h.old_sha256 = Some(sha(o.bytes()));
                out.push((h, Some(o.bytes().to_vec()), Some(n.bytes().to_vec())));
            }
            _ => {}
        }
    }
    out
}

fn export(n: u32, old: &Tree, new: &Tree) -> Vec<u8> {
    let it = items(old, new);
    let refs: Vec<DeltaItem<'_>> = it
        .iter()
        .map(|(h, o, n)| (h.clone(), o.as_deref(), n.as_deref()))
        .collect();
    let mut out = Vec::new();
    write_delta(&mut out, n, &refs).unwrap();
    out
}

fn base_tree() -> Tree {
    tree(&[
        (
            "README.md",
            C::f(b"# Demo\n\nline 1\nline 2\nline 3\nline 4\nline 5\nline 6\nline 7\n"),
        ),
        ("ln", C::l("src/main.rs")),
        ("logo.png", C::f(b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR")),
        ("old.txt", C::f(b"bye\n")),
        ("run.sh", C::f(b"#!/bin/sh\necho hi\n")),
        (
            "src/main.rs",
            C::f(b"fn main() {\n    println!(\"hi\");\n}\n"),
        ),
    ])
}

fn no_hits(_p: &[&str]) -> Vec<Flag> {
    Vec::new()
}

fn golden(name: &str, got: &str) {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name);
    if std::env::var_os("SAIIFE_BLESS").is_some() {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, got).unwrap();
    }
    let want = std::fs::read_to_string(&p).unwrap_or_default();
    assert_eq!(got, want, "golden {name} differs");
}

fn set(paths: &[&str]) -> BTreeSet<String> {
    paths.iter().map(|p| p.to_string()).collect()
}

fn lands_entries(w: &World) -> Vec<String> {
    match std::fs::read_dir(w.paths.lands_dir()) {
        Ok(rd) => rd
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect(),
        Err(_) => vec![],
    }
}

// ---- tests ----

#[test]
fn render_golden_text_add_modify_delete() {
    let w = World::new();
    let t0 = base_tree();
    let b0 = manifest(&t0);
    let t1 = with(
        &t0,
        &[
            (
                "README.md",
                Some(C::f(
                    "# Demo\n\nline 1\nline 2\nline two and a half \x1b[31mred\x1b[0m\rover\u{202e}\nline 3\nline 4\nline 5\nline 6\nline 7 changed\n"
                        .as_bytes(),
                )),
            ),
            ("old.txt", None),
            ("docs/new.md", Some(C::f(b"first\n\tsecond, tabbed\nno newline"))),
        ],
    );
    let v = w.land(&b0, 1, &t0, &t1);
    let (full, files) = render(&b0, &v, &w.blobs(1), None);
    golden("text_add_modify_delete.diff", &full);
    assert!(!full.contains('\x1b') && !full.contains('\r') && !full.contains('\u{202e}'));
    assert!(full.contains("\\u{001B}[31mred"), "{full}");
    assert!(full.contains("+\tsecond, tabbed\n"), "TAB is kept");
    let st: Vec<(&str, &FileStatus, u32, u32)> = files
        .iter()
        .map(|f| (f.path.as_str(), &f.status, f.added, f.removed))
        .collect();
    assert_eq!(
        st,
        vec![
            ("README.md", &FileStatus::Modified, 2, 1),
            ("docs/new.md", &FileStatus::Added, 3, 0),
            ("old.txt", &FileStatus::Deleted, 0, 0),
        ]
    );
    assert!(files.iter().all(|f| !f.binary));
}

#[test]
fn render_golden_binary_and_symlink() {
    let w = World::new();
    let t0 = base_tree();
    let b0 = manifest(&t0);
    let t1 = with(
        &t0,
        &[
            ("logo.png", Some(C::f(b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR v2"))),
            ("data.bin", Some(C::f(&[0u8, 1, 2, 3, 255]))),
            ("ln", Some(C::l("README.md"))),
            ("ln2", Some(C::l("src"))),
        ],
    );
    let v = w.land(&b0, 1, &t0, &t1);
    let (full, files) = render(&b0, &v, &w.blobs(1), None);
    golden("binary_and_symlink.diff", &full);
    assert!(full.contains(&format!(
        "Binary file b/data.bin: 5 bytes, sha256 {}\n",
        sha(&[0u8, 1, 2, 3, 255])
    )));
    assert!(full.contains("new file mode 120000\n"));
    assert!(full.contains("-src/main.rs\n\\ No newline at end of file\n+README.md\n"));
    let bin: Vec<&str> = files
        .iter()
        .filter(|f| f.binary)
        .map(|f| f.path.as_str())
        .collect();
    assert_eq!(bin, vec!["data.bin", "logo.png"]);
    let r = review(&b1(), &b0, &v, &w.blobs(1), None, &no_hits);
    let why = |p: &str| -> Vec<String> {
        r.flags
            .iter()
            .filter(|f| f.path == p)
            .map(|f| f.why.clone())
            .collect()
    };
    assert_eq!(why("data.bin"), vec!["binary"]);
    assert_eq!(why("logo.png"), vec!["binary"]);
    assert_eq!(why("ln2"), vec!["new symlink"]);
    assert!(why("ln").is_empty(), "a retargeted symlink is not new");
}

#[test]
fn render_mode_change() {
    let w = World::new();
    let t0 = base_tree();
    let b0 = manifest(&t0);
    let t1 = with(&t0, &[("run.sh", Some(C::x(b"#!/bin/sh\necho hi\n")))]);
    let v = w.land(&b0, 1, &t0, &t1);
    let (full, files) = render(&b0, &v, &w.blobs(1), None);
    let s = sha(b"#!/bin/sh\necho hi\n");
    assert_eq!(
        full,
        format!(
            "diff --saiife a/run.sh b/run.sh\nindex {s}..{s} 100755\nold mode 100644\nnew mode 100755\n--- a/run.sh\n+++ b/run.sh\n"
        )
    );
    assert_eq!((files[0].added, files[0].removed), (0, 0));
    let r = review(&b1(), &b0, &v, &w.blobs(1), None, &no_hits);
    assert_eq!(
        r.flags,
        vec![Flag {
            path: "run.sh".into(),
            why: "becomes executable".into()
        }]
    );
    // A new executable file is flagged too; an executable staying one is not.
    let t2 = with(
        &t1,
        &[
            ("tool", Some(C::x(b"x\n"))),
            ("run.sh", Some(C::x(b"#!/bin/sh\n"))),
        ],
    );
    let b1m = apply_manifest(&b0, &v, None);
    let v2 = w.land(&b1m, 2, &t1, &t2);
    let r2 = review(&b1(), &b1m, &v2, &w.blobs(2), None, &no_hits);
    let flagged: Vec<&str> = r2.flags.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(flagged, vec!["tool"]);
}

#[test]
fn diff_sha256_is_of_the_full_text() {
    let w = World::new();
    let t0 = base_tree();
    let b0 = manifest(&t0);
    let mut changes = Vec::new();
    let big: Vec<Vec<u8>> = (0..4)
        .map(|k| {
            let mut s = String::new();
            let mut i = 0;
            while s.len() < 800_000 {
                s.push_str(&format!("file {k} generated line {i}\n"));
                i += 1;
            }
            s.into_bytes()
        })
        .collect();
    let names = ["big/a.txt", "big/b.txt", "big/c.txt", "big/d.txt"];
    for (n, b) in names.iter().zip(&big) {
        changes.push((*n, Some(C::f(b))));
    }
    let t1 = with(&t0, &changes);
    let v = w.land(&b0, 1, &t0, &t1);
    let (full, _) = render(&b0, &v, &w.blobs(1), None);
    assert!(full.len() > 3_000_000, "{}", full.len());
    let r = review(&b1(), &b0, &v, &w.blobs(1), None, &no_hits);
    assert!(r.summary.truncated);
    assert!(r.summary.unified.len() <= MAX_DIFF_BYTES);
    assert!(r.summary.unified.ends_with('\n'));
    assert!(full.starts_with(&r.summary.unified));
    assert!(full.as_bytes()[r.summary.unified.len() - 1] == b'\n');
    assert!(
        r.summary.unified.len() + full[r.summary.unified.len()..].find('\n').unwrap() + 1
            > MAX_DIFF_BYTES,
        "the cut is at the last line end that fits"
    );
    assert_eq!(r.summary.diff_sha256, sha(full.as_bytes()));
    assert_ne!(r.summary.diff_sha256, sha(r.summary.unified.as_bytes()));
    assert_eq!(r.summary.base_commit, b0.snapshot_commit);
    assert_eq!(r.base_head, b0.base_commit);
    assert_eq!(r.summary.files.len(), 4);
}

#[test]
fn binary_change_changes_the_hash() {
    let w = World::new();
    let t0 = base_tree();
    let b0 = manifest(&t0);
    let a = with(&t0, &[("blob.bin", Some(C::f(&[0u8, 1, 2, 3, 4, 5])))]);
    let b = with(&t0, &[("blob.bin", Some(C::f(&[0u8, 1, 2, 3, 4, 6])))]);
    let va = w.land(&b0, 1, &t0, &a);
    let vb = w.land(&b0, 2, &t0, &b);
    let ra = review(&b1(), &b0, &va, &w.blobs(1), None, &no_hits);
    let rb = review(&b1(), &b0, &vb, &w.blobs(2), None, &no_hits);
    assert!(ra.summary.files[0].binary && rb.summary.files[0].binary);
    assert_ne!(ra.summary.diff_sha256, rb.summary.diff_sha256);
    // And a text change that escapes to the same rendering still differs
    // through the index line (R-P2).
    let c = with(&t0, &[("t.txt", Some(C::f(b"\x01\n")))]);
    let d = with(&t0, &[("t.txt", Some(C::f(b"\\u{0001}\n")))]);
    let vc = w.land(&b0, 3, &t0, &c);
    let vd = w.land(&b0, 4, &t0, &d);
    let rc = review(&b1(), &b0, &vc, &w.blobs(3), None, &no_hits);
    let rd = review(&b1(), &b0, &vd, &w.blobs(4), None, &no_hits);
    let body = |r: &Review| {
        r.summary
            .unified
            .lines()
            .skip(2)
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert_eq!(body(&rc), body(&rd), "escaping is not injective");
    assert_ne!(rc.summary.diff_sha256, rd.summary.diff_sha256);
}

#[test]
fn flags_protected_and_hits() {
    for p in [
        ".claude/settings.json",
        ".claude",
        "CLAUDE.md",
        "sub/claude.md",
        "AGENTS.md",
        ".mcp.json",
        ".saiife/x",
        ".github/workflows/ci.yml",
        ".gitlab-ci.yml",
        ".gitattributes",
        ".gitmodules",
        ".envrc",
        "a/.envrc",
        "a/.gitattributes",
        "a/.gitkeep",
        ".gitconfig",
        // R-T3i: spellings a normalising, case-insensitive host folds.
        "Cla\u{301}ude.md",
        ".ClAuDe/settings.json",
        "CLAUDE.md.",
        ".claude ./x",
        ".hus\u{212A}y/pre-commit",
        ".\u{17F}aiife/x",
        ".gem\u{131}n\u{130}/settings.json",
        ".G\u{131}tattributes",
        // R-T3l: the shared key (decomposition, full case fold).
        ".G\u{130}THUB/workflows/ci.yml",
        "CL\u{C1}UDE.md",
        "sub/AG\u{C9}NTS.MD",
        ".\u{17F}AIIFE/x",
        ".gi\u{301}tmodules",
        // R-T3n: the round-trip fold (ligatures).
        ".pre-commit-con\u{FB01}g.yaml",
        ".github/work\u{FB02}ows/ci.yml",
        // R-T3j.
        ".vscode/tasks.json",
        ".devcontainer/devcontainer.json",
        ".husky/pre-commit",
        ".pre-commit-config.yaml",
        ".cursor/rules/x.mdc",
        ".cursorrules",
        ".gemini/settings.json",
        "GEMINI.md",
        "pkg/gemini.md",
        ".codex/config.toml",
        ".gitlab/ci.yml",
        ".circleci/config.yml",
        // R-T6e: git-lfs's config.
        ".lfsconfig",
        "a/.lfsconfig",
        ".LFSCONFIG.",
    ] {
        assert!(protected(p), "{p}");
    }
    for p in [
        ".gitignore",
        "a/.gitignore",
        "src/main.rs",
        "docs/claude.txt",
        "docs/claude-notes.md",
        "README.md",
        "x/.mcp.json",
        "src/.vscode.rs",
    ] {
        assert!(!protected(p), "{p}");
    }
    let w = World::new();
    let t0 = base_tree();
    let b0 = manifest(&t0);
    let t1 = with(
        &t0,
        &[
            ("CLAUDE.md", Some(C::f(b"obey\n"))),
            (".github/workflows/ci.yml", Some(C::f(b"on: push\n"))),
            (".gitignore", Some(C::f(b"target\n"))),
            ("sub/.gitattributes", Some(C::f(b"* filter=evil\n"))),
            ("src/x.rs", Some(C::f(b"// x\n"))),
            ("old.txt", None),
        ],
    );
    let v = w.land(&b0, 1, &t0, &t1);
    let seen: Mutex<Vec<String>> = Mutex::default();
    let hits = |paths: &[&str]| -> Vec<Flag> {
        *seen.lock().unwrap() = paths.iter().map(|p| p.to_string()).collect();
        paths
            .iter()
            .filter(|p| p.ends_with("x.rs"))
            .map(|p| Flag {
                path: p.to_string(),
                why: "rule mypack: no writes to src".into(),
            })
            .collect()
    };
    let r = review(&b1(), &b0, &v, &w.blobs(1), None, &hits);
    let got: Vec<(&str, &str)> = r
        .flags
        .iter()
        .map(|f| (f.path.as_str(), f.why.as_str()))
        .collect();
    assert_eq!(
        got,
        vec![
            (".github/workflows/ci.yml", "protected path"),
            ("CLAUDE.md", "protected path"),
            ("sub/.gitattributes", "protected path (git config)"),
            ("src/x.rs", "rule mypack: no writes to src"),
        ]
    );
    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            ".github/workflows/ci.yml",
            ".gitignore",
            "CLAUDE.md",
            "old.txt",
            "src/x.rs",
            "sub/.gitattributes"
        ]
    );
}

#[test]
fn case_collision_is_flagged() {
    let w = World::new();
    let t0 = base_tree();
    let b0 = manifest(&t0);
    let t1 = with(&t0, &[("readme.md", Some(C::f(b"lower\n")))]);
    let v = w.land(&b0, 1, &t0, &t1);
    let r = review(&b1(), &b0, &v, &w.blobs(1), None, &no_hits);
    assert_eq!(
        r.flags,
        vec![Flag {
            path: "readme.md".into(),
            why: "differs only in case or accents from README.md".into()
        }]
    );
}

#[test]
fn full_case_fold_collision_is_flagged() {
    // R-T3l: the collision flag folds with the shared key: `STRASSE.md`
    // and `stra\u{DF}e.md` are one name on a case-insensitive host.
    let w = World::new();
    let t0 = with(&base_tree(), &[("STRASSE.md", Some(C::f(b"a\n")))]);
    let b0 = manifest(&t0);
    let t1 = with(&t0, &[("stra\u{DF}e.md", Some(C::f(b"b\n")))]);
    let v = w.land(&b0, 1, &t0, &t1);
    let r = review(&b1(), &b0, &v, &w.blobs(1), None, &no_hits);
    assert_eq!(
        r.flags,
        vec![Flag {
            path: "stra\u{DF}e.md".into(),
            why: "differs only in case or accents from STRASSE.md".into()
        }]
    );
}

#[test]
fn subset_review_hashes_only_the_subset() {
    let w = World::new();
    let t0 = base_tree();
    let b0 = manifest(&t0);
    let t1 = with(
        &t0,
        &[("a.txt", Some(C::f(b"a\n"))), ("b.txt", Some(C::f(b"b\n")))],
    );
    let v = w.land(&b0, 1, &t0, &t1);
    let only = set(&["a.txt"]);
    let all = review(&b1(), &b0, &v, &w.blobs(1), None, &no_hits);
    let sub = review(&b1(), &b0, &v, &w.blobs(1), Some(&only), &no_hits);
    let (text, files) = render(&b0, &v, &w.blobs(1), Some(&only));
    assert_eq!(sub.summary.diff_sha256, sha(text.as_bytes()));
    assert_eq!(sub.summary.unified, text);
    assert_ne!(sub.summary.diff_sha256, all.summary.diff_sha256);
    assert_eq!(files.len(), 1);
    assert_eq!(sub.summary.files, files);
    assert_eq!(
        sub.entries
            .iter()
            .map(|h| h.path.as_str())
            .collect::<Vec<_>>(),
        vec!["a.txt"]
    );
    assert!(!text.contains("b.txt"));
    check_subset(&b0, &v, Some(&only)).unwrap();
}

#[test]
fn hostile_delta_stores_nothing() {
    let w = World::new();
    let t0 = base_tree();
    let b0 = manifest(&t0);
    let good = C::f(b"evil\n");
    let mut cases: Vec<Vec<u8>> = Vec::new();
    for path in [
        "../x",
        "/etc/passwd",
        ".git/hooks/pre-commit",
        "sub/.GIT/config",
    ] {
        let mut out = Vec::new();
        write_delta(
            &mut out,
            0,
            &[(add_head(path, &good), None, Some(good.bytes()))],
        )
        .unwrap();
        cases.push(out);
    }
    // A good first entry (its blob is stored), then a lie about the second.
    let mut out = Vec::new();
    let mut lie = add_head("zz.txt", &good);
    lie.sha256 = sha(b"something else");
    write_delta(
        &mut out,
        0,
        &[
            (add_head("aa.txt", &good), None, Some(good.bytes())),
            (lie, None, Some(good.bytes())),
        ],
    )
    .unwrap();
    cases.push(out);
    // A stream cut in the middle.
    let full = export(
        0,
        &t0,
        &with(&t0, &[("big.txt", Some(C::f(&[b'y'; 5000])))]),
    );
    cases.push(full[..full.len() / 2].to_vec());
    for (i, bytes) in cases.into_iter().enumerate() {
        let n = i as u32 + 1;
        // The delta header must carry the requested n.
        let bytes = renumber(&bytes, n);
        w.answer(n, Answer::Bytes(bytes));
        let e = w.receive(&b0, n).unwrap_err();
        assert!(!e.reason.is_empty());
        assert!(!w.paths.land_dir(n).exists(), "case {i}: {e}");
    }
    assert!(lands_entries(&w).is_empty(), "{:?}", lands_entries(&w));
    // An export numbered other than requested is refused too.
    w.answer(
        9,
        Answer::Bytes(export(8, &t0, &with(&t0, &[("a", Some(good.clone()))]))),
    );
    let e = w.receive(&b0, 9).unwrap_err();
    assert!(e.reason.contains("export 8"), "{e}");
    assert!(lands_entries(&w).is_empty());
}

/// Rewrites the delta header's `n` (the first frame).
fn renumber(bytes: &[u8], n: u32) -> Vec<u8> {
    let mut r = bytes;
    let mut out = Vec::new();
    if let Ok(Some(Frame::Json(mut v))) = read_frame(&mut r) {
        v["n"] = n.into();
        write_frame(&mut out, &Frame::Json(v)).unwrap();
        out.extend_from_slice(r);
        out
    } else {
        bytes.to_vec()
    }
}

#[test]
fn guest_err_frame_is_escaped() {
    let w = World::new();
    let b0 = manifest(&base_tree());
    w.answer(
        1,
        Answer::Err("cannot read \x1b[31mwork/\u{202e}evil\x07".into()),
    );
    let e = w.receive(&b0, 1).unwrap_err();
    let s = e.to_string();
    assert!(s.contains("could not export"), "{s}");
    assert!(s.contains("\\u{001B}") || s.contains("\\u{1b}"), "{s}");
    assert!(!s.chars().any(saiife_wire::text::is_unsafe_char), "{s:?}");
    assert!(!w.paths.land_dir(1).exists());
}

#[test]
fn export_past_total_deadline_is_refused() {
    let w = World::new();
    let b0 = manifest(&base_tree());
    w.answer(1, Answer::Drip(Duration::from_millis(100)));
    let t0 = Instant::now();
    let e = receive_within(
        &w.guest,
        &b1(),
        &w.paths,
        &b0,
        1,
        Duration::from_millis(900),
        Duration::from_millis(500),
    )
    .unwrap_err();
    assert!(e.reason.contains("export timeout"), "{e}");
    assert!(t0.elapsed() < Duration::from_secs(4), "{:?}", t0.elapsed());
    assert!(!w.paths.land_dir(1).exists());
    assert!(lands_entries(&w).is_empty());
}

#[test]
fn second_land_diffs_against_the_first() {
    let w = World::new();
    let t0 = base_tree();
    let b0 = manifest(&t0);
    let t1 = with(
        &t0,
        &[
            ("README.md", Some(C::f(b"# Demo v1\n"))),
            ("new.txt", Some(C::f(b"1\n"))),
        ],
    );
    let v1 = w.land(&b0, 1, &t0, &t1);
    let b1m = apply_manifest(&b0, &v1, None);
    assert_eq!(b1m, manifest(&t1));
    let t2 = with(&t1, &[("new.txt", Some(C::f(b"1\n2\n")))]);
    let v2 = w.land(&b1m, 2, &t1, &t2);
    let r2 = review(&b1(), &b1m, &v2, &w.blobs(2), None, &no_hits);
    let paths: Vec<&str> = r2.summary.files.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(paths, vec!["new.txt"]);
    assert!(
        r2.summary.unified.contains(" 1\n+2\n"),
        "{}",
        r2.summary.unified
    );
    // The same export against the spawn manifest does not validate.
    w.answer(3, Answer::Bytes(export(3, &t1, &t2)));
    let e = w.receive(&b0, 3).unwrap_err();
    assert!(
        e.reason.contains("base does not have") || e.reason.contains(BASE_MISMATCH),
        "{e}"
    );
}

#[test]
fn partial_land_keeps_the_rest() {
    let w = World::new();
    let t0 = base_tree();
    let b0 = manifest(&t0);
    let t1 = with(
        &t0,
        &[
            ("old.txt", Some(C::f(b"changed\n"))),
            ("run.sh", Some(C::f(b"#!/bin/sh\necho bye\n"))),
        ],
    );
    let v1 = w.land(&b0, 1, &t0, &t1);
    let only = set(&["old.txt"]);
    let r1 = review(&b1(), &b0, &v1, &w.blobs(1), Some(&only), &no_hits);
    write_land_files(&w.paths, &b0, &r1, Some(&only)).unwrap();
    let b1m = apply_manifest(&b0, &v1, Some(&only));
    // The guest advanced only old.txt: its next export is base1 → t1.
    let guest_base = with(&t0, &[("old.txt", Some(C::f(b"changed\n")))]);
    assert_eq!(b1m, manifest(&guest_base));
    let v2 = w.land(&b1m, 2, &guest_base, &t1);
    let r2 = review(&b1(), &b1m, &v2, &w.blobs(2), None, &no_hits);
    let paths: Vec<&str> = r2.summary.files.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(paths, vec!["run.sh"]);
}

#[test]
fn lying_advance_is_caught() {
    let w = World::new();
    let t0 = base_tree();
    let b0 = manifest(&t0);
    let t1 = with(
        &t0,
        &[
            ("old.txt", Some(C::f(b"changed\n"))),
            ("run.sh", Some(C::f(b"#!/bin/sh\necho bye\n"))),
        ],
    );
    let v1 = w.land(&b0, 1, &t0, &t1);
    let only = set(&["old.txt"]);
    let b1m = apply_manifest(&b0, &v1, Some(&only));
    // The guest "advanced" everything: run.sh's old side is from a base the
    // host never landed.
    let t2 = with(&t1, &[("run.sh", Some(C::f(b"#!/bin/sh\necho third\n")))]);
    w.answer(2, Answer::Bytes(export(2, &t1, &t2)));
    let e = w.receive(&b1m, 2).unwrap_err();
    assert_eq!(e.reason, BASE_MISMATCH);
    assert_eq!(e.path.as_deref(), Some("run.sh"));
    assert!(!w.paths.land_dir(2).exists());
    assert!(w.paths.land_dir(1).exists());
}

#[test]
fn inconsistent_subset_is_refused() {
    let w = World::new();
    let t0 = base_tree();
    let b0 = manifest(&t0);
    // old.txt (a file) becomes a directory: delete old.txt, add old.txt/x.
    let t1 = with(&t0, &[("old.txt", None), ("old.txt/x", Some(C::f(b"x\n")))]);
    let v = w.land(&b0, 1, &t0, &t1);
    let only = set(&["old.txt/x"]);
    let e = check_subset(&b0, &v, Some(&only)).unwrap_err();
    assert!(e.contains("select the change of \"old.txt\" too"), "{e}");
    let r = review(&b1(), &b0, &v, &w.blobs(1), Some(&only), &no_hits);
    let e = write_land_files(&w.paths, &b0, &r, Some(&only)).unwrap_err();
    assert!(e.contains("\"old.txt\""), "{e}");
    assert!(!w.paths.land_delta(1).exists());
    // The delete alone is a valid tree, and so is all of it.
    check_subset(&b0, &v, Some(&set(&["old.txt"]))).unwrap();
    check_subset(&b0, &v, Some(&set(&["old.txt", "old.txt/x"]))).unwrap();
    check_subset(&b0, &v, None).unwrap();
    // A path the delta does not have.
    let e = check_subset(&b0, &v, Some(&set(&["nope.txt"]))).unwrap_err();
    assert!(e.contains("\"nope.txt\" is not in the diff"), "{e}");
}

/// Collects blobs in memory for `Reader::paths_only`.
#[derive(Default)]
struct Mem {
    cur: Vec<u8>,
    done: BTreeMap<String, Vec<u8>>,
}

impl BlobSink for Mem {
    fn begin(&mut self) -> std::io::Result<()> {
        self.cur.clear();
        Ok(())
    }
    fn write(&mut self, b: &[u8]) -> std::io::Result<()> {
        self.cur.extend_from_slice(b);
        Ok(())
    }
    fn finish(&mut self, sha256: &str) -> std::io::Result<()> {
        self.done
            .insert(sha256.into(), std::mem::take(&mut self.cur));
        Ok(())
    }
}

#[test]
fn land_files_reread_with_paths_only() {
    let w = World::new();
    let t0 = base_tree();
    let b0 = manifest(&t0);
    let big = vec![b'z'; (1 << 20) + 17];
    let t1 = with(
        &t0,
        &[
            ("README.md", Some(C::f(b"# Demo v2\n"))),
            ("old.txt", None),
            ("big.bin", Some(C::f(&big))),
            ("ln", Some(C::l("README.md"))),
            ("empty", Some(C::f(b""))),
        ],
    );
    let v = w.land(&b0, 1, &t0, &t1);
    let r = review(&b1(), &b0, &v, &w.blobs(1), None, &no_hits);
    write_land_files(&w.paths, &b0, &r, None).unwrap();
    // Modes: dir 0700, files 0600.
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&w.paths.land_dir(1)), 0o700);
    assert_eq!(mode(&w.paths.land_blobs(1)), 0o700);
    assert_eq!(mode(&w.paths.land_delta(1)), 0o600);
    assert_eq!(mode(&w.paths.land_review(1)), 0o600);
    assert_eq!(mode(&w.paths.land_blob(1, &sha(&big))), 0o600);
    // review.json round-trips.
    let back: Review =
        serde_json::from_slice(&std::fs::read(w.paths.land_review(1)).unwrap()).unwrap();
    assert_eq!(back, r);
    // delta.bin is write_delta of the new content only, and paths_only
    // reads it back.
    let bin = std::fs::read(w.paths.land_delta(1)).unwrap();
    let it: Vec<(EntryHead, Option<Vec<u8>>)> = items(&t0, &t1)
        .into_iter()
        .map(|(mut h, _old, new)| {
            if h.op == Op::Modify {
                h.old_size = None;
            }
            (h, new)
        })
        .collect();
    let refs: Vec<DeltaItem<'_>> = it
        .iter()
        .map(|(h, n)| (h.clone(), None, n.as_deref()))
        .collect();
    let mut want = Vec::new();
    write_delta(&mut want, 1, &refs).unwrap();
    assert!(
        bin == want,
        "delta.bin is not the canonical write_delta output"
    );
    let mut sink = Mem::default();
    let mut rd = Reader::paths_only(Limits::default(), &mut sink);
    let mut s = bin.as_slice();
    while let Some(f) = read_frame(&mut s).unwrap() {
        rd.push(f).unwrap();
    }
    let back = rd.finish().unwrap();
    assert_eq!(
        back.entries
            .iter()
            .map(|h| h.path.as_str())
            .collect::<Vec<_>>(),
        v.entries
            .iter()
            .map(|h| h.path.as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(sink.done.get(&sha(&big)).map(Vec::len), Some(big.len()));
    assert_eq!(
        sink.done.get(&sha(b"README.md")).map(Vec::as_slice),
        Some(&b"README.md"[..])
    );
    // A partial selection writes only the selected entries; a rewrite of
    // the same land replaces the files.
    let only = set(&["README.md"]);
    let rs = review(&b1(), &b0, &v, &w.blobs(1), Some(&only), &no_hits);
    write_land_files(&w.paths, &b0, &rs, Some(&only)).unwrap();
    let bin = std::fs::read(w.paths.land_delta(1)).unwrap();
    let mut sink = Mem::default();
    let mut rd = Reader::paths_only(Limits::default(), &mut sink);
    let mut sl = bin.as_slice();
    while let Some(f) = read_frame(&mut sl).unwrap() {
        rd.push(f).unwrap();
    }
    assert_eq!(rd.finish().unwrap().entries.len(), 1);
}

#[test]
fn subset_through_folded_symlink_is_refused() {
    // check_subset folds like the validator (R-T3i): a hand-made delta
    // writing under a Unicode spelling of the base symlink `links`.
    let t0 = with(&base_tree(), &[("links", Some(C::l("src")))]);
    let b0 = manifest(&t0);
    let p = "lin\u{212A}s/x";
    let v = Valid {
        n: 1,
        entries: vec![add_head(p, &C::f(b"x\n"))],
    };
    let e = check_subset(&b0, &v, Some(&set(&[p]))).unwrap_err();
    assert!(e.contains("through a symlink"), "{e}");
    // R-T3l: full case fold and a base link committed decomposed;
    // R-T3n: spellings only the round-trip fold joins.
    let t0 = with(
        &base_tree(),
        &[
            ("strasse", Some(C::l("src"))),
            ("\u{3C3}\u{3C3}", Some(C::l("src"))),
            ("Cafe\u{301}", Some(C::l("src"))),
            ("files", Some(C::l("src"))),
            ("\u{3BC}", Some(C::l("src"))),
            ("\u{3B1}\u{3B9}", Some(C::l("src"))),
        ],
    );
    let b0 = manifest(&t0);
    for p in [
        "STRA\u{1E9E}E/x",
        "\u{3C3}\u{3C2}/x",
        "CAF\u{C9}/x",
        "\u{FB01}les/x",
        "\u{B5}/x",
        "\u{1FB3}/x",
    ] {
        let v = Valid {
            n: 1,
            entries: vec![add_head(p, &C::f(b"x\n"))],
        };
        let e = check_subset(&b0, &v, Some(&set(&[p]))).unwrap_err();
        assert!(e.contains("through a symlink"), "{p}: {e}");
    }
}

#[test]
fn existing_land_is_not_replaced() {
    let w = World::new();
    let t0 = base_tree();
    let b0 = manifest(&t0);
    let t1 = with(&t0, &[("a.txt", Some(C::f(b"a\n")))]);
    w.land(&b0, 1, &t0, &t1);
    let e = w.receive(&b0, 1).unwrap_err();
    assert!(e.reason.contains("already exists"), "{e}");
    assert!(w.paths.land_blob(1, &sha(b"a\n")).exists());
    // Only the setup and one export reached the guest.
    let exports = w
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|r| matches!(r, Request::Export { .. }))
        .count();
    assert_eq!(exports, 1);
}

#[test]
fn git_config_paths() {
    for p in [
        ".gitattributes",
        "a/b/.gitattributes",
        ".gitmodules",
        ".gitconfig",
        ".lfsconfig",
        "sub/.lfsconfig",
        ".LfsConfig",
        ".G\u{130}TATTRIBUTES",
        ".gitattributes.",
        ".gitattributes/x",
        "a/.gitconfig",
        ".github",
        "a/.gitkeep",
    ] {
        assert!(git_config(p), "{p}");
        assert!(protected(p), "{p}");
    }
    for p in [
        ".gitignore",
        "a/.gitignore",
        "CLAUDE.md",
        "src/lfsconfig",
        "x.git",
    ] {
        assert!(!git_config(p), "{p}");
    }
    // R-T6f: a `.git*` directory is not git config, only protected.
    for p in [
        ".github/workflows/ci.yml",
        ".github/CODEOWNERS",
        ".gitignore/x",
        ".gitlab/ci.yml",
    ] {
        assert!(!git_config(p), "{p}");
        assert!(protected(p), "{p}");
    }
}
