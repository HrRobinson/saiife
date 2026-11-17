//! `saiife box diff | land | apply | push` (plan 39 Task 6) and the land
//! commit, with real git in a temp repo (no global or system config).
//!
//! The daemon is a stub on the control socket: the CLI's daemon in a
//! `fake-vmm` build has no land book (production never attaches one before
//! plan 35/31, Task 4 ruling R-T4a), so `box.land*` would answer
//! `unavailable`. The stub speaks the op shapes of Task 5 (task-5-report)
//! and hands real `delta.bin` files written with `write_delta`; the daemon
//! side of those ops is tested in `crates/daemon/tests/box_land.rs`. The
//! box's base ref comes from a real `saiife box spawn` against the stub
//! (plan 37's snapshot commit).
#![cfg(unix)]

mod common;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use common::daemon::{Opts, TestDaemon};
use saiife_boxproto::delta::{write_delta, EntryHead, Op};
use saiife_boxproto::manifest::EntryKind;
use saiife_ipc::frame::{read_frame, write_frame};
use saiife_ipc::msg::{err_with, ok, ErrorCode, Request};
use saiife_touch::soft::SoftAuthenticator;
use saiife_touch::TouchRequest;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------- stub

#[derive(Default)]
struct State {
    /// Every op the stub answered, with its arguments.
    seen: Vec<(String, Value)>,
    /// Approved lands: `n` -> (`LandInfo` JSON, its delta.bin).
    lands: BTreeMap<u32, (Value, PathBuf)>,
    /// The approved lands not applied yet.
    waiting: Vec<u32>,
    /// The land `box.land` approves.
    next: Option<u32>,
    /// `box.land.applied` fails this many times first.
    applied_fails: u32,
    /// `box.diff`'s answer.
    diff: Map<String, Value>,
    /// The soft key's credential id.
    credential: Vec<u8>,
    /// The box's repo display name (`box.list`).
    repo: String,
    /// The git-config paths of the next land (R-T6e): `box.land.begin`
    /// refuses them without `allow_git_config`, as the daemon does.
    git_config: Vec<String>,
}

#[derive(Clone)]
struct Stub(Arc<Mutex<State>>);

impl Stub {
    fn start(dir: &Path) -> Stub {
        fs::create_dir_all(dir).unwrap();
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
        let l = UnixListener::bind(dir.join("saiife.sock")).unwrap();
        let stub = Stub(Arc::new(Mutex::new(State::default())));
        let s = stub.clone();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let s = s.clone();
                std::thread::spawn(move || s.serve(c));
            }
        });
        stub
    }

    fn serve(&self, mut c: UnixStream) {
        while let Ok(m) = read_frame(&mut c) {
            let Ok(req) = Request::from_map(m) else {
                return;
            };
            let (answer, fd) = self.answer(&req, &c);
            if write_frame(&mut c, &answer).is_err() {
                return;
            }
            if let Some(f) = fd {
                saiife_ipc::fdpass::send_fds(&c, &[f.as_fd()]).unwrap();
            }
        }
    }

    fn answer(&self, req: &Request, c: &UnixStream) -> (Value, Option<fs::File>) {
        let id = req.id;
        let a = &req.args;
        let mut st = self.0.lock().unwrap();
        st.seen.push((req.op.clone(), Value::Object(a.clone())));
        let refuse = |code, m: &str| {
            let mut x = Map::new();
            x.insert("rule".into(), "invalid".into());
            (err_with(id, code, m, x), None)
        };
        let obj = |v: Value| match v {
            Value::Object(m) => m,
            _ => Map::new(),
        };
        let touch = |st: &State| {
            serde_json::to_value(TouchRequest {
                rp_id: saiife_touch::LOCAL_RP_ID.into(),
                challenge: [7; 32],
                allow: vec![st.credential.clone()],
                uv: true,
                summary: "land b1".into(),
                short_code: "123456".into(),
            })
            .unwrap()
        };
        match req.op.as_str() {
            "hello" => (ok(id, obj(json!({"proto": 1, "mode": "locked"}))), None),
            "box.fds" => {
                let n = a["n"].as_u64().unwrap() as usize;
                drop(st);
                saiife_ipc::fdpass::recv_fds(c, n).unwrap();
                (ok(id, Map::new()), None)
            }
            "box.spawn" => (
                ok(id, obj(json!({"box": {"id": "b1", "state": "running"}}))),
                None,
            ),
            "box.list" => (
                ok(
                    id,
                    obj(
                        json!({"boxes": [{"id": "b1", "state": "landed", "repo": st.repo,
                        "template": "bash", "task": "t", "created_at": 0, "lands": 1}],
                        "slots_total": 1, "slots_free": 0}),
                    ),
                ),
                None,
            ),
            "box.discard" => (ok(id, obj(json!({"box": {"id": "b1"}}))), None),
            "box.diff" => (ok(id, st.diff.clone()), None),
            "box.land.fetch" => match a.get("n").and_then(Value::as_u64) {
                None => (
                    ok(id, obj(json!({"waiting": st.waiting, "unreadable": 0}))),
                    None,
                ),
                Some(n) if st.waiting.contains(&(n as u32)) => {
                    let (info, delta) = st.lands[&(n as u32)].clone();
                    (
                        ok(id, obj(json!({"land": info}))),
                        Some(fs::File::open(delta).unwrap()),
                    )
                }
                Some(n) => refuse(
                    ErrorCode::BadRequest,
                    &format!("land {n} of box b1 is not an approved land waiting to be applied"),
                ),
            },
            "box.land.applied" => {
                if st.applied_fails > 0 {
                    st.applied_fails -= 1;
                    return refuse(ErrorCode::Unavailable, "cannot record the apply: disk full");
                }
                let n = a["n"].as_u64().unwrap() as u32;
                st.waiting.retain(|w| *w != n);
                (ok(id, Map::new()), None)
            }
            "box.land.begin" => {
                if !st.git_config.is_empty() && a.get("allow_git_config") != Some(&json!(true)) {
                    return refuse(
                        ErrorCode::BadRequest,
                        &format!(
                            "land b1 changes git config ({}), which git and your filters read once it is checked out; review it, then run: saiife box land b1 --allow-git-config",
                            st.git_config.join(", ")
                        ),
                    );
                }
                let n = st.next.unwrap();
                let review = json!({"n": n, "flags": [{"path": "CLAUDE.md", "why": "protected path"}],
                    "entries": [], "base_head": null, "git_config": st.git_config});
                let diff = st.diff.get("diff").cloned().unwrap_or(Value::Null);
                (
                    ok(
                        id,
                        obj(json!({"request_id": "4294967297", "touch": touch(&st),
                            "expires_at": 1, "review": review, "diff": diff})),
                    ),
                    None,
                )
            }
            "box.land" => {
                assert!(a["assertion"].is_object(), "{a:?}");
                let n = st.next.take().unwrap();
                st.waiting.push(n);
                let (info, delta) = st.lands[&n].clone();
                (
                    ok(id, obj(json!({"land": info}))),
                    Some(fs::File::open(delta).unwrap()),
                )
            }
            "box.push.begin" => (
                ok(
                    id,
                    obj(json!({"request_id": "4294967298", "touch": touch(&st), "expires_at": 1})),
                ),
                None,
            ),
            "box.push" => {
                assert!(a["assertion"].is_object(), "{a:?}");
                (ok(id, Map::new()), None)
            }
            "box.push.done" => (ok(id, Map::new()), None),
            other => refuse(ErrorCode::BadRequest, &format!("stub: no op {other}")),
        }
    }

    fn seen(&self) -> Vec<(String, Value)> {
        self.0.lock().unwrap().seen.clone()
    }

    fn ops(&self) -> Vec<String> {
        self.seen().into_iter().map(|(o, _)| o).collect()
    }

    fn applied(&self) -> Vec<(u64, String)> {
        self.seen()
            .into_iter()
            .filter(|(o, _)| o == "box.land.applied")
            .map(|(_, a)| {
                (
                    a["n"].as_u64().unwrap(),
                    a["commit"].as_str().unwrap().into(),
                )
            })
            .collect()
    }
}

// ---------------------------------------------------------------- world

struct W {
    d: TestDaemon,
    stub: Stub,
    base: String,
}

fn exec(p: &Path, body: &str) {
    fs::write(p, body).unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(0o755)).unwrap();
}

fn git_env(c: &mut Command, d: &TestDaemon) {
    c.env("HOME", d.path().join("home"))
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1");
}

fn git_raw(d: &TestDaemon, dir: &Path, args: &[&str]) -> Output {
    let mut c = Command::new("/usr/bin/git");
    c.arg("-C").arg(dir).args(args);
    git_env(&mut c, d);
    c.output().unwrap()
}

fn git_in(d: &TestDaemon, dir: &Path, args: &[&str]) -> String {
    let o = git_raw(d, dir, args);
    assert!(
        o.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).trim_end().to_string()
}

fn sha(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

impl W {
    fn project(&self) -> PathBuf {
        fs::canonicalize(self.d.path().join("project")).unwrap()
    }

    fn git(&self, args: &[&str]) -> String {
        git_in(&self.d, &self.project(), args)
    }

    fn wt(&self) -> PathBuf {
        self.d.path().join("data-home/saiife/worktrees/project-b1")
    }

    fn tip(&self) -> String {
        self.git(&["rev-parse", "refs/heads/saiife/box-b1"])
    }

    fn key(&self) -> PathBuf {
        self.d.path().join("key.json")
    }

    fn cmd(&self, args: &[&str], soft: bool) -> Command {
        let d = &self.d;
        let mut c = Command::new(env!("CARGO_BIN_EXE_saiife"));
        git_env(&mut c, d);
        c.arg("box")
            .arg("--system-config")
            .arg(d.config())
            .args(args)
            .env("XDG_CACHE_HOME", d.path().join("cache"))
            .env("XDG_DATA_HOME", d.path().join("data-home"))
            .env("SAIIFE_TOOL_MKE2FS", d.path().join("bin/mke2fs"))
            .env("XDG_RUNTIME_DIR", d.path().join("no-runtime"))
            .env("XDG_CONFIG_HOME", d.path().join("home/.config"))
            .env("PATH", "/usr/bin:/bin")
            .env("DBUS_SESSION_BUS_ADDRESS", d.path().join("no-bus"))
            .env("SAIIFE_DATA_DIR", d.path().join("data"))
            .env("SAIIFE_AUDIT_DIR", d.audit_dir())
            .env_remove("SAIIFE_TEST_TOUCH_SOFT")
            .env_remove("SAIIFE_TEST_FIDO_HELPER")
            .current_dir(self.project())
            .stdin(Stdio::null());
        if soft {
            c.env("SAIIFE_TEST_TOUCH_SOFT", self.key());
        }
        c
    }

    fn bx(&self, args: &[&str]) -> Output {
        self.cmd(args, true).output().unwrap()
    }

    /// A delta.bin of land `n`: `(head, new content)` per entry.
    fn delta(&self, n: u32, mut items: Vec<(EntryHead, Option<Vec<u8>>)>) -> PathBuf {
        items.sort_by(|a, b| a.0.path.as_bytes().cmp(b.0.path.as_bytes()));
        let refs: Vec<_> = items
            .iter()
            .map(|(h, c)| (h.clone(), None, c.as_deref()))
            .collect();
        let mut buf = Vec::new();
        write_delta(&mut buf, n, &refs).unwrap();
        let p = self.d.path().join(format!("deltas/{n}.bin"));
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, buf).unwrap();
        p
    }

    fn info(&self, n: u32, task: &str) -> Value {
        json!({"id": "b1", "n": n, "target_ref": "saiife/box-b1", "base_commit": self.base,
            "diff_sha256": sha(format!("land {n}").as_bytes()), "task": task,
            "repo_dir": self.project().to_string_lossy()})
    }

    /// Land `n`, approved and waiting for `saiife box apply`.
    fn approved(&self, n: u32, items: Vec<(EntryHead, Option<Vec<u8>>)>) {
        let info = self.info(n, "make it better\nsecond line");
        self.approved_as(n, info, items);
    }

    fn approved_as(&self, n: u32, info: Value, items: Vec<(EntryHead, Option<Vec<u8>>)>) {
        let p = self.delta(n, items);
        let mut st = self.stub.0.lock().unwrap();
        st.lands.insert(n, (info, p));
        st.waiting.push(n);
    }

    /// Land `n`, approved by the next `box.land`.
    fn next(&self, n: u32, items: Vec<(EntryHead, Option<Vec<u8>>)>) {
        let info = self.info(n, "make it better");
        let p = self.delta(n, items);
        let mut st = self.stub.0.lock().unwrap();
        st.lands.insert(n, (info, p));
        st.next = Some(n);
    }

    fn apply_ok(&self) -> String {
        let o = self.bx(&["apply", "b1"]);
        assert_eq!(code(&o), 0, "{}{}", out(&o), err(&o));
        out(&o)
    }

    /// `git ls-tree -r` of `rev`: path -> (mode, oid).
    fn tree(&self, rev: &str) -> BTreeMap<String, (String, String)> {
        self.git(&["ls-tree", "-r", "--full-tree", rev])
            .lines()
            .map(|l| {
                let (head, path) = l.split_once('\t').unwrap();
                let f: Vec<&str> = head.split(' ').collect();
                (path.to_string(), (f[0].to_string(), f[2].to_string()))
            })
            .collect()
    }

    fn blob(&self, content: &[u8]) -> String {
        let mut c = Command::new("/usr/bin/git");
        c.arg("-C")
            .arg(self.project())
            .args(["hash-object", "--no-filters", "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        git_env(&mut c, &self.d);
        let mut ch = c.spawn().unwrap();
        use std::io::Write;
        ch.stdin.take().unwrap().write_all(content).unwrap();
        String::from_utf8(ch.wait_with_output().unwrap().stdout)
            .unwrap()
            .trim()
            .to_string()
    }
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap()
}
fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn file(path: &str, op: Op, mode: u32, content: &[u8]) -> (EntryHead, Option<Vec<u8>>) {
    let modify = op == Op::Modify;
    (
        EntryHead {
            path: path.into(),
            op,
            kind: EntryKind::File,
            mode,
            size: content.len() as u64,
            sha256: sha(content),
            old_kind: modify.then_some(EntryKind::File),
            // R-T3d: delta.bin's modify heads carry no old size.
            old_size: None,
            old_sha256: modify.then(|| "0".repeat(64)),
        },
        Some(content.to_vec()),
    )
}

fn link(path: &str, op: Op, old: Option<EntryKind>, target: &str) -> (EntryHead, Option<Vec<u8>>) {
    (
        EntryHead {
            path: path.into(),
            op,
            kind: EntryKind::Symlink,
            mode: 0,
            size: target.len() as u64,
            sha256: sha(target.as_bytes()),
            old_kind: old,
            old_size: None,
            old_sha256: (op == Op::Modify).then(|| "0".repeat(64)),
        },
        Some(target.as_bytes().to_vec()),
    )
}

fn delete(path: &str, kind: EntryKind) -> (EntryHead, Option<Vec<u8>>) {
    (
        EntryHead {
            path: path.into(),
            op: Op::Delete,
            kind: kind.clone(),
            mode: 0,
            size: 0,
            sha256: String::new(),
            old_kind: Some(kind),
            old_size: Some(1),
            old_sha256: Some("0".repeat(64)),
        },
        None,
    )
}

/// A repo with a few files, a stub daemon, and box b1 spawned from it
/// (the base ref is plan 37's snapshot commit).
fn world() -> W {
    let d = TestDaemon::prepare(&Opts::default());
    let stub = Stub::start(&d.socket_dir());
    let project = d.path().join("project");
    fs::create_dir_all(project.join("src")).unwrap();
    fs::create_dir_all(project.join("docs")).unwrap();
    fs::write(project.join("README"), "hello\n").unwrap();
    fs::write(project.join("src/main.rs"), "fn main() {}\n").unwrap();
    fs::write(project.join("docs/a.txt"), "a\n").unwrap();
    fs::write(project.join("old.txt"), "old\n").unwrap();
    fs::write(project.join("script.sh"), "echo hi\n").unwrap();
    fs::create_dir_all(d.path().join("bin")).unwrap();
    exec(
        &d.path().join("bin/mke2fs"),
        "#!/bin/sh\nfor a; do img=$last; last=$a; done\n\
         head -c 1080 /dev/zero > \"$img\" && printf '\\123\\357' >> \"$img\" \
         && head -c 4096 /dev/zero >> \"$img\"\n",
    );
    let (_, pkcs8, cred, counter) = SoftAuthenticator::new_es256().parts();
    fs::write(
        d.path().join("key.json"),
        json!({"alg": "es256", "pkcs8": URL_SAFE_NO_PAD.encode(pkcs8),
            "credential_id": URL_SAFE_NO_PAD.encode(&cred), "counter": counter})
        .to_string(),
    )
    .unwrap();
    {
        let mut st = stub.0.lock().unwrap();
        st.credential = cred;
        st.repo = "project".into();
    }
    let mut w = W {
        d,
        stub,
        base: String::new(),
    };
    w.git(&["init", "-q", "-b", "main"]);
    w.git(&["config", "user.name", "Test User"]);
    w.git(&["config", "user.email", "test@example.invalid"]);
    w.git(&["add", "-A"]);
    w.git(&["commit", "-q", "-m", "first"]);
    let o = w.bx(&["spawn", "--template", "bash", "--task", "make it better"]);
    assert_eq!(code(&o), 0, "{}{}", out(&o), err(&o));
    w.base = w.git(&["rev-parse", "refs/saiife/box-b1/base"]);
    w
}

// ---------------------------------------------------------------- tests

#[test]
fn build_commit_tree_is_exact() {
    let w = world();
    let before = w.tree(&w.base);
    w.approved(
        1,
        vec![
            file("README", Op::Modify, 0o644, b"hello world\n"),
            file("new/file.txt", Op::Add, 0o644, b"new\n"),
            delete("old.txt", EntryKind::File),
        ],
    );
    let o = w.apply_ok();
    let tip = w.tip();
    assert!(
        o.contains(&format!("applied b1 #1: {tip} on saiife/box-b1\n")),
        "{o}"
    );
    let mut want = before.clone();
    want.insert("README".into(), ("100644".into(), w.blob(b"hello world\n")));
    want.insert("new/file.txt".into(), ("100644".into(), w.blob(b"new\n")));
    want.remove("old.txt");
    assert_eq!(w.tree(&tip), want);
    // One commit on the base, with the fixed message.
    assert_eq!(w.git(&["rev-parse", &format!("{tip}^")]), w.base);
    let msg = w.git(&["cat-file", "commit", &tip]);
    let body = msg.split_once("\n\n").unwrap().1;
    assert_eq!(
        format!("{body}\n"),
        format!(
            "saiife box b1: land 1\n\nmake it better\n\nSaiife-Box: b1\nSaiife-Land: 1\nSaiife-Diff-Sha256: {}\n",
            sha(b"land 1")
        )
    );
    assert_eq!(w.stub.applied(), vec![(1, tip)]);
    // The user's own checkout is untouched.
    assert_eq!(w.git(&["rev-parse", "--abbrev-ref", "HEAD"]), "main");
    assert_eq!(
        fs::read_to_string(w.project().join("README")).unwrap(),
        "hello\n"
    );
    assert_eq!(w.git(&["status", "--porcelain"]), "");
}

#[test]
fn deletes_and_symlinks_and_modes() {
    let w = world();
    w.approved(
        1,
        vec![
            delete("docs/a.txt", EntryKind::File),
            link("ln", Op::Add, None, "README"),
            file("script.sh", Op::Modify, 0o755, b"echo hi\n"),
            link(
                "src/main.rs",
                Op::Modify,
                Some(EntryKind::File),
                "../README",
            ),
        ],
    );
    w.apply_ok();
    let t = w.tree(&w.tip());
    assert!(!t.contains_key("docs/a.txt"), "{t:?}");
    assert_eq!(t["ln"], ("120000".into(), w.blob(b"README")));
    assert_eq!(t["script.sh"], ("100755".into(), w.blob(b"echo hi\n")));
    assert_eq!(t["src/main.rs"], ("120000".into(), w.blob(b"../README")));
    // Nothing was checked out (R-T6d).
    assert!(!w.wt().exists());
}

#[test]
fn first_land_creates_branch() {
    let w = world();
    w.next(3, vec![file("README", Op::Modify, 0o644, b"landed\n")]);
    let o = w.bx(&["land", "b1"]);
    assert_eq!(code(&o), 0, "{}{}", out(&o), err(&o));
    let tip = w.tip();
    assert!(
        err(&o).contains("touch your key to land box b1 (code 123456)"),
        "{}",
        err(&o)
    );
    assert!(
        out(&o).contains("! CLAUDE.md: protected path"),
        "{}",
        out(&o)
    );
    assert!(
        out(&o).contains(&format!("landed b1 #3: {tip} on saiife/box-b1\n")),
        "{}",
        out(&o)
    );
    assert!(
        out(&o).contains(&format!(
            "to check it out: git -C {} worktree add --detach {} saiife/box-b1",
            w.project().display(),
            w.wt().display()
        )),
        "{}",
        out(&o)
    );
    assert_eq!(w.tree(&tip)["README"].1, w.blob(b"landed\n"));
    assert!(!w.wt().exists(), "saiife checks nothing out");
    let ops = w.stub.ops();
    let i = |op: &str| ops.iter().position(|o| o == op).unwrap();
    assert!(i("box.land.fetch") < i("box.land.begin"), "{ops:?}");
    assert!(i("box.land.begin") < i("box.land"), "{ops:?}");
    assert_eq!(w.stub.applied(), vec![(3, tip)]);
    // The main checkout is where it was.
    assert_eq!(w.git(&["rev-parse", "--abbrev-ref", "HEAD"]), "main");
    assert_eq!(
        fs::read_to_string(w.project().join("README")).unwrap(),
        "hello\n"
    );
}

#[test]
fn second_land_advances_the_branch() {
    let w = world();
    w.approved(1, vec![file("README", Op::Modify, 0o644, b"one\n")]);
    w.apply_ok();
    let first = w.tip();
    w.approved(2, vec![file("README", Op::Modify, 0o644, b"two\n")]);
    w.apply_ok();
    let second = w.tip();
    assert_ne!(first, second);
    assert_eq!(w.git(&["rev-parse", &format!("{second}^")]), first);
    assert_eq!(w.tree(&second)["README"].1, w.blob(b"two\n"));
    assert_eq!(w.stub.applied(), vec![(1, first), (2, second)]);
}

#[test]
fn existing_worktree_is_not_touched() {
    let w = world();
    w.approved(1, vec![file("README", Op::Modify, 0o644, b"one\n")]);
    w.apply_ok();
    let first = w.tip();
    // The user checks it out as told (detached: the branch stays movable).
    let wt = w.wt().to_str().unwrap().to_string();
    w.git(&["worktree", "add", "-q", "--detach", &wt, "saiife/box-b1"]);
    w.approved(2, vec![file("README", Op::Modify, 0o644, b"two\n")]);
    let o = w.apply_ok();
    let second = w.tip();
    assert_eq!(w.git(&["rev-parse", &format!("{second}^")]), first);
    assert!(
        o.contains(&format!(
            "the worktree {wt} is not updated; to update it: git -C {wt} merge --ff-only saiife/box-b1"
        )),
        "{o}"
    );
    assert_eq!(fs::read_to_string(w.wt().join("README")).unwrap(), "one\n");
    assert_eq!(git_in(&w.d, &w.wt(), &["rev-parse", "HEAD"]), first);
    git_in(
        &w.d,
        &w.wt(),
        &["merge", "-q", "--ff-only", "saiife/box-b1"],
    );
    assert_eq!(fs::read_to_string(w.wt().join("README")).unwrap(), "two\n");
}

#[test]
fn checked_out_branch_is_not_moved() {
    let w = world();
    w.approved(1, vec![file("README", Op::Modify, 0o644, b"one\n")]);
    w.apply_ok();
    let first = w.tip();
    let co = w.d.path().join("co");
    w.git(&[
        "worktree",
        "add",
        "-q",
        co.to_str().unwrap(),
        "saiife/box-b1",
    ]);
    w.approved(2, vec![file("README", Op::Modify, 0o644, b"two\n")]);
    let o = w.bx(&["apply", "b1"]);
    assert_eq!(code(&o), 1, "{}{}", out(&o), err(&o));
    let kept = w.git(&["rev-parse", "refs/saiife/box-b1/land-2"]);
    assert_eq!(w.git(&["rev-parse", &format!("{kept}^")]), first);
    let co = fs::canonicalize(&co).unwrap();
    assert!(
        err(&o).contains(&format!("git -C {} merge --ff-only {kept}", co.display())),
        "{}",
        err(&o)
    );
    assert_eq!(w.tip(), first, "the branch did not move");
    assert_eq!(fs::read_to_string(co.join("README")).unwrap(), "one\n");
    assert_eq!(w.stub.applied().len(), 1);
    // The user fast-forwards it; the next apply records the same commit.
    git_in(&w.d, &co, &["merge", "-q", "--ff-only", &kept]);
    w.apply_ok();
    assert_eq!(w.tip(), kept);
    assert_eq!(w.stub.applied()[1], (2, kept));
}

#[test]
fn apply_refuses_moved_branch() {
    let w = world();
    w.approved(1, vec![file("README", Op::Modify, 0o644, b"one\n")]);
    w.apply_ok();
    w.git(&["commit", "-q", "--allow-empty", "-m", "elsewhere"]);
    let other = w.git(&["rev-parse", "HEAD"]);
    w.git(&["update-ref", "refs/heads/saiife/box-b1", &other]);
    w.approved(2, vec![file("README", Op::Modify, 0o644, b"two\n")]);
    let o = w.bx(&["apply", "b1"]);
    assert_eq!(code(&o), 2, "{}{}", out(&o), err(&o));
    assert!(err(&o).contains("saiife/box-b1 has moved"), "{}", err(&o));
    assert!(
        err(&o).contains("git branch -f saiife/box-b1"),
        "{}",
        err(&o)
    );
    assert_eq!(w.tip(), other);
    assert_eq!(w.stub.applied().len(), 1);
}

#[test]
fn apply_twice_is_ok_once() {
    let w = world();
    w.stub.0.lock().unwrap().applied_fails = 1;
    w.approved(1, vec![file("README", Op::Modify, 0o644, b"one\n")]);
    let o = w.bx(&["apply", "b1"]);
    assert_eq!(code(&o), 5, "{}{}", out(&o), err(&o));
    assert!(err(&o).contains("did not record it"), "{}", err(&o));
    let first = w.tip();
    // Again: the land is on the branch already; recorded, not written twice.
    let o = w.apply_ok();
    assert!(o.contains(&format!("applied b1 #1: {first}")), "{o}");
    assert_eq!(w.tip(), first);
    assert_eq!(
        w.git(&["rev-list", "--count", &format!("{}..{first}", w.base)]),
        "1"
    );
    assert_eq!(w.stub.applied(), vec![(1, first.clone()), (1, first)]);
    let o = w.apply_ok();
    assert!(o.contains("nothing to apply for box b1"), "{o}");
}

#[test]
fn missing_base_ref_is_recreated() {
    let w = world();
    w.git(&["update-ref", "-d", "refs/saiife/box-b1/base"]);
    w.approved(1, vec![file("README", Op::Modify, 0o644, b"one\n")]);
    w.apply_ok();
    assert_eq!(w.git(&["rev-parse", "refs/saiife/box-b1/base"]), w.base);
    assert_eq!(w.git(&["rev-parse", &format!("{}^", w.tip())]), w.base);
}

#[test]
fn gc_d_base_commit_fails_clearly() {
    let w = world();
    w.git(&["update-ref", "-d", "refs/saiife/box-b1/base"]);
    let gone = "1234567890abcdef1234567890abcdef12345678";
    let mut info = w.info(1, "t");
    info["base_commit"] = gone.into();
    w.approved_as(1, info, vec![file("README", Op::Modify, 0o644, b"one\n")]);
    let o = w.bx(&["apply", "b1"]);
    assert_eq!(code(&o), 2, "{}{}", out(&o), err(&o));
    assert!(
        err(&o).contains(&format!(
            "the box's base commit {gone} is no longer in {} (its base ref was deleted and git gc removed it); this land cannot be applied",
            w.project().display()
        )),
        "{}",
        err(&o)
    );
    assert!(w.git(&["for-each-ref", "refs/heads/saiife"]).is_empty());
    assert!(w.stub.applied().is_empty());
}

#[test]
fn no_user_hook_runs() {
    let w = world();
    let marks = w.d.path().join("marks");
    fs::create_dir_all(&marks).unwrap();
    let hooks = w.project().join(".git/hooks");
    fs::create_dir_all(&hooks).unwrap();
    for h in [
        "pre-commit",
        "post-commit",
        "post-checkout",
        "post-merge",
        "pre-push",
        "reference-transaction",
        "post-index-change",
    ] {
        exec(
            &hooks.join(h),
            &format!("#!/bin/sh\ntouch {}\n", marks.join(h).display()),
        );
    }
    // A worktree add (post-checkout), a fast-forward (post-merge) and a push.
    w.next(1, vec![file("README", Op::Modify, 0o644, b"one\n")]);
    let o = w.bx(&["land", "b1"]);
    assert_eq!(code(&o), 0, "{}{}", out(&o), err(&o));
    w.approved(2, vec![file("README", Op::Modify, 0o644, b"two\n")]);
    w.apply_ok();
    let bare = w.d.path().join("remote.git");
    git_in(
        &w.d,
        w.d.path(),
        &["init", "-q", "--bare", bare.to_str().unwrap()],
    );
    let o = w.bx(&["push", "b1", "--remote", bare.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "{}{}", out(&o), err(&o));
    let ran: Vec<_> = fs::read_dir(&marks)
        .unwrap()
        .flatten()
        .map(|e| e.file_name())
        .collect();
    assert!(ran.is_empty(), "hooks ran: {ran:?}");
    // The hooks are live for git itself.
    w.git(&["commit", "-q", "--allow-empty", "-m", "x"]);
    assert!(marks.join("pre-commit").exists());
}

#[test]
fn box_attributes_add_no_filter() {
    let w = world();
    let raw = b"a\r\nb\r\n";
    w.approved(
        1,
        vec![
            file(
                ".gitattributes",
                Op::Add,
                0o644,
                b"* filter=evil text eol=lf\n",
            ),
            file("x.txt", Op::Add, 0o644, raw),
        ],
    );
    w.apply_ok();
    let t = w.tree(&w.tip());
    assert_eq!(t["x.txt"].1, w.blob(raw));
    let o = git_raw(&w.d, &w.project(), &["cat-file", "blob", &t["x.txt"].1]);
    assert_eq!(o.stdout, raw);
}

fn hostile_diff() -> Map<String, Value> {
    let p = "a\u{202e}b.txt";
    json!({
        "diff": {"id": "b1", "base_commit": "c".repeat(40), "diff_sha256": "d".repeat(64),
            "files": [{"path": p, "status": "added", "added": 1, "removed": 0, "binary": false}],
            "unified": format!("diff --saiife a/{p} b/{p}\n+x\u{202e}y\u{1b}[31m\n"),
            "truncated": false, "tests": null},
        "review": {"n": 1, "flags": [{"path": p, "why": "new \u{202e}file"}],
            "entries": [{"path": p, "op": "add", "kind": "file", "mode": 420, "size": 4,
                "sha256": "e".repeat(64), "old_kind": null, "old_size": null, "old_sha256": null}],
            "base_head": null}
    })
    .as_object()
    .unwrap()
    .clone()
}

#[test]
fn diff_output_is_sanitized() {
    let w = world();
    w.stub.0.lock().unwrap().diff = hostile_diff();
    for args in [&["diff", "b1"][..], &["diff", "b1", "--stat"][..]] {
        let o = w.bx(args);
        assert_eq!(code(&o), 0, "{}{}", out(&o), err(&o));
        let s = out(&o);
        assert!(!s.contains('\u{202e}') && !s.contains('\u{1b}'), "{s}");
        assert!(s.contains("a\\u{202E}b.txt"), "{s}");
    }
    let o = w.bx(&["diff", "b1", "--json"]);
    let s = out(&o);
    assert!(s.is_ascii(), "{s}");
    let v: Value = serde_json::from_str(&s).unwrap();
    assert_eq!(Value::Object(hostile_diff()), v);
}

/// FU1: a flagged box's `box diff` warns first (text); `--json` carries
/// the guard object; an unflagged one prints no warning.
#[test]
fn diff_warns_when_guard_skipped() {
    let w = world();
    let mut d = hostile_diff();
    d.insert(
        "guard".into(),
        json!({"skipped": true, "checks": 0, "turns": 2}),
    );
    w.stub.0.lock().unwrap().diff = d.clone();
    let o = w.bx(&["diff", "b1"]);
    assert_eq!(code(&o), 0, "{}{}", out(&o), err(&o));
    let first = out(&o).lines().next().unwrap_or("").to_string();
    assert!(
        first.starts_with("warning: guard_skipped: the box changed files"),
        "{first}"
    );
    let v: Value = serde_json::from_str(&out(&w.bx(&["diff", "b1", "--json"]))).unwrap();
    assert_eq!(
        v["guard"],
        json!({"skipped": true, "checks": 0, "turns": 2})
    );
    d.insert(
        "guard".into(),
        json!({"skipped": false, "checks": 5, "turns": 2}),
    );
    w.stub.0.lock().unwrap().diff = d;
    let o = w.bx(&["diff", "b1"]);
    assert!(!out(&o).contains("guard_skipped"), "{}", out(&o));
}

#[test]
fn push_to_local_remote() {
    let w = world();
    w.approved(1, vec![file("README", Op::Modify, 0o644, b"one\n")]);
    w.apply_ok();
    let tip = w.tip();
    let bare = w.d.path().join("remote.git");
    git_in(
        &w.d,
        w.d.path(),
        &["init", "-q", "--bare", bare.to_str().unwrap()],
    );
    let remote = bare.to_str().unwrap();
    let o = w.bx(&["push", "b1", "--remote", remote]);
    assert_eq!(code(&o), 0, "{}{}", out(&o), err(&o));
    assert_eq!(
        git_in(&w.d, &bare, &["rev-parse", "refs/heads/saiife/box-b1"]),
        tip
    );
    let seen = w.stub.seen();
    let begin = &seen.iter().find(|(o, _)| o == "box.push.begin").unwrap().1;
    assert_eq!(begin["commit"], tip.as_str());
    assert_eq!(begin["remote"], remote);
    let done = &seen.iter().find(|(o, _)| o == "box.push.done").unwrap().1;
    assert_eq!(done["ok"], true);
    assert_eq!(done["request_id"], "4294967298");
    // A remote that is an option never reaches git.
    let o = w.bx(&["push", "b1", "--remote=--upload-pack=x"]);
    assert_eq!(code(&o), 2, "{}{}", out(&o), err(&o));
}

#[test]
fn discard_force_flag_is_sent() {
    let w = world();
    let o = w.bx(&["discard", "b1", "--yes", "--force"]);
    assert_eq!(code(&o), 0, "{}{}", out(&o), err(&o));
    let o = w.bx(&["discard", "b1", "--yes"]);
    assert_eq!(code(&o), 0, "{}{}", out(&o), err(&o));
    let d: Vec<Value> = w
        .stub
        .seen()
        .into_iter()
        .filter(|(o, _)| o == "box.discard")
        .map(|(_, a)| a)
        .collect();
    assert_eq!(d[0], json!({"box": "b1", "force": true}));
    assert_eq!(d[1], json!({"box": "b1"}));
}

/// A debug build without `fido-hid` and without a key seam: no key support.
#[cfg(not(feature = "fido-hid"))]
#[test]
fn land_without_key_support_points_to_workspace() {
    let w = world();
    w.next(1, vec![file("README", Op::Modify, 0o644, b"one\n")]);
    let before = w.stub.ops().len();
    let o = w.cmd(&["land", "b1"], false).output().unwrap();
    assert_eq!(code(&o), 5, "{}{}", out(&o), err(&o));
    let e = err(&o);
    assert!(
        e.contains("saiife: this saiife build has no FIDO2 key support"),
        "{e}"
    );
    assert!(
        e.contains("saiife: land box b1 from the Workspace instead (Face ID or your passkey), then run: saiife box apply b1"),
        "{e}"
    );
    let ops = w.stub.ops();
    assert!(!ops.contains(&"box.land.begin".to_string()), "{ops:?}");
    assert_eq!(ops.len(), before, "no daemon call at all: {ops:?}");
}

#[test]
fn land_that_does_not_fit_the_branch_is_refused() {
    let w = world();
    // An add of a path the base has, and a guest path that delta.bin's
    // re-check refuses.
    w.approved(1, vec![file("README", Op::Add, 0o644, b"again\n")]);
    let o = w.bx(&["apply", "b1"]);
    assert_eq!(code(&o), 2, "{}{}", out(&o), err(&o));
    assert!(err(&o).contains("the path to add is there"), "{}", err(&o));
    w.stub.0.lock().unwrap().waiting.clear();
    w.approved(2, vec![file(".git/hooks/x", Op::Add, 0o644, b"x\n")]);
    let o = w.bx(&["apply", "b1"]);
    assert_eq!(code(&o), 2, "{}{}", out(&o), err(&o));
    assert!(err(&o).contains("delta refused"), "{}", err(&o));
    assert!(w.git(&["for-each-ref", "refs/heads/saiife"]).is_empty());
    assert!(w.stub.applied().is_empty());
}

/// A box-written `.gitattributes` naming filters the user's config defines
/// (a fake one, and `lfs`): saiife's land and apply never run them; the
/// user's own checkout afterwards would.
#[test]
fn git_config_filters_never_run() {
    let w = world();
    let marks = w.d.path().join("marks");
    fs::create_dir_all(&marks).unwrap();
    let script = w.d.path().join("bin/filter");
    exec(
        &script,
        &format!(
            "#!/bin/sh\necho \"$*\" >> {}\ncat\n",
            marks.join("filter").display()
        ),
    );
    let sc = script.to_str().unwrap();
    for (k, v) in [
        ("filter.fake.clean", format!("{sc} clean")),
        ("filter.fake.smudge", format!("{sc} smudge")),
        ("filter.fake.process", format!("{sc} process")),
        ("filter.lfs.clean", format!("{sc} lfs-clean %f")),
        ("filter.lfs.smudge", format!("{sc} lfs-smudge %f")),
        ("filter.lfs.process", format!("{sc} lfs-process")),
    ] {
        w.git(&["config", k, &v]);
    }
    let attrs = b"* filter=fake\n*.bin filter=lfs diff=lfs merge=lfs\n";
    w.stub.0.lock().unwrap().git_config = vec![".gitattributes".into(), ".lfsconfig".into()];
    w.next(
        1,
        vec![
            file(".gitattributes", Op::Add, 0o644, attrs),
            file(
                ".lfsconfig",
                Op::Add,
                0o644,
                b"[lfs]\n\turl = http://192.0.2.1/x\n",
            ),
            file("x.txt", Op::Add, 0o644, b"text\n"),
            file("y.bin", Op::Add, 0o644, b"bin\n"),
        ],
    );
    // Without the flag: refused at begin, no touch asked.
    let o = w.bx(&["land", "b1"]);
    assert_eq!(code(&o), 2, "{}{}", out(&o), err(&o));
    assert!(
        err(&o).contains("saiife box land b1 --allow-git-config"),
        "{}",
        err(&o)
    );
    assert!(!w.stub.ops().contains(&"box.land".to_string()));
    let begin = &w
        .stub
        .seen()
        .into_iter()
        .find(|(o, _)| o == "box.land.begin")
        .unwrap()
        .1;
    assert!(begin.get("allow_git_config").is_none(), "{begin}");
    // With it: landed; then a second land through apply.
    let o = w.bx(&["land", "b1", "--allow-git-config"]);
    assert_eq!(code(&o), 0, "{}{}", out(&o), err(&o));
    let begin = w
        .stub
        .seen()
        .into_iter()
        .filter(|(o, _)| o == "box.land.begin")
        .nth(1)
        .unwrap()
        .1;
    assert_eq!(begin["allow_git_config"], true);
    w.approved(2, vec![file("z.bin", Op::Add, 0o644, b"more\n")]);
    w.apply_ok();
    let t = w.tree(&w.tip());
    assert_eq!(t["y.bin"].1, w.blob(b"bin\n"));
    assert_eq!(t["z.bin"].1, w.blob(b"more\n"));
    assert!(!marks.join("filter").exists(), "a filter ran");
    // The user's own checkout of it is where their filters act.
    let wt = w.wt().to_str().unwrap().to_string();
    let _ = git_raw(
        &w.d,
        &w.project(),
        &["worktree", "add", "-q", "--detach", &wt, "saiife/box-b1"],
    );
    assert!(marks.join("filter").exists(), "the filters are live");
}

#[test]
fn diff_names_git_config() {
    let w = world();
    let mut d = hostile_diff();
    d["review"]["git_config"] = json!([".gitattributes"]);
    w.stub.0.lock().unwrap().diff = d;
    let o = w.bx(&["diff", "b1", "--stat"]);
    assert_eq!(code(&o), 0, "{}{}", out(&o), err(&o));
    assert!(
        out(&o).contains(
            "this land changes git config (.gitattributes); it lands only from the CLI: saiife box land b1 --allow-git-config"
        ),
        "{}",
        out(&o)
    );
}
