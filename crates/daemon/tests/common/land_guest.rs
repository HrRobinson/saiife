//! The fake land guest shared by `box_land.rs` and `workspace_land.rs`
//! (plan 39, plan 31): a tree model (manifests and exports made with
//! `write_delta`), and plan 38's vsock multiplexer over a box's runtime dir
//! whose fake guest keeps a base tree and a work tree and serves exports of
//! the difference. No VM is ever started.
#![allow(dead_code)]

use saiife_boxes::BoxId;
use saiife_boxhost::guest::{SetupSource, VsockGuest};
use saiife_boxhost::paths::BoxPaths;
use saiife_boxhost::vmm::VmHooks;
use saiife_boxproto::delta::{write_delta, DeltaItem, EntryHead, Op};
use saiife_boxproto::frame::{read_msg, write_msg};
use saiife_boxproto::manifest::{BaseManifest, Entry, EntryKind};
use saiife_boxproto::msg::{AgentSpec, Event, HostReply, Reply, Request, Setup};
use saiife_boxproto::{ports, PROTO};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// How long the guest's hello and setup may take.
const WAIT: Duration = Duration::from_secs(10);

pub fn sha(b: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, b)
        .as_ref()
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

// ---- a tree model: manifests and exports ----

#[derive(Clone, Debug, PartialEq)]
pub struct C(pub Vec<u8>);

pub type Tree = BTreeMap<String, C>;

pub fn tree(items: &[(&str, &str)]) -> Tree {
    items
        .iter()
        .map(|(p, c)| (p.to_string(), C(c.as_bytes().to_vec())))
        .collect()
}

pub fn base_tree() -> Tree {
    tree(&[
        ("README.md", "# Demo\n\nline 1\nline 2\n"),
        ("old.txt", "bye\n"),
        ("src/main.rs", "fn main() {}\n"),
    ])
}

pub fn manifest(t: &Tree) -> BaseManifest {
    let entries: BTreeMap<String, Entry> = t
        .iter()
        .map(|(p, c)| {
            (
                p.clone(),
                Entry {
                    kind: EntryKind::File,
                    mode: 0o644,
                    size: c.0.len() as u64,
                    sha256: sha(&c.0),
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

pub fn head(p: &str, op: Op, old: Option<&C>, new: Option<&C>) -> EntryHead {
    let (size, sha256, mode) = match new {
        Some(n) => (n.0.len() as u64, sha(&n.0), 0o644),
        None => (0, String::new(), 0),
    };
    EntryHead {
        path: p.into(),
        op,
        kind: EntryKind::File,
        mode,
        size,
        sha256,
        old_kind: old.map(|_| EntryKind::File),
        old_size: old.map(|o| o.0.len() as u64),
        old_sha256: old.map(|o| sha(&o.0)),
    }
}

/// An entry head with its old and new content.
pub type Item = (EntryHead, Option<Vec<u8>>, Option<Vec<u8>>);

/// Export `n` of `old → new`, as the guest sends it.
pub fn export(n: u32, old: &Tree, new: &Tree) -> Vec<u8> {
    let keys: BTreeSet<&String> = old.keys().chain(new.keys()).collect();
    let mut items: Vec<Item> = Vec::new();
    for k in keys {
        match (old.get(k), new.get(k)) {
            (None, Some(c)) => {
                items.push((head(k, Op::Add, None, Some(c)), None, Some(c.0.clone())))
            }
            (Some(o), None) => items.push((head(k, Op::Delete, Some(o), None), None, None)),
            (Some(o), Some(c)) if o != c => items.push((
                head(k, Op::Modify, Some(o), Some(c)),
                Some(o.0.clone()),
                Some(c.0.clone()),
            )),
            _ => {}
        }
    }
    let refs: Vec<DeltaItem<'_>> = items
        .iter()
        .map(|(h, o, n)| (h.clone(), o.as_deref(), n.as_deref()))
        .collect();
    let mut out = Vec::new();
    write_delta(&mut out, n, &refs).unwrap();
    out
}

// ---- the fake guest: plan 38's multiplexer over the box's vsock ----

pub struct Setups;
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

/// The guest's git: the base tree, `/work`, and the exports it made.
#[derive(Default)]
pub struct GuestRepo {
    pub base: Tree,
    pub work: Tree,
    pub exports: BTreeMap<u32, Tree>,
    /// Served (once) instead of the next export.
    pub hostile: Option<Answer>,
}

#[derive(Clone)]
pub enum Answer {
    Bytes(Vec<u8>),
    Err(String),
}

pub struct Served {
    pub repo: Arc<Mutex<GuestRepo>>,
    pub requests: Arc<Mutex<Vec<Request>>>,
    pub stop: Arc<AtomicBool>,
    pub _events: UnixStream,
}

pub fn serve(repo: &Mutex<GuestRepo>, r: Request, s: &mut UnixStream) {
    match r {
        Request::Export { n } => {
            let mut g = repo.lock().unwrap();
            if let Some(a) = g.hostile.take() {
                match a {
                    Answer::Bytes(b) => {
                        let _ = s.write_all(&b);
                    }
                    Answer::Err(why) => {
                        let _ = write_msg(s, &Reply::Err { why });
                    }
                }
                return;
            }
            let work = g.work.clone();
            g.exports.insert(n, work.clone());
            let b = export(n, &g.base, &work);
            drop(g);
            let _ = s.write_all(&b);
        }
        Request::Advance { n, paths } => {
            let mut g = repo.lock().unwrap();
            let Some(e) = g.exports.get(&n).cloned() else {
                let _ = write_msg(
                    s,
                    &Reply::Err {
                        why: "no such export".into(),
                    },
                );
                return;
            };
            match paths {
                None => g.base = e,
                Some(ps) => {
                    for p in ps {
                        match e.get(&p) {
                            Some(c) => g.base.insert(p, c.clone()),
                            None => g.base.remove(&p),
                        };
                    }
                }
            }
            let _ = write_msg(s, &Reply::Ok);
        }
        _ => {
            let _ = write_msg(s, &Reply::Ok);
        }
    }
}

/// One multiplexer connection: `CONNECT 1024\n` → `OK 1\n`, then one request.
pub fn mux_conn(mut s: UnixStream, reqs: Arc<Mutex<Vec<Request>>>, repo: Arc<Mutex<GuestRepo>>) {
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
    serve(&repo, req, &mut s);
}

pub fn changed() -> Tree {
    let mut t = base_tree();
    t.insert("src/main.rs".into(), C(b"fn main() { run(); }\n".to_vec()));
    t.insert("NEW.md".into(), C(b"new\n".to_vec()));
    t.remove("old.txt");
    t
}

/// Serves a fake guest for box `i` on `p`'s vsock (base `base`, `/work` =
/// `work`), registers it with `guest`, and says hello as the guest does;
/// returns once the host asked for the setup.
pub fn connect(guest: &VsockGuest, p: &BoxPaths, i: &BoxId, base: &Tree, work: &Tree) -> Served {
    let repo = Arc::new(Mutex::new(GuestRepo {
        base: base.clone(),
        work: work.clone(),
        ..GuestRepo::default()
    }));
    let requests: Arc<Mutex<Vec<Request>>> = Arc::default();
    let stop = Arc::new(AtomicBool::new(false));
    let l = UnixListener::bind(p.vsock()).unwrap();
    l.set_nonblocking(true).unwrap();
    let (reqs, st, rp) = (requests.clone(), stop.clone(), repo.clone());
    thread::spawn(move || {
        while !st.load(Ordering::SeqCst) {
            let s = match l.accept() {
                Ok((s, _)) => s,
                Err(_) => {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
            };
            s.set_nonblocking(false).unwrap();
            let (reqs, rp) = (reqs.clone(), rp.clone());
            thread::spawn(move || mux_conn(s, reqs, rp));
        }
    });
    guest.before_boot(i, p).unwrap();
    let mut ev = UnixStream::connect(p.vsock_port(ports::EVENTS)).unwrap();
    ev.set_read_timeout(Some(WAIT)).unwrap();
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
    let end = Instant::now() + WAIT;
    while requests.lock().unwrap().is_empty() {
        assert!(Instant::now() < end, "no setup request");
        thread::sleep(Duration::from_millis(20));
    }
    Served {
        repo,
        requests,
        stop,
        _events: ev,
    }
}
