//! Land from the browser over a real land book (plan 31 with plan 39): a
//! locked daemon context with a fake-VMM box manager and NO demo source,
//! the land book attached after the context exists (`box_ops::attach_lands`,
//! as `start.rs` does), `serve_link` on a Unix socket, and Workspace devices
//! of two users paired with soft passkeys. A box of alice's is `Done` with
//! its review made by a fake guest over plan 38's vsock multiplexer (as in
//! `box_land.rs`). The browser reads the land request from `box.inbox`, the
//! diff hash from `box.diff`, and lands with a WebAuthn touch over the
//! challenge it was shown. No VM is ever started.
#![cfg(all(unix, feature = "fake-vmm"))]

use saiife_audit::{ChainWriter, WriterOptions};
use saiife_boxes::capacity::{self, HostFacts};
use saiife_boxes::guest::fake::FakeGuest;
use saiife_boxes::guest::{GuestEvent, GuestLink};
use saiife_boxes::manager::{Manager, ManagerInit, SpawnArgs};
use saiife_boxes::source::LandBook;
use saiife_boxes::store::Store;
use saiife_boxes::template::{self, Size};
use saiife_boxes::vmm::fake::FakeVmm;
use saiife_boxes::{BoxError, BoxId, BoxState};
use saiife_boxhost::guest::{SetupSource, VsockGuest};
use saiife_boxhost::paths::{BoxPaths, RecordPaths, BASE_MANIFEST};
use saiife_boxhost::vmm::VmHooks;
use saiife_boxproto::delta::{write_delta, DeltaItem, EntryHead, Op};
use saiife_boxproto::frame::{read_msg, write_msg};
use saiife_boxproto::manifest::{BaseManifest, Entry, EntryKind};
use saiife_boxproto::msg::{AgentSpec, Event, HostReply, Reply, Request, Setup};
use saiife_boxproto::{ports, PROTO};
use saiife_daemon::box_land::Lands;
use saiife_daemon::box_ops;
use saiife_daemon::ops::{self, Conn, Ctx, CtxInit, Mode, PolicyState};
use saiife_daemon::touch::IssueKey;
use saiife_daemon::workspace::{dir_in, now_secs, Workspace};
use saiife_daemon::workspace_link;
use saiife_daemon::writer::{self, WriterConfig};
use saiife_ipc::frame::{body_len_max, encode_max, MAX_ANSWER_FRAME, MAX_FRAME};
use saiife_ipc::msg::{
    Request as IpcRequest, LINK_SOCKET_NAME, OP_HELLO, OP_WORKSPACE_FRAME,
    OP_WORKSPACE_PAIR_CONFIRM, OP_WORKSPACE_PAIR_FINISH, PROTO as IPC_PROTO,
};
use saiife_ipc::peer::PeerCred;
use saiife_policy::{Directory, Fsync};
use saiife_touch::soft::SoftAuthenticator;
use saiife_touch::{challenge, Assertion, EnrolRequest, Touch, TouchError, LOCAL_RP_ID};
use saiife_wire::frame::{Frame, SignedFrame};
use saiife_wire::sig::TestDevice;
use saiife_wire::source::{Decision, PendingAction};
use saiife_wire::{b64, pair};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener as StdListener, UnixStream as StdStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

const ALICE: u32 = 2000;
const BOB: u32 = 2001;
const ORIGIN: &str = "http://localhost:47810";
const T: Duration = Duration::from_secs(10);

fn scratch() -> tempfile::TempDir {
    let base = std::env::var_os("SAIIFE_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    std::fs::create_dir_all(&base).unwrap();
    tempfile::Builder::new()
        .prefix("w")
        .tempdir_in(base)
        .unwrap()
}

fn me() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn sha(b: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, b)
        .as_ref()
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

// ---- a tree model: manifests and exports (as in box_land.rs) ----

type Tree = BTreeMap<String, Vec<u8>>;

fn tree(items: &[(&str, &str)]) -> Tree {
    items
        .iter()
        .map(|(p, c)| (p.to_string(), c.as_bytes().to_vec()))
        .collect()
}

fn base_tree() -> Tree {
    tree(&[
        ("README.md", "# Demo\n\nline 1\nline 2\n"),
        ("old.txt", "bye\n"),
        ("src/main.rs", "fn main() {}\n"),
    ])
}

fn changed() -> Tree {
    let mut t = base_tree();
    t.insert("src/main.rs".into(), b"fn main() { run(); }\n".to_vec());
    t.insert("NEW.md".into(), b"new\n".to_vec());
    t.remove("old.txt");
    t
}

fn manifest(t: &Tree) -> BaseManifest {
    let entries: BTreeMap<String, Entry> = t
        .iter()
        .map(|(p, c)| {
            (
                p.clone(),
                Entry {
                    kind: EntryKind::File,
                    mode: 0o644,
                    size: c.len() as u64,
                    sha256: sha(c),
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

fn head(p: &str, op: Op, old: Option<&[u8]>, new: Option<&[u8]>) -> EntryHead {
    let (size, sha256, mode) = match new {
        Some(n) => (n.len() as u64, sha(n), 0o644),
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
        old_size: old.map(|o| o.len() as u64),
        old_sha256: old.map(sha),
    }
}

type Item = (EntryHead, Option<Vec<u8>>, Option<Vec<u8>>);

/// Export `n` of `old → new`, as the guest sends it.
fn export(n: u32, old: &Tree, new: &Tree) -> Vec<u8> {
    let keys: BTreeSet<&String> = old.keys().chain(new.keys()).collect();
    let mut items: Vec<Item> = Vec::new();
    for k in keys {
        match (old.get(k), new.get(k)) {
            (None, Some(c)) => items.push((head(k, Op::Add, None, Some(c)), None, Some(c.clone()))),
            (Some(o), None) => items.push((head(k, Op::Delete, Some(o), None), None, None)),
            (Some(o), Some(c)) if o != c => items.push((
                head(k, Op::Modify, Some(o), Some(c)),
                Some(o.clone()),
                Some(c.clone()),
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

#[derive(Default)]
struct GuestRepo {
    base: Tree,
    work: Tree,
    exports: BTreeMap<u32, Tree>,
}

fn serve(repo: &Mutex<GuestRepo>, r: Request, s: &mut StdStream) {
    match r {
        Request::Export { n } => {
            let mut g = repo.lock().unwrap();
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
fn mux_conn(mut s: StdStream, reqs: Arc<Mutex<Vec<Request>>>, repo: Arc<Mutex<GuestRepo>>) {
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

struct Served {
    repo: Arc<Mutex<GuestRepo>>,
    requests: Arc<Mutex<Vec<Request>>>,
    stop: Arc<AtomicBool>,
    _events: StdStream,
}

// ---- the world ----

struct World {
    ctx: Arc<Ctx>,
    mgr: Arc<Manager>,
    lands: Arc<Lands>,
    guest: Arc<VsockGuest>,
    audit: PathBuf,
    run: PathBuf,
    root: PathBuf,
    runtime: PathBuf,
    served: Mutex<BTreeMap<BoxId, Served>>,
    /// Each user's CLI (CTAP) key, under the local RP id.
    cli_keys: BTreeMap<u32, SoftAuthenticator>,
    _tmp: tempfile::TempDir,
}

impl Drop for World {
    fn drop(&mut self) {
        for (id, s) in self.served.lock().unwrap().iter() {
            s.stop.store(true, Ordering::SeqCst);
            self.guest.after_off(id);
        }
    }
}

fn host(n: u64) -> HostFacts {
    HostFacts {
        mem_total_mib: 8192 + n * capacity::charge_mib(&Size::default()),
        mem_avail_mib: 4096,
        threads: 12,
        disk_free_mib: 1024 * 1024,
        cpu_pct: None,
    }
}

/// A locked daemon (uid 999) with a box manager, no demo source, the land
/// book attached only after the context exists, and `link.sock` served.
async fn world() -> World {
    let tmp = scratch();
    let audit = tmp.path().join("audit");
    let state = tmp.path().join("state");
    let run = tmp.path().join("run");
    for d in [&audit, &state, &run] {
        std::fs::create_dir_all(d).unwrap();
    }
    let cw = ChainWriter::open(
        &audit,
        WriterOptions {
            mode: "locked".into(),
            saiife: "test".into(),
            key: None,
        },
    )
    .unwrap();
    let cfg = WriterConfig {
        checkpoint_every: 1000,
        checkpoint_interval: Duration::from_secs(900),
        fsync: Fsync::Always,
    };
    let (handle, _join) = writer::spawn(cw, cfg, None).unwrap();
    let dirs: Arc<dyn Directory + Send + Sync> =
        Arc::new(saiife_policy::FixedDirectory::from_text(
            "root:x:0:0::/root:/bin/sh\n\
             saiife:x:999:999::/var/lib/saiife:/bin/sh\n\
             alice:x:2000:2000::/home/alice:/bin/sh\n\
             bob:x:2001:2001::/home/bob:/bin/sh\n",
            "admins:x:3000:\n",
        ));
    let root = box_ops::dir_in(&state);
    let h = host(4);
    let fake: Arc<dyn GuestLink> = Arc::new(FakeGuest::new());
    let mgr = Arc::new(
        Manager::open(ManagerInit {
            store: Store::open(root.clone()).unwrap(),
            vmm: Arc::new(FakeVmm::new()),
            guest: fake,
            templates: template::builtin(),
            host: Arc::new(move || h),
            clock: Arc::new(now_secs),
            disk_place: box_ops::disk_place(),
        })
        .unwrap()
        .manager,
    );
    let (ws, warning) = Workspace::open(dir_in(&state));
    assert!(warning.is_none(), "{warning:?}");
    // No demo: frames build their source from the manager per call.
    let (boxes, workspace_demo) =
        box_ops::pick_workspace_boxes(Arc::new(saiife_wire::source::NoBoxes), None);
    assert!(!workspace_demo);
    let ctx = Arc::new(Ctx::new(CtxInit {
        mode: Mode::Locked,
        own_uid: 999,
        own_user: "saiife".into(),
        audit_dir: audit.clone(),
        socket_dir: run.clone(),
        workspace: Arc::new(ws),
        boxes,
        workspace_demo,
        box_manager: Some(Arc::clone(&mgr)),
        policy: PolicyState {
            admin_groups: vec!["admins".into()],
            ..PolicyState::invalid(0)
        },
        ..CtxInit::minimal(handle, cfg, dirs, &state)
    }));
    assert!(ctx.box_lands.get().is_none(), "no book before the context");
    let mut cli_keys = BTreeMap::new();
    for uid in [ALICE, BOB] {
        let s = SoftAuthenticator::new_es256();
        ctx.touch.add(s.credential(LOCAL_RP_ID, uid, "k")).unwrap();
        cli_keys.insert(uid, s);
    }
    let guest = VsockGuest::new(Arc::new(Setups), false, me());
    // The book is attached after the context exists, as on a real start.
    let lands = box_ops::attach_lands(&ctx, Arc::clone(&guest)).expect("attached once");
    let listener = UnixListener::bind(run.join(LINK_SOCKET_NAME)).unwrap();
    tokio::spawn(saiife_daemon::server::serve_link(
        listener,
        Arc::clone(&ctx),
    ));
    World {
        ctx,
        mgr,
        lands,
        guest,
        audit,
        run,
        root,
        runtime: state.join("runtime"),
        served: Mutex::new(BTreeMap::new()),
        cli_keys,
        _tmp: tmp,
    }
}

impl World {
    fn state(&self, i: &BoxId) -> BoxState {
        self.mgr.get(i).unwrap().state
    }

    fn requests(&self, i: &BoxId) -> Vec<Request> {
        self.served.lock().unwrap()[i]
            .requests
            .lock()
            .unwrap()
            .clone()
    }

    fn with_repo<T>(&self, i: &BoxId, f: impl FnOnce(&mut GuestRepo) -> T) -> T {
        let s = self.served.lock().unwrap();
        let mut g = s[i].repo.lock().unwrap();
        f(&mut g)
    }

    /// A Done box of `uid` (base → `work`) whose review is made.
    fn done(&self, uid: u32, work: &Tree) -> BoxId {
        let i = self
            .mgr
            .spawn(&SpawnArgs {
                template: "claude-code".into(),
                repo: "demo".into(),
                repo_dir: None,
                task: "make it better".into(),
                start: saiife_wire::source::Start::Queue,
                owner_uid: uid,
                repo_image: None,
                base_manifest: None,
            })
            .unwrap()
            .id;
        let base = base_tree();
        std::fs::write(
            RecordPaths::of(&self.root, &i).dir.join(BASE_MANIFEST),
            serde_json::to_string(&manifest(&base)).unwrap(),
        )
        .unwrap();
        self.connect(&i, &base, work);
        self.mgr.guest_event(&i, GuestEvent::Ready).unwrap();
        assert_eq!(self.state(&i), BoxState::Running);
        self.mgr.done(&i).unwrap();
        tokio::task::block_in_place(|| self.lands.refresh(&i)).unwrap();
        assert_eq!(self.state(&i), BoxState::Done);
        i
    }

    fn connect(&self, i: &BoxId, base: &Tree, work: &Tree) {
        let p = BoxPaths::of(&self.runtime, i);
        std::fs::create_dir_all(&p.dir).unwrap();
        let repo = Arc::new(Mutex::new(GuestRepo {
            base: base.clone(),
            work: work.clone(),
            ..GuestRepo::default()
        }));
        let requests: Arc<Mutex<Vec<Request>>> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let l = StdListener::bind(p.vsock()).unwrap();
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
        self.guest.before_boot(i, &p).unwrap();
        let mut ev = StdStream::connect(p.vsock_port(ports::EVENTS)).unwrap();
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
        self.served.lock().unwrap().insert(
            i.clone(),
            Served {
                repo,
                requests,
                stop,
                _events: ev,
            },
        );
    }

    /// The book's pending land for box `i` (the daemon's own view).
    fn pending_of(&self, i: &BoxId) -> PendingAction {
        self.lands
            .pending()
            .into_iter()
            .find(|p| p.box_id.as_ref() == Some(i))
            .unwrap_or_else(|| panic!("no pending land for {}", i.as_str()))
    }

    /// The audit records of `kind`, oldest first.
    fn records(&self, kind: &str) -> Vec<Value> {
        fn walk(p: &Path, kind: &str, out: &mut Vec<Value>) {
            let mut entries: Vec<_> = std::fs::read_dir(p).unwrap().flatten().collect();
            entries.sort_by_key(|e| e.path());
            for e in entries {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, kind, out);
                } else if let Ok(t) = std::fs::read_to_string(&p) {
                    for line in t.lines() {
                        if let Ok(v) = serde_json::from_str::<Value>(line) {
                            if v["kind"] == kind {
                                out.push(v);
                            }
                        }
                    }
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.audit, kind, &mut out);
        out
    }
}

fn field<'a>(r: &'a Value, k: &str) -> &'a Value {
    match &r[k] {
        Value::Null => &r["extra"][k],
        v => v,
    }
}

// ---- the link: pairing, frames, touches ----

fn root_peer() -> PeerCred {
    PeerCred {
        uid: 0,
        gid: 0,
        pid: std::process::id(),
        sid: None,
        group_sids: Vec::new(),
    }
}

async fn control(w: &World, op: &str, args: Value) -> Value {
    let req = IpcRequest {
        id: 1,
        op: op.into(),
        args: args.as_object().unwrap().clone(),
    };
    ops::dispatch(&w.ctx, &root_peer(), req).await
}

/// A user's link process. The daemon answers a device's frames only to its
/// owner's processes (`wrong_owner`), and a test runs as one uid, so the
/// link of alice (uid 2000) and of bob (uid 2001) reach `link.sock`'s own
/// dispatcher in process, each with its user's peer credentials. One link
/// of this test's uid goes over the real socket to show it is served.
struct Link {
    ctx: Arc<Ctx>,
    conn: Conn,
    next: u64,
}

fn peer_of(uid: u32) -> PeerCred {
    PeerCred {
        uid,
        gid: uid,
        pid: std::process::id(),
        sid: None,
        group_sids: Vec::new(),
    }
}

impl Link {
    async fn open(w: &World, uid: u32) -> Link {
        let mut l = Link {
            ctx: Arc::clone(&w.ctx),
            conn: Conn::new(peer_of(uid), None),
            next: 1,
        };
        let h = l.call(OP_HELLO, json!({"proto": IPC_PROTO})).await;
        assert_eq!(h["ok"], true, "{h}");
        l
    }

    async fn call(&mut self, op: &str, args: Value) -> Value {
        let req = IpcRequest {
            id: self.next,
            op: op.into(),
            args: args.as_object().unwrap().clone(),
        };
        self.next += 1;
        workspace_link::dispatch_link(&self.ctx, &self.conn, req).await
    }
}

/// `hello` over the real `link.sock` the world serves.
async fn socket_hello(w: &World) -> Value {
    let mut s = UnixStream::connect(w.run.join(LINK_SOCKET_NAME))
        .await
        .unwrap();
    let bytes = encode_max(
        &json!({"id": 1, "op": OP_HELLO, "proto": IPC_PROTO}),
        MAX_FRAME,
    )
    .unwrap();
    s.write_all(&bytes).await.unwrap();
    let mut h = [0u8; 4];
    s.read_exact(&mut h).await.unwrap();
    let n = body_len_max(h, MAX_ANSWER_FRAME).unwrap();
    let mut body = vec![0u8; n];
    s.read_exact(&mut body).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// A browser of `user`: its device key and its passkey.
struct Browser {
    d: TestDevice,
    soft: SoftAuthenticator,
}

/// Pairs a device of `user` with a soft passkey for `localhost`: the offer
/// is `user`'s (as `workspace.pair.begin` from that user makes it), the
/// browser finishes it over the link, root confirms it on the machine.
async fn pair_as(w: &World, link: &mut Link, user: &str) -> Browser {
    let offer = w
        .ctx
        .workspace
        .begin_pair(user, Some("laptop".into()), w.ctx.workspace.now())
        .unwrap();
    let (pair_id, secret) = (offer.pair_id.clone(), offer.secret);
    let d = TestDevice::generate();
    let pubkey = d.public_raw();
    let soft = SoftAuthenticator::new_es256();
    let ad = soft
        .enrol(&EnrolRequest {
            rp_id: "localhost".into(),
            rp_name: "saiife".into(),
            user_id: vec![1],
            user_name: user.into(),
            challenge: [0; 32],
            exclude: vec![],
        })
        .unwrap();
    let ch = b64::enc(&pair::passkey_challenge(&pair_id, &pubkey));
    let cdj = format!(
        "{{\"type\":\"webauthn.create\",\"challenge\":\"{ch}\",\"origin\":\"{ORIGIN}\",\"crossOrigin\":false}}"
    );
    let mut att = pair::PasskeyAttestation {
        credential_id: b64::enc(&soft.credential_id()),
        authenticator_data: b64::enc(&ad),
        client_data_json: b64::enc(cdj.as_bytes()),
        device_sig: String::new(),
    };
    let msg = pair::passkey_sig_msg(&pair_id, &att).unwrap();
    att.device_sig = b64::enc(&d.sign_domain(pair::PASSKEY_DOMAIN, &msg));
    let f = link
        .call(
            OP_WORKSPACE_PAIR_FINISH,
            json!({
                "pair_id": pair_id,
                "device_pub": b64::enc(&pubkey),
                "label": "phone",
                "proof": b64::enc(&pair::proof(&secret, &pair_id, &pubkey)),
                "passkey": att,
            }),
        )
        .await;
    assert_eq!(f["ok"], true, "{f}");
    let c = control(
        w,
        OP_WORKSPACE_PAIR_CONFIRM,
        json!({"pair_id": pair_id, "accept": true}),
    )
    .await;
    assert_eq!(c["ok"], true, "{c}");
    assert_eq!(c["passkey"], b64::enc(&soft.credential_id()), "{c}");
    Browser { d, soft }
}

fn nonce() -> String {
    let mut n = [0u8; 16];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut n).unwrap();
    b64::enc(&n)
}

fn frame_for(ws: &Workspace, d: &TestDevice, action: &str, args: Value) -> SignedFrame {
    let h = ws.hello();
    let now = now_secs();
    d.frame(&Frame {
        v: 1,
        machine_id: h["machine_id"].as_str().unwrap().into(),
        epoch: h["epoch"].as_str().unwrap().into(),
        device_id: d.device_id(),
        action: action.into(),
        args: args.as_object().unwrap().clone(),
        nonce: nonce(),
        issued_at: now,
        expires_at: now + 60,
    })
}

async fn send(w: &World, link: &mut Link, b: &Browser, action: &str, args: Value) -> Value {
    let sf = frame_for(&w.ctx.workspace, &b.d, action, args);
    link.call(
        OP_WORKSPACE_FRAME,
        json!({"body": sf.body, "sig": sf.sig, "via": "local"}),
    )
    .await
}

async fn send_touch(
    w: &World,
    link: &mut Link,
    b: &Browser,
    action: &str,
    args: Value,
    proof: Value,
) -> Value {
    let sf = frame_for(&w.ctx.workspace, &b.d, action, args);
    link.call(
        OP_WORKSPACE_FRAME,
        json!({"body": sf.body, "sig": sf.sig, "via": "local", "touch": proof}),
    )
    .await
}

/// The browser's WebAuthn assertion over `ch` as touch request `rid`.
fn proof(b: &Browser, rid: &str, ch: &[u8; 32]) -> Value {
    match b.soft.assert_webauthn("localhost", ORIGIN, ch) {
        Assertion::WebAuthn {
            credential_id,
            auth_data,
            signature,
            client_data_json,
            ..
        } => json!({
            "request_id": rid,
            "credential_id": b64::enc(&credential_id),
            "authenticator_data": b64::enc(&auth_data),
            "client_data_json": b64::enc(&client_data_json),
            "signature": b64::enc(&signature),
        }),
        other => panic!("not a web assertion: {other:?}"),
    }
}

fn unhex32(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64, "{s}");
    let mut out = [0u8; 32];
    for (k, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * k..2 * k + 2], 16).unwrap();
    }
    out
}

/// What the browser learns of a land: the inbox item for box `id` (its
/// request id and the challenge it shows) and the diff hash from
/// `box.diff`, all through frames.
struct Seen {
    rid: String,
    challenge: [u8; 32],
    diff_sha256: String,
}

async fn browse_land(w: &World, link: &mut Link, b: &Browser, id: &BoxId) -> Seen {
    let o = send(w, link, b, "box.overview", json!({})).await;
    assert_eq!(o["ok"], true, "{o}");
    let boxes = o["result"]["boxes"].as_array().unwrap();
    let mine = boxes
        .iter()
        .find(|x| x["id"] == id.as_str())
        .unwrap_or_else(|| panic!("{} not in the overview: {o}", id.as_str()));
    assert_eq!(mine["state"], "done", "{o}");
    let inbox = send(w, link, b, "box.inbox", json!({})).await;
    assert_eq!(inbox["ok"], true, "{inbox}");
    let items = inbox["result"]["items"].as_array().unwrap();
    let item = items
        .iter()
        .find(|x| x["box_id"] == id.as_str())
        .unwrap_or_else(|| panic!("no land for {} in the inbox: {inbox}", id.as_str()));
    assert_eq!(item["class"], "land", "{item}");
    let d = send(w, link, b, "box.diff", json!({"id": id.as_str()})).await;
    assert_eq!(d["ok"], true, "{d}");
    Seen {
        rid: item["request_id"].as_str().unwrap().to_string(),
        challenge: unhex32(item["challenge_hex"].as_str().unwrap()),
        diff_sha256: d["result"]["diff_sha256"].as_str().unwrap().to_string(),
    }
}

fn land_args(id: &BoxId, sha: &str) -> Value {
    json!({"id": id.as_str(), "diff_sha256": sha})
}

struct Two {
    w: World,
    /// Alice's link process.
    link: Link,
    alice: Browser,
    /// Bob's link process.
    bob_link: Link,
    bob: Browser,
}

async fn two() -> Two {
    let w = world().await;
    let h = socket_hello(&w).await;
    assert_eq!(h["ok"], true, "{h}");
    let mut link = Link::open(&w, ALICE).await;
    let alice = pair_as(&w, &mut link, "alice").await;
    let mut bob_link = Link::open(&w, BOB).await;
    let bob = pair_as(&w, &mut bob_link, "bob").await;
    Two {
        w,
        link,
        alice,
        bob_link,
        bob,
    }
}

// ---- the tests ----

/// The browser lands a Done box through the book attached after the
/// context: the box advances, the land is approved (not applied, L4), the
/// frame's record carries the touch, and the CLI path's entry for the same
/// request is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn browser_lands_through_the_late_book() {
    let Two {
        w, mut link, alice, ..
    } = two().await;
    let i = w.done(ALICE, &changed());
    let p = w.pending_of(&i);
    let n = w.lands.latest(&i).unwrap().n;
    let seen = browse_land(&w, &mut link, &alice, &i).await;
    // What the browser was shown is the daemon's own record.
    assert_eq!(seen.rid, p.request_id.to_string());
    assert_eq!(seen.challenge, challenge(&p.record));
    assert_eq!(seen.diff_sha256, p.record.fields["diff_sha256"]);
    let a = send_touch(
        &w,
        &mut link,
        &alice,
        "box.land",
        land_args(&i, &seen.diff_sha256),
        proof(&alice, &seen.rid, &seen.challenge),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a["result"], json!({}), "{a}");
    // Applied to the box: Landed, the guest's base advanced to the export.
    let r = w.mgr.get(&i).unwrap();
    assert_eq!((r.state, r.lands), (BoxState::Landed, 1));
    assert!(w
        .requests(&i)
        .contains(&Request::Advance { n, paths: None }));
    assert_eq!(w.with_repo(&i, |g| g.base.clone()), changed());
    // Approved, not applied (L4); nothing left pending.
    assert!(RecordPaths::of(&w.root, &i).land_approved(n).exists());
    assert_eq!(w.lands.unapplied(&i), 1);
    assert!(w.lands.pending().is_empty());
    // The land record: the web touch, the owner, the diff.
    let lands: Vec<Value> = w
        .records("box")
        .into_iter()
        .filter(|r| r["action"] == "land")
        .collect();
    assert_eq!(lands.len(), 1, "{lands:?}");
    let l = &lands[0];
    assert_eq!(l["box"], i.as_str(), "{l}");
    assert_eq!(l["via"], "web", "{l}");
    assert_eq!(l["uid"], ALICE, "{l}");
    assert_eq!(l["diff_sha256"], seen.diff_sha256.as_str(), "{l}");
    assert_eq!(
        l["touch"]["cred_id"],
        b64::enc(&alice.soft.credential_id()),
        "{l}"
    );
    // The Workspace's own record of the frame, with the touch evidence.
    let ws: Vec<Value> = w
        .records("workspace")
        .into_iter()
        .filter(|r| field(r, "action") == "box.land")
        .collect();
    let last = ws.last().unwrap_or_else(|| panic!("no box.land record"));
    assert_eq!(last["decision"], "allow", "{last}");
    assert_eq!(field(last, "box"), i.as_str(), "{last}");
    let t = field(last, "touch");
    assert_eq!(t["kind"], "webauthn", "{last}");
    assert_eq!(t["via"], "web", "{last}");
    assert_eq!(t["uv"], true, "{last}");
    assert_eq!(
        t["challenge"],
        seen.challenge
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        "{last}"
    );
    // The CLI path's entry for this request is burned: its touch finds
    // nothing, and the book refuses a second approval.
    let asr = w.cli_keys[&ALICE].assert_ctap(LOCAL_RP_ID, &challenge(&p.record));
    let rec = p.record.clone();
    let r = w.ctx.touch.consume(
        &IssueKey::Land(p.request_id),
        ALICE,
        |_| rec,
        &asr,
        LOCAL_RP_ID,
        now_secs(),
    );
    assert_eq!(r.unwrap_err(), TouchError::Expired);
    let ev = w
        .ctx
        .touch
        .verify_counted(ALICE, &p.record, &asr, LOCAL_RP_ID, now_secs())
        .unwrap();
    let second = tokio::task::block_in_place(|| {
        (
            w.lands.approve(p.request_id, &ev, "cli"),
            w.lands
                .complete(p.request_id, Decision::Approve, Some(ev.clone())),
        )
    });
    assert!(
        matches!(second.0, Err(BoxError::WrongState { .. })),
        "{second:?}"
    );
    assert!(
        matches!(second.1, Err(BoxError::WrongState { .. })),
        "{second:?}"
    );
    // And the browser cannot approve it again either.
    let again = send_touch(
        &w,
        &mut link,
        &alice,
        "box.land",
        land_args(&i, &seen.diff_sha256),
        proof(&alice, &seen.rid, &seen.challenge),
    )
    .await;
    assert_eq!(again["error"], "forbidden", "{again}");
    assert_eq!(again["rule"], "touch_failed", "{again}");
    assert_eq!(w.mgr.get(&i).unwrap().lands, 1);
}

/// The reverse order: the CLI path approves first; the browser's touch for
/// the same request then finds no pending action.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cli_approval_burns_the_browser_path() {
    let Two {
        w, mut link, alice, ..
    } = two().await;
    let i = w.done(ALICE, &changed());
    let seen = browse_land(&w, &mut link, &alice, &i).await;
    let p = w.pending_of(&i);
    let asr = w.cli_keys[&ALICE].assert_ctap(LOCAL_RP_ID, &challenge(&p.record));
    let rec = p.record.clone();
    let (ev, _) = w
        .ctx
        .touch
        .consume(
            &IssueKey::Land(p.request_id),
            ALICE,
            |_| rec,
            &asr,
            LOCAL_RP_ID,
            now_secs(),
        )
        .unwrap();
    tokio::task::block_in_place(|| w.lands.approve(p.request_id, &ev, "cli")).unwrap();
    assert_eq!(w.state(&i), BoxState::Landed);
    let a = send_touch(
        &w,
        &mut link,
        &alice,
        "box.land",
        land_args(&i, &seen.diff_sha256),
        proof(&alice, &seen.rid, &seen.challenge),
    )
    .await;
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "touch_failed", "{a}");
    assert_eq!(w.mgr.get(&i).unwrap().lands, 1);
}

/// Bob's device sees none of alice's land, and cannot land it even with a
/// valid touch of his own over its record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_owner_cannot_see_or_land_it() {
    let Two {
        w,
        mut link,
        alice,
        mut bob_link,
        bob,
    } = two().await;
    let i = w.done(ALICE, &changed());
    let p = w.pending_of(&i);
    let inbox = send(&w, &mut bob_link, &bob, "box.inbox", json!({})).await;
    assert_eq!(inbox["ok"], true, "{inbox}");
    assert_eq!(inbox["result"]["items"], json!([]), "{inbox}");
    let o = send(&w, &mut bob_link, &bob, "box.overview", json!({})).await;
    assert_eq!(o["ok"], true, "{o}");
    assert_eq!(o["result"]["boxes"], json!([]), "{o}");
    let d = send(
        &w,
        &mut bob_link,
        &bob,
        "box.diff",
        json!({"id": i.as_str()}),
    )
    .await;
    assert_eq!(d["rule"], "not_found", "{d}");
    // Bob somehow holds the record (rid, challenge, hash) and touches it.
    let sha = p.record.fields["diff_sha256"].clone();
    let a = send_touch(
        &w,
        &mut bob_link,
        &bob,
        "box.land",
        land_args(&i, &sha),
        proof(&bob, &p.request_id.to_string(), &challenge(&p.record)),
    )
    .await;
    assert_eq!(a["rule"], "not_found", "{a}");
    assert_eq!(w.state(&i), BoxState::Done);
    assert_eq!(w.lands.unapplied(&i), 0);
    // Alice's request is untouched by it: she still lands.
    let seen = browse_land(&w, &mut link, &alice, &i).await;
    let a = send_touch(
        &w,
        &mut link,
        &alice,
        "box.land",
        land_args(&i, &seen.diff_sha256),
        proof(&alice, &seen.rid, &seen.challenge),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(w.state(&i), BoxState::Landed);
}

/// Without a proof: `touch_required`, nothing spent. A wrong or stale
/// `diff_sha256` is refused, and nothing lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proofless_and_wrong_hash_lands_are_refused() {
    let Two {
        w, mut link, alice, ..
    } = two().await;
    let i = w.done(ALICE, &changed());
    let seen = browse_land(&w, &mut link, &alice, &i).await;
    let a = send(
        &w,
        &mut link,
        &alice,
        "box.land",
        land_args(&i, &seen.diff_sha256),
    )
    .await;
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "touch_required", "{a}");
    // A hash that is not the request's.
    let wrong = "0".repeat(64);
    let a = send_touch(
        &w,
        &mut link,
        &alice,
        "box.land",
        land_args(&i, &wrong),
        proof(&alice, &seen.rid, &seen.challenge),
    )
    .await;
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "touch_mismatch", "{a}");
    assert_eq!(w.state(&i), BoxState::Done);
    // The agent's work changed and the review was made again: the old
    // request (and its hash) is stale.
    let mut more = changed();
    more.insert("MORE.md".into(), b"more\n".to_vec());
    w.with_repo(&i, |g| g.work = more.clone());
    tokio::task::block_in_place(|| w.lands.refresh(&i)).unwrap();
    let fresh = w.pending_of(&i);
    assert_ne!(fresh.request_id.to_string(), seen.rid);
    assert_ne!(fresh.record.fields["diff_sha256"], seen.diff_sha256);
    let a = send_touch(
        &w,
        &mut link,
        &alice,
        "box.land",
        land_args(&i, &seen.diff_sha256),
        proof(&alice, &seen.rid, &seen.challenge),
    )
    .await;
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "touch_failed", "{a}");
    // The fresh request with the old hash is a mismatch too.
    let a = send_touch(
        &w,
        &mut link,
        &alice,
        "box.land",
        land_args(&i, &seen.diff_sha256),
        proof(
            &alice,
            &fresh.request_id.to_string(),
            &challenge(&fresh.record),
        ),
    )
    .await;
    assert_eq!(a["rule"], "touch_mismatch", "{a}");
    assert_eq!(w.state(&i), BoxState::Done);
    assert_eq!(w.lands.unapplied(&i), 0);
    // The fresh one, as the browser sees it now, lands.
    let now = browse_land(&w, &mut link, &alice, &i).await;
    assert_eq!(now.rid, fresh.request_id.to_string());
    let a = send_touch(
        &w,
        &mut link,
        &alice,
        "box.land",
        land_args(&i, &now.diff_sha256),
        proof(&alice, &now.rid, &now.challenge),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(w.with_repo(&i, |g| g.base.clone()), more);
}

/// R-LW2: Workspace push is not built; `box.push` stays refused from the
/// browser, with or without a touch, after the box has landed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_from_the_browser_stays_refused() {
    let Two {
        w, mut link, alice, ..
    } = two().await;
    let i = w.done(ALICE, &changed());
    let seen = browse_land(&w, &mut link, &alice, &i).await;
    let a = send_touch(
        &w,
        &mut link,
        &alice,
        "box.land",
        land_args(&i, &seen.diff_sha256),
        proof(&alice, &seen.rid, &seen.challenge),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
    let p = send(&w, &mut link, &alice, "box.push", json!({"id": i.as_str()})).await;
    assert_eq!(p["error"], "unavailable", "{p}");
    assert_eq!(p["rule"], "unavailable", "{p}");
    let p = send_touch(
        &w,
        &mut link,
        &alice,
        "box.push",
        json!({"id": i.as_str()}),
        proof(&alice, &seen.rid, &seen.challenge),
    )
    .await;
    assert_eq!(p["error"], "unavailable", "{p}");
    assert_eq!(p["rule"], "unavailable", "{p}");
    assert!(w.records("box").iter().all(|r| r["action"] != "push"));
}
