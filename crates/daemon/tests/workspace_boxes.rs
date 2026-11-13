//! The Workspace over plan 34's box manager (plan 31, Task 1): a locked
//! daemon context with a fake-VMM manager, `serve_link` on a Unix socket and
//! a paired `TestDevice`. Spawns, overviews and admissions go through frames;
//! the audit chain shows who admitted what.
#![cfg(all(unix, feature = "fake-vmm"))]

use saiife_audit::{ChainWriter, WriterOptions};
use saiife_boxes::capacity::{self, HostFacts};
use saiife_boxes::guest::fake::FakeGuest;
use saiife_boxes::guest::GuestLink;
use saiife_boxes::manager::{Manager, ManagerInit};
use saiife_boxes::store::Store;
use saiife_boxes::template::{self, Size};
use saiife_boxes::vmm::fake::FakeVmm;
use saiife_boxes::BoxId;
use saiife_daemon::box_ops;
use saiife_daemon::ops::{self, Ctx, CtxInit, Mode, PolicyState};
use saiife_daemon::workspace::{dir_in, now_secs, Workspace};
use saiife_daemon::writer::{self, WriterConfig};
use saiife_ipc::frame::{body_len_max, encode_max, MAX_ANSWER_FRAME, MAX_FRAME};
use saiife_ipc::msg::{
    Request, LINK_SOCKET_NAME, OP_HELLO, OP_WORKSPACE_FRAME, OP_WORKSPACE_PAIR_BEGIN,
    OP_WORKSPACE_PAIR_CONFIRM, OP_WORKSPACE_PAIR_FINISH, PROTO,
};
use saiife_ipc::peer::PeerCred;
use saiife_policy::{Directory, Fsync, GroupEntry, UserEntry};
use saiife_wire::frame::{Frame, SignedFrame};
use saiife_wire::sig::TestDevice;
use saiife_wire::{b64, pair};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

const OWN: u32 = 999;

fn me() -> u32 {
    rustix::process::getuid().as_raw()
}

fn scratch() -> tempfile::TempDir {
    let base = std::env::var_os("SAIIFE_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    std::fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

/// A host that holds exactly `n` default boxes.
fn host(n: u64) -> HostFacts {
    HostFacts {
        mem_total_mib: 8192 + n * capacity::charge_mib(&Size::default()),
        mem_avail_mib: 4096,
        threads: 12,
        disk_free_mib: 1024 * 1024,
        cpu_pct: None,
    }
}

/// `saiife` (the daemon), `me` (this process's uid), and the `admins` group
/// with `me` in it while the flag is set.
struct Dir(Arc<AtomicBool>);

impl Directory for Dir {
    fn user(&self, name: &str) -> Option<UserEntry> {
        match name {
            "saiife" => Some(UserEntry { uid: OWN, gid: OWN }),
            // Pairing is done as root; the frames come from this process's
            // uid, so the device owner "root" resolves to it.
            "me" | "root" => Some(UserEntry {
                uid: me(),
                gid: me(),
            }),
            _ => None,
        }
    }
    fn name_of(&self, uid: u32) -> Option<String> {
        match uid {
            OWN => Some("saiife".into()),
            0 => Some("root".into()),
            u if u == me() => Some("me".into()),
            _ => None,
        }
    }
    fn group(&self, name: &str) -> Option<GroupEntry> {
        (name == "admins").then(|| GroupEntry {
            gid: 3000,
            members: if self.0.load(Ordering::SeqCst) {
                vec!["me".into()]
            } else {
                Vec::new()
            },
        })
    }
    fn groups_of(&self, user: &str) -> Vec<String> {
        if user == "me" && self.0.load(Ordering::SeqCst) {
            vec!["admins".into()]
        } else {
            Vec::new()
        }
    }
}

struct World {
    ctx: Arc<Ctx>,
    mgr: Arc<Manager>,
    run: PathBuf,
    audit: PathBuf,
    _tmp: tempfile::TempDir,
}

/// A locked daemon: uid `OWN`, the device owner `me` (this process's uid, in
/// `[admin] groups`), one box slot, the Workspace over the manager.
async fn world(slots: u64) -> World {
    world_as(slots, true).await
}

/// [`world`] with the device owner an admin or not.
async fn world_as(slots: u64, admin: bool) -> World {
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
    let dirs: Arc<dyn Directory + Send + Sync> = Arc::new(Dir(Arc::new(AtomicBool::new(admin))));
    let clock = Arc::new(AtomicU64::new(1_000_000));
    let guest: Arc<dyn GuestLink> = Arc::new(FakeGuest::new());
    let h = host(slots);
    let c = Arc::clone(&clock);
    let mgr = Arc::new(
        Manager::open(ManagerInit {
            store: Store::open(box_ops::dir_in(&state)).unwrap(),
            vmm: Arc::new(FakeVmm::new()),
            guest,
            templates: template::builtin(),
            host: Arc::new(move || h),
            clock: Arc::new(move || c.load(Ordering::SeqCst)),
            disk_place: box_ops::disk_place(),
        })
        .unwrap()
        .manager,
    );
    let (ws, warning) = Workspace::open(dir_in(&state));
    assert!(warning.is_none(), "{warning:?}");
    let cell: box_ops::CtxCell = Arc::default();
    let boxes = box_ops::pick_workspace_boxes(
        Arc::new(saiife_wire::source::NoBoxes),
        Some(&mgr),
        None,
        Arc::clone(&cell),
        None,
    );
    let ctx = Arc::new(Ctx::new(CtxInit {
        mode: Mode::Locked,
        own_uid: OWN,
        own_user: "saiife".into(),
        audit_dir: audit.clone(),
        socket_dir: run.clone(),
        workspace: Arc::new(ws),
        boxes,
        box_manager: Some(Arc::clone(&mgr)),
        policy: PolicyState {
            admin_groups: vec!["admins".into()],
            ..PolicyState::invalid(0)
        },
        ..CtxInit::minimal(handle, cfg, dirs, &state)
    }));
    cell.set(Arc::downgrade(&ctx)).unwrap();
    let listener = UnixListener::bind(run.join(LINK_SOCKET_NAME)).unwrap();
    tokio::spawn(saiife_daemon::server::serve_link(
        listener,
        Arc::clone(&ctx),
    ));
    World {
        ctx,
        mgr,
        run,
        audit,
        _tmp: tmp,
    }
}

fn peer() -> PeerCred {
    PeerCred {
        uid: 0,
        gid: 0,
        pid: std::process::id(),
        sid: None,
        group_sids: Vec::new(),
    }
}

async fn control(w: &World, op: &str, args: Value) -> Value {
    let req = Request {
        id: 1,
        op: op.into(),
        args: args.as_object().unwrap().clone(),
    };
    ops::dispatch(&w.ctx, &peer(), req).await
}

struct Link {
    s: UnixStream,
    next: u64,
}

impl Link {
    async fn open(w: &World) -> Link {
        let s = UnixStream::connect(w.run.join(LINK_SOCKET_NAME))
            .await
            .unwrap();
        let mut l = Link { s, next: 1 };
        let h = l.call(OP_HELLO, json!({"proto": PROTO})).await;
        assert_eq!(h["ok"], true, "{h}");
        l
    }

    async fn call(&mut self, op: &str, args: Value) -> Value {
        let mut m = args.as_object().unwrap().clone();
        m.insert("id".into(), self.next.into());
        m.insert("op".into(), op.into());
        self.next += 1;
        let bytes = encode_max(&Value::Object(m), MAX_FRAME).unwrap();
        self.s.write_all(&bytes).await.unwrap();
        let mut h = [0u8; 4];
        self.s.read_exact(&mut h).await.unwrap();
        let n = body_len_max(h, MAX_ANSWER_FRAME).unwrap();
        let mut body = vec![0u8; n];
        self.s.read_exact(&mut body).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }
}

async fn pair_device(w: &World, link: &mut Link) -> TestDevice {
    let b = control(w, OP_WORKSPACE_PAIR_BEGIN, json!({"label": "laptop"})).await;
    assert_eq!(b["ok"], true, "{b}");
    let (pair_id, secret, _, _) = pair::parse_fragment(b["fragment"].as_str().unwrap()).unwrap();
    let d = TestDevice::generate();
    let pubkey = d.public_raw();
    let f = link
        .call(
            OP_WORKSPACE_PAIR_FINISH,
            json!({
                "pair_id": pair_id,
                "device_pub": b64::enc(&pubkey),
                "label": "phone",
                "proof": b64::enc(&pair::proof(&secret, &pair_id, &pubkey)),
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
    d
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

async fn send(w: &World, link: &mut Link, d: &TestDevice, action: &str, args: Value) -> Value {
    let sf = frame_for(&w.ctx.workspace, d, action, args);
    link.call(
        OP_WORKSPACE_FRAME,
        json!({"body": sf.body, "sig": sf.sig, "via": "local"}),
    )
    .await
}

/// The audit records of `kind`, oldest first.
fn records(w: &World, kind: &str) -> Vec<Value> {
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
    walk(&w.audit, kind, &mut out);
    out
}

fn field<'a>(r: &'a Value, k: &str) -> &'a Value {
    match &r[k] {
        Value::Null => &r["extra"][k],
        v => v,
    }
}

/// The `box` records for `id` with `via`, waiting for the sink's task.
async fn box_records(w: &World, id: &str, via: &str, want: usize) -> Vec<Value> {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let r: Vec<Value> = records(w, "box")
            .into_iter()
            .filter(|r| field(r, "box") == id && field(r, "via") == via)
            .collect();
        if r.len() >= want || Instant::now() > until {
            return r;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn paired(slots: u64) -> (World, Link, TestDevice) {
    paired_as(slots, true).await
}

async fn paired_as(slots: u64, admin: bool) -> (World, Link, TestDevice) {
    let w = world_as(slots, admin).await;
    let mut link = Link::open(&w).await;
    let d = pair_device(&w, &mut link).await;
    (w, link, d)
}

fn spawn_args(task: &str) -> Value {
    json!({"template": "claude-code", "repo": "shop", "task": task, "start": "queue"})
}

#[tokio::test]
async fn overview_comes_from_the_manager() {
    let (w, mut link, d) = paired(2).await;
    let a = control(&w, "box.spawn", spawn_args("hello")).await;
    assert_eq!(a["ok"], true, "{a}");
    let id = a["box"]["id"].as_str().unwrap().to_string();
    let o = send(&w, &mut link, &d, "box.overview", json!({})).await;
    assert_eq!(o["ok"], true, "{o}");
    let boxes = o["result"]["boxes"].as_array().unwrap();
    assert_eq!(boxes.len(), 1, "{o}");
    assert_eq!(boxes[0]["id"], id.as_str(), "{o}");
    assert_eq!(boxes[0]["task"], "hello", "{o}");
    assert_eq!(o["result"]["slots_total"], 2, "{o}");
}

#[tokio::test]
async fn remote_spawn_names_the_owner() {
    let (w, mut link, d) = paired(2).await;
    let a = send(&w, &mut link, &d, "box.spawn", spawn_args("from phone")).await;
    assert_eq!(a["ok"], true, "{a}");
    let id = BoxId::parse(a["result"]["id"].as_str().unwrap()).unwrap();
    let r = w.mgr.get(&id).unwrap();
    assert_eq!(r.owner_uid, me(), "the device owner, not the daemon");
    assert_ne!(r.owner_uid, OWN);
    // The frame's own workspace record covers the new box.
    let ws: Vec<_> = records(&w, "workspace")
        .into_iter()
        .filter(|r| field(r, "action") == "box.spawn")
        .collect();
    assert_eq!(ws.len(), 1, "{ws:?}");
}

#[tokio::test]
async fn admission_of_other_boxes_is_audited() {
    let (w, mut link, d) = paired(1).await;
    // A runs (slot 1), B waits.
    let a = send(&w, &mut link, &d, "box.spawn", spawn_args("a")).await;
    let a = a["result"]["id"].as_str().unwrap().to_string();
    let b = send(&w, &mut link, &d, "box.spawn", spawn_args("b")).await;
    let b = b["result"]["id"].as_str().unwrap().to_string();
    assert_eq!(
        w.mgr.get(&BoxId::parse(&b).unwrap()).unwrap().state,
        saiife_boxes::BoxState::Queued
    );
    // Stopping A is the frame's own record; the tick admits B (via tick).
    let s = send(&w, &mut link, &d, "box.stop", json!({"id": a})).await;
    assert_eq!(s["ok"], true, "{s}");
    assert_eq!(box_ops::tick_once(&w.ctx).await, 1);
    let tick = box_records(&w, &b, "tick", 1).await;
    assert_eq!(tick.len(), 1, "{tick:?}");
    // A frame spawn whose admission pass admits a queue head: B is the head
    // again once its box is gone and C takes the slot's place.
    let c = send(&w, &mut link, &d, "box.spawn", spawn_args("c")).await;
    let c = c["result"]["id"].as_str().unwrap().to_string();
    let e = send(&w, &mut link, &d, "box.spawn", spawn_args("e")).await;
    let e = e["result"]["id"].as_str().unwrap().to_string();
    // B stops (slot frees), then a spawn frame admits C, the head.
    let s = send(&w, &mut link, &d, "box.stop", json!({"id": b})).await;
    assert_eq!(s["ok"], true, "{s}");
    let f = send(&w, &mut link, &d, "box.spawn", spawn_args("f")).await;
    assert_eq!(f["ok"], true, "{f}");
    let rec = box_records(&w, &c, "workspace", 1).await;
    assert_eq!(rec.len(), 1, "{rec:?}");
    let r = &rec[0];
    assert_eq!(field(r, "action"), "tick", "{r}");
    assert_eq!(field(r, "via"), "workspace", "{r}");
    assert_eq!(field(r, "from"), "queued", "{r}");
    assert_eq!(field(r, "to"), "starting", "{r}");
    assert_eq!(field(r, "template"), "claude-code", "{r}");
    // The new box is the frame's record, not the sink's; E stayed queued.
    let f_id = f["result"]["id"].as_str().unwrap();
    assert!(box_records(&w, f_id, "workspace", 0).await.is_empty());
    assert!(box_records(&w, &e, "workspace", 0).await.is_empty());
}

/// The demo wins over a manager when asked (test builds).
#[cfg(feature = "fake-boxes")]
#[tokio::test]
async fn fake_boxes_env_still_wins() {
    use saiife_wire::source::BoxSource;
    let w = world(1).await;
    let demo: Arc<dyn BoxSource> = Arc::new(saiife_wire::fake::FakeBoxSource::demo(now_secs()));
    let picked = box_ops::pick_workspace_boxes(
        Arc::new(saiife_wire::source::NoBoxes),
        Some(&w.mgr),
        None,
        Arc::default(),
        Some(demo),
    );
    assert_eq!(picked.overview().boxes.len(), 4);
}

/// Another user's box, running, made straight on the manager.
fn others_box(w: &World) -> String {
    let rec = w
        .mgr
        .spawn(&saiife_boxes::manager::SpawnArgs {
            template: "claude-code".into(),
            repo: "shop".into(),
            repo_dir: None,
            task: "theirs".into(),
            start: saiife_wire::source::Start::Queue,
            owner_uid: me().wrapping_add(7),
            repo_image: None,
            base_manifest: None,
        })
        .unwrap();
    rec.id.as_str().to_string()
}

fn rules(w: &World, kind: &str) -> Vec<String> {
    records(w, kind)
        .iter()
        .filter_map(|r| field(r, "rule").as_str().map(String::from))
        .collect()
}

#[tokio::test]
async fn a_user_cannot_reach_another_users_box() {
    let (w, mut link, d) = paired_as(3, false).await;
    let theirs = others_box(&w);
    let mine = send(&w, &mut link, &d, "box.spawn", spawn_args("mine")).await;
    assert_eq!(mine["ok"], true, "{mine}");
    let o = send(&w, &mut link, &d, "box.overview", json!({})).await;
    let ids: Vec<_> = o["result"]["boxes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        ids,
        vec![mine["result"]["id"].as_str().unwrap().to_string()]
    );
    let l = send(&w, &mut link, &d, "box.list", json!({})).await;
    assert_eq!(l["result"].as_array().unwrap().len(), 1, "{l}");
    for (action, args) in [
        ("box.diff", json!({"id": theirs})),
        ("box.term.read", json!({"id": theirs})),
        ("box.stop", json!({"id": theirs})),
        ("box.pause", json!({"id": theirs})),
        ("box.discard", json!({"id": theirs})),
    ] {
        let a = send(&w, &mut link, &d, action, args).await;
        assert_eq!(a["ok"], false, "{action}: {a}");
        assert_eq!(a["rule"], "not_found", "{action}: {a}");
    }
    // Untouched, and the failed changes are audited.
    let r = w.mgr.get(&BoxId::parse(&theirs).unwrap()).unwrap();
    assert_ne!(r.state, saiife_boxes::BoxState::Done);
    let stops: Vec<_> = records(&w, "workspace")
        .into_iter()
        .filter(|r| field(r, "action") == "box.stop" && field(r, "box") == theirs.as_str())
        .collect();
    assert_eq!(stops.len(), 1, "{stops:?}");
    assert_eq!(stops[0]["decision"], "deny", "{:?}", stops[0]);
}

#[tokio::test]
async fn an_admin_sees_but_cannot_change_another_users_box() {
    let (w, mut link, d) = paired_as(3, true).await;
    let theirs = others_box(&w);
    let o = send(&w, &mut link, &d, "box.overview", json!({})).await;
    let ids: Vec<_> = o["result"]["boxes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["id"].as_str().unwrap().to_string())
        .collect();
    assert!(ids.contains(&theirs), "{o}");
    let df = send(&w, &mut link, &d, "box.diff", json!({"id": theirs})).await;
    assert_ne!(df["rule"], "not_found", "{df}");
    let s = send(&w, &mut link, &d, "box.stop", json!({"id": theirs})).await;
    assert_eq!(s["ok"], false, "{s}");
    assert_eq!(s["error"], "forbidden", "{s}");
    assert_eq!(s["rule"], "not_owner", "{s}");
    let r = w.mgr.get(&BoxId::parse(&theirs).unwrap()).unwrap();
    assert_ne!(r.state, saiife_boxes::BoxState::Done);
    let denied = records(&w, "workspace")
        .into_iter()
        .filter(|r| field(r, "action") == "box.stop" && r["decision"] == "deny")
        .count();
    assert_eq!(denied, 1);
}

fn lock_all(w: &World) {
    w.ctx
        .lockdown
        .set(Some(saiife_broker::pipeline::Lockdown {
            scope: saiife_broker::pipeline::LockScope::All,
            reason: "incident".into(),
            by_uid: 0,
            since: "t".into(),
        }))
        .unwrap();
}

#[tokio::test]
async fn lockdown_all_refuses_a_frame_spawn_but_not_stop_or_list() {
    let (w, mut link, d) = paired(2).await;
    let a = send(&w, &mut link, &d, "box.spawn", spawn_args("a")).await;
    let a = a["result"]["id"].as_str().unwrap().to_string();
    lock_all(&w);
    let s = send(&w, &mut link, &d, "box.spawn", spawn_args("b")).await;
    assert_eq!(s["ok"], false, "{s}");
    assert_eq!(s["rule"], "lockdown", "{s}");
    assert_eq!(w.mgr.list().len(), 1, "nothing was spawned");
    assert!(rules(&w, "workspace").contains(&"lockdown".to_string()));
    for action in ["box.steer", "box.revise", "box.resume"] {
        let r = send(&w, &mut link, &d, action, json!({"id": a, "msg": "x"})).await;
        assert_eq!(r["rule"], "lockdown", "{action}: {r}");
    }
    let l = send(&w, &mut link, &d, "box.list", json!({})).await;
    assert_eq!(l["ok"], true, "{l}");
    let st = send(&w, &mut link, &d, "box.stop", json!({"id": a})).await;
    assert_eq!(st["ok"], true, "{st}");
}

#[tokio::test]
async fn the_shared_gate_holds_all_six_power_actions() {
    let w = world(1).await;
    for a in ["spawn", "resume", "steer", "revise", "land", "push"] {
        assert!(box_ops::power_refusal(&w.ctx, a).is_none(), "{a}");
    }
    lock_all(&w);
    for a in ["spawn", "resume", "steer", "revise", "land", "push"] {
        assert!(box_ops::power_refusal(&w.ctx, a).is_some(), "{a}");
        assert!(box_ops::power_refusal(&w.ctx, &format!("box.{a}")).is_some());
    }
    for a in ["stop", "pause", "discard", "list", "overview", "diff"] {
        assert!(box_ops::power_refusal(&w.ctx, a).is_none(), "{a}");
    }
}
