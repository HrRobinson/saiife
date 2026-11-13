//! The `box.*` ops on the control socket (plan 34, Task 8), over a box
//! manager on `FakeVmm` and `FakeGuest`: owners, lockdown, audit records and
//! the tick. No VM is ever started.
#![cfg(all(unix, feature = "fake-vmm"))]

use saiife_audit::{ChainWriter, WriterOptions};
use saiife_boxes::capacity::{self, HostFacts};
use saiife_boxes::guest::fake::FakeGuest;
use saiife_boxes::guest::{GuestEvent, GuestLink};
use saiife_boxes::manager::{Manager, ManagerInit, DONE_IDLE_SECS};
use saiife_boxes::store::Store;
use saiife_boxes::template::{self, Size};
use saiife_boxes::vmm::fake::{FakeVmm, VmOp};
use saiife_boxes::BoxId;
use saiife_broker::pipeline::{LockScope, Lockdown};
use saiife_daemon::box_ops;
use saiife_daemon::ops::{dispatch, Ctx, CtxInit, Mode, PolicyState};
use saiife_daemon::writer::{self, WriterConfig};
use saiife_ipc::msg::Request;
use saiife_ipc::peer::PeerCred;
use saiife_policy::{Directory, Fsync};
use serde_json::{json, Value};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

const ALICE: u32 = 2000;
const BOB: u32 = 2001;
/// In `[admin] groups` (`admins`).
const CAROL: u32 = 2002;
const ROOT: u32 = 0;
const T0: u64 = 1_000_000;

fn scratch() -> tempfile::TempDir {
    let base = std::env::var_os("SAIIFE_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    std::fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

/// A host that holds exactly two default boxes.
fn two_boxes() -> HostFacts {
    two_boxes_host(2)
}

fn two_boxes_host(n: u64) -> HostFacts {
    HostFacts {
        mem_total_mib: 8192 + n * capacity::charge_mib(&Size::default()),
        mem_avail_mib: 4096,
        threads: 12,
        disk_free_mib: 1024 * 1024,
        cpu_pct: None,
    }
}

struct World {
    ctx: Arc<Ctx>,
    mgr: Option<Arc<Manager>>,
    vmm: Arc<FakeVmm>,
    guest: Arc<FakeGuest>,
    clock: Arc<AtomicU64>,
    audit: PathBuf,
    _tmp: tempfile::TempDir,
}

struct Setup {
    manager: bool,
    template_warnings: Vec<saiife_boxes::template::TemplateWarning>,
    built: Option<Arc<Manager>>,
    /// Why boxes are unavailable (a failed preflight), with no manager.
    unavailable: Option<String>,
}

fn world() -> World {
    world_with(Setup {
        manager: true,
        template_warnings: Vec::new(),
        built: None,
        unavailable: None,
    })
}

fn world_with(s: Setup) -> World {
    let tmp = scratch();
    let audit = tmp.path().join("audit");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&audit).unwrap();
    std::fs::create_dir_all(&state).unwrap();
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
         bob:x:2001:2001::/home/bob:/bin/sh\n\
         carol:x:2002:2002::/home/carol:/bin/sh\n",
            "admins:x:3000:carol\n",
        ));
    let vmm = Arc::new(FakeVmm::new());
    let guest = Arc::new(FakeGuest::new());
    let clock = Arc::new(AtomicU64::new(T0));
    let mgr = match (s.manager, s.built) {
        (_, Some(m)) => Some(m),
        (false, None) => None,
        (true, None) => {
            let c = Arc::clone(&clock);
            let host = two_boxes();
            let g: Arc<dyn GuestLink> = guest.clone();
            let o = Manager::open(ManagerInit {
                store: Store::open(box_ops::dir_in(&state)).unwrap(),
                vmm: vmm.clone(),
                guest: g,
                templates: template::builtin(),
                host: Arc::new(move || host),
                clock: Arc::new(move || c.load(Ordering::SeqCst)),
                disk_place: box_ops::disk_place(),
            })
            .unwrap();
            assert!(o.warnings.is_empty(), "{:?}", o.warnings);
            Some(Arc::new(o.manager))
        }
    };
    let base = CtxInit::minimal(handle, cfg, dirs, &state);
    let ctx = Arc::new(Ctx::new(CtxInit {
        audit_dir: audit.clone(),
        own_user: "saiife".into(),
        own_uid: 999,
        mode: Mode::Locked,
        policy: PolicyState {
            admin_groups: vec!["admins".into()],
            ..PolicyState::invalid(0)
        },
        box_manager: mgr.clone(),
        box_unavailable: s.unavailable,
        box_template_warnings: s.template_warnings,
        ..base
    }));
    World {
        ctx,
        mgr,
        vmm,
        guest,
        clock,
        audit,
        _tmp: tmp,
    }
}

fn peer(uid: u32) -> PeerCred {
    PeerCred {
        uid,
        gid: uid,
        pid: std::process::id(),
        sid: None,
        group_sids: Vec::new(),
    }
}

fn id(s: &str) -> BoxId {
    BoxId::parse(s).unwrap()
}

impl World {
    async fn call(&self, uid: u32, op: &str, args: Value) -> Value {
        let req = Request {
            id: 7,
            op: op.into(),
            args: args.as_object().cloned().unwrap_or_default(),
        };
        dispatch(&self.ctx, &peer(uid), req).await
    }

    async fn ok(&self, uid: u32, op: &str, args: Value) -> Value {
        let a = self.call(uid, op, args).await;
        assert_eq!(a["ok"], true, "{op}: {a}");
        a
    }

    async fn spawn(&self, uid: u32, task: &str) -> Value {
        self.ok(
            uid,
            "box.spawn",
            json!({"template": "claude-code", "repo": "shop", "task": task, "start": "queue"}),
        )
        .await
    }

    fn mgr(&self) -> &Manager {
        self.mgr.as_deref().unwrap()
    }

    /// Spawned and booted: the guest said Ready.
    async fn running(&self, uid: u32, task: &str) -> String {
        let a = self.spawn(uid, task).await;
        let b = a["box"]["id"].as_str().unwrap().to_string();
        self.mgr().guest_event(&id(&b), GuestEvent::Ready).unwrap();
        assert_eq!(
            self.mgr().get(&id(&b)).unwrap().state.to_string_lossy(),
            "running"
        );
        b
    }

    /// The `box` records written so far.
    fn records(&self) -> Vec<Value> {
        let mut files: Vec<_> = std::fs::read_dir(&self.audit)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
            .collect();
        files.sort();
        files
            .iter()
            .flat_map(|f| {
                std::fs::read_to_string(f)
                    .unwrap()
                    .lines()
                    .map(|l| serde_json::from_str::<Value>(l).unwrap())
                    .collect::<Vec<_>>()
            })
            .filter(|r| r["kind"] == "box")
            .collect()
    }
}

trait Lossy {
    fn to_string_lossy(&self) -> String;
}

impl Lossy for saiife_boxes::BoxState {
    fn to_string_lossy(&self) -> String {
        serde_json::to_value(self)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string()
    }
}

fn assert_refused(a: &Value, error: &str, rule: &str) {
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["error"], error, "{a}");
    assert_eq!(a["rule"], rule, "{a}");
}

const EVERY_OP: [(&str, &str); 14] = [
    (
        "box.spawn",
        r#"{"template":"claude-code","repo":"shop","task":"t","start":"queue"}"#,
    ),
    ("box.list", "{}"),
    ("box.templates", "{}"),
    ("box.pause", r#"{"box":"b1"}"#),
    ("box.stop", r#"{"box":"b1"}"#),
    ("box.discard", r#"{"box":"b1"}"#),
    ("box.done", r#"{"box":"b1"}"#),
    ("box.resume", r#"{"box":"b1"}"#),
    ("box.revise", r#"{"box":"b1","comment":"c"}"#),
    ("box.steer", r#"{"box":"b1","msg":"m"}"#),
    ("box.reorder", r#"{"ids":[]}"#),
    ("box.gc", "{}"),
    ("box.diff", r#"{"box":"b1"}"#),
    ("box.term.read", r#"{"box":"b1"}"#),
];

#[tokio::test]
async fn unavailable_without_manager() {
    let w = world_with(Setup {
        manager: false,
        template_warnings: Vec::new(),
        built: None,
        unavailable: None,
    });
    for (op, args) in EVERY_OP {
        let a = w.call(ALICE, op, serde_json::from_str(args).unwrap()).await;
        assert_eq!(a["ok"], false, "{op}: {a}");
        assert_eq!(a["error"], "unavailable", "{op}: {a}");
        assert_eq!(
            a["message"], "boxes are not available in this version",
            "{op}: {a}"
        );
    }
    assert!(w.records().is_empty());
}

#[tokio::test]
async fn spawn_list_stop_roundtrip() {
    let w = world();
    let a = w.spawn(ALICE, "add a cart").await;
    assert_eq!(a["box"]["id"], "b1", "{a}");
    assert_eq!(a["box"]["state"], "starting", "{a}");
    assert_eq!(a["box"]["template"], "claude-code");
    assert_eq!(a["box"]["repo"], "shop");
    assert_eq!(a["box"]["task"], "add a cart");
    let l = w.ok(ALICE, "box.list", json!({})).await;
    assert_eq!(l["boxes"].as_array().unwrap().len(), 1, "{l}");
    assert_eq!(l["boxes"][0]["id"], "b1");
    assert_eq!(
        (l["slots_total"].as_u64(), l["slots_free"].as_u64()),
        (Some(2), Some(1))
    );
    let s = w.ok(ALICE, "box.stop", json!({"box": "b1"})).await;
    assert_eq!(
        (s["box"]["id"].as_str(), s["box"]["state"].as_str()),
        (Some("b1"), Some("done")),
        "{s}"
    );
    let l = w.ok(ALICE, "box.list", json!({})).await;
    assert_eq!(l["boxes"][0]["state"], "done");
    assert_eq!(l["slots_free"], 2);
    let d = w.ok(ALICE, "box.discard", json!({"box": "b1"})).await;
    assert_eq!(d["box"]["id"], "b1", "{d}");
    let l = w.ok(ALICE, "box.list", json!({})).await;
    assert!(l["boxes"].as_array().unwrap().is_empty(), "{l}");
}

#[tokio::test]
async fn spawn_is_recorded_with_session() {
    let w = world();
    w.spawn(ALICE, "add a cart").await;
    let recs = w.records();
    assert_eq!(recs.len(), 1, "{recs:?}");
    let r = &recs[0];
    assert_eq!(r["kind"], "box");
    assert_eq!(r["action"], "spawn");
    assert_eq!(r["box"], "b1");
    assert_eq!(r["session"], "box-b1");
    assert_eq!(r["template"], "claude-code");
    assert_eq!(r["from"], Value::Null);
    assert_eq!(r["to"], "starting");
    assert_eq!(r["via"], "cli");
    assert_eq!(r["decision"], "allow");
    assert_eq!(r["uid"], ALICE);
    assert_eq!(r["user"], "alice");
}

#[tokio::test]
async fn other_user_gets_not_found() {
    let w = world();
    let b = w.running(ALICE, "add a cart").await;
    let missing = w.call(BOB, "box.stop", json!({"box": "b9"})).await;
    assert_refused(&missing, "bad_request", "not_found");
    for (op, args) in [
        ("box.stop", json!({"box": b})),
        ("box.steer", json!({"box": b, "msg": "hi"})),
        ("box.diff", json!({"box": b})),
        ("box.pause", json!({"box": b})),
        ("box.term.read", json!({"box": b})),
    ] {
        let a = w.call(BOB, op, args).await;
        assert_refused(&a, "bad_request", "not_found");
        assert_eq!(
            a["message"], missing["message"],
            "{op}: same answer as a missing id"
        );
    }
    let l = w.ok(BOB, "box.list", json!({})).await;
    assert!(l["boxes"].as_array().unwrap().is_empty(), "{l}");
    let l = w.ok(BOB, "box.list", json!({"all": true})).await;
    assert!(
        l["boxes"].as_array().unwrap().is_empty(),
        "not an admin: {l}"
    );
    // Alice's box is untouched.
    assert_eq!(
        w.mgr().get(&id(&b)).unwrap().state.to_string_lossy(),
        "running"
    );
}

#[tokio::test]
async fn admin_sees_all() {
    let w = world();
    w.spawn(ALICE, "one").await;
    w.spawn(BOB, "two").await;
    for uid in [CAROL, ROOT] {
        let l = w.ok(uid, "box.list", json!({"all": true})).await;
        assert_eq!(l["boxes"].as_array().unwrap().len(), 2, "{uid}: {l}");
        let l = w.ok(uid, "box.list", json!({})).await;
        assert!(
            l["boxes"].as_array().unwrap().is_empty(),
            "{uid}: own only: {l}"
        );
    }
    let l = w.ok(ALICE, "box.list", json!({"all": true})).await;
    assert_eq!(l["boxes"].as_array().unwrap().len(), 1, "{l}");
    // An admin may act on another user's box.
    let s = w.ok(CAROL, "box.stop", json!({"box": "b2"})).await;
    assert_eq!(s["box"]["state"], "done", "{s}");
}

#[tokio::test]
async fn lockdown_refuses_power_ops_only() {
    let w = world();
    let b1 = w.running(ALICE, "one").await;
    let b2 = w.running(ALICE, "two").await;
    w.ctx
        .lockdown
        .set(Some(Lockdown {
            scope: LockScope::All,
            reason: "incident".into(),
            by_uid: 0,
            since: "t".into(),
        }))
        .unwrap();
    let before = w.records().len();
    // Allowed: they only take power away.
    let p = w.ok(ALICE, "box.pause", json!({"box": b1})).await;
    assert_eq!(p["box"]["state"], "paused");
    let s = w.ok(ALICE, "box.stop", json!({"box": b2})).await;
    assert_eq!(s["box"]["state"], "done");
    w.ok(ALICE, "box.list", json!({})).await;
    w.ok(ALICE, "box.templates", json!({})).await;
    // Refused.
    for (op, args) in [
        (
            "box.spawn",
            json!({"template": "claude-code", "repo": "shop", "task": "x", "start": "queue"}),
        ),
        ("box.resume", json!({"box": b1})),
        ("box.revise", json!({"box": b2, "comment": "more"})),
        ("box.steer", json!({"box": b1, "msg": "go"})),
    ] {
        let a = w.call(ALICE, op, args).await;
        assert_refused(&a, "lockdown", "lockdown");
    }
    let d = w.ok(ALICE, "box.discard", json!({"box": b2})).await;
    assert_eq!(d["box"]["id"], b2.as_str());
    // Nothing moved behind the refusals.
    assert_eq!(
        w.mgr().get(&id(&b1)).unwrap().state.to_string_lossy(),
        "paused"
    );
    assert_eq!(w.mgr().list().len(), 1, "no box was spawned");
    let recs = w.records();
    let new = &recs[before..];
    let denies: Vec<&Value> = new.iter().filter(|r| r["decision"] == "deny").collect();
    assert_eq!(denies.len(), 4, "{new:?}");
    let actions: Vec<&str> = denies
        .iter()
        .map(|r| r["action"].as_str().unwrap())
        .collect();
    assert_eq!(actions, ["spawn", "resume", "revise", "steer"]);
    for r in &denies {
        assert_eq!(r["rule"], "lockdown", "{r}");
    }
    let allows: Vec<&str> = new
        .iter()
        .filter(|r| r["decision"] == "allow")
        .map(|r| r["action"].as_str().unwrap())
        .collect();
    assert_eq!(allows, ["pause", "stop", "discard"]);
}

#[tokio::test]
async fn bad_id_is_bad_request() {
    let w = world();
    w.spawn(ALICE, "one").await;
    for args in [json!({"box": "../b1"}), json!({"box": 1}), json!({})] {
        let a = w.call(ALICE, "box.stop", args).await;
        assert_refused(&a, "bad_request", "invalid");
    }
    let a = w
        .call(ALICE, "box.reorder", json!({"ids": ["b1", "../b2"]}))
        .await;
    assert_refused(&a, "bad_request", "invalid");
    assert_eq!(
        w.mgr().get(&id("b1")).unwrap().state.to_string_lossy(),
        "starting"
    );
}

#[tokio::test]
async fn escape_in_task_is_bad_request() {
    let w = world();
    let a = w
        .call(
            ALICE,
            "box.spawn",
            json!({"template": "claude-code", "repo": "shop", "task": "a\u{1b}[2Jb", "start": "queue"}),
        )
        .await;
    assert_refused(&a, "bad_request", "invalid");
    let a = w
        .call(
            ALICE,
            "box.spawn",
            json!({"template": "claude-code", "repo": "shop", "task": "t", "start": "later"}),
        )
        .await;
    assert_refused(&a, "bad_request", "invalid");
    assert!(w.mgr().list().is_empty());
    // No id was claimed.
    let a = w.spawn(ALICE, "ok").await;
    assert_eq!(a["box"]["id"], "b1");
    // A steer with a control character never reaches the manager.
    w.mgr().guest_event(&id("b1"), GuestEvent::Ready).unwrap();
    let a = w
        .call(ALICE, "box.steer", json!({"box": "b1", "msg": "x\u{7}"}))
        .await;
    assert_refused(&a, "bad_request", "invalid");
}

#[tokio::test]
async fn spawn_now_is_strict() {
    let w = world();
    w.spawn(ALICE, "one").await;
    w.spawn(ALICE, "two").await;
    let a = w
        .call(
            ALICE,
            "box.spawn",
            json!({"template": "claude-code", "repo": "shop", "task": "three", "start": "now"}),
        )
        .await;
    assert_refused(&a, "busy", "busy");
    assert_eq!(w.mgr().list().len(), 2);
    // A queued box: stop of it is wrong_state (R1); discard cancels it.
    let q = w.spawn(ALICE, "three").await;
    assert_eq!(
        (q["box"]["id"].as_str(), q["box"]["state"].as_str()),
        (Some("b3"), Some("queued"))
    );
    assert_eq!(q["box"]["queue_pos"], 1);
    let a = w.call(ALICE, "box.stop", json!({"box": "b3"})).await;
    assert_refused(&a, "bad_request", "wrong_state");
    w.ok(ALICE, "box.discard", json!({"box": "b3"})).await;
}

#[tokio::test]
async fn tick_records_changes() {
    let w = world();
    let b = w.running(ALICE, "one").await;
    w.mgr()
        .guest_event(&id(&b), GuestEvent::TurnFinished)
        .unwrap();
    let before = w.records().len();
    w.clock.fetch_add(DONE_IDLE_SECS + 1, Ordering::SeqCst);
    assert_eq!(box_ops::tick_once(&w.ctx).await, 1);
    let recs = w.records();
    let new = &recs[before..];
    assert_eq!(new.len(), 1, "{new:?}");
    let r = &new[0];
    assert_eq!(r["action"], "tick");
    assert_eq!(r["box"], b.as_str());
    assert_eq!(r["session"], format!("box-{b}"));
    assert_eq!(r["from"], "running");
    assert_eq!(r["to"], "done");
    assert_eq!(r["via"], "tick");
    assert_eq!(r["uid"], 999, "the daemon's own record");
    // Nothing more to do: no record.
    assert_eq!(box_ops::tick_once(&w.ctx).await, 0);
    assert_eq!(w.records().len(), before + 1);
}

#[tokio::test]
async fn disk_floor_pauses_running_boxes() {
    // A manager whose free disk the test moves (spawn needs the headroom).
    let tmp = scratch();
    let state = tmp.path().join("state");
    let free = Arc::new(AtomicU64::new(1024 * 1024));
    let f = Arc::clone(&free);
    let o = Manager::open(ManagerInit {
        store: Store::open(box_ops::dir_in(&state)).unwrap(),
        vmm: Arc::new(FakeVmm::new()),
        guest: Arc::new(FakeGuest::new()),
        templates: template::builtin(),
        host: Arc::new(move || HostFacts {
            disk_free_mib: f.load(Ordering::SeqCst),
            ..two_boxes_host(3)
        }),
        clock: Arc::new(|| T0),
        disk_place: None,
    })
    .unwrap();
    let w = world_with(Setup {
        manager: true,
        template_warnings: Vec::new(),
        built: Some(Arc::new(o.manager)),
        unavailable: None,
    });
    let a = w.running(ALICE, "one").await;
    let b = w.running(ALICE, "two").await;
    let c = w.running(ALICE, "three").await;
    let before = w.records().len();
    assert_eq!(box_ops::tick_once(&w.ctx).await, 0, "plenty of disk");
    free.store(9 * 1024, Ordering::SeqCst);
    assert_eq!(box_ops::tick_once(&w.ctx).await, 3);
    for i in [&a, &b, &c] {
        let r = w.mgr().get(&id(i)).unwrap();
        assert_eq!(r.state.to_string_lossy(), "paused");
        assert_eq!(
            r.error.as_deref(),
            Some("paused: the host disk is almost full")
        );
    }
    let recs = w.records();
    let new = &recs[before..];
    assert_eq!(new.len(), 3, "{new:?}");
    for (r, i) in new.iter().zip([&a, &b, &c]) {
        assert_eq!(r["action"], "disk_low");
        assert_eq!(r["via"], "tick");
        assert_eq!(r["box"], i.as_str());
        assert_eq!(r["from"], "running");
        assert_eq!(r["to"], "paused");
        assert_eq!(r["reason"], "paused: the host disk is almost full");
    }
    // Still low: the paused boxes are not recorded again.
    assert_eq!(box_ops::tick_once(&w.ctx).await, 0);
    assert_eq!(w.records().len(), before + 3);
    // One resumed by hand while still low is paused again, with its record.
    w.mgr().resume(&id(&c)).unwrap();
    assert_eq!(w.mgr().get(&id(&c)).unwrap().error, None);
    assert_eq!(box_ops::tick_once(&w.ctx).await, 1);
    assert_eq!(w.records().len(), before + 4);
    // Back above the floor: nothing more.
    free.store(20 * 1024, Ordering::SeqCst);
    w.mgr().resume(&id(&c)).unwrap();
    assert_eq!(box_ops::tick_once(&w.ctx).await, 0);
    assert_eq!(
        w.mgr().get(&id(&c)).unwrap().state.to_string_lossy(),
        "running"
    );
}

#[tokio::test]
async fn list_reports_disk_per_entry() {
    let w = world();
    let b = w.running(ALICE, "one").await;
    let dir = w.mgr().root().join(&b);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("root.qcow2"), vec![7u8; 3 << 20]).unwrap();
    let l = w.ok(ALICE, "box.list", json!({})).await;
    assert!(l.get("disk").is_none(), "{l}");
    let e = &l["boxes"][0];
    let mib = e["disk_mib"].as_u64().expect("disk_mib present");
    assert!((3..=4).contains(&mib), "{l}");
}

#[tokio::test]
async fn spawn_records_the_heads_it_admits() {
    let w = world();
    let b1 = w.running(ALICE, "one").await;
    w.running(ALICE, "two").await;
    let q = w.spawn(BOB, "three").await;
    assert_eq!(q["box"]["state"], "queued");
    w.ok(ALICE, "box.stop", json!({"box": b1})).await;
    let before = w.records().len();
    let a = w.spawn(ALICE, "four").await;
    assert_eq!(a["box"]["id"], "b4");
    assert_eq!(a["box"]["state"], "queued");
    assert_eq!(
        w.mgr().get(&id("b3")).unwrap().state.to_string_lossy(),
        "starting"
    );
    let recs = w.records();
    let new = &recs[before..];
    let b3: Vec<_> = new.iter().filter(|r| r["box"] == "b3").collect();
    assert_eq!(b3.len(), 1, "{new:?}");
    let r = b3[0];
    assert_eq!(r["action"], "tick");
    assert_eq!(r["via"], "tick");
    assert_eq!(r["from"], "queued");
    assert_eq!(r["to"], "starting");
    assert_eq!(r["reason"], "admitted");
    assert_eq!(r["session"], "box-b3");
    assert_eq!(r["uid"], 999, "the daemon's own record");
    let b4: Vec<_> = new.iter().filter(|r| r["box"] == "b4").collect();
    assert_eq!(b4.len(), 1, "{new:?}");
    assert_eq!(b4[0]["action"], "spawn");
    assert_eq!(b4[0]["to"], "queued");
    assert_eq!(new.len(), 2, "{new:?}");
    // The tick has nothing left to record about b3.
    assert_eq!(box_ops::tick_once(&w.ctx).await, 0);
}

#[tokio::test]
async fn spawn_boot_failure_is_one_record_with_the_reason() {
    let w = world();
    let before = w.records().len();
    w.vmm.fail_next(VmOp::Boot, "no kvm");
    let a = w.spawn(ALICE, "one").await;
    assert_eq!(a["box"]["state"], "discarded");
    let recs = w.records();
    let new = &recs[before..];
    assert_eq!(new.len(), 1, "{new:?}");
    assert_eq!(new[0]["action"], "spawn");
    assert_eq!(new[0]["to"], "discarded");
    assert_eq!(new[0]["reason"], "boot failed: no kvm");
}

#[tokio::test]
async fn templates_lists_warnings() {
    let tmp = scratch();
    let xdg = tmp.path().join("xdg");
    let state = tmp.path().join("state");
    let env = |k: &str| -> Option<OsString> {
        match k {
            "SAIIFE_BOX_FAKE_VMM" => Some("1".into()),
            "XDG_CONFIG_HOME" => Some(xdg.clone().into_os_string()),
            "HOME" => Some(tmp.path().join("home").into_os_string()),
            _ => None,
        }
    };
    let (dir, trust) = box_ops::templates_dir(&Mode::Personal, &state.join("config.toml"), &env);
    assert_eq!(dir, xdg.join("saiife").join("templates.d"));
    assert_eq!(
        trust,
        saiife_boxes::template::Trust::OwnedBy(rustix::process::getuid().as_raw())
    );
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("broken.toml"), "this is not toml = [").unwrap();
    let built = box_ops::build_with(&state, &Mode::Personal, &state.join("config.toml"), &env)
        .unwrap()
        .expect("the fake VM is on");
    assert_eq!(
        built.template_warnings.len(),
        1,
        "{:?}",
        built.template_warnings
    );
    assert!(
        built.warnings.iter().any(|w| w.contains("broken.toml")),
        "{:?}",
        built.warnings
    );
    let w = world_with(Setup {
        manager: true,
        template_warnings: built.template_warnings.clone(),
        built: Some(built.manager),
        unavailable: None,
    });
    let a = w.ok(ALICE, "box.templates", json!({})).await;
    let names: Vec<&str> = a["templates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["claude-code"], "{a}");
    let warns = a["warnings"].as_array().unwrap();
    assert_eq!(warns.len(), 1, "{a}");
    assert!(
        warns[0]["file"].as_str().unwrap().ends_with("broken.toml"),
        "{a}"
    );
    assert!(!warns[0]["reason"].as_str().unwrap().is_empty(), "{a}");
}

#[tokio::test]
async fn fake_slots_env_pins_the_host() {
    let tmp = scratch();
    let state = tmp.path().join("state");
    let env = |k: &str| -> Option<OsString> {
        match k {
            "SAIIFE_BOX_FAKE_VMM" => Some("1".into()),
            "SAIIFE_BOX_FAKE_SLOTS" => Some("3".into()),
            _ => None,
        }
    };
    let built = box_ops::build_with(&state, &Mode::Locked, &state.join("config.toml"), &env)
        .unwrap()
        .expect("the fake VM is on");
    let (host, committed) = built.manager.capacity();
    assert_eq!(host.threads, 12);
    assert_eq!(host.cpu_pct, None);
    assert_eq!(host.mem_total_mib, host.mem_avail_mib);
    assert_eq!(capacity::slots(&host, &committed), (3, 3));
}

#[tokio::test]
async fn build_needs_the_fake_flag() {
    let tmp = scratch();
    let state = tmp.path().join("state");
    let off = |_: &str| -> Option<OsString> { None };
    // Without it the real driver's preflight runs: on the test's own locked
    // root (M1: never the host's /var/lib/saiife-box or /opt/saiife), which
    // has no install (read-only: nothing is created).
    let root = tmp.path().join("box-root");
    let seam = |k: &str| -> Option<OsString> {
        (k == "SAIIFE_TEST_BOX_ROOT").then(|| root.clone().into_os_string())
    };
    let why = box_ops::build_with(&state, &Mode::Locked, &state.join("config.toml"), &seam)
        .unwrap()
        .err()
        .expect("no boxes without the fake flag or an install");
    if cfg!(all(target_os = "linux", feature = "boxes")) {
        assert!(why.contains("install --boxes"), "{why}");
        assert!(
            why.contains(&root.display().to_string()),
            "the test root: {why}"
        );
        assert!(!root.exists());
    }
    assert!(!state.join("boxes").exists());
    let (dir, trust) =
        box_ops::templates_dir(&Mode::Locked, Path::new("/etc/saiife/config.toml"), &off);
    assert_eq!(dir, Path::new("/etc/saiife/templates.d"));
    assert_eq!(trust, saiife_boxes::template::Trust::RootOwned);
}

#[tokio::test]
async fn gc_by_non_admin_removes_only_own() {
    let w = world();
    // Two boot failures leave two Discarded records.
    w.vmm.fail_next(VmOp::Boot, "no kvm");
    let a = w.spawn(ALICE, "one").await;
    assert_eq!(a["box"]["state"], "discarded", "{a}");
    w.vmm.fail_next(VmOp::Boot, "no kvm");
    let b = w.spawn(BOB, "two").await;
    assert_eq!(b["box"]["state"], "discarded", "{b}");
    let before = w.records().len();
    let g = w.ok(BOB, "box.gc", json!({})).await;
    assert_eq!(g["removed"], json!(["b2"]), "{g}");
    assert!(w.mgr().get(&id("b1")).is_ok(), "alice's box stays");
    let g = w.ok(CAROL, "box.gc", json!({})).await;
    assert_eq!(g["removed"], json!(["b1"]), "{g}");
    let recs = w.records();
    let new = &recs[before..];
    assert_eq!(new.len(), 2, "{new:?}");
    assert!(new.iter().all(|r| r["action"] == "gc"), "{new:?}");
    assert_eq!(new[0]["removed"], json!(["b2"]));
}

#[tokio::test]
async fn list_entry_of_a_boot_failed_box_carries_its_error() {
    let w = world();
    w.vmm.fail_next(VmOp::Boot, "no kvm");
    w.spawn(ALICE, "one").await;
    let b = w.running(ALICE, "two").await;
    let l = w.ok(ALICE, "box.list", json!({})).await;
    let boxes = l["boxes"].as_array().unwrap();
    let failed = boxes.iter().find(|x| x["id"] == "b1").unwrap();
    assert_eq!(failed["error"], "boot failed: no kvm", "{l}");
    let fine = boxes.iter().find(|x| x["id"] == b.as_str()).unwrap();
    assert!(fine.get("error").is_none(), "{l}");
}

fn lock_all(w: &World) {
    w.ctx
        .lockdown
        .set(Some(Lockdown {
            scope: LockScope::All,
            reason: "incident".into(),
            by_uid: 0,
            since: "t".into(),
        }))
        .unwrap();
}

#[tokio::test]
async fn restart_changes_are_recorded() {
    let tmp = scratch();
    let state = tmp.path().join("state");
    let env = |k: &str| -> Option<OsString> {
        match k {
            "SAIIFE_BOX_FAKE_VMM" => Some("1".into()),
            "SAIIFE_BOX_FAKE_SLOTS" => Some("2".into()),
            _ => None,
        }
    };
    let cfg = state.join("config.toml");
    let first = box_ops::build_with(&state, &Mode::Locked, &cfg, &env)
        .unwrap()
        .expect("the fake VM is on");
    assert!(first.changes.is_empty(), "{:?}", first.changes);
    let m = &first.manager;
    let args = saiife_boxes::manager::SpawnArgs {
        template: "claude-code".into(),
        repo: "shop".into(),
        repo_dir: None,
        task: "one".into(),
        start: saiife_wire::source::Start::Queue,
        owner_uid: ALICE,
        repo_image: None,
        base_manifest: None,
    };
    let b = m.spawn(&args).unwrap().id;
    m.guest_event(&b, GuestEvent::Ready).unwrap();
    drop(first);
    // A new daemon: a new fake VMM, which knows no VM.
    let second = box_ops::build_with(&state, &Mode::Locked, &cfg, &env)
        .unwrap()
        .expect("the fake VM is on");
    assert_eq!(second.changes.len(), 1, "{:?}", second.changes);
    let w = world_with(Setup {
        manager: true,
        template_warnings: Vec::new(),
        built: Some(second.manager),
        unavailable: None,
    });
    for rec in box_ops::change_records(&w.ctx, &second.changes) {
        w.ctx.writer.append(rec).await.unwrap();
    }
    let recs = w.records();
    assert_eq!(recs.len(), 1, "{recs:?}");
    let r = &recs[0];
    assert_eq!(r["action"], "tick");
    assert_eq!(r["via"], "tick");
    assert_eq!(r["box"], b.as_str());
    assert_eq!(r["session"], format!("box-{}", b.as_str()));
    assert_eq!(r["template"], "claude-code");
    assert_eq!(r["from"], "running");
    assert_eq!(r["to"], "done");
    assert_eq!(r["reason"], "vm lost after restart");
    assert_eq!(r["uid"], 999, "the daemon's own record");
}

#[tokio::test]
async fn lockdown_holds_the_queue() {
    let w = world();
    let b1 = w.running(ALICE, "one").await;
    w.running(ALICE, "two").await;
    let q = w.spawn(BOB, "three").await;
    assert_eq!(q["box"]["state"], "queued");
    let b3 = q["box"]["id"].as_str().unwrap().to_string();
    lock_all(&w);
    // Allowed under lockdown, and it frees a slot.
    w.ok(ALICE, "box.stop", json!({"box": b1})).await;
    let before = w.vmm.calls().len();
    assert_eq!(box_ops::tick_once(&w.ctx).await, 0);
    assert_eq!(
        w.mgr().get(&id(&b3)).unwrap().state.to_string_lossy(),
        "queued"
    );
    assert_eq!(w.vmm.calls().len(), before, "no VM was made");
    w.ctx.lockdown.set(None).unwrap();
    assert_eq!(box_ops::tick_once(&w.ctx).await, 1);
    assert_eq!(
        w.mgr().get(&id(&b3)).unwrap().state.to_string_lossy(),
        "starting"
    );
    let recs = w.records();
    let last = recs.last().unwrap();
    assert_eq!(
        (&last["box"], &last["reason"]),
        (&json!(b3), &json!("admitted"))
    );
}

#[tokio::test]
async fn lockdown_holds_the_prompt() {
    let w = world();
    let a = w.spawn(ALICE, "add a cart").await;
    let b = id(a["box"]["id"].as_str().unwrap());
    lock_all(&w);
    let c = box_ops::guest_event(&w.ctx, b.clone(), GuestEvent::Ready)
        .await
        .unwrap()
        .expect("ready is a change");
    assert_eq!(c.why, "ready");
    let r = w.mgr().get(&b).unwrap();
    assert_eq!(r.state.to_string_lossy(), "running");
    assert_eq!(r.pending_prompt.as_deref(), Some("add a cart"));
    assert!(w.guest.prompts().is_empty(), "held under lockdown");
    let recs = w.records();
    assert_eq!(recs.last().unwrap()["reason"], "ready");
    box_ops::tick_once(&w.ctx).await;
    assert!(w.guest.prompts().is_empty(), "still held");
    w.ctx.lockdown.set(None).unwrap();
    box_ops::tick_once(&w.ctx).await;
    assert_eq!(
        w.guest.prompts(),
        vec![(b.clone(), "add a cart".to_string())]
    );
    assert_eq!(w.mgr().get(&b).unwrap().pending_prompt, None);
    box_ops::tick_once(&w.ctx).await;
    assert_eq!(w.guest.prompts().len(), 1, "sent once");
}

#[tokio::test]
async fn gc_goes_on_past_a_box_it_cannot_remove() {
    let w = world();
    for _ in 0..3 {
        w.vmm.fail_next(VmOp::Boot, "no kvm");
        let a = w.spawn(ALICE, "one").await;
        assert_eq!(a["box"]["state"], "discarded", "{a}");
    }
    let root = box_ops::dir_in(&w._tmp.path().join("state"));
    // Without its marker the store refuses to remove the dir.
    std::fs::remove_file(root.join("b1").join(".saiife-box")).unwrap();
    let before = w.records().len();
    let g = w.ok(ALICE, "box.gc", json!({})).await;
    assert_eq!(g["removed"], json!(["b2", "b3"]), "{g}");
    assert!(g["error"].is_string(), "{g}");
    let recs = w.records();
    let new = &recs[before..];
    assert_eq!(new.len(), 1, "{new:?}");
    assert_eq!(new[0]["action"], "gc");
    assert_eq!(new[0]["removed"], json!(["b2", "b3"]));
    assert_eq!(new[0]["reason"], g["error"]);
    // The admin path goes on the same way.
    w.vmm.fail_next(VmOp::Boot, "no kvm");
    w.spawn(BOB, "two").await;
    let g = w.ok(CAROL, "box.gc", json!({})).await;
    assert_eq!(g["removed"], json!(["b4"]), "{g}");
    assert!(g["error"].is_string(), "{g}");
    assert!(w.mgr().get(&id("b1")).is_ok(), "the stuck box stays");
}

// ---------------------------------------------------------------- plan 37

/// A sparse file of `len` bytes with the ext4 magic at 1080.
fn ext4_image(p: &Path, len: u64) -> std::fs::File {
    use std::os::unix::fs::FileExt;
    let f = std::fs::File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(p)
        .unwrap();
    f.set_len(len).unwrap();
    f.write_all_at(&[0x53, 0xEF], 1080).unwrap();
    f.write_all_at(b"repo data", 1 << 20).unwrap();
    f
}

fn manifest_file(p: &Path, repo: &str) -> std::fs::File {
    let text = format!(
        "{{\"version\":1,\"repo\":\"{repo}\",\"base_commit\":null,\
         \"snapshot_commit\":\"{}\",\"files\":0,\"bytes\":0,\"entries\":{{}}}}",
        "b".repeat(40)
    );
    std::fs::write(p, text).unwrap();
    std::fs::File::open(p).unwrap()
}

/// What `.incoming` holds.
fn incoming_entries(w: &World) -> Vec<PathBuf> {
    match std::fs::read_dir(w.mgr().root().join(".incoming")) {
        Ok(rd) => rd.map(|e| e.unwrap().path()).collect(),
        Err(_) => Vec::new(),
    }
}

/// A `box.spawn` whose connection was passed `fds`.
async fn spawn_passing(w: &World, fds: Vec<std::os::fd::OwnedFd>) -> Value {
    let conn = saiife_daemon::ops::Conn::new(peer(ALICE), None);
    *conn.fds.lock().unwrap() = fds;
    let req = Request {
        id: 7,
        op: "box.spawn".into(),
        args: json!({"template": "claude-code", "repo": "shop", "start": "queue"})
            .as_object()
            .cloned()
            .unwrap(),
    };
    let a = saiife_daemon::ops::dispatch_conn(&w.ctx, &conn, req).await;
    assert!(conn.take_fds().is_empty(), "the stash was taken");
    a
}

#[tokio::test]
async fn repo_fd_must_be_an_ext4_file() {
    use std::os::fd::OwnedFd;
    let w = world();
    let t = scratch();
    let plain = t.path().join("plain.img");
    std::fs::write(&plain, vec![0u8; 8192]).unwrap();
    let cases: Vec<(Vec<OwnedFd>, &str)> = vec![
        (
            vec![
                std::fs::File::open(&plain).unwrap().into(),
                manifest_file(&t.path().join("m1"), "shop").into(),
            ],
            "not an ext4 image",
        ),
        (
            vec![
                std::fs::File::open(t.path()).unwrap().into(),
                manifest_file(&t.path().join("m2"), "shop").into(),
            ],
            "not a regular file",
        ),
        (
            vec![ext4_image(&t.path().join("i3"), 4 << 20).into()],
            "two descriptors",
        ),
    ];
    for (fds, want) in cases {
        let a = spawn_passing(&w, fds).await;
        assert_eq!(a["ok"], false, "{a}");
        assert_eq!(a["error"], "bad_request", "{a}");
        assert!(a["message"].as_str().unwrap().contains(want), "{a}");
    }
    // Nothing claimed, nothing left, nothing recorded.
    assert!(w.mgr().list().is_empty());
    assert!(!w.mgr().root().join("b1").exists());
    assert!(incoming_entries(&w).is_empty());
    assert!(w.records().is_empty());
    // A refused spawn (unknown template) after a good intake: the copies go.
    let conn = saiife_daemon::ops::Conn::new(peer(ALICE), None);
    *conn.fds.lock().unwrap() = vec![
        ext4_image(&t.path().join("i4"), 4 << 20).into(),
        manifest_file(&t.path().join("m4"), "shop").into(),
    ];
    let req = Request {
        id: 8,
        op: "box.spawn".into(),
        args: json!({"template": "nope", "start": "queue"})
            .as_object()
            .cloned()
            .unwrap(),
    };
    let a = saiife_daemon::ops::dispatch_conn(&w.ctx, &conn, req).await;
    assert_eq!(a["error"], "bad_request", "{a}");
    assert!(incoming_entries(&w).is_empty());
}

/// A disk the daemon cannot take in for its own reasons (here `.incoming`
/// cannot hold a new dir) is `unavailable`, not the caller's `bad_request`.
#[tokio::test]
async fn intake_io_error_is_unavailable() {
    use std::os::unix::fs::PermissionsExt;
    let w = world();
    let t = scratch();
    let inc = w.mgr().root().join(".incoming");
    std::fs::create_dir(&inc).unwrap();
    std::fs::set_permissions(&inc, std::fs::Permissions::from_mode(0o500)).unwrap();
    let a = spawn_passing(
        &w,
        vec![
            ext4_image(&t.path().join("i1"), 4 << 20).into(),
            manifest_file(&t.path().join("m1"), "shop").into(),
        ],
    )
    .await;
    std::fs::set_permissions(&inc, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["error"], "unavailable", "{a}");
    assert!(
        a["message"].as_str().unwrap().contains("cannot make"),
        "{a}"
    );
    assert!(w.mgr().list().is_empty());
    assert!(incoming_entries(&w).is_empty());
    assert!(w.records().is_empty());
}

/// The whole path over a real control connection: hello, `box.fds` with the
/// disk and manifest, `box.spawn`. The box dir holds both before the VM's
/// create, the repo's name comes from the manifest and `.incoming` is empty
/// again; the next spawn on the connection, with no descriptors, has no
/// disk.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spawn_with_fds_roundtrip() {
    use saiife_ipc::frame::{body_len_max, encode_max, MAX_ANSWER_FRAME};
    use std::io::{Read, Write};
    use std::os::fd::AsFd;
    let w = world();
    let t = scratch();
    let img = ext4_image(&t.path().join("repo.img"), 64 << 20);
    let man = manifest_file(&t.path().join("base.json"), "demo");
    let (ours, theirs) = tokio::net::UnixStream::pair().unwrap();
    let server = tokio::spawn(saiife_daemon::server::connection(
        theirs,
        Arc::clone(&w.ctx),
    ));
    let mut s = ours.into_std().unwrap();
    s.set_nonblocking(false).unwrap();
    let answers = tokio::task::spawn_blocking(move || {
        let mut ask = |req: Value, fds: Option<[std::os::fd::BorrowedFd<'_>; 2]>| -> Value {
            s.write_all(&encode_max(&req, MAX_ANSWER_FRAME).unwrap())
                .unwrap();
            if let Some(f) = fds {
                saiife_ipc::fdpass::send_fds(&s, &f).unwrap();
            }
            let mut h = [0u8; 4];
            s.read_exact(&mut h).unwrap();
            let mut body = vec![0u8; body_len_max(h, MAX_ANSWER_FRAME).unwrap()];
            s.read_exact(&mut body).unwrap();
            serde_json::from_slice(&body).unwrap()
        };
        let hello = ask(
            json!({"id": 1, "op": saiife_ipc::msg::OP_HELLO, "proto": saiife_ipc::msg::PROTO}),
            None,
        );
        assert_eq!(hello["ok"], true, "{hello}");
        let fds = ask(
            json!({"id": 2, "op": saiife_ipc::msg::OP_BOX_FDS, "n": 2}),
            Some([img.as_fd(), man.as_fd()]),
        );
        assert_eq!(fds["ok"], true, "{fds}");
        drop((img, man));
        let one = ask(
            json!({"id": 3, "op": "box.spawn", "template": "claude-code", "task": "t"}),
            None,
        );
        let two = ask(
            json!({"id": 4, "op": "box.spawn", "template": "claude-code", "repo": "shop"}),
            None,
        );
        (one, two)
    })
    .await
    .unwrap();
    let (one, two) = answers;
    assert_eq!(one["ok"], true, "{one}");
    assert_eq!(one["box"]["id"], "b1", "{one}");
    assert_eq!(one["box"]["state"], "starting", "{one}");
    assert_eq!(one["box"]["repo"], "demo", "{one}");
    assert_eq!(w.vmm.saw_repo_disk(&id("b1")), Some(true));
    let dir = w.mgr().root().join("b1");
    let disk = std::fs::read(dir.join("repo.img")).unwrap();
    assert_eq!(disk.len(), 64 << 20);
    assert_eq!(&disk[1080..1082], &[0x53, 0xEF]);
    assert_eq!(&disk[1 << 20..(1 << 20) + 9], b"repo data");
    let base = std::fs::read_to_string(dir.join("base.json")).unwrap();
    assert!(base.contains("\"demo\""), "{base}");
    assert!(incoming_entries(&w).is_empty());
    assert_eq!(two["ok"], true, "{two}");
    assert_eq!(two["box"]["id"], "b2", "{two}");
    assert!(!w.mgr().root().join("b2/repo.img").exists());
    server.abort();
}

/// Plan 37 Task 4b, with plan 35's R37: the store root the daemon hands to
/// intake, gc and `disk::usage` is the record root (`layout::boxes_in`),
/// never the VMM's runtime root, and the disk placer is BoxPaths' under it.
#[test]
fn the_box_root_and_disk_places_are_the_layouts() {
    use saiife_boxhost::layout::{boxes_in, Layout};
    use saiife_boxhost::paths::BoxPaths;
    let state = Path::new("/s/state");
    let root = box_ops::dir_in(state);
    assert_eq!(root, boxes_in(state));
    assert_ne!(root, Layout::personal(state, Path::new("/s/data")).boxes);
    let place = box_ops::disk_place().expect("a placer on unix");
    let got = place(&root, &id("b4"));
    let want = BoxPaths::of(&root, &id("b4"));
    assert_eq!(got.repo_image, want.repo_disk());
    assert_eq!(got.base_manifest, want.base_manifest());
}

/// The env of a personal daemon whose data and home are under `tmp`.
fn personal_env(tmp: &Path, fake: bool) -> impl Fn(&str) -> Option<OsString> {
    let tmp = tmp.to_path_buf();
    move |k: &str| -> Option<OsString> {
        match k {
            "SAIIFE_BOX_FAKE_VMM" if fake => Some("1".into()),
            "SAIIFE_BOX_FAKE_SLOTS" if fake => Some("1".into()),
            "XDG_DATA_HOME" => Some(tmp.join("data").into_os_string()),
            "XDG_CONFIG_HOME" => Some(tmp.join("config").into_os_string()),
            "HOME" => Some(tmp.join("home").into_os_string()),
            // M-2: the personal preflight never probes the host's /dev/kvm
            "SAIIFE_TEST_KVM" => Some(tmp.join("kvm").into_os_string()),
            _ => None,
        }
    }
}

/// R38: a build without the `boxes` feature never runs the real driver: no
/// fake flag is plan 34's answer, saying boxes are not enabled.
#[cfg(not(feature = "boxes"))]
#[tokio::test]
async fn without_the_boxes_feature_boxes_are_not_enabled() {
    let tmp = scratch();
    let state = tmp.path().join("state");
    let env = personal_env(tmp.path(), false);
    let why = box_ops::build_with(&state, &Mode::Personal, &state.join("config.toml"), &env)
        .unwrap()
        .err()
        .expect("no boxes");
    assert!(why.starts_with(box_ops::UNAVAILABLE), "{why}");
    assert!(why.contains("boxes are not enabled in this build"), "{why}");
    let w = world_with(Setup {
        manager: false,
        template_warnings: Vec::new(),
        built: None,
        unavailable: Some(why.clone()),
    });
    let a = w.call(ALICE, "box.list", json!({})).await;
    assert_eq!(a["error"], "unavailable", "{a}");
    assert_eq!(a["message"], why.as_str(), "{a}");
}

/// No VMM in the personal layout and no fake flag: the preflight fails
/// before anything is made or spawned, and every op answers its detail.
#[cfg(all(target_os = "linux", feature = "boxes"))]
#[tokio::test]
async fn unavailable_message_names_the_failed_check() {
    let tmp = scratch();
    let state = tmp.path().join("state");
    let env = personal_env(tmp.path(), false);
    let why = box_ops::build_with(&state, &Mode::Personal, &state.join("config.toml"), &env)
        .unwrap()
        .err()
        .expect("no VMM: boxes are unavailable");
    assert!(why.contains("saiife box vmm fetch"), "{why}");
    assert!(!state.join("boxes").exists(), "nothing is created");
    assert!(!tmp.path().join("data").exists(), "nothing is created");
    let w = world_with(Setup {
        manager: false,
        template_warnings: Vec::new(),
        built: None,
        unavailable: Some(why.clone()),
    });
    for (op, args) in EVERY_OP {
        let a = w.call(ALICE, op, serde_json::from_str(args).unwrap()).await;
        assert_eq!(a["ok"], false, "{op}: {a}");
        assert_eq!(a["error"], "unavailable", "{op}: {a}");
        assert_eq!(a["message"], why.as_str(), "{op}: {a}");
    }
    assert!(w.records().is_empty());
}

/// The fake flag wins over the preflight: plan 34's fake manager, with no
/// VMM anywhere.
#[tokio::test]
async fn fake_env_still_wins() {
    let tmp = scratch();
    let state = tmp.path().join("state");
    let env = personal_env(tmp.path(), true);
    let built = box_ops::build_with(&state, &Mode::Personal, &state.join("config.toml"), &env)
        .unwrap()
        .expect("the fake VM is on");
    let b = built
        .manager
        .spawn(&saiife_boxes::manager::SpawnArgs {
            template: "claude-code".into(),
            repo: "shop".into(),
            repo_dir: None,
            task: "one".into(),
            start: saiife_wire::source::Start::Queue,
            owner_uid: ALICE,
            repo_image: None,
            base_manifest: None,
        })
        .unwrap();
    assert_eq!(b.vm.as_ref().map(|h| h.driver.as_str()), Some("fake"));
    assert!(state.join("boxes").join(b.id.as_str()).is_dir());
}

/// R37: the box records stay in the daemon's own state dir in both modes;
/// only the VMM's runtime dirs differ (`/var/lib/saiife-box/boxes` locked,
/// `<state>/box-run` personal).
#[test]
fn records_stay_in_the_state_dir() {
    assert_eq!(
        box_ops::dir_in(Path::new("/var/lib/saiife")),
        Path::new("/var/lib/saiife/boxes")
    );
    assert_eq!(
        box_ops::dir_in(Path::new("/s/state")),
        Path::new("/s/state/boxes")
    );
}

#[cfg(all(target_os = "linux", feature = "boxes"))]
#[test]
fn runtime_dirs_are_apart_from_the_records() {
    use saiife_daemon::box_vmm::layout_for;
    let none = |_: &str| -> Option<OsString> { None };
    let locked = layout_for(Path::new("/var/lib/saiife"), &Mode::Locked, &none).unwrap();
    assert_eq!(locked.boxes, Path::new("/var/lib/saiife-box/boxes"));
    let home = |k: &str| (k == "HOME").then(|| OsString::from("/h"));
    let personal = layout_for(Path::new("/s/state"), &Mode::Personal, &home).unwrap();
    assert_eq!(personal.boxes, Path::new("/s/state/box-run"));
    assert_ne!(personal.boxes, box_ops::dir_in(Path::new("/s/state")));
}

/// R36: a snapshot the driver did not trust is a `box` record of the
/// daemon, made from the box id alone (the hook runs under the manager's
/// lock, inside its VMM call), with the reason sanitized.
#[tokio::test]
async fn restore_refused_is_audited() {
    // (the hook type exists in `boxes` builds on Linux; the link everywhere)
    let w = world();
    let link = Arc::new(box_ops::AuditLink::default());
    // Before the context is attached: a stderr line, no record, no panic.
    let l = Arc::clone(&link);
    tokio::task::spawn_blocking(move || l.restore_refused(&id("b1"), "early"))
        .await
        .unwrap();
    link.attach(&w.ctx);
    #[cfg(all(target_os = "linux", feature = "boxes"))]
    let hook: Arc<dyn saiife_boxhost::vmm::VmHooks> =
        Arc::new(saiife_daemon::box_vmm::AuditHooks::new(Arc::clone(&link)));
    tokio::task::spawn_blocking(move || {
        #[cfg(all(target_os = "linux", feature = "boxes"))]
        hook.restore_refused(&id("b1"), "digest \u{1b}[31mmismatch");
        #[cfg(not(all(target_os = "linux", feature = "boxes")))]
        link.restore_refused(&id("b1"), "digest \u{1b}[31mmismatch");
    })
    .await
    .unwrap();
    let mut recs = Vec::new();
    for _ in 0..100 {
        recs = w.records();
        if !recs.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(recs.len(), 1, "{recs:?}");
    let r = &recs[0];
    assert_eq!(r["action"], "restore_refused", "{r}");
    assert_eq!(r["box"], "b1");
    assert_eq!(r["session"], "box-b1");
    assert_eq!(r["via"], "vmm");
    assert_eq!(r["uid"], 999, "the daemon's own record");
    let why = r["reason"].as_str().unwrap();
    assert!(why.contains("digest") && why.contains("mismatch"), "{r}");
    assert!(!why.contains('\u{1b}'), "{r}");
}

/// M1: the debug-only locked layout seam re-roots every locked path, and a
/// locked layout that is not the real one never reaches the system bus.
#[cfg(all(target_os = "linux", feature = "boxes"))]
#[test]
fn locked_test_layout_never_reaches_the_bus() {
    use saiife_daemon::box_vmm::{layout_for, real_vmm_with};
    let tmp = scratch();
    let root = tmp.path().join("box-root");
    let seam = |k: &str| -> Option<OsString> {
        (k == "SAIIFE_TEST_BOX_ROOT").then(|| root.clone().into_os_string())
    };
    let l = layout_for(Path::new("/var/lib/saiife"), &Mode::Locked, &seam).unwrap();
    assert!(l.locked);
    for p in [&l.boxes, &l.images, &l.vmm, &l.vault] {
        assert!(p.starts_with(&root), "{}", p.display());
    }
    assert_eq!(l.boxes, root.join("var/lib/saiife-box/boxes"));
    for p in [&l.images, &l.vmm, &l.vault] {
        std::fs::create_dir_all(p).unwrap();
    }
    let records = tmp.path().join("records");
    let image_records = tmp.path().join("image-records");
    let e = real_vmm_with(
        &l,
        &records,
        &image_records,
        &Mode::Locked,
        Vec::new(),
        &seam,
    )
    .err()
    .expect("refused");
    assert!(e.contains("system bus"), "{e}");
}

/// M-4: a test box root that resolves to `/`, or into the real locked
/// roots, or is not absolute, is an error (never the real layout, never
/// the system bus); unset is the real layout.
#[cfg(all(target_os = "linux", feature = "boxes"))]
#[test]
fn test_box_root_refuses_the_real_root() {
    use saiife_daemon::box_vmm::layout_for;
    for bad in [
        "/",
        "/.",
        "//",
        "/tmp/..",
        "/var/lib/saiife-box",
        "/var/lib/saiife-box/boxes",
        "/opt/saiife",
        "relative/root",
        "",
    ] {
        let seam = |k: &str| (k == "SAIIFE_TEST_BOX_ROOT").then(|| OsString::from(bad));
        let e = layout_for(Path::new("/var/lib/saiife"), &Mode::Locked, &seam).expect_err(bad);
        assert!(e.contains("SAIIFE_TEST_BOX_ROOT"), "{bad}: {e}");
    }
    let none = |_: &str| -> Option<OsString> { None };
    let l = layout_for(Path::new("/var/lib/saiife"), &Mode::Locked, &none).unwrap();
    assert_eq!(l, saiife_boxhost::layout::Layout::locked());
}

/// M-2: the device the personal preflight probes: `/dev/kvm`, or the
/// debug-only `SAIIFE_TEST_KVM` file (absolute only).
#[cfg(all(target_os = "linux", feature = "boxes"))]
#[test]
fn kvm_seam_replaces_the_device_in_tests() {
    use saiife_daemon::box_vmm::kvm_path;
    let none = |_: &str| -> Option<OsString> { None };
    assert_eq!(kvm_path(&none), Path::new("/dev/kvm"));
    let seam = |k: &str| (k == "SAIIFE_TEST_KVM").then(|| OsString::from("/s/kvm"));
    assert_eq!(kvm_path(&seam), Path::new("/s/kvm"));
    let rel = |k: &str| (k == "SAIIFE_TEST_KVM").then(|| OsString::from("kvm"));
    assert_eq!(kvm_path(&rel), Path::new("/dev/kvm"));
}
