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
    HostFacts {
        mem_total_mib: 8192 + 2 * capacity::charge_mib(&Size::default()),
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
    clock: Arc<AtomicU64>,
    audit: PathBuf,
    _tmp: tempfile::TempDir,
}

struct Setup {
    manager: bool,
    template_warnings: Vec<saiife_boxes::template::TemplateWarning>,
    built: Option<Arc<Manager>>,
}

fn world() -> World {
    world_with(Setup {
        manager: true,
        template_warnings: Vec::new(),
        built: None,
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
            let (m, warns) = Manager::open(ManagerInit {
                store: Store::open(box_ops::dir_in(&state)).unwrap(),
                vmm: vmm.clone(),
                guest: g,
                templates: template::builtin(),
                host: Arc::new(move || host),
                clock: Arc::new(move || c.load(Ordering::SeqCst)),
            })
            .unwrap();
            assert!(warns.is_empty(), "{warns:?}");
            Some(Arc::new(m))
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
        box_template_warnings: s.template_warnings,
        ..base
    }));
    World {
        ctx,
        mgr,
        vmm,
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
    assert!(
        box_ops::build_with(&state, &Mode::Locked, &state.join("config.toml"), &off)
            .unwrap()
            .is_none()
    );
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
