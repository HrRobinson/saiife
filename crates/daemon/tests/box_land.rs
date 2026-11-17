//! The land book (plan 39 Task 4): reviews per box, land touch records in
//! plan 26's touch state, Workspace approve/reject through `complete`,
//! multi-land. A box manager on `FakeVmm` and `FakeGuest` (prompts), and a
//! `VsockGuest` over plan 38's test multiplexer whose fake guest keeps a
//! base tree and a work tree and serves exports of the difference (made
//! with `write_delta`; `common/land_guest.rs`, shared with
//! `workspace_land.rs`). Touches use plan 26's `SoftAuthenticator`. No VM
//! is ever started.
//!
//! Task 5: the control-socket ops (`box.diff`, `box.land.*`, `box.push.*`,
//! `box.discard --force`) through `ops::dispatch_conn`, and once over the
//! real socket with `Client`.
#![cfg(all(unix, feature = "fake-vmm"))]

mod common;

use common::land_guest::{self, *};
use saiife_audit::{ChainWriter, WriterOptions};
use saiife_boxes::capacity::{self, HostFacts};
use saiife_boxes::guest::fake::FakeGuest;
use saiife_boxes::guest::{GuestEvent, GuestLink};
use saiife_boxes::manager::{Manager, ManagerInit, SpawnArgs};
use saiife_boxes::source::{LandBook, ManagerSource};
use saiife_boxes::store::Store;
use saiife_boxes::template::{self, Size};
use saiife_boxes::vmm::fake::FakeVmm;
use saiife_boxes::{BoxError, BoxId, BoxState};
use saiife_boxhost::guest::VsockGuest;
use saiife_boxhost::paths::{BoxPaths, RecordPaths, BASE_MANIFEST};
use saiife_boxhost::vmm::VmHooks;
use saiife_boxproto::msg::Request;
use saiife_broker::pipeline::{LockScope, Lockdown};
use saiife_daemon::box_land::{self, Lands};
use saiife_daemon::box_ops;
use saiife_daemon::ops::{dispatch_conn, Conn, Ctx, CtxInit, Mode, PolicyState};
use saiife_daemon::touch::IssueKey;
use saiife_daemon::writer::{self, WriterConfig};
use saiife_ipc::msg::Request as IpcRequest;
use saiife_ipc::peer::PeerCred;
use saiife_policy::{Directory, Fsync};
use saiife_touch::soft::SoftAuthenticator;
use saiife_touch::{
    challenge, ActionRecord, TouchClass, TouchError, TouchEvidence, LOCAL_RP_ID as RP,
};
use saiife_wire::conformance::{check, Fixture};
use saiife_wire::source::{BoxSource, Decision, PendingAction, Start};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const ALICE: u32 = 2000;
const BOB: u32 = 2001;
/// A user with no touch device.
const CAROL: u32 = 2002;
const T0: u64 = 1_800_000_000;
const T: Duration = Duration::from_secs(10);

fn scratch() -> tempfile::TempDir {
    let base = std::env::var_os("SAIIFE_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    std::fs::create_dir_all(&base).unwrap();
    tempfile::Builder::new()
        .prefix("l")
        .tempdir_in(base)
        .unwrap()
}

fn me() -> u32 {
    rustix::process::geteuid().as_raw()
}

// ---- the world ----

struct World {
    ctx: Arc<Ctx>,
    mgr: Arc<Manager>,
    lands: Arc<Lands>,
    guest: Arc<VsockGuest>,
    clock: Arc<AtomicU64>,
    audit: PathBuf,
    /// The box records (the store root; the land records live here, R37).
    root: PathBuf,
    /// The VMM runtime dirs (`Layout.boxes`), apart from the records.
    runtime: PathBuf,
    served: Mutex<BTreeMap<BoxId, Served>>,
    keys: BTreeMap<u32, SoftAuthenticator>,
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

fn world(slots: u64) -> World {
    world_with(slots, true)
}

/// A world whose land book is attached to the context or not (`attach`).
fn world_with(slots: u64, attach: bool) -> World {
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
            "admins:x:3000:\n",
        ));
    let clock = Arc::new(AtomicU64::new(T0));
    let root = box_ops::dir_in(&state);
    let c = Arc::clone(&clock);
    let h = host(slots);
    let fake: Arc<dyn GuestLink> = Arc::new(FakeGuest::new());
    let o = Manager::open(ManagerInit {
        store: Store::open(root.clone()).unwrap(),
        vmm: Arc::new(FakeVmm::new()),
        guest: fake,
        templates: template::builtin(),
        host: Arc::new(move || h),
        clock: Arc::new(move || c.load(Ordering::SeqCst)),
        disk_place: box_ops::disk_place(),
    })
    .unwrap();
    let mgr = Arc::new(o.manager);
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
        box_manager: Some(Arc::clone(&mgr)),
        ..base
    }));
    let mut keys = BTreeMap::new();
    for uid in BTreeSet::from([ALICE, BOB, me()]) {
        let s = SoftAuthenticator::new_es256();
        ctx.touch.add(s.credential(RP, uid, "k")).unwrap();
        keys.insert(uid, s);
    }
    let guest = VsockGuest::new(Arc::new(Setups), false, me());
    // the VMM runtime dirs, apart from the records (R37)
    let runtime = state.join("runtime");
    let c = Arc::clone(&clock);
    let lands = Lands::with_clock(
        Arc::clone(&ctx),
        Arc::clone(&mgr),
        Arc::clone(&guest),
        Arc::new(move || c.load(Ordering::SeqCst)),
    );
    if attach {
        assert!(ctx.box_lands.set(Arc::clone(&lands)).is_ok());
    }
    World {
        ctx,
        mgr,
        lands,
        guest,
        clock,
        audit,
        root,
        runtime,
        served: Mutex::new(BTreeMap::new()),
        keys,
        _tmp: tmp,
    }
}

impl World {
    fn now(&self) -> u64 {
        self.clock.load(Ordering::SeqCst)
    }

    fn paths(&self, i: &BoxId) -> RecordPaths {
        RecordPaths::of(&self.root, i)
    }

    /// Box `i`'s runtime dir (the vsock sockets).
    fn rt(&self, i: &BoxId) -> BoxPaths {
        let p = BoxPaths::of(&self.runtime, i);
        std::fs::create_dir_all(&p.dir).unwrap();
        p
    }

    /// A spawned box of `uid` (Queued, or Starting when there is room).
    fn spawn(&self, uid: u32) -> BoxId {
        self.mgr
            .spawn(&SpawnArgs {
                template: "claude-code".into(),
                repo: "demo".into(),
                repo_dir: None,
                task: "make it better".into(),
                start: Start::Queue,
                owner_uid: uid,
                repo_image: None,
                base_manifest: None,
            })
            .unwrap()
            .id
    }

    /// A Running box of `uid` whose repo is `base` and whose guest serves
    /// exports of `/work` = `work`.
    fn running(&self, uid: u32, base: &Tree, work: &Tree) -> BoxId {
        let i = self.spawn(uid);
        let p = self.paths(&i);
        std::fs::write(
            p.dir.join(BASE_MANIFEST),
            serde_json::to_string(&manifest(base)).unwrap(),
        )
        .unwrap();
        self.connect(&i, base, work);
        self.mgr.guest_event(&i, GuestEvent::Ready).unwrap();
        assert_eq!(self.state(&i), BoxState::Running);
        i
    }

    /// A Done box of `uid` (base → work), its review made.
    fn done(&self, uid: u32, work: &Tree) -> BoxId {
        let i = self.running(uid, &base_tree(), work);
        self.mgr.done(&i).unwrap();
        self.lands.refresh(&i).unwrap();
        i
    }

    fn connect(&self, i: &BoxId, base: &Tree, work: &Tree) {
        let p = self.rt(i);
        let s = land_guest::connect(&self.guest, &p, i, base, work);
        self.served.lock().unwrap().insert(i.clone(), s);
    }

    fn with_repo<T>(&self, i: &BoxId, f: impl FnOnce(&mut GuestRepo) -> T) -> T {
        let s = self.served.lock().unwrap();
        let mut g = s[i].repo.lock().unwrap();
        f(&mut g)
    }

    fn requests(&self, i: &BoxId) -> Vec<Request> {
        self.served.lock().unwrap()[i]
            .requests
            .lock()
            .unwrap()
            .clone()
    }

    fn exports(&self, i: &BoxId) -> usize {
        self.requests(i)
            .iter()
            .filter(|r| matches!(r, Request::Export { .. }))
            .count()
    }

    fn state(&self, i: &BoxId) -> BoxState {
        self.mgr.get(i).unwrap().state
    }

    fn src(&self, owner: Option<u32>) -> ManagerSource {
        ManagerSource::new(Arc::clone(&self.mgr), owner).with_lands(self.lands.clone())
    }

    fn pending_of(&self, i: &BoxId) -> PendingAction {
        self.lands
            .pending()
            .into_iter()
            .find(|p| p.box_id.as_ref() == Some(i))
            .unwrap_or_else(|| panic!("no pending land for {}", i.as_str()))
    }

    /// The owner's touch for `p`'s record, verified as plan 31 does.
    fn evidence(&self, uid: u32, p: &PendingAction) -> TouchEvidence {
        let asr = self.keys[&uid].assert_ctap(RP, &challenge(&p.record));
        self.ctx
            .touch
            .verify_counted(uid, &p.record, &asr, RP, self.now())
            .unwrap()
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

    fn actions(&self, action: &str) -> Vec<Value> {
        self.records()
            .into_iter()
            .filter(|r| r["action"] == action)
            .collect()
    }
}

fn files_of(w: &World, i: &BoxId) -> Vec<String> {
    w.lands
        .latest(i)
        .unwrap()
        .summary
        .files
        .iter()
        .map(|f| f.path.clone())
        .collect()
}

// ---- the tests ----

#[test]
fn manager_source_with_lands_passes_conformance() {
    let w = world(2);
    let b1 = w.running(ALICE, &base_tree(), &base_tree());
    let b2 = w.done(ALICE, &changed());
    let b3 = w.spawn(ALICE);
    let b4 = w.spawn(ALICE);
    assert_eq!(w.state(&b3), BoxState::Queued);
    let src = w.src(Some(ALICE));
    // The land binding is exercised: b2 has a pending land.
    assert_eq!(src.pending_actions().len(), 1);
    let r = check(&Fixture {
        source: &src,
        running: b1,
        done: b2,
        queued: vec![b3, b4],
        template: "claude-code".into(),
    });
    assert_eq!(r, Ok(()));
}

#[test]
fn pending_issues_four_per_owner() {
    let w = world(6);
    let ids: Vec<BoxId> = (0..5)
        .map(|_| {
            w.clock.fetch_add(1, Ordering::SeqCst);
            w.done(ALICE, &changed())
        })
        .collect();
    let p = w.lands.pending();
    assert_eq!(p.len(), 4, "{p:?}");
    let shown: Vec<BoxId> = p.iter().map(|x| x.box_id.clone().unwrap()).collect();
    assert_eq!(shown, ids[..4].to_vec(), "the four oldest");
    for x in &p {
        let i = x.box_id.as_ref().unwrap();
        let r = w.lands.latest(i).unwrap();
        let f = &x.record.fields;
        assert_eq!(x.class, TouchClass::Land);
        assert_eq!(f["diff_sha256"], r.summary.diff_sha256);
        assert_eq!(f["base_commit"], "b".repeat(40));
        assert_eq!(f["repo"], "demo");
        assert_eq!(f["target_ref"], format!("saiife/box-{}", i.as_str()));
        assert!(
            x.summary
                .starts_with(&format!("land {}: 3 files (+2 \u{2212}1)", i.as_str())),
            "{}",
            x.summary
        );
        assert!(w.paths(i).land_request(r.n).exists());
    }
    // Stable: the same requests again.
    let again: Vec<u64> = w.lands.pending().iter().map(|x| x.request_id).collect();
    assert_eq!(again, p.iter().map(|x| x.request_id).collect::<Vec<_>>());
    // One decided (rejected): the fifth appears.
    w.src(Some(ALICE))
        .complete(p[0].request_id, Decision::Reject, None)
        .unwrap();
    let next: Vec<BoxId> = w
        .lands
        .pending()
        .iter()
        .map(|x| x.box_id.clone().unwrap())
        .collect();
    assert_eq!(next, ids[1..].to_vec());
}

/// `box_waiting`, in the notifier's queue (the test double: no target
/// is configured, so nothing leaves it).
fn waiting(w: &World) -> Vec<saiife_daemon::notifier::NotifyEvent> {
    w.ctx
        .notifier
        .queued_events()
        .into_iter()
        .filter(|e| e.event == saiife_policy::Event::BoxWaiting)
        .collect()
}

#[test]
fn a_finished_run_sends_box_waiting_once() {
    let w = world(3);
    let b = w.done(ALICE, &changed());
    assert!(waiting(&w).is_empty());
    let p = w.lands.pending();
    assert_eq!(p.len(), 1);
    let q = waiting(&w);
    assert_eq!(q.len(), 1, "{q:?}");
    assert_eq!(q[0].box_id.as_deref(), Some(b.as_str()));
    let code = p[0].view().short_code;
    assert!(q[0].summary.contains(&code), "{}", q[0].summary);
    // Nothing in it approves: no link, no request id.
    let text = format!("{:?} {:?} {:?}", q[0].summary, q[0].service, q[0].operation);
    assert!(!text.contains("http"), "{text}");
    assert!(!text.contains(&p[0].request_id.to_string()), "{text}");
    assert!(q[0].id.is_none());
    // The inbox poll lists again: the same request, no second event.
    for _ in 0..3 {
        let again = w.lands.pending();
        assert_eq!(again[0].request_id, p[0].request_id);
    }
    assert_eq!(waiting(&w).len(), 1);
}

/// Task 5 (a): `box_waiting` is once per finished run, not per request id.
/// The request expires and is issued again under a new id for the same
/// review: no second event.
#[test]
fn a_reissued_request_for_the_same_run_sends_no_second_box_waiting() {
    let w = world(3);
    let i = w.done(ALICE, &changed());
    let first = w.pending_of(&i);
    assert_eq!(waiting(&w).len(), 1);
    for _ in 0..3 {
        w.clock
            .fetch_add(saiife_touch::CHALLENGE_TTL_SECS + 1, Ordering::SeqCst);
        let again = w.pending_of(&i);
        assert_ne!(again.request_id, first.request_id);
    }
    assert_eq!(waiting(&w).len(), 1, "{:?}", waiting(&w));
}

/// Task 5 (a): a new finished run of the same box (revised, runs, Done
/// again with a new review) notifies again, once.
#[test]
fn a_new_finished_run_sends_box_waiting_again() {
    let w = world(3);
    let i = w.done(ALICE, &changed());
    w.pending_of(&i);
    assert_eq!(waiting(&w).len(), 1);
    w.mgr.revise(&i, "add docs").unwrap();
    // The inbox polls while it runs: nothing waits.
    assert!(w.lands.pending().is_empty());
    w.with_repo(&i, |g| {
        g.work.insert("docs.md".into(), C(b"docs\n".to_vec()));
    });
    w.mgr.done(&i).unwrap();
    w.lands.refresh(&i).unwrap();
    for _ in 0..3 {
        w.pending_of(&i);
    }
    let q = waiting(&w);
    assert_eq!(q.len(), 2, "{q:?}");
    assert!(q.iter().all(|e| e.box_id.as_deref() == Some(i.as_str())));
}

/// Task 5 (a): a new run whose result is byte-identical to the one already
/// notified still notifies (the run finished again), when the book saw the
/// box leave `Done` in between.
#[test]
fn a_new_run_with_the_same_result_notifies_again() {
    let w = world(3);
    let i = w.done(ALICE, &changed());
    w.pending_of(&i);
    w.mgr.revise(&i, "again").unwrap();
    assert!(w.lands.pending().is_empty());
    w.mgr.done(&i).unwrap();
    w.lands.refresh(&i).unwrap();
    w.pending_of(&i);
    assert_eq!(waiting(&w).len(), 2, "{:?}", waiting(&w));
}

#[test]
fn owner_scoped_pending_hides_others() {
    let w = world(3);
    let a = w.done(ALICE, &changed());
    let b = w.done(BOB, &changed());
    let pa = w.src(Some(ALICE)).pending_actions();
    assert_eq!(pa.len(), 1);
    assert_eq!(pa[0].box_id.as_ref(), Some(&a));
    let pb = w.src(Some(BOB)).pending_actions();
    assert_eq!(pb.len(), 1);
    assert_eq!(pb[0].box_id.as_ref(), Some(&b));
    assert_eq!(w.src(None).pending_actions().len(), 2);
    // Bob cannot decide Alice's request: it is a missing one.
    assert_eq!(
        w.src(Some(BOB))
            .complete(pa[0].request_id, Decision::Reject, None),
        Err(BoxError::NotFound)
    );
    assert_eq!(w.src(Some(ALICE)).pending_actions().len(), 1);
    // The record is issued to the box's owner.
    let e = w.evidence(BOB, &pb[0]);
    assert!(e.user_verified);
}

#[test]
fn expired_pending_is_reissued() {
    let w = world(2);
    let i = w.done(ALICE, &changed());
    let first = w.pending_of(&i);
    w.clock
        .fetch_add(saiife_touch::CHALLENGE_TTL_SECS + 1, Ordering::SeqCst);
    let second = w.pending_of(&i);
    assert_ne!(first.request_id, second.request_id);
    assert!(second.expires_at > first.expires_at);
    assert_eq!(
        second.record.fields["diff_sha256"],
        first.record.fields["diff_sha256"]
    );
    // The expired one is gone.
    assert_eq!(
        w.lands.complete(first.request_id, Decision::Reject, None),
        Err(BoxError::NotFound)
    );
}

#[test]
fn complete_approve_lands_and_advances() {
    let w = world(2);
    let i = w.done(ALICE, &changed());
    let n = w.lands.latest(&i).unwrap().n;
    let p = w.pending_of(&i);
    let ev = w.evidence(ALICE, &p);
    w.src(Some(ALICE))
        .complete(p.request_id, Decision::Approve, Some(ev.clone()))
        .unwrap();
    let r = w.mgr.get(&i).unwrap();
    assert_eq!((r.state, r.lands), (BoxState::Landed, 1));
    assert!(w
        .requests(&i)
        .contains(&Request::Advance { n, paths: None }));
    assert_eq!(w.with_repo(&i, |g| g.base.clone()), changed());
    let lands = w.actions("land");
    assert_eq!(lands.len(), 1, "{lands:?}");
    let l = &lands[0];
    assert_eq!(l["box"], i.as_str());
    assert_eq!(l["land"], n);
    assert_eq!(l["via"], "web");
    assert_eq!(l["files"], 3);
    assert_eq!(l["diff_sha256"], p.record.fields["diff_sha256"].as_str());
    assert_eq!(l["uid"], ALICE);
    assert!(l["touch"].is_object(), "{l}");
    assert_eq!(l["touch"]["cred_id"], ev.credential_id.as_str());
    let paths = w.paths(&i);
    assert!(paths.land_approved(n).exists());
    assert!(paths.land_advanced(n).exists());
    // Approved, not applied (L4).
    assert_eq!(w.lands.unapplied(&i), 1);
    let info = w.lands.approved_unapplied(&i);
    assert_eq!(info.len(), 1);
    assert_eq!(info[0].n, n);
    assert_eq!(info[0].target_ref, format!("saiife/box-{}", i.as_str()));
    assert_eq!(info[0].base_commit, "b".repeat(40));
    assert_eq!(info[0].diff_sha256, p.record.fields["diff_sha256"]);
    assert_eq!(info[0].task, "make it better");
    let v = box_land::land_answer(&info[0]);
    assert_eq!(v["land"]["id"], i.as_str());
    // No longer pending; one approval only.
    assert!(w.lands.pending().is_empty());
    assert_eq!(
        w.lands.complete(p.request_id, Decision::Approve, Some(ev)),
        Err(BoxError::WrongState {
            state: BoxState::Landed
        })
    );
    assert_eq!(w.mgr.get(&i).unwrap().lands, 1);
}

/// R37: the land records are daemon-trusted state, kept in the box's
/// record dir and never in the runtime dir the VMM shares.
#[test]
fn land_records_live_in_the_record_dir() {
    let w = world(2);
    let i = w.done(ALICE, &changed());
    let n = w.lands.latest(&i).unwrap().n;
    let p = w.pending_of(&i);
    let ev = w.evidence(ALICE, &p);
    w.src(Some(ALICE))
        .complete(p.request_id, Decision::Approve, Some(ev))
        .unwrap();
    let rec = w.paths(&i);
    assert!(rec.land_review(n).exists());
    assert!(rec.land_approved(n).exists());
    let lands_in_runtime = w.rt(&i).dir.join("lands");
    assert!(!lands_in_runtime.exists(), "{}", lands_in_runtime.display());
}

/// Plan 31's hand-off: a Workspace source looks the land book up when it
/// is made, so one made after the book is attached late has it (pending
/// records, the L4 discard guard) and one made before has none.
#[test]
fn workspace_source_looks_the_book_up_at_call_time() {
    let w = world_with(2, false);
    let i = w.done(ALICE, &changed());
    let before = box_ops::workspace_source(&w.ctx, Some(ALICE)).expect("a manager");
    assert!(before.pending_actions().is_empty());
    assert!(w.ctx.box_lands.set(Arc::clone(&w.lands)).is_ok());
    let after = box_ops::workspace_source(&w.ctx, Some(ALICE)).expect("a manager");
    let p = after.pending_actions();
    assert_eq!(p.len(), 1, "{p:?}");
    assert_eq!(p[0].box_id, Some(i));
    // the owner scope holds: another owner sees none of it
    let bob = box_ops::workspace_source(&w.ctx, Some(BOB)).expect("a manager");
    assert!(bob.pending_actions().is_empty());
}

#[test]
fn complete_burns_the_cli_entry() {
    let w = world(2);
    let i = w.done(ALICE, &changed());
    let p = w.pending_of(&i);
    let ev = w.evidence(ALICE, &p);
    w.lands
        .complete(p.request_id, Decision::Approve, Some(ev.clone()))
        .unwrap();
    // The CLI path (`box.land`) spends `IssueKey::Land(rid)`: gone.
    let asr = w.keys[&ALICE].assert_ctap(RP, &challenge(&p.record));
    let rec = p.record.clone();
    let r = w.ctx.touch.consume(
        &IssueKey::Land(p.request_id),
        ALICE,
        |_| rec,
        &asr,
        RP,
        w.now(),
    );
    assert_eq!(r.unwrap_err(), TouchError::Expired);
    assert!(matches!(
        w.lands.approve(p.request_id, &ev, "cli"),
        Err(BoxError::WrongState { .. })
    ));
    assert_eq!(w.mgr.get(&i).unwrap().lands, 1);
}

#[test]
fn complete_reject_keeps_done() {
    let w = world(2);
    let i = w.done(ALICE, &changed());
    let p = w.pending_of(&i);
    w.src(Some(ALICE))
        .complete(p.request_id, Decision::Reject, None)
        .unwrap();
    assert_eq!(w.state(&i), BoxState::Done);
    assert_eq!(w.mgr.get(&i).unwrap().lands, 0);
    let rej = w.actions("land_rejected");
    assert_eq!(rej.len(), 1);
    assert_eq!(rej[0]["box"], i.as_str());
    assert_eq!(rej[0]["via"], "web");
    // The CLI entry is burned too.
    let asr = w.keys[&ALICE].assert_ctap(RP, &challenge(&p.record));
    let rec = p.record.clone();
    let r = w.ctx.touch.consume(
        &IssueKey::Land(p.request_id),
        ALICE,
        |_| rec,
        &asr,
        RP,
        w.now(),
    );
    assert_eq!(r.unwrap_err(), TouchError::Expired);
    // The rejected review is not offered again; a new one is.
    assert!(w.lands.pending().is_empty());
    assert_eq!(
        w.lands.complete(p.request_id, Decision::Reject, None),
        Err(BoxError::WrongState {
            state: BoxState::Done
        })
    );
    w.with_repo(&i, |g| {
        g.work.insert("more.txt".into(), C(b"more\n".to_vec()));
    });
    w.lands.refresh(&i).unwrap();
    assert_eq!(w.lands.pending().len(), 1);
    assert!(w.lands.approved_unapplied(&i).is_empty());
}

#[test]
fn stale_complete_is_wrong_state() {
    let w = world(2);
    let i = w.done(ALICE, &changed());
    let p = w.pending_of(&i);
    let ev = w.evidence(ALICE, &p);
    // The box writes more; the review moves on.
    w.with_repo(&i, |g| {
        g.work.insert("late.txt".into(), C(b"late\n".to_vec()));
    });
    w.lands.refresh(&i).unwrap();
    assert!(!w.lands.is_current(p.request_id));
    assert_eq!(
        w.lands.complete(p.request_id, Decision::Approve, Some(ev)),
        Err(BoxError::WrongState {
            state: BoxState::Done
        })
    );
    assert_eq!(w.state(&i), BoxState::Done);
    assert_eq!(w.mgr.get(&i).unwrap().lands, 0);
    assert!(w.lands.approved_unapplied(&i).is_empty());
    assert!(w.actions("land").is_empty());
    // The new review gets its own request.
    let q = w.pending_of(&i);
    assert_ne!(q.request_id, p.request_id);
    assert!(files_of(&w, &i).contains(&"late.txt".to_string()));
}

#[test]
fn revise_then_second_land() {
    let w = world(2);
    let i = w.done(ALICE, &changed());
    let p = w.pending_of(&i);
    let ev = w.evidence(ALICE, &p);
    w.lands
        .complete(p.request_id, Decision::Approve, Some(ev))
        .unwrap();
    assert_eq!(w.state(&i), BoxState::Landed);
    // R-F1: revise a Landed box, it runs and finishes again.
    w.mgr.revise(&i, "add docs").unwrap();
    assert_eq!(w.state(&i), BoxState::Running);
    w.with_repo(&i, |g| {
        g.work.insert("docs.md".into(), C(b"docs\n".to_vec()));
    });
    w.mgr.done(&i).unwrap();
    let r2 = w.lands.refresh(&i).unwrap();
    assert_eq!(r2.n, 2);
    // Only what changed since the first land.
    assert_eq!(files_of(&w, &i), vec!["docs.md".to_string()]);
    let q = w.pending_of(&i);
    let ev = w.evidence(ALICE, &q);
    w.lands
        .complete(q.request_id, Decision::Approve, Some(ev))
        .unwrap();
    let r = w.mgr.get(&i).unwrap();
    assert_eq!((r.state, r.lands), (BoxState::Landed, 2));
    assert!(w
        .requests(&i)
        .contains(&Request::Advance { n: 2, paths: None }));
    let ns: Vec<u32> = w.lands.approved_unapplied(&i).iter().map(|l| l.n).collect();
    assert_eq!(ns, vec![1, 2]);
    assert_eq!(w.actions("land").len(), 2);
}

#[test]
fn discard_refuses_unapplied_land() {
    let w = world(2);
    let i = w.done(ALICE, &changed());
    let p = w.pending_of(&i);
    let ev = w.evidence(ALICE, &p);
    w.lands
        .complete(p.request_id, Decision::Approve, Some(ev))
        .unwrap();
    let src = w.src(Some(ALICE));
    let s = i.as_str();
    assert_eq!(
        src.discard(&i),
        Err(BoxError::Invalid(format!(
            "box {s} has an approved land that is not applied: saiife box apply {s}, or discard --force"
        )))
    );
    assert_eq!(w.state(&i), BoxState::Landed);
    // Applied: recorded once, then discard works.
    let commit = "c".repeat(40);
    assert!(matches!(
        w.lands.applied(&i, 1, "not a commit"),
        Err(BoxError::Invalid(_))
    ));
    w.lands.applied(&i, 1, &commit).unwrap();
    assert!(matches!(
        w.lands.applied(&i, 1, &commit),
        Err(BoxError::Invalid(_))
    ));
    let a = w.actions("land_applied");
    assert_eq!(a.len(), 1);
    assert_eq!(a[0]["commit"], commit.as_str());
    assert_eq!(a[0]["land"], 1);
    assert_eq!(w.lands.unapplied(&i), 0);
    src.discard(&i).unwrap();
    assert_eq!(w.mgr.get(&i), Err(BoxError::NotFound));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refresh_runs_on_done() {
    let w = tokio::task::spawn_blocking(|| {
        let w = world(2);
        let i = w.running(ALICE, &base_tree(), &changed());
        (w, i)
    })
    .await
    .unwrap();
    let (w, i) = w;
    assert!(w.lands.latest(&i).is_none());
    // The guest says the agent exited: the box is Done, its review comes.
    let c = box_ops::guest_event(&w.ctx, i.clone(), GuestEvent::Exited)
        .await
        .unwrap();
    assert_eq!(c.unwrap().to, BoxState::Done);
    let end = Instant::now() + T;
    while w.lands.latest(&i).is_none() {
        assert!(Instant::now() < end, "no review after Done");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(w.exports(&i), 1);
    let src = w.src(Some(ALICE));
    let d = tokio::task::spawn_blocking({
        let i = i.clone();
        move || src.diff(&i)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        d.diff_sha256,
        w.lands.latest(&i).unwrap().summary.diff_sha256
    );
    tokio::task::spawn_blocking(move || drop(w)).await.unwrap();
}

#[test]
fn vm_off_uses_cached_review() {
    let w = world(2);
    let i = w.done(ALICE, &changed());
    let before = w.lands.latest(&i).unwrap();
    let exports = w.exports(&i);
    w.mgr.stop(&i, false).unwrap();
    assert!(!w.mgr.get(&i).unwrap().vm_on);
    let r = w.lands.refresh(&i).unwrap();
    assert_eq!(r.summary.diff_sha256, before.summary.diff_sha256);
    assert_eq!(w.exports(&i), exports, "no export with the VM off");
    assert_eq!(
        w.src(Some(ALICE)).diff(&i).unwrap().diff_sha256,
        before.summary.diff_sha256
    );
    // Another box, VM off, never reviewed.
    let j = w.running(ALICE, &base_tree(), &changed());
    w.mgr.stop(&j, false).unwrap();
    let s = j.as_str();
    assert_eq!(
        w.lands.refresh(&j),
        Err(BoxError::Unavailable(format!(
            "the box's VM is off and it has no review; saiife box revise {s} restarts it"
        )))
    );
    assert_eq!(w.exports(&j), 0);
}

#[test]
fn inconsistent_subset_begin_is_refused() {
    let w = world(2);
    // `old.txt` becomes a directory: delete the file, add `old.txt/x`.
    let mut work = base_tree();
    work.remove("old.txt");
    work.insert("old.txt/x".into(), C(b"x\n".to_vec()));
    work.insert("NEW.md".into(), C(b"new\n".to_vec()));
    let i = w.done(ALICE, &work);
    let set = |ps: &[&str]| Some(ps.iter().map(|p| p.to_string()).collect::<BTreeSet<_>>());
    let e = w
        .lands
        .begin(&i, ALICE, set(&["old.txt/x"]), false, w.now());
    match e {
        Err(BoxError::Invalid(m)) => {
            assert!(m.contains("select the change of"), "{m}");
            assert!(m.contains("old.txt"), "{m}");
        }
        other => panic!("{other:?}"),
    }
    match w
        .lands
        .begin(&i, ALICE, set(&["nope\u{1b}[31m"]), false, w.now())
    {
        Err(BoxError::Invalid(m)) => {
            assert!(m.contains("is not in the diff"), "{m}");
            assert!(!m.contains('\u{1b}'), "unescaped guest text: {m:?}");
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        w.lands.begin(&i, ALICE, set(&[]), false, w.now()),
        Err(BoxError::Invalid(_))
    ));
    // A consistent subset lands alone, with its own hash.
    let (rid, rec, rev) = w
        .lands
        .begin(&i, ALICE, set(&["NEW.md"]), false, w.now())
        .unwrap();
    let full = w.lands.latest(&i).unwrap();
    assert_ne!(rev.summary.diff_sha256, full.summary.diff_sha256);
    assert_eq!(rec.fields["diff_sha256"], rev.summary.diff_sha256);
    assert_eq!(rev.summary.files.len(), 1);
    let p = PendingAction {
        request_id: rid,
        class: TouchClass::Land,
        box_id: Some(i.clone()),
        summary: rec.summary.clone(),
        record: rec.clone(),
        created_at: w.now(),
        expires_at: rec.expires_at,
    };
    let ev = w.evidence(ALICE, &p);
    w.ctx.touch.take(&IssueKey::Land(rid), ALICE).unwrap();
    let info = w.lands.approve(rid, &ev, "cli").unwrap();
    assert_eq!(info.diff_sha256, rev.summary.diff_sha256);
    assert!(w.requests(&i).contains(&Request::Advance {
        n: full.n,
        paths: Some(vec!["NEW.md".into()]),
    }));
    // The rest stays for the next land.
    w.mgr.revise(&i, "go on").unwrap();
    w.mgr.done(&i).unwrap();
    w.lands.refresh(&i).unwrap();
    assert_eq!(
        files_of(&w, &i),
        vec!["old.txt".to_string(), "old.txt/x".to_string()]
    );
    assert_eq!(w.actions("land")[0]["via"], "cli");
}

#[test]
fn hostile_export_audits_diff_rejected() {
    let w = world(2);
    let i = w.done(ALICE, &changed());
    assert!(w.lands.latest(&i).is_some());
    // An entry that climbs out of the repo.
    let evil = BTreeMap::from([("../x".to_string(), C(b"x".to_vec()))]);
    let bytes = export(2, &Tree::new(), &evil);
    w.with_repo(&i, |g| g.hostile = Some(Answer::Bytes(bytes)));
    let e = w.lands.refresh(&i).unwrap_err();
    let BoxError::Unavailable(m) = &e else {
        panic!("{e:?}")
    };
    assert!(m.starts_with("delta refused"), "{m}");
    let rej = w.actions("diff_rejected");
    assert_eq!(rej.len(), 1, "{rej:?}");
    assert_eq!(rej[0]["box"], i.as_str());
    assert_eq!(rej[0]["reason"], m.as_str());
    // Nothing stored, nothing offered.
    assert!(!w.paths(&i).land_dir(2).exists());
    assert!(w.lands.latest(&i).is_none());
    assert!(w.lands.pending().is_empty());
    // A guest refusal with escapes: recorded escaped.
    w.with_repo(&i, |g| {
        g.hostile = Some(Answer::Err("no\u{1b}[31m way".into()))
    });
    let e = w.lands.refresh(&i).unwrap_err();
    let rej = w.actions("diff_rejected");
    assert_eq!(rej.len(), 2);
    let reason = rej[1]["reason"].as_str().unwrap();
    assert!(!reason.contains('\u{1b}'), "{reason:?}");
    assert!(reason.contains("the guest could not export"), "{reason}");
    assert_eq!(e, BoxError::Unavailable(reason.to_string()));
    // The next honest export is reviewed again, under a fresh number.
    let r = w.lands.refresh(&i).unwrap();
    assert_eq!(r.n, 4);
}

/// FU1: a box that changed files while its in-box guard reported no
/// check is flagged once (one `guard_skipped` record), shown in the diff
/// answer, and its land carries the flag; landing is not blocked.
#[test]
fn guard_skipped_is_flagged_once_and_shown() {
    let w = world(2);
    let i = w.running(ALICE, &base_tree(), &changed());
    w.mgr.guest_event(&i, GuestEvent::TurnFinished).unwrap();
    let s = i.as_str();
    // Running: a review is not judged yet (a guard check may be in flight).
    let d = w.ok(ALICE, "box.diff", json!({"box": s, "refresh": true}));
    assert_eq!(d["guard"]["skipped"], false, "{d}");
    assert!(w.actions("guard_skipped").is_empty());
    w.mgr.done(&i).unwrap();
    let d = w.ok(ALICE, "box.diff", json!({"box": s, "refresh": true}));
    assert_eq!(
        d["guard"],
        json!({"skipped": true, "checks": 0, "turns": 1}),
        "{d}"
    );
    w.ok(ALICE, "box.diff", json!({"box": s, "refresh": true}));
    let g = w.actions("guard_skipped");
    assert_eq!(g.len(), 1, "{g:?}");
    assert_eq!(g[0]["box"], s);
    assert_eq!(g[0]["guard_checks"], 0);
    assert_eq!(g[0]["turns"], 1);
    assert_eq!(g[0]["files"], 3);
    assert!(w.mgr.get(&i).unwrap().guard_skipped);
    // Advisory: the land goes on, and says so.
    w.cli_land(ALICE, &i);
    let l = w.actions("land");
    assert_eq!(l.len(), 1);
    assert_eq!(l[0]["guard_skipped"], true);
}

/// FU1 (review M2): a box reviewed only while it ran is judged at its land.
#[test]
fn guard_skipped_is_judged_at_the_land() {
    let w = world(2);
    let i = w.running(ALICE, &base_tree(), &changed());
    w.lands.refresh(&i).unwrap();
    w.mgr.done(&i).unwrap();
    assert!(w.actions("guard_skipped").is_empty());
    w.cli_land(ALICE, &i);
    let g = w.actions("guard_skipped");
    assert_eq!(g.len(), 1, "{g:?}");
    assert_eq!(g[0]["files"], 3);
    assert_eq!(w.actions("land")[0]["guard_skipped"], true);
}

/// FU1: a box whose guard reported checks is not flagged.
#[test]
fn guard_checks_keep_the_flag_off() {
    let w = world(2);
    let i = w.running(ALICE, &base_tree(), &changed());
    w.mgr.guest_event(&i, GuestEvent::GuardChecks(4)).unwrap();
    w.mgr.done(&i).unwrap();
    let s = i.as_str();
    let d = w.ok(ALICE, "box.diff", json!({"box": s}));
    assert_eq!(
        d["guard"],
        json!({"skipped": false, "checks": 4, "turns": 0}),
        "{d}"
    );
    assert!(w.actions("guard_skipped").is_empty());
    w.cli_land(ALICE, &i);
    assert_eq!(w.actions("land")[0]["guard_skipped"], false);
    // No changes, no checks: never flagged.
    let j = w.running(ALICE, &base_tree(), &base_tree());
    w.mgr.done(&j).unwrap();
    let d = w.ok(ALICE, "box.diff", json!({"box": j.as_str()}));
    assert_eq!(d["guard"]["skipped"], false, "{d}");
    assert!(w.actions("guard_skipped").is_empty());
}

// ---- Task 5: the control-socket ops ----

fn rt() -> &'static tokio::runtime::Runtime {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    })
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

fn unhex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn read_fd(fd: OwnedFd) -> Vec<u8> {
    let mut b = Vec::new();
    std::fs::File::from(fd).read_to_end(&mut b).unwrap();
    b
}

fn rule(a: &Value) -> &str {
    a["rule"].as_str().unwrap_or("")
}

impl World {
    /// One op on the control socket's dispatch as `uid`: the answer and
    /// the descriptors it hands to the connection.
    fn op(&self, uid: u32, op: &str, args: Value) -> (Value, Vec<OwnedFd>) {
        let conn = Conn::new(peer(uid), None);
        let req = IpcRequest {
            id: 7,
            op: op.into(),
            args: args.as_object().cloned().unwrap_or_default(),
        };
        let a = rt().block_on(dispatch_conn(&self.ctx, &conn, req));
        (a, conn.take_out_fds())
    }

    fn call(&self, uid: u32, op: &str, args: Value) -> Value {
        let (a, fds) = self.op(uid, op, args);
        assert!(fds.is_empty(), "{op} passed descriptors: {a}");
        a
    }

    fn ok(&self, uid: u32, op: &str, args: Value) -> Value {
        let a = self.call(uid, op, args);
        assert_eq!(a["ok"], true, "{op}: {a}");
        a
    }

    /// `uid`'s touch over the challenge of a begin answer.
    fn assert_for(&self, uid: u32, begun: &Value) -> Value {
        let ch = unhex32(begun["touch"]["challenge"].as_str().unwrap());
        serde_json::to_value(self.keys[&uid].assert_ctap(RP, &ch)).unwrap()
    }

    /// begin → touch → `box.land`: the answer and its delta fd.
    fn cli_land(&self, uid: u32, i: &BoxId) -> (Value, Vec<u8>) {
        let b = self.ok(uid, "box.land.begin", json!({"box": i.as_str()}));
        let asr = self.assert_for(uid, &b);
        let (a, fds) = self.op(
            uid,
            "box.land",
            json!({"request_id": b["request_id"], "assertion": asr}),
        );
        assert_eq!(a["ok"], true, "{a}");
        assert_eq!(fds.len(), 1);
        (a, read_fd(fds.into_iter().next().unwrap()))
    }

    fn allowed(&self, action: &str) -> Vec<Value> {
        let mut v = self.actions(action);
        v.retain(|r| r["decision"] != "deny");
        v
    }

    fn denied(&self, action: &str) -> Vec<Value> {
        let mut v = self.actions(action);
        v.retain(|r| r["decision"] == "deny");
        v
    }

    fn lockdown(&self) {
        self.ctx
            .lockdown
            .set(Some(Lockdown {
                scope: LockScope::All,
                reason: "incident".into(),
                by_uid: 0,
                since: "t".into(),
            }))
            .unwrap();
    }
}

#[test]
fn cli_land_roundtrip() {
    let w = world(2);
    let i = w.done(ALICE, &changed());
    let s = i.as_str();
    // box.diff: the cached review, its entries and flags.
    let d = w.ok(ALICE, "box.diff", json!({"box": s}));
    let full = w.lands.latest(&i).unwrap();
    assert_eq!(d["diff"]["diff_sha256"], full.summary.diff_sha256.as_str());
    assert_eq!(d["diff"]["id"], s);
    assert_eq!(d["review"]["n"], full.n);
    assert_eq!(d["review"]["entries"].as_array().unwrap().len(), 3);
    assert_eq!(d["review"]["base_head"], "a".repeat(40));
    assert!(d["review"]["flags"].is_array());
    let before = w.exports(&i);
    w.ok(ALICE, "box.diff", json!({"box": s, "refresh": true}));
    assert_eq!(w.exports(&i), before + 1, "refresh exports again");

    let b = w.ok(ALICE, "box.land.begin", json!({"box": s}));
    let rid: u64 = b["request_id"].as_str().unwrap().parse().unwrap();
    let (req, rec) = w.lands.request(rid).unwrap();
    assert_eq!(b["touch"]["rp_id"], RP);
    assert_eq!(b["touch"]["uv"], true);
    assert_eq!(
        unhex32(b["touch"]["challenge"].as_str().unwrap()),
        challenge(&rec)
    );
    assert_eq!(b["touch"]["summary"], rec.summary.as_str());
    assert_eq!(b["expires_at"], rec.expires_at);
    assert_eq!(b["review"]["n"], req.n);
    assert_eq!(b["diff"]["diff_sha256"], req.diff_sha256.as_str());
    assert_eq!(b["id"], 7, "no box id at the top: {b}");

    let asr = w.assert_for(ALICE, &b);
    let (a, fds) = w.op(
        ALICE,
        "box.land",
        json!({"request_id": b["request_id"], "assertion": asr}),
    );
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a["land"]["id"], s);
    assert_eq!(a["land"]["n"], req.n);
    assert_eq!(a["land"]["diff_sha256"], req.diff_sha256.as_str());
    assert_eq!(a["land"]["target_ref"], format!("saiife/box-{s}"));
    assert_eq!(fds.len(), 1);
    let got = read_fd(fds.into_iter().next().unwrap());
    let on_disk = std::fs::read(w.paths(&i).land_delta(req.n)).unwrap();
    assert!(!got.is_empty());
    assert_eq!(got, on_disk);
    let r = w.mgr.get(&i).unwrap();
    assert_eq!((r.state, r.lands), (BoxState::Landed, 1));
    let l = w.actions("land");
    assert_eq!(l.len(), 1);
    assert_eq!(l[0]["via"], "cli");
    assert_eq!(l[0]["uid"], ALICE);
    assert!(l[0]["touch"].is_object(), "{}", l[0]);
}

#[test]
fn later_writes_need_a_new_touch() {
    let w = world(2);
    let i = w.done(ALICE, &changed());
    let s = i.as_str();
    let b = w.ok(ALICE, "box.land.begin", json!({"box": s}));
    let asr = w.assert_for(ALICE, &b);
    // The box writes more after the touch was asked for.
    w.with_repo(&i, |g| {
        g.work.insert("late.txt".into(), C(b"late\n".to_vec()));
    });
    let a = w.call(
        ALICE,
        "box.land",
        json!({"request_id": b["request_id"], "assertion": asr}),
    );
    assert_eq!(a["ok"], false);
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(rule(&a), "touch_mismatch", "{a}");
    assert_eq!(w.state(&i), BoxState::Done);
    assert_eq!(w.mgr.get(&i).unwrap().lands, 0);
    assert!(w.allowed("land").is_empty());
    let refused = w.denied("land");
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(refused[0]["rule"], "touch_mismatch");
    // The review was refreshed: the next begin covers the late write.
    assert!(files_of(&w, &i).contains(&"late.txt".to_string()));
    let (a, _) = w.cli_land(ALICE, &i);
    assert_eq!(a["land"]["id"], s);
    assert_eq!(w.mgr.get(&i).unwrap().lands, 1);
}

#[test]
fn subset_hash_is_bound() {
    let w = world(2);
    let i = w.done(ALICE, &changed());
    let full = w.lands.latest(&i).unwrap();
    let b = w.ok(
        ALICE,
        "box.land.begin",
        json!({"box": i.as_str(), "files": ["NEW.md"]}),
    );
    let rid: u64 = b["request_id"].as_str().unwrap().parse().unwrap();
    let (req, rec) = w.lands.request(rid).unwrap();
    assert_eq!(b["diff"]["files"].as_array().unwrap().len(), 1);
    assert_ne!(req.diff_sha256, full.summary.diff_sha256);
    assert_eq!(rec.fields["diff_sha256"], req.diff_sha256);
    // A touch over the record of the whole diff (both changes) never
    // verifies for the subset's request.
    let mut whole: ActionRecord = rec.clone();
    whole
        .fields
        .insert("diff_sha256".into(), full.summary.diff_sha256.clone());
    let asr = w.keys[&ALICE].assert_ctap(RP, &challenge(&whole));
    let a = w.call(
        ALICE,
        "box.land",
        json!({"request_id": b["request_id"], "assertion": asr}),
    );
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["error"], "forbidden", "{a}");
    assert!(
        ["touch_mismatch", "touch_failed"].contains(&rule(&a)),
        "{a}"
    );
    assert_eq!(w.mgr.get(&i).unwrap().lands, 0);
    assert!(!w.paths(&i).land_approved(req.n).exists());
}

#[test]
fn request_is_single_use() {
    let w = world(2);
    let i = w.done(ALICE, &changed());
    let b = w.ok(ALICE, "box.land.begin", json!({"box": i.as_str()}));
    let asr = w.assert_for(ALICE, &b);
    let args = json!({"request_id": b["request_id"], "assertion": asr});
    let (a, fds) = w.op(ALICE, "box.land", args.clone());
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(fds.len(), 1);
    let a = w.call(ALICE, "box.land", args);
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(rule(&a), "touch_failed", "{a}");
    let a = w.call(
        ALICE,
        "box.land.reject",
        json!({"request_id": b["request_id"]}),
    );
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(w.mgr.get(&i).unwrap().lands, 1);
    assert_eq!(w.allowed("land").len(), 1);
    assert_eq!(w.denied("land").len(), 1);
}

#[test]
fn other_uid_is_refused() {
    let w = world(2);
    let i = w.done(ALICE, &changed());
    let s = i.as_str();
    // Bob cannot see Alice's box (B8).
    for (op, args) in [
        ("box.land.begin", json!({"box": s})),
        ("box.diff", json!({"box": s})),
        ("box.land.fetch", json!({"box": s, "n": 1})),
        (
            "box.land.applied",
            json!({"box": s, "n": 1, "commit": "c".repeat(40)}),
        ),
        (
            "box.push.begin",
            json!({"box": s, "remote": "origin", "commit": "c".repeat(40)}),
        ),
    ] {
        let a = w.call(BOB, op, args);
        assert_eq!(a["ok"], false, "{op}: {a}");
        assert_eq!(rule(&a), "not_found", "{op}: {a}");
    }
    // Nor use Alice's request, even with a touch of his own.
    let b = w.ok(ALICE, "box.land.begin", json!({"box": s}));
    let ch = unhex32(b["touch"]["challenge"].as_str().unwrap());
    let bob = serde_json::to_value(w.keys[&BOB].assert_ctap(RP, &ch)).unwrap();
    let a = w.call(
        BOB,
        "box.land",
        json!({"request_id": b["request_id"], "assertion": bob}),
    );
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["error"], "bad_request", "{a}");
    let a = w.call(
        BOB,
        "box.land.reject",
        json!({"request_id": b["request_id"]}),
    );
    assert_eq!(a["ok"], false, "{a}");
    // Alice's request is untouched by Bob's tries.
    let asr = w.assert_for(ALICE, &b);
    let (a, fds) = w.op(
        ALICE,
        "box.land",
        json!({"request_id": b["request_id"], "assertion": asr}),
    );
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(fds.len(), 1);
}

#[test]
fn expired_request_is_refused() {
    let w = world(2);
    let i = w.done(ALICE, &changed());
    let b = w.ok(ALICE, "box.land.begin", json!({"box": i.as_str()}));
    let asr = w.assert_for(ALICE, &b);
    w.clock
        .fetch_add(saiife_touch::CHALLENGE_TTL_SECS + 1, Ordering::SeqCst);
    let a = w.call(
        ALICE,
        "box.land",
        json!({"request_id": b["request_id"], "assertion": asr}),
    );
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(rule(&a), "touch_failed", "{a}");
    assert_eq!(w.mgr.get(&i).unwrap().lands, 0);
}

#[test]
fn no_credential_names_enrol() {
    let w = world(2);
    let i = w.done(CAROL, &changed());
    let a = w.call(CAROL, "box.land.begin", json!({"box": i.as_str()}));
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(rule(&a), "touch_unavailable", "{a}");
    let m = a["message"].as_str().unwrap();
    assert!(m.contains("enrol a key: saiife touch enrol"), "{m}");
    let r = w.actions("land.begin");
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(r[0]["decision"], "deny");
    assert_eq!(r[0]["rule"], "touch_unavailable");
}

#[test]
fn fetch_for_web_approved_land() {
    let w = world(2);
    let i = w.done(ALICE, &changed());
    let s = i.as_str();
    let p = w.pending_of(&i);
    let ev = w.evidence(ALICE, &p);
    w.src(Some(ALICE))
        .complete(p.request_id, Decision::Approve, Some(ev))
        .unwrap();
    let n = w.lands.approved_unapplied(&i)[0].n;
    // Without `n`: the list, and no descriptor.
    let (a, fds) = w.op(ALICE, "box.land.fetch", json!({"box": s}));
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a["waiting"], json!([n]), "{a}");
    assert_eq!(a["unreadable"], 0, "{a}");
    assert!(fds.is_empty());
    let (a, fds) = w.op(ALICE, "box.land.fetch", json!({"box": s, "n": n}));
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a["land"]["id"], s);
    assert_eq!(a["land"]["n"], n);
    assert_eq!(fds.len(), 1);
    assert_eq!(
        read_fd(fds.into_iter().next().unwrap()),
        std::fs::read(w.paths(&i).land_delta(n)).unwrap()
    );
    let a = w.call(ALICE, "box.land.fetch", json!({"box": s, "n": n + 5}));
    assert_eq!(a["error"], "bad_request", "{a}");
    w.ok(
        ALICE,
        "box.land.applied",
        json!({"box": s, "n": n, "commit": "c".repeat(40)}),
    );
    let a = w.call(ALICE, "box.land.fetch", json!({"box": s, "n": n}));
    assert_eq!(a["error"], "bad_request", "applied: {a}");
    let a = w.call(ALICE, "box.land.fetch", json!({"box": s}));
    assert_eq!(a["waiting"], json!([]), "{a}");
}

#[test]
fn applied_is_recorded_once() {
    let w = world(2);
    let i = w.done(ALICE, &changed());
    let s = i.as_str();
    let (a, _) = w.cli_land(ALICE, &i);
    let n = a["land"]["n"].as_u64().unwrap();
    let a = w.call(
        ALICE,
        "box.land.applied",
        json!({"box": s, "n": n, "commit": "not a commit"}),
    );
    assert_eq!(a["error"], "bad_request", "{a}");
    let c = "c".repeat(40);
    w.ok(
        ALICE,
        "box.land.applied",
        json!({"box": s, "n": n, "commit": c}),
    );
    let a = w.call(
        ALICE,
        "box.land.applied",
        json!({"box": s, "n": n, "commit": c}),
    );
    assert_eq!(a["error"], "bad_request", "{a}");
    assert!(
        a["message"].as_str().unwrap().contains("already applied"),
        "{a}"
    );
    let r = w.actions("land_applied");
    assert_eq!(r.len(), 1);
    assert_eq!(r[0]["commit"], c.as_str());
    // Applied: discard needs no force.
    w.ok(ALICE, "box.discard", json!({"box": s}));
}

#[test]
fn push_needs_touch_and_records() {
    let w = world(2);
    let i = w.done(ALICE, &changed());
    let s = i.as_str();
    let c = "d".repeat(40);
    // Nothing landed yet: nothing to push.
    let a = w.call(
        ALICE,
        "box.push.begin",
        json!({"box": s, "remote": "origin", "commit": c}),
    );
    assert_eq!(a["error"], "bad_request", "{a}");
    w.cli_land(ALICE, &i);
    for bad in ["-oops", "", "two words", "a\u{1b}b"] {
        let a = w.call(
            ALICE,
            "box.push.begin",
            json!({"box": s, "remote": bad, "commit": c}),
        );
        assert_eq!(a["error"], "bad_request", "{bad:?}: {a}");
    }
    let b = w.ok(
        ALICE,
        "box.push.begin",
        json!({"box": s, "remote": "origin", "commit": c}),
    );
    let rid: u64 = b["request_id"].as_str().unwrap().parse().unwrap();
    let (req, rec) = w.lands.push_request(rid).unwrap();
    assert_eq!(rec.class, TouchClass::PushProtected);
    assert_eq!(rec.fields["remote"], "origin");
    assert_eq!(rec.fields["commit"], c);
    assert_eq!(rec.fields["repo"], "demo");
    assert_eq!(rec.fields["target_ref"], format!("saiife/box-{s}"));
    assert!(rec.summary.contains(&c), "{}", rec.summary);
    assert_eq!(req.owner, ALICE);
    assert_eq!(b["touch"]["uv"], false);
    // Done before a touch: refused.
    let a = w.call(
        ALICE,
        "box.push.done",
        json!({"request_id": b["request_id"], "ok": true, "detail": ""}),
    );
    assert_eq!(a["error"], "bad_request", "{a}");
    // A touch for something else: refused, and the challenge is spent.
    let mut other = rec.clone();
    other.fields.insert("remote".into(), "evil".into());
    let wrong = w.keys[&ALICE].assert_ctap(RP, &challenge(&other));
    let a = w.call(
        ALICE,
        "box.push",
        json!({"request_id": b["request_id"], "assertion": wrong}),
    );
    assert_eq!(a["error"], "forbidden", "{a}");
    let asr = w.assert_for(ALICE, &b);
    let a = w.call(
        ALICE,
        "box.push",
        json!({"request_id": b["request_id"], "assertion": asr}),
    );
    assert_eq!(rule(&a), "touch_failed", "spent: {a}");
    // A new request, its touch, the push and its record.
    let b = w.ok(
        ALICE,
        "box.push.begin",
        json!({"box": s, "remote": "origin", "commit": c}),
    );
    let asr = w.assert_for(ALICE, &b);
    let args = json!({"request_id": b["request_id"], "assertion": asr});
    w.ok(ALICE, "box.push", args.clone());
    assert_eq!(rule(&w.call(ALICE, "box.push", args)), "touch_failed");
    // Not Bob's to finish.
    let a = w.call(
        BOB,
        "box.push.done",
        json!({"request_id": b["request_id"], "ok": true}),
    );
    assert_eq!(a["error"], "bad_request", "{a}");
    let long = format!("rejected\u{1b}[31m {}", "x".repeat(2000));
    w.ok(
        ALICE,
        "box.push.done",
        json!({"request_id": b["request_id"], "ok": false, "detail": long}),
    );
    let a = w.call(
        ALICE,
        "box.push.done",
        json!({"request_id": b["request_id"], "ok": true, "detail": ""}),
    );
    assert_eq!(a["error"], "bad_request", "once: {a}");
    let p = w.allowed("push");
    assert_eq!(p.len(), 1, "{p:?}");
    assert_eq!(p[0]["box"], s);
    assert_eq!(p[0]["remote"], "origin");
    assert_eq!(p[0]["commit"], c.as_str());
    assert_eq!(p[0]["ok"], false);
    assert_eq!(p[0]["uid"], ALICE);
    assert!(p[0]["touch"].is_object(), "{}", p[0]);
    let d = p[0]["detail"].as_str().unwrap();
    assert!(!d.contains('\u{1b}'), "{d:?}");
    assert!(d.chars().count() <= 512, "{}", d.len());
    // Every refused touch is recorded.
    let r = w.denied("push");
    assert_eq!(r.len(), 3, "{r:?}");
    assert!(r.iter().all(|x| x["box"] == s), "{r:?}");
}

#[test]
fn lockdown_refuses_land_and_push() {
    let w = world(2);
    let i = w.done(ALICE, &changed());
    let s = i.as_str();
    let (a, _) = w.cli_land(ALICE, &i);
    let n = a["land"]["n"].as_u64().unwrap();
    // A second review, begun before the lockdown.
    w.mgr.revise(&i, "more").unwrap();
    w.with_repo(&i, |g| {
        g.work.insert("docs.md".into(), C(b"docs\n".to_vec()));
    });
    w.mgr.done(&i).unwrap();
    w.lands.refresh(&i).unwrap();
    let b = w.ok(ALICE, "box.land.begin", json!({"box": s}));
    let asr = w.assert_for(ALICE, &b);
    let c = "e".repeat(40);
    let pb = w.ok(
        ALICE,
        "box.push.begin",
        json!({"box": s, "remote": "origin", "commit": c}),
    );
    let pasr = w.assert_for(ALICE, &pb);
    w.lockdown();
    let before = w.records().len();
    for (op, args) in [
        ("box.land.begin", json!({"box": s})),
        (
            "box.land",
            json!({"request_id": b["request_id"], "assertion": asr}),
        ),
        ("box.land.fetch", json!({"box": s, "n": n})),
        (
            "box.push.begin",
            json!({"box": s, "remote": "origin", "commit": c}),
        ),
        (
            "box.push",
            json!({"request_id": pb["request_id"], "assertion": pasr}),
        ),
    ] {
        let a = w.call(ALICE, op, args);
        assert_eq!(a["ok"], false, "{op}: {a}");
        assert_eq!(a["error"], "lockdown", "{op}: {a}");
        assert_eq!(rule(&a), "lockdown", "{op}: {a}");
    }
    let recs = w.records();
    let denies: Vec<&Value> = recs[before..]
        .iter()
        .filter(|r| r["decision"] == "deny")
        .collect();
    assert_eq!(denies.len(), 5, "{denies:?}");
    assert!(denies.iter().all(|r| r["rule"] == "lockdown"));
    assert_eq!(w.mgr.get(&i).unwrap().lands, 1);
    // What only records or takes away stays allowed.
    w.ok(ALICE, "box.diff", json!({"box": s}));
    w.ok(
        ALICE,
        "box.land.applied",
        json!({"box": s, "n": n, "commit": c}),
    );
    w.ok(
        ALICE,
        "box.land.reject",
        json!({"request_id": b["request_id"]}),
    );
}

/// C1: a land record that cannot be read counts as an unapplied land, so
/// `box.discard` refuses without `force`.
#[test]
fn unreadable_land_record_blocks_discard() {
    let w = world(2);
    let i = w.done(ALICE, &changed());
    let s = i.as_str();
    let (a, _) = w.cli_land(ALICE, &i);
    let n = a["land"]["n"].as_u64().unwrap() as u32;
    let a = w.call(ALICE, "box.discard", json!({"box": s}));
    assert_eq!(a["error"], "bad_request", "{a}");
    assert!(
        a["message"].as_str().unwrap().ends_with(&format!(
            "box {s} has an approved land that is not applied: saiife box apply {s}, or discard --force"
        )),
        "{a}"
    );
    w.ok(
        ALICE,
        "box.land.applied",
        json!({"box": s, "n": n, "commit": "c".repeat(40)}),
    );
    assert_eq!(w.lands.unapplied(&i), 0);
    // approved.json replaced by a directory: unreadable, so unapplied.
    let ap = w.paths(&i).land_approved(n);
    std::fs::remove_file(&ap).unwrap();
    std::fs::create_dir(&ap).unwrap();
    assert_eq!(w.lands.unapplied(&i), 1);
    let a = w.call(ALICE, "box.discard", json!({"box": s}));
    assert_eq!(a["error"], "bad_request", "{a}");
    assert_eq!(w.state(&i), BoxState::Landed);
    let a = w.ok(ALICE, "box.discard", json!({"box": s, "force": true}));
    assert_eq!(a["box"]["id"], s);
    let d = w.actions("discard");
    assert_eq!(d.last().unwrap()["force"], true);
}

/// C3: a partial land that is not taken puts the whole export's files back,
/// so a later whole land of the same export builds the right base.
#[test]
fn failed_partial_land_restores_the_whole_export() {
    let w = world(2);
    let i = w.done(ALICE, &changed());
    let full = w.lands.latest(&i).unwrap();
    let n = full.n;
    let paths = w.paths(&i);
    let review_before = std::fs::read(paths.land_review(n)).unwrap();
    let delta_before = std::fs::read(paths.land_delta(n)).unwrap();
    let only = Some(BTreeSet::from(["NEW.md".to_string()]));
    let (rid, rec, _) = w.lands.begin(&i, ALICE, only, false, w.now()).unwrap();
    let p = PendingAction {
        request_id: rid,
        class: TouchClass::Land,
        box_id: Some(i.clone()),
        summary: rec.summary.clone(),
        record: rec.clone(),
        created_at: w.now(),
        expires_at: rec.expires_at,
    };
    let ev = w.evidence(ALICE, &p);
    w.ctx.touch.take(&IssueKey::Land(rid), ALICE).unwrap();
    // The approval cannot be recorded: the land is not taken.
    std::fs::create_dir(paths.land_approved(n)).unwrap();
    assert!(matches!(
        w.lands.approve(rid, &ev, "cli"),
        Err(BoxError::WrongState { .. })
    ));
    assert_eq!(w.mgr.get(&i).unwrap().lands, 0);
    let r: saiife_boxhost::review::Review =
        serde_json::from_slice(&std::fs::read(paths.land_review(n)).unwrap()).unwrap();
    assert_eq!(r, full, "review.json is the whole export again");
    assert_eq!(
        serde_json::from_slice::<saiife_boxhost::review::Review>(&review_before).unwrap(),
        r
    );
    assert_eq!(std::fs::read(paths.land_delta(n)).unwrap(), delta_before);
    // A whole land of the same export then takes every change.
    std::fs::remove_dir(paths.land_approved(n)).unwrap();
    let (rid, rec, _) = w.lands.begin(&i, ALICE, None, false, w.now()).unwrap();
    let p = PendingAction {
        request_id: rid,
        record: rec.clone(),
        summary: rec.summary.clone(),
        expires_at: rec.expires_at,
        ..p
    };
    let ev = w.evidence(ALICE, &p);
    w.ctx.touch.take(&IssueKey::Land(rid), ALICE).unwrap();
    let restored = w.lands.approve(rid, &ev, "cli").unwrap();
    assert_eq!(restored.n, n);
    assert_eq!(w.with_repo(&i, |g| g.base.clone()), changed());
    // The next review is empty: the base the daemon rebuilds has it all.
    w.mgr.revise(&i, "again").unwrap();
    w.mgr.done(&i).unwrap();
    let next = w.lands.refresh(&i).unwrap();
    assert!(next.summary.files.is_empty(), "{:?}", next.summary.files);
}

/// Over the real control socket with the ipc crate's `Client`: per-box
/// ops take `{box}`, and `box.land`'s answer nests the box id under `land`
/// and is followed by the delta's descriptor.
#[test]
fn per_box_ops_take_box_not_id() {
    use std::os::unix::fs::PermissionsExt;
    let w = world(2);
    let i = w.done(me(), &changed());
    assert_eq!(i.as_str(), "b1");
    let run = w._tmp.path().join("run");
    std::fs::create_dir(&run).unwrap();
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();
    let sock = run.join(saiife_ipc::msg::SOCKET_NAME);
    let ctx = Arc::clone(&w.ctx);
    let listener = {
        let _g = rt().enter();
        tokio::net::UnixListener::bind(&sock).unwrap()
    };
    let server = rt().spawn(async move {
        loop {
            let Ok((s, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(saiife_daemon::server::connection(s, Arc::clone(&ctx)));
        }
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut c = saiife_ipc::client::Client::connect(&run, me(), deadline).unwrap();
    let args = |v: Value| v.as_object().cloned().unwrap();
    let d = c
        .call("box.diff", args(json!({"box": "b1"})), deadline)
        .unwrap();
    assert_eq!(d["diff"]["id"], "b1");
    assert!(d["id"].is_u64(), "the answer's id is the request's: {d:?}");
    let r = c.call("box.diff", args(json!({"id": "b1"})), deadline);
    assert!(r.is_err(), "{r:?}");
    let b = c
        .call("box.land.begin", args(json!({"box": "b1"})), deadline)
        .unwrap();
    let asr = w.assert_for(me(), &Value::Object(b.clone()));
    let (a, fds) = c
        .call_recv_fds(
            "box.land",
            args(json!({"request_id": b["request_id"], "assertion": asr})),
            1,
            deadline,
        )
        .unwrap();
    assert_eq!(a["land"]["id"], "b1");
    assert!(a["id"].is_u64());
    let n = a["land"]["n"].as_u64().unwrap() as u32;
    assert_eq!(fds.len(), 1);
    assert_eq!(
        read_fd(fds.into_iter().next().unwrap()),
        std::fs::read(w.paths(&i).land_delta(n)).unwrap()
    );
    // The connection stays in step after the descriptor.
    let (f, fds) = c
        .call_recv_fds(
            "box.land.fetch",
            args(json!({"box": "b1", "n": n})),
            1,
            deadline,
        )
        .unwrap();
    assert_eq!(f["land"]["id"], "b1");
    assert_eq!(fds.len(), 1);
    c.call(
        "box.land.applied",
        args(json!({"box": "b1", "n": n, "commit": "c".repeat(40)})),
        deadline,
    )
    .unwrap();
    drop(c);
    server.abort();
}

/// `changed()` plus a box-written `.gitattributes` naming a filter.
fn with_git_config(name: &str) -> Tree {
    let mut t = changed();
    t.insert(
        name.into(),
        C(b"* filter=lfs diff=lfs merge=lfs\n".to_vec()),
    );
    t
}

#[test]
fn git_config_needs_the_cli_flag() {
    let w = world(2);
    let i = w.done(ALICE, &with_git_config(".gitattributes"));
    let s = i.as_str();
    let d = w.ok(ALICE, "box.diff", json!({"box": s}));
    assert_eq!(d["review"]["git_config"], json!([".gitattributes"]), "{d}");
    let a = w.call(ALICE, "box.land.begin", json!({"box": s}));
    assert_eq!(a["error"], "bad_request", "{a}");
    let m = a["message"].as_str().unwrap();
    assert!(m.contains("changes git config (.gitattributes)"), "{m}");
    assert!(
        m.contains(&format!("saiife box land {s} --allow-git-config")),
        "{m}"
    );
    let a = w.call(
        ALICE,
        "box.land.begin",
        json!({"box": s, "allow_git_config": "yes"}),
    );
    assert_eq!(a["error"], "bad_request", "{a}");
    let b = w.ok(
        ALICE,
        "box.land.begin",
        json!({"box": s, "allow_git_config": true}),
    );
    let rid: u64 = b["request_id"].as_str().unwrap().parse().unwrap();
    let (req, rec) = w.lands.request(rid).unwrap();
    assert_eq!(rec.fields["git_config"], "allowed");
    assert_eq!(req.git_config.as_deref(), Some("allowed"));
    assert!(
        rec.summary.contains("; git config: .gitattributes"),
        "{}",
        rec.summary
    );
    assert_eq!(b["touch"]["summary"], rec.summary.as_str());
    let asr = w.assert_for(ALICE, &b);
    let (a, fds) = w.op(
        ALICE,
        "box.land",
        json!({"request_id": b["request_id"], "assertion": asr}),
    );
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(fds.len(), 1);
    // A box without git config needs no flag, and its record has none.
    let j = w.done(ALICE, &changed());
    let b = w.ok(ALICE, "box.land.begin", json!({"box": j.as_str()}));
    let rid: u64 = b["request_id"].as_str().unwrap().parse().unwrap();
    let (req, rec) = w.lands.request(rid).unwrap();
    assert!(!rec.fields.contains_key("git_config"));
    assert_eq!(req.git_config, None);
}

#[test]
fn pending_skips_git_config() {
    let w = world(3);
    let i = w.done(ALICE, &with_git_config(".lfsconfig"));
    assert!(w.lands.pending().is_empty());
    w.clock.fetch_add(1, Ordering::SeqCst);
    let j = w.done(ALICE, &changed());
    let p = w.lands.pending();
    assert_eq!(p.len(), 1, "{p:?}");
    assert_eq!(p[0].box_id.as_ref(), Some(&j));
    let f = &w.lands.latest(&i).unwrap().flags;
    assert!(
        f.iter()
            .any(|x| x.path == ".lfsconfig" && x.why == "protected path (git config)"),
        "{f:?}"
    );
}

/// R-T6f: a workflow under `.github/` is protected, not git config: it
/// needs no flag and the Workspace gets its record.
#[test]
fn github_workflow_is_protected_not_git_config() {
    let w = world(3);
    let i = w.done(ALICE, &with_git_config(".github/workflows/ci.yml"));
    let p = w.lands.pending();
    assert_eq!(p.len(), 1, "{p:?}");
    assert_eq!(p[0].box_id.as_ref(), Some(&i));
    let r = w.lands.latest(&i).unwrap();
    assert!(
        r.flags
            .iter()
            .any(|x| x.path == ".github/workflows/ci.yml" && x.why == "protected path"),
        "{:?}",
        r.flags
    );
    assert!(!p[0].record.fields.contains_key("git_config"));
    let d = w.ok(ALICE, "box.diff", json!({"box": i.as_str()}));
    assert_eq!(d["review"]["git_config"], json!([]), "{d}");
    // And sub/.gitattributes, .gitconfig still are.
    let j = w.done(ALICE, &with_git_config("sub/.gitattributes"));
    let a = w.call(ALICE, "box.land.begin", json!({"box": j.as_str()}));
    assert_eq!(a["error"], "bad_request", "{a}");
    let k = w.done(ALICE, &with_git_config(".gitconfig"));
    let a = w.call(ALICE, "box.land.begin", json!({"box": k.as_str()}));
    assert_eq!(a["error"], "bad_request", "{a}");
    assert!(
        a["message"]
            .as_str()
            .unwrap()
            .contains("--allow-git-config"),
        "{a}"
    );
}

// ---- final fix wave ----

/// I-3: every refresh stores a whole export; the unused ones go, the
/// newest stays (its number is the highest on disk).
#[test]
fn three_refreshes_leave_one_unapproved_land_dir() {
    let w = world(2);
    let i = w.done(ALICE, &changed());
    w.lands.refresh(&i).unwrap();
    let r = w.lands.refresh(&i).unwrap();
    let dirs: Vec<String> = std::fs::read_dir(w.paths(&i).lands_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(dirs, [r.n.to_string()], "{dirs:?}");
    // An approved land and a land an undecided request names stay.
    let p = w.pending_of(&i);
    let n = w.lands.request(p.request_id).unwrap().0.n;
    assert_eq!(n, r.n);
    w.lands.refresh(&i).unwrap();
    let r = w.lands.refresh(&i).unwrap();
    assert!(w.paths(&i).land_dir(n).exists());
    assert!(!w.paths(&i).land_dir(n + 1).exists());
    assert!(w.paths(&i).land_dir(r.n).exists());
    let p = w.pending_of(&i);
    let approved = w.lands.request(p.request_id).unwrap().0.n;
    let ev = w.evidence(ALICE, &p);
    w.lands
        .complete(p.request_id, Decision::Approve, Some(ev))
        .unwrap();
    w.with_repo(&i, |g| {
        g.work.insert("more.txt".into(), C(b"more\n".to_vec()));
    });
    w.mgr.revise(&i, "more").unwrap();
    w.mgr.done(&i).unwrap();
    let last = w.lands.refresh(&i).unwrap();
    assert!(w.paths(&i).land_approved(approved).exists());
    assert!(w.paths(&i).land_dir(last.n).exists());
    // Only the approved land and the newest are left.
    let mut ns: Vec<u32> = std::fs::read_dir(w.paths(&i).lands_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().parse().unwrap())
        .collect();
    ns.sort_unstable();
    assert_eq!(ns, [approved, last.n]);
}

/// I-4: the Workspace never approves a land that changes git config, even
/// a CLI-begun request it was handed.
#[test]
fn complete_refuses_git_config_request() {
    let w = world(2);
    let i = w.done(ALICE, &with_git_config(".gitattributes"));
    let (rid, record, _) = w.lands.begin(&i, ALICE, None, true, w.now()).unwrap();
    let asr = w.keys[&ALICE].assert_ctap(RP, &challenge(&record));
    let ev = w
        .ctx
        .touch
        .verify_counted(ALICE, &record, &asr, RP, w.now())
        .unwrap();
    let s = i.as_str();
    assert_eq!(
        w.lands.complete(rid, Decision::Approve, Some(ev)),
        Err(BoxError::Invalid(format!(
            "land {s} changes git config; land it from the CLI: saiife box land {s} --allow-git-config"
        )))
    );
    let r = w.mgr.get(&i).unwrap();
    assert_eq!((r.state, r.lands), (BoxState::Done, 0));
    assert!(w.actions("land").is_empty());
    // Rejecting it from the Workspace still works.
    w.lands.complete(rid, Decision::Reject, None).unwrap();
}

/// M-2: a guest that is not connected refused nothing: the cached review
/// stays, and no diff_rejected record is written.
#[test]
fn not_connected_keeps_the_cached_review() {
    let w = world(2);
    let i = w.done(ALICE, &changed());
    let before = w.lands.latest(&i).unwrap();
    w.guest.after_off(&i);
    let e = w.lands.refresh(&i).unwrap_err();
    assert!(e.to_string().contains("not connected"), "{e}");
    assert_eq!(
        w.lands.latest(&i).unwrap().summary.diff_sha256,
        before.summary.diff_sha256
    );
    assert!(w.actions("diff_rejected").is_empty());
}

/// Item 7: a request issued again for the same box supersedes the older
/// undecided one, touch entry and all, so re-issues cannot fill the
/// owner's touch cap and drop boxes from pending().
#[test]
fn superseded_requests_release_their_touch() {
    let w = world(2);
    let i = w.done(ALICE, &changed());
    let first = w.lands.begin(&i, ALICE, None, false, w.now()).unwrap().0;
    // Well past the per-uid cap of 8.
    let mut last = first;
    for _ in 0..12 {
        last = w.lands.begin(&i, ALICE, None, false, w.now()).unwrap().0;
    }
    assert!(w.lands.request(first).is_none());
    assert!(w.lands.request(last).is_some());
    assert_eq!(
        w.ctx.touch.take(&IssueKey::Land(first), ALICE).unwrap_err(),
        TouchError::Expired
    );
    // The owner still gets a pending land for another box.
    w.clock.fetch_add(1, Ordering::SeqCst);
    let j = w.done(ALICE, &changed());
    w.pending_of(&j);
    w.pending_of(&i);
    // A partial request does not supersede the whole one (nor the reverse).
    let part = w
        .lands
        .begin(
            &i,
            ALICE,
            Some(BTreeSet::from(["NEW.md".to_string()])),
            false,
            w.now(),
        )
        .unwrap()
        .0;
    let whole = w.pending_of(&i).request_id;
    assert!(w.lands.request(whole).is_some());
    assert!(w.lands.request(part).is_some());
}

/// Item 9: a daemon whose land book is not attached answers every land and
/// push op with `unavailable` and NO_LANDS.
#[test]
fn unattached_book_answers_no_lands() {
    let w = world_with(2, false);
    let i = w.done(ALICE, &changed());
    for op in box_land::OPS {
        let a = w.call(
            ALICE,
            op,
            json!({"box": i.as_str(), "request_id": "4294967297"}),
        );
        assert_eq!(a["error"], "unavailable", "{op}: {a}");
        assert_eq!(a["message"], box_land::NO_LANDS, "{op}: {a}");
    }
}
