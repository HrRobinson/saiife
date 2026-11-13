#![cfg(feature = "fake")]

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use common::{id, template_sized, world, world_with, World};
use saiife_boxes::capacity::{self, Committed};
use saiife_boxes::guest::GuestEvent;
use saiife_boxes::manager::{
    Change, DiskPlace, DiskPlacer, GcReport, Manager, SpawnArgs, BOOT_TIMEOUT_SECS, DONE_IDLE_SECS,
};
use saiife_boxes::store::{BoxRecord, Store};
use saiife_boxes::template::Size;
use saiife_boxes::vmm::fake::{FakeVmm, VmOp};
use saiife_boxes::vmm::{VmHandle, VmSpec, VmStatus, Vmm, VmmError};
use saiife_boxes::{BoxError, BoxId, BoxState};
use saiife_wire::source::Start;

fn ops(w: &World, i: &BoxId) -> Vec<VmOp> {
    w.vmm
        .calls()
        .into_iter()
        .filter(|c| &c.id == i)
        .map(|c| c.op)
        .collect()
}

fn count(w: &World, i: &BoxId, op: VmOp) -> usize {
    ops(w, i).into_iter().filter(|o| *o == op).count()
}

fn handle(i: &BoxId) -> VmHandle {
    VmHandle {
        id: i.clone(),
        driver: "fake".into(),
        data: String::new(),
    }
}

fn change(i: &BoxId, from: BoxState, to: BoxState, why: &'static str) -> Change {
    Change {
        id: i.clone(),
        from,
        to,
        why,
        image: None,
    }
}

fn state(w: &World, i: &BoxId) -> BoxState {
    w.mgr.get(i).unwrap().state
}

/// Spawn and send `Ready`: a running box.
fn running(w: &World, task: &str) -> BoxId {
    let r = w.spawn(task);
    assert_eq!(r.state, BoxState::Starting);
    w.mgr.guest_event(&r.id, GuestEvent::Ready).unwrap();
    r.id
}

#[test]
fn constants_are_the_fixed_values() {
    assert_eq!(BOOT_TIMEOUT_SECS, 90);
    assert_eq!(DONE_IDLE_SECS, 30);
}

#[test]
fn spawn_starts_when_room() {
    let w = world(1);
    let r = w.spawn("do the thing");
    assert_eq!(r.id, id("b1"));
    assert_eq!(r.state, BoxState::Starting);
    assert!(r.vm_on);
    assert_eq!(r.started_at, Some(w.now()));
    assert_eq!(r.session, "box-b1");
    assert_eq!(r.owner_uid, 1000);
    assert_eq!(r.queue_seq, None);
    assert_eq!(r.pending_prompt.as_deref(), Some("do the thing"));
    assert_eq!(r.image, None);
    assert_eq!(ops(&w, &r.id), vec![VmOp::Create, VmOp::Boot]);
    assert!(w.mgr.queue().is_empty());
    w.assert_saved(&r.id);
    let (_, c) = w.mgr.capacity();
    assert_eq!(
        c,
        Committed {
            mem_mib: capacity::charge_mib(&Size::default()),
            vcpus: 2
        }
    );
}

#[test]
fn spawn_queues_when_full() {
    let w = world(1);
    w.spawn("a");
    let b = w.spawn("b");
    assert_eq!(b.state, BoxState::Queued);
    assert!(!b.vm_on);
    assert_eq!(b.pending_prompt.as_deref(), Some("b"));
    assert_eq!(w.mgr.queue(), vec![b.id.clone()]);
    assert_eq!(w.mgr.queue_pos(&b.id), Some(1));
    assert_eq!(w.mgr.queue_pos(&id("b1")), None);
    assert!(ops(&w, &b.id).is_empty());
    w.assert_saved(&b.id);
}

#[test]
fn now_is_busy_when_full_and_claims_no_id() {
    let w = world(1);
    let a = w.spawn("a");
    let now = w.args("claude-code", "x", Start::Now);
    assert_eq!(w.mgr.spawn(&now), Err(BoxError::Busy));
    // Room, but a non-empty queue: Now never jumps it.
    let b = w.spawn("b");
    assert_eq!(b.id, id("b2"));
    w.mgr.stop(&a.id, false).unwrap();
    assert_eq!(w.mgr.spawn(&now), Err(BoxError::Busy));
    assert_eq!(w.spawn("c").id, id("b3"));
    assert!(!w.root.join("b4").exists());
}

#[test]
fn now_starts_when_room_and_queue_empty() {
    let w = world(1);
    let r = w
        .mgr
        .spawn(&w.args("claude-code", "x", Start::Now))
        .unwrap();
    assert_eq!(r.state, BoxState::Starting);
}

#[test]
fn unknown_template_is_invalid() {
    let w = world(1);
    assert_eq!(
        w.mgr.spawn(&w.args("nope", "x", Start::Queue)),
        Err(BoxError::Invalid("unknown template nope".into()))
    );
    assert!(w.mgr.list().is_empty());
}

#[test]
fn never_fits_is_invalid() {
    let huge = Size {
        mem_mib: 65536,
        mem_max_mib: 65536,
        ..Size::default()
    };
    let w = world_with(1, vec![template_sized("huge", huge)]);
    let want = capacity::fits_ever(&w.host, &huge).unwrap_err().message();
    assert_eq!(
        w.mgr.spawn(&w.args("huge", "x", Start::Queue)),
        Err(BoxError::Invalid(want))
    );
    assert!(w.mgr.list().is_empty());
    assert_eq!(w.spawn("a").id, id("b1"));
}

#[test]
fn task_with_escape_is_invalid() {
    let w = world(2);
    let bad = w.args("claude-code", "a\x1bb", Start::Queue);
    assert!(matches!(w.mgr.spawn(&bad), Err(BoxError::Invalid(_))));
    let mut bad_repo = w.args("claude-code", "ok", Start::Queue);
    bad_repo.repo = "a\x1bb".into();
    assert!(matches!(w.mgr.spawn(&bad_repo), Err(BoxError::Invalid(_))));
    bad_repo.repo = "r".repeat(257);
    assert!(matches!(w.mgr.spawn(&bad_repo), Err(BoxError::Invalid(_))));
    let long = w.args("claude-code", &"t".repeat(8193), Start::Queue);
    assert!(matches!(w.mgr.spawn(&long), Err(BoxError::Invalid(_))));
    assert!(w.mgr.list().is_empty());
    // An empty task is allowed and leaves nothing to prompt.
    let r = w.spawn("");
    assert_eq!(r.id, id("b1"));
    assert_eq!(r.pending_prompt, None);
    w.mgr.guest_event(&r.id, GuestEvent::Ready).unwrap();
    assert!(w.guest.prompts().is_empty());
}

/// `<root>/.incoming/<sub>/` with a repo disk and a base manifest in it,
/// as the daemon's intake leaves them.
fn incoming(w: &World, sub: &str) -> (PathBuf, PathBuf) {
    let d = w.root.join(".incoming").join(sub);
    std::fs::create_dir_all(&d).unwrap();
    let (img, man) = (d.join("repo.img"), d.join("base.json"));
    std::fs::write(&img, b"disk").unwrap();
    std::fs::write(&man, b"{}").unwrap();
    (img, man)
}

fn with_disk(w: &World, img: &Path, man: &Path) -> SpawnArgs {
    let mut a = w.args("claude-code", "x", Start::Queue);
    a.repo_image = Some(img.to_path_buf());
    a.base_manifest = Some(man.to_path_buf());
    a
}

#[test]
fn spawn_places_repo_disk_before_admission() {
    let w = world(1);
    let (img, man) = incoming(&w, "00112233aabbccdd");
    let r = w.mgr.spawn(&with_disk(&w, &img, &man)).unwrap();
    assert_eq!(r.state, BoxState::Starting);
    // The VMM's create already saw the disk in the box dir.
    assert_eq!(w.vmm.saw_repo_disk(&r.id), Some(true));
    let dir = w.root.join(r.id.as_str());
    assert_eq!(std::fs::read(dir.join("repo.img")).unwrap(), b"disk");
    assert_eq!(std::fs::read(dir.join("base.json")).unwrap(), b"{}");
    assert!(!img.exists() && !man.exists());
    assert!(!w.root.join(".incoming/00112233aabbccdd").exists());
    w.assert_saved(&r.id);
    // `.incoming` is no box: no warning on a restart, no orphan for gc.
    let mut w = w;
    assert!(w.reopen().is_empty());
    assert_eq!(w.mgr.gc(), GcReport::default());
    // A queued box gets its disk at spawn too, long before its admission.
    let (img, man) = incoming(&w, "1111111111111111");
    let q = w.mgr.spawn(&with_disk(&w, &img, &man)).unwrap();
    assert_eq!(q.state, BoxState::Queued);
    assert!(w.root.join(q.id.as_str()).join("repo.img").is_file());
    assert_eq!(w.vmm.saw_repo_disk(&q.id), None);
}

#[test]
fn spawn_without_repo_is_unchanged() {
    let w = world(1);
    let r = w.spawn("a");
    assert_eq!(r.id, id("b1"));
    assert_eq!(r.state, BoxState::Starting);
    assert_eq!(w.vmm.saw_repo_disk(&r.id), Some(false));
    assert!(!w.root.join("b1/repo.img").exists());
    assert!(!w.root.join("b1/base.json").exists());
    assert!(!w.root.join(".incoming").exists());
}

#[test]
fn repo_image_without_manifest_is_invalid() {
    let w = world(1);
    let (img, man) = incoming(&w, "00112233aabbccdd");
    let mut a = w.args("claude-code", "x", Start::Queue);
    a.repo_image = Some(img.clone());
    assert!(matches!(w.mgr.spawn(&a), Err(BoxError::Invalid(_))));
    let mut a = w.args("claude-code", "x", Start::Queue);
    a.base_manifest = Some(man.clone());
    assert!(matches!(w.mgr.spawn(&a), Err(BoxError::Invalid(_))));
    // Outside .incoming, in two dirs, or one file twice: invalid too.
    let elsewhere = w.dir.path().join("repo.img");
    std::fs::write(&elsewhere, b"x").unwrap();
    let (img2, _) = incoming(&w, "ffffffffffffffff");
    let deep = w.root.join(".incoming/a/b/repo.img");
    for (i, m) in [
        (&elsewhere, &man),
        (&img2, &man),
        (&img, &img),
        (&deep, &man),
    ] {
        let e = w.mgr.spawn(&with_disk(&w, i, m));
        assert!(matches!(e, Err(BoxError::Invalid(_))), "{i:?} {m:?}: {e:?}");
    }
    // No id was claimed: the counter is unchanged.
    assert!(!w.root.join("b1").exists());
    assert!(!w.root.join("next-id").exists());
    assert_eq!(w.spawn("a").id, id("b1"));
    assert!(img.exists() && man.exists(), "left for the caller");
}

#[test]
fn rename_failure_releases_the_id() {
    let w = world(1);
    // In .incoming, but not there: the move fails after the id is claimed.
    let d = w.root.join(".incoming/00112233aabbccdd");
    let e = w
        .mgr
        .spawn(&with_disk(&w, &d.join("repo.img"), &d.join("base.json")));
    assert!(matches!(e, Err(BoxError::Unavailable(_))), "{e:?}");
    assert!(!w.root.join("b1").exists(), "the id's dir is released");
    assert!(w.mgr.list().is_empty());
    assert!(w.vmm.calls().is_empty());
    // A manifest that is not a regular file: refused the same way, and the
    // disk moved in first goes with the dir.
    let (img, man) = incoming(&w, "1111111111111111");
    std::fs::remove_file(&man).unwrap();
    std::fs::create_dir(&man).unwrap();
    let e = w.mgr.spawn(&with_disk(&w, &img, &man));
    assert!(matches!(e, Err(BoxError::Unavailable(_))), "{e:?}");
    assert!(!w.root.join("b2").exists());
    // Ids are never reused.
    assert_eq!(w.spawn("a").id, id("b3"));
}

/// `w`'s manager reopened with `place` as its disk placer.
fn with_placer(w: &mut World, place: Option<DiskPlacer>) {
    let guest: Arc<dyn saiife_boxes::guest::GuestLink> = w.guest.clone();
    let mut init = w.init(guest);
    init.disk_place = place;
    w.mgr = Arc::new(Manager::open(init).unwrap().manager);
}

#[test]
fn spawn_places_the_disk_where_the_placer_says() {
    let mut w = world(1);
    with_placer(
        &mut w,
        Some(Arc::new(|root: &Path, i: &BoxId| DiskPlace {
            repo_image: root.join(i.as_str()).join("disk.img"),
            base_manifest: root.join(i.as_str()).join("m.json"),
        })),
    );
    let (img, man) = incoming(&w, "00112233aabbccdd");
    let r = w.mgr.spawn(&with_disk(&w, &img, &man)).unwrap();
    let dir = w.root.join(r.id.as_str());
    assert_eq!(std::fs::read(dir.join("disk.img")).unwrap(), b"disk");
    assert_eq!(std::fs::read(dir.join("m.json")).unwrap(), b"{}");
    assert!(!dir.join("repo.img").exists() && !dir.join("base.json").exists());
    // A place outside the box dir: refused once the id is claimed, which
    // is then released; the disk stays for the caller to discard.
    with_placer(
        &mut w,
        Some(Arc::new(|root: &Path, i: &BoxId| DiskPlace {
            repo_image: root.join(i.as_str()).join("repo.img"),
            base_manifest: root.join("elsewhere").join("base.json"),
        })),
    );
    let (img, man) = incoming(&w, "1111111111111111");
    let e = w.mgr.spawn(&with_disk(&w, &img, &man));
    assert!(matches!(e, Err(BoxError::Unavailable(_))), "{e:?}");
    assert!(!w.root.join("b2").exists());
    assert!(img.exists() && man.exists());
    // No placer: a repo disk is refused before any id is claimed.
    with_placer(&mut w, None);
    let e = w.mgr.spawn(&with_disk(&w, &img, &man));
    assert!(matches!(e, Err(BoxError::Unavailable(_))), "{e:?}");
    assert_eq!(w.spawn("a").id, id("b3"));
}

/// A placer that, once, runs `during` on the manager while the spawn has
/// the lock let go (the id claimed, the disk not yet moved in), then names
/// the usual places.
fn placer_running(
    w: &mut World,
    during: impl Fn(&Manager, &BoxId) + Send + Sync + 'static,
) -> Arc<Mutex<Option<std::sync::Weak<Manager>>>> {
    let slot: Arc<Mutex<Option<std::sync::Weak<Manager>>>> = Arc::new(Mutex::new(None));
    let s = Arc::clone(&slot);
    let once = std::sync::atomic::AtomicBool::new(false);
    let usual = common::placer();
    with_placer(
        w,
        Some(Arc::new(move |root: &Path, i: &BoxId| {
            let m = s
                .lock()
                .unwrap()
                .as_ref()
                .and_then(std::sync::Weak::upgrade);
            if let Some(m) = m {
                if !once.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    during(&m, i);
                }
            }
            usual(root, i)
        })),
    );
    *slot.lock().unwrap() = Some(Arc::downgrade(&w.mgr));
    slot
}

#[test]
fn gc_skips_an_id_being_placed() {
    let mut w = world(1);
    let seen: Arc<Mutex<Option<(GcReport, bool)>>> = Arc::new(Mutex::new(None));
    let s = Arc::clone(&seen);
    let root = w.root.clone();
    placer_running(&mut w, move |m, i| {
        // The claimed dir has no record yet: an orphan, but for `placing`.
        let rep = m.gc();
        *s.lock().unwrap() = Some((rep, root.join(i.as_str()).is_dir()));
    });
    let (img, man) = incoming(&w, "00112233aabbccdd");
    let r = w.mgr.spawn(&with_disk(&w, &img, &man)).unwrap();
    let (rep, kept) = seen.lock().unwrap().take().expect("gc ran mid-spawn");
    assert_eq!(rep, GcReport::default(), "{rep:?}");
    assert!(kept, "the dir being placed stays");
    assert_eq!(r.id, id("b1"));
    assert_eq!(r.state, BoxState::Starting);
    assert!(w.root.join("b1/repo.img").is_file());
    w.assert_saved(&r.id);
}

#[test]
fn now_busy_after_the_renames_leaves_no_dir() {
    let mut w = world(1);
    let other = w.args("claude-code", "other", Start::Now);
    placer_running(&mut w, move |m, _| {
        // Another spawn takes the one slot while the disk moves in.
        let r = m.spawn(&other).unwrap();
        assert_eq!(r.state, BoxState::Starting);
    });
    let (img, man) = incoming(&w, "00112233aabbccdd");
    let mut a = with_disk(&w, &img, &man);
    a.start = Start::Now;
    assert_eq!(w.mgr.spawn(&a), Err(BoxError::Busy));
    // The racing spawn got b2; b1's dir and the disk moved into it are gone.
    let ids: Vec<BoxId> = w.mgr.list().iter().map(|r| r.id.clone()).collect();
    assert_eq!(ids, vec![id("b2")]);
    assert!(!w.root.join("b1").exists(), "no stray dir");
    assert!(!w.root.join(".incoming/00112233aabbccdd").exists());
    assert_eq!(w.vmm.saw_repo_disk(&id("b2")), Some(false));
    // Nothing for gc either, and the id is not reused.
    assert_eq!(w.mgr.gc(), GcReport::default());
    assert_eq!(w.spawn("q").id, id("b3"));
}

#[test]
fn incoming_is_swept_by_gc() {
    use std::os::unix::fs::symlink;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    let w = world(1);
    let now = SystemTime::now();
    w.clock.store(
        now.duration_since(UNIX_EPOCH).unwrap().as_secs(),
        std::sync::atomic::Ordering::SeqCst,
    );
    let (old_img, _) = incoming(&w, "0000000000000000");
    let (new_img, _) = incoming(&w, "1111111111111111");
    // A file outside, linked from the old dir: never followed.
    let outside = w.dir.path().join("keep");
    std::fs::write(&outside, b"keep").unwrap();
    let old = old_img.parent().unwrap().to_path_buf();
    symlink(&outside, old.join("link")).unwrap();
    std::fs::create_dir(old.join("nested")).unwrap();
    std::fs::write(old.join("nested/f"), b"f").unwrap();
    let back = now - Duration::from_secs(2 * 3600);
    std::fs::File::open(&old)
        .unwrap()
        .set_modified(back)
        .unwrap();
    let stray = w.root.join(".incoming/stray");
    std::fs::write(&stray, b"s").unwrap();
    std::fs::File::options()
        .write(true)
        .open(&stray)
        .unwrap()
        .set_modified(back)
        .unwrap();
    let rep = w.mgr.gc();
    assert_eq!(rep, GcReport::default());
    assert!(!old.exists());
    assert!(!stray.exists());
    assert!(new_img.exists(), "under an hour old: kept");
    assert_eq!(std::fs::read(&outside).unwrap(), b"keep");
}

#[test]
fn queue_head_blocks() {
    let big = Size {
        mem_mib: 8192,
        mem_max_mib: 8192,
        ..Size::default()
    };
    let w = world_with(2, vec![template_sized("big", big)]);
    let a = w.spawn("a");
    assert_eq!(a.state, BoxState::Starting);
    let head = w.mgr.spawn(&w.args("big", "b", Start::Queue)).unwrap();
    let small = w.spawn("c");
    assert_eq!(head.state, BoxState::Queued);
    assert_eq!(small.state, BoxState::Queued);
    assert!(w.mgr.tick().is_empty());
    assert_eq!(w.mgr.queue(), vec![head.id.clone(), small.id.clone()]);
    assert!(ops(&w, &small.id).is_empty());
}

#[test]
fn ready_sends_the_task_once() {
    let w = world(1);
    let r = w.spawn("do it");
    w.advance(5);
    let c = w.mgr.guest_event(&r.id, GuestEvent::Ready).unwrap();
    assert_eq!(
        c,
        Some(change(
            &r.id,
            BoxState::Starting,
            BoxState::Running,
            "ready"
        ))
    );
    assert_eq!(w.guest.prompts(), vec![(r.id.clone(), "do it".to_string())]);
    let g = w.mgr.get(&r.id).unwrap();
    assert_eq!(g.pending_prompt, None);
    assert_eq!(g.last_activity, w.now());
    assert_eq!(g.updated_at, w.now());
    w.assert_saved(&r.id);
    assert_eq!(
        w.mgr.guest_event(&r.id, GuestEvent::Ready),
        Err(BoxError::WrongState {
            state: BoxState::Running
        })
    );
    assert_eq!(w.guest.prompts().len(), 1);
}

#[test]
fn ready_prompt_failure_is_kept_in_error() {
    let w = world(1);
    let r = w.spawn("do it");
    w.guest.disconnect(&r.id);
    w.mgr.guest_event(&r.id, GuestEvent::Ready).unwrap();
    let g = w.mgr.get(&r.id).unwrap();
    assert_eq!(g.state, BoxState::Running);
    assert!(g.error.is_some());
    assert_eq!(g.pending_prompt, None);
}

#[test]
fn turn_finished_then_idle_is_done() {
    let w = world(1);
    let i = running(&w, "a");
    w.mgr.guest_event(&i, GuestEvent::TurnFinished).unwrap();
    assert_eq!(w.mgr.get(&i).unwrap().turn_finished_at, Some(w.now()));
    w.assert_saved(&i);
    w.advance(DONE_IDLE_SECS - 1);
    assert!(w.mgr.tick().is_empty());
    // Activity resets the clock and the finished turn.
    w.mgr.guest_event(&i, GuestEvent::Activity).unwrap();
    assert_eq!(w.mgr.get(&i).unwrap().turn_finished_at, None);
    w.assert_saved(&i);
    w.advance(60);
    assert!(w.mgr.tick().is_empty());
    assert_eq!(state(&w, &i), BoxState::Running);
    w.mgr.guest_event(&i, GuestEvent::TurnFinished).unwrap();
    w.advance(DONE_IDLE_SECS - 1);
    assert!(w.mgr.tick().is_empty());
    w.advance(1);
    assert_eq!(
        w.mgr.tick(),
        vec![change(
            &i,
            BoxState::Running,
            BoxState::Done,
            "turn finished"
        )]
    );
    let g = w.mgr.get(&i).unwrap();
    assert!(g.vm_on);
    w.assert_saved(&i);
}

#[test]
fn exited_is_done() {
    let w = world(1);
    let i = running(&w, "a");
    assert_eq!(
        w.mgr.guest_event(&i, GuestEvent::Exited).unwrap(),
        Some(change(&i, BoxState::Running, BoxState::Done, "exited"))
    );
    assert!(w.mgr.get(&i).unwrap().vm_on);
    w.assert_saved(&i);
}

#[test]
fn guest_event_for_unknown_box_is_not_found() {
    let w = world(1);
    assert_eq!(
        w.mgr.guest_event(&id("b9"), GuestEvent::Activity),
        Err(BoxError::NotFound)
    );
}

#[test]
fn spawn_changes_reports_every_admission() {
    let w = world(1);
    // Own admission only.
    let (a, ch) = w
        .mgr
        .spawn_changes(&w.args("claude-code", "a", Start::Queue))
        .unwrap();
    assert_eq!(a.state, BoxState::Starting);
    assert_eq!(
        ch,
        vec![change(
            &a.id,
            BoxState::Queued,
            BoxState::Starting,
            "admitted"
        )]
    );
    // Queued: no change at all.
    let (b, ch) = w
        .mgr
        .spawn_changes(&w.args("claude-code", "b", Start::Queue))
        .unwrap();
    assert_eq!(b.state, BoxState::Queued);
    assert!(ch.is_empty());
    // A slot frees; the next spawn's pass admits the earlier head, whose
    // boot fails, then the one after it; the new box waits.
    let (c, _) = w
        .mgr
        .spawn_changes(&w.args("claude-code", "c", Start::Queue))
        .unwrap();
    w.mgr.stop(&a.id, false).unwrap();
    w.vmm.fail_next(VmOp::Boot, "no kvm");
    let (d, ch) = w
        .mgr
        .spawn_changes(&w.args("claude-code", "d", Start::Queue))
        .unwrap();
    assert_eq!(d.state, BoxState::Queued);
    assert_eq!(
        ch,
        vec![
            change(&b.id, BoxState::Queued, BoxState::Starting, "admitted"),
            change(
                &b.id,
                BoxState::Starting,
                BoxState::Discarded,
                "boot failed"
            ),
            change(&c.id, BoxState::Queued, BoxState::Starting, "admitted"),
        ]
    );
    assert_eq!(w.mgr.queue(), vec![d.id.clone()]);
}

#[test]
fn boot_failure_discards_and_keeps_dir() {
    let w = world(1);
    w.vmm.fail_next(VmOp::Boot, "no kvm");
    let r = w.spawn("a");
    assert_eq!(r.state, BoxState::Discarded);
    assert!(!r.vm_on);
    assert_eq!(r.error.as_deref(), Some("boot failed: no kvm"));
    assert_eq!(
        ops(&w, &r.id),
        vec![VmOp::Create, VmOp::Boot, VmOp::Destroy]
    );
    assert!(w.root.join("b1").join("box.json").exists());
    w.assert_saved(&r.id);
    assert_eq!(w.mgr.capacity().1, Committed::default());
    // The pass goes on with the next head.
    let a = w.spawn("b");
    let b = w.spawn("c");
    let c = w.spawn("d");
    assert_eq!(a.state, BoxState::Starting);
    assert_eq!(b.state, BoxState::Queued);
    w.vmm.fail_next(VmOp::Create, "disk gone");
    w.mgr.stop(&a.id, false).unwrap();
    let changes = w.mgr.tick();
    assert_eq!(
        changes,
        vec![
            change(&b.id, BoxState::Queued, BoxState::Starting, "admitted"),
            change(
                &b.id,
                BoxState::Starting,
                BoxState::Discarded,
                "boot failed"
            ),
            change(&c.id, BoxState::Queued, BoxState::Starting, "admitted"),
        ]
    );
    assert_eq!(
        w.mgr.get(&b.id).unwrap().error.as_deref(),
        Some("boot failed: disk gone")
    );
    assert_eq!(state(&w, &c.id), BoxState::Starting);
}

#[test]
fn boot_timeout_discards() {
    let w = world(1);
    let r = w.spawn("a");
    w.advance(BOOT_TIMEOUT_SECS - 1);
    assert!(w.mgr.tick().is_empty());
    w.advance(1);
    assert_eq!(
        w.mgr.tick(),
        vec![change(
            &r.id,
            BoxState::Starting,
            BoxState::Discarded,
            "boot timed out"
        )]
    );
    let g = w.mgr.get(&r.id).unwrap();
    assert!(!g.vm_on);
    assert_eq!(g.error.as_deref(), Some("boot timed out"));
    assert_eq!(
        ops(&w, &r.id),
        vec![VmOp::Create, VmOp::Boot, VmOp::Stop, VmOp::Destroy]
    );
    assert!(w.root.join("b1").exists());
    w.assert_saved(&r.id);
}

#[test]
fn idle_stop_turns_vm_off() {
    let w = world(2);
    let a = running(&w, "a");
    let b = running(&w, "b");
    w.mgr.done(&b).unwrap();
    let idle = 120 * 60;
    w.advance(idle - 1);
    assert!(w.mgr.tick().is_empty());
    w.advance(1);
    let changes = w.mgr.tick();
    assert_eq!(
        changes,
        vec![
            change(&a, BoxState::Running, BoxState::Done, "idle stop"),
            change(&b, BoxState::Done, BoxState::Done, "idle stop"),
        ]
    );
    for i in [&a, &b] {
        let g = w.mgr.get(i).unwrap();
        assert!(!g.vm_on);
        assert_eq!(g.state, BoxState::Done);
        assert_eq!(count(&w, i, VmOp::Stop), 1);
        w.assert_saved(i);
    }
    assert_eq!(w.mgr.capacity().1, Committed::default());
    assert!(w.mgr.tick().is_empty());
}

#[test]
fn stop_running_is_done_vm_off() {
    let w = world(1);
    let i = running(&w, "a");
    w.advance(3);
    assert_eq!(
        w.mgr.stop(&i, false).unwrap(),
        change(&i, BoxState::Running, BoxState::Done, "stop")
    );
    let g = w.mgr.get(&i).unwrap();
    assert!(!g.vm_on);
    assert!(!g.keep);
    assert_eq!(g.updated_at, w.now());
    assert_eq!(w.vmm.status(&handle(&i)), VmStatus::Off);
    w.assert_saved(&i);
}

#[test]
fn stop_queued_is_wrong_state() {
    let w = world(1);
    w.spawn("a");
    let b = w.spawn("b");
    assert_eq!(
        w.mgr.stop(&b.id, false),
        Err(BoxError::WrongState {
            state: BoxState::Queued
        })
    );
    assert!(ops(&w, &b.id).is_empty());
    assert_eq!(w.mgr.queue(), vec![b.id.clone()]);
}

#[test]
fn stop_twice_is_ok_and_calls_vmm_once() {
    let w = world(1);
    let i = running(&w, "a");
    w.mgr.stop(&i, false).unwrap();
    assert_eq!(
        w.mgr.stop(&i, false).unwrap(),
        change(&i, BoxState::Done, BoxState::Done, "stop")
    );
    assert_eq!(count(&w, &i, VmOp::Stop), 1);
}

#[test]
fn stop_keep_snapshots_first() {
    let w = world(1);
    let i = running(&w, "a");
    w.mgr.stop(&i, true).unwrap();
    assert_eq!(
        ops(&w, &i),
        vec![
            VmOp::Create,
            VmOp::Boot,
            VmOp::Pause,
            VmOp::Snapshot,
            VmOp::Stop
        ]
    );
    assert!(w.root.join("b1/snapshot/snapshot.fake").exists());
    let g = w.mgr.get(&i).unwrap();
    assert!(g.keep);
    assert!(!g.vm_on);
    assert_eq!(g.state, BoxState::Done);
    w.assert_saved(&i);
}

#[test]
fn stop_keep_snapshot_failure_changes_nothing() {
    let w = world(1);
    let i = running(&w, "a");
    let before = w.mgr.get(&i).unwrap();
    w.vmm.fail_next(VmOp::Snapshot, "disk full");
    assert_eq!(
        w.mgr.stop(&i, true),
        Err(BoxError::Unavailable("snapshot failed: disk full".into()))
    );
    assert_eq!(w.mgr.get(&i).unwrap(), before);
    assert_eq!(w.vmm.status(&handle(&i)), VmStatus::Running);
    assert_eq!(count(&w, &i, VmOp::Stop), 0);
    w.assert_saved(&i);
}

#[test]
fn stop_does_not_admit_until_tick() {
    let w = world(1);
    let a = running(&w, "a");
    let b = w.spawn("b");
    w.mgr.stop(&a, false).unwrap();
    assert_eq!(state(&w, &b.id), BoxState::Queued);
    assert_eq!(
        w.mgr.tick(),
        vec![change(
            &b.id,
            BoxState::Queued,
            BoxState::Starting,
            "admitted"
        )]
    );
    assert!(w.mgr.queue().is_empty());
    w.assert_saved(&b.id);
}

#[test]
fn pause_resume_roundtrip() {
    let w = world(1);
    let i = running(&w, "a");
    assert_eq!(
        w.mgr.pause(&i).unwrap(),
        change(&i, BoxState::Running, BoxState::Paused, "pause")
    );
    assert_eq!(w.vmm.status(&handle(&i)), VmStatus::Paused);
    w.assert_saved(&i);
    assert_eq!(
        w.mgr.resume(&i).unwrap(),
        change(&i, BoxState::Paused, BoxState::Running, "resume")
    );
    assert_eq!(w.vmm.status(&handle(&i)), VmStatus::Running);
    w.assert_saved(&i);
}

#[test]
fn pause_for_sets_error() {
    let w = world(1);
    let i = running(&w, "a");
    let c = w
        .mgr
        .pause_for(&i, "paused: the host disk is almost full")
        .unwrap();
    assert_eq!(c, change(&i, BoxState::Running, BoxState::Paused, "pause"));
    let r = w.mgr.get(&i).unwrap();
    assert_eq!(r.state, BoxState::Paused);
    assert_eq!(
        r.error.as_deref(),
        Some("paused: the host disk is almost full")
    );
    assert_eq!(w.vmm.status(&handle(&i)), VmStatus::Paused);
    w.assert_saved(&i);
    w.mgr.resume(&i).unwrap();
    assert_eq!(w.mgr.get(&i).unwrap().error, None);
}

#[test]
fn pause_wrong_state_makes_no_vmm_call() {
    let w = world(1);
    let a = w.spawn("a");
    let q = w.spawn("q");
    let before = w.vmm.calls().len();
    assert_eq!(
        w.mgr.pause(&a.id),
        Err(BoxError::WrongState {
            state: BoxState::Starting
        })
    );
    assert_eq!(
        w.mgr.pause(&q.id),
        Err(BoxError::WrongState {
            state: BoxState::Queued
        })
    );
    assert_eq!(
        w.mgr.resume(&a.id),
        Err(BoxError::WrongState {
            state: BoxState::Starting
        })
    );
    assert_eq!(w.vmm.calls().len(), before);
    assert_eq!(w.mgr.pause(&id("b9")), Err(BoxError::NotFound));
    // A VMM error leaves the state unchanged.
    w.mgr.guest_event(&a.id, GuestEvent::Ready).unwrap();
    w.vmm.fail_next(VmOp::Pause, "busy");
    assert_eq!(
        w.mgr.pause(&a.id),
        Err(BoxError::Unavailable("busy".into()))
    );
    assert_eq!(state(&w, &a.id), BoxState::Running);
}

#[test]
fn say_needs_running() {
    // R3: Running and Paused both accept a steer.
    let w = world(1);
    let i = w.spawn("");
    assert_eq!(
        w.mgr.say(&i.id, "hi"),
        Err(BoxError::WrongState {
            state: BoxState::Starting
        })
    );
    w.mgr.guest_event(&i.id, GuestEvent::Ready).unwrap();
    w.mgr.say(&i.id, "hi").unwrap();
    w.mgr.pause(&i.id).unwrap();
    w.mgr.say(&i.id, "still there").unwrap();
    w.mgr.resume(&i.id).unwrap();
    assert!(matches!(
        w.mgr.say(&i.id, "a\x1bb"),
        Err(BoxError::Invalid(_))
    ));
    assert!(matches!(w.mgr.say(&i.id, ""), Err(BoxError::Invalid(_))));
    w.mgr.done(&i.id).unwrap();
    assert_eq!(
        w.mgr.say(&i.id, "hi"),
        Err(BoxError::WrongState {
            state: BoxState::Done
        })
    );
    let sent: Vec<String> = w.guest.prompts().into_iter().map(|(_, t)| t).collect();
    assert_eq!(sent, vec!["hi".to_string(), "still there".to_string()]);
}

#[test]
fn done_needs_running() {
    let w = world(1);
    let i = w.spawn("a");
    assert_eq!(
        w.mgr.done(&i.id),
        Err(BoxError::WrongState {
            state: BoxState::Starting
        })
    );
    w.mgr.guest_event(&i.id, GuestEvent::Ready).unwrap();
    assert_eq!(
        w.mgr.done(&i.id).unwrap(),
        change(&i.id, BoxState::Running, BoxState::Done, "done")
    );
    w.assert_saved(&i.id);
}

#[test]
fn revise_running_box_is_wrong_state() {
    let w = world(1);
    let i = running(&w, "a");
    assert_eq!(
        w.mgr.revise(&i, "more"),
        Err(BoxError::WrongState {
            state: BoxState::Running
        })
    );
    assert_eq!(w.guest.prompts().len(), 1);
}

#[test]
fn revise_done_vm_on_prompts_and_runs() {
    let w = world(1);
    let i = running(&w, "a");
    w.mgr.guest_event(&i, GuestEvent::TurnFinished).unwrap();
    w.mgr.guest_event(&i, GuestEvent::Exited).unwrap();
    assert_eq!(
        w.mgr.revise(&i, "more tests").unwrap(),
        change(&i, BoxState::Done, BoxState::Running, "revise")
    );
    assert_eq!(w.guest.prompts().last().unwrap().1, "more tests");
    let g = w.mgr.get(&i).unwrap();
    assert_eq!(g.turn_finished_at, None);
    assert!(g.vm_on);
    w.assert_saved(&i);
    assert!(matches!(
        w.mgr.revise(&i, "a\x1bb"),
        Err(BoxError::Invalid(_))
    ));
}

#[test]
fn revise_done_vm_off_requeues_and_prompts_on_ready() {
    let w = world(1);
    let i = running(&w, "a");
    w.mgr.stop(&i, false).unwrap();
    assert_eq!(
        w.mgr.revise(&i, "again").unwrap(),
        change(&i, BoxState::Done, BoxState::Queued, "requeue")
    );
    let g = w.mgr.get(&i).unwrap();
    assert_eq!(g.pending_prompt.as_deref(), Some("again"));
    assert_eq!(w.mgr.queue_pos(&i), Some(1));
    w.assert_saved(&i);
    assert_eq!(
        w.mgr.tick(),
        vec![change(&i, BoxState::Queued, BoxState::Starting, "admitted")]
    );
    w.mgr.guest_event(&i, GuestEvent::Ready).unwrap();
    assert_eq!(w.guest.prompts().last().unwrap().1, "again");
    assert_eq!(w.mgr.get(&i).unwrap().pending_prompt, None);
}

#[test]
fn revise_prompt_failure_keeps_done() {
    let w = world(1);
    let i = running(&w, "a");
    w.mgr.done(&i).unwrap();
    w.guest.disconnect(&i);
    assert!(matches!(
        w.mgr.revise(&i, "more"),
        Err(BoxError::Unavailable(_))
    ));
    assert_eq!(state(&w, &i), BoxState::Done);
}

#[test]
fn revise_landed_is_like_done() {
    let mut w = world(1);
    let i = running(&w, "a");
    w.mgr.stop(&i, false).unwrap();
    let mut r = w.mgr.get(&i).unwrap();
    r.state = BoxState::Landed;
    r.lands = 1;
    Store::open(w.root.clone()).unwrap().save(&r).unwrap();
    assert!(w.reopen().is_empty());
    assert_eq!(
        w.mgr.revise(&i, "again").unwrap(),
        change(&i, BoxState::Landed, BoxState::Queued, "requeue")
    );
    assert_eq!(w.mgr.get(&i).unwrap().lands, 1);
}

#[test]
fn reorder_rules() {
    let w = world(1);
    w.spawn("a");
    let q: Vec<BoxId> = (0..3).map(|n| w.spawn(&format!("q{n}")).id).collect();
    assert_eq!(w.mgr.queue(), q);
    let bad = Err(BoxError::Invalid(
        "reorder must list every queued box once".into(),
    ));
    assert_eq!(w.mgr.reorder(&q[..2]), bad);
    let mut extra = q.clone();
    extra.push(id("b1"));
    assert_eq!(w.mgr.reorder(&extra), bad);
    let dup = vec![q[0].clone(), q[0].clone(), q[1].clone()];
    assert_eq!(w.mgr.reorder(&dup), bad);
    assert_eq!(w.mgr.queue(), q);
    let rev: Vec<BoxId> = q.iter().rev().cloned().collect();
    w.mgr.reorder(&rev).unwrap();
    assert_eq!(w.mgr.queue(), rev);
    assert_eq!(w.mgr.queue_pos(&q[2]), Some(1));
    assert_eq!(w.mgr.queue_pos(&q[0]), Some(3));
    for i in &q {
        w.assert_saved(i);
    }
}

#[test]
fn discard_removes_dir_and_frees_capacity() {
    let w = world(1);
    let a = running(&w, "a");
    let b = w.spawn("b");
    // R2: a live box must be stopped first.
    assert_eq!(
        w.mgr.discard(&a),
        Err(BoxError::WrongState {
            state: BoxState::Running
        })
    );
    assert_eq!(count(&w, &a, VmOp::Stop), 0);
    w.mgr.done(&a).unwrap();
    assert_eq!(
        w.mgr.discard(&a).unwrap(),
        change(&a, BoxState::Done, BoxState::Discarded, "discard")
    );
    assert_eq!(count(&w, &a, VmOp::Stop), 1);
    assert_eq!(count(&w, &a, VmOp::Destroy), 1);
    assert!(!w.root.join("b1").exists());
    assert_eq!(w.mgr.get(&a), Err(BoxError::NotFound));
    assert_eq!(w.mgr.capacity().1, Committed::default());
    assert_eq!(
        w.mgr.tick(),
        vec![change(
            &b.id,
            BoxState::Queued,
            BoxState::Starting,
            "admitted"
        )]
    );
}

#[test]
fn discard_queued_renumbers_queue() {
    let w = world(1);
    w.spawn("a");
    let q: Vec<BoxId> = (0..3).map(|n| w.spawn(&format!("q{n}")).id).collect();
    assert_eq!(w.mgr.queue_pos(&q[2]), Some(3));
    assert_eq!(
        w.mgr.discard(&q[1]).unwrap(),
        change(&q[1], BoxState::Queued, BoxState::Discarded, "discard")
    );
    assert!(ops(&w, &q[1]).is_empty());
    assert!(!w.root.join(q[1].as_str()).exists());
    assert_eq!(w.mgr.queue(), vec![q[0].clone(), q[2].clone()]);
    assert_eq!(w.mgr.queue_pos(&q[2]), Some(2));
    assert_eq!(w.mgr.discard(&q[1]), Err(BoxError::NotFound));
}

#[test]
fn discard_boot_failed_box() {
    let w = world(1);
    w.vmm.fail_next(VmOp::Boot, "no kvm");
    let r = w.spawn("a");
    assert_eq!(
        w.mgr.discard(&r.id).unwrap(),
        change(&r.id, BoxState::Discarded, BoxState::Discarded, "discard")
    );
    assert!(!w.root.join("b1").exists());
    assert_eq!(w.mgr.get(&r.id), Err(BoxError::NotFound));
}

#[test]
fn list_order_matches_plan_28() {
    let w = world(4);
    w.vmm.fail_next(VmOp::Boot, "no kvm");
    let discarded = w.spawn("x").id;
    let run = running(&w, "r");
    let paused = running(&w, "p");
    w.mgr.pause(&paused).unwrap();
    let done = running(&w, "d");
    w.mgr.done(&done).unwrap();
    let starting = w.spawn("s").id;
    let q1 = w.spawn("q1").id;
    let q2 = w.spawn("q2").id;
    w.mgr.reorder(&[q2.clone(), q1.clone()]).unwrap();
    let got: Vec<BoxId> = w.mgr.list().into_iter().map(|r| r.id).collect();
    assert_eq!(got, vec![run, paused, done, q2, q1, starting, discarded]);
}

#[test]
fn templates_are_the_init_templates() {
    let w = world(1);
    let names: Vec<String> = w.mgr.templates().into_iter().map(|t| t.name).collect();
    assert_eq!(names, vec!["claude-code".to_string()]);
}

#[test]
fn restart_marks_lost_vms_done() {
    let mut w = world(2);
    let a = running(&w, "a");
    let b = w.spawn("b").id;
    w.vmm.set_status(&a, VmStatus::Gone);
    w.vmm.set_status(&b, VmStatus::Off);
    let warns = w.reopen();
    assert_eq!(warns.len(), 2, "{warns:?}");
    for i in [&a, &b] {
        let g = w.mgr.get(i).unwrap();
        assert_eq!(g.state, BoxState::Done);
        assert!(!g.vm_on);
        assert_eq!(
            g.error.as_deref(),
            Some("the VM was gone after a daemon restart")
        );
        w.assert_saved(i);
    }
    assert_eq!(w.mgr.capacity().1, Committed::default());
}

#[test]
fn restart_keeps_live_vms() {
    let mut w = world(3);
    let a = running(&w, "a");
    let p = running(&w, "p");
    let s = w.spawn("s").id;
    w.vmm.set_status(&p, VmStatus::Paused);
    w.vmm.set_status(&s, VmStatus::Created);
    let before = w.mgr.get(&a).unwrap();
    w.reopen();
    assert_eq!(w.mgr.get(&a).unwrap(), before);
    assert_eq!(state(&w, &p), BoxState::Paused);
    w.assert_saved(&p);
    assert_eq!(state(&w, &s), BoxState::Starting);
    assert!(w.mgr.get(&s).unwrap().vm_on);
    // The boot timeout still applies to the kept starting box.
    w.advance(BOOT_TIMEOUT_SECS);
    let changes = w.mgr.tick();
    assert_eq!(
        changes,
        vec![change(
            &s,
            BoxState::Starting,
            BoxState::Discarded,
            "boot timed out"
        )]
    );
}

#[test]
fn restart_keeps_queue_order() {
    let mut w = world(1);
    w.spawn("a");
    let q: Vec<BoxId> = (0..3).map(|n| w.spawn(&format!("q{n}")).id).collect();
    let order = vec![q[2].clone(), q[0].clone(), q[1].clone()];
    w.mgr.reorder(&order).unwrap();
    assert!(w.reopen().is_empty());
    assert_eq!(w.mgr.queue(), order);
    let e = w.spawn("e").id;
    assert_eq!(e, id("b5"));
    assert_eq!(w.mgr.queue_pos(&e), Some(4));
}

#[test]
fn gc_removes_discarded_and_orphans() {
    let w = world(1);
    w.vmm.fail_next(VmOp::Boot, "no kvm");
    let failed = w.spawn("a").id;
    let live = w.spawn("b").id;
    // A claimed dir with no box.json: a crash between claim and save.
    let orphan = Store::open(w.root.clone()).unwrap().claim_id().unwrap();
    assert_eq!(
        w.mgr.gc(),
        GcReport {
            removed: vec![failed.clone(), orphan.clone()],
            error: None,
        }
    );
    assert!(!w.root.join(failed.as_str()).exists());
    assert!(!w.root.join(orphan.as_str()).exists());
    assert_eq!(w.mgr.get(&failed), Err(BoxError::NotFound));
    assert!(w.root.join(live.as_str()).join("box.json").exists());
    assert_eq!(w.mgr.gc(), GcReport::default());
    // Ids are never reused.
    assert_eq!(w.spawn("c").id, id("b4"));
}

#[test]
fn discard_destroy_failure_keeps_record_for_gc() {
    let w = world(1);
    let a = running(&w, "a");
    w.mgr.done(&a).unwrap();
    w.vmm.fail_next(VmOp::Destroy, "busy");
    assert_eq!(
        w.mgr.discard(&a).unwrap(),
        change(&a, BoxState::Done, BoxState::Discarded, "discard")
    );
    let g = w.mgr.get(&a).unwrap();
    assert_eq!(g.state, BoxState::Discarded);
    assert!(!g.vm_on);
    assert!(g.vm.is_some());
    assert_eq!(
        g.error.as_deref(),
        Some("discard: the VM could not be destroyed: busy")
    );
    assert!(w.root.join(a.as_str()).join("box.json").exists());
    w.assert_saved(&a);
    assert_eq!(w.mgr.capacity().1, Committed::default());
    // gc retries the destroy; a second failure keeps the record.
    w.vmm.fail_next(VmOp::Destroy, "still busy");
    assert_eq!(w.mgr.gc(), GcReport::default());
    assert_eq!(
        w.mgr.get(&a).unwrap().error.as_deref(),
        Some("gc: the VM could not be destroyed: still busy")
    );
    w.assert_saved(&a);
    assert_eq!(
        w.mgr.gc(),
        GcReport {
            removed: vec![a.clone()],
            error: None,
        }
    );
    assert_eq!(count(&w, &a, VmOp::Destroy), 3);
    assert!(!w.root.join(a.as_str()).exists());
    assert_eq!(w.mgr.get(&a), Err(BoxError::NotFound));
}

#[test]
fn discard_clears_the_vm_handle_on_success() {
    let w = world(1);
    w.vmm.fail_next(VmOp::Boot, "no kvm");
    let r = w.spawn("a");
    // The boot failure destroyed the VM, so its handle is gone and a later
    // discard makes no VMM call.
    assert_eq!(r.vm, None);
    let before = w.vmm.calls().len();
    w.mgr.discard(&r.id).unwrap();
    assert_eq!(w.vmm.calls().len(), before);
}

#[test]
fn boot_timeout_destroy_failure_is_recorded() {
    let w = world(1);
    let r = w.spawn("a");
    w.vmm.fail_next(VmOp::Destroy, "stuck");
    w.advance(BOOT_TIMEOUT_SECS);
    assert_eq!(
        w.mgr.tick(),
        vec![change(
            &r.id,
            BoxState::Starting,
            BoxState::Discarded,
            "boot timed out"
        )]
    );
    let g = w.mgr.get(&r.id).unwrap();
    assert_eq!(
        g.error.as_deref(),
        Some("boot timed out; destroy failed: stuck")
    );
    assert!(g.vm.is_some());
    w.assert_saved(&r.id);
    assert_eq!(
        w.mgr.gc(),
        GcReport {
            removed: vec![r.id.clone()],
            error: None,
        }
    );
    assert_eq!(count(&w, &r.id, VmOp::Destroy), 2);
}

#[test]
fn boot_failure_destroy_failure_keeps_vm() {
    let w = world(1);
    w.vmm.fail_next(VmOp::Boot, "no kvm");
    w.vmm.fail_next(VmOp::Destroy, "stuck");
    let r = w.spawn("a");
    assert_eq!(r.state, BoxState::Discarded);
    assert_eq!(
        r.error.as_deref(),
        Some("boot failed: no kvm; destroy failed: stuck")
    );
    assert!(r.vm.is_some());
    w.assert_saved(&r.id);
}

#[test]
fn admission_save_failure_leaves_box_queued() {
    let w = world(1);
    let a = running(&w, "a");
    let b = w.spawn("b");
    // Without its marker the store refuses to save the box.
    std::fs::remove_file(w.root.join(b.id.as_str()).join(".saiife-box")).unwrap();
    w.mgr.stop(&a, false).unwrap();
    assert!(w.mgr.tick().is_empty());
    assert_eq!(state(&w, &b.id), BoxState::Queued);
    assert_eq!(w.mgr.queue(), vec![b.id.clone()]);
    assert!(ops(&w, &b.id).is_empty());
    assert_eq!(w.mgr.capacity().1, Committed::default());
}

#[test]
fn restart_returns_its_changes() {
    let mut w = world(3);
    let a = running(&w, "a");
    let p = running(&w, "p");
    w.mgr.pause(&p).unwrap();
    let d = running(&w, "d");
    w.mgr.done(&d).unwrap();
    w.vmm.set_status(&a, VmStatus::Gone);
    w.vmm.set_status(&p, VmStatus::Running);
    w.vmm.set_status(&d, VmStatus::Gone);
    let (warns, changes) = w.reopen_changes();
    assert_eq!(warns.len(), 3, "{warns:?}");
    assert_eq!(
        changes,
        vec![
            change(
                &a,
                BoxState::Running,
                BoxState::Done,
                "vm lost after restart"
            ),
            change(&p, BoxState::Paused, BoxState::Running, "reconciled"),
            change(&d, BoxState::Done, BoxState::Done, "vm lost after restart"),
        ]
    );
    // Nothing more to recover on the next start.
    assert_eq!(w.reopen_changes(), (Vec::new(), Vec::new()));
}

/// A VMM that reads the box's record from disk when asked to boot it.
struct PeekVmm {
    inner: Arc<FakeVmm>,
    root: std::path::PathBuf,
    seen: Mutex<Vec<BoxRecord>>,
}

impl Vmm for PeekVmm {
    fn create(&self, spec: &VmSpec) -> Result<VmHandle, VmmError> {
        self.inner.create(spec)
    }
    fn boot(&self, h: &VmHandle) -> Result<(), VmmError> {
        let r = Store::open(self.root.clone()).unwrap().load(&h.id).unwrap();
        self.seen.lock().unwrap().extend(r);
        self.inner.boot(h)
    }
    fn pause(&self, h: &VmHandle) -> Result<(), VmmError> {
        self.inner.pause(h)
    }
    fn resume(&self, h: &VmHandle) -> Result<(), VmmError> {
        self.inner.resume(h)
    }
    fn stop(&self, h: &VmHandle) -> Result<(), VmmError> {
        self.inner.stop(h)
    }
    fn snapshot(&self, h: &VmHandle, dest: &std::path::Path) -> Result<(), VmmError> {
        self.inner.snapshot(h, dest)
    }
    fn status(&self, h: &VmHandle) -> VmStatus {
        self.inner.status(h)
    }
    fn destroy(&self, h: &VmHandle) -> Result<(), VmmError> {
        self.inner.destroy(h)
    }
}

#[test]
fn the_handle_is_saved_before_boot() {
    let w = world(1);
    let peek = Arc::new(PeekVmm {
        inner: w.vmm.clone(),
        root: w.root.clone(),
        seen: Mutex::new(Vec::new()),
    });
    let mut init = w.init(w.guest.clone());
    init.vmm = peek.clone();
    let mgr = Manager::open(init).unwrap().manager;
    let r = mgr
        .spawn(&w.args("claude-code", "a", Start::Queue))
        .unwrap();
    assert_eq!(r.state, BoxState::Starting);
    let seen = peek.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1, "boot read the record once");
    assert_eq!(seen[0].state, BoxState::Starting);
    assert_eq!(seen[0].vm, Some(handle(&r.id)), "saved before boot");
    assert!(!seen[0].vm_on);
}

/// A crash after `create` (and maybe `boot`) but before the save of
/// `vm_on`: the record is Starting, names its VM and says it is off.
fn crash_after_create(w: &World) -> BoxId {
    let r = w.spawn("a");
    let mut d = w.on_disk(&r.id).unwrap();
    assert_eq!(d.vm, Some(handle(&r.id)));
    d.vm_on = false;
    Store::open(w.root.clone()).unwrap().save(&d).unwrap();
    r.id
}

#[test]
fn restart_with_a_created_vm_lets_the_boot_timeout_destroy_it() {
    let mut w = world(1);
    let i = crash_after_create(&w);
    w.vmm.set_status(&i, VmStatus::Created);
    let (warns, changes) = w.reopen_changes();
    assert!(
        warns.is_empty() && changes.is_empty(),
        "{warns:?} {changes:?}"
    );
    assert_eq!(state(&w, &i), BoxState::Starting);
    w.advance(BOOT_TIMEOUT_SECS);
    assert_eq!(
        w.mgr.tick(),
        vec![change(
            &i,
            BoxState::Starting,
            BoxState::Discarded,
            "boot timed out"
        )]
    );
    let g = w.mgr.get(&i).unwrap();
    assert_eq!(g.vm, None, "the VM was destroyed");
    assert_eq!(w.vmm.status(&handle(&i)), VmStatus::Gone);
    w.assert_saved(&i);
}

#[test]
fn restart_with_a_booted_vm_marks_it_on() {
    let mut w = world(1);
    let i = crash_after_create(&w);
    // The fake VM is running (boot happened before the crash).
    assert_eq!(w.vmm.status(&handle(&i)), VmStatus::Running);
    let (warns, changes) = w.reopen_changes();
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert_eq!(
        changes,
        vec![change(
            &i,
            BoxState::Starting,
            BoxState::Starting,
            "reconciled"
        )]
    );
    assert!(w.mgr.get(&i).unwrap().vm_on);
    w.assert_saved(&i);
    assert_ne!(
        w.mgr.capacity().1,
        Committed::default(),
        "it holds its slot"
    );
}

#[test]
fn tick_without_admit_holds_the_queue() {
    let w = world(1);
    let a = running(&w, "a");
    let b = w.spawn("b").id;
    w.mgr.stop(&a, false).unwrap();
    assert!(w.mgr.tick_with(false).is_empty());
    assert_eq!(state(&w, &b), BoxState::Queued);
    assert!(ops(&w, &b).is_empty());
    assert_eq!(
        w.mgr.tick_with(true),
        vec![change(&b, BoxState::Queued, BoxState::Starting, "admitted")]
    );
}

#[test]
fn tick_without_admit_still_takes_power_away() {
    let w = world(2);
    let s = w.spawn("s").id;
    let r = running(&w, "r");
    w.mgr.guest_event(&r, GuestEvent::TurnFinished).unwrap();
    w.advance(BOOT_TIMEOUT_SECS);
    let changes = w.mgr.tick_with(false);
    assert_eq!(
        changes,
        vec![
            change(
                &s,
                BoxState::Starting,
                BoxState::Discarded,
                "boot timed out"
            ),
            change(&r, BoxState::Running, BoxState::Done, "turn finished"),
        ]
    );
}

#[test]
fn ready_without_prompt_holds_it_until_an_admitting_tick() {
    let w = world(1);
    let r = w.spawn("do it");
    let c = w
        .mgr
        .guest_event_with(&r.id, GuestEvent::Ready, false)
        .unwrap();
    assert_eq!(
        c,
        Some(change(
            &r.id,
            BoxState::Starting,
            BoxState::Running,
            "ready"
        ))
    );
    assert!(w.guest.prompts().is_empty());
    assert_eq!(
        w.mgr.get(&r.id).unwrap().pending_prompt.as_deref(),
        Some("do it")
    );
    w.assert_saved(&r.id);
    w.advance(5);
    assert!(w.mgr.tick_with(false).is_empty());
    assert!(w.guest.prompts().is_empty());
    assert!(w.mgr.tick().is_empty());
    assert_eq!(w.guest.prompts(), vec![(r.id.clone(), "do it".to_string())]);
    let g = w.mgr.get(&r.id).unwrap();
    assert_eq!(g.pending_prompt, None);
    assert_eq!(g.last_activity, w.now());
    w.assert_saved(&r.id);
    w.mgr.tick();
    assert_eq!(w.guest.prompts().len(), 1, "sent once");
}

#[test]
fn gc_goes_on_past_a_box_it_cannot_remove() {
    let w = world(1);
    w.vmm.fail_next(VmOp::Boot, "no kvm");
    let stuck = w.spawn("a").id;
    w.vmm.fail_next(VmOp::Boot, "no kvm");
    let next = w.spawn("b").id;
    let orphan = Store::open(w.root.clone()).unwrap().claim_id().unwrap();
    // Without its marker the store refuses to remove the dir.
    std::fs::remove_file(w.root.join(stuck.as_str()).join(".saiife-box")).unwrap();
    let rep = w.mgr.gc();
    assert_eq!(rep.removed, vec![next.clone(), orphan.clone()]);
    assert!(rep.error.is_some(), "{rep:?}");
    assert!(w.mgr.get(&stuck).is_ok(), "the stuck box stays");
    assert!(!w.root.join(next.as_str()).exists());
    assert!(!w.root.join(orphan.as_str()).exists());
}

/// R41: a destroy that fails (a VMM still stopping) keeps `vm`; the next
/// tick retries it and clears `vm` (and the destroy failure in `error`)
/// once it succeeds. A finished retry is not tried again.
#[test]
fn tick_retries_a_failed_destroy_until_it_succeeds() {
    let w = world(1);
    let r = w.spawn("a");
    w.vmm.fail_next(VmOp::Destroy, "the VMM is still stopping");
    w.advance(BOOT_TIMEOUT_SECS);
    assert_eq!(w.mgr.tick().len(), 1);
    let g = w.mgr.get(&r.id).unwrap();
    assert_eq!(g.state, BoxState::Discarded);
    assert!(g.vm.is_some(), "a failed destroy keeps the handle");
    assert_eq!(count(&w, &r.id, VmOp::Destroy), 1);
    // the next tick retries it, fails again, keeps the handle
    w.vmm.fail_next(VmOp::Destroy, "the VMM is still stopping");
    assert!(w.mgr.tick().is_empty());
    assert_eq!(count(&w, &r.id, VmOp::Destroy), 2);
    assert!(w.mgr.get(&r.id).unwrap().vm.is_some());
    // then it succeeds: vm cleared, the destroy failure dropped, saved
    assert!(w.mgr.tick().is_empty());
    assert_eq!(count(&w, &r.id, VmOp::Destroy), 3);
    let g = w.mgr.get(&r.id).unwrap();
    assert_eq!(g.vm, None);
    assert_eq!(g.state, BoxState::Discarded);
    assert_eq!(g.error.as_deref(), Some("boot timed out"));
    w.assert_saved(&r.id);
    // nothing left to retry
    assert!(w.mgr.tick().is_empty());
    assert_eq!(count(&w, &r.id, VmOp::Destroy), 3);
}

/// R41: a discard whose destroy failed is retried by the tick too.
#[test]
fn tick_retries_a_failed_discard_destroy() {
    let w = world(1);
    let a = running(&w, "a");
    w.mgr.done(&a).unwrap();
    w.vmm.fail_next(VmOp::Destroy, "busy");
    w.mgr.discard(&a).unwrap();
    assert!(w.mgr.get(&a).unwrap().vm.is_some());
    assert!(w.mgr.tick().is_empty());
    let g = w.mgr.get(&a).unwrap();
    assert_eq!(g.vm, None);
    assert_eq!(g.error, None);
    w.assert_saved(&a);
    assert_eq!(
        w.mgr.gc(),
        GcReport {
            removed: vec![a.clone()],
            error: None,
        }
    );
    assert_eq!(count(&w, &a, VmOp::Destroy), 2);
}
