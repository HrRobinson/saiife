#![cfg(feature = "fake")]
mod common;

use std::sync::Arc;

use common::{id, world};
use saiife_boxes::guest::{GuestEvent, NoGuest};
use saiife_boxes::manager::Manager;
use saiife_boxes::source::ManagerSource;
use saiife_wire::conformance::{check, Fixture};
use saiife_wire::source::{BoxError, BoxSource, BoxState, DiffSummary, SpawnReq, Start, TermFrame};
use sha2::{Digest, Sha256};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn diff_for(i: &saiife_boxes::BoxId) -> DiffSummary {
    let unified = "--- a/f\n+++ b/f\n@@ -1 +1 @@\n-a\n+b\n".to_string();
    DiffSummary {
        id: i.clone(),
        base_commit: "0".repeat(40),
        diff_sha256: hex(&Sha256::digest(unified.as_bytes())),
        files: Vec::new(),
        unified,
        truncated: false,
        tests: None,
    }
}

fn frame(seq: u64) -> TermFrame {
    TermFrame::Delta {
        seq,
        lines: vec![(0, format!("line {seq}"))],
        cursor: (0, 0),
    }
}

/// b1, b2 running as uid 1000; b2 done; b3, b4 queued.
fn fixture(w: &common::World) -> [saiife_boxes::BoxId; 4] {
    let b: Vec<_> = (0..2).map(|_| w.spawn("t").id).collect();
    for i in &b {
        w.mgr.guest_event(i, GuestEvent::Ready).unwrap();
    }
    w.mgr.done(&b[1]).unwrap();
    let q3 = w.spawn("t").id;
    let q4 = w.spawn("t").id;
    [b[0].clone(), b[1].clone(), q3, q4]
}

#[test]
fn manager_source_passes_conformance() {
    let w = world(2);
    let [b1, b2, b3, b4] = fixture(&w);
    w.guest.set_diff(&b2, diff_for(&b2));
    w.guest.set_terminal(&b2, vec![frame(1), frame(2)]);
    let src = ManagerSource::new(w.mgr.clone(), Some(1000));
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
fn owner_filter_hides_other_users() {
    let w = world(2);
    let mine = ManagerSource::new(w.mgr.clone(), Some(1000));
    let theirs = ManagerSource::new(w.mgr.clone(), Some(1001));
    let i = theirs
        .spawn(&SpawnReq {
            template: "claude-code".into(),
            repo: "r".into(),
            task: "t".into(),
            start: Start::Queue,
        })
        .unwrap();
    assert!(mine.list().is_empty() && mine.overview().boxes.is_empty());
    assert_eq!(mine.stop(&i), Err(BoxError::NotFound));
    assert_eq!(mine.diff(&i), Err(BoxError::NotFound));
    assert_eq!(mine.terminal(&i, None), Err(BoxError::NotFound));
    assert_eq!(mine.steer(&i, "x"), Err(BoxError::NotFound));
    assert_eq!(theirs.list().len(), 1);
    let locked = ManagerSource::new(w.mgr.clone(), None);
    assert_eq!(locked.list().len(), 1);
}

#[test]
fn reorder_filtered_keeps_other_slots() {
    let w = world(1);
    w.spawn("run"); // runs
    let a1 = w.spawn("a").id; // uid 1000
    let other = w
        .mgr
        .spawn(&saiife_boxes::manager::SpawnArgs {
            owner_uid: 1001,
            ..w.args("claude-code", "o", Start::Queue)
        })
        .unwrap()
        .id;
    let a2 = w.spawn("b").id;
    let src = ManagerSource::new(w.mgr.clone(), Some(1000));
    assert_eq!(
        src.reorder(std::slice::from_ref(&a1)).unwrap_err().rule(),
        "invalid"
    );
    src.reorder(&[a2.clone(), a1.clone()]).unwrap();
    assert_eq!(w.mgr.queue(), vec![a2.clone(), other, a1.clone()]);
    let pos: Vec<_> = src
        .list()
        .iter()
        .map(|b| (b.id.clone(), b.queue_pos))
        .collect();
    assert!(pos.contains(&(a2, Some(1))) && pos.contains(&(a1, Some(2))));
}

#[test]
fn locked_source_cannot_spawn() {
    let w = world(2);
    let src = ManagerSource::new(w.mgr.clone(), None);
    let r = src.spawn(&SpawnReq {
        template: "claude-code".into(),
        repo: "r".into(),
        task: "t".into(),
        start: Start::Now,
    });
    assert_eq!(
        r,
        Err(BoxError::Unavailable(
            "Workspace spawn in locked mode needs the device owner".into()
        ))
    );
}

#[test]
fn spawn_now_falls_back_to_queue() {
    let w = world(1);
    let src = ManagerSource::new(w.mgr.clone(), Some(1000));
    let req = SpawnReq {
        template: "claude-code".into(),
        repo: "r".into(),
        task: "t".into(),
        start: Start::Now,
    };
    let a = src.spawn(&req).unwrap();
    let b = src.spawn(&req).unwrap();
    assert_eq!(w.mgr.get(&a).unwrap().state, BoxState::Starting);
    assert_eq!(w.mgr.get(&b).unwrap().state, BoxState::Queued);
}

#[test]
fn diff_goes_through_the_guest() {
    let w = world(2);
    let [_, b2, _, _] = fixture(&w);
    let d = diff_for(&b2);
    w.guest.set_diff(&b2, d.clone());
    let src = ManagerSource::new(w.mgr.clone(), Some(1000));
    assert_eq!(src.diff(&b2), Ok(d));

    let mgr = Manager::open(w.init(Arc::new(NoGuest))).unwrap().manager;
    let src = ManagerSource::new(Arc::new(mgr), Some(1000));
    assert!(matches!(src.diff(&b2), Err(BoxError::Unavailable(_))));
    // Ended box with no guest: empty ended batch; live box: unavailable.
    let t = src.terminal(&b2, Some(7)).unwrap();
    assert!(t.ended && t.frames.is_empty() && t.next == 7);
    assert!(matches!(
        src.terminal(&id("b1"), None),
        Err(BoxError::Unavailable(_))
    ));
}

#[test]
fn overview_load_and_slots() {
    let w = world(3);
    w.spawn("t");
    let mut init = w.init(w.guest.clone());
    let mut host = w.host;
    host.cpu_pct = Some(42);
    host.mem_avail_mib = 1000;
    init.host = Arc::new(move || host);
    let mgr = Manager::open(init).unwrap().manager;
    let src = ManagerSource::new(Arc::new(mgr), Some(1000));
    let o = src.overview();
    let l = o.load.expect("load when the host reports cpu");
    assert_eq!(l.cpu_pct, 42);
    assert_eq!(l.mem_total_mb, host.mem_total_mib);
    assert_eq!(l.mem_used_mb, host.mem_total_mib - 1000);
    assert_eq!((o.slots_total, o.slots_free), (3, 2));
    // No cpu sample, no load.
    assert!(ManagerSource::new(w.mgr.clone(), Some(1000))
        .overview()
        .load
        .is_none());
}

#[test]
fn with_changes_receives_spawn_admissions() {
    use std::sync::Mutex;
    let w = world(1);
    let got: Arc<Mutex<Vec<(saiife_boxes::BoxId, BoxState)>>> = Arc::default();
    let sink: saiife_boxes::source::ChangeSink = {
        let got = Arc::clone(&got);
        Arc::new(move |cs| {
            let mut g = got.lock().unwrap();
            g.extend(cs.iter().map(|c| (c.id.clone(), c.to)));
        })
    };
    let src = ManagerSource::new(w.mgr.clone(), Some(1000)).with_changes(sink);
    let req = |t: &str| SpawnReq {
        template: "claude-code".into(),
        repo: "shop".into(),
        task: t.into(),
        start: Start::Queue,
    };
    // The new box's own admission is not the sink's.
    let a = src.spawn(&req("a")).unwrap();
    assert!(got.lock().unwrap().is_empty());
    let b = src.spawn(&req("b")).unwrap();
    assert!(got.lock().unwrap().is_empty());
    // A slot frees; the next spawn's pass admits the head, B.
    w.mgr.stop(&a, false).unwrap();
    let c = src.spawn(&req("c")).unwrap();
    assert_eq!(
        *got.lock().unwrap(),
        vec![(b.clone(), BoxState::Starting)],
        "only the earlier head, never the new box {c:?}"
    );
}
