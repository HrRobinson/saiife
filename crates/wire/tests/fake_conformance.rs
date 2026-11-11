#![cfg(feature = "fake")]

use saiife_touch::{TouchClass, TouchEvidence};
use saiife_wire::conformance::{check, Fixture};
use saiife_wire::fake::{FakeBoxSource, FakeCall};
use saiife_wire::source::*;
use std::sync::Mutex;

const NOW: u64 = 1_800_000_000;

fn id(s: &str) -> BoxId {
    BoxId::parse(s).unwrap()
}

fn fixture(src: &dyn BoxSource) -> Fixture<'_> {
    Fixture {
        source: src,
        running: id("b-run"),
        done: id("b-done"),
        queued: vec![id("b-q1"), id("b-q2")],
        template: "claude".into(),
    }
}

fn evidence() -> TouchEvidence {
    TouchEvidence {
        credential_id: "cred".into(),
        kind: "webauthn",
        user_verified: true,
        sign_count: 1,
        challenge_hex: "00".repeat(32),
        label: "key".into(),
        via: "web",
        flags: 0x05,
        auth_data: vec![0; 37],
        client_data: None,
        client_data_hash: [0; 32],
        signature: vec![1, 2, 3],
        preimage_hex: String::new(),
        action: "land".into(),
    }
}

fn info(src: &FakeBoxSource, b: &str) -> BoxInfo {
    src.list().into_iter().find(|i| i.id.as_str() == b).unwrap()
}

#[test]
fn demo_passes_conformance() {
    let src = FakeBoxSource::demo(NOW);
    assert_eq!(check(&fixture(&src)), Ok(()));
}

#[test]
fn fake_carries_hostile_display_data() {
    let src = FakeBoxSource::demo(NOW);
    let d = src.diff(&id("b-done")).unwrap();
    assert!(d
        .files
        .iter()
        .any(|f| f.path == "../../.ssh/authorized_keys"));
    assert!(d
        .files
        .iter()
        .any(|f| f.path == "<img src=x onerror=alert(1)>.md"));
    assert!(d.files.iter().any(|f| f.binary));
    assert!(d.unified.contains("\x1b]52;c;"));
    assert!(info(&src, "b-done").task.contains('\u{202e}'));
}

#[test]
fn diff_is_capped_and_flagged() {
    let src = FakeBoxSource::demo(NOW);
    let d = src.diff(&id("b-done")).unwrap();
    assert!(d.truncated);
    assert!(d.unified.len() <= MAX_DIFF_BYTES);
    assert!(d.unified.len() > MAX_DIFF_BYTES - 4096);
    assert!(d.unified.ends_with('\n'));
    assert_eq!(d.diff_sha256.len(), 64);
}

#[test]
fn revise_moves_done_to_running() {
    let src = FakeBoxSource::demo(NOW);
    src.revise(&id("b-done"), "please add tests").unwrap();
    assert_eq!(info(&src, "b-done").state, BoxState::Running);
    assert!(matches!(
        src.revise(&id("b-run"), "x"),
        Err(BoxError::WrongState { .. })
    ));
}

#[test]
fn complete_approve_lands() {
    let src = FakeBoxSource::demo(NOW);
    let p = src.pending_actions();
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].class, TouchClass::Land);
    let rid = p[0].request_id;
    assert_eq!(
        src.complete(rid, Decision::Approve, None),
        Err(BoxError::Invalid("approve needs evidence".into()))
    );
    src.complete(rid, Decision::Approve, Some(evidence()))
        .unwrap();
    let b = info(&src, "b-done");
    assert_eq!(b.state, BoxState::Landed);
    assert_eq!(b.lands, 1);
    assert!(src.pending_actions().is_empty());
    assert_eq!(
        src.complete(rid, Decision::Reject, None),
        Err(BoxError::NotFound)
    );
}

#[test]
fn complete_reject_keeps_done() {
    let src = FakeBoxSource::demo(NOW);
    let rid = src.pending_actions()[0].request_id;
    assert!(matches!(
        src.complete(rid, Decision::Reject, Some(evidence())),
        Err(BoxError::Invalid(_))
    ));
    src.complete(rid, Decision::Reject, None).unwrap();
    assert_eq!(info(&src, "b-done").state, BoxState::Done);
    assert!(src.pending_actions().is_empty());
}

#[test]
fn spawn_queues_or_starts() {
    let src = FakeBoxSource::demo(NOW);
    let req = SpawnReq {
        template: "claude".into(),
        repo: "erp".into(),
        task: "do it".into(),
        start: Start::Queue,
    };
    let n = src.spawn(&req).unwrap();
    let b = info(&src, n.as_str());
    assert_eq!((b.state, b.queue_pos), (BoxState::Queued, Some(3)));
    let n2 = src
        .spawn(&SpawnReq {
            start: Start::Now,
            ..req.clone()
        })
        .unwrap();
    assert_ne!(n, n2);
    assert_eq!(info(&src, n2.as_str()).state, BoxState::Running);
    let o = src.overview();
    assert_eq!((o.slots_total, o.slots_free), (4, 2));
    assert!(matches!(
        src.spawn(&SpawnReq {
            template: "nope".into(),
            ..req.clone()
        }),
        Err(BoxError::Invalid(_))
    ));
    assert!(matches!(
        src.spawn(&SpawnReq {
            task: "a\x1bb".into(),
            ..req
        }),
        Err(BoxError::Invalid(_))
    ));
}

#[test]
fn terminal_pages_by_seq() {
    let src = FakeBoxSource::demo(NOW);
    let b = src.terminal(&id("b-run"), None).unwrap();
    assert!(b.frames.len() >= 2 && !b.ended);
    let again = src.terminal(&id("b-run"), Some(b.next)).unwrap();
    assert!(again.frames.is_empty());
    assert_eq!(again.next, b.next);
    let first = match &b.frames[0] {
        TermFrame::Snapshot { seq, .. } | TermFrame::Delta { seq, .. } => seq,
    };
    let rest = src.terminal(&id("b-run"), Some(*first)).unwrap();
    assert_eq!(rest.frames.len(), b.frames.len() - 1);
    assert!(src.terminal(&id("b-done"), None).unwrap().ended);
    let none = src.terminal(&id("b-q1"), None).unwrap();
    assert_eq!((none.frames.len(), none.next), (0, 0));
    let custom = FakeBoxSource::demo(NOW).with_terminal(
        "b-q1",
        vec![TermFrame::Delta {
            seq: 7,
            lines: vec![],
            cursor: (0, 0),
        }],
    );
    assert_eq!(custom.terminal(&id("b-q1"), None).unwrap().next, 7);
}

#[test]
fn calls_are_recorded() {
    let src = FakeBoxSource::demo(NOW);
    src.pause(&id("b-run")).unwrap();
    src.resume(&id("b-run")).unwrap();
    src.steer(&id("b-run"), "go left").unwrap();
    src.reorder(&[id("b-q2"), id("b-q1")]).unwrap();
    src.discard(&id("b-q1")).unwrap();
    assert_eq!(info(&src, "b-q2").queue_pos, Some(1));
    src.stop(&id("b-run")).unwrap();
    assert_eq!(
        src.calls(),
        vec![
            FakeCall::Pause(id("b-run")),
            FakeCall::Resume(id("b-run")),
            FakeCall::Steer(id("b-run"), "go left".into()),
            FakeCall::Reorder(vec![id("b-q2"), id("b-q1")]),
            FakeCall::Discard(id("b-q1")),
            FakeCall::Stop(id("b-run")),
        ]
    );
    src.set_now(NOW + 5);
    assert_eq!(info(&src, "b-run").updated_at, NOW);
}

#[test]
fn empty_source_is_empty() {
    let src = FakeBoxSource::empty(NOW);
    assert!(src.list().is_empty() && src.pending_actions().is_empty());
    assert!(src.overview().load.is_none());
}

/// Delegates everything; a second successful `stop` of one id errs.
struct Broken {
    inner: FakeBoxSource,
    stopped: Mutex<Vec<BoxId>>,
}

impl BoxSource for Broken {
    fn overview(&self) -> Overview {
        self.inner.overview()
    }
    fn list(&self) -> Vec<BoxInfo> {
        self.inner.list()
    }
    fn terminal(&self, i: &BoxId, a: Option<u64>) -> Result<TermBatch, BoxError> {
        self.inner.terminal(i, a)
    }
    fn diff(&self, i: &BoxId) -> Result<DiffSummary, BoxError> {
        self.inner.diff(i)
    }
    fn stop(&self, i: &BoxId) -> Result<(), BoxError> {
        let mut s = self.stopped.lock().unwrap();
        if s.contains(i) {
            return Err(BoxError::Invalid("already stopped".into()));
        }
        self.inner.stop(i)?;
        s.push(i.clone());
        Ok(())
    }
    fn pause(&self, i: &BoxId) -> Result<(), BoxError> {
        self.inner.pause(i)
    }
    fn resume(&self, i: &BoxId) -> Result<(), BoxError> {
        self.inner.resume(i)
    }
    fn discard(&self, i: &BoxId) -> Result<(), BoxError> {
        self.inner.discard(i)
    }
    fn reorder(&self, q: &[BoxId]) -> Result<(), BoxError> {
        self.inner.reorder(q)
    }
    fn steer(&self, i: &BoxId, m: &str) -> Result<(), BoxError> {
        self.inner.steer(i, m)
    }
    fn revise(&self, i: &BoxId, c: &str) -> Result<(), BoxError> {
        self.inner.revise(i, c)
    }
    fn pending_actions(&self) -> Vec<PendingAction> {
        self.inner.pending_actions()
    }
    fn complete(&self, r: u64, d: Decision, e: Option<TouchEvidence>) -> Result<(), BoxError> {
        self.inner.complete(r, d, e)
    }
    fn templates(&self) -> Vec<Template> {
        self.inner.templates()
    }
    fn spawn(&self, r: &SpawnReq) -> Result<BoxId, BoxError> {
        self.inner.spawn(r)
    }
}

#[test]
fn broken_source_fails_conformance() {
    let src = Broken {
        inner: FakeBoxSource::demo(NOW),
        stopped: Mutex::new(Vec::new()),
    };
    let err = check(&fixture(&src)).unwrap_err();
    assert!(err.contains("stop is idempotent"), "{err}");
}

#[test]
fn land_after_discard_is_refused() {
    let src = FakeBoxSource::demo(NOW);
    let rid = src.pending_actions()[0].request_id;
    src.discard(&id("b-done")).unwrap();
    assert!(src.pending_actions().is_empty());
    assert_eq!(
        src.complete(rid, Decision::Approve, Some(evidence())),
        Err(BoxError::NotFound)
    );
    assert_eq!(info(&src, "b-done").state, BoxState::Discarded);
    assert_eq!(info(&src, "b-done").lands, 0);
}

#[test]
fn land_after_revise_is_refused() {
    let src = FakeBoxSource::demo(NOW);
    let rid = src.pending_actions()[0].request_id;
    src.revise(&id("b-done"), "more").unwrap();
    assert_eq!(
        src.complete(rid, Decision::Approve, Some(evidence())),
        Err(BoxError::NotFound)
    );
    assert_eq!(info(&src, "b-done").state, BoxState::Running);
    assert_eq!(info(&src, "b-done").lands, 0);
}

#[test]
fn bad_fixture_is_named() {
    let src = FakeBoxSource::demo(NOW);
    let mut fx = fixture(&src);
    fx.queued.pop();
    assert!(check(&fx).unwrap_err().starts_with("fixture"));
}
