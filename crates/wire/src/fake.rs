//! `FakeBoxSource`: an in-memory `BoxSource` for plans 29/30 (daemon, UI) and
//! the reference the conformance kit (`crate::conformance`) is proven on.
//!
//! It follows the §7.7 state machine of the `BoxSource` trait doc and carries
//! hostile display data in the demo (a path traversal, an HTML file name, an
//! OSC 52 line, an RTL override, a binary file, a 2.5 MB diff): the DTOs cap
//! and flag it, the UI must escape it.
//!
//! `terminal(id, after)` returns the frames with `seq > after` (all when
//! `after` is `None`); `next` is the highest `seq` returned, or
//! `after.unwrap_or(0)` when none is returned; `ended` is true once the box is
//! Done, Landed or Discarded.

use crate::source::*;
use saiife_touch::{ActionRecord, TouchClass, TouchEvidence};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

/// Every mutating call the fake received, in order (failed calls included).
#[derive(Debug, Clone, PartialEq)]
pub enum FakeCall {
    Stop(BoxId),
    Pause(BoxId),
    Resume(BoxId),
    Discard(BoxId),
    Reorder(Vec<BoxId>),
    Steer(BoxId, String),
    Revise(BoxId, String),
    /// request id, decision, whether evidence was given.
    Complete(u64, Decision, bool),
    Spawn(SpawnReq),
}

const SLOTS_TOTAL: u32 = 4;
const INSTANCE_ID: [u8; 16] = *b"saiife-fake-inst";
const DIFF_GENERATED_BYTES: usize = 2_500_000;

struct FakeState {
    now: u64,
    counter: u64,
    next_box: u64,
    boxes: Vec<BoxInfo>,
    pending: Vec<PendingAction>,
    terminals: HashMap<BoxId, Vec<TermFrame>>,
    diffs: HashMap<BoxId, DiffSummary>,
    templates: Vec<Template>,
    load: Option<Load>,
    calls: Vec<FakeCall>,
}

pub struct FakeBoxSource {
    state: Mutex<FakeState>,
}

fn id(s: &str) -> BoxId {
    BoxId::parse(s).expect("fake box id")
}

fn templates() -> Vec<Template> {
    vec![
        Template {
            name: "claude".into(),
            description: "Claude Code, no secrets, no egress".into(),
            has_secrets: false,
            has_egress: false,
        },
        Template {
            name: "claude-gh".into(),
            description: "Claude Code with a GitHub token".into(),
            has_secrets: true,
            has_egress: true,
        },
    ]
}

fn rank(s: BoxState) -> u8 {
    match s {
        BoxState::Running => 0,
        BoxState::Paused => 1,
        BoxState::Done => 2,
        BoxState::Queued => 3,
        BoxState::Starting => 4,
        _ => 5,
    }
}

fn active(s: BoxState) -> bool {
    matches!(s, BoxState::Starting | BoxState::Running | BoxState::Paused)
}

fn seq_of(f: &TermFrame) -> u64 {
    match f {
        TermFrame::Snapshot { seq, .. } | TermFrame::Delta { seq, .. } => *seq,
    }
}

fn hex(b: &[u8]) -> String {
    crate::b64::hex(b)
}

fn hostile_diff(base_commit: &str) -> DiffSummary {
    let mut full = String::new();
    full.push_str("diff --git a/../../.ssh/authorized_keys b/../../.ssh/authorized_keys\n");
    full.push_str(
        "--- a/../../.ssh/authorized_keys\n+++ b/../../.ssh/authorized_keys\n@@ -0,0 +1 @@\n",
    );
    full.push_str("+ssh-ed25519 AAAA-not-a-real-key attacker\n");
    full.push_str(
        "diff --git a/<img src=x onerror=alert(1)>.md b/<img src=x onerror=alert(1)>.md\n",
    );
    full.push_str("--- /dev/null\n+++ b/<img src=x onerror=alert(1)>.md\n@@ -0,0 +1 @@\n");
    full.push_str("+\x1b]52;c;ZXZpbA==\x07 a clipboard attempt\n");
    full.push_str(
        "diff --git a/logo.png b/logo.png\nBinary files a/logo.png and b/logo.png differ\n",
    );
    full.push_str("diff --git a/src/big.rs b/src/big.rs\n--- a/src/big.rs\n+++ b/src/big.rs\n");
    let mut n = 0u64;
    while full.len() < DIFF_GENERATED_BYTES {
        full.push_str(&format!("+let generated_line_{n} = {n}; // filler\n"));
        n += 1;
    }
    let diff_sha256 = hex(&Sha256::digest(full.as_bytes()));
    let truncated = full.len() > MAX_DIFF_BYTES;
    let unified = if truncated {
        // '\n' is ASCII, so this is a char boundary.
        let cut = full.as_bytes()[..MAX_DIFF_BYTES]
            .iter()
            .rposition(|b| *b == b'\n')
            .map_or(0, |i| i + 1);
        full[..cut].to_string()
    } else {
        full
    };
    let file = |path: &str, status, added, removed, binary| FileChange {
        path: path.into(),
        status,
        added,
        removed,
        binary,
    };
    DiffSummary {
        id: id("b-done"),
        base_commit: base_commit.into(),
        diff_sha256,
        files: vec![
            file("../../.ssh/authorized_keys", FileStatus::Added, 1, 0, false),
            file(
                "<img src=x onerror=alert(1)>.md",
                FileStatus::Added,
                1,
                0,
                false,
            ),
            file("logo.png", FileStatus::Modified, 0, 0, true),
            file("src/big.rs", FileStatus::Modified, n as u32, 0, false),
        ],
        unified,
        truncated,
        tests: Some(TestResult {
            passed: 41,
            failed: 0,
            skipped: 2,
            summary: "41 passed, 2 skipped".into(),
        }),
    }
}

impl FakeState {
    fn next_counter(&mut self) -> u64 {
        self.counter += 1;
        self.counter
    }

    fn nonce(&mut self) -> [u8; 32] {
        let c = self.next_counter();
        let mut n = [0u8; 32];
        n[..8].copy_from_slice(&c.to_be_bytes());
        n
    }

    /// A fresh pending `land` for `bid`, binding `diff`.
    fn push_land(&mut self, bid: BoxId, repo: &str, diff: &DiffSummary) {
        let now = self.now;
        let mut fields = BTreeMap::new();
        fields.insert("repo".to_string(), repo.to_string());
        fields.insert("base_commit".to_string(), diff.base_commit.clone());
        fields.insert("diff_sha256".to_string(), diff.diff_sha256.clone());
        let request_id = self.next_counter();
        let record = ActionRecord {
            instance_id: INSTANCE_ID,
            request_id,
            class: TouchClass::Land,
            summary: format!("land {}", bid.as_str()),
            fields,
            nonce: self.nonce(),
            expires_at: now + 300,
        };
        self.pending.push(PendingAction {
            request_id,
            class: TouchClass::Land,
            box_id: Some(bid),
            summary: record.summary.clone(),
            expires_at: record.expires_at,
            record,
            created_at: now,
        });
    }

    fn find(&mut self, i: &BoxId) -> Result<&mut BoxInfo, BoxError> {
        self.boxes
            .iter_mut()
            .find(|b| &b.id == i)
            .ok_or(BoxError::NotFound)
    }

    fn renumber(&mut self) {
        let mut q: Vec<&mut BoxInfo> = self
            .boxes
            .iter_mut()
            .filter(|b| b.state == BoxState::Queued)
            .collect();
        q.sort_by_key(|b| b.queue_pos.unwrap_or(u32::MAX));
        for (i, b) in q.into_iter().enumerate() {
            b.queue_pos = Some(i as u32 + 1);
        }
    }

    fn free_slots(&self) -> u32 {
        let used = self.boxes.iter().filter(|b| active(b.state)).count() as u32;
        SLOTS_TOTAL.saturating_sub(used)
    }

    fn add_box(&mut self, id: BoxId, state: BoxState, template: &str, repo: &str, task: &str) {
        let now = self.now;
        let queue_pos = (state == BoxState::Queued).then(|| {
            self.boxes
                .iter()
                .filter(|b| b.state == BoxState::Queued)
                .count() as u32
                + 1
        });
        self.boxes.push(BoxInfo {
            id,
            state,
            template: template.into(),
            repo: repo.into(),
            task: task.into(),
            created_at: now,
            started_at: (state != BoxState::Queued).then_some(now),
            updated_at: now,
            queue_pos,
            lands: 0,
        });
    }

    fn set_state(&mut self, i: &BoxId, to: BoxState) -> Result<(), BoxError> {
        let now = self.now;
        let b = self.find(i)?;
        let from = b.state;
        b.state = to;
        b.updated_at = now;
        if to != BoxState::Queued {
            b.queue_pos = None;
        }
        if from == BoxState::Done && to != BoxState::Done {
            // A touch binds the diff of a Done box; leaving Done voids it.
            self.pending.retain(|p| p.box_id.as_ref() != Some(i));
        }
        Ok(())
    }
}

impl FakeBoxSource {
    fn new(now: u64) -> FakeBoxSource {
        FakeBoxSource {
            state: Mutex::new(FakeState {
                now,
                counter: 0,
                next_box: 0,
                boxes: Vec::new(),
                pending: Vec::new(),
                terminals: HashMap::new(),
                diffs: HashMap::new(),
                templates: templates(),
                load: None,
                calls: Vec::new(),
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.state.lock().expect("fake state lock")
    }

    /// No boxes, the two templates, no load figures, four slots.
    pub fn empty(now: u64) -> FakeBoxSource {
        FakeBoxSource::new(now)
    }

    /// Four boxes: "b-run" Running, "b-done" Done (with the hostile diff and a
    /// pending `land`), "b-q1" and "b-q2" Queued; two templates:
    /// "claude" (no secrets, no egress) and "claude-gh" (has_secrets).
    pub fn demo(now: u64) -> FakeBoxSource {
        let src = FakeBoxSource::new(now);
        {
            let mut s = src.lock();
            s.load = Some(Load {
                cpu_pct: 37,
                mem_used_mb: 6144,
                mem_total_mb: 16384,
            });
            s.add_box(
                id("b-run"),
                BoxState::Running,
                "claude",
                "erp",
                "refactor the invoice export",
            );
            s.add_box(
                id("b-done"),
                BoxState::Done,
                "claude-gh",
                "erp",
                "fix the login bug \u{202e}gnp.exe and add tests",
            );
            s.add_box(
                id("b-q1"),
                BoxState::Queued,
                "claude",
                "web",
                "bump dependencies",
            );
            s.add_box(
                id("b-q2"),
                BoxState::Queued,
                "claude",
                "web",
                "write the changelog",
            );
            let base = "0123456789abcdef0123456789abcdef01234567";
            let diff = hostile_diff(base);
            let mut fields = BTreeMap::new();
            fields.insert("repo".to_string(), "erp".to_string());
            fields.insert("base_commit".to_string(), base.to_string());
            fields.insert("diff_sha256".to_string(), diff.diff_sha256.clone());
            s.push_land(id("b-done"), "erp", &diff);
            s.diffs.insert(id("b-done"), diff);
            let snap = TermFrame::Snapshot {
                seq: 1,
                rows: 2,
                cols: 40,
                lines: vec!["$ cargo test".into(), "running 41 tests".into()],
                cursor: (1, 16),
            };
            let d2 = TermFrame::Delta {
                seq: 2,
                lines: vec![(1, "test result: ok".into())],
                cursor: (1, 15),
            };
            let d3 = TermFrame::Delta {
                seq: 3,
                lines: vec![(0, "$ ".into())],
                cursor: (0, 2),
            };
            s.terminals.insert(id("b-run"), vec![snap, d2, d3]);
            s.terminals.insert(
                id("b-done"),
                vec![TermFrame::Snapshot {
                    seq: 1,
                    rows: 1,
                    cols: 40,
                    lines: vec!["done".into()],
                    cursor: (0, 4),
                }],
            );
        }
        src
    }

    /// Every mutating call so far, in order (failed calls are recorded too).
    pub fn calls(&self) -> Vec<FakeCall> {
        self.lock().calls.clone()
    }

    /// Fake-only: the box finishes its work. Running -> Done, with a new small
    /// diff and a fresh pending `land` binding it (so a revised box can land
    /// again). Any other state is `WrongState`.
    pub fn finish(&self, id: &str) -> Result<(), BoxError> {
        let bid = BoxId::parse(id).map_err(|_| BoxError::NotFound)?;
        let mut s = self.lock();
        let (state, repo, lands) = {
            let b = s.find(&bid)?;
            (b.state, b.repo.clone(), b.lands)
        };
        if state != BoxState::Running {
            return Err(BoxError::WrongState { state });
        }
        s.set_state(&bid, BoxState::Done)?;
        let unified = format!(
            "diff --git a/notes.txt b/notes.txt\n--- a/notes.txt\n+++ b/notes.txt\n@@ -0,0 +1 @@\n+revision {}\n",
            lands + 1
        );
        let diff = DiffSummary {
            id: bid.clone(),
            base_commit: format!("{:040x}", lands + 1),
            diff_sha256: hex(&Sha256::digest(unified.as_bytes())),
            files: vec![FileChange {
                path: "notes.txt".into(),
                status: FileStatus::Modified,
                added: 1,
                removed: 0,
                binary: false,
            }],
            unified,
            truncated: false,
            tests: None,
        };
        s.push_land(bid.clone(), &repo, &diff);
        s.diffs.insert(bid, diff);
        Ok(())
    }

    /// Time used for `updated_at` and new boxes from now on.
    pub fn set_now(&self, now: u64) {
        self.lock().now = now;
    }

    /// Replace the terminal frames of a box (frames should have increasing seq).
    pub fn with_terminal(self, id: &str, frames: Vec<TermFrame>) -> FakeBoxSource {
        let bid = BoxId::parse(id).expect("fake box id");
        self.lock().terminals.insert(bid, frames);
        self
    }
}

impl BoxSource for FakeBoxSource {
    fn overview(&self) -> Overview {
        let s = self.lock();
        let mut boxes = s.boxes.clone();
        boxes.sort_by(|a, b| {
            let key = |x: &BoxInfo| {
                (
                    rank(x.state),
                    if x.state == BoxState::Queued {
                        x.queue_pos.unwrap_or(u32::MAX)
                    } else {
                        0
                    },
                    x.id.clone(),
                )
            };
            key(a).cmp(&key(b))
        });
        Overview {
            boxes,
            load: s.load.clone(),
            slots_total: SLOTS_TOTAL,
            slots_free: s.free_slots(),
        }
    }

    fn list(&self) -> Vec<BoxInfo> {
        self.lock().boxes.clone()
    }

    fn terminal(&self, i: &BoxId, after: Option<u64>) -> Result<TermBatch, BoxError> {
        let mut s = self.lock();
        let state = s.find(i)?.state;
        let frames: Vec<TermFrame> = s
            .terminals
            .get(i)
            .map(|v| {
                v.iter()
                    .filter(|f| after.is_none_or(|a| seq_of(f) > a))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let next = frames
            .iter()
            .map(seq_of)
            .max()
            .unwrap_or_else(|| after.unwrap_or(0));
        Ok(TermBatch {
            frames,
            next,
            ended: matches!(
                state,
                BoxState::Done | BoxState::Landed | BoxState::Discarded
            ),
        })
    }

    fn diff(&self, i: &BoxId) -> Result<DiffSummary, BoxError> {
        let mut s = self.lock();
        s.find(i)?;
        match s.diffs.get(i) {
            Some(d) => Ok(DiffSummary {
                id: i.clone(),
                ..d.clone()
            }),
            None => Ok(DiffSummary {
                id: i.clone(),
                base_commit: "0".repeat(40),
                diff_sha256: hex(&Sha256::digest(b"")),
                files: Vec::new(),
                unified: String::new(),
                truncated: false,
                tests: None,
            }),
        }
    }

    fn stop(&self, i: &BoxId) -> Result<(), BoxError> {
        let mut s = self.lock();
        s.calls.push(FakeCall::Stop(i.clone()));
        match s.find(i)?.state {
            BoxState::Starting | BoxState::Running | BoxState::Paused => {
                s.set_state(i, BoxState::Done)
            }
            BoxState::Done | BoxState::Landed | BoxState::Discarded => Ok(()),
            state @ BoxState::Queued => Err(BoxError::WrongState { state }),
        }
    }

    fn pause(&self, i: &BoxId) -> Result<(), BoxError> {
        let mut s = self.lock();
        s.calls.push(FakeCall::Pause(i.clone()));
        match s.find(i)?.state {
            BoxState::Running => s.set_state(i, BoxState::Paused),
            state => Err(BoxError::WrongState { state }),
        }
    }

    fn resume(&self, i: &BoxId) -> Result<(), BoxError> {
        let mut s = self.lock();
        s.calls.push(FakeCall::Resume(i.clone()));
        match s.find(i)?.state {
            BoxState::Paused => s.set_state(i, BoxState::Running),
            state => Err(BoxError::WrongState { state }),
        }
    }

    fn discard(&self, i: &BoxId) -> Result<(), BoxError> {
        let mut s = self.lock();
        s.calls.push(FakeCall::Discard(i.clone()));
        match s.find(i)?.state {
            BoxState::Queued | BoxState::Done | BoxState::Landed => {
                s.set_state(i, BoxState::Discarded)?;
                s.renumber();
                Ok(())
            }
            state => Err(BoxError::WrongState { state }),
        }
    }

    fn reorder(&self, queue: &[BoxId]) -> Result<(), BoxError> {
        let mut s = self.lock();
        s.calls.push(FakeCall::Reorder(queue.to_vec()));
        let mut want: Vec<&BoxId> = queue.iter().collect();
        want.sort();
        let mut have: Vec<&BoxId> = s
            .boxes
            .iter()
            .filter(|b| b.state == BoxState::Queued)
            .map(|b| &b.id)
            .collect();
        have.sort();
        if want != have {
            return Err(BoxError::Invalid(
                "reorder must list exactly the queued boxes".into(),
            ));
        }
        for (n, qid) in queue.iter().enumerate() {
            s.find(qid)?.queue_pos = Some(n as u32 + 1);
        }
        Ok(())
    }

    fn steer(&self, i: &BoxId, msg: &str) -> Result<(), BoxError> {
        let mut s = self.lock();
        s.calls.push(FakeCall::Steer(i.clone(), msg.to_string()));
        let state = s.find(i)?.state;
        if !matches!(state, BoxState::Running | BoxState::Paused) {
            return Err(BoxError::WrongState { state });
        }
        check_text(msg, MAX_STEER_BYTES)
    }

    fn revise(&self, i: &BoxId, comment: &str) -> Result<(), BoxError> {
        let mut s = self.lock();
        s.calls
            .push(FakeCall::Revise(i.clone(), comment.to_string()));
        let state = s.find(i)?.state;
        if !matches!(state, BoxState::Done | BoxState::Landed) {
            return Err(BoxError::WrongState { state });
        }
        check_text(comment, MAX_STEER_BYTES)?;
        s.set_state(i, BoxState::Running)
    }

    fn pending_actions(&self) -> Vec<PendingAction> {
        self.lock().pending.clone()
    }

    fn complete(
        &self,
        request_id: u64,
        decision: Decision,
        evidence: Option<TouchEvidence>,
    ) -> Result<(), BoxError> {
        let mut s = self.lock();
        s.calls
            .push(FakeCall::Complete(request_id, decision, evidence.is_some()));
        let pos = s
            .pending
            .iter()
            .position(|p| p.request_id == request_id)
            .ok_or(BoxError::NotFound)?;
        match (decision, evidence.is_some()) {
            (Decision::Approve, false) => {
                return Err(BoxError::Invalid("approve needs evidence".into()))
            }
            (Decision::Reject, true) => {
                return Err(BoxError::Invalid("reject takes no evidence".into()))
            }
            _ => {}
        }
        let p = s.pending.remove(pos);
        if decision == Decision::Approve && p.class == TouchClass::Land {
            if let Some(bid) = p.box_id {
                let state = s.find(&bid)?.state;
                if state != BoxState::Done {
                    return Err(BoxError::WrongState { state });
                }
                s.set_state(&bid, BoxState::Landed)?;
                s.find(&bid)?.lands += 1;
            }
        }
        Ok(())
    }

    fn templates(&self) -> Vec<Template> {
        self.lock().templates.clone()
    }

    fn spawn(&self, req: &SpawnReq) -> Result<BoxId, BoxError> {
        let mut s = self.lock();
        s.calls.push(FakeCall::Spawn(req.clone()));
        if !s.templates.iter().any(|t| t.name == req.template) {
            return Err(BoxError::Invalid("unknown template".into()));
        }
        check_text(&req.task, MAX_TASK_BYTES)?;
        s.next_box += 1;
        let new = id(&format!("b-{}", s.next_box));
        let state = if req.start == Start::Now && s.free_slots() > 0 {
            BoxState::Running
        } else {
            BoxState::Queued
        };
        s.add_box(new.clone(), state, &req.template, &req.repo, &req.task);
        Ok(new)
    }
}
