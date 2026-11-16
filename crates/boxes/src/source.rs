//! The box source implementation: `saiife_wire::BoxSource` over the box
//! [`Manager`], the seam the Workspace uses (B9).
//!
//! Owner scope: with `owner = Some(u)` the source sees only boxes whose
//! `owner_uid` is `u`; another user's id behaves exactly like a missing one
//! (`NotFound`). With `owner = None` (locked mode) it sees every box, but
//! cannot spawn.
//!
//! Lands (plan 39): with a [`LandBook`] ([`ManagerSource::with_lands`]),
//! `diff`, `pending_actions` and `complete` go to the book, and `discard`
//! refuses a box with an approved land that is not applied yet (L4). An
//! owner-scoped source shows only the records of that owner's boxes, and
//! a request of another owner's box is `NotFound`.

use std::sync::Arc;

use saiife_touch::TouchEvidence;
use saiife_wire::source::{
    BoxError, BoxId, BoxInfo, BoxSource, BoxState, Decision, DiffSummary, Load, Overview,
    PendingAction, SpawnReq, Start, Template, TermBatch, TermFrame,
};

use crate::capacity;
use crate::manager::{Change, Manager, SpawnArgs};
use crate::store::BoxRecord;

/// Where a [`ManagerSource`] hands the state changes an op made to boxes
/// other than the one it was asked about (the frame layer audits them).
pub type ChangeSink = Arc<dyn Fn(&[Change]) + Send + Sync>;

pub struct ManagerSource {
    mgr: Arc<Manager>,
    owner: Option<u32>,
    sink: Option<ChangeSink>,
    lands: Option<Arc<dyn LandBook>>,
}

/// The daemon's land book (plan 39 Task 4): reviews, land requests and
/// their decisions. Every method may block on the guest or the disk.
pub trait LandBook: Send + Sync {
    /// The box's latest review (`NotFound` for an unknown box).
    fn diff(&self, id: &BoxId) -> Result<DiffSummary, BoxError>;
    /// The land requests the Workspace may decide, all owners' (L8: at
    /// most four per owner); the source filters them by owner.
    fn pending(&self) -> Vec<PendingAction>;
    /// Decide request `request_id` (plan 28's `complete` contract).
    fn complete(
        &self,
        request_id: u64,
        d: Decision,
        ev: Option<TouchEvidence>,
    ) -> Result<(), BoxError>;
    /// Approved lands of the box not applied yet (L4).
    fn unapplied(&self, id: &BoxId) -> u32;
    /// Runs `discard` unless the box has an unapplied land (`force` skips
    /// that check). A book that approves lands overrides it to hold its
    /// per-box lock across the check and the discard, so an approval
    /// cannot slip in between (L4).
    fn discard_with(
        &self,
        id: &BoxId,
        force: bool,
        discard: &mut dyn FnMut() -> Result<(), BoxError>,
    ) -> Result<(), BoxError> {
        if !force && self.unapplied(id) > 0 {
            return Err(unapplied_refusal(id));
        }
        discard()
    }
    /// The box a request is for, `None` for an unknown request: lets an
    /// owner-scoped source refuse another owner's request as `NotFound`.
    fn box_of(&self, request_id: u64) -> Option<BoxId> {
        let _ = request_id;
        None
    }
}

/// [`ManagerSource::discard`]'s refusal while `unapplied(id) > 0` (L4).
pub fn unapplied_refusal(id: &BoxId) -> BoxError {
    let i = id.as_str();
    BoxError::Invalid(format!(
        "box {i} has an approved land that is not applied: saiife box apply {i}, or discard --force"
    ))
}

/// The wire view of a record. `queue_pos` is the caller's choice (see
/// [`ManagerSource::list`] for how the source numbers it).
pub fn info(r: &BoxRecord, queue_pos: Option<u32>) -> BoxInfo {
    BoxInfo {
        id: r.id.clone(),
        state: r.state,
        template: r.template.clone(),
        repo: r.repo.clone(),
        task: r.task.clone(),
        created_at: r.created_at,
        started_at: r.started_at,
        updated_at: r.updated_at,
        queue_pos,
        lands: r.lands,
    }
}

fn frame_seq(f: &TermFrame) -> u64 {
    match f {
        TermFrame::Snapshot { seq, .. } | TermFrame::Delta { seq, .. } => *seq,
    }
}

fn is_over(s: BoxState) -> bool {
    matches!(s, BoxState::Done | BoxState::Landed | BoxState::Discarded)
}

impl ManagerSource {
    pub fn new(mgr: Arc<Manager>, owner: Option<u32>) -> ManagerSource {
        ManagerSource {
            mgr,
            owner,
            sink: None,
            lands: None,
        }
    }

    /// Hand `sink` every change `spawn` makes to a box other than the new
    /// one (queue heads its admission pass moved); the caller's own record
    /// covers the new box.
    pub fn with_changes(mut self, sink: ChangeSink) -> ManagerSource {
        self.sink = Some(sink);
        self
    }

    /// This source with a land book (plan 39): `diff`, `pending_actions`
    /// and `complete` go to it, and `discard` refuses unapplied lands.
    pub fn with_lands(mut self, lands: Arc<dyn LandBook>) -> ManagerSource {
        self.lands = Some(lands);
        self
    }

    /// Whether this source sees box `id` (a missing box is not seen).
    fn sees_id(&self, id: &BoxId) -> bool {
        self.mgr.get(id).is_ok_and(|r| self.sees(&r))
    }

    fn sees(&self, r: &BoxRecord) -> bool {
        self.owner.is_none_or(|u| r.owner_uid == u)
    }

    /// The record, or `NotFound` when it is missing or another user's.
    fn visible(&self, id: &BoxId) -> Result<BoxRecord, BoxError> {
        let r = self.mgr.get(id)?;
        if self.sees(&r) {
            Ok(r)
        } else {
            Err(BoxError::NotFound)
        }
    }

    /// Visible records in the manager's order, with queue positions.
    fn view(&self) -> Vec<BoxInfo> {
        let mut next = 0u32;
        let queued = self.mgr.queue();
        self.mgr
            .list()
            .iter()
            .filter(|r| self.sees(r))
            .map(|r| {
                let pos = if r.state == BoxState::Queued && queued.contains(&r.id) {
                    next += 1;
                    Some(next)
                } else {
                    None
                };
                info(r, pos)
            })
            .collect()
    }
}

impl BoxSource for ManagerSource {
    fn overview(&self) -> Overview {
        let (host, committed) = self.mgr.capacity();
        let (slots_total, slots_free) = capacity::slots(&host, &committed);
        Overview {
            boxes: self.view(),
            load: host.cpu_pct.map(|cpu_pct| Load {
                cpu_pct,
                mem_used_mb: host.mem_total_mib.saturating_sub(host.mem_avail_mib),
                mem_total_mb: host.mem_total_mib,
            }),
            slots_total,
            slots_free,
        }
    }

    /// Queue positions: the manager lists queued boxes head first, so the
    /// visible queued boxes are numbered 1..=k in that order. With an owner
    /// filter this renumbers the owner's boxes, not the whole queue.
    fn list(&self) -> Vec<BoxInfo> {
        self.view()
    }

    fn terminal(&self, id: &BoxId, after: Option<u64>) -> Result<TermBatch, BoxError> {
        let r = self.visible(id)?;
        let ended = is_over(r.state);
        let floor = after.unwrap_or(0);
        match self.mgr.guest().terminal(id, after) {
            Ok(mut b) => {
                b.next = b.frames.iter().map(frame_seq).max().unwrap_or(floor);
                b.ended = ended;
                Ok(b)
            }
            Err(_) if ended => Ok(TermBatch {
                frames: Vec::new(),
                next: floor,
                ended: true,
            }),
            Err(e) => Err(e.into()),
        }
    }

    fn diff(&self, id: &BoxId) -> Result<DiffSummary, BoxError> {
        self.visible(id)?;
        match &self.lands {
            Some(l) => l.diff(id),
            None => self.mgr.guest().diff(id).map_err(BoxError::from),
        }
    }

    fn stop(&self, id: &BoxId) -> Result<(), BoxError> {
        self.visible(id)?;
        self.mgr.stop(id, false).map(|_| ())
    }

    fn pause(&self, id: &BoxId) -> Result<(), BoxError> {
        self.visible(id)?;
        self.mgr.pause(id).map(|_| ())
    }

    fn resume(&self, id: &BoxId) -> Result<(), BoxError> {
        self.visible(id)?;
        self.mgr.resume(id).map(|_| ())
    }

    fn discard(&self, id: &BoxId) -> Result<(), BoxError> {
        self.visible(id)?;
        match &self.lands {
            Some(l) => l.discard_with(id, false, &mut || self.mgr.discard(id).map(|_| ())),
            None => self.mgr.discard(id).map(|_| ()),
        }
    }

    /// With an owner filter `queue` must list exactly that user's queued
    /// boxes. Other users' queued boxes keep their slots; the owner's boxes
    /// are permuted among the slots they already hold.
    fn reorder(&self, queue: &[BoxId]) -> Result<(), BoxError> {
        let Some(u) = self.owner else {
            return self.mgr.reorder(queue);
        };
        let full = self.mgr.queue();
        let mine = |id: &BoxId| self.mgr.get(id).is_ok_and(|r| r.owner_uid == u);
        let slots: Vec<bool> = full.iter().map(&mine).collect();
        let mut want = queue.to_vec();
        want.sort();
        want.dedup();
        let mut have: Vec<BoxId> = full
            .iter()
            .zip(&slots)
            .filter(|(_, m)| **m)
            .map(|(i, _)| i.clone())
            .collect();
        have.sort();
        if want.len() != queue.len() || want != have {
            return Err(BoxError::Invalid(
                "reorder must list every queued box once".into(),
            ));
        }
        let mut it = queue.iter();
        let merged: Vec<BoxId> = full
            .iter()
            .zip(&slots)
            .filter_map(|(id, m)| {
                if *m {
                    it.next().cloned()
                } else {
                    Some(id.clone())
                }
            })
            .collect();
        self.mgr.reorder(&merged)
    }

    fn steer(&self, id: &BoxId, msg: &str) -> Result<(), BoxError> {
        self.visible(id)?;
        self.mgr.say(id, msg)
    }

    fn revise(&self, id: &BoxId, comment: &str) -> Result<(), BoxError> {
        self.revise_noted(id, comment).map(|_| ())
    }

    fn revise_noted(&self, id: &BoxId, comment: &str) -> Result<Option<&'static str>, BoxError> {
        self.visible(id)?;
        self.mgr.revise_noted(id, comment).map(|(_, note)| note)
    }

    /// Without a land book nothing is ever pending.
    fn pending_actions(&self) -> Vec<PendingAction> {
        let Some(l) = &self.lands else {
            return Vec::new();
        };
        l.pending()
            .into_iter()
            .filter(|p| self.owner.is_none() || p.box_id.as_ref().is_some_and(|b| self.sees_id(b)))
            .collect()
    }

    fn complete(
        &self,
        request_id: u64,
        decision: Decision,
        evidence: Option<TouchEvidence>,
    ) -> Result<(), BoxError> {
        let Some(l) = &self.lands else {
            return Err(BoxError::NotFound);
        };
        if self.owner.is_some() {
            if let Some(b) = l.box_of(request_id) {
                if !self.sees_id(&b) {
                    return Err(BoxError::NotFound);
                }
            }
        }
        l.complete(request_id, decision, evidence)
    }

    fn templates(&self) -> Vec<Template> {
        self.mgr.templates().iter().map(|t| t.wire()).collect()
    }

    /// `Start::Now` that finds no room (`Busy`) joins the queue instead, so
    /// the Workspace sees Running-if-free, else Queued.
    fn spawn(&self, req: &SpawnReq) -> Result<BoxId, BoxError> {
        let Some(owner_uid) = self.owner else {
            return Err(BoxError::Unavailable(
                "Workspace spawn in locked mode needs the device owner".into(),
            ));
        };
        let mut args = SpawnArgs {
            template: req.template.clone(),
            repo: req.repo.clone(),
            repo_dir: None,
            task: req.task.clone(),
            start: req.start,
            owner_uid,
            repo_image: None,
            base_manifest: None,
        };
        let (rec, changes) = match self.mgr.spawn_changes(&args) {
            Err(BoxError::Busy) if req.start == Start::Now => {
                args.start = Start::Queue;
                self.mgr.spawn_changes(&args)?
            }
            other => other?,
        };
        if let Some(sink) = &self.sink {
            let others: Vec<Change> = changes.into_iter().filter(|c| c.id != rec.id).collect();
            if !others.is_empty() {
                sink(&others);
            }
        }
        Ok(rec.id)
    }
}
