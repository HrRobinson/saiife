//! A fake guest (feature `fake`): records prompts, serves canned terminal and diff.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, MutexGuard};

use saiife_wire::source::{BoxId, DiffSummary, TermBatch, TermFrame};

use super::{GuestError, GuestLink};

#[derive(Default)]
struct State {
    prompts: Vec<(BoxId, String)>,
    terminals: HashMap<BoxId, Vec<TermFrame>>,
    diffs: HashMap<BoxId, DiffSummary>,
    disconnected: HashSet<BoxId>,
}

#[derive(Default)]
pub struct FakeGuest {
    state: Mutex<State>,
}

fn seq_of(f: &TermFrame) -> u64 {
    match f {
        TermFrame::Snapshot { seq, .. } | TermFrame::Delta { seq, .. } => *seq,
    }
}

impl FakeGuest {
    pub fn new() -> FakeGuest {
        FakeGuest::default()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn prompts(&self) -> Vec<(BoxId, String)> {
        self.lock().prompts.clone()
    }

    pub fn set_terminal(&self, id: &BoxId, frames: Vec<TermFrame>) {
        self.lock().terminals.insert(id.clone(), frames);
    }

    pub fn set_diff(&self, id: &BoxId, d: DiffSummary) {
        self.lock().diffs.insert(id.clone(), d);
    }

    /// Later `prompt`s for this box err `NotConnected`.
    pub fn disconnect(&self, id: &BoxId) {
        self.lock().disconnected.insert(id.clone());
    }
}

impl GuestLink for FakeGuest {
    fn prompt(&self, id: &BoxId, text: &str) -> Result<(), GuestError> {
        let mut s = self.lock();
        if s.disconnected.contains(id) {
            return Err(GuestError::NotConnected);
        }
        s.prompts.push((id.clone(), text.to_string()));
        Ok(())
    }

    /// `ended` stays false: the box state is the manager's business.
    fn terminal(&self, id: &BoxId, after: Option<u64>) -> Result<TermBatch, GuestError> {
        let s = self.lock();
        let frames: Vec<TermFrame> = s
            .terminals
            .get(id)
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
            ended: false,
        })
    }

    fn diff(&self, id: &BoxId) -> Result<DiffSummary, GuestError> {
        self.lock()
            .diffs
            .get(id)
            .cloned()
            .ok_or_else(|| GuestError::Unavailable("no diff for this box".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest::{GuestError, GuestLink, NoGuest};
    use saiife_wire::source::{BoxError, BoxId, DiffSummary, TermFrame};

    fn id(s: &str) -> BoxId {
        BoxId::parse(s).unwrap()
    }

    fn delta(seq: u64) -> TermFrame {
        TermFrame::Delta {
            seq,
            lines: vec![(0, format!("l{seq}"))],
            cursor: (0, 0),
        }
    }

    #[test]
    fn no_guest_is_unavailable() {
        let g = NoGuest;
        let b = id("b1");
        let msg = "the guest channel is not built yet".to_string();
        assert_eq!(g.prompt(&b, "x"), Err(GuestError::Unavailable(msg.clone())));
        assert_eq!(
            g.terminal(&b, None).unwrap_err(),
            GuestError::Unavailable(msg.clone())
        );
        assert_eq!(
            g.diff(&b).unwrap_err(),
            GuestError::Unavailable(msg.clone())
        );
        assert_eq!(
            BoxError::from(GuestError::Unavailable(msg.clone())),
            BoxError::Unavailable(msg)
        );
        assert_eq!(
            BoxError::from(GuestError::NotConnected),
            BoxError::Unavailable("the box is not connected".into())
        );
    }

    #[test]
    fn fake_guest_records_prompts() {
        let g = FakeGuest::new();
        g.prompt(&id("b1"), "hello").unwrap();
        g.prompt(&id("b2"), "world").unwrap();
        assert_eq!(
            g.prompts(),
            vec![
                (id("b1"), "hello".to_string()),
                (id("b2"), "world".to_string())
            ]
        );
    }

    #[test]
    fn fake_guest_disconnect() {
        let g = FakeGuest::new();
        g.disconnect(&id("b1"));
        assert_eq!(g.prompt(&id("b1"), "x"), Err(GuestError::NotConnected));
        assert!(g.prompts().is_empty());
        g.prompt(&id("b2"), "x").unwrap();
    }

    #[test]
    fn fake_guest_terminal_pages_by_seq() {
        let g = FakeGuest::new();
        let b = id("b1");
        let empty = g.terminal(&b, None).unwrap();
        assert!(empty.frames.is_empty());
        assert_eq!(empty.next, 0);
        assert!(!empty.ended);
        g.set_terminal(&b, vec![delta(1), delta(2), delta(3)]);
        let all = g.terminal(&b, None).unwrap();
        assert_eq!(all.frames.len(), 3);
        assert_eq!(all.next, 3);
        let rest = g.terminal(&b, Some(1)).unwrap();
        assert_eq!(rest.frames, vec![delta(2), delta(3)]);
        assert_eq!(rest.next, 3);
        let none = g.terminal(&b, Some(3)).unwrap();
        assert!(none.frames.is_empty());
        assert_eq!(none.next, 3);
        assert!(!none.ended);
    }

    #[test]
    fn fake_guest_diff() {
        let g = FakeGuest::new();
        let b = id("b1");
        assert!(matches!(g.diff(&b), Err(GuestError::Unavailable(_))));
        let d = DiffSummary {
            id: b.clone(),
            base_commit: "abc".into(),
            diff_sha256: "0".repeat(64),
            files: vec![],
            unified: String::new(),
            truncated: false,
            tests: None,
        };
        g.set_diff(&b, d.clone());
        assert_eq!(g.diff(&b).unwrap(), d);
    }
}
