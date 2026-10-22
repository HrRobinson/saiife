//! Lock labels: can a managed saiife hook lock this agent? The label comes
//! from the live lock checks (docs/lock-check.md), recorded as fixtures in
//! `tests/fixtures/lock-check/<agent>.tsv`. An agent without a recording is
//! `Unverified` (plan 7 gate rule, spec §0 decision 9).

use crate::Agent;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LockLabel {
    /// Every gate held.
    Lockable,
    /// Gates held; some hook failures let the call run.
    LockableWithGaps,
    /// Gates held; a known bypass worked.
    LockableWithCaveats,
    /// A gate failed.
    NotLockable,
    /// No recording, or a gate or the control was inconclusive.
    Unverified,
}

impl LockLabel {
    pub const ALL: [LockLabel; 5] = [
        LockLabel::Lockable,
        LockLabel::LockableWithGaps,
        LockLabel::LockableWithCaveats,
        LockLabel::NotLockable,
        LockLabel::Unverified,
    ];

    /// The id in a recording's `# label=` line.
    pub fn id(self) -> &'static str {
        match self {
            LockLabel::Lockable => "lockable",
            LockLabel::LockableWithGaps => "lockable-with-gaps",
            LockLabel::LockableWithCaveats => "lockable-with-caveats",
            LockLabel::NotLockable => "not-lockable",
            LockLabel::Unverified => "unverified",
        }
    }

    /// How `doctor` and `status` say it.
    pub fn wording(self) -> &'static str {
        match self {
            LockLabel::Lockable => "lockable",
            LockLabel::LockableWithGaps => "lockable, fail-open gaps listed",
            LockLabel::LockableWithCaveats => "lockable with caveats",
            LockLabel::NotLockable => "not lockable",
            LockLabel::Unverified => "unverified",
        }
    }
}

/// The recorded label of each agent. `tests/lock_check_fixtures.rs` fails
/// when this and the recordings disagree.
pub fn label(agent: Agent) -> LockLabel {
    match agent {
        // Plan 7 recording, claude.tsv.
        Agent::Claude => LockLabel::Lockable,
        // No recording yet.
        Agent::Codex | Agent::Gemini => LockLabel::Unverified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wording column of the label table in docs/lock-check.md.
    #[test]
    fn wording_matches_lock_check_doc() {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/lock-check.md");
        let doc = std::fs::read_to_string(&p).unwrap();
        for l in LockLabel::ALL {
            let row = format!("| `{}` | {} |", l.id(), l.wording());
            assert!(doc.contains(&row), "docs/lock-check.md has no row {row}");
        }
    }

    #[test]
    fn ids_are_distinct() {
        let ids: std::collections::BTreeSet<_> = LockLabel::ALL.iter().map(|l| l.id()).collect();
        assert_eq!(ids.len(), LockLabel::ALL.len());
    }
}
