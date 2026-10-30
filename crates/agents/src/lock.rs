//! Lock labels: can a managed saiife hook lock this agent? The label comes
//! from the live lock checks (docs/lock-check.md), recorded as fixtures in
//! `tests/fixtures/lock-check/<agent>.tsv` (Linux) and
//! `tests/fixtures/lock-check/macos/<agent>.tsv` (macOS). Labels are per
//! platform (plan 13 decision 12): an agent without a recording for the
//! platform is `Unverified` (plan 7 gate rule, spec §0 decision 9).

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

    /// The managed hook holds the agent (lockable, with gaps or with
    /// caveats): its project hook may go quiet.
    pub fn holds(self) -> bool {
        matches!(
            self,
            LockLabel::Lockable | LockLabel::LockableWithGaps | LockLabel::LockableWithCaveats
        )
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

/// The recorded label of each agent on this platform.
pub fn label(agent: Agent) -> LockLabel {
    label_for(agent, cfg!(target_os = "macos"))
}

/// The recorded label of each agent on Linux (`macos` false) or macOS.
/// `tests/lock_check_fixtures.rs` fails when this and the recordings
/// disagree.
pub fn label_for(agent: Agent, macos: bool) -> LockLabel {
    if macos {
        // No macOS recording yet (tests/fixtures/lock-check/macos/).
        return LockLabel::Unverified;
    }
    match agent {
        // Plan 7 recording, claude.tsv.
        Agent::Claude => LockLabel::Lockable,
        // No recording yet.
        Agent::Codex | Agent::Gemini => LockLabel::Unverified,
    }
}

/// Whether the managed hook installed.toml lists for `agent` (with the
/// fingerprint `sha256`) replaces its project hook (spec §6.1.1): install
/// finished writing it (a fingerprint on record) and the agent's lock
/// holds. Otherwise the project hook keeps judging, and `status` says so.
pub fn replaces_project_hook(agent: &str, sha256: &str) -> bool {
    !sha256.is_empty() && Agent::from_name(agent).is_some_and(|a| label(a).holds())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_written_holding_managed_hook_replaces_the_project_hook() {
        // Claude Code holds on Linux; on macOS it is unverified for now.
        assert!(label_for(Agent::Claude, false).holds());
        assert_eq!(
            replaces_project_hook("claude", "ab"),
            label(Agent::Claude).holds()
        );
        assert!(!replaces_project_hook("claude", ""));
        assert!(!replaces_project_hook("codex", "ab"));
        assert!(!replaces_project_hook("gemini", "ab"));
        assert!(!replaces_project_hook("other", "ab"));
        let holding: Vec<_> = LockLabel::ALL.into_iter().filter(|l| l.holds()).collect();
        assert_eq!(
            holding,
            [
                LockLabel::Lockable,
                LockLabel::LockableWithGaps,
                LockLabel::LockableWithCaveats
            ]
        );
    }

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

    /// Every macOS label is `unverified` until the owner records
    /// `tests/fixtures/lock-check/macos/<agent>.tsv` in a macOS VM.
    #[test]
    fn macos_labels_unverified_without_recordings() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/lock-check/macos");
        assert!(dir.is_dir(), "{} is missing", dir.display());
        for a in Agent::ALL {
            if !dir.join(format!("{}.tsv", a.name())).exists() {
                assert_eq!(label_for(a, true), LockLabel::Unverified, "{}", a.name());
            }
        }
        if cfg!(target_os = "macos") {
            for a in Agent::ALL {
                assert_eq!(label(a), label_for(a, true), "{}", a.name());
            }
        }
    }

    #[test]
    fn ids_are_distinct() {
        let ids: std::collections::BTreeSet<_> = LockLabel::ALL.iter().map(|l| l.id()).collect();
        assert_eq!(ids.len(), LockLabel::ALL.len());
    }
}
