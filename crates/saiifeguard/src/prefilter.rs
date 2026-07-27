//! Fast literal pre-filter.
//!
//! The hot path: the vast majority of commands contain no token any loaded
//! pack cares about, so we reject them with a cheap substring scan before any
//! regex runs. A pack declares literal `triggers`; a command that contains none
//! of a pack's triggers skips that pack's regexes entirely.

/// A set of literal trigger substrings. Built per pack (and, for the engine's
/// combined gate, from the union of all packs' triggers).
#[derive(Debug, Clone, Default)]
pub struct Prefilter {
    triggers: Vec<String>,
}

impl Prefilter {
    /// Build a pre-filter from literal trigger substrings. An empty set means
    /// "always matches" (the pack opts out of pre-filtering, at a cost).
    pub fn new<I, S>(triggers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            triggers: triggers.into_iter().map(Into::into).collect(),
        }
    }

    /// True if `normalized` might match — i.e. it contains at least one trigger,
    /// or the trigger set is empty (opt-out).
    pub fn might_match(&self, normalized: &str) -> bool {
        if self.triggers.is_empty() {
            return true;
        }
        self.triggers
            .iter()
            .any(|t| normalized.contains(t.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_when_a_trigger_is_present() {
        let pf = Prefilter::new(["git", "rm"]);
        assert!(pf.might_match("git status"));
        assert!(pf.might_match("rm -rf /"));
    }

    #[test]
    fn rejects_when_no_trigger_present() {
        let pf = Prefilter::new(["git", "rm"]);
        assert!(!pf.might_match("ls -la"));
    }

    #[test]
    fn empty_triggers_always_match() {
        let pf = Prefilter::new(Vec::<String>::new());
        assert!(pf.might_match("anything at all"));
    }
}
