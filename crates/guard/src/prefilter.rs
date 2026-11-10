//! Fast literal pre-filter.
//!
//! The hot path: the vast majority of commands contain no token any loaded
//! pack cares about, so we reject them with a cheap substring scan before any
//! regex runs. A pack declares literal `triggers`; a command that contains none
//! of a pack's triggers skips that pack's regexes entirely.
//!
//! The triggers are compiled into one literal-alternation regex (an
//! Aho-Corasick scan), so the cost of the check stays flat as packs add
//! triggers, instead of one substring search per trigger.

use regex::Regex;

/// A trigger that starts with this ignores case (`(?i)format-volume`): Windows
/// commands are case-insensitive, and the readers pass an unknown command's
/// name as it was written.
const NOCASE: &str = "(?i)";

/// A set of literal trigger substrings. Built per pack (and, for the engine's
/// combined gate, from the union of all packs' triggers).
#[derive(Debug, Clone, Default)]
pub struct Prefilter {
    triggers: Vec<String>,
    /// All triggers as one regex, compiled on the first `might_match` (a
    /// pack's own pre-filter is asked only once the engine's combined one
    /// matched); clones share it. `None` if empty (or, never in practice,
    /// too large to compile — then each trigger is searched on its own).
    set: std::sync::Arc<std::sync::OnceLock<Option<Regex>>>,
}

impl Prefilter {
    /// Build a pre-filter from literal trigger substrings. An empty set means
    /// "always matches" (the pack opts out of pre-filtering, at a cost).
    pub fn new<I, S>(triggers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let triggers: Vec<String> = triggers.into_iter().map(Into::into).collect();
        Self {
            triggers,
            set: Default::default(),
        }
    }

    /// The triggers as one regex. Its compile time is not the engine's
    /// (`pack::budget_elapsed`).
    fn set(&self) -> Option<&Regex> {
        self.set
            .get_or_init(|| {
                if self.triggers.is_empty() {
                    return None;
                }
                let began = std::time::Instant::now();
                let alts: Vec<String> = self
                    .triggers
                    .iter()
                    .map(|t| match t.strip_prefix(NOCASE) {
                        Some(rest) => format!("(?i:{})", regex::escape(rest)),
                        None => regex::escape(t),
                    })
                    .collect();
                let set = Regex::new(&alts.join("|")).ok();
                crate::pack::note_compile(began, began.elapsed());
                set
            })
            .as_ref()
    }

    /// True if `normalized` might match — i.e. it contains at least one trigger,
    /// or the trigger set is empty (opt-out).
    pub fn might_match(&self, normalized: &str) -> bool {
        if self.triggers.is_empty() {
            return true;
        }
        match self.set() {
            Some(set) => set.is_match(normalized),
            None => self.triggers.iter().any(|t| match t.strip_prefix(NOCASE) {
                Some(rest) => normalized
                    .to_lowercase()
                    .contains(rest.to_lowercase().as_str()),
                None => normalized.contains(t.as_str()),
            }),
        }
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
    fn nocase_triggers_ignore_case_and_the_rest_stay_exact() {
        let pf = Prefilter::new(["(?i)format-volume", "PATH="]);
        assert!(pf.might_match("Format-Volume -DriveLetter C"));
        assert!(pf.might_match("FORMAT-VOLUME"));
        assert!(pf.might_match("PATH=x"));
        assert!(!pf.might_match("path=x"));
        assert!(!pf.might_match("format volume"));
    }

    #[test]
    fn triggers_are_literals_not_regex() {
        let pf = Prefilter::new(["a.b", "/dev/", "PATH="]);
        assert!(pf.might_match("x a.b y"));
        assert!(!pf.might_match("x aXb y"));
        assert!(pf.might_match("> /dev/sda"));
        assert!(pf.might_match("env PATH=/x"));
    }

    #[test]
    fn empty_triggers_always_match() {
        let pf = Prefilter::new(Vec::<String>::new());
        assert!(pf.might_match("anything at all"));
    }
}
