//! One audit record per guard decision (spec §6.2).

use serde::{Deserialize, Serialize};
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime};

use crate::mask::mask;

/// Schema version written into every record's `v` field.
pub const RECORD_VERSION: u32 = 1;

/// Longest `input` kept in a record, in characters. Longer inputs are cut on
/// a character boundary and marked, so one huge command cannot bloat the log.
pub const MAX_INPUT_CHARS: usize = 4096;

const TRUNCATED_MARK: &str = "…[truncated]";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    Allow,
    Deny,
    /// The guard failed open (crash, unusable payload, budget exceeded): the
    /// action was allowed without being judged.
    ErrorAllowed,
    /// A decision value this version does not know (e.g. v2's `error_denied`,
    /// spec §6.2). Readers keep the record instead of dropping it.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub v: u32,
    /// UTC, `YYYY-MM-DDTHH:MM:SS.mmmZ`.
    pub ts: String,
    pub agent: String,
    pub project: String,
    #[serde(default)]
    pub session: Option<String>,
    pub tool: String,
    /// The command (shell tools) or path (read tools), masked and truncated.
    pub input: String,
    pub decision: DecisionKind,
    #[serde(default)]
    pub pack: Option<String>,
    #[serde(default)]
    pub rule: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    /// Version of the saiife binary that wrote the record.
    pub saiife: String,
}

/// The caller-supplied part of a record. `Record::new` adds the timestamp,
/// version, masking and truncation so no caller can forget them.
///
/// `input` and `reason` are masked (a reason can quote a path with a
/// token-shaped segment). `rule` and `project` are written as given and must
/// never contain command text.
#[derive(Debug, Clone, Copy)]
pub struct NewRecord<'a> {
    pub agent: &'a str,
    pub project: &'a str,
    pub session: Option<&'a str>,
    pub tool: &'a str,
    pub input: &'a str,
    pub decision: DecisionKind,
    pub pack: Option<&'a str>,
    pub rule: Option<&'a str>,
    pub reason: Option<&'a str>,
}

const TS_FORMAT: &[time::format_description::FormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z");

impl Record {
    pub fn new(r: NewRecord<'_>, saiife_version: &str) -> Self {
        Self::at(r, saiife_version, OffsetDateTime::now_utc())
    }

    pub fn at(r: NewRecord<'_>, saiife_version: &str, now: OffsetDateTime) -> Self {
        let utc = now.to_offset(time::UtcOffset::UTC);
        Self {
            v: RECORD_VERSION,
            ts: utc.format(TS_FORMAT).expect("UTC timestamp formats"),
            agent: r.agent.to_string(),
            project: r.project.to_string(),
            session: r.session.map(str::to_string),
            tool: r.tool.to_string(),
            input: truncate(&mask(r.input)),
            decision: r.decision,
            pack: r.pack.map(str::to_string),
            rule: r.rule.map(str::to_string),
            reason: r.reason.map(mask),
            saiife: saiife_version.to_string(),
        }
    }

    /// `YYYY-MM` of `ts`, used to pick the monthly file.
    pub fn month(&self) -> &str {
        self.ts.get(..7).unwrap_or("unknown")
    }

    /// `ts` parsed back to a UTC time; `None` if the record was hand-edited
    /// into something unparseable.
    pub fn timestamp(&self) -> Option<OffsetDateTime> {
        PrimitiveDateTime::parse(&self.ts, TS_FORMAT)
            .ok()
            .map(PrimitiveDateTime::assume_utc)
    }
}

fn truncate(s: &str) -> String {
    match s.char_indices().nth(MAX_INPUT_CHARS) {
        None => s.to_string(),
        Some((cut, _)) => format!("{}{TRUNCATED_MARK}", &s[..cut]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn base<'a>(input: &'a str) -> NewRecord<'a> {
        NewRecord {
            agent: "claude",
            project: "/home/u/app",
            session: Some("s1"),
            tool: "Bash",
            input,
            decision: DecisionKind::Deny,
            pack: Some("core.filesystem"),
            rule: Some("^rm"),
            reason: Some("deletes the filesystem root"),
        }
    }

    #[test]
    fn timestamp_format_and_month() {
        let r = Record::at(
            base("rm -rf /"),
            "0.1.0",
            datetime!(2026-10-13 08:14:02.381 UTC),
        );
        assert_eq!(r.ts, "2026-10-13T08:14:02.381Z");
        assert_eq!(r.month(), "2026-10");
        assert_eq!(r.timestamp(), Some(datetime!(2026-10-13 08:14:02.381 UTC)));
        assert_eq!(r.v, RECORD_VERSION);
        assert_eq!(r.saiife, "0.1.0");
    }

    #[test]
    fn serializes_decision_snake_case() {
        let mut nr = base("x");
        nr.decision = DecisionKind::ErrorAllowed;
        let json = serde_json::to_string(&Record::new(nr, "0.1.0")).unwrap();
        assert!(json.contains(r#""decision":"error_allowed""#), "{json}");
    }

    #[test]
    fn input_is_masked() {
        let tok = format!("ghp_{}", "a".repeat(36));
        let r = Record::new(base(&format!("echo {tok}")), "0.1.0");
        assert_eq!(r.input, "echo [MASKED]");
    }

    #[test]
    fn unjudgeable_reason_is_masked() {
        let tok = format!("ghp_{}", "a".repeat(36));
        let mut nr = base("x");
        let reason = format!("cannot judge /home/u/{tok}/f");
        nr.reason = Some(&reason);
        let r = Record::new(nr, "0.1.0");
        let got = r.reason.unwrap();
        assert!(!got.contains(&tok), "{got}");
        assert!(got.contains("[MASKED]"), "{got}");
    }

    #[test]
    fn ordinary_path_in_reason_stays_unmasked() {
        let mut nr = base("x");
        let reason = "cannot resolve /home/u/project/src/main.rs";
        nr.reason = Some(reason);
        let r = Record::new(nr, "0.1.0");
        assert_eq!(r.reason.as_deref(), Some(reason));
    }

    #[test]
    fn long_input_is_truncated_on_char_boundary() {
        let input = "a".repeat(MAX_INPUT_CHARS + 10);
        let r = Record::new(base(&input), "0.1.0");
        assert_eq!(
            r.input.chars().count(),
            MAX_INPUT_CHARS + TRUNCATED_MARK.chars().count()
        );
        assert!(r.input.ends_with(TRUNCATED_MARK));
    }

    #[test]
    fn multibyte_input_truncates_without_panic() {
        let input = "é".repeat(MAX_INPUT_CHARS * 2);
        let r = Record::new(base(&input), "0.1.0");
        assert!(r.input.starts_with("éé"));
        assert!(r.input.ends_with(TRUNCATED_MARK));
    }

    #[test]
    fn deserializes_record_without_optional_fields() {
        let line = r#"{"v":1,"ts":"2026-10-13T08:14:02.381Z","agent":"codex","project":"/p","tool":"shell","input":"ls","decision":"allow","saiife":"0.1.0"}"#;
        let r: Record = serde_json::from_str(line).unwrap();
        assert_eq!(r.decision, DecisionKind::Allow);
        assert_eq!(r.session, None);
        assert_eq!(r.pack, None);
    }

    #[test]
    fn unknown_decision_value_is_tolerated() {
        let line = r#"{"v":1,"ts":"2026-10-13T08:14:02.381Z","agent":"codex","project":"/p","tool":"shell","input":"ls","decision":"error_denied","saiife":"2.0.0"}"#;
        let r: Record = serde_json::from_str(line).unwrap();
        assert_eq!(r.decision, DecisionKind::Unknown);
    }

    #[test]
    fn unparseable_ts_gives_none() {
        let mut r = Record::new(base("x"), "0.1.0");
        r.ts = "yesterday".into();
        assert_eq!(r.timestamp(), None);
    }
}
