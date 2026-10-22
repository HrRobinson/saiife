//! One audit record per guard decision (spec §6.2).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime};

use crate::mask::mask;

/// Schema version written into every record's `v` field.
pub const RECORD_VERSION: u32 = 2;

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
    /// The guard failed closed: the action was denied without being judged.
    ErrorDenied,
    /// The guard asked the user to decide.
    Ask,
    Approved,
    Rejected,
    Expired,
    /// A decision value this version does not know. Readers keep the record
    /// instead of dropping it.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub v: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    /// UTC, `YYYY-MM-DDTHH:MM:SS.mmmZ`.
    pub ts: String,
    /// `guard` when absent; bookkeeping kinds are `genesis`, `checkpoint`
    /// and `key_rotate`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_mode: Option<String>,
    /// Version of the saiife binary that wrote the record.
    pub saiife: String,
    /// Fields this version does not know (`chain`, `key`, future ones),
    /// kept so a re-serialized record loses nothing.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
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
    pub mode: &'a str,
    pub policy: Option<&'a str>,
    pub permission_mode: Option<&'a str>,
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
            seq: None,
            prev: None,
            ts: utc.format(TS_FORMAT).expect("UTC timestamp formats"),
            kind: Some("guard".to_string()),
            host: None,
            uid: None,
            user: None,
            mode: Some(r.mode.to_string()),
            policy: r.policy.map(str::to_string),
            agent: r.agent.to_string(),
            project: r.project.to_string(),
            session: r.session.map(str::to_string),
            tool: r.tool.to_string(),
            input: truncate(&mask(r.input)),
            decision: r.decision,
            pack: r.pack.map(str::to_string),
            rule: r.rule.map(str::to_string),
            reason: r.reason.map(mask),
            permission_mode: r
                .permission_mode
                .map(|m| mask(m).chars().take(64).collect()),
            saiife: saiife_version.to_string(),
            extra: BTreeMap::new(),
        }
    }

    /// The record kind; `guard` when the field is absent (v1 lines).
    pub fn kind(&self) -> &str {
        self.kind.as_deref().unwrap_or("guard")
    }

    /// Chain bookkeeping (not a guard decision): hidden from listings and counts.
    pub fn is_bookkeeping(&self) -> bool {
        matches!(self.kind(), "genesis" | "checkpoint" | "key_rotate")
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
            mode: "developer",
            policy: None,
            permission_mode: None,
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
        let line = r#"{"v":1,"ts":"2026-10-13T08:14:02.381Z","agent":"codex","project":"/p","tool":"shell","input":"ls","decision":"later","saiife":"2.0.0"}"#;
        let r: Record = serde_json::from_str(line).unwrap();
        assert_eq!(r.decision, DecisionKind::Unknown);
    }

    #[test]
    fn unparseable_ts_gives_none() {
        let mut r = Record::new(base("x"), "0.1.0");
        r.ts = "yesterday".into();
        assert_eq!(r.timestamp(), None);
    }

    #[test]
    fn v2_guard_record_field_order() {
        let r = Record::at(base("ls"), "0.1.0", datetime!(2026-10-13 08:14:02.381 UTC));
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.starts_with(r#"{"v":2,"ts":"#), "{json}");
        assert!(
            json.contains(r#""kind":"guard","mode":"developer""#),
            "{json}"
        );
        assert!(!json.contains(r#""seq""#), "{json}");
        assert!(json.contains(r#""session":"s1""#), "{json}");
    }

    #[test]
    fn v1_optionals_still_serialize_as_null() {
        let mut nr = base("ls");
        nr.session = None;
        nr.pack = None;
        let json = serde_json::to_string(&Record::new(nr, "0.1.0")).unwrap();
        assert!(json.contains(r#""session":null"#), "{json}");
        assert!(json.contains(r#""pack":null"#), "{json}");
    }

    #[test]
    fn permission_mode_is_masked_and_cut() {
        let tok = format!("ghp_{}", "a".repeat(36));
        let mut nr = base("x");
        let long = "p".repeat(100);
        nr.permission_mode = Some(&long);
        let r = Record::new(nr, "0.1.0");
        assert_eq!(r.permission_mode.unwrap().chars().count(), 64);
        let mut nr = base("x");
        nr.permission_mode = Some(&tok);
        let r = Record::new(nr, "0.1.0");
        assert_eq!(r.permission_mode.as_deref(), Some("[MASKED]"));
    }

    #[test]
    fn v1_line_still_parses() {
        let line = r#"{"v":1,"ts":"2026-10-13T08:14:02.381Z","agent":"codex","project":"/p","tool":"shell","input":"ls","decision":"allow","saiife":"0.1.0"}"#;
        let r: Record = serde_json::from_str(line).unwrap();
        assert_eq!(r.kind(), "guard");
        assert_eq!(r.seq, None);
        assert!(!r.is_bookkeeping());
    }

    #[test]
    fn unknown_fields_round_trip() {
        let line = r#"{"v":2,"ts":"2026-10-13T08:14:02.381Z","agent":"codex","project":"/p","tool":"shell","input":"ls","decision":"allow","saiife":"0.1.0","chain":"abc","future":1}"#;
        let r: Record = serde_json::from_str(line).unwrap();
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains(r#""chain":"abc""#), "{json}");
        assert!(json.contains(r#""future":1"#), "{json}");
    }

    #[test]
    fn new_decisions_parse() {
        for (s, k) in [
            ("error_denied", DecisionKind::ErrorDenied),
            ("ask", DecisionKind::Ask),
            ("approved", DecisionKind::Approved),
            ("rejected", DecisionKind::Rejected),
            ("expired", DecisionKind::Expired),
            ("later", DecisionKind::Unknown),
        ] {
            let got: DecisionKind = serde_json::from_str(&format!("\"{s}\"")).unwrap();
            assert_eq!(got, k, "{s}");
        }
    }

    #[test]
    fn genesis_is_bookkeeping() {
        let mut r = Record::new(base("x"), "0.1.0");
        assert!(!r.is_bookkeeping());
        for k in ["genesis", "checkpoint", "key_rotate"] {
            r.kind = Some(k.into());
            assert!(r.is_bookkeeping(), "{k}");
        }
    }
}
