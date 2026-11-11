//! The box source seam: what the Workspace can see and do with boxes.

use saiife_touch::{ActionRecord, TouchClass, TouchEvidence};
use serde::{Deserialize, Serialize};
use std::fmt;

/// `[a-z0-9][a-z0-9-]{0,39}`; anything else is refused before a source sees it.
#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct BoxId(String);

impl BoxId {
    pub fn parse(s: &str) -> Result<BoxId, BoxError> {
        let b = s.as_bytes();
        let ok = !b.is_empty()
            && b.len() <= 40
            && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
            && b.iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-');
        if ok {
            Ok(BoxId(s.to_string()))
        } else {
            Err(BoxError::Invalid("box id".into()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for BoxId {
    type Error = BoxError;
    fn try_from(s: String) -> Result<BoxId, BoxError> {
        BoxId::parse(&s)
    }
}

impl From<BoxId> for String {
    fn from(id: BoxId) -> String {
        id.0
    }
}

/// §7.7: queued → starting → running ⇄ paused → done → landed | discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoxState {
    Queued,
    Starting,
    Running,
    Paused,
    Done,
    Landed,
    Discarded,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct BoxInfo {
    pub id: BoxId,
    pub state: BoxState,
    pub template: String,
    /// Display name, not a path.
    pub repo: String,
    pub task: String,
    pub created_at: u64,
    pub started_at: Option<u64>,
    pub updated_at: u64,
    pub queue_pos: Option<u32>,
    pub lands: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Load {
    pub cpu_pct: u8,
    pub mem_used_mb: u64,
    pub mem_total_mb: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Overview {
    /// Sorted: running, paused, done, queued (by queue_pos), starting, then
    /// the rest; ties by id. Sorting is the source's duty.
    pub boxes: Vec<BoxInfo>,
    pub load: Option<Load>,
    pub slots_total: u32,
    pub slots_free: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileStatus {
    Added,
    Modified,
    Deleted,
    Renamed { from: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FileChange {
    pub path: String,
    pub status: FileStatus,
    pub added: u32,
    pub removed: u32,
    pub binary: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TestResult {
    pub passed: u32,
    pub failed: u32,
    pub skipped: u32,
    pub summary: String,
}

pub const MAX_DIFF_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DiffSummary {
    pub id: BoxId,
    pub base_commit: String,
    pub diff_sha256: String,
    pub files: Vec<FileChange>,
    /// At most `MAX_DIFF_BYTES`, cut at a line end.
    pub unified: String,
    pub truncated: bool,
    pub tests: Option<TestResult>,
}

/// Plain text lines: the host's headless terminal has already applied every
/// escape; OSC 52 / OSC 8 never reach a client (§9.4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TermFrame {
    Snapshot {
        seq: u64,
        rows: u16,
        cols: u16,
        lines: Vec<String>,
        cursor: (u16, u16),
    },
    Delta {
        seq: u64,
        lines: Vec<(u16, String)>,
        cursor: (u16, u16),
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TermBatch {
    pub frames: Vec<TermFrame>,
    pub next: u64,
    pub ended: bool,
}

/// One pending touch-bound action the daemon created (§15: it accepts only
/// actions it created). Not serialized as is: the daemon sends `PendingView`.
#[derive(Debug, Clone)]
pub struct PendingAction {
    /// = record.request_id
    pub request_id: u64,
    /// = record.class
    pub class: TouchClass,
    pub box_id: Option<BoxId>,
    pub summary: String,
    pub record: ActionRecord,
    pub created_at: u64,
    /// = record.expires_at
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PendingView {
    /// Decimal: a u64 is not safe in JS.
    pub request_id: String,
    /// `TouchClass::name()`.
    pub class: String,
    pub box_id: Option<BoxId>,
    pub summary: String,
    pub challenge_hex: String,
    pub short_code: String,
    pub created_at: u64,
    pub expires_at: u64,
}

impl PendingAction {
    /// challenge_hex = hex(challenge(record)); short_code = short_code(challenge)
    /// (plan 26 D9; §8.3).
    pub fn view(&self) -> PendingView {
        let ch = saiife_touch::challenge(&self.record);
        PendingView {
            request_id: self.request_id.to_string(),
            class: self.record.class.name().to_string(),
            box_id: self.box_id.clone(),
            summary: self.summary.clone(),
            challenge_hex: crate::b64::hex(&ch),
            short_code: saiife_touch::short_code(&ch),
            created_at: self.created_at,
            expires_at: self.expires_at,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Approve,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Template {
    pub name: String,
    pub description: String,
    pub has_secrets: bool,
    pub has_egress: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Start {
    Now,
    Queue,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SpawnReq {
    pub template: String,
    pub repo: String,
    pub task: String,
    pub start: Start,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoxError {
    NotFound,
    WrongState { state: BoxState },
    Invalid(String),
    Busy,
    Unavailable(String),
}

impl BoxError {
    /// not_found | wrong_state | invalid | busy | unavailable
    pub fn rule(&self) -> &'static str {
        match self {
            BoxError::NotFound => "not_found",
            BoxError::WrongState { .. } => "wrong_state",
            BoxError::Invalid(_) => "invalid",
            BoxError::Busy => "busy",
            BoxError::Unavailable(_) => "unavailable",
        }
    }
}

impl fmt::Display for BoxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BoxError::NotFound => f.write_str("no such box"),
            BoxError::WrongState { state } => write!(f, "not allowed in state {state:?}"),
            BoxError::Invalid(why) => write!(f, "invalid: {why}"),
            BoxError::Busy => f.write_str("busy"),
            BoxError::Unavailable(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for BoxError {}

/// What the Workspace can see and do with boxes. Implemented by the box
/// manager (step 3, plan 34) and by `FakeBoxSource`. Every method is
/// synchronous and may block briefly; the daemon calls it from
/// `spawn_blocking`.
///
/// Contract with step 3 (plan 34 cites this):
/// - No method checks access: the daemon has verified the frame, its level
///   and any touch before it calls one.
/// - `state` follows §7.7 only.
/// - `Overview.boxes` order is the source's duty: running, paused, done,
///   queued (by `queue_pos`), starting, then the rest; ties by id.
/// - `stop`: Starting/Running/Paused -> Done; Done/Landed/Discarded -> `Ok(())`
///   (idempotent no-op); Queued -> `WrongState`.
/// - `pause` is Running -> Paused, `resume` Paused -> Running, `discard`
///   Queued|Done -> Discarded; anything else is `WrongState`.
/// - `revise` is only valid in `Done` (`WrongState` otherwise); it moves the
///   box to Running with the comment as the next prompt.
/// - `complete(Approve)` takes `Some(evidence)`, `complete(Reject)` takes
///   `None`; any other combination is `Invalid`. Approving `land` adds one
///   commit per §7.7 and never writes a user's repo (§5.1: the CLI does).
/// - `diff_sha256` is the SHA-256 (lowercase hex) of the full unified diff
///   before truncation: the value the `land` `ActionRecord` binds.
pub trait BoxSource: Send + Sync {
    fn overview(&self) -> Overview;
    fn list(&self) -> Vec<BoxInfo>;
    fn terminal(&self, id: &BoxId, after: Option<u64>) -> Result<TermBatch, BoxError>;
    fn diff(&self, id: &BoxId) -> Result<DiffSummary, BoxError>;
    fn stop(&self, id: &BoxId) -> Result<(), BoxError>;
    fn pause(&self, id: &BoxId) -> Result<(), BoxError>;
    fn resume(&self, id: &BoxId) -> Result<(), BoxError>;
    fn discard(&self, id: &BoxId) -> Result<(), BoxError>;
    /// The full new order of the queued boxes.
    fn reorder(&self, queue: &[BoxId]) -> Result<(), BoxError>;
    fn steer(&self, id: &BoxId, msg: &str) -> Result<(), BoxError>;
    /// Done -> Running, with the comment as the next prompt.
    fn revise(&self, id: &BoxId, comment: &str) -> Result<(), BoxError>;
    fn pending_actions(&self) -> Vec<PendingAction>;
    /// Evidence is `Some` for Approve, `None` for Reject.
    fn complete(
        &self,
        request_id: u64,
        decision: Decision,
        evidence: Option<TouchEvidence>,
    ) -> Result<(), BoxError>;
    fn templates(&self) -> Vec<Template>;
    fn spawn(&self, req: &SpawnReq) -> Result<BoxId, BoxError>;
}

pub const MAX_STEER_BYTES: usize = 4096;
pub const MAX_TASK_BYTES: usize = 8192;

/// Non-empty, at most `max` bytes, no NUL, no C0 controls but `\n` and `\t`,
/// no DEL and no C1 controls. Bidi and format characters stay allowed:
/// escaping them for display is the UI's job.
pub fn check_text(s: &str, max: usize) -> Result<(), BoxError> {
    if s.is_empty() {
        return Err(BoxError::Invalid("empty text".into()));
    }
    if s.len() > max {
        return Err(BoxError::Invalid(format!("text over {max} bytes")));
    }
    for c in s.chars() {
        let bad = match c {
            '\n' | '\t' => false,
            '\0'..='\u{1f}' | '\u{7f}' | '\u{80}'..='\u{9f}' => true,
            _ => false,
        };
        if bad {
            return Err(BoxError::Invalid("control character in text".into()));
        }
    }
    Ok(())
}

/// Step 3 has not landed: the daemon's default source.
pub struct NoBoxes;

fn unavailable<T>() -> Result<T, BoxError> {
    Err(BoxError::Unavailable(
        "boxes are not available in this version".into(),
    ))
}

impl BoxSource for NoBoxes {
    fn overview(&self) -> Overview {
        Overview {
            boxes: Vec::new(),
            load: None,
            slots_total: 0,
            slots_free: 0,
        }
    }
    fn list(&self) -> Vec<BoxInfo> {
        Vec::new()
    }
    fn terminal(&self, _id: &BoxId, _after: Option<u64>) -> Result<TermBatch, BoxError> {
        unavailable()
    }
    fn diff(&self, _id: &BoxId) -> Result<DiffSummary, BoxError> {
        unavailable()
    }
    fn stop(&self, _id: &BoxId) -> Result<(), BoxError> {
        unavailable()
    }
    fn pause(&self, _id: &BoxId) -> Result<(), BoxError> {
        unavailable()
    }
    fn resume(&self, _id: &BoxId) -> Result<(), BoxError> {
        unavailable()
    }
    fn discard(&self, _id: &BoxId) -> Result<(), BoxError> {
        unavailable()
    }
    fn reorder(&self, _queue: &[BoxId]) -> Result<(), BoxError> {
        unavailable()
    }
    fn steer(&self, _id: &BoxId, _msg: &str) -> Result<(), BoxError> {
        unavailable()
    }
    fn revise(&self, _id: &BoxId, _comment: &str) -> Result<(), BoxError> {
        unavailable()
    }
    fn pending_actions(&self) -> Vec<PendingAction> {
        Vec::new()
    }
    fn complete(
        &self,
        _request_id: u64,
        _decision: Decision,
        _evidence: Option<TouchEvidence>,
    ) -> Result<(), BoxError> {
        unavailable()
    }
    fn templates(&self) -> Vec<Template> {
        Vec::new()
    }
    fn spawn(&self, _req: &SpawnReq) -> Result<BoxId, BoxError> {
        unavailable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use saiife_touch::{ActionRecord, TouchClass};
    use std::collections::BTreeMap;

    #[test]
    fn box_id_rules() {
        assert!(BoxId::parse("a").is_ok());
        assert!(BoxId::parse("b-1").is_ok());
        assert!(BoxId::parse(&"a".repeat(40)).is_ok());
        for bad in ["", "-a", "A", "a/b", "../x", &"a".repeat(41)] {
            assert!(BoxId::parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(BoxId::parse("b-1").unwrap().as_str(), "b-1");
    }

    #[test]
    fn box_id_rejects_on_deserialize() {
        assert!(serde_json::from_str::<BoxId>("\"b-1\"").is_ok());
        assert!(serde_json::from_str::<BoxId>("\"../x\"").is_err());
        assert!(serde_json::from_str::<BoxId>("\"\"").is_err());
    }

    #[test]
    fn state_serializes_snake_case() {
        assert_eq!(serde_json::to_string(&BoxState::Done).unwrap(), "\"done\"");
        assert_eq!(
            serde_json::to_string(&BoxState::Discarded).unwrap(),
            "\"discarded\""
        );
    }

    #[test]
    fn no_boxes_is_empty_and_unavailable() {
        let s = NoBoxes;
        let o = s.overview();
        assert!(o.boxes.is_empty() && o.load.is_none());
        assert_eq!((o.slots_total, o.slots_free), (0, 0));
        assert!(s.list().is_empty() && s.pending_actions().is_empty());
        assert!(s.templates().is_empty());
        let id = BoxId::parse("a").unwrap();
        let un = BoxError::Unavailable("boxes are not available in this version".into());
        assert_eq!(s.stop(&id), Err(un.clone()));
        assert_eq!(s.pause(&id), Err(un.clone()));
        assert_eq!(s.resume(&id), Err(un.clone()));
        assert_eq!(s.discard(&id), Err(un.clone()));
        assert_eq!(s.reorder(&[]), Err(un.clone()));
        assert_eq!(s.steer(&id, "x"), Err(un.clone()));
        assert_eq!(s.revise(&id, "x"), Err(un.clone()));
        assert_eq!(s.terminal(&id, None), Err(un.clone()));
        assert_eq!(s.diff(&id), Err(un.clone()));
        assert_eq!(s.complete(1, Decision::Reject, None), Err(un.clone()));
        let req = SpawnReq {
            template: "t".into(),
            repo: "r".into(),
            task: "x".into(),
            start: Start::Now,
        };
        assert_eq!(s.spawn(&req), Err(un));
        assert_eq!(BoxError::NotFound.rule(), "not_found");
        assert_eq!(
            BoxError::WrongState {
                state: BoxState::Queued
            }
            .rule(),
            "wrong_state"
        );
        assert_eq!(BoxError::Invalid("x".into()).rule(), "invalid");
        assert_eq!(BoxError::Busy.rule(), "busy");
        assert_eq!(BoxError::Unavailable("x".into()).rule(), "unavailable");
    }

    #[test]
    fn check_text_rules() {
        assert!(check_text("hello\nworld\t!", 100).is_ok());
        assert!(check_text("", 10).is_err());
        assert!(check_text("a\x1bb", 10).is_err());
        assert!(check_text("a\0b", 10).is_err());
        assert!(check_text("a\x7fb", 10).is_err());
        assert!(check_text("a\u{9b}b", 10).is_err());
        assert!(check_text("a\u{202e}b", 10).is_ok());
        assert!(check_text(&"a".repeat(MAX_STEER_BYTES), MAX_STEER_BYTES).is_ok());
        assert!(check_text(&"a".repeat(MAX_STEER_BYTES + 1), MAX_STEER_BYTES).is_err());
    }

    #[test]
    fn dto_json_shape() {
        let o = Overview {
            boxes: vec![BoxInfo {
                id: BoxId::parse("b-1").unwrap(),
                state: BoxState::Running,
                template: "rust".into(),
                repo: "erp".into(),
                task: "fix it".into(),
                created_at: 1,
                started_at: Some(2),
                updated_at: 3,
                queue_pos: None,
                lands: 0,
            }],
            load: Some(Load {
                cpu_pct: 7,
                mem_used_mb: 100,
                mem_total_mb: 200,
            }),
            slots_total: 4,
            slots_free: 3,
        };
        assert_eq!(
            serde_json::to_string(&o).unwrap(),
            r#"{"boxes":[{"id":"b-1","state":"running","template":"rust","repo":"erp","task":"fix it","created_at":1,"started_at":2,"updated_at":3,"queue_pos":null,"lands":0}],"load":{"cpu_pct":7,"mem_used_mb":100,"mem_total_mb":200},"slots_total":4,"slots_free":3}"#
        );
    }

    #[test]
    fn pending_view_has_challenge_and_code() {
        let mut fields = BTreeMap::new();
        fields.insert("service".to_string(), "erp".to_string());
        fields.insert("body_sha256".to_string(), "0".repeat(64));
        fields.insert("operation".to_string(), "payments.create".to_string());
        let record = ActionRecord {
            instance_id: [0x11; 16],
            request_id: 42,
            class: TouchClass::Deploy,
            summary: "#42 erp payments.create".to_string(),
            fields,
            nonce: [0x22; 32],
            expires_at: 1_800_000_000,
        };
        let p = PendingAction {
            request_id: 42,
            class: TouchClass::Deploy,
            box_id: None,
            summary: record.summary.clone(),
            expires_at: record.expires_at,
            record,
            created_at: 1_799_999_000,
        };
        let v = p.view();
        assert_eq!(v.request_id, "42");
        assert_eq!(v.class, "deploy");
        assert_eq!(
            v.challenge_hex,
            "9759e53f34fc0f4308fe8e0d10a32b4bd0e0d85365c969948afca55866496db6"
        );
        assert_eq!(v.short_code, "918949");
    }
}
