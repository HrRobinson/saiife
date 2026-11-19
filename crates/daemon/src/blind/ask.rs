//! The Data Shield ask (plan 48 Task 1; spec §2.1.6, §2.1.7, §2.3.5,
//! §2.3.6, §6.5): a small state machine per ask, keyed by a random id,
//! owned by the uid that made it (R48-1). Each step is one IPC call: the
//! daemon says what it needs (a pick, "did you mean", keeping a name, the
//! method preview) and the caller sends the user's answer back.
//!
//! `blind.ask` fixes the dataset's live build for the whole ask
//! ([`data::live_snapshot`], plan 48 C2), parameterizes the question
//! locally and resolves its names (plan 44). A ready draft reuses an
//! approved method of the same template and parameter types with no cloud
//! call (R45-11), or goes to the planner through plan 47's send sequence.
//! A method, its self-checks or its template that does not validate goes
//! back to the planner as its error class, by the previous method's hash
//! (R48-2, R-C11): the first try plus at most [`MAX_TRIES`]` - 1` retries.
//! The preview is then built from the validated method (plan 45) and the
//! ask waits for Run or Stop (Task 2).
//!
//! **Local only:** pick lists, "did you mean" suggestions, the preview and
//! the user's words go into the answer of the step that shows them and
//! nowhere else. Records hold the parameterized question with stand-ins
//! (`blind_ask`), counts (`blind_resolve`) and hashes (`blind_preview`).
//! Every refused step carries a machine `code` (R-C5) so a later step can
//! key on it (`identifier_output`: the reveal, plan 49).
//!
//! The run after the preview (Task 2) is in the child module `run`
//! (`ask_run.rs`).

use super::audit::{self, BlindRecord};
use super::data::{self, LiveSnapshot};
use super::model::{self, PlanError};
use super::{keys, lock, Blind, Refusal};
use crate::ops::Ctx;
use saiife_ipc::msg::ErrorCode;
use saiife_ipc::peer::PeerCred;
use saiife_shield::envelope::{
    bind_context, build_envelope, cloud_schema, logged_question, method_sha256, schema_sha256,
    synthetic_sha256, Retry, SentSummary,
};
use saiife_shield::firewall::{self, retry_error_class, Expected, Firewall, Hit};
use saiife_shield::lexicon::{Candidate, Resolve, MAX_CANDIDATES};
use saiife_shield::methods::{ApprovedMethod, MethodStore};
use saiife_shield::plan::{intent_line, PlanReply};
use saiife_shield::preview::{preview, Preview};
use saiife_shield::public::PublicValues;
use saiife_shield::question::{self, Draft, Pending};
use saiife_shield::schema::{DatasetName, Lang, Param, Schema};
use saiife_shield::sql::{validate, validate_check, ErrorClass, MethodError, Validated};
use saiife_shield::standin::KeySet;
use saiife_shield::synth::{os_rng, synthetic_rows};
use saiife_shield::template::{check_params_covered, entity_label, parse_template, preview_params};
use saiife_shield::ShieldError;
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[path = "ask_run.rs"]
mod run;
pub use run::{
    ACCEPT_UNRECORDED, FILL_FAILED, RUN_UNRECORDED, SANDBOX_TEXT, SELF_CHECK_FAILED, STOPPED,
    STOP_UNRECORDED, TIME_CAP_TEXT,
};

// ------------------------------------------------------------ values ----

/// An ask lives this long after its last step; an answered one is kept as
/// long again for `methods approve` (R48-1).
pub const ASK_TTL: Duration = Duration::from_secs(600);
/// Open asks per uid and per daemon (R48-1).
pub const MAX_OPEN_PER_UID: usize = 4;
pub const MAX_OPEN: usize = 64;
/// Answered asks kept for `methods approve` (R48-1), per uid and per
/// daemon (T1 review M8): over either, the oldest answered ask goes. They
/// do not count against the open-ask limits.
pub const MAX_ANSWERED_PER_UID: usize = 4;
pub const MAX_ANSWERED: usize = 64;
/// The longest question, in characters.
pub const MAX_QUESTION_CHARS: usize = 2_000;
/// Planner requests per ask before the preview: the first try plus 3
/// retries (R48-2, plan 45 R45-8).
pub const MAX_TRIES: u32 = 4;
/// Synthetic rows per table in an envelope (plan 44 R44-6: at most 5).
const SYNTHETIC_PER_TABLE: usize = 5;

/// R48-5: `--judgment`, or a plan reply with `needs_judgment`.
pub const JUDGMENT: &str = "this question needs judgment, which needs the local composer \
     (a later stage); exact mode cannot answer it";
/// An ask id that is not (or no longer) there.
pub const NO_SUCH_ASK: &str =
    "no such ask: it ended or expired (an ask lasts 10 minutes after its last step); ask again";
/// Another uid's ask (R48-1).
pub const NOT_YOURS: &str = "this ask belongs to another user";
/// A step sent while the ask still works on the last one.
pub const ASK_BUSY: &str = "this ask is still working on its last step; wait for it";
/// R-C8: no `[blind.ner]` pins.
pub const NER_NOT_PINNED: &str = "Data Shield needs its local name detector first: [blind.ner] \
     must pin the model, vocab and labels by sha256 (saiife blind init sets it up; see the Data \
     Shield docs)";
/// R-C8: pinned, but no detector is running.
pub const NER_NOT_READY: &str = "the local name detector is not ready: saiife blind status \
     shows why (saiife blind init fetches its files)";
/// R-C12: the asker lost the role on the dataset (a policy change).
pub const ROLE_LOST: &str =
    "you may no longer ask this dataset (the policy changed); the ask has ended";
/// R-C12 at a `blind:approve` commit (plan 48 T3): the approver role is
/// gone.
pub const APPROVER_LOST: &str = "you are no longer an approver of this dataset (the policy \
                                 changed); nothing was approved and the ask has ended";
/// R-C12: the dataset left policy.
pub const DATASET_GONE: &str = "this dataset is no longer in policy; the ask has ended";
/// A record failed before anything was sent.
pub const UNRECORDED_NOTHING_SENT: &str = "the ask could not be recorded; nothing was sent";
/// I3: the preview record failed after the planner was asked: the
/// preview is not shown (never "nothing was sent").
pub const PREVIEW_UNRECORDED: &str = "the preview could not be recorded, so it was not shown";
/// R48-3: `--yes` on a dataset whose policy wants the preview.
pub fn preview_required_text(dataset: &str) -> String {
    format!("{dataset} needs the method preview before it runs: ask again without --yes")
}
/// `{"keep_name": true}` on `blind.ask.answer`: only the touch keeps a name.
pub const KEEP_NEEDS_TOUCH: &str =
    "keeping a name as plain text needs a touch (blind:name): blind.touch.begin {purpose: name}";

/// The machine codes of refused steps (R-C5).
pub mod code {
    /// "None of these", or a "yes" whose name no longer resolves.
    pub const NO_MATCH: &str = "no_match";
    /// "None of these" on a list cut at the candidate cap.
    pub const TOO_MANY: &str = "too_many";
    /// The user would not keep an unknown name.
    pub const NAME_REFUSED: &str = "name_refused";
    /// A literal that does not parse as its type.
    pub const BAD_LITERAL: &str = "bad_literal";
    /// The name detector failed.
    pub const DETECTOR: &str = "detector";
    /// The planner's method did not validate after every try.
    pub const INVALID_METHOD: &str = "invalid_method";
    /// R45-13: the method would print an identifier (the reveal hook).
    pub const IDENTIFIER_OUTPUT: &str = "identifier_output";
    /// R48-5.
    pub const NEEDS_JUDGMENT: &str = "needs_judgment";
    /// The planner gave no usable reply.
    pub const PLANNER: &str = "planner";
    /// The leak firewall stopped the request (R48-9).
    pub const BLOCKED: &str = "blocked";
    /// The reply held a value of the dataset.
    pub const LEAK: &str = "leak";
    /// The request or its reply could not be recorded (R-C9).
    pub const UNRECORDED: &str = "unrecorded";
    /// `--yes` on a dataset whose policy wants the preview (R48-3).
    pub const PREVIEW_REQUIRED: &str = "preview_required";
    /// The user stopped at the preview (Task 2).
    pub const STOPPED: &str = "stopped";
    /// After the run (Task 2): the entity has no rows (R45-6).
    pub const EMPTY_FOR_KEY: &str = "empty_for_key";
    /// After the run: the method matched nothing.
    pub const EMPTY_RESULT: &str = "empty_result";
    /// After the run: the checker (or a self-check, or the fill) refused.
    pub const CHECK_FAILED: &str = "check_failed";
    /// After the run: the method does not apply every part of the question.
    pub const PARAM_MISUSE: &str = "param_misuse";
    /// After the run: the dataset changed under the job.
    pub const SNAPSHOT_MISMATCH: &str = "snapshot_mismatch";
    /// After the run: the time or step cap.
    pub const TIME_CAP: &str = "time_cap";
    /// After the run: any other calculator refusal.
    pub const CALC_REFUSED: &str = "calc_refused";
}

/// The head of a refusal made before anything was sent.
pub fn head_nothing_sent(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "refused, nothing sent",
        Lang::Da => "afvist, intet sendt",
    }
}

/// The head of a refusal once the planner was asked.
pub fn head_no_answer(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "I could not produce a verified answer",
        Lang::Da => "Jeg kunne ikke give et verificeret svar",
    }
}

// ------------------------------------------------------------- steps ----

/// What the daemon shows next (JSON, tag `kind`). Holds what the user may
/// see locally; never logged. `Debug` prints the kind only.
#[derive(Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Step {
    /// Namesakes: the user picks one (`n` is 1-based; 0 is "none").
    Pick {
        word: String,
        written: String,
        candidates: Vec<PickItem>,
        too_many: bool,
    },
    /// An unknown name close to one known one (see [`did_you_mean_step`]).
    DidYouMean {
        word: String,
        written: String,
        suggestion: String,
    },
    /// An unknown name: keep it as plain text (a touch, Task 3) or stop.
    KeepName { name: String },
    /// The method in plain words; Run or Stop next.
    Preview {
        text: String,
        /// The planner's intent line (R-C10: only without numbers).
        #[serde(skip_serializing_if = "Option::is_none")]
        planner_says: Option<String>,
        /// The approved method reused (no cloud call).
        #[serde(skip_serializing_if = "Option::is_none")]
        approved: Option<String>,
        sent: Sent,
        /// The exact envelope sent (canonical JSON), with `show_sent`.
        #[serde(skip_serializing_if = "Option::is_none")]
        envelope: Option<String>,
    },
    /// The checked answer (Task 2, R48-4).
    Answer {
        text: String,
        method_line: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        cap_note: Option<String>,
        footer: String,
        checked: Checked,
    },
    /// The ask ended without an answer. `code` is fixed (see [`code`]).
    Refused {
        code: &'static str,
        head: String,
        reason: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        method_line: Option<String>,
    },
    /// The dataset is being rebuilt; ask again in a moment.
    Refreshing { text: String },
}

/// One line of a pick list: the display name and the `show` values that
/// are not Identifier-class (R-C2); never the key.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct PickItem {
    pub n: usize,
    pub label: String,
}

/// What the envelope held (counts only; zeros when nothing was sent).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Sent {
    pub tables: usize,
    pub synthetic_rows: usize,
    pub params: usize,
    pub personal_values: usize,
}

impl From<SentSummary> for Sent {
    fn from(s: SentSummary) -> Sent {
        Sent {
            tables: s.tables,
            synthetic_rows: s.synthetic_rows,
            params: s.params,
            personal_values: s.personal_values,
        }
    }
}

/// The checker's count (Task 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Checked {
    pub numbers: u32,
    pub from_calc: u32,
}

impl Step {
    pub fn kind(&self) -> &'static str {
        match self {
            Step::Pick { .. } => "pick",
            Step::DidYouMean { .. } => "did_you_mean",
            Step::KeepName { .. } => "keep_name",
            Step::Preview { .. } => "preview",
            Step::Answer { .. } => "answer",
            Step::Refused { .. } => "refused",
            Step::Refreshing { .. } => "refreshing",
        }
    }

    /// A refusal without a method line.
    pub fn refused(code: &'static str, head: &str, reason: impl Into<String>) -> Step {
        Step::Refused {
            code,
            head: head.to_string(),
            reason: reason.into(),
            method_line: None,
        }
    }

    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

impl std::fmt::Debug for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Step::Refused { code, .. } => write!(f, "Step::Refused({code})"),
            s => write!(f, "Step::{}", s.kind()),
        }
    }
}

/// The step of a "did you mean" (R-C4: built here only, so plan 49 can
/// change its shape in one place).
pub fn did_you_mean_step(
    word: &str,
    written: &str,
    suggestion: &Candidate,
    schema: &Schema,
) -> Step {
    Step::DidYouMean {
        word: word.to_string(),
        written: written.to_string(),
        suggestion: entity_label(suggestion, schema),
    }
}

// ----------------------------------------------------------- answers ----

/// The parsed `blind.ask` arguments. `Debug` hides the question.
#[derive(Clone)]
pub struct AskArgs {
    pub question: String,
    pub dataset: Option<String>,
    pub lang: Option<Lang>,
    pub new_session: bool,
    pub yes: bool,
    pub limit: Option<u32>,
    pub show_sent: bool,
    pub judgment: bool,
}

impl std::fmt::Debug for AskArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AskArgs")
            .field("dataset", &self.dataset)
            .field("lang", &self.lang)
            .field("new_session", &self.new_session)
            .field("yes", &self.yes)
            .field("limit", &self.limit)
            .field("show_sent", &self.show_sent)
            .field("judgment", &self.judgment)
            .finish_non_exhaustive()
    }
}

fn bad(text: impl Into<String>) -> Refusal {
    Refusal::new(ErrorCode::BadRequest, text)
}

fn unavailable(text: impl Into<String>) -> Refusal {
    Refusal::new(ErrorCode::Unavailable, text)
}

fn flag(a: &Map<String, Value>, k: &str) -> Result<bool, Refusal> {
    match a.get(k) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(bad(format!("{k} must be true or false"))),
    }
}

impl AskArgs {
    /// From the op's arguments: the question (1 to 2 000 characters), an
    /// optional dataset, `lang` `en` or `da`, the flags and `limit`.
    pub fn from_args(a: &Map<String, Value>) -> Result<AskArgs, Refusal> {
        let question = a
            .get("question")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("question is required"))?;
        if question.trim().is_empty() {
            return Err(bad("the question is empty"));
        }
        if question.chars().count() > MAX_QUESTION_CHARS {
            return Err(bad(format!(
                "the question is longer than {MAX_QUESTION_CHARS} characters"
            )));
        }
        let dataset = match a.get("dataset") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => return Err(bad("dataset must be a name")),
        };
        let lang = match a.get("lang") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if s == "en" => Some(Lang::En),
            Some(Value::String(s)) if s == "da" => Some(Lang::Da),
            Some(_) => return Err(bad("lang must be en or da")),
        };
        let limit = match a.get("limit") {
            None | Some(Value::Null) => None,
            Some(v) => Some(
                v.as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .filter(|n| *n >= 1)
                    .ok_or_else(|| bad("limit must be a whole number of at least 1"))?,
            ),
        };
        Ok(AskArgs {
            question: question.to_string(),
            dataset,
            lang,
            new_session: flag(a, "new_session")?,
            yes: flag(a, "yes")?,
            limit,
            show_sent: flag(a, "show_sent")?,
            judgment: flag(a, "judgment")?,
        })
    }
}

/// The user's answer to a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AskAnswer {
    /// 1-based; 0 is "none of these".
    Pick(usize),
    DidYouMean(bool),
    KeepNameNo,
    Run(bool),
    /// Only from `blind.touch.commit` once the `blind:name` touch verified
    /// (Task 3).
    KeepNameTouched,
}

/// The answer of a "did you mean" (R-C4: parsed here only).
fn did_you_mean_answer(v: &Value) -> Result<AskAnswer, Refusal> {
    match v {
        Value::Bool(b) => Ok(AskAnswer::DidYouMean(*b)),
        _ => Err(bad("did_you_mean must be true or false")),
    }
}

/// `{"pick": n}`, `{"did_you_mean": bool}`, `{"keep_name": false}` or
/// `{"run": bool}`; `keep_name: true` goes through the touch.
pub fn parse_answer(v: Option<&Value>) -> Result<AskAnswer, Refusal> {
    let shape = "answer must be one of {\"pick\": n}, {\"did_you_mean\": bool}, \
                 {\"keep_name\": false}, {\"run\": bool}";
    let Some(Value::Object(m)) = v else {
        return Err(bad(shape));
    };
    let mut it = m.iter();
    let (Some((k, v)), None) = (it.next(), it.next()) else {
        return Err(bad(shape));
    };
    match (k.as_str(), v) {
        ("pick", v) => v
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .map(AskAnswer::Pick)
            .ok_or_else(|| bad("pick must be a whole number")),
        ("did_you_mean", v) => did_you_mean_answer(v),
        ("keep_name", Value::Bool(false)) => Ok(AskAnswer::KeepNameNo),
        ("keep_name", Value::Bool(true)) => Err(bad(KEEP_NEEDS_TOUCH)),
        ("run", Value::Bool(b)) => Ok(AskAnswer::Run(*b)),
        _ => Err(bad(shape)),
    }
}

// ------------------------------------------------------------- state ----

/// Where an ask is. The shape is the plan's (Tasks 2 and 3 match on it);
/// an ask lives in a map, never on a hot path, so the size is no concern.
#[allow(clippy::large_enum_variant)]
pub enum AskPhase {
    /// A step of local resolution is shown (`draft.pending[0]`).
    Resolving(Draft),
    /// The preview is shown; Run or Stop next (Task 2).
    Previewing {
        draft: Draft,
        validated: Validated,
        reply: PlanReply,
        preview: Preview,
        /// The approved method's id when one was reused.
        approved: Option<String>,
    },
    /// A checked answer was shown (Task 2); kept for `methods approve`.
    Answered {
        draft: Draft,
        reply: PlanReply,
        preview: Preview,
    },
    /// Ended: the ask is dropped.
    Done,
}

impl AskPhase {
    fn word(&self) -> &'static str {
        match self {
            AskPhase::Resolving(_) => "resolving",
            AskPhase::Previewing { .. } => "previewing",
            AskPhase::Answered { .. } => "answered",
            AskPhase::Done => "done",
        }
    }

    /// Resolving or previewing: counts against the open-ask limits.
    fn is_open(&self) -> bool {
        matches!(self, AskPhase::Resolving(_) | AskPhase::Previewing { .. })
    }
}

impl std::fmt::Debug for AskPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.word())
    }
}

/// What the ask was asked with, fixed at its begin.
#[derive(Debug, Clone, Copy)]
pub struct AskOpts {
    pub yes: bool,
    pub show_sent: bool,
    /// The envelope's and the calculator's row cap (`--limit` or policy).
    pub list_cap: u32,
    /// The dataset's `preview_required` (R48-3, Task 2).
    pub preview_required: bool,
    /// The session length (policy).
    pub session: Duration,
}

/// Resolution counts for `blind_resolve` (never a candidate).
#[derive(Debug, Default)]
struct Counts {
    /// Param -> the candidates its pick list had.
    picks: BTreeMap<String, u32>,
    did_you_mean: u32,
    kept_names: u32,
    /// The latest draft's params: (name, tag, bound).
    seen: Vec<(String, String, bool)>,
}

/// One ask. Holds the question, the user's words and the chosen
/// candidates: local only; `Debug` prints none of them.
pub struct AskState {
    pub uid: u32,
    pub dataset: DatasetName,
    pub phase: AskPhase,
    pub last_step: Instant,
    /// The build the ask runs on, fixed at `blind.ask` (plan 48 C2): every
    /// step, and the run (Task 2), use it.
    pub snapshot: Arc<LiveSnapshot>,
    pub opts: AskOpts,
    /// Names a `blind:name` touch released in this ask (ruling P-28).
    pub released: Vec<String>,
    /// The candidate each picked or confirmed parameter resolved to (the
    /// preview shows its non-Identifier `show` values, R-C2).
    chosen: Vec<(String, Candidate)>,
    counts: Counts,
    /// The asker's credentials of the latest step: the role is checked
    /// again with them before every step and every planner call (R-C12).
    peer: PeerCred,
    /// What the envelope of the previewed method held (the footer's count).
    sent: Sent,
    /// [`audit::preview_mac`] of the preview, for its `blind_preview`
    /// records (shown or auto, then accepted or stopped).
    preview_mac: String,
    /// The template key and type tags of the user's own question, taken
    /// before any context parameter was bound (plan 48 T3: approve uses
    /// these, never the bound draft's).
    template: Option<(String, Vec<String>)>,
    /// The approved method the preview reused, if any.
    reused: Option<String>,
    /// Every name the firewall let pass as released when the method was
    /// planned (the session's and this ask's): approve refuses a method
    /// that holds one (plan 48 T3 review I1).
    planned_released: Vec<String>,
}

/// What `methods approve` takes from an answered ask (plan 48 T3).
#[derive(Clone)]
pub struct ForApprove {
    pub dataset: DatasetName,
    pub lang: Lang,
    /// From the original question ([`AskState`]'s `template`).
    pub template_key: String,
    pub param_tags: Vec<String>,
    pub reply: PlanReply,
    /// The preview text the answer ran with.
    pub preview_text: String,
    /// Its [`audit::preview_mac`].
    pub preview_mac: String,
    /// The approved method the ask reused, if any.
    pub reused: Option<String>,
    /// Whether this ask kept a name through a `blind:name` touch.
    pub kept_name: bool,
    /// The names released when the method was planned (session and ask).
    pub released: Vec<String>,
}

impl std::fmt::Debug for ForApprove {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForApprove")
            .field("dataset", &self.dataset)
            .finish_non_exhaustive()
    }
}

impl AskState {
    /// The name a `keep_name` step waits on, if that is the pending step.
    pub fn keep_name_pending(&self) -> Option<&str> {
        match &self.phase {
            AskPhase::Resolving(d) => match d.pending.first() {
                Some(Pending::KeepName { name, .. }) => Some(name.as_str()),
                _ => None,
            },
            _ => None,
        }
    }

    /// What approving this ask would store: only an ask that ended with a
    /// checked answer (Task 2's `Answered`).
    pub fn for_approve(&self) -> Option<ForApprove> {
        let AskPhase::Answered {
            draft,
            reply,
            preview,
        } = &self.phase
        else {
            return None;
        };
        let (template_key, param_tags) = self.template.clone()?;
        Some(ForApprove {
            dataset: self.dataset.clone(),
            lang: draft.lang,
            template_key,
            param_tags,
            reply: reply.clone(),
            preview_text: preview.text.clone(),
            preview_mac: self.preview_mac.clone(),
            reused: self.reused.clone(),
            kept_name: !self.released.is_empty() || self.counts.kept_names > 0,
            released: self.planned_released.clone(),
        })
    }
}

impl std::fmt::Debug for AskState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AskState")
            .field("uid", &self.uid)
            .field("dataset", &self.dataset)
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

/// The asks of a daemon (`Blind::asks`). An ask being worked on (a step
/// in flight) is out of the map and listed in `working`, so a second step
/// for it is `busy` and every lookup still knows its owner.
#[derive(Debug, Default)]
pub struct Asks {
    map: BTreeMap<String, AskState>,
    working: BTreeMap<String, u32>,
}

impl Asks {
    pub fn new() -> Asks {
        Asks::default()
    }

    /// Drops every ask whose last step is [`ASK_TTL`] old.
    pub fn sweep(&mut self, now: Instant) {
        self.map
            .retain(|_, s| now.saturating_duration_since(s.last_step) < ASK_TTL);
    }

    /// The asks kept (any phase), and those in flight.
    pub fn len(&self) -> usize {
        self.map.len() + self.working.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The uids of the open asks: resolving, previewing or in flight.
    fn open_uids(&self) -> impl Iterator<Item = u32> + '_ {
        self.map
            .values()
            .filter(|s| s.phase.is_open())
            .map(|s| s.uid)
            .chain(self.working.values().copied())
    }

    /// Drops the oldest answered asks until one more of `uid`'s fits under
    /// [`MAX_ANSWERED_PER_UID`] and [`MAX_ANSWERED`].
    fn make_room_answered(&mut self, uid: u32) {
        let answered = |s: &AskState| matches!(s.phase, AskPhase::Answered { .. });
        loop {
            let mine = self
                .map
                .values()
                .filter(|s| s.uid == uid && answered(s))
                .count();
            let all = self.map.values().filter(|s| answered(s)).count();
            let pick_mine = mine >= MAX_ANSWERED_PER_UID;
            if !pick_mine && all < MAX_ANSWERED {
                return;
            }
            let oldest = self
                .map
                .iter()
                .filter(|(_, s)| answered(s) && (!pick_mine || s.uid == uid))
                .min_by_key(|(_, s)| s.last_step)
                .map(|(id, _)| id.clone());
            match oldest {
                Some(id) => {
                    self.map.remove(&id);
                }
                None => return,
            }
        }
    }

    /// Holds a new ask's slot for `uid` (R48-1 limits).
    fn reserve(&mut self, id: &str, uid: u32) -> Result<(), Refusal> {
        if self.open_uids().filter(|u| *u == uid).count() >= MAX_OPEN_PER_UID {
            return Err(Refusal::new(
                ErrorCode::Busy,
                format!(
                    "you have {MAX_OPEN_PER_UID} open asks: answer one, or wait for one to expire"
                ),
            ));
        }
        if self.open_uids().count() >= MAX_OPEN {
            return Err(Refusal::new(
                ErrorCode::Busy,
                format!("Data Shield has {MAX_OPEN} open asks; try again in a moment"),
            ));
        }
        self.working.insert(id.to_string(), uid);
        Ok(())
    }

    /// Takes ask `id` of `uid` out to work on it.
    fn take(&mut self, id: &str, uid: u32) -> Result<AskState, Refusal> {
        if let Some(owner) = self.working.get(id) {
            return Err(if *owner == uid {
                Refusal::new(ErrorCode::Busy, ASK_BUSY)
            } else {
                Refusal::new(ErrorCode::Forbidden, NOT_YOURS)
            });
        }
        match self.map.get(id) {
            None => return Err(bad(NO_SUCH_ASK)),
            Some(s) if s.uid != uid => return Err(Refusal::new(ErrorCode::Forbidden, NOT_YOURS)),
            Some(_) => {}
        }
        let st = self.map.remove(id).ok_or_else(|| bad(NO_SUCH_ASK))?;
        self.working.insert(id.to_string(), uid);
        Ok(st)
    }

    /// Runs `f` on ask `id` of `uid` (Task 3: the touch flows read the
    /// pending name or the answered method).
    pub fn peek<T>(
        &self,
        id: &str,
        uid: u32,
        f: impl FnOnce(&AskState) -> T,
    ) -> Result<T, Refusal> {
        if let Some(owner) = self.working.get(id) {
            return Err(if *owner == uid {
                Refusal::new(ErrorCode::Busy, ASK_BUSY)
            } else {
                Refusal::new(ErrorCode::Forbidden, NOT_YOURS)
            });
        }
        match self.map.get(id) {
            None => Err(bad(NO_SUCH_ASK)),
            Some(s) if s.uid != uid => Err(Refusal::new(ErrorCode::Forbidden, NOT_YOURS)),
            Some(s) => Ok(f(s)),
        }
    }

    /// Drops ask `id` of `uid` when it is kept (not in flight): `methods
    /// approve` ends the ask it approved. Whether it was there.
    pub fn forget(&mut self, id: &str, uid: u32) -> bool {
        if self.map.get(id).is_some_and(|s| s.uid == uid) {
            self.map.remove(id);
            return true;
        }
        false
    }

    /// Test seam: every ask's last step `by` earlier.
    #[cfg(debug_assertions)]
    pub fn test_backdate(&mut self, by: Duration) {
        for s in self.map.values_mut() {
            if let Some(t) = s.last_step.checked_sub(by) {
                s.last_step = t;
            }
        }
    }
}

/// An ask in flight: its `working` mark goes when this drops (also when
/// the connection's task is dropped mid-step).
struct Working {
    blind: Arc<Blind>,
    id: String,
}

impl Drop for Working {
    fn drop(&mut self) {
        lock(&self.blind.asks).working.remove(&self.id);
    }
}

/// Keeps `st` for its next step unless it ended. An answered ask makes
/// room first: at most [`MAX_ANSWERED_PER_UID`] per uid and
/// [`MAX_ANSWERED`] per daemon are kept, the oldest go (T1 review M8).
fn store(ctx: &Ctx, id: &str, mut st: AskState) {
    if matches!(st.phase, AskPhase::Done) {
        return;
    }
    st.last_step = Instant::now();
    let mut a = lock(&ctx.blind.asks);
    if matches!(st.phase, AskPhase::Answered { .. }) {
        a.make_room_answered(st.uid);
    }
    a.map.insert(id.to_string(), st);
}

fn new_id() -> Result<String, Refusal> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|_| unavailable("no randomness for an ask id"))?;
    Ok(crate::api_ops::hex(&b))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn shield_err(e: &ShieldError) -> Refusal {
    unavailable(format!("the ask could not go on: {e}"))
}

fn join_err() -> Refusal {
    unavailable("the ask could not go on: a local step stopped")
}

// ----------------------------------------------------------- dataset ----

/// The dataset to ask, its policy entry, and what the ask takes from
/// policy. Named: it must be in policy and the peer may ask it; unnamed:
/// the one dataset the peer may ask.
async fn dataset_for(
    ctx: &Ctx,
    peer: &PeerCred,
    want: Option<&str>,
    limit: Option<u32>,
) -> Result<(DatasetName, AskOpts), Refusal> {
    let p = ctx.policy();
    let blind = p
        .system
        .as_ref()
        .map(|s| s.blind.clone())
        .unwrap_or_default();
    let name: DatasetName = match want {
        Some(n) => {
            let name: DatasetName = n.parse().map_err(|_| bad("not a dataset name"))?;
            if !blind.dataset.iter().any(|d| d.name == name.as_str()) {
                return Err(bad(format!("{name} is not in policy")));
            }
            if !super::ops::role_of(ctx, peer, &name).await.may_ask() {
                return Err(Refusal::new(
                    ErrorCode::Forbidden,
                    format!("you have no role on {name}"),
                ));
            }
            name
        }
        None => {
            let mut mine = Vec::new();
            for d in &blind.dataset {
                if let Ok(n) = d.name.parse::<DatasetName>() {
                    if super::ops::role_of(ctx, peer, &n).await.may_ask() {
                        mine.push(n);
                    }
                }
            }
            match mine.len() {
                0 => {
                    return Err(Refusal::new(
                        ErrorCode::Forbidden,
                        "you may not ask any Data Shield dataset",
                    ))
                }
                1 => mine.remove(0),
                _ => {
                    return Err(bad(
                        "you may ask more than one dataset: pass --dataset <name>",
                    ))
                }
            }
        }
    };
    let d = blind
        .dataset
        .iter()
        .find(|d| d.name == name.as_str())
        .ok_or_else(|| bad(format!("{name} is not in policy")))?;
    let cap = d.list_cap.unwrap_or_else(|| blind.list_cap());
    if let Some(l) = limit {
        if l > cap {
            return Err(bad(format!("--limit must be at most {cap} for {name}")));
        }
    }
    Ok((
        name,
        AskOpts {
            yes: false,
            show_sent: false,
            list_cap: limit.unwrap_or(cap),
            preview_required: d.preview_required,
            session: blind.session(),
        },
    ))
}

/// R-C8: `[blind.ner]` pins the detector's files, and the detector runs.
fn detector(ctx: &Ctx) -> Result<Arc<dyn saiife_shield::ner::NameDetector>, Refusal> {
    let pinned = ctx
        .policy()
        .system
        .as_ref()
        .is_some_and(|s| s.blind.ner.is_some());
    if !pinned {
        return Err(unavailable(NER_NOT_PINNED));
    }
    ctx.blind
        .detector()
        .ok_or_else(|| unavailable(NER_NOT_READY))
}

async fn load_keys(ctx: &Arc<Ctx>, ds: &DatasetName) -> Result<KeySet, Refusal> {
    let (c, d) = (Arc::clone(ctx), ds.clone());
    tokio::task::spawn_blocking(move || keys::load(&c, &d).map_err(|e| e.refusal(&d)))
        .await
        .map_err(|_| join_err())?
}

// -------------------------------------------------------------- flow ----

/// `blind.ask`: a new ask and its first step.
pub async fn begin(
    ctx: &Arc<Ctx>,
    peer: &PeerCred,
    args: AskArgs,
) -> Result<(String, Step), Refusal> {
    let (name, mut opts) = dataset_for(ctx, peer, args.dataset.as_deref(), args.limit).await?;
    opts.yes = args.yes;
    opts.show_sent = args.show_sent;
    // A refusal before a draft exists speaks the question's language.
    let lang0 = args
        .lang
        .unwrap_or_else(|| saiife_shield::lang::detect_lang(&args.question));
    let id = new_id()?;
    // R48-3: such a dataset never runs a method unseen.
    if args.yes && opts.preview_required {
        return Ok((
            id,
            Step::refused(
                code::PREVIEW_REQUIRED,
                head_nothing_sent(lang0),
                preview_required_text(name.as_str()),
            ),
        ));
    }
    if args.judgment {
        return Ok((
            id,
            Step::refused(code::NEEDS_JUDGMENT, head_nothing_sent(lang0), JUDGMENT),
        ));
    }
    let det = detector(ctx)?;
    // The build, fixed for the whole ask; a refresh is a step of its own.
    let snap = match data::live_snapshot(ctx, &name) {
        Ok(s) => s,
        Err(r)
            if r.code == ErrorCode::Busy
                && matches!(ctx.blind.state(&name), super::DatasetState::Building { .. }) =>
        {
            return Ok((id, Step::Refreshing { text: r.text }))
        }
        Err(r) => return Err(r),
    };
    if snap.open.index.is_none() {
        return Err(unavailable(format!(
            "{name} has no known-value index: saiife blind data refresh --dataset {name}"
        )));
    }
    {
        let mut a = lock(&ctx.blind.asks);
        a.sweep(Instant::now());
        a.reserve(&id, peer.uid)?;
    }
    let _w = Working {
        blind: Arc::clone(&ctx.blind),
        id: id.clone(),
    };
    // `--new-session` starts the session over now.
    let keys = load_keys(ctx, &name).await?;
    lock(&ctx.blind.sessions)
        .get_or_new(
            peer.uid,
            &name,
            &keys,
            unix_now(),
            opts.session,
            args.new_session,
        )
        .map_err(|e| shield_err(&e))?;
    drop(keys);
    let st = AskState {
        uid: peer.uid,
        dataset: name,
        phase: AskPhase::Done,
        last_step: Instant::now(),
        snapshot: Arc::clone(&snap),
        opts,
        released: Vec::new(),
        chosen: Vec::new(),
        counts: Counts::default(),
        peer: peer.clone(),
        sent: Sent::default(),
        preview_mac: String::new(),
        template: None,
        reused: None,
        planned_released: Vec::new(),
    };
    let q = args.question;
    let lang = args.lang;
    let got = tokio::task::spawn_blocking(move || {
        let lex = lock(&snap.open.lexicon);
        question::parameterize(&q, lang, snap.schema(), &lex, &*det)
    })
    .await
    .map_err(|_| join_err())?
    .map_err(|e| shield_err(&e))?;
    let (st, r) = resolved(ctx, &id, st, got, lang0).await;
    store(ctx, &id, st);
    r.map(|s| (id, s))
}

/// `blind.ask.answer`: the user's answer to ask `id`'s step.
pub async fn step(
    ctx: &Arc<Ctx>,
    peer: &PeerCred,
    id: &str,
    a: AskAnswer,
) -> Result<Step, Refusal> {
    let st = {
        let mut asks = lock(&ctx.blind.asks);
        asks.sweep(Instant::now());
        asks.take(id, peer.uid)?
    };
    let _w = Working {
        blind: Arc::clone(&ctx.blind),
        id: id.to_string(),
    };
    let mut st = st;
    st.peer = peer.clone();
    // R-C12: the role and the dataset's place in policy, again; a lost
    // one ends the ask (it is not stored again).
    still_allowed(ctx, id, &st).await?;
    let (st, r) = advance(ctx, id, st, a).await;
    store(ctx, id, st);
    r
}

/// R-C12: `st.peer` may still ask `st.dataset`, which is still in policy.
/// Otherwise a `blind_check_refused` record (fixed reason) and `forbidden`;
/// the caller drops the ask. The ask keeps running on its held build
/// (P47-37); only the authorization is current.
async fn still_allowed(ctx: &Ctx, id: &str, st: &AskState) -> Result<(), Refusal> {
    allowed(ctx, id, &Asker::of(st), false).await
}

/// R-C12 for a touch commit on ask `id` of `peer` (plan 48 T3): the
/// dataset is still in policy and `peer` still may ask it (`approver`: is
/// still its approver). On a failure the ask ends (dropped, unless a step
/// holds it), a `blind_check_refused` record is written and the answer is
/// `forbidden`.
pub(crate) async fn recheck(
    ctx: &Ctx,
    id: &str,
    peer: &PeerCred,
    approver: bool,
) -> Result<(), Refusal> {
    let mut w = lock(&ctx.blind.asks).peek(id, peer.uid, Asker::of)?;
    w.peer = peer.clone();
    if let Err(r) = allowed(ctx, id, &w, approver).await {
        lock(&ctx.blind.asks).forget(id, peer.uid);
        return Err(r);
    }
    Ok(())
}

/// Who an ask belongs to, as R-C12 checks it (a copy: the check awaits).
struct Asker {
    uid: u32,
    dataset: DatasetName,
    peer: PeerCred,
    snapshot: Arc<LiveSnapshot>,
}

impl Asker {
    fn of(st: &AskState) -> Asker {
        Asker {
            uid: st.uid,
            dataset: st.dataset.clone(),
            peer: st.peer.clone(),
            snapshot: Arc::clone(&st.snapshot),
        }
    }
}

/// [`still_allowed`] on a copy of the ask's owner (`approver`: the
/// approver role, not only `may_ask`).
async fn allowed(ctx: &Ctx, id: &str, w: &Asker, approver: bool) -> Result<(), Refusal> {
    let in_policy = ctx
        .policy()
        .system
        .as_ref()
        .is_some_and(|s| s.blind.dataset.iter().any(|d| d.name == w.dataset.as_str()));
    let has_role = in_policy && {
        let r = super::ops::role_of(ctx, &w.peer, &w.dataset).await;
        if approver {
            r.approver
        } else {
            r.may_ask()
        }
    };
    let why = if !in_policy {
        Some(("dataset_not_in_policy", DATASET_GONE))
    } else if !has_role {
        Some((
            "role_lost",
            if approver { APPROVER_LOST } else { ROLE_LOST },
        ))
    } else {
        None
    };
    let Some((reason, text)) = why else {
        return Ok(());
    };
    let r = BlindRecord::CheckRefused {
        ask: id.to_string(),
        reason: reason.to_string(),
    };
    if audit::write(
        ctx,
        w.uid,
        w.dataset.as_str(),
        r,
        w.snapshot.open.index.as_ref(),
    )
    .await
    .is_err()
    {
        eprintln!("saiifed: blind: an ask ended by a policy change was not recorded");
    }
    Err(Refusal::new(ErrorCode::Forbidden, text))
}

/// R-C12, after a policy reload: every kept ask whose asker lost the role
/// (or whose dataset left policy) is dropped, with its refusal record.
/// Asks in flight are checked by their next step or planner call. The
/// asks stay in the map while their copies are checked (T1 re-review
/// RR1): a step meanwhile finds its ask, and the open-ask limits hold;
/// only the asks that failed are removed afterwards.
pub async fn policy_reloaded(ctx: &Arc<Ctx>) {
    let kept: Vec<(String, Asker)> = {
        let mut a = lock(&ctx.blind.asks);
        a.sweep(Instant::now());
        a.map
            .iter()
            .map(|(id, st)| (id.clone(), Asker::of(st)))
            .collect()
    };
    let mut gone = Vec::new();
    for (id, w) in kept {
        if allowed(ctx, &id, &w, false).await.is_err() {
            gone.push((id, w.uid));
        }
    }
    let mut a = lock(&ctx.blind.asks);
    for (id, uid) in gone {
        // A step that took the ask meanwhile checks it again itself.
        if a.map.get(&id).is_some_and(|s| s.uid == uid) {
            a.map.remove(&id);
        }
    }
}

fn misfit() -> Refusal {
    bad("that answer does not fit this step of the ask")
}

/// One answer applied.
async fn advance(
    ctx: &Arc<Ctx>,
    id: &str,
    mut st: AskState,
    a: AskAnswer,
) -> (AskState, Result<Step, Refusal>) {
    match std::mem::replace(&mut st.phase, AskPhase::Done) {
        AskPhase::Resolving(d) => {
            let lang = d.lang;
            let fit = match (d.pending.first(), a) {
                (
                    Some(Pending::Pick {
                        param, candidates, ..
                    }),
                    AskAnswer::Pick(n),
                ) if n <= candidates.len() => {
                    let c = n.checked_sub(1).and_then(|i| candidates.get(i));
                    if let Some(c) = c {
                        st.chosen.push((param.clone(), c.clone()));
                    }
                    Some(question::Answer::Pick(n))
                }
                (
                    Some(Pending::DidYouMean {
                        param, suggestion, ..
                    }),
                    AskAnswer::DidYouMean(yes),
                ) => {
                    if yes {
                        st.chosen.push((param.clone(), suggestion.clone()));
                    }
                    Some(question::Answer::DidYouMean(yes))
                }
                (Some(Pending::KeepName { .. }), AskAnswer::KeepNameNo) => {
                    Some(question::Answer::KeepName(false))
                }
                (Some(Pending::KeepName { name, .. }), AskAnswer::KeepNameTouched) => {
                    st.released.push(name.clone());
                    st.counts.kept_names += 1;
                    Some(question::Answer::KeepName(true))
                }
                _ => None,
            };
            let Some(qa) = fit else {
                st.phase = AskPhase::Resolving(d);
                return (st, Err(misfit()));
            };
            let snap = Arc::clone(&st.snapshot);
            let got = tokio::task::spawn_blocking(move || {
                let lex = lock(&snap.open.lexicon);
                question::answer(d, qa, &lex)
            })
            .await;
            match got {
                Ok(Ok(s)) => resolved(ctx, id, st, s, lang).await,
                Ok(Err(e)) => (st, Err(shield_err(&e))),
                Err(_) => (st, Err(join_err())),
            }
        }
        p @ AskPhase::Previewing { .. } => {
            st.phase = p;
            match a {
                AskAnswer::Run(go) => run::run_or_stop(ctx, id, st, go, true).await,
                _ => (st, Err(misfit())),
            }
        }
        p => {
            st.phase = p;
            (st, Err(misfit()))
        }
    }
}

/// After a resolution step: the next question for the user, a refusal, or
/// (draft ready) the method and its preview.
async fn resolved(
    ctx: &Arc<Ctx>,
    id: &str,
    mut st: AskState,
    s: question::Step,
    lang0: Lang,
) -> (AskState, Result<Step, Refusal>) {
    match s {
        question::Step::Ask(d) => {
            note_params(&mut st, &d);
            let schema = st.snapshot.schema();
            match pending_step(&mut st.counts, &d, schema) {
                Some(step) => {
                    st.phase = AskPhase::Resolving(d);
                    (st, Ok(step))
                }
                None => (
                    st,
                    Err(shield_err(&ShieldError::Corrupt("no pending step"))),
                ),
            }
        }
        question::Step::Ready(d) => {
            note_params(&mut st, &d);
            if let Err(e) = record_resolve(ctx, id, &st).await {
                return (st, Err(e));
            }
            proceed(ctx, id, st, d).await
        }
        question::Step::Refuse(r) => {
            if let Err(e) = record_resolve(ctx, id, &st).await {
                return (st, Err(e));
            }
            let step = question_refusal(r, lang0, &st.dataset);
            (st, Ok(step))
        }
    }
}

fn note_params(st: &mut AskState, d: &Draft) {
    st.counts.seen = d
        .params
        .iter()
        .map(|p| (p.name.clone(), p.ty.tag(), p.bound.is_some()))
        .collect();
}

/// The step that shows `d.pending[0]`.
fn pending_step(counts: &mut Counts, d: &Draft, schema: &Schema) -> Option<Step> {
    match d.pending.first()? {
        Pending::Pick {
            param,
            word,
            candidates,
            too_many,
        } => {
            counts.picks.insert(
                param.clone(),
                u32::try_from(candidates.len()).unwrap_or(u32::MAX),
            );
            let written = d
                .params
                .iter()
                .find(|p| p.name == *param)
                .map(|p| p.display.clone())
                .unwrap_or_default();
            Some(Step::Pick {
                word: word.clone(),
                written,
                candidates: candidates
                    .iter()
                    .enumerate()
                    .map(|(i, c)| PickItem {
                        n: i + 1,
                        label: entity_label(c, schema),
                    })
                    .collect(),
                too_many: *too_many,
            })
        }
        Pending::DidYouMean {
            word,
            written,
            suggestion,
            ..
        } => {
            counts.did_you_mean += 1;
            Some(did_you_mean_step(word, written, suggestion, schema))
        }
        Pending::KeepName { name, .. } => Some(Step::KeepName { name: name.clone() }),
    }
}

/// A resolution refusal as the user sees it (nothing was sent).
fn question_refusal(r: question::Refusal, lang: Lang, ds: &DatasetName) -> Step {
    let head = head_nothing_sent(lang);
    match r {
        question::Refusal::NoMatch { word, written } => Step::refused(
            code::NO_MATCH,
            head,
            match lang {
                Lang::En => format!("no {word} named \"{written}\""),
                Lang::Da => format!("ingen {word} ved navn \"{written}\""),
            },
        ),
        question::Refusal::BadLiteral { why, .. } => Step::refused(code::BAD_LITERAL, head, why),
        question::Refusal::NameRefused { name } => Step::refused(
            code::NAME_REFUSED,
            head,
            format!(
                "\"{name}\" is not in {ds} and was not sent; ask without it, or check the spelling"
            ),
        ),
        question::Refusal::TooMany { word } => Step::refused(
            code::TOO_MANY,
            head,
            format!("more than {MAX_CANDIDATES} of that {word} name; write more of the name"),
        ),
        question::Refusal::Detector(t) => Step::refused(code::DETECTOR, head, t),
    }
}

/// Writes `r`; a failure is `unavailable` with `failed`, a text that is
/// true at that point (I3: once a request left, never "nothing was sent").
async fn record(
    ctx: &Ctx,
    st: &AskState,
    r: BlindRecord,
    failed: &'static str,
) -> Result<(), Refusal> {
    audit::write(
        ctx,
        st.uid,
        st.dataset.as_str(),
        r,
        st.snapshot.open.index.as_ref(),
    )
    .await
    .map_err(|_| unavailable(failed))
}

/// `blind_resolve`: each parameter's tag and candidate count (a picked
/// one: its list's length; a bound one: 1; else 0).
async fn record_resolve(ctx: &Ctx, id: &str, st: &AskState) -> Result<(), Refusal> {
    let c = &st.counts;
    let params = c
        .seen
        .iter()
        .map(|(n, tag, bound)| {
            (
                tag.clone(),
                c.picks.get(n).copied().unwrap_or(u32::from(*bound)),
            )
        })
        .collect();
    let r = BlindRecord::Resolve {
        ask: id.to_string(),
        params,
        did_you_mean: c.did_you_mean,
        kept_names: c.kept_names,
    };
    record(ctx, st, r, UNRECORDED_NOTHING_SENT).await
}

/// The `blind_ask` record (the question with its stand-ins, R44-4).
async fn record_ask(
    ctx: &Arc<Ctx>,
    id: &str,
    st: &AskState,
    d: &Draft,
    approved: Option<String>,
) -> Result<(), Refusal> {
    let keys = load_keys(ctx, &st.dataset).await?;
    let schema = st.snapshot.schema();
    let (question, session) = {
        let mut ss = lock(&ctx.blind.sessions);
        let s = ss
            .get_or_new(
                st.uid,
                &st.dataset,
                &keys,
                unix_now(),
                st.opts.session,
                false,
            )
            .map_err(|e| shield_err(&e))?;
        // A name a `blind:name` touch kept (this ask's or an earlier turn's)
        // is logged by its keyed hash only (`blind_name`, plan 48 T3).
        let mut kept = s.released_names();
        kept.extend(st.released.iter().cloned());
        let q = saiife_shield::envelope::mask_released(&logged_question(d, s, schema), &kept);
        (q, crate::api_ops::hex(&s.id.0))
    };
    let r = BlindRecord::Ask {
        ask: id.to_string(),
        dataset: st.dataset.to_string(),
        lang: d.lang,
        question,
        session,
        approved_method: approved,
    };
    record(ctx, st, r, UNRECORDED_NOTHING_SENT).await
}

/// The dataset's active approved method for this template and these
/// parameter types (R45-11), if any.
async fn approved_for(
    ctx: &Arc<Ctx>,
    st: &AskState,
    lang: Lang,
    key: String,
    tags: Vec<String>,
) -> Result<Option<ApprovedMethod>, Refusal> {
    let path = ctx
        .blind
        .dataset_dir(&st.dataset)
        .root
        .join(data::METHODS_FILE);
    let ds = st.dataset.clone();
    let name = ds.to_string();
    tokio::task::spawn_blocking(move || {
        let store = MethodStore::load(&path)
            .map_err(|_| unavailable(format!("the methods file of {name} cannot be read")))?;
        Ok(store.find(&ds, lang, &key, &tags).cloned())
    })
    .await
    .map_err(|_| join_err())?
}

/// A reply's method, self-checks and template against the draft (R48-2:
/// any error here goes back to the planner). The template is parsed
/// against the method's output names, then every bound parameter must be
/// used (ruling F-f).
fn check_reply(
    r: &PlanReply,
    schema: &Schema,
    public: &[PublicValues],
    params: &[Param],
    list_cap: u32,
) -> Result<Validated, MethodError> {
    let v = validate(&r.method, schema, public, params)?;
    for c in &r.checks {
        validate_check(c, schema, public, params)?;
    }
    let t = parse_template(&r.template, &v.output_columns(), params, list_cap)?;
    check_params_covered(&v, &t, params)?;
    Ok(v)
}

/// R48-9: what a firewall hit would have sent, in words.
fn hit_words(h: &Hit) -> &'static str {
    match h.kind {
        firewall::KNOWN_VALUE | firewall::KNOWN_PHRASE => "a value of the dataset",
        firewall::NUMBER => "a number",
        firewall::EMAIL => "an email address",
        firewall::PHONE => "a phone number",
        firewall::IBAN => "an account number",
        firewall::CPR => "a CPR number",
        firewall::BIRTH_DATE => "a birth date",
        firewall::NAME => "a name",
        firewall::OVERSIZE => "too much text",
        _ => "a part that is not allowed",
    }
}

/// A planner failure as the user sees it. `sent_before`: an earlier
/// request of this ask left the machine, so no head may say nothing was
/// sent (I3); R48-9's reason still speaks of this request only.
/// Unreachable and timeout are unavailable (R-C9); an unrecorded request
/// was not sent, an unrecorded reply was not used (R-C9a).
fn plan_error(e: PlanError, lang: Lang, sent_before: bool) -> Result<Step, Refusal> {
    let head = if sent_before {
        head_no_answer(lang)
    } else {
        head_nothing_sent(lang)
    };
    match e {
        PlanError::Unreachable | PlanError::Timeout => Err(unavailable(e.to_string())),
        PlanError::Unrecorded(t) if sent_before => Ok(Step::refused(
            code::UNRECORDED,
            head,
            format!("{t}; this request was not sent"),
        )),
        PlanError::Unrecorded(t) => Ok(Step::refused(
            code::UNRECORDED,
            head,
            format!("{t}; nothing left this machine"),
        )),
        PlanError::ReplyUnrecorded => Ok(Step::refused(
            code::UNRECORDED,
            head_no_answer(lang),
            model::REPLY_UNRECORDED,
        )),
        PlanError::Blocked(h) => {
            let (what, part) = h
                .first()
                .map_or(("a part that is not allowed", "envelope"), |h| {
                    (hit_words(h), h.part.as_str())
                });
            Ok(Step::refused(
                code::BLOCKED,
                head,
                format!(
                    "this would send {what} ({part}); nothing was sent. Rephrase the question, \
                     or ask without the name"
                ),
            ))
        }
        PlanError::Leak(_) => Ok(Step::refused(
            code::LEAK,
            head_no_answer(lang),
            e.to_string(),
        )),
        e => Ok(Step::refused(
            code::PLANNER,
            head_no_answer(lang),
            e.to_string(),
        )),
    }
}

/// A ready draft: an approved method, else the planner (with retries),
/// then the preview.
async fn proceed(
    ctx: &Arc<Ctx>,
    id: &str,
    st: AskState,
    d: Draft,
) -> (AskState, Result<Step, Refusal>) {
    let snap = Arc::clone(&st.snapshot);
    let schema = snap.schema();
    let public = snap.manifest.public.as_slice();
    let list_cap = st.opts.list_cap;
    let (key, tags) = question::template_key(&d);
    let mut st = st;
    st.template = Some((key.clone(), tags.clone()));
    let found = match approved_for(ctx, &st, d.lang, key, tags).await {
        Ok(f) => f,
        Err(e) => return (st, Err(e)),
    };
    // Reuse (R45-11): no cloud call; a method that no longer validates for
    // this draft is not used.
    // A method that binds a context symbol (R44-5) is tied to the session
    // it was planned in: never reused.
    if let Some(m) = found.filter(|m| m.reply.context.is_empty()) {
        if let Ok(v) = check_reply(&m.reply, schema, public, &d.params, list_cap) {
            if let Err(e) = record_ask(ctx, id, &st, &d, Some(m.id.clone())).await {
                return (st, Err(e));
            }
            return finish_preview(
                ctx,
                id,
                st,
                d,
                v,
                m.reply,
                Some(m.id),
                Sent::default(),
                None,
            )
            .await;
        }
    }
    if let Err(e) = record_ask(ctx, id, &st, &d, None).await {
        return (st, Err(e));
    }
    let det = match detector(ctx) {
        Ok(d) => d,
        Err(e) => return (st, Err(e)),
    };
    let Some(index) = snap.open.index.as_ref() else {
        return (st, Err(unavailable("the dataset has no known-value index")));
    };
    let planner = model::planner(ctx);
    let cloud = cloud_schema(schema, public);
    let schema_hash = schema_sha256(&cloud);
    // (the method received, its retry class): kept locally, sent by hash.
    let mut prev: Option<(String, String)> = None;
    let mut last: Option<MethodError> = None;
    for _ in 0..MAX_TRIES {
        // R-C12: a policy change during a long step stops the next call.
        if let Err(r) = still_allowed(ctx, id, &st).await {
            return (st, Err(r));
        }
        let keys = match load_keys(ctx, &st.dataset).await {
            Ok(k) => k,
            Err(e) => return (st, Err(e)),
        };
        let synth = synthetic_rows(
            schema,
            &snap.manifest.formats,
            public,
            SYNTHETIC_PER_TABLE,
            &mut os_rng(),
        );
        let synth_hash = synthetic_sha256(&synth);
        let retry = prev.as_ref().map(|(m, c)| Retry::new(m, c));
        let prev_hash = prev.as_ref().map(|(m, _)| method_sha256(m));
        let built = {
            let mut ss = lock(&ctx.blind.sessions);
            ss.get_or_new(
                st.uid,
                &st.dataset,
                &keys,
                unix_now(),
                st.opts.session,
                false,
            )
            .map(|s| {
                let env = build_envelope(&d, s, schema, public, synth, list_cap, retry);
                // The context as sent: what a reply may refer to (R44-5).
                let known = s.context_entities();
                (env, s.issued_symbols(), s.released_names(), known)
            })
        };
        drop(keys);
        let (env, symbols, mut released, known) = match built {
            Ok(b) => b,
            Err(e) => return (st, Err(shield_err(&e))),
        };
        released.extend(st.released.iter().cloned());
        st.planned_released.clone_from(&released);
        let fw = Firewall {
            index,
            allow: &snap.open.allow,
            detector: &*det,
            released_names: &released,
            expected: Expected {
                list_cap,
                lang: d.lang,
                schema_sha256: &schema_hash,
                synthetic_sha256: &synth_hash,
                symbols: &symbols,
                previous_method_sha256: prev_hash.as_deref(),
            },
        };
        let got = planner.plan(ctx, st.uid, id, &st.dataset, &env, &fw).await;
        let reply = match got {
            Ok(r) => r,
            Err(e) => return (st, plan_error(e, d.lang, prev.is_some())),
        };
        if reply.needs_judgment {
            return (
                st,
                Ok(Step::refused(
                    code::NEEDS_JUDGMENT,
                    head_no_answer(d.lang),
                    JUDGMENT,
                )),
            );
        }
        // R44-5: the reply's context references become parameters bound to
        // the keys of this session's earlier turns; then the usual checks.
        let bound = bind_context(&d, &reply.context, &known, schema).and_then(|d2| {
            check_reply(&reply, schema, public, &d2.params, list_cap).map(|v| (d2, v))
        });
        match bound {
            Ok((d, v)) => {
                let sent = Sent::from(env.summary());
                let envelope = st
                    .opts
                    .show_sent
                    .then(|| String::from_utf8_lossy(&env.canonical()).into_owned());
                return finish_preview(ctx, id, st, d, v, reply, None, sent, envelope).await;
            }
            Err(e) => {
                prev = Some((reply.method.clone(), retry_error_class(&e, &cloud)));
                last = Some(e);
            }
        }
    }
    let class = last.map_or(ErrorClass::Syntax, |e| e.class);
    let step = match class.user_reason() {
        Some(reason) if class == ErrorClass::IdentifierOutput => {
            Step::refused(code::IDENTIFIER_OUTPUT, head_no_answer(d.lang), reason)
        }
        _ => Step::refused(
            code::INVALID_METHOD,
            head_no_answer(d.lang),
            format!(
                "the planner's method was not valid after {MAX_TRIES} tries ({})",
                class.as_str()
            ),
        ),
    };
    (st, Ok(step))
}

/// The preview step and record; the ask waits for Run or Stop.
#[allow(clippy::too_many_arguments)]
async fn finish_preview(
    ctx: &Arc<Ctx>,
    id: &str,
    mut st: AskState,
    d: Draft,
    v: Validated,
    reply: PlanReply,
    approved: Option<String>,
    sent: Sent,
    envelope: Option<String>,
) -> (AskState, Result<Step, Refusal>) {
    let snap = Arc::clone(&st.snapshot);
    let chosen = st.chosen.clone();
    let d2 = d.clone();
    let params = match tokio::task::spawn_blocking(move || {
        let lex = lock(&snap.open.lexicon);
        // The lexicon's records for the user's words (R-C2); a lookup
        // that fails finds none, so the words show alone.
        let lookup = |table: &str, words: &str| match lex.resolve(table, words) {
            Ok((Resolve::One(c), _)) => vec![c],
            Ok((Resolve::Many(cs), _)) => cs,
            _ => Vec::new(),
        };
        preview_params(&d2, snap.schema(), &chosen, &lookup)
    })
    .await
    {
        Ok(p) => p,
        Err(_) => return (st, Err(join_err())),
    };
    let p = preview(&v, &params, st.snapshot.schema(), d.lang);
    let says = if approved.is_some() {
        None
    } else {
        intent_line(&reply.intent, d.lang)
    };
    // `--yes` (R48-3): the preview is not waited for; it is recorded as
    // `auto` and becomes the answer's method line.
    let outcome = if st.opts.yes { "auto" } else { "shown" };
    // Keyed (T2 review I2): the preview holds the user's words.
    st.preview_mac = match load_keys(ctx, &st.dataset).await {
        Ok(k) => audit::preview_mac(&k.index_key(), &p.text),
        Err(e) => return (st, Err(e)),
    };
    let r = run::preview_record(id, &st.preview_mac, &p, outcome);
    // Reuse sent nothing; the planner path asked the planner.
    let failed = if approved.is_some() {
        UNRECORDED_NOTHING_SENT
    } else {
        PREVIEW_UNRECORDED
    };
    if let Err(e) = record(ctx, &st, r, failed).await {
        return (st, Err(e));
    }
    let step = Step::Preview {
        text: p.text.clone(),
        planner_says: says,
        approved: approved.clone(),
        sent,
        envelope,
    };
    st.sent = sent;
    st.reused = approved.clone();
    st.phase = AskPhase::Previewing {
        draft: d,
        validated: v,
        reply,
        preview: p,
        approved,
    };
    if st.opts.yes {
        return run::run_or_stop(ctx, id, st, true, false).await;
    }
    (st, Ok(step))
}

// --------------------------------------------------------------- ops ----

/// `blind.ask {question, dataset?, lang?, new_session?, yes?, limit?,
/// show_sent?, judgment?}` -> `{ask, step}`.
pub async fn begin_op(
    ctx: &Arc<Ctx>,
    peer: &PeerCred,
    args: &Map<String, Value>,
) -> Result<Value, Refusal> {
    let a = AskArgs::from_args(args)?;
    let (id, s) = begin(ctx, peer, a).await?;
    Ok(json!({"ask": id, "step": s.to_value()}))
}

/// `blind.ask.answer {ask, answer}` -> `{ask, step}`.
pub async fn answer_op(
    ctx: &Arc<Ctx>,
    peer: &PeerCred,
    args: &Map<String, Value>,
) -> Result<Value, Refusal> {
    let id = args
        .get("ask")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("ask is required"))?;
    let a = parse_answer(args.get("answer"))?;
    let s = step(ctx, peer, id, a).await?;
    Ok(json!({"ask": id, "step": s.to_value()}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_parse() {
        let p = |v: Value| parse_answer(Some(&v));
        assert_eq!(p(json!({"pick": 2})).unwrap(), AskAnswer::Pick(2));
        assert_eq!(p(json!({"pick": 0})).unwrap(), AskAnswer::Pick(0));
        assert_eq!(
            p(json!({"did_you_mean": false})).unwrap(),
            AskAnswer::DidYouMean(false)
        );
        assert_eq!(
            p(json!({"keep_name": false})).unwrap(),
            AskAnswer::KeepNameNo
        );
        assert_eq!(p(json!({"run": true})).unwrap(), AskAnswer::Run(true));
        let r = p(json!({"keep_name": true})).unwrap_err();
        assert_eq!(
            (r.code, r.text.as_str()),
            (ErrorCode::BadRequest, KEEP_NEEDS_TOUCH)
        );
        for v in [
            json!({}),
            json!({"pick": -1}),
            json!({"pick": "1"}),
            json!({"pick": 1, "run": true}),
            json!({"did_you_mean": 1}),
            json!({"reveal": true}),
            json!([1]),
        ] {
            assert_eq!(p(v.clone()).unwrap_err().code, ErrorCode::BadRequest, "{v}");
        }
        assert!(parse_answer(None).is_err());
    }

    #[test]
    fn steps_serialize_by_kind() {
        let s = Step::refused(code::NO_MATCH, "h", "r");
        assert_eq!(
            s.to_value(),
            json!({"kind": "refused", "code": "no_match", "head": "h", "reason": "r"})
        );
        assert_eq!(format!("{s:?}"), "Step::Refused(no_match)");
        let s = Step::Preview {
            text: "I'm counting.".into(),
            planner_says: None,
            approved: None,
            sent: Sent::default(),
            envelope: None,
        };
        assert_eq!(
            s.to_value(),
            json!({"kind": "preview", "text": "I'm counting.",
                   "sent": {"tables": 0, "synthetic_rows": 0, "params": 0, "personal_values": 0}})
        );
        assert_eq!(format!("{s:?}"), "Step::preview");
        assert_eq!(
            Step::Refreshing { text: "x".into() }.to_value(),
            json!({"kind": "refreshing", "text": "x"})
        );
    }

    #[test]
    fn plan_errors_map() {
        let r = plan_error(PlanError::Unreachable, Lang::En, false).unwrap_err();
        assert_eq!(r.code, ErrorCode::Unavailable);
        let unrec = || PlanError::Unrecorded("the request could not be recorded".into());
        // R-C9a: an unrecorded request before anything left.
        let s = plan_error(unrec(), Lang::En, false).unwrap().to_value();
        assert_eq!(
            s["reason"],
            "the request could not be recorded; nothing left this machine"
        );
        assert_eq!(s["head"], "refused, nothing sent");
        // I3: an earlier request of the ask had left.
        let s = plan_error(unrec(), Lang::En, true).unwrap().to_value();
        assert_eq!(
            s["reason"],
            "the request could not be recorded; this request was not sent"
        );
        assert_eq!(s["head"], head_no_answer(Lang::En));
        // R-C9a: an unrecorded reply was sent and not used.
        for before in [false, true] {
            let s = plan_error(PlanError::ReplyUnrecorded, Lang::En, before)
                .unwrap()
                .to_value();
            assert_eq!(s["code"], code::UNRECORDED);
            assert_eq!(s["head"], head_no_answer(Lang::En));
            assert_eq!(
                s["reason"],
                "the planner's reply could not be recorded, so it was not used"
            );
            assert!(!s.to_string().contains("nothing"), "{s}");
        }
        let blocked = || {
            PlanError::Blocked(vec![Hit {
                kind: firewall::NAME,
                part: "question".into(),
                span: Some((0, 3)),
            }])
        };
        let s = plan_error(blocked(), Lang::En, false).unwrap().to_value();
        assert_eq!(
            s["reason"],
            "this would send a name (question); nothing was sent. Rephrase the question, or ask \
             without the name"
        );
        assert_eq!(s["head"], "refused, nothing sent");
        // I3: the head is truthful on a retry; R48-9's reason is this try's.
        let s = plan_error(blocked(), Lang::En, true).unwrap().to_value();
        assert_eq!(s["head"], head_no_answer(Lang::En));
        let s = plan_error(PlanError::Refused, Lang::Da, false).unwrap();
        assert_eq!(s.to_value()["code"], code::PLANNER);
        assert_eq!(s.to_value()["head"], head_no_answer(Lang::Da));
    }

    #[test]
    fn record_failure_texts_are_truthful() {
        assert!(UNRECORDED_NOTHING_SENT.contains("nothing was sent"));
        assert!(!PREVIEW_UNRECORDED.contains("nothing"));
    }

    #[test]
    fn ask_args_parse() {
        let m = |v: Value| match v {
            Value::Object(m) => m,
            _ => unreachable!(),
        };
        let a = AskArgs::from_args(&m(json!({"question": "q", "lang": "da", "limit": 5,
            "yes": true, "show_sent": true, "new_session": true, "judgment": false})))
        .unwrap();
        assert_eq!(a.lang, Some(Lang::Da));
        assert_eq!(a.limit, Some(5));
        assert!(a.yes && a.show_sent && a.new_session && !a.judgment);
        assert!(!format!("{a:?}").contains("\"q\""));
        for v in [
            json!({"question": "q", "yes": "true"}),
            json!({"question": "q", "limit": -1}),
            json!({"question": "q", "dataset": 3}),
        ] {
            assert!(AskArgs::from_args(&m(v.clone())).is_err(), "{v}");
        }
    }
}
