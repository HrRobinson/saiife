//! The Data Shield touches (plan 48 Task 3; R48-6, R48-8, R-C5, R-C12;
//! spec §2.1.4, §2.1.7, §2.3.5, §6.3): `blind.touch.begin` and
//! `blind.touch.commit`, on the same begin/assert/commit pattern as
//! `box.land` (`box_land.rs`).
//!
//! `begin` checks the role first (before any challenge), then what the
//! touch is for, then that the caller has a device, and issues
//! [`IssueKey::Blind`] for a random request id. The action record is the
//! daemon's own: built at begin from the issued entry's nonce and expiry,
//! never from the client. The purposes:
//!
//! | purpose | class | who | what the commit does |
//! |---|---|---|---|
//! | `name {ask, name}` | `blind:name` | the asker | `blind_name`, then the ask goes on as if `keep_name: true` |
//! | `approve {ask}` | `blind:approve` | an approver who asked it | `MethodStore::add`, `blind_approve {add}` |
//! | `method_rm {dataset, id}` | `blind:approve` | an approver | the method removed, `blind_approve {remove}` |
//! | `keys {dataset, action}` | `blind:keys` | an approver or admin | `blind_keys`, then `keys::rotate` / `keys::shred` |
//! | `loosen {dataset, column, to}` | `blind:loosen` | an approver or admin | `blind_loosen`, then the grant in `loosen.json` |
//!
//! There is no `blind:reveal` or `blind:show` purpose here (R-C5: plan
//! 49's). A touch is bound to the uid it was issued to and is burned when
//! its owner commits it, whatever the outcome; another uid's commit is
//! `touch_mismatch` and leaves it. Every commit checks the role and the
//! dataset's place in policy again (R-C12): a policy reload between begin
//! and commit may have taken them. The record of an action is written
//! before the action (an action that cannot be recorded does not happen);
//! the approval, whose id the store gives, is undone when its record
//! fails.

use super::ask::{self, AskAnswer, ForApprove};
use super::audit::{self, BlindRecord};
use super::data::{self, LoosenGrant};
use super::{keys, lock, Refusal};
use crate::ops::Ctx;
use crate::touch::{unix_now, IssueKey};
use saiife_ipc::msg::{err_with, ErrorCode};
use saiife_ipc::peer::PeerCred;
use saiife_shield::envelope::method_sha256;
use saiife_shield::index::KnownIndex;
use saiife_shield::methods::{ApprovedMethod, MethodStatus, MethodStore};
use saiife_shield::schema::{ColumnClass, DatasetName};
use saiife_touch::{ActionRecord, Assertion, TouchClass, TouchError, TouchEvidence};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

/// A touch begun and not yet committed, by request id. `Debug` prints no
/// name or column.
#[derive(Default)]
pub struct Touches {
    map: BTreeMap<u64, Pending>,
}

impl std::fmt::Debug for Touches {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Touches")
            .field("pending", &self.map.len())
            .finish()
    }
}

impl Touches {
    pub fn new() -> Touches {
        Touches::default()
    }

    /// The touches begun and not yet committed or expired.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn sweep(&mut self, now: u64) {
        self.map.retain(|_, p| p.record.expires_at >= now);
    }
}

struct Pending {
    uid: u32,
    dataset: DatasetName,
    record: ActionRecord,
    action: Action,
}

/// What a commit does; fixed at begin.
enum Action {
    Name {
        ask: String,
        name: String,
    },
    Approve {
        ask: String,
        method_sha256: String,
        template_key: String,
        preview_mac: String,
    },
    MethodRm {
        id: String,
    },
    Keys {
        delete: bool,
    },
    Loosen {
        column: String,
        from: ColumnClass,
        to: ColumnClass,
    },
}

impl Action {
    fn purpose(&self) -> &'static str {
        match self {
            Action::Name { .. } => "name",
            Action::Approve { .. } => "approve",
            Action::MethodRm { .. } => "method_rm",
            Action::Keys { .. } => "keys",
            Action::Loosen { .. } => "loosen",
        }
    }
}

/// Why a touch op refused: an ordinary refusal, or a touch that did not
/// verify (`rule`: `touch_expired`, `touch_mismatch`, `touch_unavailable`
/// or `touch_failed`), answered `forbidden` with the rule.
#[derive(Debug)]
pub enum Failure {
    Refused(Refusal),
    Touch { rule: &'static str, text: String },
}

impl From<Refusal> for Failure {
    fn from(r: Refusal) -> Failure {
        Failure::Refused(r)
    }
}

impl Failure {
    fn touch(e: TouchError) -> Failure {
        let rule = match e {
            TouchError::Expired => "touch_expired",
            TouchError::Mismatch | TouchError::UnknownCredential => "touch_mismatch",
            TouchError::Unavailable => "touch_unavailable",
            _ => "touch_failed",
        };
        Failure::Touch {
            rule,
            text: e.to_string(),
        }
    }

    fn mismatch(text: impl Into<String>) -> Failure {
        Failure::Touch {
            rule: "touch_mismatch",
            text: text.into(),
        }
    }

    /// The error answer of request `id`.
    pub fn to_value(&self, id: u64) -> Value {
        match self {
            Failure::Refused(r) => r.to_value(id),
            Failure::Touch { rule, text } => {
                let mut m = Map::new();
                m.insert("rule".into(), (*rule).into());
                let msg = if *rule == "touch_unavailable" && text.starts_with("refused: ") {
                    text.clone()
                } else {
                    format!("refused ({rule}): {text}")
                };
                err_with(id, ErrorCode::Forbidden, &msg, m)
            }
        }
    }
}

fn bad(text: impl Into<String>) -> Refusal {
    Refusal::new(ErrorCode::BadRequest, text)
}

fn unavailable(text: impl Into<String>) -> Refusal {
    Refusal::new(ErrorCode::Unavailable, text)
}

fn join_err() -> Refusal {
    unavailable("the touch could not go on: a local step stopped")
}

fn str_arg<'a>(a: &'a Map<String, Value>, k: &str) -> Result<&'a str, Refusal> {
    a.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| bad(format!("{k} is required")))
}

fn dataset_arg(a: &Map<String, Value>) -> Result<DatasetName, Refusal> {
    str_arg(a, "dataset")?
        .parse()
        .map_err(|_| bad("not a dataset name"))
}

/// The no-device text (plan 48 Task 3).
pub fn no_device_text(purpose: &str, class: TouchClass) -> String {
    format!(
        "refused: {purpose} needs a touch ({}) and no touch device is enrolled for you: saiife touch enrol",
        class.name()
    )
}

/// The touch text when the ask changed between begin and commit.
pub const ASK_CHANGED: &str = "the ask changed after the touch began; nothing was done";
/// `approve` of an ask that has no checked answer.
pub const NOT_ANSWERED: &str =
    "only an ask that ended with a checked answer can be approved; this one has not";
/// `approve` of a method that binds a symbol of an earlier question (T2 I1).
pub const USES_CONTEXT: &str = "this method refers to someone from an earlier question in the \
     session, so it only works in that session and cannot be approved for reuse; ask again \
     with the name in the question, then approve that";
/// `approve` of an ask that kept a name as plain text (T3 review I1): the
/// name would be saved in the template key, and maybe in the method, and
/// listed by `methods ls`.
pub const KEPT_NAME: &str = "this answer kept a name as plain text, so it cannot be approved \
     for reuse: a kept name is never saved; ask again without keeping the name";
/// The approval was stored but its record failed: undone.
pub const APPROVE_UNRECORDED: &str = "the approval could not be recorded, so it was not kept";
/// A change whose record failed: not made.
pub const ACTION_UNRECORDED: &str = "the change could not be recorded, so it was not made";

/// What role a purpose needs.
#[derive(Clone, Copy)]
enum Need {
    Ask,
    Approver,
    Manage,
}

fn in_policy(ctx: &Ctx, ds: &DatasetName) -> bool {
    ctx.policy()
        .system
        .as_ref()
        .is_some_and(|s| s.blind.dataset.iter().any(|d| d.name == ds.as_str()))
}

async fn has(ctx: &Ctx, peer: &PeerCred, ds: &DatasetName, need: Need) -> bool {
    let r = super::ops::role_of(ctx, peer, ds).await;
    match need {
        Need::Ask => r.may_ask(),
        Need::Approver => r.approver,
        Need::Manage => r.may_manage(),
    }
}

fn role_text(ds: &DatasetName, need: Need) -> String {
    match need {
        Need::Ask => format!("you have no role on {ds}"),
        Need::Approver => format!("only an approver of {ds} may approve or remove its methods"),
        Need::Manage => {
            format!("only an admin or an approver of {ds} may change its keys or classes")
        }
    }
}

/// At begin: the dataset is in policy and the peer has the role.
async fn need_role(
    ctx: &Ctx,
    peer: &PeerCred,
    ds: &DatasetName,
    need: Need,
) -> Result<(), Refusal> {
    if !in_policy(ctx, ds) {
        return Err(bad(format!("{ds} is not in policy")));
    }
    if !has(ctx, peer, ds, need).await {
        return Err(Refusal::new(ErrorCode::Forbidden, role_text(ds, need)));
    }
    Ok(())
}

/// The live build's index (the record scrub), when there is one.
fn live_index(ctx: &Ctx, ds: &DatasetName) -> Option<Arc<super::LiveHandles>> {
    ctx.blind.live(ds).ok().map(|(_, h)| h)
}

async fn record(
    ctx: &Ctx,
    uid: u32,
    ds: &DatasetName,
    r: BlindRecord,
    failed: &str,
) -> Result<(), Refusal> {
    let h = live_index(ctx, ds);
    let index: Option<&KnownIndex> = h.as_ref().and_then(|h| h.index.as_ref());
    audit::write(ctx, uid, ds.as_str(), r, index)
        .await
        .map_err(|_| unavailable(failed))
}

/// A refused touch commit, recorded (fixed texts only).
async fn deny_record(ctx: &Ctx, uid: u32, ds: &DatasetName, purpose: &str, rule: &str, why: &str) {
    let mut rec = ctx.record("blind_touch", &format!("blind_touch {ds}"));
    rec.uid = Some(uid);
    rec.user = ctx.name_of(uid).await;
    rec.decision = saiife_audit::DecisionKind::Deny;
    rec.rule = Some(rule.into());
    rec.reason = Some(why.into());
    rec.extra.insert("dataset".into(), ds.as_str().into());
    rec.extra.insert("purpose".into(), purpose.into());
    if ctx.writer.append(rec).await.is_err() {
        eprintln!("saiifed: blind: a refused touch was not recorded");
    }
}

/// The credential label and new sign count, for `ApprovedMethod::touch`
/// (methods.json is not scrubbed).
fn touch_label(ev: &TouchEvidence) -> String {
    format!("{} #{}", ev.label, ev.sign_count)
}

/// The records' `touch`: the credential id (hex: one token) and the new
/// sign count, `c<n>`. Not the label: a record's strings are scanned
/// against the dataset's known values, and a label (free text) or a bare
/// count (`#1` matches a key 1) would be scrubbed.
fn touch_ref(credential_id: &[u8], ev: &TouchEvidence) -> String {
    format!("{} c{}", crate::api_ops::hex(credential_id), ev.sign_count)
}

fn template_sha256(t: &str) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, t.as_bytes());
    crate::api_ops::hex(d.as_ref())
}

fn new_request_id() -> Result<u64, Refusal> {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).map_err(|_| unavailable("no randomness for a touch request"))?;
    // At most 2^53: an id a JSON number could hold too.
    Ok((u64::from_le_bytes(b) & ((1 << 53) - 1)).max(1))
}

/// A touch request for `rec` to the caller's devices (plan 26's shape).
fn touch_request(rec: &ActionRecord, creds: Vec<saiife_touch::Credential>) -> Value {
    let c = saiife_touch::challenge(rec);
    let tr = saiife_touch::TouchRequest {
        rp_id: saiife_touch::LOCAL_RP_ID.into(),
        challenge: c,
        allow: creds.into_iter().map(|c| c.id).collect(),
        uv: rec.class.needs_uv(),
        summary: rec.summary.clone(),
        short_code: saiife_touch::short_code(&c),
    };
    serde_json::to_value(&tr).unwrap_or(Value::Null)
}

fn parse_class(s: &str) -> Result<ColumnClass, Refusal> {
    serde_json::from_value(Value::String(s.to_string()))
        .map_err(|_| bad("to must be one of identifier, quasi, sensitive, free_text, public"))
}

// ------------------------------------------------------------- begin ----

/// What a begin found: the dataset, the class, the summary and fields of
/// the touch, and the action the commit runs.
struct Plan {
    dataset: DatasetName,
    class: TouchClass,
    summary: String,
    fields: BTreeMap<String, String>,
    action: Action,
}

fn fields(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

async fn plan_name(ctx: &Ctx, peer: &PeerCred, a: &Map<String, Value>) -> Result<Plan, Refusal> {
    let id = str_arg(a, "ask")?.to_string();
    let name = str_arg(a, "name")?.to_string();
    let (ds, pending) = lock(&ctx.blind.asks).peek(&id, peer.uid, |s| {
        (s.dataset.clone(), s.keep_name_pending().map(str::to_string))
    })?;
    need_role(ctx, peer, &ds, Need::Ask).await?;
    if pending.as_deref() != Some(name.as_str()) {
        return Err(bad("this ask is not waiting on keeping that name"));
    }
    Ok(Plan {
        summary: format!("keep \"{name}\" as plain text in a question about {ds}"),
        fields: fields(&[("dataset", ds.as_str()), ("ask", &id)]),
        class: TouchClass::BlindName,
        dataset: ds,
        action: Action::Name { ask: id, name },
    })
}

/// Why an answered ask cannot be approved, if it cannot.
fn approvable(f: &ForApprove) -> Result<(), Refusal> {
    if let Some(m) = &f.reused {
        return Err(bad(format!(
            "this answer came from approved method {m}; it is approved already"
        )));
    }
    if !f.reply.context.is_empty() {
        return Err(bad(USES_CONTEXT));
    }
    if f.kept_name || holds_released(f) {
        return Err(bad(KEPT_NAME));
    }
    Ok(())
}

/// Whether a name released in the session when the method was planned is
/// in anything approve would store (key, method, template, checks,
/// intent): normalized as the index folds names.
fn holds_released(f: &ForApprove) -> bool {
    use saiife_shield::norm::normalize;
    // The whole reply as stored (method, template, checks, intent).
    let reply = serde_json::to_string(&f.reply).unwrap_or_default();
    let stored = [normalize(&f.template_key), normalize(&reply)];
    f.released
        .iter()
        .map(|n| normalize(n))
        .any(|n| !n.trim().is_empty() && stored.iter().any(|s| s.contains(n.as_str())))
}

async fn plan_approve(ctx: &Ctx, peer: &PeerCred, a: &Map<String, Value>) -> Result<Plan, Refusal> {
    let id = str_arg(a, "ask")?.to_string();
    let (ds, f) =
        lock(&ctx.blind.asks).peek(&id, peer.uid, |s| (s.dataset.clone(), s.for_approve()))?;
    need_role(ctx, peer, &ds, Need::Approver).await?;
    let f = f.ok_or_else(|| bad(NOT_ANSWERED))?;
    approvable(&f)?;
    let sha = method_sha256(&f.reply.method);
    Ok(Plan {
        summary: format!(
            "approve for reuse: {} · template \"{}\"",
            f.preview_text, f.template_key
        ),
        fields: fields(&[
            ("dataset", ds.as_str()),
            ("template_key", &f.template_key),
            ("method_sha256", &sha),
            ("preview_mac", &f.preview_mac),
        ]),
        class: TouchClass::BlindApprove,
        dataset: ds,
        action: Action::Approve {
            ask: id,
            method_sha256: sha,
            template_key: f.template_key,
            preview_mac: f.preview_mac,
        },
    })
}

async fn load_store(ctx: &Arc<Ctx>, ds: &DatasetName) -> Result<MethodStore, Refusal> {
    let path = ctx.blind.dataset_dir(ds).root.join(data::METHODS_FILE);
    let name = ds.clone();
    tokio::task::spawn_blocking(move || MethodStore::load(&path))
        .await
        .map_err(|_| join_err())?
        .map_err(|_| unavailable(format!("the methods file of {name} cannot be read")))
}

async fn plan_method_rm(
    ctx: &Arc<Ctx>,
    peer: &PeerCred,
    a: &Map<String, Value>,
) -> Result<Plan, Refusal> {
    let ds = dataset_arg(a)?;
    let id = str_arg(a, "id")?.to_string();
    need_role(ctx, peer, &ds, Need::Approver).await?;
    let store = load_store(ctx, &ds).await?;
    let m = store
        .methods
        .iter()
        .find(|m| m.id == id)
        .ok_or_else(|| bad(format!("{ds} has no approved method {id}")))?;
    Ok(Plan {
        summary: format!(
            "remove approved method {id} (template \"{}\") from {ds}",
            m.template_key
        ),
        fields: fields(&[("dataset", ds.as_str()), ("method", &id)]),
        class: TouchClass::BlindApprove,
        dataset: ds,
        action: Action::MethodRm { id },
    })
}

async fn plan_keys(
    ctx: &Arc<Ctx>,
    peer: &PeerCred,
    a: &Map<String, Value>,
) -> Result<Plan, Refusal> {
    let ds = dataset_arg(a)?;
    let delete = match str_arg(a, "action")? {
        "rotate" => false,
        "delete" => true,
        _ => return Err(bad("action must be rotate or delete")),
    };
    need_role(ctx, peer, &ds, Need::Manage).await?;
    if !delete {
        // Rotating needs keys that open now.
        let (c, d) = (Arc::clone(ctx), ds.clone());
        tokio::task::spawn_blocking(move || {
            keys::load(&c, &d).map(|_| ()).map_err(|e| e.refusal(&d))
        })
        .await
        .map_err(|_| join_err())??;
    }
    let summary = if delete {
        format!(
            "delete the keys of {ds}: its stand-ins can never be linked back to anyone, and it needs a refresh"
        )
    } else {
        format!("rotate the stand-in key of {ds}")
    };
    let action = if delete { "delete" } else { "rotate" };
    Ok(Plan {
        summary,
        fields: fields(&[("dataset", ds.as_str()), ("action", action)]),
        class: TouchClass::BlindKeys,
        dataset: ds,
        action: Action::Keys { delete },
    })
}

async fn plan_loosen(
    ctx: &Arc<Ctx>,
    peer: &PeerCred,
    a: &Map<String, Value>,
) -> Result<Plan, Refusal> {
    let ds = dataset_arg(a)?;
    let column = str_arg(a, "column")?.to_string();
    let to = parse_class(str_arg(a, "to")?)?;
    need_role(ctx, peer, &ds, Need::Manage).await?;
    let (m, _) = ctx.blind.live(&ds)?;
    let from = data::class_in_force(ctx, &ds, &m, &column)
        .ok_or_else(|| bad(format!("{column} is not a column of {ds}")))?;
    let (fname, tname) = (data::class_name(from), data::class_name(to));
    if !to.is_looser_than(from) {
        return Err(bad(format!(
            "{column} is {fname}; {tname} is not looser, so it needs no touch: write it to policy"
        )));
    }
    if to == ColumnClass::Public {
        // R48-8 (spec §2.1.2 [owner]): names, IDs and amounts never.
        let (table, col) = column
            .split_once('.')
            .ok_or_else(|| bad(format!("{column} is not a column of {ds}")))?;
        let (table, col) = (table.to_string(), col.to_string());
        let snap = ctx.blind.dataset_dir(&ds).snapshot();
        let schema = m.schema.clone();
        let why = tokio::task::spawn_blocking(move || {
            let conn = saiife_shield::snapshot::open_ro(&snap)?;
            saiife_shield::public::snapshot_public_refusal(&conn, &schema, &table, &col)
        })
        .await
        .map_err(|_| join_err())?
        .map_err(|e| unavailable(format!("{column} could not be checked: {e}")))?;
        if let Some(why) = why {
            return Err(bad(format!("{column} cannot be public: it {why}")));
        }
    }
    Ok(Plan {
        summary: format!("make {column} {tname} (now {fname})"),
        fields: fields(&[
            ("dataset", ds.as_str()),
            ("column", &column),
            ("from", fname),
            ("to", tname),
        ]),
        class: TouchClass::BlindLoosen,
        dataset: ds,
        action: Action::Loosen { column, from, to },
    })
}

/// `blind.touch.begin {purpose, …}` -> `{request_id, touch, expires_at,
/// class}`.
pub async fn begin(
    ctx: &Arc<Ctx>,
    peer: &PeerCred,
    a: &Map<String, Value>,
) -> Result<Value, Failure> {
    let purpose = str_arg(a, "purpose")?;
    let plan = match purpose {
        "name" => plan_name(ctx, peer, a).await?,
        "approve" => plan_approve(ctx, peer, a).await?,
        "method_rm" => plan_method_rm(ctx, peer, a).await?,
        "keys" => plan_keys(ctx, peer, a).await?,
        "loosen" => plan_loosen(ctx, peer, a).await?,
        _ => {
            return Err(bad("purpose must be one of name, approve, method_rm, keys, loosen").into())
        }
    };
    let uid = peer.uid;
    let c = Arc::clone(ctx);
    let creds = tokio::task::spawn_blocking(move || c.touch.credentials_of(uid))
        .await
        .map_err(|_| join_err())?;
    if creds.is_empty() {
        return Err(Failure::Touch {
            rule: "touch_unavailable",
            text: no_device_text(purpose, plan.class),
        });
    }
    let rid = new_request_id()?;
    let (c, class, summary, f) = (
        Arc::clone(ctx),
        plan.class,
        plan.summary.clone(),
        plan.fields.clone(),
    );
    let issued = tokio::task::spawn_blocking(move || {
        c.touch
            .issue(IssueKey::Blind(rid), uid, class, summary, f, unix_now())
    })
    .await
    .map_err(|_| join_err())?
    .map_err(|e| Refusal::new(ErrorCode::Busy, e))?;
    let record = ActionRecord {
        instance_id: ctx.touch.instance_id(),
        request_id: rid,
        class: plan.class,
        summary: plan.summary,
        fields: plan.fields,
        nonce: issued.nonce,
        expires_at: issued.expires_at,
    };
    let touch = touch_request(&record, creds);
    let expires_at = record.expires_at;
    {
        let mut t = lock(&ctx.blind.touches);
        t.sweep(unix_now());
        t.map.insert(
            rid,
            Pending {
                uid,
                dataset: plan.dataset,
                record,
                action: plan.action,
            },
        );
    }
    Ok(json!({
        "request_id": rid.to_string(),
        "touch": touch,
        "expires_at": expires_at,
        "class": class.name(),
    }))
}

// ------------------------------------------------------------ commit ----

fn request_id_arg(a: &Map<String, Value>) -> Result<u64, Refusal> {
    match a.get("request_id") {
        Some(Value::String(s)) => s.parse().ok(),
        Some(Value::Number(n)) => n.as_u64(),
        _ => None,
    }
    .ok_or_else(|| bad("request_id is required"))
}

/// `blind.touch.commit {request_id, assertion}`: the action, once the
/// touch verifies.
pub async fn commit(
    ctx: &Arc<Ctx>,
    peer: &PeerCred,
    a: &Map<String, Value>,
) -> Result<Value, Failure> {
    let rid = request_id_arg(a)?;
    let asr: Assertion = a
        .get("assertion")
        .cloned()
        .ok_or_else(|| bad("assertion is required"))
        .and_then(|v| {
            serde_json::from_value(v).map_err(|_| bad("assertion is not a touch assertion"))
        })?;
    let uid = peer.uid;
    let cred = asr.credential_id().to_vec();
    // Another uid's commit leaves the owner's touch as it is.
    let p = {
        let mut t = lock(&ctx.blind.touches);
        t.sweep(unix_now());
        match t.map.get(&rid) {
            None => return Err(Failure::touch(TouchError::Expired)),
            Some(p) if p.uid != uid => return Err(Failure::touch(TouchError::Mismatch)),
            Some(_) => {}
        }
        t.map
            .remove(&rid)
            .ok_or(Failure::touch(TouchError::Expired))?
    };
    let c = Arc::clone(ctx);
    let rec = p.record.clone();
    let verified = tokio::task::spawn_blocking(move || {
        // The record is the daemon's own, never the client's.
        let built = |i: &crate::touch::Issued| ActionRecord {
            nonce: i.nonce,
            expires_at: i.expires_at,
            ..rec.clone()
        };
        c.touch.consume(
            &IssueKey::Blind(rid),
            uid,
            built,
            &asr,
            saiife_touch::LOCAL_RP_ID,
            unix_now(),
        )
    })
    .await
    .map_err(|_| join_err())?;
    let ev = match verified {
        Ok((ev, _)) => ev,
        Err(e) => {
            let f = Failure::touch(e);
            if let Failure::Touch { rule, .. } = &f {
                deny_record(
                    ctx,
                    uid,
                    &p.dataset,
                    p.action.purpose(),
                    rule,
                    &e.to_string(),
                )
                .await;
            }
            return Err(f);
        }
    };
    let touch = Touched {
        label: touch_label(&ev),
        record: touch_ref(&cred, &ev),
    };
    let ds = p.dataset.clone();
    let purpose = p.action.purpose();
    let r = match p.action {
        Action::Name { ask, name } => commit_name(ctx, peer, &ds, ask, name, touch).await,
        Action::Approve {
            ask,
            method_sha256,
            template_key,
            preview_mac,
        } => {
            commit_approve(
                ctx,
                peer,
                &ds,
                &ask,
                (&method_sha256, &template_key, &preview_mac),
                touch,
            )
            .await
        }
        Action::MethodRm { id } => commit_method_rm(ctx, peer, &ds, id, touch).await,
        Action::Keys { delete } => commit_keys(ctx, peer, &ds, delete, touch).await,
        Action::Loosen { column, from, to } => {
            commit_loosen(ctx, peer, &ds, column, from, to, touch).await
        }
    };
    if let Err(Failure::Refused(r)) = &r {
        if r.code == ErrorCode::Forbidden {
            deny_record(ctx, uid, &ds, purpose, "role_lost", &r.text).await;
        }
    }
    r
}

/// The verified touch: for methods.json and for the records.
struct Touched {
    label: String,
    record: String,
}

/// R-C12 for the touches that act on a dataset: still in policy, the role
/// still held.
async fn still_has(
    ctx: &Ctx,
    peer: &PeerCred,
    ds: &DatasetName,
    need: Need,
) -> Result<(), Failure> {
    if !in_policy(ctx, ds) {
        return Err(Refusal::new(
            ErrorCode::Forbidden,
            format!("{ds} is no longer in policy; nothing was changed"),
        )
        .into());
    }
    if !has(ctx, peer, ds, need).await {
        return Err(Refusal::new(
            ErrorCode::Forbidden,
            format!(
                "{} (the policy changed); nothing was changed",
                role_text(ds, need)
            ),
        )
        .into());
    }
    Ok(())
}

async fn commit_name(
    ctx: &Arc<Ctx>,
    peer: &PeerCred,
    ds: &DatasetName,
    id: String,
    name: String,
    touch: Touched,
) -> Result<Value, Failure> {
    // R-C12: a lost role ends the ask, recorded.
    ask::recheck(ctx, &id, peer, false).await?;
    let still = lock(&ctx.blind.asks).peek(&id, peer.uid, |s| {
        s.dataset == *ds && s.keep_name_pending() == Some(name.as_str())
    })?;
    if !still {
        return Err(Failure::mismatch(ASK_CHANGED));
    }
    // The release is recorded before the name can leave (keyed hash only).
    let (c, d) = (Arc::clone(ctx), ds.clone());
    let key = tokio::task::spawn_blocking(move || keys::load(&c, &d).map_err(|e| e.refusal(&d)))
        .await
        .map_err(|_| join_err())??
        .index_key();
    let r = BlindRecord::Name {
        ask: id.clone(),
        touch: touch.record,
        name_sha256: audit::name_sha256(&key, &name),
    };
    record(
        ctx,
        peer.uid,
        ds,
        r,
        "the release could not be recorded; nothing was sent",
    )
    .await?;
    let step = ask::step(ctx, peer, &id, AskAnswer::KeepNameTouched).await?;
    Ok(json!({"ask": id, "step": step.to_value()}))
}

async fn commit_approve(
    ctx: &Arc<Ctx>,
    peer: &PeerCred,
    ds: &DatasetName,
    id: &str,
    (sha, key, mac): (&str, &str, &str),
    touch: Touched,
) -> Result<Value, Failure> {
    // R-C12 (T2 M6): an ask answered while a reload took the role is
    // caught here.
    ask::recheck(ctx, id, peer, true).await?;
    let f = lock(&ctx.blind.asks)
        .peek(id, peer.uid, |s| s.for_approve())?
        .ok_or_else(|| Failure::mismatch(ASK_CHANGED))?;
    if f.dataset != *ds
        || method_sha256(&f.reply.method) != sha
        || f.template_key != key
        || f.preview_mac != mac
    {
        return Err(Failure::mismatch(ASK_CHANGED));
    }
    approvable(&f)?;
    let by = ctx
        .name_of(peer.uid)
        .await
        .unwrap_or_else(|| peer.uid.to_string());
    let m = ApprovedMethod {
        id: String::new(),
        version: 1,
        dataset: ds.clone(),
        lang: f.lang,
        template_key: f.template_key.clone(),
        param_tags: f.param_tags.clone(),
        reply: f.reply.clone(),
        preview_mac: f.preview_mac.clone(),
        approved_by: by,
        approved_at: crate::tokens::rfc3339(crate::workspace::now_secs()),
        touch: touch.label,
        status: MethodStatus::Active,
    };
    let stored = data::with_methods(ctx, ds, move |s| Ok(s.add(m).clone())).await?;
    let r = BlindRecord::Approve {
        method: stored.id.clone(),
        version: stored.version,
        dataset: ds.to_string(),
        template_sha256: template_sha256(&stored.reply.template),
        touch: touch.record,
        action: "add",
    };
    if let Err(e) = record(ctx, peer.uid, ds, r, APPROVE_UNRECORDED).await {
        let gone = stored.id.clone();
        if data::with_methods(ctx, ds, move |s| Ok(s.remove(&gone)))
            .await
            .is_err()
        {
            eprintln!("saiifed: blind: an unrecorded approval could not be undone");
        }
        return Err(e.into());
    }
    // The ask is done: approved once.
    lock(&ctx.blind.asks).forget(id, peer.uid);
    Ok(json!({"method": stored.id, "version": stored.version}))
}

async fn commit_method_rm(
    ctx: &Arc<Ctx>,
    peer: &PeerCred,
    ds: &DatasetName,
    id: String,
    touch: Touched,
) -> Result<Value, Failure> {
    still_has(ctx, peer, ds, Need::Approver).await?;
    let store = load_store(ctx, ds).await?;
    let m = store
        .methods
        .iter()
        .find(|m| m.id == id)
        .cloned()
        .ok_or_else(|| bad(format!("{ds} has no approved method {id}")))?;
    let r = BlindRecord::Approve {
        method: m.id.clone(),
        version: m.version,
        dataset: ds.to_string(),
        template_sha256: template_sha256(&m.reply.template),
        touch: touch.record,
        action: "remove",
    };
    record(ctx, peer.uid, ds, r, ACTION_UNRECORDED).await?;
    let gone = id.clone();
    let removed = data::with_methods(ctx, ds, move |s| Ok(s.remove(&gone))).await?;
    Ok(json!({"method": id, "removed": removed}))
}

async fn commit_keys(
    ctx: &Arc<Ctx>,
    peer: &PeerCred,
    ds: &DatasetName,
    delete: bool,
    touch: Touched,
) -> Result<Value, Failure> {
    still_has(ctx, peer, ds, Need::Manage).await?;
    let (c, d) = (Arc::clone(ctx), ds.clone());
    let now = tokio::task::spawn_blocking(move || keys::load(&c, &d))
        .await
        .map_err(|_| join_err())?;
    let version = match (&now, delete) {
        (Ok(k), false) => k.version.saturating_add(1),
        (Err(e), false) => return Err(e.refusal(ds).into()),
        (Ok(k), true) => k.version,
        (Err(_), true) => 0,
    };
    drop(now);
    let action = if delete { "delete" } else { "rotate" };
    let r = BlindRecord::Keys {
        dataset: ds.to_string(),
        action,
        version,
        touch: Some(touch.record),
        reason: None,
    };
    record(ctx, peer.uid, ds, r, ACTION_UNRECORDED).await?;
    let (c, d) = (Arc::clone(ctx), ds.clone());
    let done = tokio::task::spawn_blocking(move || {
        if delete {
            keys::shred(&c, &d).map(|()| None)
        } else {
            keys::rotate(&c, &d).map(Some)
        }
    })
    .await
    .map_err(|_| join_err())?
    .map_err(|e| e.refusal(ds))?;
    Ok(match done {
        Some(v) => json!({"action": action, "version": v}),
        None => json!({"action": action}),
    })
}

async fn commit_loosen(
    ctx: &Arc<Ctx>,
    peer: &PeerCred,
    ds: &DatasetName,
    column: String,
    from: ColumnClass,
    to: ColumnClass,
    touch: Touched,
) -> Result<Value, Failure> {
    still_has(ctx, peer, ds, Need::Manage).await?;
    let by = ctx
        .name_of(peer.uid)
        .await
        .unwrap_or_else(|| peer.uid.to_string());
    let r = BlindRecord::Loosen {
        dataset: ds.to_string(),
        column: column.clone(),
        from,
        to,
        touch: touch.record,
    };
    record(ctx, peer.uid, ds, r, ACTION_UNRECORDED).await?;
    let g = LoosenGrant {
        column: column.clone(),
        class: to,
        touched_at: crate::tokens::rfc3339(crate::workspace::now_secs()),
        by,
    };
    let (c, d) = (Arc::clone(ctx), ds.clone());
    tokio::task::spawn_blocking(move || data::add_grant(&c, &d, g))
        .await
        .map_err(|_| join_err())??;
    Ok(json!({"column": column, "to": data::class_name(to), "granted": true}))
}

// --------------------------------------------------------------- ops ----

/// `blind.touch.begin` as an IPC answer.
pub async fn begin_op(ctx: &Arc<Ctx>, peer: &PeerCred, id: u64, a: &Map<String, Value>) -> Value {
    match begin(ctx, peer, a).await {
        Ok(Value::Object(m)) => saiife_ipc::msg::ok(id, m),
        Ok(_) => unavailable("internal: not an object").to_value(id),
        Err(f) => f.to_value(id),
    }
}

/// `blind.touch.commit` as an IPC answer.
pub async fn commit_op(ctx: &Arc<Ctx>, peer: &PeerCred, id: u64, a: &Map<String, Value>) -> Value {
    match commit(ctx, peer, a).await {
        Ok(Value::Object(m)) => saiife_ipc::msg::ok(id, m),
        Ok(_) => unavailable("internal: not an object").to_value(id),
        Err(f) => f.to_value(id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn touch_errors_map_to_rules() {
        let rule = |e| match Failure::touch(e) {
            Failure::Touch { rule, .. } => rule,
            Failure::Refused(_) => "refused",
        };
        assert_eq!(rule(TouchError::Expired), "touch_expired");
        assert_eq!(rule(TouchError::Mismatch), "touch_mismatch");
        assert_eq!(rule(TouchError::UnknownCredential), "touch_mismatch");
        assert_eq!(rule(TouchError::Unavailable), "touch_unavailable");
        assert_eq!(rule(TouchError::BadSignature), "touch_failed");
        assert_eq!(rule(TouchError::Replayed), "touch_failed");
        let v = Failure::touch(TouchError::Expired).to_value(3);
        assert_eq!(v["error"], "forbidden");
        assert_eq!(v["rule"], "touch_expired");
        assert!(v["message"]
            .as_str()
            .unwrap()
            .starts_with("refused (touch_expired): "));
    }

    #[test]
    fn no_device_text_is_the_plans() {
        let t = no_device_text("approve", TouchClass::BlindApprove);
        assert_eq!(
            t,
            "refused: approve needs a touch (blind:approve) and no touch device is enrolled for you: saiife touch enrol"
        );
        let v = Failure::Touch {
            rule: "touch_unavailable",
            text: t.clone(),
        }
        .to_value(1);
        assert_eq!(v["message"], t.as_str());
        assert_eq!(v["rule"], "touch_unavailable");
    }

    /// T3 review I1: an ask that kept a name, or a stored text holding a
    /// name released earlier in the session, is never approved (`approvable`
    /// runs at begin and again at commit).
    #[test]
    fn kept_names_are_never_approved() {
        use saiife_shield::plan::PlanReply;
        let base = ForApprove {
            dataset: "crm".parse().unwrap(),
            lang: saiife_shield::schema::Lang::En,
            template_key: "what is the balance of :p1".into(),
            param_tags: vec!["entity:customers".into()],
            reply: PlanReply {
                method: "SELECT COUNT(*) AS n FROM customers c".into(),
                template: "There are {int(n)} customers.".into(),
                checks: vec![],
                intent: "counts".into(),
                needs_judgment: false,
                context: vec![],
            },
            preview_text: "p".into(),
            preview_mac: "m".into(),
            reused: None,
            kept_name: false,
            released: vec!["Zed Quorra".into()],
        };
        assert!(approvable(&base).is_ok(), "an unrelated released name");
        let refused = |f: &ForApprove| approvable(f).unwrap_err().text;
        let mut f = base.clone();
        f.kept_name = true;
        assert_eq!(refused(&f), KEPT_NAME);
        let mut f = base.clone();
        f.template_key = "what is the balance of zed quorra".into();
        assert_eq!(refused(&f), KEPT_NAME);
        let mut f = base.clone();
        f.reply.template = "ZED QUORRA has {int(n)} rows.".into();
        assert_eq!(refused(&f), KEPT_NAME);
        let mut f = base.clone();
        f.reply.intent = "about Zed  Quorra".into();
        assert_eq!(refused(&f), KEPT_NAME);
    }

    #[test]
    fn request_ids_fit_a_json_number() {
        for _ in 0..64 {
            let id = new_request_id().unwrap();
            assert!(id > 0 && id < (1 << 53));
        }
    }
}
