//! Approval requests of connector calls (spec §6.10.1, §8.7): step 8 of
//! the pipeline stores a request ([`create`]), an approver decides it
//! (`approval.decide`), and the daemon sends the stored, sealed request
//! ([`send`]); the requester fetches the result (`api.result`,
//! `GET /v1/requests/{id}`).
//!
//! Who sees what (decision 4): approvers see every request, a requester
//! its own; an admin who is not an approver sees only its own. A request
//! the caller may not see answers exactly as an unknown id.
//!
//! The store does blocking IO under a std mutex and the vault holds its
//! own: both are used off the runtime thread (`spawn_blocking`), the store
//! first and never inside the vault's lock. `may_decide` (directory
//! lookups, up to 120 s of re-authentication) runs there too.

use crate::api_ops::{answer, DaemonEnv, Groups};
use crate::approvals::{
    aad, result_aad, state_name, Amount, ApprovalType, Filter, NewRequest, PendingFull,
    Request as ApprovalRequest, SendDisplay, State, Store, StoreError,
};
use crate::approvers::{may_decide, Refusal};
use crate::ops::{Conn, Ctx, VERSION};
use crate::reauth::{Reauth, ReauthResult};
use crate::vault::VaultError;
use saiife_audit::{DecisionKind, Record};
use saiife_broker::pipeline::{self, Outcome, PendingCall, StoredCall};
use saiife_ipc::msg::{
    err, err_with, ok, ErrorCode, Request, MAX_RECORD_BYTES, OP_APPROVAL_CREATE,
    OP_APPROVAL_DECIDE, OP_APPROVAL_LIST, OP_APPROVAL_SHOW, OP_GRANT_CONSUME,
};
use saiife_ipc::peer::PeerCred;
use serde_json::{json, Map, Value};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use zeroize::Zeroizing;

/// The rule of a request still `approved` at start: the daemon stopped
/// between the approval and the send. It is never sent again by itself
/// (that could send a write twice).
pub const INTERRUPTED: &str = "interrupted";
/// The rule of an approved connector request whose environment changed
/// between the ask and the send (rebound scope, or an environment no
/// longer defined): nothing is sent.
pub const ENV_CHANGED: &str = "env_changed";
/// The note of a request its requester rejected (withdrew).
pub const CANCELLED: &str = "cancelled by requester";
/// At most this many pending requests per uid; more are denied
/// (`approvals_full`), so an agent cannot flood its approvers.
pub const MAX_PENDING_PER_UID: usize = 20;

fn now() -> SystemTime {
    crate::import_backup::now()
}

/// `f` on the store, on a blocking thread. `None`: no store, or the task
/// failed.
async fn on_store<T: Send + 'static>(
    ctx: &Arc<Ctx>,
    f: impl FnOnce(&Ctx, &Store) -> T + Send + 'static,
) -> Option<T> {
    ctx.approvals.as_ref().ok()?;
    let c = Arc::clone(ctx);
    tokio::task::spawn_blocking(move || match &c.approvals {
        Ok(s) => Some(f(&c, s)),
        Err(_) => None,
    })
    .await
    .ok()
    .flatten()
}

/// Whether `uid` is listed in `[approval] approvers` (by name or a current
/// group). Lookups are the context's cached, off-thread ones; any failure
/// is no.
pub(crate) async fn is_approver(ctx: &Ctx, uid: u32) -> bool {
    // The personal broker: its own user approves (§6.10.2).
    if ctx.mode == crate::ops::Mode::Personal {
        return uid == ctx.own_uid;
    }
    let approvers = match ctx.policy().system {
        Some(s) => s.approval.approvers.clone(),
        None => return false,
    };
    if approvers.is_empty() {
        return false;
    }
    let Some(name) = ctx.name_of(uid).await else {
        return false;
    };
    let mut groups: Option<Vec<String>> = None;
    for a in &approvers {
        match a.strip_prefix("group:") {
            Some(g) => {
                if groups.is_none() {
                    groups = Some(ctx.groups_of(&name).await);
                }
                if groups.iter().flatten().any(|x| x == g) {
                    return true;
                }
            }
            None if *a == name => return true,
            None => {}
        }
    }
    false
}

// ------------------------------------------------------------ create

/// Step 8 for the daemon: seal `p`'s exact request (bound to its id), store
/// it with the masked display copy, and write its `approval`/`created`
/// record. Errs with the deny rule; nothing is left pending on an error.
pub(crate) async fn create(ctx: &Arc<Ctx>, p: &PendingCall, agent: &str) -> Result<u64, String> {
    if ctx.approvals.is_err() {
        return Err("approvals_unavailable".into());
    }
    let ttl = ctx
        .policy()
        .system
        .map(|s| s.approval.timeout)
        .unwrap_or_else(|| saiife_policy::ApprovalCfg::default().timeout);
    let exact = Zeroizing::new(
        serde_json::to_vec(&p.stored).map_err(|_| "approvals_unavailable".to_string())?,
    );
    let new = NewRequest {
        uid: p.stored.uid,
        user: p.stored.user.clone(),
        session: p.stored.session.clone(),
        agent: agent.to_string(),
        project: p.project.clone(),
        kind: ApprovalType::Connector,
        service: Some(p.stored.service.clone()),
        operation: Some(p.operation.clone()),
        capability: p.capability.clone(),
        params: p.params.clone(),
        input: None,
        grant_key: None,
        scope: None,
        ask_rule: None,
        send: SendDisplay {
            body_display: p.body_display.clone(),
            body_sha256: p.body_sha256.clone(),
            body_truncated: p.body_truncated,
            amount: p
                .amount
                .clone()
                .map(|(minor, currency)| Amount { minor, currency }),
            headers: p.headers.clone(),
            env: p.stored.env.clone(),
            env_base: p.stored.env_recorded && p.stored.env.is_none(),
        },
    };
    store_new(ctx, new, Some(exact), ttl).await
}

/// Store request `new` (with `exact` sealed to its id, when given) under
/// the per-uid cap and write its `approval`/`created` record. Errs with
/// the deny rule; nothing is left pending on an error.
async fn store_new(
    ctx: &Arc<Ctx>,
    new: NewRequest,
    exact: Option<Zeroizing<Vec<u8>>>,
    ttl: Duration,
) -> Result<u64, String> {
    let created = on_store(ctx, move |c, s| {
        // Store lock, then the vault's (inside `seal`): the only order.
        s.create_dedup(
            new,
            |id| match &exact {
                Some(b) => c.vault.seal(&aad(id), b).map(Some),
                None => Ok(None),
            },
            ttl,
            now(),
            Some(MAX_PENDING_PER_UID),
        )
    })
    .await;
    let r = match created {
        // The same command is already waiting: its id, no new record.
        Some(Ok((r, false))) => return Ok(r.id),
        Some(Ok((r, true))) => r,
        Some(Err(e))
            if e.get_ref()
                .is_some_and(|x| x.downcast_ref::<PendingFull>().is_some()) =>
        {
            return Err("approvals_full".into());
        }
        Some(Err(e)) => {
            let vault = e
                .get_ref()
                .and_then(|x| x.downcast_ref::<VaultError>())
                .is_some();
            if !vault {
                eprintln!("saiife: warning: cannot store an approval request: {e}");
            }
            return Err(if vault {
                "vault_unavailable"
            } else {
                "approvals_unavailable"
            }
            .into());
        }
        None => return Err("approvals_unavailable".into()),
    };
    if let Err(e) = ctx.writer.append(ctx.approval_record(&r, "created")).await {
        // No record, no request: it expires at once and nobody can approve it.
        eprintln!(
            "saiife: warning: approval #{} not recorded ({e}); expiring it",
            r.id
        );
        let id = r.id;
        on_store(ctx, move |_, s| {
            s.transition(id, &[State::Pending], State::Expired, None, None, now())
        })
        .await;
        return Err("unrecorded".into());
    }
    // A new request only (a dedupe hit returned above).
    ctx.notify(
        saiife_policy::Event::ApprovalCreated,
        Some(r.id),
        r.service.as_deref(),
        r.operation.as_deref(),
        Some(r.uid),
        &format!(
            "approval #{} needed: {}",
            r.id,
            crate::approvals::offhost_summary(&r)
        ),
    );
    Ok(r.id)
}

// ------------------------------------------------------------ ops

pub async fn handle(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value {
    match req.op.as_str() {
        OP_APPROVAL_LIST => list(ctx, &conn.peer, req).await,
        OP_APPROVAL_SHOW => show(ctx, &conn.peer, req).await,
        OP_APPROVAL_DECIDE => decide(ctx, conn, req).await,
        OP_GRANT_CONSUME => {
            let (v, granted) = grant_consume(ctx, &conn.peer, req).await;
            conn.steps().granted = granted;
            v
        }
        OP_APPROVAL_CREATE => {
            let v = command_create(ctx, &conn.peer, req).await;
            conn.steps().created = v
                .get("ok")
                .filter(|o| **o == Value::Bool(true))
                .and_then(|_| v.get("request"))
                .and_then(Value::as_u64);
            v
        }
        other => err(
            req.id,
            ErrorCode::UnknownOp,
            &format!("unknown op {other:?}"),
        ),
    }
}

fn unavailable(id: u64, ctx: &Ctx) -> Value {
    let why = match &ctx.approvals {
        Err(e) => format!("approvals are unavailable: {e}"),
        Ok(_) => "approvals are unavailable".into(),
    };
    err(id, ErrorCode::Unavailable, &why)
}

fn unknown(id: u64, rid: u64) -> Value {
    err(
        id,
        ErrorCode::BadRequest,
        &format!("no approval request #{rid} (or not yours)"),
    )
}

/// A request as `approval.list` / `show` give it: the file (§8.10) less
/// the sealed request and the grant key. Everything left is masked.
pub fn item(r: &ApprovalRequest) -> Value {
    let mut v = serde_json::to_value(r).unwrap_or(Value::Null);
    if let Some(o) = v.as_object_mut() {
        o.remove("request_sealed");
        o.remove("grant_key");
    }
    v
}

/// The longest masked body `approval.list` shows, in characters.
const LIST_BODY_CHARS: usize = 200;

/// [`item`] for `approval.list`: the body cut short, no headers (`show`
/// has both in full).
pub fn brief(r: &ApprovalRequest) -> Value {
    let mut v = item(r);
    if let Some(o) = v.as_object_mut() {
        o.remove("headers");
        if let Some(Value::String(b)) = o.get_mut("body_display") {
            if b.chars().count() > LIST_BODY_CHARS {
                *b = format!("{}…", b.chars().take(LIST_BODY_CHARS).collect::<String>());
            }
        }
    }
    v
}

fn parse_state(s: &str) -> Option<State> {
    [
        State::Pending,
        State::Approved,
        State::Rejected,
        State::Expired,
        State::Sent,
        State::SendFailed,
    ]
    .into_iter()
    .find(|st| state_name(*st) == s)
}

async fn list(ctx: &Arc<Ctx>, peer: &PeerCred, req: Request) -> Value {
    let id = req.id;
    let mut states = Vec::new();
    match req.args.get("states") {
        None | Some(Value::Null) => {}
        Some(Value::Array(a)) => {
            for s in a {
                match s.as_str().and_then(parse_state) {
                    Some(st) => states.push(st),
                    None => return err(id, ErrorCode::BadRequest, "states: unknown state"),
                }
            }
        }
        Some(_) => return err(id, ErrorCode::BadRequest, "states is a list"),
    }
    // `own: true`: only the caller's requests (`saiife status`), even for
    // an approver.
    let own = req.args.get("own").and_then(Value::as_bool) == Some(true);
    let uid = (own || !is_approver(ctx, peer.uid).await).then_some(peer.uid);
    let Some(items) = on_store(ctx, move |_, s| s.list(Filter { uid, states })).await else {
        return unavailable(id, ctx);
    };
    let mut m = Map::new();
    m.insert(
        "items".into(),
        Value::Array(items.iter().map(brief).collect()),
    );
    ok(id, m)
}

/// The approval request's id: arg `request` (a frame's own `id` is the
/// frame's, so the spec's `id` cannot be an argument).
fn request_id(req: &Request) -> Result<u64, Value> {
    req.args
        .get("request")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            err(
                req.id,
                ErrorCode::BadRequest,
                "takes the approval request's id in request",
            )
        })
}

/// Request `rid` when `uid` may see it.
async fn visible(ctx: &Arc<Ctx>, uid: u32, rid: u64) -> Result<Option<ApprovalRequest>, ()> {
    let r = on_store(ctx, move |_, s| s.get(rid)).await.ok_or(())?;
    match r {
        Some(r) if r.uid == uid || is_approver(ctx, uid).await => Ok(Some(r)),
        _ => Ok(None),
    }
}

async fn show(ctx: &Arc<Ctx>, peer: &PeerCred, req: Request) -> Value {
    let id = req.id;
    let rid = match request_id(&req) {
        Ok(r) => r,
        Err(v) => return v,
    };
    match visible(ctx, peer.uid, rid).await {
        Err(()) => unavailable(id, ctx),
        Ok(None) => unknown(id, rid),
        Ok(Some(r)) => {
            let mut m = Map::new();
            m.insert("item".into(), item(&r));
            ok(id, m)
        }
    }
}

/// The re-authentication of a caller whose process start time is not
/// known: available as the real one says, but every check is an error.
pub(crate) struct NoStartTime<'a>(pub(crate) &'a dyn Reauth);

impl Reauth for NoStartTime<'_> {
    fn available(&self) -> bool {
        self.0.available()
    }
    fn check(&self, _pid: u32, _s: u64, _uid: u32, _d: &str, _t: Duration) -> ReauthResult {
        ReauthResult::Error("the approver's process start time is unknown".into())
    }
}

/// Refuse a decision on `r` by `by`: an `approval`/`refused` record with
/// `rule`, and `forbidden` with the rule.
async fn refuse(
    ctx: &Arc<Ctx>,
    r: &ApprovalRequest,
    by: u32,
    id: u64,
    rule: &str,
    why: &str,
) -> Value {
    let mut rec = decided_record(ctx, r, "refused", by);
    rec.rule = Some(rule.into());
    rec.reason = Some(why.into());
    if let Err(e) = ctx.writer.append(rec).await {
        eprintln!(
            "saiife: warning: cannot record a refused approval of #{}: {e}",
            r.id
        );
    }
    let mut m = Map::new();
    m.insert("rule".into(), rule.into());
    err_with(
        id,
        ErrorCode::Forbidden,
        &format!("refused ({rule}): {why}"),
        m,
    )
}

/// An `approval` record of `action` for `r`, decided by `by`.
fn decided_record(ctx: &Ctx, r: &ApprovalRequest, action: &str, by: u32) -> Record {
    let mut rec = ctx.approval_record(r, action);
    rec.extra.insert("by_uid".into(), by.into());
    rec
}

async fn decide(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value {
    let id = req.id;
    let peer = conn.peer;
    let rid = match request_id(&req) {
        Ok(r) => r,
        Err(v) => return v,
    };
    let approve = match req.args.get("action").and_then(Value::as_str) {
        Some("approve") => true,
        Some("reject") => false,
        _ => {
            return err(
                id,
                ErrorCode::BadRequest,
                "action is \"approve\" or \"reject\"",
            )
        }
    };
    let note = match req.args.get("note") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => {
            if let Err(e) = crate::approvals::check_note(s) {
                return err(id, ErrorCode::BadRequest, &e.to_string());
            }
            Some(s.clone())
        }
        Some(_) => return err(id, ErrorCode::BadRequest, "note is a string"),
    };
    let r = match visible(ctx, peer.uid, rid).await {
        Err(()) => return unavailable(id, ctx),
        Ok(None) => return unknown(id, rid),
        Ok(Some(r)) => r,
    };
    let Some(cfg) = ctx.policy().system.map(|s| s.approval.clone()) else {
        return err(
            id,
            ErrorCode::Unavailable,
            "no valid policy is loaded: nobody can approve",
        );
    };

    // A body too large to show whole is approved only knowingly. Checked
    // first: no re-authentication prompt for an approval refused anyway.
    let ack = req.args.get("ack_truncated").and_then(Value::as_bool) == Some(true);
    if approve && r.body_truncated && !ack {
        return refuse(
            ctx,
            &r,
            peer.uid,
            id,
            "truncated_not_acknowledged",
            "the body is over 1 MiB and shown cut; approve with ack_truncated (--accept-truncated)",
        )
        .await;
    }

    // The requester may always withdraw its own request: a rejection that
    // lets nothing through needs no approver and no re-authentication.
    let cancel = !approve && r.uid == peer.uid;
    let note = if cancel {
        Some(match note {
            // (Within the note limit; a note too long for the prefix is dropped.)
            Some(n)
                if !n.is_empty() && n.len() + CANCELLED.len() + 2 <= crate::approvals::NOTE_MAX =>
            {
                format!("{CANCELLED}: {n}")
            }
            _ => CANCELLED.to_string(),
        })
    } else {
        note
    };

    // Who may decide: the daemon's own name for the peer uid, never the
    // client's; the lookups and any re-authentication off the runtime.
    let refusal = if cancel {
        None
    } else if ctx.mode == crate::ops::Mode::Personal {
        crate::approvers::personal_may_decide(ctx.own_uid, peer.uid).err()
    } else {
        match ctx.name_of(peer.uid).await {
            None => Some(Refusal::NotApprover),
            Some(name) => {
                let c = Arc::clone(ctx);
                let start = conn.start_time;
                let requester = r.uid;
                let detail = crate::approvals::reauth_detail(&r);
                tokio::task::spawn_blocking(move || {
                    // Re-authentication names the approver's process: without
                    // its start time it cannot run (fail closed).
                    let no_start = NoStartTime(c.reauth.as_ref());
                    let reauth: &dyn Reauth = match start {
                        Some(_) => c.reauth.as_ref(),
                        None => &no_start,
                    };
                    may_decide(
                        &cfg,
                        c.directory.as_ref(),
                        &name,
                        requester,
                        reauth,
                        &peer,
                        start.unwrap_or(0),
                        c.proc.as_ref(),
                        &c.reauth_cooldowns,
                        &detail,
                    )
                })
                .await
                .unwrap_or_else(|e| Err(Refusal::ReauthError(e.to_string())))
                .err()
            }
        }
    };
    if let Some(why) = refusal {
        return refuse(ctx, &r, peer.uid, id, why.rule(), &why.to_string()).await;
    }

    let to = if approve {
        State::Approved
    } else {
        State::Rejected
    };
    let moved = on_store(ctx, move |_, s| {
        s.transition(rid, &[State::Pending], to, Some(peer.uid), note, now())
    })
    .await;
    let r = match moved {
        None => return unavailable(id, ctx),
        Some(Ok(r)) => r,
        Some(Err(StoreError::WrongState {
            state,
            newly_expired,
        })) => {
            if let Some(gone) = newly_expired {
                ctx.record_expired(vec![*gone]).await;
            }
            return err(
                id,
                ErrorCode::BadRequest,
                &format!("request #{rid} is {}", state_name(state)),
            );
        }
        Some(Err(StoreError::Unknown)) => return unknown(id, rid),
        Some(Err(e)) => return err(id, ErrorCode::BadRequest, &e.to_string()),
    };
    let action = if approve { "approved" } else { "rejected" };
    let recorded = ctx
        .writer
        .append(decided_record(ctx, &r, action, peer.uid))
        .await;
    if let Err(e) = recorded {
        if approve {
            // An approval that is not on record is not acted on.
            fail(
                ctx,
                &r,
                "unrecorded",
                &format!("the approval was not recorded: {e}"),
            )
            .await;
        }
        return err(
            id,
            ErrorCode::Unrecorded,
            &format!("request #{rid} is {action}, but its record could not be written: {e}"),
        );
    }
    if approve && r.kind == ApprovalType::Connector {
        let c = Arc::clone(ctx);
        let by = peer.uid;
        tokio::spawn(async move { send(c, r, by).await });
    } else if approve {
        // A command: the grant is kept before the answer, so the command
        // can run as soon as the approver is told.
        if let Err(why) = grant(ctx, &r).await {
            return err(
                id,
                ErrorCode::Internal,
                &format!("request #{rid} is approved, but its grant could not be kept: {why}"),
            );
        }
    }
    let mut m = Map::new();
    m.insert("request".into(), rid.into());
    m.insert("state".into(), action.into());
    ok(id, m)
}

// ------------------------------------------------------------ commands

/// The fields of the guard record a hook sends with `grant.consume` and
/// `approval.create` (spec §6.10.4).
struct CallFields {
    agent: String,
    /// The record's project (the cwd), shown to approvers.
    project: String,
    /// The canonical project root (arg `project`): what the key holds.
    key_project: String,
    tool: String,
    /// As the record shows it (the hook sends only whole, unmasked ones).
    input: String,
    /// SHA-256 of the exact command judged (arg `raw_sha256`).
    raw_sha256: [u8; 32],
    session: Option<String>,
    pack: Option<String>,
    rule_id: Option<String>,
}

impl CallFields {
    /// The grant key for this call by `uid`: computed here, never taken
    /// from the client.
    fn key(&self, uid: u32) -> [u8; 32] {
        crate::grants::grant_key(
            uid,
            &self.agent,
            &self.key_project,
            &self.tool,
            &self.input,
            &self.raw_sha256,
        )
    }

    /// `pack/rule_id`, when the record names both.
    fn ask(&self) -> Option<String> {
        Some(format!(
            "{}/{}",
            self.pack.as_ref()?,
            self.rule_id.as_ref()?
        ))
    }
}

/// `rec` of `req`: `agent`, `project`, `tool` and `input` are strings.
fn call_fields(req: &Request) -> Result<CallFields, Value> {
    let bad = |m: &str| err(req.id, ErrorCode::BadRequest, m);
    let Some(rec) = req.args.get("rec").and_then(Value::as_object) else {
        return Err(bad("takes the guard record in rec"));
    };
    if !matches!(serde_json::to_vec(rec), Ok(b) if b.len() <= MAX_RECORD_BYTES) {
        return Err(bad(&format!("rec is larger than {MAX_RECORD_BYTES} bytes")));
    }
    let text = |k: &str| rec.get(k).and_then(Value::as_str).map(str::to_string);
    let (Some(agent), Some(project), Some(tool), Some(input)) =
        (text("agent"), text("project"), text("tool"), text("input"))
    else {
        return Err(bad("rec needs agent, project, tool and input"));
    };
    let raw_sha256 = req
        .args
        .get("raw_sha256")
        .and_then(Value::as_str)
        .and_then(crate::grants::unhex);
    let key_project = req.args.get("project").and_then(Value::as_str);
    let (Some(raw_sha256), Some(key_project)) = (raw_sha256, key_project) else {
        return Err(bad("takes raw_sha256 (64 hex) and project"));
    };
    Ok(CallFields {
        agent,
        project,
        key_project: key_project.to_string(),
        tool,
        input,
        raw_sha256,
        session: text("session"),
        pack: text("pack"),
        rule_id: text("rule_id"),
    })
}

/// An absolute path in normal form: no `.` or `..` components, no `//`,
/// no trailing `/` (except `/` itself).
fn normal_absolute(p: &str) -> bool {
    p == "/"
        || (p.starts_with('/')
            && !p.ends_with('/')
            && p[1..]
                .split('/')
                .all(|c| !c.is_empty() && c != "." && c != ".."))
}

/// The record's project (the cwd) must be the key's project root or lie
/// below it, at a component boundary: a grant cannot be scoped to another
/// tree than the one the command runs in. Checked lexically: the hook
/// canonicalizes both, and the daemon (another uid, `ProtectHome=`) does no
/// filesystem access here.
fn project_ok(f: &CallFields) -> bool {
    normal_absolute(&f.project)
        && normal_absolute(&f.key_project)
        && std::path::Path::new(&f.project).starts_with(&f.key_project)
}

/// Lockdown `all` answers every hook step with `lockdown`: no grant is
/// used up and no request made while it is on.
fn locked_down(ctx: &Ctx, id: u64) -> Option<Value> {
    ctx.lockdown
        .get()
        .filter(|l| l.scope == saiife_broker::pipeline::LockScope::All)
        .map(|l| err(id, ErrorCode::Lockdown, &crate::lockdown::message(&l)))
}

/// `grant.consume {rec}`: use up the caller's grant for this exact call.
/// `{granted: true, approval}` once; `{granted: false}` when there is
/// none (or it lapsed). A failure to save the use is an error: the call
/// is not allowed. The second value is the approval granted, if any.
async fn grant_consume(ctx: &Arc<Ctx>, peer: &PeerCred, req: Request) -> (Value, Option<u64>) {
    let id = req.id;
    let f = match call_fields(&req) {
        Ok(f) => f,
        Err(v) => return (v, None),
    };
    if let Some(v) = locked_down(ctx, id) {
        return (v, None);
    }
    if !project_ok(&f) {
        let mut m = Map::new();
        m.insert("rule".into(), "project_mismatch".into());
        return (
            err_with(
                id,
                ErrorCode::Denied,
                "project_mismatch: the project is not the cwd or above it",
                m,
            ),
            None,
        );
    }
    let key = f.key(peer.uid);
    let c = Arc::clone(ctx);
    let used = tokio::task::spawn_blocking(move || c.grants.consume(&key, now()))
        .await
        .unwrap_or_else(|e| Err(std::io::Error::other(e.to_string())));
    let mut m = Map::new();
    let granted = match used {
        Ok(Some(approval)) => {
            // The use is on record before the call is allowed.
            if let Err(e) = ctx
                .writer
                .append(grant_used_record(ctx, peer, approval, &f).await)
                .await
            {
                let v = err(
                    id,
                    ErrorCode::Unrecorded,
                    &format!("the use of approval #{approval} could not be recorded: {e}"),
                );
                return (v, None);
            }
            m.insert("granted".into(), true.into());
            m.insert("approval".into(), approval.into());
            Some(approval)
        }
        Ok(None) => {
            m.insert("granted".into(), false.into());
            None
        }
        Err(e) => {
            let v = err(
                id,
                ErrorCode::Unavailable,
                &format!("the command grants are unavailable: {e}"),
            );
            return (v, None);
        }
    };
    (ok(id, m), granted)
}

/// The `approval`/`grant_used` record of approval `approval`, used by
/// `peer` for call `f`.
async fn grant_used_record(
    ctx: &Arc<Ctx>,
    peer: &PeerCred,
    approval: u64,
    f: &CallFields,
) -> Record {
    let stored = on_store(ctx, move |_, s| s.get(approval)).await.flatten();
    let mut rec = match &stored {
        Some(r) => ctx.approval_record(r, "grant_used"),
        None => {
            let mut rec = ctx.record("approval", &f.input);
            rec.extra.insert("action".into(), "grant_used".into());
            rec.extra.insert("id".into(), approval.into());
            rec.extra.insert("approval".into(), approval.into());
            rec.extra.insert("type".into(), "command".into());
            rec.uid = Some(peer.uid);
            rec.agent = f.agent.clone();
            rec.project = f.project.clone();
            rec
        }
    };
    rec.decision = DecisionKind::Allow;
    rec
}

/// Refuse an `approval.create` with `rule` (`not_ask`,
/// `ask_rule_mismatch`): an `approval`/`refused` record (no request is
/// made) and `denied` with the rule.
async fn refuse_create(
    ctx: &Arc<Ctx>,
    peer: &PeerCred,
    id: u64,
    f: &CallFields,
    rule: &str,
    why: &str,
) -> Value {
    let mut rec = ctx.record("approval", &f.input);
    rec.uid = Some(peer.uid);
    rec.user = ctx.name_of(peer.uid).await;
    rec.agent = f.agent.clone();
    rec.project = f.project.clone();
    rec.session = f.session.clone();
    rec.decision = DecisionKind::Deny;
    rec.pack = f.pack.clone();
    rec.rule = Some(rule.into());
    rec.reason = Some(why.into());
    rec.extra.insert("action".into(), "refused".into());
    rec.extra.insert("type".into(), "command".into());
    if let Some(r) = &f.rule_id {
        rec.extra.insert("rule_id".into(), r.clone().into());
    }
    if let Err(e) = ctx.writer.append(rec).await {
        eprintln!("saiife: warning: cannot record a refused command request: {e}");
    }
    let mut m = Map::new();
    m.insert("rule".into(), rule.into());
    err_with(id, ErrorCode::Denied, &format!("{rule}: {why}"), m)
}

/// `approval.create {rec}`: a command request for a call a `[guard] ask`
/// rule denied (`pack` and `rule_id` in `rec` name it), keyed for the
/// caller's uid. `{request}`; the request counts toward the per-uid cap.
async fn command_create(ctx: &Arc<Ctx>, peer: &PeerCred, req: Request) -> Value {
    let id = req.id;
    let f = match call_fields(&req) {
        Ok(f) => f,
        Err(v) => return v,
    };
    let Some(sys) = ctx.policy().system else {
        return err(id, ErrorCode::Unavailable, "no valid policy is loaded");
    };
    let asked = f.ask().is_some_and(|a| sys.guard.ask.contains(&a));
    if !asked {
        return refuse_create(
            ctx,
            peer,
            id,
            &f,
            "not_ask",
            "the call's rule is not in [guard] ask",
        )
        .await;
    }
    if let Some(v) = locked_down(ctx, id) {
        return v;
    }
    if !project_ok(&f) {
        return refuse_create(
            ctx,
            peer,
            id,
            &f,
            "project_mismatch",
            "the project is not the cwd or above it",
        )
        .await;
    }
    // The shown input must be the exact command: never ask an approver
    // about one the grant could not be used for.
    let shown: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(f.input.as_bytes()).into();
    if shown != f.raw_sha256 {
        return refuse_create(
            ctx,
            peer,
            id,
            &f,
            "raw_mismatch",
            "the input is not the exact command (sha256 differs)",
        )
        .await;
    }
    // The claimed rule must deny the submitted command itself.
    let (pack, rule_id, input) = (
        f.pack.clone().unwrap_or_default(),
        f.rule_id.clone().unwrap_or_default(),
        f.input.clone(),
    );
    let matches = tokio::task::spawn_blocking(move || {
        saiifeguard::builtins::builtin_rule_denies(&pack, &rule_id, &input)
    })
    .await
    .unwrap_or(false);
    if !matches {
        return refuse_create(
            ctx,
            peer,
            id,
            &f,
            "ask_rule_mismatch",
            "the claimed [guard] ask rule does not deny this command",
        )
        .await;
    }
    if ctx.approvals.is_err() {
        return unavailable(id, ctx);
    }
    let new = NewRequest {
        uid: peer.uid,
        user: ctx.name_of(peer.uid).await.unwrap_or_default(),
        session: f.session.clone(),
        agent: f.agent.clone(),
        project: f.project.clone(),
        kind: ApprovalType::Command,
        service: None,
        operation: None,
        capability: None,
        params: Default::default(),
        input: Some(f.input.clone()),
        grant_key: Some(crate::grants::hex(&f.key(peer.uid))),
        scope: Some(f.key_project.clone()),
        ask_rule: f.ask(),
        send: SendDisplay::default(),
    };
    match store_new(ctx, new, None, sys.approval.timeout).await {
        Ok(rid) => {
            let mut m = Map::new();
            m.insert("request".into(), rid.into());
            ok(id, m)
        }
        Err(rule) => {
            let code = match rule.as_str() {
                "approvals_full" => ErrorCode::Denied,
                "unrecorded" => ErrorCode::Unrecorded,
                _ => ErrorCode::Unavailable,
            };
            let mut m = Map::new();
            m.insert("rule".into(), rule.clone().into());
            err_with(
                id,
                code,
                &format!("{rule}: no approval request was made"),
                m,
            )
        }
    }
}

/// Keep the grant of approved command request `r` for `[approval]
/// grant_ttl`, then move it to `sent` (its record says so). A grant that
/// cannot be kept is `send_failed` (`grants_unavailable`).
async fn grant(ctx: &Arc<Ctx>, r: &ApprovalRequest) -> Result<(), String> {
    let Some(key) = r.grant_key.as_deref().and_then(crate::grants::unhex) else {
        let why = "the request has no valid grant key";
        fail(ctx, r, "grant_invalid", why).await;
        return Err(why.into());
    };
    let ttl = ctx
        .policy()
        .system
        .map(|s| s.approval.grant_ttl)
        .unwrap_or_else(|| saiife_policy::ApprovalCfg::default().grant_ttl);
    let c = Arc::clone(ctx);
    let rid = r.id;
    let kept = tokio::task::spawn_blocking(move || c.grants.insert(key, rid, now() + ttl))
        .await
        .unwrap_or_else(|e| Err(std::io::Error::other(e.to_string())));
    match kept {
        Ok(()) => {
            let none = Detail {
                rule: None,
                reason: None,
                limit: None,
                status: None,
                resp_bytes: None,
                asked_via: None,
            };
            finish(ctx, r, State::Sent, None, none).await;
            Ok(())
        }
        Err(e) => {
            let why = format!("the grant could not be saved: {e}");
            fail(ctx, r, "grants_unavailable", &why).await;
            Err(why)
        }
    }
}

// ------------------------------------------------------------ send

/// Approved -> SendFailed with `rule`, a result saying so (when it can be
/// sealed) and the `approval`/`send_failed` record.
async fn fail(ctx: &Arc<Ctx>, r: &ApprovalRequest, rule: &str, message: &str) {
    let result = failure_result(rule, message);
    finish(
        ctx,
        r,
        State::SendFailed,
        Some(result),
        rule_record(rule, message),
    )
    .await;
}

fn failure_result(rule: &str, message: &str) -> Value {
    json!({"ok": false, "error": "denied", "rule": rule, "message": message})
}

/// What the `send_failed` / `sent` record carries besides the action.
struct Detail {
    rule: Option<String>,
    reason: Option<String>,
    limit: Option<String>,
    status: Option<u16>,
    resp_bytes: Option<usize>,
    /// How the request came in (`cli`, `http`).
    asked_via: Option<String>,
}

fn rule_record(rule: &str, message: &str) -> Detail {
    Detail {
        rule: Some(rule.into()),
        reason: Some(message.into()),
        limit: None,
        status: None,
        resp_bytes: None,
        asked_via: None,
    }
}

/// Seal `v` as the result of `rid` and keep it. A sealed result over the
/// store's cap is replaced by a small `result_too_large` one (`true`).
fn keep_result(
    c: &Ctx,
    s: &Store,
    rid: u64,
    v: &Value,
    status: Option<u16>,
    resp_bytes: Option<usize>,
) -> bool {
    let seal = |v: &Value| {
        let bytes = Zeroizing::new(serde_json::to_vec(v).unwrap_or_default());
        c.vault.seal(&result_aad(rid), &bytes)
    };
    // Store calls hold the store's lock only inside; the vault's is taken
    // and released in `seal`, never around a store call.
    let mut too_large = false;
    let sealed = match seal(v) {
        Ok(sealed) if sealed.len() > s.result_cap() => {
            too_large = true;
            eprintln!(
                "saiife: warning: the result of approval #{rid} ({} bytes sealed) is over the store's cap of {} bytes; keeping a note instead",
                sealed.len(),
                s.result_cap()
            );
            seal(&json!({"ok": false, "error": "result_too_large",
                "message": "the result was too large to keep",
                "status": status, "resp_bytes": resp_bytes}))
        }
        other => other,
    };
    let problem = match sealed {
        Ok(sealed) => s
            .put_result(rid, sealed, now())
            .err()
            .map(|e| format!("cannot keep the result of #{rid}: {e}")),
        Err(e) => Some(format!("cannot seal the result of #{rid}: {e}")),
    };
    if let Some(p) = problem {
        eprintln!("saiife: warning: {p}");
        result_unavailable(s, rid);
    }
    too_large
}

/// Mark `rid`'s result as not kept (best effort: a store that cannot be
/// written leaves no result either way).
fn result_unavailable(s: &Store, rid: u64) {
    if let Err(e) = s.mark_result_unavailable(rid) {
        eprintln!("saiife: warning: cannot note that the result of #{rid} is unavailable: {e}");
    }
}

/// What the requester gets for a result that could not be kept.
pub(crate) fn unavailable_result() -> Value {
    json!({"ok": false, "error": "result_unavailable",
        "message": "the result could not be kept (it could not be sealed or written)"})
}

/// Store the sealed result (if any), move to `to`, and write the record
/// of the state the store actually holds.
async fn finish(ctx: &Arc<Ctx>, r: &ApprovalRequest, to: State, result: Option<Value>, d: Detail) {
    let rid = r.id;
    let (status, resp_bytes) = (d.status, d.resp_bytes);
    let stored = on_store(ctx, move |c, s| {
        let too_large = result
            .as_ref()
            .is_some_and(|v| keep_result(c, s, rid, v, status, resp_bytes));
        let moved = s.transition(rid, &[State::Approved], to, None, None, now());
        let now_held = match &moved {
            Ok(r) => Some(r.clone()),
            Err(_) => s.get(rid),
        };
        (moved.map(|_| ()), now_held, too_large)
    })
    .await;
    let (moved, held, too_large) = match stored {
        Some(x) => x,
        None => (Err(StoreError::Unknown), None, false),
    };
    if let Err(e) = &moved {
        eprintln!(
            "saiife: warning: approval #{rid} could not be marked {}: {e}",
            state_name(to)
        );
    }
    let r = held.unwrap_or_else(|| r.clone());
    // The record says what the store holds: `sent` / `send_failed` once
    // moved; otherwise the intended action, with the state still held.
    let action = match r.state {
        State::Sent | State::SendFailed => state_name(r.state),
        _ => state_name(to),
    };
    let mut rec = ctx.approval_record(&r, action);
    if let Some(by) = r.decided_by {
        rec.extra.insert("by_uid".into(), by.into());
    }
    rec.rule = d.rule;
    rec.reason = d.reason;
    if r.state != to {
        rec.extra
            .insert("stored_state".into(), state_name(r.state).into());
        rec.rule = Some("store_failed".into());
        rec.reason = Some(format!(
            "the request could not be marked {}; it is {}",
            state_name(to),
            state_name(r.state)
        ));
    }
    if action == "send_failed" || r.state != to {
        rec.decision = DecisionKind::Deny;
    }
    if let Some(l) = d.limit {
        rec.extra.insert("limit".into(), l.into());
    }
    if let Some(s) = d.status {
        rec.extra.insert("status".into(), s.into());
    }
    if let Some(v) = d.asked_via {
        rec.extra.insert("asked_via".into(), v.into());
    }
    if too_large {
        rec.extra.insert("result_too_large".into(), true.into());
        rec.extra.insert("resp_bytes".into(), json!(resp_bytes));
    }
    if let Err(e) = ctx.writer.append(rec).await {
        eprintln!("saiife: warning: cannot record approval #{rid} {action}: {e}");
    }
}

/// Send approved request `r` (spec §6.10.1 step 4): only the sealed stored
/// request, under the policy in force now (decision 2). A stop waits for
/// it like any connector call.
pub(crate) async fn send(ctx: Arc<Ctx>, r: ApprovalRequest, by: u32) {
    let _busy = ctx.calls.enter();
    let rid = r.id;
    let opened = on_store(&ctx, move |c, s| {
        let sealed = s.sealed_request(rid).ok_or(VaultError::Crypto)?;
        // The store's lock is released: now the vault's.
        c.vault.open_sealed(&aad(rid), &sealed)
    })
    .await;
    let exact =
        match opened {
            Some(Ok(b)) => b,
            Some(Err(_)) => return fail(
                &ctx,
                &r,
                "vault_unavailable",
                "the stored request cannot be opened (vault unavailable or the request altered)",
            )
            .await,
            None => {
                return fail(
                    &ctx,
                    &r,
                    "approvals_unavailable",
                    "the approval store is unavailable",
                )
                .await
            }
        };
    let Ok(stored) = serde_json::from_slice::<StoredCall>(&exact) else {
        return fail(
            &ctx,
            &r,
            "stored_request_invalid",
            "the stored request cannot be read",
        )
        .await;
    };
    drop(exact);
    if stored.uid != r.uid {
        return fail(
            &ctx,
            &r,
            "stored_request_invalid",
            "the stored request is another uid's",
        )
        .await;
    }
    let state = ctx.policy();
    let Some(g) = state.gateway.clone() else {
        return fail(&ctx, &r, "policy_invalid", "no valid policy is loaded").await;
    };
    let groups = if stored.user.is_empty() {
        Vec::new()
    } else {
        ctx.groups_of(&stored.user).await
    };
    // The environment, chosen as for a new call: locked mode takes the
    // scope's as it is now; developer mode the one the request was asked
    // under (stored with it).
    let groups = Groups(groups);
    let mode = crate::api_ops::gateway_mode(&ctx);
    let Ok((env_name, _)) = g.select_env(mode, &groups, &stored.user, stored.env.as_deref()) else {
        return fail(
            &ctx,
            &r,
            crate::ops::UNKNOWN_ENV_RULE,
            "the scope's environment has no policy snapshot",
        )
        .await;
    };
    // An approved request is sent under the environment it was asked
    // under, or not at all: locked mode refuses a scope rebound to another
    // environment (or from the base config to one) since the ask,
    // developer mode an environment no longer defined (never the base
    // config instead). Only a request sealed before the environment was
    // recorded (`env_recorded` false, no `env`) is not checked.
    if (stored.env_recorded || stored.env.is_some()) && env_name != stored.env.as_deref() {
        let message = match mode {
            saiife_policy::Mode::Locked => {
                "the scope's environment changed since the request was asked"
            }
            saiife_policy::Mode::Developer => {
                "the environment the request was asked under is no longer defined"
            }
        };
        return fail(&ctx, &r, ENV_CHANGED, message).await;
    }
    let snap = g.snapshot_for(env_name);
    let env = DaemonEnv {
        ctx: &ctx,
        config: &snap.config,
        groups,
        agent: r.agent.clone(),
    };
    let up = ctx.upstream.as_ref().ok();
    let (call, outcome, trace) =
        pipeline::send_approved(&stored, snap, &g.catalog, &ctx.limiter, &env, up).await;
    let asked_via = stored.via.clone();
    drop(stored);
    if let Outcome::Limited { limit } = &outcome {
        ctx.notify_limit(
            r.uid,
            r.service.as_deref().unwrap_or(""),
            r.operation.as_deref().unwrap_or(""),
            limit,
        );
    }

    // The connector record of the send: `via = approval`, linked by id,
    // with how the request first came in.
    let mut rec = pipeline::record(&call, snap, &trace, &outcome, &r.agent, VERSION);
    rec.extra.insert("approval".into(), rid.into());
    rec.extra.insert("approved_by".into(), by.into());
    rec.extra
        .insert("asked_via".into(), asked_via.clone().into());
    let recorded = ctx.writer.append(rec).await;

    let detail = Detail {
        rule: match &outcome {
            Outcome::Denied { rule } => Some(rule.clone()),
            _ => None,
        },
        reason: match &outcome {
            Outcome::UpstreamFailed { reason } => Some(format!("upstream failed: {reason}")),
            Outcome::Limited { limit } => Some(format!("limit reached: {limit}")),
            _ => None,
        },
        limit: match &outcome {
            Outcome::Limited { limit } => Some(limit.to_string()),
            _ => None,
        },
        status: trace.status,
        resp_bytes: trace.resp_bytes,
        asked_via: Some(asked_via),
    };
    let sent = matches!(outcome, Outcome::Done { .. }) || outcome.is_post_send_deny();
    let to = if sent { State::Sent } else { State::SendFailed };
    let mut result = answer(0, outcome);
    if let Some(o) = result.as_object_mut() {
        o.remove("id");
    }
    if let Err(e) = recorded {
        // As for a direct call: an unrecorded result is withheld.
        result = json!({"ok": false, "error": "unrecorded",
            "message": format!("the connector record could not be written: {e}")});
    }
    finish(&ctx, &r, to, Some(result), detail).await;
}

/// At start: every request still `approved` was interrupted between its
/// approval and its send. Each becomes `send_failed` (`rule =
/// interrupted`) with a result saying so; it is never sent by itself.
/// Returns the `approval`/`send_failed` records, for the start records.
pub fn reconcile_interrupted(ctx: &Ctx) -> Vec<Record> {
    let Ok(store) = &ctx.approvals else {
        return Vec::new();
    };
    let message = "the daemon stopped between the approval and the end of the send: it may have been sent; check the service before asking again";
    let mut out = Vec::new();
    for r in store.list(Filter {
        uid: None,
        states: vec![State::Approved],
    }) {
        // A command's grant may or may not have been kept: revoke it, so
        // the command needs a new approval.
        if r.kind == ApprovalType::Command {
            if let Some(key) = r.grant_key.as_deref().and_then(crate::grants::unhex) {
                if let Err(e) = ctx.grants.revoke(&key) {
                    eprintln!(
                        "saiife: warning: cannot save the revoked grant of #{}: {e}",
                        r.id
                    );
                }
            }
        }
        let result = failure_result(INTERRUPTED, message);
        let bytes = Zeroizing::new(serde_json::to_vec(&result).unwrap_or_default());
        let kept = ctx
            .vault
            .seal(&result_aad(r.id), &bytes)
            .map_err(|_| ())
            .and_then(|sealed| store.put_result(r.id, sealed, now()).map_err(|_| ()));
        if kept.is_err() {
            result_unavailable(store, r.id);
        }
        match store.transition(
            r.id,
            &[State::Approved],
            State::SendFailed,
            None,
            None,
            now(),
        ) {
            Ok(r) => {
                eprintln!(
                    "saiife: warning: approval #{} was interrupted before its send",
                    r.id
                );
                let mut rec = ctx.approval_record(&r, "send_failed");
                rec.decision = DecisionKind::Deny;
                rec.rule = Some(INTERRUPTED.into());
                rec.reason = Some(message.into());
                if let Some(by) = r.decided_by {
                    rec.extra.insert("by_uid".into(), by.into());
                }
                out.push(rec);
            }
            Err(e) => eprintln!(
                "saiife: warning: cannot settle interrupted approval #{}: {e}",
                r.id
            ),
        }
    }
    out
}

// ------------------------------------------------------------ results

/// What a requester learns about its request.
pub(crate) enum ResultView {
    /// No such request, or not the caller's.
    Unknown,
    /// Pending or approved (being sent).
    Waiting(State),
    /// Decided: `rejected`, `expired`, `sent` or `send_failed`, with the
    /// stored result (the api.call answer) of a send while it is kept.
    Done { state: State, result: Option<Value> },
}

/// Request `rid` as `uid` may see it: the requester only (decision 4).
/// `Err` when the store is unavailable.
pub(crate) async fn result_for(ctx: &Arc<Ctx>, uid: u32, rid: u64) -> Result<ResultView, ()> {
    let got = on_store(ctx, move |c, s| {
        let r = s.get(rid)?;
        if r.uid != uid {
            return None;
        }
        let done = matches!(r.state, State::Sent | State::SendFailed);
        let result = done
            .then(|| s.get_result(rid))
            .flatten()
            .and_then(|sealed| c.vault.open_sealed(&result_aad(rid), &sealed).ok())
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .or_else(|| {
                (done && r.result_ref.as_deref() == Some(crate::approvals::RESULT_UNAVAILABLE))
                    .then(unavailable_result)
            });
        Some((r, result))
    })
    .await
    .ok_or(())?;
    let Some((r, result)) = got else {
        return Ok(ResultView::Unknown);
    };
    Ok(match r.state {
        // Past its expiry but not swept yet: expired all the same.
        State::Pending if r.expires <= crate::approvals::ts(now()) => ResultView::Done {
            state: State::Expired,
            result: None,
        },
        State::Pending | State::Approved => ResultView::Waiting(r.state),
        state => ResultView::Done { state, result },
    })
}

/// `api.result {id}`: `{id, state}` while it waits or once it was rejected
/// or expired, plus `result` (the answer `api.call` would have given) once
/// it was sent or failed to send.
pub(crate) async fn api_result(ctx: &Arc<Ctx>, peer: &PeerCred, req: Request) -> Value {
    let id = req.id;
    let rid = match request_id(&req) {
        Ok(r) => r,
        Err(v) => return v,
    };
    let view = match result_for(ctx, peer.uid, rid).await {
        Ok(v) => v,
        Err(()) => return unavailable(id, ctx),
    };
    let mut m = Map::new();
    m.insert("request".into(), rid.into());
    match view {
        ResultView::Unknown => return unknown(id, rid),
        ResultView::Waiting(s) => {
            m.insert("state".into(), state_name(s).into());
        }
        ResultView::Done { state, result } => {
            m.insert("state".into(), state_name(state).into());
            if let Some(r) = result {
                m.insert("result".into(), r);
            }
        }
    }
    ok(id, m)
}
