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
    aad, result_aad, state_name, Amount, ApprovalType, Filter, NewRequest,
    Request as ApprovalRequest, SendDisplay, State, Store, StoreError,
};
use crate::approvers::{may_decide, Refusal};
use crate::ops::{Conn, Ctx, VERSION};
use crate::reauth::{Reauth, ReauthResult};
use crate::vault::VaultError;
use saiife_audit::{DecisionKind, Record};
use saiife_broker::pipeline::{self, Outcome, PendingCall, StoredCall};
use saiife_ipc::msg::{
    err, err_with, ok, ErrorCode, Request, OP_APPROVAL_DECIDE, OP_APPROVAL_LIST, OP_APPROVAL_SHOW,
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
        send: SendDisplay {
            body_display: p.body_display.clone(),
            body_sha256: p.body_sha256.clone(),
            amount: p
                .amount
                .clone()
                .map(|(minor, currency)| Amount { minor, currency }),
            headers: p.headers.clone(),
        },
    };
    let created = on_store(ctx, move |c, s| {
        // Store lock, then the vault's (inside `seal`): the only order.
        s.create(
            new,
            |id| c.vault.seal(&aad(id), &exact).map(Some),
            ttl,
            now(),
        )
    })
    .await;
    let r = match created {
        Some(Ok(r)) => r,
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
    Ok(r.id)
}

// ------------------------------------------------------------ ops

pub async fn handle(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value {
    match req.op.as_str() {
        OP_APPROVAL_LIST => list(ctx, &conn.peer, req).await,
        OP_APPROVAL_SHOW => show(ctx, &conn.peer, req).await,
        OP_APPROVAL_DECIDE => decide(ctx, conn, req).await,
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
struct NoStartTime<'a>(&'a dyn Reauth);

impl Reauth for NoStartTime<'_> {
    fn available(&self) -> bool {
        self.0.available()
    }
    fn check(&self, _pid: u32, _start: u64, _uid: u32, _t: Duration) -> ReauthResult {
        ReauthResult::Error("the approver's process start time is unknown".into())
    }
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

    // Who may decide: the daemon's own name for the peer uid, never the
    // client's; the lookups and any re-authentication off the runtime.
    let refusal = match ctx.name_of(peer.uid).await {
        None => Some(Refusal::NotApprover),
        Some(name) => {
            let c = Arc::clone(ctx);
            let start = conn.start_time;
            let requester = r.uid;
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
                )
            })
            .await
            .unwrap_or_else(|e| Err(Refusal::ReauthError(e.to_string())))
            .err()
        }
    };
    if let Some(why) = refusal {
        let mut rec = decided_record(ctx, &r, "refused", peer.uid);
        rec.rule = Some(why.rule().into());
        rec.reason = Some(why.to_string());
        if let Err(e) = ctx.writer.append(rec).await {
            eprintln!("saiife: warning: cannot record a refused approval of #{rid}: {e}");
        }
        let mut m = Map::new();
        m.insert("rule".into(), why.rule().into());
        return err_with(
            id,
            ErrorCode::Forbidden,
            &format!("refused ({}): {why}", why.rule()),
            m,
        );
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
        if approve && r.kind == ApprovalType::Connector {
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
    }
    let mut m = Map::new();
    m.insert("request".into(), rid.into());
    m.insert("state".into(), action.into());
    ok(id, m)
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
}

fn rule_record(rule: &str, message: &str) -> Detail {
    Detail {
        rule: Some(rule.into()),
        reason: Some(message.into()),
        limit: None,
        status: None,
    }
}

/// Store the sealed result (if any), move to `to`, write the record.
async fn finish(ctx: &Arc<Ctx>, r: &ApprovalRequest, to: State, result: Option<Value>, d: Detail) {
    let rid = r.id;
    let stored = on_store(ctx, move |c, s| {
        if let Some(v) = result {
            let bytes = Zeroizing::new(serde_json::to_vec(&v).unwrap_or_default());
            // Store first (its lock released), then the vault.
            match c.vault.seal(&result_aad(rid), &bytes) {
                Ok(sealed) => {
                    if let Err(e) = s.put_result(rid, sealed, now()) {
                        eprintln!("saiife: warning: cannot keep the result of #{rid}: {e}");
                    }
                }
                Err(e) => eprintln!("saiife: warning: cannot seal the result of #{rid}: {e}"),
            }
        }
        s.transition(rid, &[State::Approved], to, None, None, now())
    })
    .await;
    let r = match stored {
        Some(Ok(r)) => r,
        other => {
            eprintln!(
                "saiife: warning: approval #{rid} could not be marked {}: {other:?}",
                state_name(to)
            );
            r.clone()
        }
    };
    let action = state_name(to);
    let mut rec = ctx.approval_record(&r, action);
    if let Some(by) = r.decided_by {
        rec.extra.insert("by_uid".into(), by.into());
    }
    if to == State::SendFailed {
        rec.decision = DecisionKind::Deny;
    }
    rec.rule = d.rule;
    rec.reason = d.reason;
    if let Some(l) = d.limit {
        rec.extra.insert("limit".into(), l.into());
    }
    if let Some(s) = d.status {
        rec.extra.insert("status".into(), s.into());
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
    let env = DaemonEnv {
        ctx: &ctx,
        config: &g.snap.config,
        groups: Groups(groups),
        agent: r.agent.clone(),
    };
    let up = ctx.upstream.as_ref().ok();
    let (call, outcome, trace) =
        pipeline::send_approved(&stored, &g.snap, &g.catalog, &ctx.limiter, &env, up).await;
    drop(stored);

    // The connector record of the send: `via = approval`, linked by id.
    let mut rec = pipeline::record(&call, &g.snap, &trace, &outcome, &r.agent, VERSION);
    rec.extra.insert("approval".into(), rid.into());
    rec.extra.insert("approved_by".into(), by.into());
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
    let message = "the daemon stopped after the approval and before the send; ask again";
    let mut out = Vec::new();
    for r in store.list(Filter {
        uid: None,
        states: vec![State::Approved],
    }) {
        let result = failure_result(INTERRUPTED, message);
        let bytes = Zeroizing::new(serde_json::to_vec(&result).unwrap_or_default());
        if let Ok(sealed) = ctx.vault.seal(&result_aad(r.id), &bytes) {
            let _ = store.put_result(r.id, sealed, now());
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
        let result = matches!(r.state, State::Sent | State::SendFailed)
            .then(|| s.get_result(rid))
            .flatten()
            .and_then(|sealed| c.vault.open_sealed(&result_aad(rid), &sealed).ok())
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok());
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
