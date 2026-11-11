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
use crate::reauth::{parse_auth_hex, Reauth, ReauthResult, Subject};
use crate::touch::{unix_now, IssueKey};
use crate::vault::VaultError;
use saiife_audit::{DecisionKind, Record};
use saiife_broker::pipeline::{self, Outcome, PendingCall, StoredCall};
use saiife_ipc::msg::{
    err, err_with, ok, ErrorCode, Request, MAX_RECORD_BYTES, OP_APPROVAL_CREATE,
    OP_APPROVAL_DECIDE, OP_APPROVAL_LIST, OP_APPROVAL_SHOW, OP_GRANT_CONSUME,
};
use saiife_ipc::peer::PeerCred;
use saiife_touch::{Assertion, TouchClass, TouchError, TouchEvidence, LOCAL_RP_ID};
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
pub(crate) async fn is_approver(ctx: &Ctx, peer: &PeerCred) -> bool {
    // The personal broker: its own user approves (§6.10.2).
    if ctx.mode == crate::ops::Mode::Personal {
        return ctx.peer_is_own(peer);
    }
    let approvers = match ctx.policy().system {
        Some(s) => s.approval.approvers.clone(),
        None => return false,
    };
    if approvers.is_empty() {
        return false;
    }
    let Some(name) = ctx.peer_name(peer).await else {
        return false;
    };
    // Windows: a `group:` entry matches the token's groups, and a user entry the peer's
    // SID (W12). `name` is the canonical `DOMAIN\name`, which a policy's `approver`
    // never equals as text. Nothing else counts: a lookup of the name's groups would
    // count the Administrators a non-elevated admin's token holds deny-only.
    if let Some(sid) = peer.sid.as_deref() {
        let (groups, users): (Vec<&String>, Vec<&String>) =
            approvers.iter().partition(|a| a.starts_with("group:"));
        let wanted: Vec<String> = groups
            .iter()
            .filter_map(|a| a.strip_prefix("group:").map(str::to_string))
            .collect();
        if ctx.token_in_any_group(&peer.group_sids, &wanted).await {
            return true;
        }
        let users: Vec<String> = users.into_iter().cloned().collect();
        return ctx
            .token_in_any_group(std::slice::from_ref(&sid.to_string()), &users)
            .await;
    }
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

/// The display is the request itself only when masking changed none of it
/// (step 8 already refused a body it would change, and a binary raw body
/// as `body_not_displayable`): only then may an identical pending request
/// be given back (decision 8). A body without a display (plan 15's binary
/// raw upload, should one ever reach here) is never faithful: its hash
/// alone is not what the approver reads.
fn display_is_faithful(p: &PendingCall) -> bool {
    p.operation == p.stored.operation
        && p.project == p.stored.project
        && *p.params.get() == p.stored.params
        && p.headers == p.stored.headers
        && p.body_sha256 == p.stored.body_sha256
        && (p.body_sha256.is_none() || p.body_display.is_some())
}

/// The class a new connector request is stored with: the stronger of the
/// broker's class (of the real capability) and the daemon's (of the masked
/// one), so masking can never weaken it. A name this version cannot read
/// is the strictest (`deploy`), as at decide.
fn combined_class(broker: Option<&str>, daemon: Option<&str>) -> Option<String> {
    let strictest = |n: &str| TouchClass::from_name(n).unwrap_or(TouchClass::Deploy);
    TouchClass::stronger(broker.map(strictest), daemon.map(strictest)).map(|c| c.name().to_string())
}

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
    let faithful = display_is_faithful(p);
    // Fail closed: the class comes from the environment-applied snapshot of
    // the call's env. Without a snapshot, or for a service it does not know,
    // the request cannot be classified, so nothing is stored.
    let touch_class = {
        const UNCLASSIFIED: &str = "touch_policy_unavailable";
        let policy = ctx.policy();
        let g = policy.gateway.as_deref().ok_or(UNCLASSIFIED)?;
        let cfg = &g.snapshot_for(p.stored.env.as_deref()).config;
        if !cfg.services.contains_key(&p.stored.service) {
            return Err(UNCLASSIFIED.into());
        }
        let here =
            saiife_policy::touch::class_for_call(cfg, &p.stored.service, p.capability.as_deref());
        combined_class(p.touch_class, here)
    };
    let new = NewRequest {
        uid: p.stored.uid,
        sid: p.stored.sid.clone(),
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
        touch_class,
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
            faithful,
        },
    };
    store_new(ctx, new, Some(exact), ttl).await
}

/// Step 9 of an mcp call (plan 17): seal `p`'s exact call (bound to its
/// id), store it with the masked display copy (type `mcp`: `service`
/// `mcp:<server>`, `operation` the tool, `body_display` the arguments) and
/// write its `approval`/`created` record. An identical pending request
/// gives its id back. Errs with the deny rule; nothing is left pending on
/// an error.
pub(crate) async fn create_mcp(
    ctx: &Arc<Ctx>,
    p: &crate::mcp_ops::PendingMcp,
    agent: &str,
) -> Result<u64, String> {
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
        sid: p.stored.sid.clone(),
        user: p.stored.user.clone(),
        session: p.stored.session.clone(),
        agent: agent.to_string(),
        project: p.project.clone(),
        kind: ApprovalType::Mcp,
        service: Some(format!("mcp:{}", p.stored.server)),
        operation: Some(p.tool.clone()),
        capability: None,
        params: Default::default(),
        input: None,
        grant_key: None,
        scope: None,
        ask_rule: None,
        touch_class: None,
        send: SendDisplay {
            body_display: Some(p.display.clone()),
            body_sha256: Some(p.stored.arguments_sha256.clone()),
            body_truncated: p.truncated,
            amount: None,
            headers: Vec::new(),
            env: p.stored.env.clone(),
            env_base: p.stored.env_recorded && p.stored.env.is_none(),
            // Step 9 refused a tool name or arguments masking would change
            // (`masked_content`); the project must be unchanged too.
            // A cut display is still compared whole by its SHA-256.
            faithful: p.tool == p.stored.tool && p.project == p.stored.project,
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
            // The grant's key and scope, as `grant_consume` computes them.
            let used = call_fields(&req).ok().map(|f| crate::hooks::UsedGrant {
                key: crate::grants::hex(&f.key(&conn.peer)),
                project: f.key_project,
            });
            let (v, granted) = grant_consume(ctx, &conn.peer, req).await;
            conn.steps().granted = granted;
            // The co-signer lets the service's `ask` deny pass only for the
            // call this connection's grant was for (plan 21).
            if let (Some(_), Some(used)) = (granted, used) {
                ctx.hooks.granted(conn.id, used);
            }
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

pub(crate) fn unavailable(id: u64, ctx: &Ctx) -> Value {
    let why = match &ctx.approvals {
        Err(e) => format!("approvals are unavailable: {e}"),
        Ok(_) => "approvals are unavailable".into(),
    };
    err(id, ErrorCode::Unavailable, &why)
}

pub(crate) fn unknown(id: u64, rid: u64) -> Value {
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
    let uid = (own || !is_approver(ctx, peer).await).then_some(peer.uid);
    let sid = peer.sid.clone();
    let Some(items) = on_store(ctx, move |_, s| s.list(Filter { uid, sid, states })).await else {
        return unavailable(id, ctx);
    };
    let mut m = Map::new();
    m.insert(
        "items".into(),
        Value::Array(
            items
                .iter()
                .map(|r| with_effective_class(ctx, r, brief(r)))
                .collect(),
        ),
    );
    ok(id, m)
}

/// The approval request's id: arg `request` (a frame's own `id` is the
/// frame's, so the spec's `id` cannot be an argument).
pub(crate) fn request_id(req: &Request) -> Result<u64, Value> {
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

/// Whether `peer` made request `r`.
fn is_requester(r: &ApprovalRequest, peer: &PeerCred) -> bool {
    crate::ops::same_principal(r.uid, r.sid.as_deref(), peer.uid, peer.sid.as_deref())
}

/// Request `rid` when `peer` may see it.
pub(crate) async fn visible(
    ctx: &Arc<Ctx>,
    peer: &PeerCred,
    rid: u64,
) -> Result<Option<ApprovalRequest>, ()> {
    let r = on_store(ctx, move |_, s| s.get(rid)).await.ok_or(())?;
    match r {
        Some(r) if is_requester(&r, peer) || is_approver(ctx, peer).await => Ok(Some(r)),
        _ => Ok(None),
    }
}

async fn show(ctx: &Arc<Ctx>, peer: &PeerCred, req: Request) -> Value {
    let id = req.id;
    let rid = match request_id(&req) {
        Ok(r) => r,
        Err(v) => return v,
    };
    match visible(ctx, peer, rid).await {
        Err(()) => unavailable(id, ctx),
        Ok(None) => unknown(id, rid),
        Ok(Some(r)) => {
            let mut m = Map::new();
            m.insert("item".into(), with_effective_class(ctx, &r, item(&r)));
            ok(id, m)
        }
    }
}

/// `v` (the [`item`] or [`brief`] of `r`) with `touch_class` the class a
/// decision needs now (D8), not only the stored one: `approval.list` and
/// `approval.show` agree.
fn with_effective_class(ctx: &Ctx, r: &ApprovalRequest, mut v: Value) -> Value {
    if let (Some(c), Some(o)) = (effective_class(ctx, r), v.as_object_mut()) {
        o.insert("touch_class".into(), c.name().into());
    }
    v
}

/// The touch class approving `r` needs (D8): the stronger of the stored
/// class and the class under the current policy. Only connector requests
/// get a class *now*, from the environment-applied snapshot of `r.env`
/// (as `create` classifies); no gateway, an environment with no snapshot
/// or a service the snapshot does not know give none *now*, so the stored
/// class still counts: never weaker. A stored class this version cannot
/// read is the strictest (`deploy`, needs UV), never none.
pub(crate) fn effective_class(ctx: &Ctx, r: &ApprovalRequest) -> Option<TouchClass> {
    let strictest = |n: &str| TouchClass::from_name(n).unwrap_or(TouchClass::Deploy);
    let stored = r.touch_class.as_deref().map(strictest);
    let now = match r.kind {
        ApprovalType::Connector => class_now(ctx, r).map(strictest),
        ApprovalType::Command | ApprovalType::Mcp => None,
    };
    TouchClass::stronger(stored, now)
}

/// The class name of connector request `r` under the current policy.
fn class_now(ctx: &Ctx, r: &ApprovalRequest) -> Option<&'static str> {
    let policy = ctx.policy();
    let g = policy.gateway.as_deref()?;
    let snap = match r.env.as_deref() {
        Some(e) => g.by_env.get(e)?,
        None => &g.snap,
    };
    let service = r.service.as_deref()?;
    if !snap.config.services.contains_key(service) {
        return None;
    }
    saiife_policy::touch::class_for_call(&snap.config, service, r.capability.as_deref())
}

/// The re-authentication of a caller whose process start time is not
/// known: available as the real one says, but every check is an error.
pub(crate) struct NoStartTime<'a>(pub(crate) &'a dyn Reauth);

impl Reauth for NoStartTime<'_> {
    fn available(&self) -> bool {
        self.0.available()
    }
    fn off_text(&self) -> Option<&'static str> {
        self.0.off_text()
    }
    fn check(&self, _who: &Subject, _d: &str, _t: Duration) -> ReauthResult {
        ReauthResult::Error("the approver's process start time is unknown".into())
    }
}

/// The optional `auth` argument (macOS): absent or null is `None`; anything
/// but 64 lowercase hex characters is a bad request.
pub(crate) fn auth_arg(args: &Map<String, Value>) -> Result<Option<[u8; 32]>, String> {
    match args.get("auth") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => parse_auth_hex(s).map(Some),
        Some(_) => Err("auth is 64 lowercase hex characters".into()),
    }
}

/// Refuse a decision on `r` by `by`: an `approval`/`refused` record with
/// `rule`, and `forbidden` with the rule.
pub(crate) async fn refuse(
    ctx: &Arc<Ctx>,
    r: &ApprovalRequest,
    by: &PeerCred,
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
fn decided_record(ctx: &Ctx, r: &ApprovalRequest, action: &str, by: &PeerCred) -> Record {
    let mut rec = ctx.approval_record(r, action);
    rec.extra.insert("by_uid".into(), by.uid.into());
    // Windows: every elevated admin's uid is 0, so `by_uid` alone names nobody.
    if let Some(sid) = &by.sid {
        rec.extra.insert("by_sid".into(), sid.clone().into());
    }
    rec
}

async fn decide(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value {
    let id = req.id;
    let peer = conn.peer.clone();
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
    let auth = match auth_arg(&req.args) {
        Ok(a) => a,
        Err(e) => return err(id, ErrorCode::BadRequest, &e),
    };
    let r = match visible(ctx, &peer, rid).await {
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
        let why = if r.kind == ApprovalType::Mcp {
            "the arguments are over 4 KiB and shown cut; approve with ack_truncated (--accept-truncated)"
        } else {
            "the body is over 1 MiB and shown cut; approve with ack_truncated (--accept-truncated)"
        };
        return refuse(ctx, &r, &peer, id, "truncated_not_acknowledged", why).await;
    }

    // A touch-class approval needs a `touch` argument that is an assertion.
    // Checked before who may decide, as the acknowledgement is: no
    // re-authentication prompt for an approval refused anyway. It is
    // verified (and its challenge spent) only after that, below.
    let early_touch = match effective_class(ctx, &r).filter(|_| approve) {
        None => None,
        Some(class) => match touch_arg(&r, &req, class) {
            Ok(a) => Some(a),
            Err(e) => return touch_refused(ctx, &r, &peer, id, e).await,
        },
    };

    // The requester may always withdraw its own request: a rejection that
    // lets nothing through needs no approver and no re-authentication.
    let cancel = !approve && is_requester(&r, &peer);
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
        match ctx.peer_is_own(&peer) {
            true => None,
            false => Some(Refusal::NotApprover),
        }
    } else {
        match ctx.peer_name(&peer).await {
            None => Some(Refusal::NotApprover),
            Some(name) => {
                let c = Arc::clone(ctx);
                let peer = peer.clone();
                let start = conn.start_time;
                let requester = r.uid;
                let requester_sid = r.sid.clone();
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
                        (requester, requester_sid.as_deref()),
                        reauth,
                        &peer,
                        start.unwrap_or(0),
                        c.proc.as_ref(),
                        &c.reauth_cooldowns,
                        &detail,
                        auth,
                    )
                })
                .await
                .unwrap_or_else(|e| Err(Refusal::ReauthError(e.to_string())))
                .err()
            }
        }
    };
    if let Some(why) = refusal {
        return refuse(ctx, &r, &peer, id, why.rule(), &why.to_string()).await;
    }

    // A touch-class approval needs an assertion over the challenge issued
    // for this request (`touch.begin`). A rejection or a withdrawal lets
    // nothing through and needs none. The class is taken again: a reload
    // during the re-authentication can only make it stronger (D8), and a
    // class that appeared meanwhile still needs its `touch` argument.
    let evidence = match effective_class(ctx, &r).filter(|_| approve) {
        None => None,
        Some(class) => {
            let asr = match early_touch {
                Some(a) => Ok(a),
                None => touch_arg(&r, &req, class),
            };
            match asr {
                Ok(asr) => match touch_for(ctx, &r, &peer, asr, class).await {
                    Ok(ev) => Some(ev),
                    Err(e) => return touch_refused(ctx, &r, &peer, id, e).await,
                },
                Err(e) => return touch_refused(ctx, &r, &peer, id, e).await,
            }
        }
    };

    let to = if approve {
        State::Approved
    } else {
        State::Rejected
    };
    let by = (peer.uid, peer.sid.clone());
    let moved = on_store(ctx, move |_, s| {
        s.transition_by(rid, &[State::Pending], to, Some(by), note, now())
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
    let mut rec = decided_record(ctx, &r, action, &peer);
    if let Some(ev) = &evidence {
        rec = crate::approvals::record_with_touch(rec, ev);
    }
    let recorded = ctx.writer.append(rec).await;
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
    if approve && matches!(r.kind, ApprovalType::Connector | ApprovalType::Mcp) {
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

/// Why [`touch_for`] did not verify a touch.
enum TouchRefused {
    /// The `touch` argument is not an assertion.
    BadRequest(String),
    /// Refused as `refuse` records it; the request stays pending.
    Refused(Refusal),
}

/// The `touch` argument of an approval of `r`, which needs a touch of
/// class `class`. Absent or null: refused (`touch_unavailable`, recorded
/// by [`touch_refused`]). Not an assertion: a bad request. Neither spends
/// the challenge: nothing was verified.
fn touch_arg(
    r: &ApprovalRequest,
    req: &Request,
    class: TouchClass,
) -> Result<Assertion, TouchRefused> {
    let rid = r.id;
    let Some(t) = req.args.get("touch").filter(|t| !t.is_null()) else {
        return Err(TouchRefused::Refused(Refusal::TouchUnavailable(format!(
            "request #{rid} needs a touch ({}) from an enrolled device",
            class.name()
        ))));
    };
    serde_json::from_value(t.clone())
        .map_err(|e| TouchRefused::BadRequest(format!("touch is not an assertion: {e}")))
}

/// The answer to a decision whose touch was refused: `bad_request`, or an
/// `approval`/`refused` record and `forbidden`. The request stays pending.
async fn touch_refused(
    ctx: &Arc<Ctx>,
    r: &ApprovalRequest,
    peer: &PeerCred,
    id: u64,
    e: TouchRefused,
) -> Value {
    match e {
        TouchRefused::BadRequest(m) => err(id, ErrorCode::BadRequest, &m),
        TouchRefused::Refused(why) => refuse(ctx, r, peer, id, why.rule(), &why.to_string()).await,
    }
}

/// Verifies `asr`, the parsed `touch` argument of a decision on `r` (see
/// [`touch_arg`]), as a touch of class `class` by `peer`, against the live
/// `Approve(r.id)` challenge and the peer's own credentials (D6). The
/// action record is built from `r`, the request `decide` loaded, and the
/// challenge's nonce and expiry; nothing but the assertion comes from the
/// client. Once here the challenge is spent whatever the outcome; an
/// absent or unparsable `touch` never gets here, so it spends nothing.
async fn touch_for(
    ctx: &Arc<Ctx>,
    r: &ApprovalRequest,
    peer: &PeerCred,
    asr: Assertion,
    class: TouchClass,
) -> Result<TouchEvidence, TouchRefused> {
    let rid = r.id;
    let c = Arc::clone(ctx);
    let r = r.clone();
    let uid = peer.uid;
    tokio::task::spawn_blocking(move || {
        let instance = c.touch.instance_id();
        c.touch.consume(
            &IssueKey::Approve(rid),
            uid,
            |i| crate::approvals::action_record(&r, class, instance, i.nonce, i.expires_at),
            &asr,
            LOCAL_RP_ID,
            unix_now(),
        )
    })
    .await
    .unwrap_or(Err(TouchError::Unavailable))
    .map(|(ev, _)| ev)
    .map_err(|e| TouchRefused::Refused(Refusal::from(e)))
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
    /// The grant key for this call by `peer`: computed here, never taken
    /// from the client.
    fn key(&self, peer: &PeerCred) -> [u8; 32] {
        if let Some(sid) = &peer.sid {
            return crate::grants::grant_key_for_sid(
                sid,
                &self.agent,
                &self.key_project,
                &self.tool,
                &self.input,
                &self.raw_sha256,
            );
        }
        crate::grants::grant_key(
            peer.uid,
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
    within_project(&f.project, &f.key_project)
}

/// Whether `project` (a cwd) is the project root `root` or below it, by
/// the rules of [`project_ok`]. The co-signer checks a co-signed body's
/// `cwd` against the root of the grant its hook used (plan 21).
pub(crate) fn within_project(project: &str, root: &str) -> bool {
    if cfg!(windows) {
        return windows_within(project, root);
    }
    normal_absolute(project)
        && normal_absolute(root)
        && std::path::Path::new(project).starts_with(root)
}

/// No `.` or `..` component in `p`, past a device prefix (`\\?\`, `\\.\`, `\??\`).
fn windows_no_dots(p: &str) -> bool {
    let body = [r"\\?\", r"\\.\", r"\??\", "//?/", "//./"]
        .iter()
        .find_map(|pre| p.strip_prefix(pre))
        .unwrap_or(p);
    body.split(['\\', '/']).all(|c| c != "." && c != "..")
}

/// [`project_ok`] on Windows, where the hook sends `std::fs::canonicalize`'s paths
/// (`\\?\C:\…`). Both sides are read by the guard's Windows path rules (W6): the verbatim
/// prefix goes, the drive letter is one case and `\` and `/` are one separator, so the same
/// directory compares equal however it was spelled. Neither may be relative or hold a `.`
/// or `..`, and neither may be one the rules cannot read. A UNC or device path is taken only
/// as exactly the project root: a share or device is never "below" a root here.
fn windows_within(project: &str, root: &str) -> bool {
    use saiifeguard::canon::PathVars;
    use saiifeguard::winpath;
    if !windows_no_dots(project) || !windows_no_dots(root) {
        return false;
    }
    let vars = PathVars::new();
    let (Ok(p), Ok(r)) = (
        winpath::read(project, None, &vars),
        winpath::read(root, None, &vars),
    ) else {
        // A device path (`\\?\Volume{…}`) has no form: only itself, spelled the same.
        let device = |s: &str| s.starts_with(r"\\?\") || s.starts_with(r"\\.\");
        return device(project) && project == root;
    };
    if p.starts_with("//") || r.starts_with("//") {
        return p == r;
    }
    let base = r.trim_end_matches('/');
    p == r
        || p.strip_prefix(base)
            .is_some_and(|rest| rest.starts_with('/'))
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
    let key = f.key(peer);
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
            rec.sid = peer.sid.clone();
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
    rec.sid = peer.sid.clone();
    rec.user = ctx.peer_name(peer).await;
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
    // A user pack's rule is checked against the pack file the daemon holds.
    let user = sys.user_packs.iter().find(|u| u.id == pack).cloned();
    let matches = tokio::task::spawn_blocking(move || match user {
        Some(u) => {
            let src = [saiifeguard::userpack::UserSrc {
                source: &u.path,
                text: &u.text,
            }];
            saiifeguard::userpack::load_user_packs_cached(
                &src,
                saiifeguard::canon::PathStyle::host(),
                saiifeguard::profile::Profile::Host,
            )
            .ok()
            .and_then(|v| v.into_iter().next())
            .is_some_and(|p| saiifeguard::builtins::pack_rule_denies(&p, &rule_id, &input))
        }
        None => saiifeguard::builtins::builtin_rule_denies(&pack, &rule_id, &input),
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
        sid: peer.sid.clone(),
        user: ctx.peer_name(peer).await.unwrap_or_default(),
        session: f.session.clone(),
        agent: f.agent.clone(),
        project: f.project.clone(),
        kind: ApprovalType::Command,
        service: None,
        operation: None,
        capability: None,
        params: Default::default(),
        input: Some(f.input.clone()),
        grant_key: Some(crate::grants::hex(&f.key(peer))),
        scope: Some(f.key_project.clone()),
        ask_rule: f.ask(),
        touch_class: None,
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
    if r.kind == ApprovalType::Mcp {
        return send_mcp(Arc::clone(&ctx), r, by, exact).await;
    }
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
    let (g, env_name, groups) = match send_env(
        &ctx,
        (&stored.user, r.sid.as_deref()),
        stored.env.as_deref(),
        stored.env_recorded,
    )
    .await
    {
        Ok(x) => x,
        Err((rule, message)) => return fail(&ctx, &r, rule, message).await,
    };
    let snap = g.snapshot_for(env_name.as_deref());
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

/// The policy, environment and groups an approved request of `user` is
/// sent under, chosen as for a new call: locked mode takes the scope's
/// environment as it is now, developer mode the one the request was asked
/// under (`env`). An approved request is sent under the environment it was
/// asked under or not at all (`env_changed`): locked mode refuses a scope
/// rebound to another environment (or from the base config to one) since
/// the ask, developer mode an environment no longer defined (never the
/// base config instead). Only a request sealed before the environment was
/// recorded (`env_recorded` false, no `env`) is not checked. `sid` is the
/// requester's on Windows, for a scope that names it (see [`Groups::of`]).
/// `Err` is the failure's rule and message.
async fn send_env(
    ctx: &Arc<Ctx>,
    (user, sid): (&str, Option<&str>),
    env: Option<&str>,
    env_recorded: bool,
) -> Result<SendEnv, (&'static str, &'static str)> {
    let state = ctx.policy();
    let Some(g) = state.gateway.clone() else {
        return Err(("policy_invalid", "no valid policy is loaded"));
    };
    let groups = if user.is_empty() {
        Vec::new()
    } else {
        ctx.groups_of(user).await
    };
    let groups = Groups::of(ctx, &g, user, sid, groups).await;
    let mode = crate::api_ops::gateway_mode(ctx);
    let env_name = match g.select_env(mode, &groups, user, env) {
        Ok((e, _)) => e.map(str::to_string),
        Err(_) => {
            return Err((
                crate::ops::UNKNOWN_ENV_RULE,
                "the scope's environment has no policy snapshot",
            ))
        }
    };
    if (env_recorded || env.is_some()) && env_name.as_deref() != env {
        let message = match mode {
            saiife_policy::Mode::Locked => {
                "the scope's environment changed since the request was asked"
            }
            saiife_policy::Mode::Developer => {
                "the environment the request was asked under is no longer defined"
            }
        };
        return Err((ENV_CHANGED, message));
    }
    Ok((g, env_name, groups))
}

/// What [`send_env`] chose: the policy, the environment and the groups.
type SendEnv = (Arc<crate::ops::GatewayPolicy>, Option<String>, Groups);

/// [`send`] for an mcp request: the sealed `StoredMcpCall`, re-run through
/// steps 3–8 under the policy in force now, then sent through the daemon's
/// tool caller. Its `connector` record has `via = approval`.
async fn send_mcp(ctx: Arc<Ctx>, r: ApprovalRequest, by: u32, exact: Zeroizing<Vec<u8>>) {
    use crate::mcp_ops::{self, McpOutcome, StoredMcpCall};
    let rid = r.id;
    let Ok(stored) = serde_json::from_slice::<StoredMcpCall>(&exact) else {
        return fail(
            &ctx,
            &r,
            "stored_request_invalid",
            "the stored request cannot be read",
        )
        .await;
    };
    drop(exact);
    let service = format!("mcp:{}", stored.server);
    if stored.uid != r.uid || r.service.as_deref() != Some(service.as_str()) {
        return fail(
            &ctx,
            &r,
            "stored_request_invalid",
            "the stored request is another uid's or another server's",
        )
        .await;
    }
    let (g, env_name, groups) = match send_env(
        &ctx,
        (&stored.user, r.sid.as_deref()),
        stored.env.as_deref(),
        stored.env_recorded,
    )
    .await
    {
        Ok(x) => x,
        Err((rule, message)) => return fail(&ctx, &r, rule, message).await,
    };
    let snap = g.snapshot_for(env_name.as_deref());
    let tools = Arc::clone(&ctx.tool_caller);
    let (call, outcome, trace) = mcp_ops::send_approved(
        &ctx,
        tools.as_ref(),
        &stored,
        r.body_sha256.as_deref(),
        snap,
        &groups,
        &r.agent,
    )
    .await;
    let asked_via = stored.via.clone();
    drop(stored);
    if let McpOutcome::Limited { limit } = &outcome {
        ctx.notify_limit(
            r.uid,
            r.service.as_deref().unwrap_or(""),
            r.operation.as_deref().unwrap_or(""),
            limit,
        );
    }
    // The connector record of the send: `via = approval`, linked by id,
    // with how the call first came in.
    let mut rec = mcp_ops::mcp_record(&call, snap, &trace, &outcome, &r.agent, VERSION);
    rec.extra.insert("approval".into(), rid.into());
    rec.extra.insert("approved_by".into(), by.into());
    rec.extra
        .insert("asked_via".into(), asked_via.clone().into());
    let recorded = ctx.writer.append(rec).await;
    let detail = Detail {
        rule: match &outcome {
            McpOutcome::Denied { rule } => Some(rule.clone()),
            _ => None,
        },
        reason: match &outcome {
            McpOutcome::UpstreamFailed { reason } => Some(format!("upstream failed: {reason}")),
            McpOutcome::Limited { limit } => Some(format!("limit reached: {limit}")),
            _ => None,
        },
        limit: match &outcome {
            McpOutcome::Limited { limit } => Some(limit.to_string()),
            _ => None,
        },
        status: None,
        resp_bytes: trace.resp_bytes,
        asked_via: Some(asked_via),
    };
    let to = if matches!(outcome, McpOutcome::Done { .. }) {
        State::Sent
    } else {
        State::SendFailed
    };
    let mut result = mcp_ops::answer(0, outcome);
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
        sid: None,
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
pub(crate) async fn result_for(
    ctx: &Arc<Ctx>,
    uid: u32,
    sid: Option<&str>,
    rid: u64,
) -> Result<ResultView, ()> {
    let sid = sid.map(str::to_string);
    let got = on_store(ctx, move |c, s| {
        let r = s.get(rid)?;
        if !crate::ops::same_principal(r.uid, r.sid.as_deref(), uid, sid.as_deref()) {
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
    let view = match result_for(ctx, peer.uid, peer.sid.as_deref(), rid).await {
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

#[cfg(test)]
mod requester_tests {
    use super::*;

    fn peer(uid: u32, sid: Option<&str>) -> PeerCred {
        PeerCred {
            uid,
            gid: 0,
            pid: 1,
            sid: sid.map(str::to_string),
            group_sids: Vec::new(),
        }
    }

    fn request(uid: u32, sid: Option<&str>) -> ApprovalRequest {
        serde_json::from_value(json!({
            "id": 1, "created": "c", "expires": "e", "uid": uid, "sid": sid, "user": "u",
            "session": null, "agent": "a", "project": "p", "type": "connector",
            "service": null, "operation": null, "capability": null, "params": {},
            "input": null, "grant_key": null, "state": "pending"
        }))
        .unwrap()
    }

    const A: &str = "S-1-5-21-1-2-3-1001";
    const B: &str = "S-1-5-21-1-2-3-1002";

    /// `visible` and withdraw: another admin, with the same uid 0, did not make it.
    #[test]
    fn the_requester_is_a_sid_on_windows() {
        let r = request(0, Some(A));
        assert!(is_requester(&r, &peer(0, Some(A))));
        assert!(!is_requester(&r, &peer(0, Some(B))));
        // The same SID elevated later: same person, another label.
        assert!(is_requester(&r, &peer(0x4000_0001, Some(A))));
    }

    /// A label collision is no identity either.
    #[test]
    fn a_shared_label_is_not_the_requester() {
        let r = request(0x4000_0001, Some(A));
        assert!(!is_requester(&r, &peer(0x4000_0001, Some(B))));
    }

    /// What a Windows hook sends (`std::fs::canonicalize`) matches its project however
    /// each side is spelled; a sibling with the same prefix does not.
    #[test]
    fn a_hook_shaped_windows_path_matches_its_project() {
        let root = r"\\?\C:\Users\a\p";
        for cwd in [
            r"\\?\C:\Users\a\p",
            r"\\?\C:\Users\a\p\sub\dir",
            r"C:\Users\a\p\sub",
            r"\\?\c:\Users\a\p\sub",
            "C:/Users/a/p/sub",
        ] {
            assert!(windows_within(cwd, root), "{cwd}");
        }
        assert!(windows_within(r"\\?\C:\Users\a\p\sub", r"c:\Users\a\p"));
        assert!(windows_within(r"\\?\C:\w\x", r"\\?\C:\"));
        for cwd in [r"\\?\C:\Users\a\pp", r"\\?\C:\Users\a", r"\\?\D:\Users\a\p"] {
            assert!(!windows_within(cwd, root), "{cwd}");
        }
    }

    #[test]
    fn dots_and_relative_windows_paths_are_refused() {
        let root = r"\\?\C:\Users\a\p";
        for cwd in [
            r"\\?\C:\Users\a\p\..\q",
            r"\\?\C:\Users\a\p\sub\..",
            r"C:\Users\a\p\.\sub",
            r"p\sub",
            r"sub",
            r"C:p\sub",
            "",
        ] {
            assert!(!windows_within(cwd, root), "{cwd:?}");
        }
        // A `..` in the root lets nothing in either.
        assert!(!windows_within(r"\\?\C:\Users\x", r"\\?\C:\Users\a\.."));
        assert!(!windows_within(r"\\?\C:\Users\a\p", r"Users\a\p"));
    }

    /// A share or a device is a project only as itself, never as a root with paths below.
    #[test]
    fn unc_and_device_windows_paths_only_as_themselves() {
        let unc = r"\\?\UNC\server\share\p";
        assert!(windows_within(unc, unc));
        assert!(windows_within(r"\\server\share\p", unc));
        assert!(!windows_within(r"\\?\UNC\server\share\p\sub", unc));
        assert!(!windows_within(unc, r"\\?\C:\"));
        assert!(!windows_within(r"\\?\C:\p", unc));
        let dev = r"\\?\Volume{12345678-1234-1234-1234-123456789abc}\p";
        assert!(windows_within(dev, dev));
        assert!(!windows_within(&format!(r"{dev}\sub"), dev));
        assert!(!windows_within(dev, r"\\?\C:\"));
        assert!(!windows_within(r"\\.\PhysicalDrive0", r"\\?\C:\"));
        assert!(!windows_within(r"\\?\C:\p", r"\\.\PhysicalDrive0"));
    }

    #[test]
    fn unix_requesters_stay_uids() {
        let r = request(1000, None);
        assert!(is_requester(&r, &peer(1000, None)));
        assert!(!is_requester(&r, &peer(1001, None)));
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use saiife_broker::mask::Masker;
    use serde_json::json;

    fn pending(body_display: Option<&str>, body_sha256: Option<&str>) -> PendingCall {
        let stored: StoredCall = serde_json::from_value(json!({
            "uid": 1000, "user": "u", "session": null, "project": "/p",
            "service": "s3_ask", "operation": "s3.put_object",
            "params": {"bucket": "reports", "key": "logo.png"},
            "body_b64": null, "body_sha256": body_sha256, "headers": [],
            "overlay": null, "via": "cli",
        }))
        .unwrap();
        PendingCall {
            operation: stored.operation.clone(),
            capability: None,
            params: Masker::new(&[]).mask_params(&stored.params),
            project: stored.project.clone(),
            body_display: body_display.map(str::to_string),
            body_truncated: false,
            body_sha256: body_sha256.map(str::to_string),
            amount: None,
            headers: vec![],
            touch_class: None,
            stored,
        }
    }

    /// The stored class is the stronger of the broker's and the daemon's;
    /// an unreadable name is the strictest.
    #[test]
    fn combined_class_is_the_stronger() {
        assert_eq!(combined_class(None, None), None);
        assert_eq!(
            combined_class(Some("deploy"), None).as_deref(),
            Some("deploy")
        );
        assert_eq!(
            combined_class(None, Some("deploy")).as_deref(),
            Some("deploy")
        );
        assert_eq!(
            combined_class(Some("egress:external"), Some("deploy")).as_deref(),
            Some("deploy")
        );
        assert_eq!(
            combined_class(Some("deploy"), Some("egress:external")).as_deref(),
            Some("deploy")
        );
        assert_eq!(
            combined_class(Some("egress:external"), None).as_deref(),
            Some("egress:external")
        );
        assert_eq!(
            combined_class(Some("future"), None).as_deref(),
            Some("deploy")
        );
    }

    /// Plan 15's binary raw body meets plan 17's dedupe: a body the
    /// approver is not shown is never faithful, so it is never deduped.
    #[test]
    fn body_without_display_is_never_faithful() {
        let h = "ab".repeat(32);
        assert!(display_is_faithful(&pending(Some("text upload"), Some(&h))));
        assert!(display_is_faithful(&pending(None, None)));
        assert!(!display_is_faithful(&pending(None, Some(&h))));
    }

    /// A connector call to a `deploy`-marked operation is stored with its
    /// touch class; an unmarked one with none.
    #[tokio::test]
    async fn connector_create_sets_the_class() {
        let d = tempfile::tempdir().unwrap();
        let (mut ctx, _join) = crate::ops::test_ctx(d.path(), crate::ops::Mode::Locked, 0);
        let store = crate::approvals::Store::open(&d.path().join("approvals")).unwrap();
        let key = d.path().join("vault-key");
        std::fs::write(&key, [7u8; 32]).unwrap();
        std::fs::set_permissions(
            &key,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
        )
        .unwrap();
        let v = crate::vault::open(&key, &d.path().join("vault").join("vault.bin"));
        assert!(matches!(v, crate::vault::VaultState::Ready(_)));
        let c = Arc::get_mut(&mut ctx).unwrap();
        c.approvals = Ok(store);
        c.vault = crate::vault::Shared::new(v);
        let cfg: saiife_policy::SystemConfig = toml::from_str(
            "version = 2\nlocked = true\n[services.s3_ask]\nconnector = \"s3\"\n\
             deploy = [\"objects:write\"]\n",
        )
        .unwrap();
        let g = crate::ops::GatewayPolicy::build(
            &cfg,
            &[],
            saiife_broker::Catalog::default(),
            saiife_policy::Mode::Locked,
        )
        .unwrap();
        *ctx.policy.lock().unwrap() = crate::ops::PolicyState {
            ok: true,
            system: Some(Arc::new(cfg)),
            gateway: Some(Arc::new(g)),
            ..crate::ops::PolicyState::invalid(0)
        };
        let mut marked = pending(None, None);
        marked.capability = Some("objects:write".into());
        let id = create(&ctx, &marked, "claude").await.unwrap();
        let r = ctx.approvals.as_ref().unwrap().get(id).unwrap();
        assert_eq!(r.touch_class.as_deref(), Some("deploy"));

        let mut plain = pending(Some("other"), None);
        plain.capability = Some("objects:read".into());
        let id = create(&ctx, &plain, "claude").await.unwrap();
        let r = ctx.approvals.as_ref().unwrap().get(id).unwrap();
        assert_eq!(r.touch_class, None);

        // An unparsable or missing capability on a deploy-marked service is
        // the strictest class, never none.
        for cap in [Some("not a capability"), None] {
            let mut bad = pending(Some("third"), None);
            bad.capability = cap.map(str::to_string);
            let id = create(&ctx, &bad, "claude").await.unwrap();
            let r = ctx.approvals.as_ref().unwrap().get(id).unwrap();
            assert_eq!(r.touch_class.as_deref(), Some("deploy"), "{cap:?}");
        }

        // Final review Minor 2: the masked capability classifies weaker
        // than the real one (the masker rewrote its qualifier); the broker's
        // class of the real one still counts.
        let mut masked = pending(Some("fourth"), None);
        masked.capability = Some("objects:read".into());
        masked.touch_class = Some("deploy");
        let id = create(&ctx, &masked, "claude").await.unwrap();
        let r = ctx.approvals.as_ref().unwrap().get(id).unwrap();
        assert_eq!(r.touch_class.as_deref(), Some("deploy"));

        // A service the snapshot does not know cannot be classified.
        let before = ctx
            .approvals
            .as_ref()
            .unwrap()
            .list(crate::approvals::Filter::default())
            .len();
        let mut unknown = pending(Some("fourth"), None);
        unknown.stored.service = "nope".into();
        let e = create(&ctx, &unknown, "claude").await.unwrap_err();
        assert_eq!(e, "touch_policy_unavailable");
        assert_eq!(
            ctx.approvals
                .as_ref()
                .unwrap()
                .list(crate::approvals::Filter::default())
                .len(),
            before
        );
    }

    /// No gateway snapshot: the request is refused and nothing is stored.
    #[tokio::test]
    async fn connector_create_without_a_gateway_refuses() {
        let d = tempfile::tempdir().unwrap();
        let (mut ctx, _join) = crate::ops::test_ctx(d.path(), crate::ops::Mode::Locked, 0);
        let store = crate::approvals::Store::open(&d.path().join("approvals")).unwrap();
        Arc::get_mut(&mut ctx).unwrap().approvals = Ok(store);
        let e = create(&ctx, &pending(None, None), "claude")
            .await
            .unwrap_err();
        assert_eq!(e, "touch_policy_unavailable");
        assert!(ctx
            .approvals
            .as_ref()
            .unwrap()
            .list(crate::approvals::Filter::default())
            .is_empty());
    }

    #[test]
    fn auth_arg_is_optional_hex() {
        let a = |v: Value| v.as_object().unwrap().clone();
        assert_eq!(auth_arg(&a(json!({}))), Ok(None));
        assert_eq!(auth_arg(&a(json!({"auth": null}))), Ok(None));
        assert_eq!(
            auth_arg(&a(json!({"auth": "0f".repeat(32)}))),
            Ok(Some([0x0f; 32]))
        );
        for bad in [json!("0F".repeat(32)), json!("ab"), json!(7), json!([1])] {
            assert!(auth_arg(&a(json!({ "auth": bad }))).is_err(), "{bad}");
        }
    }

    /// Windows' withdraw through `decide`, with peers that carry a SID as the pipe's do:
    /// another SID with the same label 0 does not see the request and cannot withdraw
    /// it; the requester's SID can. The end-to-end half is windows_daemon.rs's
    /// `the_requester_withdraws_its_own_request`.
    #[tokio::test]
    async fn another_sid_with_the_same_label_cannot_withdraw() {
        const A: &str = "S-1-5-21-1-2-3-1001";
        const B: &str = "S-1-5-21-1-2-3-1002";
        let d = tempfile::tempdir().unwrap();
        let (mut ctx, _join) = crate::ops::test_ctx(d.path(), crate::ops::Mode::Locked, 0);
        let store = crate::approvals::Store::open(&d.path().join("approvals")).unwrap();
        Arc::get_mut(&mut ctx).unwrap().approvals = Ok(store);
        let cfg: saiife_policy::SystemConfig =
            toml::from_str("version = 2\nlocked = true\n").unwrap();
        *ctx.policy.lock().unwrap() = crate::ops::PolicyState {
            system: Some(Arc::new(cfg)),
            ..crate::ops::PolicyState::invalid(0)
        };
        let new = NewRequest {
            uid: 0,
            sid: Some(A.into()),
            user: "a".into(),
            session: None,
            agent: "claude".into(),
            project: "/w".into(),
            kind: ApprovalType::Command,
            service: None,
            operation: None,
            capability: None,
            params: Default::default(),
            input: Some("git push --force".into()),
            grant_key: None,
            scope: None,
            ask_rule: None,
            touch_class: None,
            send: SendDisplay::default(),
        };
        let rid = ctx
            .approvals
            .as_ref()
            .unwrap()
            .create(new, |_| Ok(None), Duration::from_secs(600), now())
            .unwrap()
            .id;
        let as_sid = |sid: &str| {
            Conn::new(
                PeerCred {
                    uid: 0,
                    gid: 0,
                    pid: 1,
                    sid: Some(sid.into()),
                    group_sids: Vec::new(),
                },
                Some(1),
            )
        };
        let withdraw = || Request {
            id: 4,
            op: OP_APPROVAL_DECIDE.into(),
            args: json!({"request": rid, "action": "reject"})
                .as_object()
                .unwrap()
                .clone(),
        };
        let state = || ctx.approvals.as_ref().unwrap().get(rid).unwrap();

        let v = decide(&ctx, &as_sid(B), withdraw()).await;
        assert_eq!(v["ok"], false, "{v}");
        assert!(v.to_string().contains("(or not yours)"), "{v}");
        assert_eq!(state().state, State::Pending);

        let v = decide(&ctx, &as_sid(A), withdraw()).await;
        assert_eq!(v["ok"], true, "{v}");
        let r = state();
        assert_eq!(r.state, State::Rejected);
        assert_eq!(r.note.as_deref(), Some(CANCELLED));
        assert_eq!(r.decided_by_sid.as_deref(), Some(A));
    }

    /// Windows' accounts as the locked-windows CI has them: a policy names `approver`,
    /// and the daemon's lookup of the pipe peer's SID says `HOST\approver`.
    struct CiAccounts;

    const AGENT_SID: &str = "S-1-5-21-1-2-3-1003";
    const APPROVER_SID: &str = "S-1-5-21-1-2-3-1004";

    impl saiife_policy::WinAccounts for CiAccounts {
        fn lookup_name(&self, name: &str) -> Result<(String, String), String> {
            let bare = name
                .rsplit('\\')
                .next()
                .unwrap_or(name)
                .to_ascii_lowercase();
            match bare.as_str() {
                "agent" => Ok((AGENT_SID.into(), r"HOST\agent".into())),
                "approver" => Ok((APPROVER_SID.into(), r"HOST\approver".into())),
                "administrators" => Ok((
                    saiife_win::sid::ADMINISTRATORS.into(),
                    r"BUILTIN\Administrators".into(),
                )),
                _ => Err(format!("no account {name}")),
            }
        }
        fn lookup_sid(&self, sid: &str) -> Result<String, String> {
            match sid {
                AGENT_SID => Ok(r"HOST\agent".into()),
                APPROVER_SID => Ok(r"HOST\approver".into()),
                _ => Err(format!("no SID {sid}")),
            }
        }
        /// The approver is a non-elevated admin: Windows lists it in Administrators by
        /// name, while its token holds that group deny-only.
        fn local_groups_of(&self, user: &str) -> Result<Vec<String>, String> {
            Ok(match user.to_ascii_lowercase().ends_with("approver") {
                true => vec!["Users".into(), "Administrators".into()],
                false => vec!["Users".into()],
            })
        }
        fn local_group_members(&self, group: &str) -> Result<Vec<String>, String> {
            Err(format!("no group {group}"))
        }
    }

    fn sid_conn(sid: &str) -> Conn {
        Conn::new(
            PeerCred {
                uid: saiife_win::sid::uid_of(sid, false),
                gid: 0,
                pid: 1,
                sid: Some(sid.into()),
                group_sids: Vec::new(),
            },
            Some(1),
        )
    }

    fn windows_ctx(d: &std::path::Path) -> (Arc<Ctx>, std::thread::JoinHandle<()>) {
        let (mut ctx, join) = crate::ops::test_ctx(d, crate::ops::Mode::Locked, 0);
        let store = crate::approvals::Store::open(&d.join("approvals")).unwrap();
        let c = Arc::get_mut(&mut ctx).unwrap();
        c.approvals = Ok(store);
        c.directory = Arc::new(saiife_policy::WinDirectory::new(CiAccounts));
        let cfg: saiife_policy::SystemConfig = toml::from_str(
            "version = 2\nlocked = true\n[approval]\napprovers = [\"approver\"]\nsame_user = \"deny\"\n",
        )
        .unwrap();
        *ctx.policy.lock().unwrap() = crate::ops::PolicyState {
            system: Some(Arc::new(cfg)),
            ..crate::ops::PolicyState::invalid(0)
        };
        (ctx, join)
    }

    /// locked-windows CI run 9: `approvers = ["approver"]` never matched the daemon's
    /// `HOST\approver`, so the second account saw no request ("or not yours") and was
    /// no approver for lockdown. The entry names the account when the SIDs agree.
    #[tokio::test]
    async fn a_bare_approver_name_matches_its_windows_account() {
        let d = tempfile::tempdir().unwrap();
        let (ctx, _join) = windows_ctx(d.path());
        let new = NewRequest {
            uid: saiife_win::sid::uid_of(AGENT_SID, false),
            sid: Some(AGENT_SID.into()),
            user: r"HOST\agent".into(),
            session: None,
            agent: "claude".into(),
            project: "/w".into(),
            kind: ApprovalType::Command,
            service: None,
            operation: None,
            capability: None,
            params: Default::default(),
            input: Some("git push --force".into()),
            grant_key: None,
            scope: None,
            ask_rule: None,
            touch_class: None,
            send: SendDisplay::default(),
        };
        let rid = ctx
            .approvals
            .as_ref()
            .unwrap()
            .create(new, |_| Ok(None), Duration::from_secs(600), now())
            .unwrap()
            .id;
        assert!(is_approver(&ctx, &sid_conn(APPROVER_SID).peer).await);
        assert!(!is_approver(&ctx, &sid_conn(AGENT_SID).peer).await);
        // A reject, as this request carries no grant key; both pass the same checks.
        let reject = Request {
            id: 4,
            op: OP_APPROVAL_DECIDE.into(),
            args: json!({"request": rid, "action": "reject"})
                .as_object()
                .unwrap()
                .clone(),
        };
        let v = decide(&ctx, &sid_conn(APPROVER_SID), reject).await;
        assert_eq!(v["ok"], true, "{v}");
        let r = ctx.approvals.as_ref().unwrap().get(rid).unwrap();
        assert_eq!(r.state, State::Rejected);
        assert_eq!(r.decided_by_sid.as_deref(), Some(APPROVER_SID));
    }

    /// The same run's lockdown half: the approver is an approver, so `lockdown off`
    /// meets same_user = "deny" (`reauth_required`), not `forbidden`.
    #[tokio::test]
    async fn a_bare_approver_name_is_an_approver_for_lockdown() {
        let d = tempfile::tempdir().unwrap();
        let (ctx, _join) = windows_ctx(d.path());
        let off = || Request {
            id: 5,
            op: saiife_ipc::msg::OP_LOCKDOWN_SET.into(),
            args: json!({"on": false}).as_object().unwrap().clone(),
        };
        let v = crate::lockdown::set(&ctx, &sid_conn(APPROVER_SID), off()).await;
        assert_eq!(v["ok"], false, "{v}");
        assert!(v.to_string().contains("reauth_required"), "{v}");
        let v = crate::lockdown::set(&ctx, &sid_conn(AGENT_SID), off()).await;
        assert!(v.to_string().contains("[approval] approvers"), "{v}");
    }

    /// Review finding 2: a non-elevated admin's token holds Administrators deny-only
    /// (`peer_facts` leaves it out of `group_sids`), while its name's local groups list
    /// it. On Windows only the token counts, so it is no approver for
    /// `group:Administrators`: no request to see, and no lockdown off.
    #[tokio::test]
    async fn a_deny_only_administrators_is_no_group_approver() {
        let d = tempfile::tempdir().unwrap();
        let (ctx, _join) = windows_ctx(d.path());
        let cfg: saiife_policy::SystemConfig = toml::from_str(
            "version = 2\nlocked = true\n[approval]\napprovers = [\"group:Administrators\"]\n\
             same_user = \"deny\"\n",
        )
        .unwrap();
        ctx.policy.lock().unwrap().system = Some(Arc::new(cfg));
        let lowered = sid_conn(APPROVER_SID);
        assert!(!is_approver(&ctx, &lowered.peer).await);
        let off = Request {
            id: 6,
            op: saiife_ipc::msg::OP_LOCKDOWN_SET.into(),
            args: json!({"on": false}).as_object().unwrap().clone(),
        };
        let v = crate::lockdown::set(&ctx, &lowered, off.clone()).await;
        assert!(v.to_string().contains("[approval] approvers"), "{v}");
        // Elevated, the token holds the group: an approver.
        let mut elevated = sid_conn(APPROVER_SID);
        elevated.peer.group_sids = vec![saiife_win::sid::ADMINISTRATORS.into()];
        assert!(is_approver(&ctx, &elevated.peer).await);
    }

    /// [`windows_ctx`] with `[[scope]] users = ["agent"]` bound to `prod`, as the
    /// gateway's policy.
    fn scoped_ctx(d: &std::path::Path) -> (Arc<Ctx>, std::thread::JoinHandle<()>) {
        let (ctx, join) = windows_ctx(d);
        let cfg: saiife_policy::SystemConfig = toml::from_str(
            "version = 2\nlocked = true\n[[scope]]\nname = \"shop\"\nusers = [\"agent\"]\n\
             env = \"prod\"\n[environments.prod]\n",
        )
        .unwrap();
        let g = crate::ops::GatewayPolicy::build(
            &cfg,
            &[],
            saiife_broker::Catalog::default(),
            saiife_policy::Mode::Locked,
        )
        .unwrap();
        *ctx.policy.lock().unwrap() = crate::ops::PolicyState {
            ok: true,
            system: Some(Arc::new(cfg)),
            gateway: Some(Arc::new(g)),
            ..crate::ops::PolicyState::invalid(0)
        };
        (ctx, join)
    }

    /// locked-windows CI: `[[scope]] users = ["agent"]` never matched the daemon's
    /// `HOST\agent`, so the scope's rules did not apply to it. It matches by SID, and
    /// another account is still in no scope.
    #[tokio::test]
    async fn a_bare_scope_name_gives_its_windows_account_the_scope() {
        let d = tempfile::tempdir().unwrap();
        let (ctx, _join) = scoped_ctx(d.path());
        assert!(crate::api_ops::has_scope(&ctx, &sid_conn(AGENT_SID).peer).await);
        assert!(!crate::api_ops::has_scope(&ctx, &sid_conn(APPROVER_SID).peer).await);
    }

    /// The scope's environment applies to an approved request of `HOST\agent` (the
    /// request was asked under `prod`), and not to another account's.
    #[tokio::test]
    async fn a_bare_scope_name_binds_its_windows_account_to_the_scope_env() {
        let d = tempfile::tempdir().unwrap();
        let (ctx, _join) = scoped_ctx(d.path());
        let (_, env, _) = send_env(&ctx, (r"HOST\agent", Some(AGENT_SID)), Some("prod"), true)
            .await
            .unwrap();
        assert_eq!(env.as_deref(), Some("prod"));
        let other = send_env(
            &ctx,
            (r"HOST\approver", Some(APPROVER_SID)),
            Some("prod"),
            true,
        )
        .await;
        assert_eq!(other.err().map(|e| e.0), Some(ENV_CHANGED));
    }

    /// Bad `auth` hex is a bad request, before anything is looked up.
    #[tokio::test]
    async fn bad_auth_hex_is_bad_request() {
        let d = tempfile::tempdir().unwrap();
        let (ctx, _join) = crate::ops::test_ctx(d.path(), crate::ops::Mode::Locked, 0);
        let conn = Conn::new(
            PeerCred {
                uid: 1000,
                gid: 1000,
                pid: 1,
                sid: None,
                group_sids: Vec::new(),
            },
            Some(1),
        );
        for bad in [json!("AB".repeat(32)), json!("abc"), json!(1)] {
            let req = Request {
                id: 4,
                op: OP_APPROVAL_DECIDE.into(),
                args: json!({"request": 1, "action": "approve", "auth": bad})
                    .as_object()
                    .unwrap()
                    .clone(),
            };
            let v = decide(&ctx, &conn, req).await.to_string();
            assert!(v.contains("bad_request"), "{v}");
            assert!(v.contains("auth is 64 lowercase hex characters"), "{v}");
        }
    }
}

/// Touch-class approvals (plan 26, Task 8): `touch.begin {purpose:
/// "approve"}` and the touch `approval.decide` needs, through
/// `dispatch_conn` as a client sends them.
#[cfg(all(test, unix))]
pub(crate) mod touch_tests {
    use super::*;
    use crate::touch::TouchState;
    use saiife_broker::mask::Masker;
    use saiife_touch::soft::SoftAuthenticator;
    use saiife_touch::{reverify, Assertion, Touch as _, TouchRequest, LOCAL_RP_ID};
    use std::path::Path;

    pub(crate) const OWN: u32 = 1000;
    pub(crate) const MARKED: &str = "version = 2\n[services.s3_ask]\nconnector = \"s3\"\n\
                          deploy = [\"objects:write\"]\n";
    pub(crate) const PLAIN: &str = "version = 2\n[services.s3_ask]\nconnector = \"s3\"\n";
    pub(crate) const LOCKED: &str = "version = 2\nlocked = true\n[approval]\n\
                          approvers = [\"ann\", \"bob\"]\nsame_user = \"deny\"\n\
                          [services.s3_ask]\nconnector = \"s3\"\ndeploy = [\"objects:write\"]\n";
    const PASSWD: &str = "agent:x:1000:1000::/home/agent:/bin/sh\n\
                          ann:x:4242:4242::/home/ann:/bin/sh\n\
                          bob:x:4343:4343::/home/bob:/bin/sh\n";
    const GROUP: &str = "agent:x:1000:\nann:x:4242:\nbob:x:4343:\n";

    /// A connector call of `OWN` to `s3_ask` with capability `cap`; `key`
    /// tells requests apart.
    pub(crate) fn call(key: &str, cap: &str) -> PendingCall {
        let stored: StoredCall = serde_json::from_value(json!({
            "uid": OWN, "user": "agent", "session": null, "project": "/p",
            "service": "s3_ask", "operation": "s3.put_object",
            "params": {"bucket": "reports", "key": key},
            "body_b64": null, "body_sha256": null, "headers": [],
            "overlay": null, "via": "cli",
        }))
        .unwrap();
        PendingCall {
            operation: stored.operation.clone(),
            capability: Some(cap.into()),
            params: Masker::new(&[]).mask_params(&stored.params),
            project: stored.project.clone(),
            body_display: None,
            body_truncated: false,
            body_sha256: None,
            amount: None,
            headers: vec![],
            // The daemon classifies alone here (the broker's class is
            // tested in `connector_create_sets_the_class`).
            touch_class: None,
            stored,
        }
    }

    /// Replaces the context's policy (a reload).
    fn set_policy(ctx: &Ctx, text: &str) {
        let cfg: saiife_policy::SystemConfig = toml::from_str(text).unwrap();
        let mode = match cfg.locked {
            true => saiife_policy::Mode::Locked,
            false => saiife_policy::Mode::Developer,
        };
        let g =
            crate::ops::GatewayPolicy::build(&cfg, &[], saiife_broker::Catalog::default(), mode)
                .unwrap();
        *ctx.policy.lock().unwrap() = crate::ops::PolicyState {
            ok: true,
            system: Some(Arc::new(cfg)),
            gateway: Some(Arc::new(g)),
            ..crate::ops::PolicyState::invalid(0)
        };
    }

    pub(crate) struct World {
        pub(crate) d: tempfile::TempDir,
        pub(crate) ctx: Arc<Ctx>,
        _join: std::thread::JoinHandle<()>,
        pub(crate) soft: SoftAuthenticator,
    }

    /// A context with a store, a vault and `policy`; `soft` is enrolled
    /// for `OWN` unless `enrol` is false.
    pub(crate) fn world_in(mode: crate::ops::Mode, own: u32, policy: &str, enrol: bool) -> World {
        let d = tempfile::tempdir().unwrap();
        let (mut ctx, join) = crate::ops::test_ctx(d.path(), mode, own);
        let store = crate::approvals::Store::open(&d.path().join("approvals")).unwrap();
        let key = d.path().join("vault-key");
        std::fs::write(&key, [7u8; 32]).unwrap();
        std::fs::set_permissions(
            &key,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
        )
        .unwrap();
        let v = crate::vault::open(&key, &d.path().join("vault").join("vault.bin"));
        assert!(matches!(v, crate::vault::VaultState::Ready(_)));
        let c = Arc::get_mut(&mut ctx).unwrap();
        c.approvals = Ok(store);
        c.vault = crate::vault::Shared::new(v);
        c.directory = Arc::new(saiife_policy::FixedDirectory::from_text(PASSWD, GROUP));
        set_policy(&ctx, policy);
        let soft = SoftAuthenticator::new_es256();
        if enrol {
            ctx.touch
                .add(soft.credential(LOCAL_RP_ID, own, "key"))
                .unwrap();
        }
        World {
            d,
            ctx,
            _join: join,
            soft,
        }
    }

    pub(crate) fn personal(policy: &str) -> World {
        world_in(crate::ops::Mode::Personal, OWN, policy, true)
    }

    fn conn(uid: u32) -> Conn {
        Conn::new(
            PeerCred {
                uid,
                gid: uid,
                pid: 1,
                sid: None,
                group_sids: Vec::new(),
            },
            Some(1),
        )
    }

    pub(crate) async fn op(ctx: &Arc<Ctx>, uid: u32, op: &str, args: Value) -> Value {
        let req = Request {
            id: 7,
            op: op.into(),
            args: args.as_object().unwrap().clone(),
        };
        crate::ops::dispatch_conn(ctx, &conn(uid), req).await
    }

    pub(crate) async fn ask(w: &World, key: &str, cap: &str) -> u64 {
        create(&w.ctx, &call(key, cap), "claude").await.unwrap()
    }

    pub(crate) async fn begin(ctx: &Arc<Ctx>, uid: u32, rid: u64) -> Value {
        op(
            ctx,
            uid,
            saiife_ipc::msg::OP_TOUCH_BEGIN,
            json!({"purpose": "approve", "request": rid}),
        )
        .await
    }

    /// `touch.begin`'s answer as the client reads it.
    pub(crate) fn treq(v: &Value) -> TouchRequest {
        assert_eq!(v["ok"], true, "{v}");
        serde_json::from_value(v.clone()).unwrap()
    }

    pub(crate) async fn decide_with(
        ctx: &Arc<Ctx>,
        uid: u32,
        rid: u64,
        action: &str,
        touch: Option<&Assertion>,
    ) -> Value {
        let mut args = json!({"request": rid, "action": action});
        if let Some(t) = touch {
            args["touch"] = serde_json::to_value(t).unwrap();
        }
        op(ctx, uid, OP_APPROVAL_DECIDE, args).await
    }

    fn state(w: &World, rid: u64) -> State {
        w.ctx.approvals.as_ref().unwrap().get(rid).unwrap().state
    }

    pub(crate) fn records(d: &Path) -> Vec<Value> {
        let mut files: Vec<_> = std::fs::read_dir(d.join("audit"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
            .collect();
        files.sort();
        files
            .iter()
            .flat_map(|f| {
                std::fs::read_to_string(f)
                    .unwrap()
                    .lines()
                    .filter_map(|l| serde_json::from_str::<Value>(l).ok())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// The `approval` records of request `rid` with `action`.
    pub(crate) fn approval_records(w: &World, rid: u64, action: &str) -> Vec<Value> {
        records(w.d.path())
            .into_iter()
            .filter(|r| r["kind"] == "approval" && r["id"] == rid && r["action"] == action)
            .collect()
    }

    pub(crate) fn refused_rule(v: &Value) -> &str {
        assert_eq!(v["ok"], false, "{v}");
        assert_eq!(v["error"], "forbidden", "{v}");
        v["rule"].as_str().unwrap()
    }

    /// Nothing of `rid` was sent (or tried): no approved, sent or failed record.
    fn nothing_sent(w: &World, rid: u64) {
        for a in ["approved", "sent", "send_failed"] {
            assert!(approval_records(w, rid, a).is_empty(), "{a}");
        }
        assert!(records(w.d.path())
            .iter()
            .all(|r| r["kind"] != "connector" || r["approval"] != rid));
    }

    fn flip_signature(a: &mut Assertion) {
        match a {
            Assertion::Ctap2 { signature, .. } => signature[5] ^= 1,
            Assertion::WebAuthn { signature, .. } => signature[5] ^= 1,
        }
    }

    #[tokio::test]
    async fn marked_request_needs_a_touch() {
        let w = personal(MARKED);
        let rid = ask(&w, "a", "objects:write").await;
        let v = decide_with(&w.ctx, OWN, rid, "approve", None).await;
        assert_eq!(refused_rule(&v), "touch_unavailable");
        assert!(
            v["message"].as_str().unwrap().contains(&format!(
                "request #{rid} needs a touch (deploy) from an enrolled device"
            )),
            "{v}"
        );
        assert_eq!(state(&w, rid), State::Pending);
        let refused = approval_records(&w, rid, "refused");
        assert_eq!(refused.len(), 1);
        assert_eq!(refused[0]["rule"], "touch_unavailable");
        nothing_sent(&w, rid);
    }

    #[tokio::test]
    async fn touch_approves_and_is_recorded() {
        let w = personal(MARKED);
        let rid = ask(&w, "a", "objects:write").await;
        let b = begin(&w.ctx, OWN, rid).await;
        assert_eq!(b["class"], "deploy", "{b}");
        assert!(b["expires_at"].as_u64().is_some(), "{b}");
        let tr = treq(&b);
        assert_eq!(tr.rp_id, LOCAL_RP_ID);
        assert!(tr.uv);
        assert_eq!(tr.allow, vec![w.soft.credential_id()]);
        assert_eq!(tr.short_code, saiife_touch::short_code(&tr.challenge));
        let asr = w.soft.request(&tr).unwrap();
        let v = decide_with(&w.ctx, OWN, rid, "approve", Some(&asr)).await;
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["state"], "approved", "{v}");
        let rec = approval_records(&w, rid, "approved");
        assert_eq!(rec.len(), 1);
        let t = &rec[0]["touch"];
        let id = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            w.soft.credential_id(),
        );
        assert_eq!(t["cred_id"], id, "{t}");
        assert_eq!(t["uv"], true, "{t}");
        assert_eq!(t["via"], "local", "{t}");
        let hex: String = tr.challenge.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(t["challenge"], hex, "{t}");
        let enrolled = w.soft.credential(LOCAL_RP_ID, OWN, "key");
        assert_eq!(reverify(t, &enrolled), Ok(()));
        // The counter was saved.
        assert_eq!(w.ctx.touch.credentials_of(OWN)[0].sign_count, 1);
    }

    #[tokio::test]
    async fn same_assertion_twice_is_refused() {
        let w = personal(MARKED);
        let rid = ask(&w, "a", "objects:write").await;
        let tr = treq(&begin(&w.ctx, OWN, rid).await);
        let good = w.soft.request(&tr).unwrap();
        let mut bad = good.clone();
        flip_signature(&mut bad);
        // 1. A bad signature: refused, and the challenge is burned.
        let v = decide_with(&w.ctx, OWN, rid, "approve", Some(&bad)).await;
        assert_eq!(refused_rule(&v), "touch_failed");
        // 2. The untampered assertion now: no live challenge.
        let v = decide_with(&w.ctx, OWN, rid, "approve", Some(&good)).await;
        assert_eq!(refused_rule(&v), "touch_failed");
        assert!(v["message"].as_str().unwrap().contains("no live challenge"));
        // 3. A new challenge (a new nonce): the old assertion is for another.
        let tr2 = treq(&begin(&w.ctx, OWN, rid).await);
        assert_ne!(tr2.challenge, tr.challenge);
        let v = decide_with(&w.ctx, OWN, rid, "approve", Some(&good)).await;
        assert_eq!(refused_rule(&v), "touch_mismatch");
        assert_eq!(state(&w, rid), State::Pending);
        nothing_sent(&w, rid);
    }

    #[tokio::test]
    async fn restart_forgets_challenges() {
        let mut w = personal(MARKED);
        let rid = ask(&w, "a", "objects:write").await;
        let tr = treq(&begin(&w.ctx, OWN, rid).await);
        let asr = w.soft.request(&tr).unwrap();
        // The daemon restarts: the touch state is opened again from disk.
        let (fresh, why) = TouchState::open(&w.d.path().join("state"));
        assert!(why.is_none());
        assert_eq!(fresh.instance_id(), w.ctx.touch.instance_id());
        assert_eq!(fresh.credentials_of(OWN).len(), 1);
        Arc::get_mut(&mut w.ctx).unwrap().touch = Arc::new(fresh);
        let v = decide_with(&w.ctx, OWN, rid, "approve", Some(&asr)).await;
        assert_eq!(refused_rule(&v), "touch_failed");
        assert_eq!(state(&w, rid), State::Pending);
        nothing_sent(&w, rid);
    }

    #[tokio::test]
    async fn touch_for_request_a_cannot_approve_b() {
        let w = personal(MARKED);
        let a = ask(&w, "a", "objects:write").await;
        let b = ask(&w, "b", "objects:write").await;
        assert_ne!(a, b);
        let tr_a = treq(&begin(&w.ctx, OWN, a).await);
        let asr_a = w.soft.request(&tr_a).unwrap();
        treq(&begin(&w.ctx, OWN, b).await);
        let v = decide_with(&w.ctx, OWN, b, "approve", Some(&asr_a)).await;
        assert_eq!(refused_rule(&v), "touch_mismatch");
        assert_eq!(state(&w, a), State::Pending);
        assert_eq!(state(&w, b), State::Pending);
        nothing_sent(&w, a);
        nothing_sent(&w, b);
    }

    #[tokio::test]
    async fn challenge_of_another_uid_is_refused() {
        let w = world_in(crate::ops::Mode::Locked, 0, LOCKED, false);
        let ann = SoftAuthenticator::new_es256();
        let bob = SoftAuthenticator::new_es256();
        w.ctx
            .touch
            .add(ann.credential(LOCAL_RP_ID, 4242, "ann"))
            .unwrap();
        w.ctx
            .touch
            .add(bob.credential(LOCAL_RP_ID, 4343, "bob"))
            .unwrap();
        let rid = ask(&w, "a", "objects:write").await;
        let tr = treq(&begin(&w.ctx, 4242, rid).await);
        assert_eq!(tr.allow, vec![ann.credential_id()]);
        let asr = ann.request(&tr).unwrap();
        let v = decide_with(&w.ctx, 4343, rid, "approve", Some(&asr)).await;
        assert_eq!(refused_rule(&v), "touch_mismatch");
        assert_eq!(state(&w, rid), State::Pending);
        nothing_sent(&w, rid);
        // A requester that is no approver cannot begin one.
        let v = begin(&w.ctx, 1000, rid).await;
        assert_eq!(v["ok"], false, "{v}");
        assert_eq!(v["error"], "forbidden", "{v}");
        // An uninvolved uid sees no such request.
        let v = begin(&w.ctx, 5555, rid).await;
        assert!(
            v["message"].as_str().unwrap().contains("(or not yours)"),
            "{v}"
        );
    }

    /// D6: Bob's own live challenge answered by Ann's enrolled key. Ann's
    /// key is enrolled, but not for Bob: refused, the request pending.
    #[tokio::test]
    async fn another_approvers_key_cannot_answer_my_challenge() {
        let w = world_in(crate::ops::Mode::Locked, 0, LOCKED, false);
        let ann = SoftAuthenticator::new_es256();
        let bob = SoftAuthenticator::new_es256();
        w.ctx
            .touch
            .add(ann.credential(LOCAL_RP_ID, 4242, "ann"))
            .unwrap();
        w.ctx
            .touch
            .add(bob.credential(LOCAL_RP_ID, 4343, "bob"))
            .unwrap();
        let rid = ask(&w, "a", "objects:write").await;
        let tr = treq(&begin(&w.ctx, 4343, rid).await);
        assert_eq!(tr.allow, vec![bob.credential_id()]);
        // Ann's key signs Bob's request (a real key would refuse: it is not
        // in `allow`).
        let asr = ann.assert_ctap(&tr.rp_id, &tr.challenge);
        let v = decide_with(&w.ctx, 4343, rid, "approve", Some(&asr)).await;
        assert_eq!(refused_rule(&v), "touch_mismatch");
        assert!(
            v["message"]
                .as_str()
                .unwrap()
                .contains("not enrolled for you"),
            "{v}"
        );
        assert_eq!(state(&w, rid), State::Pending);
        let refused = approval_records(&w, rid, "refused");
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert_eq!(refused[0]["rule"], "touch_mismatch");
        assert_eq!(refused[0]["by_uid"], 4343);
        nothing_sent(&w, rid);
        // Ann's counter did not move.
        assert_eq!(w.ctx.touch.credentials_of(4242)[0].sign_count, 0);
    }

    /// Counts re-authentication prompts; every one is denied.
    struct CountingReauth(std::sync::atomic::AtomicUsize);

    impl Reauth for CountingReauth {
        fn available(&self) -> bool {
            true
        }
        fn check(&self, _who: &Subject, _d: &str, _t: Duration) -> ReauthResult {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            ReauthResult::Denied("counted".into())
        }
    }

    /// Final review Minor 5: a same-user approval in locked mode that has
    /// no usable `touch` is refused before the re-authentication prompt.
    #[tokio::test]
    async fn missing_touch_is_refused_before_the_prompt() {
        const SAME: &str = "version = 2\nlocked = true\n[approval]\n\
                            approvers = [\"agent\"]\nsame_user = \"reauth\"\n\
                            [services.s3_ask]\nconnector = \"s3\"\n\
                            deploy = [\"objects:write\"]\n";
        let mut w = world_in(crate::ops::Mode::Locked, 0, SAME, false);
        let counter = Arc::new(CountingReauth(Default::default()));
        Arc::get_mut(&mut w.ctx).unwrap().reauth = counter.clone();
        let prompts = || counter.0.load(std::sync::atomic::Ordering::SeqCst);
        let rid = ask(&w, "a", "objects:write").await;
        // No touch: refused (`touch_unavailable`, recorded), no prompt.
        let v = decide_with(&w.ctx, OWN, rid, "approve", None).await;
        assert_eq!(refused_rule(&v), "touch_unavailable");
        assert_eq!(prompts(), 0);
        let refused = approval_records(&w, rid, "refused");
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert_eq!(refused[0]["rule"], "touch_unavailable");
        // A touch that is no assertion: a bad request, no prompt.
        let v = op(
            &w.ctx,
            OWN,
            OP_APPROVAL_DECIDE,
            json!({"request": rid, "action": "approve", "touch": {"kind": "nope"}}),
        )
        .await;
        assert_eq!(v["error"], "bad_request", "{v}");
        assert_eq!(prompts(), 0);
        // With a parsable touch the prompt runs first (and is denied here).
        let fake = SoftAuthenticator::new_es256().assert_ctap(LOCAL_RP_ID, &[0; 32]);
        let v = decide_with(&w.ctx, OWN, rid, "approve", Some(&fake)).await;
        assert_eq!(refused_rule(&v), "reauth_failed");
        assert_eq!(prompts(), 1);
        assert_eq!(state(&w, rid), State::Pending);
    }

    #[tokio::test]
    async fn uv_missing_for_deploy() {
        let mut w = personal(MARKED);
        w.soft.uv = false;
        let rid = ask(&w, "a", "objects:write").await;
        let tr = treq(&begin(&w.ctx, OWN, rid).await);
        let asr = w.soft.request(&tr).unwrap();
        let v = decide_with(&w.ctx, OWN, rid, "approve", Some(&asr)).await;
        assert_eq!(refused_rule(&v), "touch_failed");
        assert!(
            v["message"].as_str().unwrap().contains("user verification"),
            "{v}"
        );
        assert_eq!(state(&w, rid), State::Pending);
    }

    #[tokio::test]
    async fn no_device_is_unavailable() {
        let w = world_in(crate::ops::Mode::Personal, OWN, MARKED, false);
        let rid = ask(&w, "a", "objects:write").await;
        let v = begin(&w.ctx, OWN, rid).await;
        assert_eq!(refused_rule(&v), "touch_unavailable");
        let refused = approval_records(&w, rid, "refused");
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert_eq!(refused[0]["rule"], "touch_unavailable");
        assert_eq!(state(&w, rid), State::Pending);
    }

    #[tokio::test]
    async fn reject_needs_no_touch() {
        let w = personal(MARKED);
        let rid = ask(&w, "a", "objects:write").await;
        let v = decide_with(&w.ctx, OWN, rid, "reject", None).await;
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["state"], "rejected", "{v}");
        let rec = approval_records(&w, rid, "rejected");
        assert_eq!(rec.len(), 1);
        assert!(rec[0].get("touch").is_none(), "{}", rec[0]);
    }

    #[tokio::test]
    async fn reload_removing_a_mark_keeps_the_touch() {
        let w = personal(MARKED);
        let rid = ask(&w, "a", "objects:write").await;
        set_policy(&w.ctx, PLAIN);
        let v = decide_with(&w.ctx, OWN, rid, "approve", None).await;
        assert_eq!(refused_rule(&v), "touch_unavailable");
        assert_eq!(state(&w, rid), State::Pending);
        // The stored class is shown, and a touch still approves.
        let s = op(&w.ctx, OWN, OP_APPROVAL_SHOW, json!({"request": rid})).await;
        assert_eq!(s["item"]["touch_class"], "deploy", "{s}");
        let tr = treq(&begin(&w.ctx, OWN, rid).await);
        let asr = w.soft.request(&tr).unwrap();
        let v = decide_with(&w.ctx, OWN, rid, "approve", Some(&asr)).await;
        assert_eq!(v["state"], "approved", "{v}");
    }

    #[tokio::test]
    async fn mark_added_after_ask_needs_touch() {
        let w = personal(PLAIN);
        let rid = ask(&w, "a", "objects:write").await;
        let r = w.ctx.approvals.as_ref().unwrap().get(rid).unwrap();
        assert_eq!(r.touch_class, None);
        set_policy(&w.ctx, MARKED);
        let s = op(&w.ctx, OWN, OP_APPROVAL_SHOW, json!({"request": rid})).await;
        assert_eq!(s["item"]["touch_class"], "deploy", "{s}");
        // Final review Minor 10: the list shows the same, effective class.
        let l = op(&w.ctx, OWN, OP_APPROVAL_LIST, json!({})).await;
        let items = l["items"].as_array().unwrap();
        let it = items.iter().find(|i| i["id"] == rid).unwrap();
        assert_eq!(it["touch_class"], "deploy", "{l}");
        let v = decide_with(&w.ctx, OWN, rid, "approve", None).await;
        assert_eq!(refused_rule(&v), "touch_unavailable");
        assert_eq!(state(&w, rid), State::Pending);
    }

    #[tokio::test]
    async fn unmarked_request_unchanged() {
        let w = personal(MARKED);
        let rid = ask(&w, "a", "objects:read").await;
        let s = op(&w.ctx, OWN, OP_APPROVAL_SHOW, json!({"request": rid})).await;
        assert!(s["item"].get("touch_class").is_none(), "{s}");
        let v = begin(&w.ctx, OWN, rid).await;
        assert_eq!(v["error"], "bad_request", "{v}");
        assert!(v["message"]
            .as_str()
            .unwrap()
            .contains(&format!("request #{rid} needs no touch")));
        let v = decide_with(&w.ctx, OWN, rid, "approve", None).await;
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["state"], "approved", "{v}");
        let rec = approval_records(&w, rid, "approved");
        assert_eq!(rec.len(), 1);
        assert!(rec[0].get("touch").is_none(), "{}", rec[0]);
    }

    /// A stored class this version cannot read is the strictest, never none.
    #[tokio::test]
    async fn unreadable_stored_class_is_deploy() {
        let w = world_in(crate::ops::Mode::Personal, OWN, PLAIN, false);
        let mut r: ApprovalRequest = serde_json::from_value(json!({
            "id": 1, "created": "c", "expires": "e", "uid": OWN, "user": "u",
            "session": null, "agent": "a", "project": "p", "type": "connector",
            "service": "s3_ask", "operation": null, "capability": "objects:read",
            "params": {}, "input": null, "grant_key": null, "state": "pending",
            "request_sealed": null, "decided_by": null, "note": null, "result_ref": null
        }))
        .unwrap();
        assert_eq!(effective_class(&w.ctx, &r), None);
        r.touch_class = Some("future-class".into());
        assert_eq!(
            effective_class(&w.ctx, &r),
            Some(saiife_touch::TouchClass::Deploy)
        );
        // An unknown environment, or a service the policy lost, keeps the
        // stored class.
        r.touch_class = Some("egress:external".into());
        r.env = Some("gone".into());
        assert_eq!(
            effective_class(&w.ctx, &r),
            Some(saiife_touch::TouchClass::EgressExternal)
        );
        // An mcp request gets no class from the policy now.
        set_policy(&w.ctx, MARKED);
        r.env = None;
        r.touch_class = None;
        r.capability = None;
        assert_eq!(
            effective_class(&w.ctx, &r),
            Some(saiife_touch::TouchClass::Deploy)
        );
        r.kind = ApprovalType::Mcp;
        assert_eq!(effective_class(&w.ctx, &r), None);
    }
}
