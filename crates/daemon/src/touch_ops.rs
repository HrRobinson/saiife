//! The touch ops (plan 26): `touch.begin`, `touch.enrol`, `touch.remove`,
//! `touch.list`, `touch.check`. File-touching calls run on a blocking
//! thread (`tokio::task::spawn_blocking`), as the approval ops do.
//!
//! Task 8 fills `approve_ops` (`touch.begin` for an approval), Task 9
//! `admin_ops`: enrol, remove, list and test a device, each machine only
//! (the local socket). Who may: root, an `[admin] groups` member or an
//! approver; in personal mode the own user. A peer acts on its own uid's
//! devices; root and admins may list all, and root may remove any device
//! without its touch (`host`, recovery when every device is lost).
//!
//! Enrolment (D10) proves possession and UV of the new device over the
//! challenge, and, when the uid already has a device, a touch of one of
//! them over the same challenge; for the first device host access is the
//! proof. `touch_enrolled` records everything an auditor needs to rebuild
//! the trusted credential `reverify` takes (R9).

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use saiife_audit::{DecisionKind, Record};
use saiife_ipc::msg::{
    err, err_with, ok, ErrorCode, Request, OP_TOUCH_BEGIN, OP_TOUCH_CHECK, OP_TOUCH_ENROL,
    OP_TOUCH_LIST, OP_TOUCH_REMOVE,
};
use saiife_ipc::peer::PeerCred;
use saiife_touch::{
    challenge, check_label, credential_from_attestation, short_code, verify, ActionRecord,
    Assertion, Credential, EnrolRequest, TouchClass, TouchError, TouchRequest, LOCAL_RP_ID,
    RP_NAME,
};
use serde_json::{json, Map, Value};

use crate::approvals::{action_record, state_name, State};
use crate::approvers::Refusal;
use crate::ops::{Conn, Ctx};
use crate::touch::{unix_now, IssueKey, Issued, TouchState};

pub async fn handle(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value {
    match req.op.as_str() {
        OP_TOUCH_BEGIN => approve_ops(ctx, conn, req).await,
        OP_TOUCH_ENROL | OP_TOUCH_REMOVE | OP_TOUCH_LIST | OP_TOUCH_CHECK => {
            admin_ops(ctx, conn, req).await
        }
        _ => unknown(req),
    }
}

fn unknown(req: Request) -> Value {
    err(
        req.id,
        ErrorCode::UnknownOp,
        &format!("unknown op {:?}", req.op),
    )
}

/// `touch.begin`: the `approve` purpose here; the others are Task 9's.
async fn approve_ops(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value {
    if req.args.get("purpose").and_then(Value::as_str) != Some("approve") {
        return admin_ops(ctx, conn, req).await;
    }
    begin_approve(ctx, &conn.peer, req).await
}

/// `touch.begin {purpose: "approve", request}`: a challenge bound to the
/// pending request `request`, for the peer's own devices (D6).
///
/// A second approver beginning on the same request replaces the first
/// one's challenge (`IssueKey::Approve` has no uid): the first one's later
/// decision is then refused (`touch_failed` or `touch_mismatch`), which
/// fails closed. Accepted for v3.0.
async fn begin_approve(ctx: &Arc<Ctx>, peer: &PeerCred, req: Request) -> Value {
    use crate::approval_ops as ops;
    let id = req.id;
    let rid = match ops::request_id(&req) {
        Ok(r) => r,
        Err(v) => return v,
    };
    let r = match ops::visible(ctx, peer, rid).await {
        Err(()) => return ops::unavailable(id, ctx),
        Ok(None) => return ops::unknown(id, rid),
        Ok(Some(r)) => r,
    };
    if r.state != State::Pending {
        return err(
            id,
            ErrorCode::BadRequest,
            &format!("request #{rid} is {}", state_name(r.state)),
        );
    }
    // An approver, or the own user in personal mode (`is_approver` says so).
    if !ops::is_approver(ctx, peer).await {
        return err(
            id,
            ErrorCode::Forbidden,
            &format!("only an approver can touch for request #{rid}"),
        );
    }
    let Some(class) = ops::effective_class(ctx, &r) else {
        return err(
            id,
            ErrorCode::BadRequest,
            &format!("request #{rid} needs no touch"),
        );
    };
    let c = Arc::clone(ctx);
    let uid = peer.uid;
    let creds = tokio::task::spawn_blocking(move || c.touch.credentials_of(uid))
        .await
        .unwrap_or_default();
    if creds.is_empty() {
        let why = Refusal::TouchUnavailable(format!(
            "request #{rid} needs a touch ({}) and no touch device is enrolled for you",
            class.name()
        ));
        return ops::refuse(ctx, &r, peer, id, why.rule(), &why.to_string()).await;
    }
    let c = Arc::clone(ctx);
    let issued = tokio::task::spawn_blocking(move || {
        let t = &c.touch;
        // The summary and fields do not depend on the nonce or expiry: built
        // once, then given the issued ones.
        let mut rec = action_record(&r, class, t.instance_id(), [0; 32], 0);
        let i = t.issue(
            IssueKey::Approve(rid),
            uid,
            class,
            rec.summary.clone(),
            rec.fields.clone(),
            unix_now(),
        )?;
        rec.nonce = i.nonce;
        rec.expires_at = i.expires_at;
        Ok::<_, String>((rec, i.expires_at))
    })
    .await
    .unwrap_or_else(|e| Err(e.to_string()));
    let (rec, expires_at) = match issued {
        Ok(x) => x,
        Err(e) => return err(id, ErrorCode::Busy, &e),
    };
    let c = challenge(&rec);
    let tr = TouchRequest {
        rp_id: LOCAL_RP_ID.into(),
        challenge: c,
        allow: creds.into_iter().map(|c| c.id).collect(),
        uv: class.needs_uv(),
        summary: rec.summary.clone(),
        short_code: short_code(&c),
    };
    let mut m = match serde_json::to_value(&tr) {
        Ok(Value::Object(m)) => m,
        _ => return err(id, ErrorCode::Internal, "cannot encode the touch request"),
    };
    m.insert("expires_at".into(), expires_at.into());
    m.insert("class".into(), class.name().into());
    ok(id, m)
}

// ------------------------------------------------------------ admin ops

/// Why an admin touch was refused: the rule and the reason that go in the
/// `touch_failed` record and the `forbidden` answer.
#[derive(Debug)]
struct Failure {
    rule: &'static str,
    reason: String,
}

impl From<TouchError> for Failure {
    fn from(e: TouchError) -> Self {
        Failure {
            rule: e.rule(),
            reason: e.to_string(),
        }
    }
}

impl Failure {
    fn failed(reason: impl Into<String>) -> Self {
        Failure {
            rule: "touch_failed",
            reason: reason.into(),
        }
    }
}

/// The action record of an admin purpose's challenge (enrol, remove,
/// test): request id 0, everything else from the issued entry. Every path
/// that spends an admin challenge builds it here.
pub(crate) fn admin_record(instance_id: [u8; 16], i: &Issued) -> ActionRecord {
    ActionRecord {
        instance_id,
        request_id: 0,
        class: i.class,
        summary: i.summary.clone(),
        fields: i.fields.clone(),
        nonce: i.nonce,
        expires_at: i.expires_at,
    }
}

/// `f` on the touch state, on a blocking thread (R14). `None`: the task
/// failed.
async fn blocking<T: Send + 'static>(
    ctx: &Arc<Ctx>,
    f: impl FnOnce(&TouchState) -> T + Send + 'static,
) -> Option<T> {
    let c = Arc::clone(ctx);
    tokio::task::spawn_blocking(move || f(&c.touch)).await.ok()
}

/// A device request over the challenge of `rec`.
fn touch_request(rec: &ActionRecord, allow: Vec<Vec<u8>>) -> TouchRequest {
    let c = challenge(rec);
    TouchRequest {
        rp_id: LOCAL_RP_ID.into(),
        challenge: c,
        allow,
        uv: rec.class.needs_uv(),
        summary: rec.summary.clone(),
        short_code: short_code(&c),
    }
}

fn refused(id: u64, rule: &str, why: &str) -> Value {
    let mut m = Map::new();
    m.insert("rule".into(), rule.into());
    err_with(
        id,
        ErrorCode::Forbidden,
        &format!("refused ({rule}): {why}"),
        m,
    )
}

fn object(id: u64, v: impl serde::Serialize) -> Result<Map<String, Value>, Value> {
    match serde_json::to_value(v) {
        Ok(Value::Object(m)) => Ok(m),
        _ => Err(err(id, ErrorCode::Internal, "cannot encode the answer")),
    }
}

/// The `credential` argument: a base64url credential id.
fn credential_arg(req: &Request) -> Result<Vec<u8>, Value> {
    req.args
        .get("credential")
        .and_then(Value::as_str)
        .and_then(|s| URL_SAFE_NO_PAD.decode(s).ok())
        .ok_or_else(|| {
            err(
                req.id,
                ErrorCode::BadRequest,
                "credential is a base64url credential id",
            )
        })
}

/// An assertion argument; `Ok(None)` when absent or null.
fn assertion_arg(req: &Request, name: &str) -> Result<Option<Assertion>, Value> {
    match req.args.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => serde_json::from_value(v.clone()).map(Some).map_err(|e| {
            err(
                req.id,
                ErrorCode::BadRequest,
                &format!("{name} is not an assertion: {e}"),
            )
        }),
    }
}

fn no_such_device(id: u64) -> Value {
    err(
        id,
        ErrorCode::BadRequest,
        "no such touch device (or not yours)",
    )
}

/// Root, an admin or an approver; in personal mode the own user (both
/// checks say so there).
async fn may_manage(ctx: &Ctx, peer: &PeerCred) -> bool {
    ctx.peer_is_admin(peer).await || crate::approval_ops::is_approver(ctx, peer).await
}

/// Enrol, remove, list and test, and the other purposes of `touch.begin`.
async fn admin_ops(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value {
    let peer = &conn.peer;
    if !may_manage(ctx, peer).await {
        return err(
            req.id,
            ErrorCode::Forbidden,
            "only root, an admin or an approver can manage touch devices",
        );
    }
    match req.op.as_str() {
        OP_TOUCH_BEGIN => match req.args.get("purpose").and_then(Value::as_str) {
            Some("enrol") => begin_enrol(ctx, peer, &req).await,
            Some("remove") => begin_remove(ctx, peer, &req).await,
            Some("test") => begin_test(ctx, peer, &req).await,
            _ => err(
                req.id,
                ErrorCode::BadRequest,
                "purpose is \"approve\", \"enrol\", \"remove\" or \"test\"",
            ),
        },
        OP_TOUCH_ENROL => enrol(ctx, peer, &req).await,
        OP_TOUCH_REMOVE => remove(ctx, peer, &req).await,
        OP_TOUCH_LIST => list(ctx, peer, &req).await,
        OP_TOUCH_CHECK => check(ctx, peer, &req).await,
        _ => unknown(req),
    }
}

/// Issues the challenge of `key` for `peer` and gives its action record.
async fn issue(
    ctx: &Arc<Ctx>,
    key: IssueKey,
    uid: u32,
    class: TouchClass,
    summary: String,
    fields: BTreeMap<String, String>,
) -> Result<ActionRecord, String> {
    blocking(ctx, move |t| {
        t.issue(key, uid, class, summary, fields, unix_now())
            .map(|i| admin_record(t.instance_id(), &i))
    })
    .await
    .unwrap_or_else(|| Err("the touch state is unavailable".into()))
}

/// `touch.begin {purpose: "enrol", label}` (D10): the make-credential
/// request, the new device's proof request and, when the uid already has
/// a device, the request one of them answers to approve the new one, all
/// over one challenge.
async fn begin_enrol(ctx: &Arc<Ctx>, peer: &PeerCred, req: &Request) -> Value {
    let id = req.id;
    let Some(label) = req.args.get("label").and_then(Value::as_str) else {
        return err(id, ErrorCode::BadRequest, "label is a string");
    };
    if let Err(e) = check_label(label) {
        return err(id, ErrorCode::BadRequest, &e);
    }
    let uid = peer.uid;
    let (own, all) = blocking(ctx, move |t| (t.credentials_of(uid), t.all()))
        .await
        .unwrap_or_default();
    let mut fields = BTreeMap::new();
    fields.insert("label".to_string(), label.to_string());
    fields.insert("uid".to_string(), uid.to_string());
    let rec = match issue(
        ctx,
        IssueKey::Enrol(uid),
        uid,
        TouchClass::Enrol,
        format!("enrol {label}"),
        fields,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return err(id, ErrorCode::Busy, &e),
    };
    let user_name = ctx
        .peer_name(peer)
        .await
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| uid.to_string());
    let er = EnrolRequest {
        rp_id: LOCAL_RP_ID.into(),
        rp_name: RP_NAME.into(),
        user_id: uid.to_be_bytes().to_vec(),
        user_name,
        challenge: challenge(&rec),
        exclude: all.into_iter().map(|c| c.id).collect(),
    };
    let mut m = match object(id, &er) {
        Ok(m) => m,
        Err(v) => return v,
    };
    match object(id, touch_request(&rec, Vec::new())) {
        Ok(v) => m.insert("touch".into(), Value::Object(v)),
        Err(v) => return v,
    };
    if !own.is_empty() {
        let allow = own.into_iter().map(|c| c.id).collect();
        match object(id, touch_request(&rec, allow)) {
            Ok(v) => m.insert("approve_with".into(), Value::Object(v)),
            Err(v) => return v,
        };
    }
    m.insert("expires_at".into(), rec.expires_at.into());
    ok(id, m)
}

/// What `touch.enrol` checks, all from the client but the label's uid.
struct EnrolArgs {
    uid: u32,
    sid: Option<String>,
    label: String,
    auth_data: Vec<u8>,
    proof: Assertion,
    approval: Option<Assertion>,
    created: String,
}

/// The checks of `touch.enrol`, in order, on the taken `Enrol(uid)`
/// entry (burned in every case): the label is the one the challenge
/// names; the attestation parses; the new device's proof verifies over
/// the challenge with UV; it is not enrolled yet; with existing devices,
/// one of them approves over the same challenge (its counter is saved);
/// then the credential is added, with the proof's counter. Gives the new
/// credential and who approved it (`"host"` for the first device).
fn enrol_checked(t: &TouchState, e: EnrolArgs, now: u64) -> Result<(Credential, String), Failure> {
    let entry = t.take(&IssueKey::Enrol(e.uid), e.uid)?;
    let record = admin_record(t.instance_id(), &entry);
    if entry.fields.get("label") != Some(&e.label) {
        return Err(TouchError::Mismatch.into());
    }
    let mut new = credential_from_attestation(
        &e.auth_data,
        LOCAL_RP_ID,
        &e.label,
        e.uid,
        e.sid,
        &e.created,
    )?;
    // `TouchClass::Enrol` needs UV (D4): a device without it is refused here.
    let ev = verify(
        std::slice::from_ref(&new),
        &record,
        &e.proof,
        LOCAL_RP_ID,
        now,
    )?;
    new.sign_count = ev.sign_count;
    if t.all().iter().any(|c| c.id == new.id) {
        return Err(Failure::failed("already enrolled"));
    }
    let approved_by = if t.credentials_of(e.uid).is_empty() {
        // The first device: host access is the proof (§8.4).
        "host".to_string()
    } else {
        let Some(a) = &e.approval else {
            return Err(Failure {
                rule: "touch_unavailable",
                reason: "a touch of one of your enrolled devices must approve a new one".into(),
            });
        };
        t.verify_counted(e.uid, &record, a, LOCAL_RP_ID, now)?
            .credential_id
    };
    t.add(new.clone()).map_err(Failure::failed)?;
    Ok((new, approved_by))
}

/// A `touch` record of `action` by `peer`.
async fn touch_record(ctx: &Ctx, peer: &PeerCred, input: &str, action: &str) -> Record {
    let mut r = ctx.record("touch", input);
    r.extra.insert("action".into(), action.into());
    r.extra.insert("by_uid".into(), peer.uid.into());
    // Windows: every elevated admin's uid is 0, so `by_uid` alone names nobody.
    if let Some(sid) = &peer.sid {
        r.extra.insert("by_sid".into(), sid.clone().into());
    }
    r
}

/// `rec` as the `touch_enrolled` record of `c`: everything an auditor
/// needs to rebuild the trusted credential `reverify` takes (R9), and who
/// approved it (a credential id, or `"host"` for the first device). The
/// credential's kind is `cred_kind`, as `kind` is the record's own.
pub fn enrolled_record(mut rec: Record, c: &Credential, approved_by: &str) -> Record {
    let x = &mut rec.extra;
    x.insert("action".into(), "touch_enrolled".into());
    x.insert("cred_id".into(), URL_SAFE_NO_PAD.encode(&c.id).into());
    x.insert("label".into(), c.label.clone().into());
    // `kind` is the record's own key ("touch"): the credential's is `cred_kind`.
    x.insert("cred_kind".into(), c.kind.clone().into());
    x.insert(
        "alg".into(),
        serde_json::to_value(c.public_key.alg()).unwrap_or(Value::Null),
    );
    x.insert(
        "public_key".into(),
        URL_SAFE_NO_PAD.encode(c.public_key.to_cose()).into(),
    );
    x.insert("aaguid".into(), c.aaguid.clone().into());
    x.insert("rp_id".into(), c.rp_id.clone().into());
    if !c.origins.is_empty() {
        x.insert("origins".into(), c.origins.clone().into());
    }
    x.insert("owner_uid".into(), c.owner_uid.into());
    if let Some(sid) = &c.owner_sid {
        x.insert("owner_sid".into(), sid.clone().into());
    }
    x.insert("created".into(), c.created.clone().into());
    x.insert("approved_by".into(), approved_by.into());
    rec
}

/// Writes the `touch_failed` record of `op` and answers `forbidden`.
async fn fail(ctx: &Ctx, peer: &PeerCred, id: u64, op: &str, f: Failure) -> Value {
    let mut r = touch_record(ctx, peer, op, "touch_failed").await;
    r.decision = DecisionKind::Deny;
    r.rule = Some(f.rule.into());
    r.reason = Some(f.reason.clone());
    r.extra.insert("op".into(), op.into());
    if let Err(e) = ctx.writer.append(r).await {
        eprintln!("saiife: warning: cannot record a refused touch {op}: {e}");
    }
    refused(id, f.rule, &f.reason)
}

/// `touch.enrol {label, auth_data, proof, approval?}`.
async fn enrol(ctx: &Arc<Ctx>, peer: &PeerCred, req: &Request) -> Value {
    let id = req.id;
    let Some(label) = req.args.get("label").and_then(Value::as_str) else {
        return err(id, ErrorCode::BadRequest, "label is a string");
    };
    let Some(auth_data) = req
        .args
        .get("auth_data")
        .and_then(Value::as_str)
        .and_then(|s| URL_SAFE_NO_PAD.decode(s).ok())
    else {
        return err(id, ErrorCode::BadRequest, "auth_data is base64url");
    };
    let proof = match assertion_arg(req, "proof") {
        Ok(Some(p)) => p,
        Ok(None) => return err(id, ErrorCode::BadRequest, "proof is an assertion"),
        Err(v) => return v,
    };
    let approval = match assertion_arg(req, "approval") {
        Ok(a) => a,
        Err(v) => return v,
    };
    let args = EnrolArgs {
        uid: peer.uid,
        sid: peer.sid.clone(),
        label: label.to_string(),
        auth_data,
        proof,
        approval,
        created: crate::approvals::ts(crate::import_backup::now()),
    };
    let done = blocking(ctx, move |t| enrol_checked(t, args, unix_now()))
        .await
        .unwrap_or_else(|| Err(TouchError::Unavailable.into()));
    let (c, by) = match done {
        Ok(x) => x,
        Err(f) => return fail(ctx, peer, id, "enrol", f).await,
    };
    let base = touch_record(ctx, peer, &format!("enrol {}", c.label), "touch_enrolled").await;
    if let Err(e) = ctx.writer.append(enrolled_record(base, &c, &by)).await {
        // A device that is not on record does not approve anything.
        let cid = c.id.clone();
        let undone = blocking(ctx, move |t| t.remove(&cid)).await;
        if !matches!(undone, Some(Ok(Some(_)))) {
            eprintln!(
                "saiife: warning: cannot remove the unrecorded touch device {}",
                URL_SAFE_NO_PAD.encode(&c.id)
            );
        }
        return err(
            id,
            ErrorCode::Unrecorded,
            &format!("the device was not enrolled: its record could not be written: {e}"),
        );
    }
    ok(
        id,
        json!({"id": URL_SAFE_NO_PAD.encode(&c.id), "label": c.label, "approved_by": by})
            .as_object()
            .cloned()
            .unwrap_or_default(),
    )
}

/// `touch.begin {purpose: "remove", credential}`: a challenge naming the
/// device, which any of the uid's devices answers.
async fn begin_remove(ctx: &Arc<Ctx>, peer: &PeerCred, req: &Request) -> Value {
    let id = req.id;
    let cred = match credential_arg(req) {
        Ok(c) => c,
        Err(v) => return v,
    };
    let uid = peer.uid;
    let own = blocking(ctx, move |t| t.credentials_of(uid))
        .await
        .unwrap_or_default();
    let Some(target) = own.iter().find(|c| c.id == cred) else {
        return no_such_device(id);
    };
    let mut fields = BTreeMap::new();
    fields.insert("credential".to_string(), URL_SAFE_NO_PAD.encode(&target.id));
    fields.insert("label".to_string(), target.label.clone());
    fields.insert("uid".to_string(), uid.to_string());
    let summary = format!("remove {}", target.label);
    let rec = match issue(
        ctx,
        IssueKey::Remove(uid),
        uid,
        TouchClass::Remove,
        summary,
        fields,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return err(id, ErrorCode::Busy, &e),
    };
    let allow = own.into_iter().map(|c| c.id).collect();
    let mut m = match object(id, touch_request(&rec, allow)) {
        Ok(m) => m,
        Err(v) => return v,
    };
    m.insert("expires_at".into(), rec.expires_at.into());
    ok(id, m)
}

/// `touch.remove {credential, assertion?, host?}`.
async fn remove(ctx: &Arc<Ctx>, peer: &PeerCred, req: &Request) -> Value {
    let id = req.id;
    let cred = match credential_arg(req) {
        Ok(c) => c,
        Err(v) => return v,
    };
    let host = match req.args.get("host") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return err(id, ErrorCode::BadRequest, "host is a boolean"),
    };
    let asr = match assertion_arg(req, "assertion") {
        Ok(a) => a,
        Err(v) => return v,
    };
    let uid = peer.uid;
    let gone = if host {
        // Recovery when every device is lost: host access as root, no touch.
        if uid != 0 {
            return err(
                id,
                ErrorCode::Forbidden,
                "only root can remove a touch device without its touch",
            );
        }
        let c = cred.clone();
        match blocking(ctx, move |t| t.remove(&c)).await {
            None => return fail(ctx, peer, id, "remove", TouchError::Unavailable.into()).await,
            Some(Err(e)) => return fail(ctx, peer, id, "remove", Failure::failed(e)).await,
            Some(Ok(None)) => return no_such_device(id),
            Some(Ok(Some(c))) => (c, "root".to_string()),
        }
    } else {
        let c = cred.clone();
        let mine = blocking(ctx, move |t| {
            t.credentials_of(uid).iter().any(|x| x.id == c)
        })
        .await
        .unwrap_or(false);
        if !mine {
            return no_such_device(id);
        }
        let Some(asr) = asr else {
            let f = Failure {
                rule: "touch_unavailable",
                reason: "removing a device needs a touch of one of your devices".into(),
            };
            return fail(ctx, peer, id, "remove", f).await;
        };
        let c = cred.clone();
        let done = blocking(ctx, move |t| {
            let instance = t.instance_id();
            let (ev, rec) = t.consume(
                &IssueKey::Remove(uid),
                uid,
                |i| admin_record(instance, i),
                &asr,
                LOCAL_RP_ID,
                unix_now(),
            )?;
            // The touch approved removing the device its challenge names.
            if rec.fields.get("credential") != Some(&URL_SAFE_NO_PAD.encode(&c)) {
                return Err(TouchError::Mismatch.into());
            }
            match t.remove(&c) {
                Ok(Some(gone)) => Ok((gone, ev.credential_id)),
                Ok(None) => Err(Failure::failed("the device was removed meanwhile")),
                Err(e) => Err(Failure::failed(e)),
            }
        })
        .await
        .unwrap_or_else(|| Err(TouchError::Unavailable.into()));
        match done {
            Ok(x) => x,
            Err(f) => return fail(ctx, peer, id, "remove", f).await,
        }
    };
    let (c, by) = gone;
    let mut rec = touch_record(ctx, peer, &format!("remove {}", c.label), "touch_removed").await;
    rec.extra
        .insert("cred_id".into(), URL_SAFE_NO_PAD.encode(&c.id).into());
    rec.extra.insert("label".into(), c.label.clone().into());
    rec.extra.insert("owner_uid".into(), c.owner_uid.into());
    rec.extra.insert("approved_by".into(), by.clone().into());
    if let Err(e) = ctx.writer.append(rec).await {
        // Not on record: the removal does not happen either.
        let back = c.clone();
        let restored = blocking(ctx, move |t| t.add(back)).await;
        if !matches!(restored, Some(Ok(()))) {
            eprintln!(
                "saiife: warning: cannot restore the unrecorded removal of {}",
                URL_SAFE_NO_PAD.encode(&c.id)
            );
        }
        return err(
            id,
            ErrorCode::Unrecorded,
            &format!("the device was not removed: its record could not be written: {e}"),
        );
    }
    ok(
        id,
        json!({"id": URL_SAFE_NO_PAD.encode(&c.id), "label": c.label, "approved_by": by})
            .as_object()
            .cloned()
            .unwrap_or_default(),
    )
}

/// `touch.list {all?}`: the peer's devices, or (root and admins) every
/// one. Never the public key.
async fn list(ctx: &Arc<Ctx>, peer: &PeerCred, req: &Request) -> Value {
    let id = req.id;
    let all = match req.args.get("all") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return err(id, ErrorCode::BadRequest, "all is a boolean"),
    };
    if all && !ctx.peer_is_admin(peer).await {
        return err(
            id,
            ErrorCode::Forbidden,
            "only root or an admin can list every touch device",
        );
    }
    let uid = peer.uid;
    let creds = blocking(
        ctx,
        move |t| if all { t.all() } else { t.credentials_of(uid) },
    )
    .await
    .unwrap_or_default();
    let items: Vec<Value> = creds
        .iter()
        .map(|c| {
            json!({
                "id": URL_SAFE_NO_PAD.encode(&c.id),
                "label": c.label,
                "kind": c.kind,
                "alg": serde_json::to_value(c.public_key.alg()).unwrap_or(Value::Null),
                "rp_id": c.rp_id,
                "created": c.created,
                "sign_count": c.sign_count,
                "owner_uid": c.owner_uid,
            })
        })
        .collect();
    let mut m = Map::new();
    m.insert("credentials".into(), items.into());
    ok(id, m)
}

/// `touch.begin {purpose: "test"}`: a challenge any of the peer's devices
/// answers. Nothing is recorded.
async fn begin_test(ctx: &Arc<Ctx>, peer: &PeerCred, req: &Request) -> Value {
    let id = req.id;
    let uid = peer.uid;
    let own = blocking(ctx, move |t| t.credentials_of(uid))
        .await
        .unwrap_or_default();
    if own.is_empty() {
        return refused(
            id,
            "touch_unavailable",
            "no touch device is enrolled for you",
        );
    }
    let mut fields = BTreeMap::new();
    fields.insert("uid".to_string(), uid.to_string());
    let rec = match issue(
        ctx,
        IssueKey::Test(uid),
        uid,
        TouchClass::Test,
        "test".into(),
        fields,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return err(id, ErrorCode::Busy, &e),
    };
    let allow = own.into_iter().map(|c| c.id).collect();
    let mut m = match object(id, touch_request(&rec, allow)) {
        Ok(m) => m,
        Err(v) => return v,
    };
    m.insert("expires_at".into(), rec.expires_at.into());
    ok(id, m)
}

/// `touch.check {assertion}`: verifies a test touch and saves the counter.
/// Nothing is recorded.
async fn check(ctx: &Arc<Ctx>, peer: &PeerCred, req: &Request) -> Value {
    let id = req.id;
    let asr = match assertion_arg(req, "assertion") {
        Ok(Some(a)) => a,
        Ok(None) => return err(id, ErrorCode::BadRequest, "assertion is an assertion"),
        Err(v) => return v,
    };
    let uid = peer.uid;
    let done = blocking(ctx, move |t| {
        let instance = t.instance_id();
        t.consume(
            &IssueKey::Test(uid),
            uid,
            |i| admin_record(instance, i),
            &asr,
            LOCAL_RP_ID,
            unix_now(),
        )
    })
    .await
    .unwrap_or(Err(TouchError::Unavailable));
    match done {
        Ok((ev, _)) => {
            let mut m = Map::new();
            m.insert("label".into(), ev.label.into());
            m.insert("uv".into(), ev.user_verified.into());
            m.insert("sign_count".into(), ev.sign_count.into());
            ok(id, m)
        }
        Err(e) => refused(id, e.rule(), &e.to_string()),
    }
}

/// Enrol, remove, list and test (plan 26, Task 9), through `dispatch_conn`
/// as a client sends them; the harness is Task 8's.
#[cfg(all(test, unix))]
mod tests {
    use crate::approval_ops::touch_tests::{self as h, World, LOCKED, MARKED, OWN, PLAIN};
    use crate::ops::Mode;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use saiife_ipc::msg::{
        OP_TOUCH_BEGIN, OP_TOUCH_CHECK, OP_TOUCH_ENROL, OP_TOUCH_LIST, OP_TOUCH_REMOVE,
    };
    use saiife_touch::soft::SoftAuthenticator;
    use saiife_touch::{
        reverify, Assertion, CoseKey, Credential, EnrolRequest, Touch as _, TouchRequest,
        LOCAL_RP_ID, RP_NAME,
    };
    use serde_json::{json, Value};
    use std::sync::Arc;

    fn b64(b: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(b)
    }

    fn unb64(v: &Value) -> Vec<u8> {
        URL_SAFE_NO_PAD.decode(v.as_str().unwrap()).unwrap()
    }

    fn world() -> World {
        h::world_in(Mode::Personal, OWN, PLAIN, false)
    }

    async fn begin(ctx: &Arc<crate::ops::Ctx>, uid: u32, args: Value) -> Value {
        h::op(ctx, uid, OP_TOUCH_BEGIN, args).await
    }

    async fn begin_enrol(ctx: &Arc<crate::ops::Ctx>, uid: u32, label: &str) -> Value {
        begin(ctx, uid, json!({"purpose": "enrol", "label": label})).await
    }

    fn treq(v: &Value, key: &str) -> TouchRequest {
        serde_json::from_value(v[key].clone()).unwrap_or_else(|e| panic!("{key}: {e}: {v}"))
    }

    fn ereq(v: &Value) -> EnrolRequest {
        assert_eq!(v["ok"], true, "{v}");
        serde_json::from_value(v.clone()).unwrap()
    }

    /// The `touch.enrol` body of `soft` answering the enrol answer `b`;
    /// `by` answers `approve_with` when given.
    fn enrol_body(
        b: &Value,
        soft: &SoftAuthenticator,
        label: &str,
        by: Option<&SoftAuthenticator>,
    ) -> Value {
        let auth_data = soft.enrol(&ereq(b)).unwrap();
        let proof = soft.request(&treq(b, "touch")).unwrap();
        let mut body = json!({
            "label": label,
            "auth_data": b64(&auth_data),
            "proof": serde_json::to_value(&proof).unwrap(),
        });
        if let Some(by) = by {
            let a = by.request(&treq(b, "approve_with")).unwrap();
            body["approval"] = serde_json::to_value(&a).unwrap();
        }
        body
    }

    /// A whole first (host-approved) enrolment of `soft` as `label`.
    async fn enrol_first(w: &World, soft: &SoftAuthenticator, label: &str) {
        let b = begin_enrol(&w.ctx, OWN, label).await;
        let v = h::op(
            &w.ctx,
            OWN,
            OP_TOUCH_ENROL,
            enrol_body(&b, soft, label, None),
        )
        .await;
        assert_eq!(v["ok"], true, "{v}");
    }

    async fn list(ctx: &Arc<crate::ops::Ctx>, uid: u32, all: bool) -> Value {
        h::op(ctx, uid, OP_TOUCH_LIST, json!({"all": all})).await
    }

    fn listed(v: &Value) -> Vec<Value> {
        assert_eq!(v["ok"], true, "{v}");
        v["credentials"].as_array().unwrap().clone()
    }

    fn touch_records(w: &World, action: &str) -> Vec<Value> {
        h::records(w.d.path())
            .into_iter()
            .filter(|r| r["kind"] == "touch" && r["action"] == action)
            .collect()
    }

    fn forbidden(v: &Value) {
        assert_eq!(v["ok"], false, "{v}");
        assert_eq!(v["error"], "forbidden", "{v}");
    }

    #[tokio::test]
    async fn first_enrol_needs_host_only() {
        let w = world();
        let b = begin_enrol(&w.ctx, OWN, "key").await;
        let er = ereq(&b);
        assert_eq!(er.rp_id, LOCAL_RP_ID);
        assert_eq!(er.rp_name, RP_NAME);
        assert_eq!(er.user_id, OWN.to_be_bytes().to_vec());
        assert!(!er.user_name.is_empty());
        assert!(er.exclude.is_empty());
        assert!(b.get("approve_with").is_none(), "{b}");
        let tr = treq(&b, "touch");
        assert!(tr.allow.is_empty());
        assert!(tr.uv);
        assert_eq!(tr.challenge, er.challenge);
        assert_eq!(tr.short_code, saiife_touch::short_code(&tr.challenge));

        let v = h::op(
            &w.ctx,
            OWN,
            OP_TOUCH_ENROL,
            enrol_body(&b, &w.soft, "key", None),
        )
        .await;
        assert_eq!(v["ok"], true, "{v}");
        let l = listed(&list(&w.ctx, OWN, false).await);
        assert_eq!(l.len(), 1);
        let c = &l[0];
        assert_eq!(c["id"], b64(&w.soft.credential_id()), "{c}");
        assert_eq!(c["label"], "key");
        assert_eq!(c["kind"], "fido2");
        assert_eq!(c["alg"], "es256");
        assert_eq!(c["rp_id"], LOCAL_RP_ID);
        assert_eq!(c["owner_uid"], OWN);
        assert_eq!(c["sign_count"], 1);
        assert!(c["created"].is_string());
        assert!(c.get("public_key").is_none(), "{c}");

        let rec = touch_records(&w, "touch_enrolled");
        assert_eq!(rec.len(), 1);
        let r = &rec[0];
        assert_eq!(r["approved_by"], "host", "{r}");
        assert_eq!(r["public_key"], b64(&w.soft.public_key().to_cose()), "{r}");
        assert_eq!(r["cred_id"], b64(&w.soft.credential_id()));
        assert_eq!(r["label"], "key");
        assert_eq!(r["alg"], "es256");
        assert_eq!(r["kind"], "touch");
        assert_eq!(r["cred_kind"], "fido2");
        assert_eq!(r["rp_id"], LOCAL_RP_ID);
        assert_eq!(r["owner_uid"], OWN);
        assert_eq!(r["by_uid"], OWN);
        assert_eq!(r["aaguid"], "00".repeat(16));
        assert!(r["created"].is_string());
        assert!(r.get("origins").is_none(), "{r}");
    }

    /// R9: an auditor rebuilds the trusted credential from the
    /// `touch_enrolled` record alone and re-verifies a later approval.
    #[tokio::test]
    async fn enrolled_record_rebuilds_the_credential() {
        let w = h::world_in(Mode::Personal, OWN, MARKED, false);
        enrol_first(&w, &w.soft, "key").await;
        let rid = h::ask(&w, "a", "objects:write").await;
        let tr = h::treq(&h::begin(&w.ctx, OWN, rid).await);
        let asr = w.soft.request(&tr).unwrap();
        let v = h::decide_with(&w.ctx, OWN, rid, "approve", Some(&asr)).await;
        assert_eq!(v["ok"], true, "{v}");
        let approved = h::approval_records(&w, rid, "approved");
        let touch = &approved[0]["touch"];

        let e = &touch_records(&w, "touch_enrolled")[0];
        let (key, used) = CoseKey::parse(&unb64(&e["public_key"])).unwrap();
        assert_eq!(used, unb64(&e["public_key"]).len());
        let origins = match e.get("origins") {
            None => Vec::new(),
            Some(o) => serde_json::from_value(o.clone()).unwrap(),
        };
        let rebuilt = Credential {
            id: unb64(&e["cred_id"]),
            public_key: key,
            kind: e["cred_kind"].as_str().unwrap().into(),
            rp_id: e["rp_id"].as_str().unwrap().into(),
            origins,
            label: e["label"].as_str().unwrap().into(),
            owner_uid: e["owner_uid"].as_u64().unwrap() as u32,
            owner_sid: None,
            sign_count: 0,
            created: e["created"].as_str().unwrap().into(),
            aaguid: e["aaguid"].as_str().unwrap().into(),
        };
        assert_eq!(reverify(touch, &rebuilt), Ok(()));
    }

    #[tokio::test]
    async fn second_enrol_needs_an_existing_device() {
        let w = world();
        enrol_first(&w, &w.soft, "key1").await;
        let key2 = SoftAuthenticator::new_ed25519();
        let id1 = w.soft.credential_id();

        let b = begin_enrol(&w.ctx, OWN, "key2").await;
        let er = ereq(&b);
        assert_eq!(er.exclude, vec![id1.clone()]);
        let aw = treq(&b, "approve_with");
        assert_eq!(aw.allow, vec![id1.clone()]);
        assert!(aw.uv);
        assert_eq!(aw.challenge, er.challenge);
        // Without the existing device's touch: refused, recorded.
        let v = h::op(
            &w.ctx,
            OWN,
            OP_TOUCH_ENROL,
            enrol_body(&b, &key2, "key2", None),
        )
        .await;
        assert_eq!(h::refused_rule(&v), "touch_unavailable");
        let failed = touch_records(&w, "touch_failed");
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0]["rule"], "touch_unavailable");
        assert_eq!(listed(&list(&w.ctx, OWN, false).await).len(), 1);

        // With it: enrolled, approved by key1.
        let b = begin_enrol(&w.ctx, OWN, "key2").await;
        let body = enrol_body(&b, &key2, "key2", Some(&w.soft));
        let v = h::op(&w.ctx, OWN, OP_TOUCH_ENROL, body).await;
        assert_eq!(v["ok"], true, "{v}");
        let rec = touch_records(&w, "touch_enrolled");
        assert_eq!(rec.len(), 2);
        assert_eq!(rec[1]["approved_by"], b64(&id1), "{}", rec[1]);
        assert_eq!(rec[1]["alg"], "ed25519");
        assert_eq!(listed(&list(&w.ctx, OWN, false).await).len(), 2);
        // key1's counter was saved (1 at its enrolment, 2 approving).
        let c = w.ctx.touch.credentials_of(OWN);
        assert_eq!(c.iter().find(|c| c.id == id1).unwrap().sign_count, 2);
    }

    #[tokio::test]
    async fn enrol_without_uv_is_refused() {
        let mut w = world();
        let b = begin_enrol(&w.ctx, OWN, "key").await;
        // SoftAuthenticator::enrol always sets UV: the proof lacks it.
        w.soft.uv = false;
        let v = h::op(
            &w.ctx,
            OWN,
            OP_TOUCH_ENROL,
            enrol_body(&b, &w.soft, "key", None),
        )
        .await;
        assert_eq!(h::refused_rule(&v), "touch_failed");
        assert!(
            v["message"].as_str().unwrap().contains("user verification"),
            "{v}"
        );
        let failed = touch_records(&w, "touch_failed");
        assert_eq!(failed.len(), 1);
        assert!(failed[0]["reason"]
            .as_str()
            .unwrap()
            .contains("user verification"));
        assert!(listed(&list(&w.ctx, OWN, false).await).is_empty());
    }

    #[tokio::test]
    async fn enrol_replay_is_refused() {
        let w = world();
        let b = begin_enrol(&w.ctx, OWN, "key").await;
        let body = enrol_body(&b, &w.soft, "key", None);
        let v = h::op(&w.ctx, OWN, OP_TOUCH_ENROL, body.clone()).await;
        assert_eq!(v["ok"], true, "{v}");
        let v = h::op(&w.ctx, OWN, OP_TOUCH_ENROL, body).await;
        assert_eq!(h::refused_rule(&v), "touch_failed");
        assert_eq!(touch_records(&w, "touch_failed").len(), 1);
        assert_eq!(listed(&list(&w.ctx, OWN, false).await).len(), 1);
    }

    #[tokio::test]
    async fn duplicate_device_is_refused() {
        let w = world();
        enrol_first(&w, &w.soft, "key").await;
        let b = begin_enrol(&w.ctx, OWN, "again").await;
        let body = enrol_body(&b, &w.soft, "again", Some(&w.soft));
        let v = h::op(&w.ctx, OWN, OP_TOUCH_ENROL, body).await;
        forbidden(&v);
        assert!(
            v["message"].as_str().unwrap().contains("already enrolled"),
            "{v}"
        );
        assert_eq!(listed(&list(&w.ctx, OWN, false).await).len(), 1);
    }

    #[tokio::test]
    async fn bad_label_is_refused_at_begin() {
        let w = world();
        let v = begin_enrol(&w.ctx, OWN, "").await;
        assert_eq!(v["error"], "bad_request", "{v}");
        let v = begin_enrol(&w.ctx, OWN, "a\u{200b}b").await;
        assert_eq!(v["error"], "bad_request", "{v}");
    }

    #[tokio::test]
    async fn remove_with_touch() {
        let w = world();
        enrol_first(&w, &w.soft, "key").await;
        let id = b64(&w.soft.credential_id());
        // An unknown id is a bad request, at begin and at remove.
        let v = begin(
            &w.ctx,
            OWN,
            json!({"purpose": "remove", "credential": "AAAA"}),
        )
        .await;
        assert_eq!(v["error"], "bad_request", "{v}");
        let v = h::op(&w.ctx, OWN, OP_TOUCH_REMOVE, json!({"credential": "AAAA"})).await;
        assert_eq!(v["error"], "bad_request", "{v}");

        let b = begin(&w.ctx, OWN, json!({"purpose": "remove", "credential": id})).await;
        assert_eq!(b["ok"], true, "{b}");
        let tr: TouchRequest = serde_json::from_value(b.clone()).unwrap();
        assert_eq!(tr.allow, vec![w.soft.credential_id()]);
        assert!(tr.uv);
        let asr: Assertion = w.soft.request(&tr).unwrap();
        let v = h::op(
            &w.ctx,
            OWN,
            OP_TOUCH_REMOVE,
            json!({"credential": id, "assertion": asr}),
        )
        .await;
        assert_eq!(v["ok"], true, "{v}");
        let rec = touch_records(&w, "touch_removed");
        assert_eq!(rec.len(), 1);
        assert_eq!(rec[0]["cred_id"], id);
        assert_eq!(rec[0]["label"], "key");
        assert_eq!(rec[0]["approved_by"], id);
        assert!(listed(&list(&w.ctx, OWN, false).await).is_empty());
    }

    /// A removal is approved only for the device its challenge names: a
    /// touch over the challenge for key2 cannot remove key1.
    #[tokio::test]
    async fn remove_challenge_for_another_device_is_refused() {
        let w = world();
        enrol_first(&w, &w.soft, "key1").await;
        let key2 = SoftAuthenticator::new_ed25519();
        let b = begin_enrol(&w.ctx, OWN, "key2").await;
        let body = enrol_body(&b, &key2, "key2", Some(&w.soft));
        let v = h::op(&w.ctx, OWN, OP_TOUCH_ENROL, body).await;
        assert_eq!(v["ok"], true, "{v}");
        let id1 = b64(&w.soft.credential_id());
        let id2 = b64(&key2.credential_id());

        let b = begin(&w.ctx, OWN, json!({"purpose": "remove", "credential": id2})).await;
        assert_eq!(b["ok"], true, "{b}");
        let tr: TouchRequest = serde_json::from_value(b).unwrap();
        let asr = w.soft.request(&tr).unwrap();
        let v = h::op(
            &w.ctx,
            OWN,
            OP_TOUCH_REMOVE,
            json!({"credential": id1, "assertion": asr}),
        )
        .await;
        assert_eq!(h::refused_rule(&v), "touch_mismatch");
        assert_eq!(listed(&list(&w.ctx, OWN, false).await).len(), 2);
        assert!(touch_records(&w, "touch_removed").is_empty());
        let failed = touch_records(&w, "touch_failed");
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0]["rule"], "touch_mismatch");
        assert_eq!(failed[0]["op"], "remove");
    }

    /// D6 at enrolment: another uid's device cannot approve a new device.
    #[tokio::test]
    async fn another_uids_device_cannot_approve_an_enrolment() {
        let w = h::world_in(Mode::Locked, 999, LOCKED, false);
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
        let new = SoftAuthenticator::new_ed25519();
        let b = begin_enrol(&w.ctx, 4343, "new").await;
        let aw = treq(&b, "approve_with");
        assert_eq!(aw.allow, vec![bob.credential_id()]);
        let mut body = enrol_body(&b, &new, "new", None);
        // Ann's key signs Bob's approval request.
        let a = ann.assert_ctap(&aw.rp_id, &aw.challenge);
        body["approval"] = serde_json::to_value(&a).unwrap();
        let v = h::op(&w.ctx, 4343, OP_TOUCH_ENROL, body).await;
        assert_eq!(h::refused_rule(&v), "touch_mismatch");
        assert!(
            v["message"]
                .as_str()
                .unwrap()
                .contains("not enrolled for you"),
            "{v}"
        );
        assert_eq!(w.ctx.touch.credentials_of(4343).len(), 1);
        assert!(touch_records(&w, "touch_enrolled").is_empty());
        assert_eq!(touch_records(&w, "touch_failed").len(), 1);
    }

    #[tokio::test]
    async fn remove_by_host_root_only() {
        // Personal: the own user is not root.
        let w = world();
        enrol_first(&w, &w.soft, "key").await;
        let id = b64(&w.soft.credential_id());
        let host = json!({"credential": id, "host": true});
        forbidden(&h::op(&w.ctx, OWN, OP_TOUCH_REMOVE, host.clone()).await);
        assert_eq!(listed(&list(&w.ctx, OWN, false).await).len(), 1);
        assert!(touch_records(&w, "touch_removed").is_empty());

        // Locked: an approver (ann) is not root either; root is.
        let w = h::world_in(Mode::Locked, 999, LOCKED, false);
        w.ctx
            .touch
            .add(w.soft.credential(LOCAL_RP_ID, OWN, "key"))
            .unwrap();
        let id = b64(&w.soft.credential_id());
        let host = json!({"credential": id, "host": true});
        forbidden(&h::op(&w.ctx, 4242, OP_TOUCH_REMOVE, host.clone()).await);
        forbidden(&list(&w.ctx, 4242, true).await);
        assert!(listed(&list(&w.ctx, 4242, false).await).is_empty());
        assert_eq!(listed(&list(&w.ctx, 0, true).await).len(), 1);
        let v = h::op(&w.ctx, 0, OP_TOUCH_REMOVE, host).await;
        assert_eq!(v["ok"], true, "{v}");
        let rec = touch_records(&w, "touch_removed");
        assert_eq!(rec.len(), 1);
        assert_eq!(rec[0]["approved_by"], "root");
        assert_eq!(rec[0]["by_uid"], 0);
        assert!(listed(&list(&w.ctx, 0, true).await).is_empty());
    }

    #[tokio::test]
    async fn test_touch() {
        let w = world();
        enrol_first(&w, &w.soft, "key").await;
        for want in [2, 3] {
            let b = begin(&w.ctx, OWN, json!({"purpose": "test"})).await;
            assert_eq!(b["ok"], true, "{b}");
            let tr: TouchRequest = serde_json::from_value(b).unwrap();
            assert_eq!(tr.allow, vec![w.soft.credential_id()]);
            let asr = w.soft.request(&tr).unwrap();
            let v = h::op(&w.ctx, OWN, OP_TOUCH_CHECK, json!({"assertion": asr})).await;
            assert_eq!(v["ok"], true, "{v}");
            assert_eq!(v["label"], "key");
            assert_eq!(v["uv"], true);
            assert_eq!(v["sign_count"], want);
            assert_eq!(w.ctx.touch.credentials_of(OWN)[0].sign_count, want);
        }
        // A replayed check: refused.
        let v = h::op(
            &w.ctx,
            OWN,
            OP_TOUCH_CHECK,
            json!({"assertion": w.soft.assert_ctap(LOCAL_RP_ID, &[0; 32])}),
        )
        .await;
        assert_eq!(h::refused_rule(&v), "touch_failed");
        // Only the enrolment is on record.
        let touch: Vec<_> = h::records(w.d.path())
            .into_iter()
            .filter(|r| r["kind"] == "touch")
            .collect();
        assert_eq!(touch.len(), 1, "{touch:?}");
    }

    #[tokio::test]
    async fn non_approver_is_forbidden() {
        let w = h::world_in(Mode::Locked, 999, LOCKED, false);
        w.ctx
            .touch
            .add(w.soft.credential(LOCAL_RP_ID, OWN, "key"))
            .unwrap();
        let id = b64(&w.soft.credential_id());
        let calls = [
            (OP_TOUCH_BEGIN, json!({"purpose": "enrol", "label": "k"})),
            (
                OP_TOUCH_BEGIN,
                json!({"purpose": "remove", "credential": id}),
            ),
            (OP_TOUCH_BEGIN, json!({"purpose": "test"})),
            (
                OP_TOUCH_ENROL,
                json!({"label": "k", "auth_data": "AA", "proof": {}}),
            ),
            (OP_TOUCH_REMOVE, json!({"credential": id})),
            (OP_TOUCH_LIST, json!({})),
            (OP_TOUCH_CHECK, json!({"assertion": {}})),
        ];
        for (op, args) in calls {
            let v = h::op(&w.ctx, OWN, op, args.clone()).await;
            assert_eq!(v["error"], "forbidden", "{op} {args}: {v}");
        }
        assert_eq!(w.ctx.touch.credentials_of(OWN).len(), 1);
    }
}
