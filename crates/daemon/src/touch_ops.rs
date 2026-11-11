//! The touch ops (plan 26): `touch.begin`, `touch.enrol`, `touch.remove`,
//! `touch.list`, `touch.check`. File-touching calls run on a blocking
//! thread (`tokio::task::spawn_blocking`), as the approval ops do.
//!
//! Task 7 lays the dispatch; Task 8 fills `approve_ops` (`touch.begin` for
//! an approval) and Task 9 `admin_ops` (enrol, remove, list, test, and the
//! other purposes of `touch.begin`). Until then `admin_ops` answers
//! `unknown_op`.

use std::sync::Arc;

use saiife_ipc::msg::{
    err, ok, ErrorCode, Request, OP_TOUCH_BEGIN, OP_TOUCH_CHECK, OP_TOUCH_ENROL, OP_TOUCH_LIST,
    OP_TOUCH_REMOVE,
};
use saiife_ipc::peer::PeerCred;
use saiife_touch::{challenge, short_code, TouchRequest, LOCAL_RP_ID};
use serde_json::Value;

use crate::approvals::{action_record, state_name, State};
use crate::approvers::Refusal;
use crate::ops::{Conn, Ctx};
use crate::touch::{unix_now, IssueKey};

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
        // The summary and fields do not depend on the nonce or expiry.
        let shape = action_record(&r, class, t.instance_id(), [0; 32], 0);
        let i = t.issue(
            IssueKey::Approve(rid),
            uid,
            class,
            shape.summary,
            shape.fields,
            unix_now(),
        )?;
        Ok::<_, String>((
            action_record(&r, class, t.instance_id(), i.nonce, i.expires_at),
            i.expires_at,
        ))
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

/// Task 9.
async fn admin_ops(_ctx: &Arc<Ctx>, _conn: &Conn, req: Request) -> Value {
    unknown(req)
}
