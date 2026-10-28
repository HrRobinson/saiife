//! `policy.show` and `policy.reload` (spec §7).

use crate::ops::Ctx;
use saiife_ipc::msg::{err, ok, ErrorCode, Request, OP_POLICY_RELOAD, OP_POLICY_SHOW};
use saiife_ipc::peer::PeerCred;
use saiife_policy::{active_packs, effective_policy, view::user_view};
use serde_json::{json, Map, Value};
use std::sync::Arc;

pub async fn handle(ctx: &Arc<Ctx>, peer: &PeerCred, req: Request) -> Value {
    match req.op.as_str() {
        OP_POLICY_SHOW => show(ctx, peer, req).await,
        OP_POLICY_RELOAD => reload(ctx, peer, req.id).await,
        other => err(
            req.id,
            ErrorCode::UnknownOp,
            &format!("unknown op {other:?}"),
        ),
    }
}

/// Anyone gets their own scope; another user's scope and the whole merged
/// policy are for root and `[admin] groups`. A non-admin's answer holds
/// their scope, its services and the guard settings, nothing else.
async fn show(ctx: &Arc<Ctx>, peer: &PeerCred, req: Request) -> Value {
    let id = req.id;
    let bad = |m: &str| err(id, ErrorCode::BadRequest, m);
    let target = match req.args.get("user") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(_) => return bad("user is a non-empty string"),
    };
    let effective = match req.args.get("effective") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return bad("effective is true|false"),
    };
    let Some(own) = ctx.name_of(peer.uid).await else {
        return err(
            id,
            ErrorCode::Forbidden,
            "policy.show: your uid has no user name",
        );
    };
    let other = target.as_deref().is_some_and(|t| t != own);
    if (other || effective) && !ctx.is_admin(peer.uid).await {
        return err(
            id,
            ErrorCode::Forbidden,
            "policy.show for another user, or --effective, is for root and [admin] groups",
        );
    }
    let user = target.unwrap_or(own);
    let state = ctx.policy();
    let Some(system) = state.system.clone() else {
        return err(
            id,
            ErrorCode::Unavailable,
            "no valid policy is loaded (connectors are denied)",
        );
    };
    let dir = Arc::clone(&ctx.directory);
    let name = user.clone();
    let cfg = Arc::clone(&system);
    let view = tokio::task::spawn_blocking(move || {
        dir.user(&name)?;
        Some(user_view(&cfg, dir.as_ref(), &name))
    })
    .await
    .ok()
    .flatten();
    let Some(view) = view else {
        return err(id, ErrorCode::BadRequest, &format!("no user {user:?}"));
    };
    let mut m = Map::new();
    m.insert("view".into(), view);
    m.insert("hash".into(), json!(state.hash));
    if effective {
        let (packs, _) = active_packs(&system, &ctx.catalog, None);
        m.insert("effective".into(), effective_policy(&system, &packs, None));
    }
    ok(id, m)
}

async fn reload(ctx: &Arc<Ctx>, peer: &PeerCred, id: u64) -> Value {
    if !ctx.is_admin(peer.uid).await {
        return err(
            id,
            ErrorCode::Forbidden,
            "policy.reload is for root and [admin] groups",
        );
    }
    let mut m = Map::new();
    match crate::start::reload(ctx).await {
        Ok(()) => {
            m.insert("result".into(), "loaded".into());
        }
        Err(reason) => {
            m.insert("result".into(), "rejected".into());
            m.insert("reason".into(), reason.into());
        }
    }
    m.insert("hash".into(), json!(ctx.policy().hash));
    ok(id, m)
}
