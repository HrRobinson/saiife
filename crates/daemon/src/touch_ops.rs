//! The touch ops (plan 26): `touch.begin`, `touch.enrol`, `touch.remove`,
//! `touch.list`, `touch.check`. File-touching calls run on a blocking
//! thread (`tokio::task::spawn_blocking`), as the approval ops do.
//!
//! Task 7 lays the dispatch; Task 8 fills `approve_ops` (`touch.begin` for
//! an approval) and Task 9 `admin_ops` (enrol, remove, list, test). Until
//! then both answer `unknown_op`.

use std::sync::Arc;

use saiife_ipc::msg::{
    err, ErrorCode, Request, OP_TOUCH_BEGIN, OP_TOUCH_CHECK, OP_TOUCH_ENROL, OP_TOUCH_LIST,
    OP_TOUCH_REMOVE,
};
use serde_json::Value;

use crate::ops::{Conn, Ctx};

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

/// Task 8.
async fn approve_ops(_ctx: &Arc<Ctx>, _conn: &Conn, req: Request) -> Value {
    unknown(req)
}

/// Task 9.
async fn admin_ops(_ctx: &Arc<Ctx>, _conn: &Conn, req: Request) -> Value {
    unknown(req)
}
