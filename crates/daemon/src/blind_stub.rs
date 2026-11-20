//! Data Shield outside Linux (plan 47): every `blind.*` op answers
//! [`UNAVAILABLE_OS`].

/// Every `blind.*` op.
pub const OPS: &[&str] = saiife_ipc::msg::BLIND_OPS;

/// What every `blind.*` op answers outside Linux.
pub const UNAVAILABLE_OS: &str = "Data Shield runs on Linux in this release";

pub mod ops {
    use crate::ops::{Conn, Ctx};
    use saiife_ipc::msg::{err, ErrorCode, Request};
    use serde_json::Value;
    use std::sync::Arc;

    /// Every op in [`super::OPS`].
    pub async fn handle(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value {
        let _ = ctx;
        // Passed descriptors are closed.
        #[cfg(unix)]
        drop(conn.take_fds());
        #[cfg(not(unix))]
        let _ = conn;
        err(req.id, ErrorCode::Unavailable, super::UNAVAILABLE_OS)
    }
}
