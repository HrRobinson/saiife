//! The `blind.*` ops (plan 47). Control socket, machine local only: stage 1
//! has no remote surface (R47-3). Tasks 2 to 6 and plan 48 fill in the ops;
//! until then each answers [`not_yet`].

use super::Refusal;
use crate::ops::{Conn, Ctx, Mode};
use saiife_ipc::msg::{ErrorCode, Request};
use saiife_ipc::peer::PeerCred;
use saiife_policy::blind::BlindDataset;
use serde_json::Value;
use std::sync::Arc;

/// Who a peer is to a dataset (R47-3). Ordered: each role may do what the
/// ones below it may.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// Nothing.
    None,
    /// In the dataset's `users`: may ask.
    User,
    /// In the dataset's `approvers` (`[approval] approvers` when that is
    /// empty): may ask, approve and manage the dataset.
    Approver,
    /// Root or an `[admin]` group member (locked); the daemon's own user
    /// (personal, where it is the approver too).
    Admin,
}

impl Role {
    /// `ask` (users and approvers).
    pub fn may_ask(self) -> bool {
        self >= Role::User
    }

    /// `data stage` of a new name, `data commit`, `data refresh`, `data rm`,
    /// `ner fetch`, and approving.
    pub fn may_manage(self) -> bool {
        self >= Role::Approver
    }
}

/// The peer's role for `ds` (`None`: a dataset not yet in policy, so only
/// admins and `[approval] approvers` count). The personal broker's own user
/// is [`Role::Admin`], as `approval_ops::is_approver` makes it the approver.
// Task 2 (`data stage`, `commit`, `refresh`, `rm`) is the first caller.
#[allow(dead_code)]
pub(crate) async fn role(ctx: &Ctx, peer: &PeerCred, ds: Option<&BlindDataset>) -> Role {
    if ctx.mode == Mode::Personal {
        return if ctx.peer_is_own(peer) {
            Role::Admin
        } else {
            Role::None
        };
    }
    if ctx.peer_is_admin(peer).await {
        return Role::Admin;
    }
    let own = ds.map(|d| d.approvers.as_slice()).unwrap_or_default();
    let approvers = if own.is_empty() {
        match ctx.policy().system {
            Some(s) => s.approval.approvers.clone(),
            None => Vec::new(),
        }
    } else {
        own.to_vec()
    };
    if crate::approval_ops::peer_listed(ctx, peer, &approvers).await {
        return Role::Approver;
    }
    match ds {
        Some(d) if crate::approval_ops::peer_listed(ctx, peer, &d.users).await => Role::User,
        _ => Role::None,
    }
}

/// What an op answers until its task builds it.
pub fn not_yet(op: &str) -> Refusal {
    Refusal::new(
        ErrorCode::Unavailable,
        format!("{op} is not available in this build yet"),
    )
}

/// Every op in [`super::OPS`].
pub async fn handle(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value {
    // No op takes passed descriptors yet: they are closed now.
    drop(conn.take_fds());
    // Each later task replaces its arm.
    let _ = ctx;
    let r = match req.op.as_str() {
        saiife_ipc::msg::OP_BLIND_STATUS | saiife_ipc::msg::OP_BLIND_METHODS_LIST => {
            not_yet(&req.op)
        }
        saiife_ipc::msg::OP_BLIND_DATA_STAGE
        | saiife_ipc::msg::OP_BLIND_DATA_COMMIT
        | saiife_ipc::msg::OP_BLIND_DATA_REFRESH
        | saiife_ipc::msg::OP_BLIND_DATA_RM => not_yet(&req.op),
        saiife_ipc::msg::OP_BLIND_NER_FETCH => not_yet(&req.op),
        // Plan 48.
        saiife_ipc::msg::OP_BLIND_ASK
        | saiife_ipc::msg::OP_BLIND_ASK_ANSWER
        | saiife_ipc::msg::OP_BLIND_TOUCH_BEGIN
        | saiife_ipc::msg::OP_BLIND_TOUCH_COMMIT => not_yet(&req.op),
        other => Refusal::new(ErrorCode::BadRequest, format!("unknown op {other:?}")),
    };
    r.to_value(req.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::CtxInit;
    use saiife_policy::{Directory, FixedDirectory};
    use std::time::Duration;

    const PASSWD: &str = "\
root:x:0:0::/root:/bin/sh
ann:x:1001:1001::/home/ann:/bin/sh
bob:x:1002:1002::/home/bob:/bin/sh
cat:x:1003:1003::/home/cat:/bin/sh
dan:x:1004:1004::/home/dan:/bin/sh
eve:x:1005:1005::/home/eve:/bin/sh
";
    const GROUP: &str = "\
ops:x:2000:dan
sec:x:2001:eve
";

    fn peer(uid: u32) -> PeerCred {
        PeerCred {
            uid,
            gid: uid,
            pid: std::process::id(),
            sid: None,
            group_sids: Vec::new(),
        }
    }

    fn ctx(dir: &std::path::Path, mode: Mode, own_uid: u32, config: &str) -> Arc<Ctx> {
        let cw = saiife_audit::ChainWriter::open(
            &dir.join("audit"),
            saiife_audit::WriterOptions {
                mode: mode.as_str().into(),
                saiife: "test".into(),
                key: None,
            },
        )
        .unwrap();
        let cfg = crate::writer::WriterConfig {
            checkpoint_every: 1000,
            checkpoint_interval: Duration::from_secs(900),
            fsync: saiife_policy::Fsync::Always,
        };
        let (handle, _join) = crate::writer::spawn(cw, cfg, None).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, config).unwrap();
        let l = saiife_policy::load_system(&path).unwrap();
        let policy =
            crate::ops::PolicyState::from_loaded(&l, &[], saiife_broker::Catalog::new(&[], vec![]));
        let dirs: Arc<dyn Directory + Send + Sync> =
            Arc::new(FixedDirectory::from_text(PASSWD, GROUP));
        Arc::new(Ctx::new(CtxInit {
            mode,
            own_uid,
            policy,
            config_path: path,
            ..CtxInit::minimal(handle, cfg, dirs, &dir.join("state"))
        }))
    }

    const BASE: &str =
        "version = 2\n\n[admin]\ngroups = [\"sec\"]\n\n[approval]\napprovers = [\"cat\"]\n";

    fn dataset(users: &str, approvers: &str) -> String {
        format!(
            "\n[[blind.dataset]]\nname = \"crm\"\nsource = {{ kind = \"csv\", file_name = \"crm.csv\" }}\nusers = [{users}]\napprovers = [{approvers}]\n"
        )
    }

    async fn roles_of(c: &Ctx, uids: &[u32]) -> Vec<Role> {
        let p = c.policy();
        let ds = p
            .system
            .as_ref()
            .and_then(|s| s.blind.dataset.first().cloned());
        let mut out = Vec::new();
        for u in uids {
            out.push(role(c, &peer(*u), ds.as_ref()).await);
        }
        out
    }

    #[tokio::test]
    async fn roles() {
        let t = tempfile::tempdir().unwrap();
        let all = [0, 1001, 1002, 1003, 1004, 1005];
        // Locked, the dataset's own approvers.
        let c = ctx(
            t.path(),
            Mode::Locked,
            999,
            &format!("{BASE}{}", dataset("\"ann\", \"group:ops\"", "\"bob\"")),
        );
        assert_eq!(
            roles_of(&c, &all).await,
            [
                Role::Admin,    // root
                Role::User,     // ann, in users
                Role::Approver, // bob, the dataset's approver
                Role::None,     // cat: [approval] only counts when the dataset names none
                Role::User,     // dan, through group:ops
                Role::Admin,    // eve, an [admin] group
            ]
        );
        // Empty `approvers`: `[approval] approvers`.
        let t2 = tempfile::tempdir().unwrap();
        let c = ctx(
            t2.path(),
            Mode::Locked,
            999,
            &format!("{BASE}{}", dataset("\"ann\"", "")),
        );
        assert_eq!(
            roles_of(&c, &[1001, 1002, 1003]).await,
            [Role::User, Role::None, Role::Approver]
        );
        // No dataset in policy: admins and `[approval] approvers`.
        assert_eq!(role(&c, &peer(1003), None).await, Role::Approver);
        assert_eq!(role(&c, &peer(1001), None).await, Role::None);
        assert_eq!(role(&c, &peer(0), None).await, Role::Admin);
        // Personal: the own user is admin and approver; nobody else is anything.
        let t3 = tempfile::tempdir().unwrap();
        let c = ctx(
            t3.path(),
            Mode::Personal,
            1001,
            &format!("{BASE}{}", dataset("\"bob\"", "\"bob\"")),
        );
        assert_eq!(
            roles_of(&c, &[1001, 1002, 0]).await,
            [Role::Admin, Role::None, Role::None]
        );
        let own = role(&c, &peer(1001), None).await;
        assert!(own.may_manage() && own.may_ask());
        assert!(Role::User.may_ask() && !Role::User.may_manage());
        assert!(!Role::None.may_ask());
    }
}
