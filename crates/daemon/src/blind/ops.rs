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

/// Who a peer is to a dataset (R47-3, ruling P47-13). Each flag is
/// computed on its own: an admin may also be listed, and only the lists
/// give `ask`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Roles {
    /// Root or an `[admin]` group member (locked); the daemon's own user
    /// (personal).
    pub admin: bool,
    /// In the dataset's `approvers` (`[approval] approvers` when that is
    /// empty or there is no dataset yet); the own user (personal).
    pub approver: bool,
    /// In the dataset's `users`; the own user (personal).
    pub user: bool,
}

impl Roles {
    /// `ask`: users and approvers only. Root and `[admin]` members ask only
    /// when listed.
    pub fn may_ask(self) -> bool {
        self.user || self.approver
    }

    /// `data stage` of a new name, `data commit`, `data refresh`, `data rm`,
    /// `ner fetch`: admins and approvers.
    pub fn may_manage(self) -> bool {
        self.admin || self.approver
    }
}

/// The peer's roles for `ds` (`None`: a dataset not yet in policy, so only
/// admin and `[approval] approvers` count). The personal broker's own user
/// is all three, as `approval_ops::is_approver` makes it the approver.
pub(crate) async fn role(ctx: &Ctx, peer: &PeerCred, ds: Option<&BlindDataset>) -> Roles {
    if ctx.mode == Mode::Personal {
        let own = ctx.peer_is_own(peer);
        return Roles {
            admin: own,
            approver: own,
            user: own,
        };
    }
    let admin = ctx.peer_is_admin(peer).await;
    let own = ds.map(|d| d.approvers.as_slice()).unwrap_or_default();
    let approvers = if own.is_empty() {
        match ctx.policy().system {
            Some(s) => s.approval.approvers.clone(),
            None => Vec::new(),
        }
    } else {
        own.to_vec()
    };
    let approver = crate::approval_ops::peer_listed(ctx, peer, &approvers).await;
    let user = match ds {
        Some(d) => crate::approval_ops::peer_listed(ctx, peer, &d.users).await,
        None => false,
    };
    Roles {
        admin,
        approver,
        user,
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
    // Only `data stage` and `data refresh` take passed descriptors; any
    // other op closes them now.
    if !matches!(
        req.op.as_str(),
        saiife_ipc::msg::OP_BLIND_DATA_STAGE | saiife_ipc::msg::OP_BLIND_DATA_REFRESH
    ) {
        drop(conn.take_fds());
    }
    let data = match req.op.as_str() {
        saiife_ipc::msg::OP_BLIND_DATA_STAGE => {
            Some(super::data::stage(ctx, conn, &req.args).await)
        }
        saiife_ipc::msg::OP_BLIND_DATA_COMMIT => {
            Some(super::data::commit(ctx, &conn.peer, &req.args).await)
        }
        saiife_ipc::msg::OP_BLIND_DATA_REFRESH => {
            Some(super::data::refresh(ctx, conn, &req.args).await)
        }
        saiife_ipc::msg::OP_BLIND_DATA_RM => {
            Some(super::data::rm(ctx, &conn.peer, &req.args).await)
        }
        _ => None,
    };
    match data {
        Some(Ok(Value::Object(m))) => return saiife_ipc::msg::ok(req.id, m),
        Some(Ok(_)) => {
            return Refusal::new(ErrorCode::Unavailable, "internal: not an object").to_value(req.id)
        }
        Some(Err(r)) => return r.to_value(req.id),
        None => {}
    }
    let r = match req.op.as_str() {
        saiife_ipc::msg::OP_BLIND_STATUS | saiife_ipc::msg::OP_BLIND_METHODS_LIST => {
            not_yet(&req.op)
        }
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
fay:x:1006:1006::/home/fay:/bin/sh
gil:x:1007:1007::/home/gil:/bin/sh
";
    const GROUP: &str = "\
ops:x:2000:dan
sec:x:2001:eve,fay
qa:x:2002:gil
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

    async fn roles_of(c: &Ctx, uids: &[u32]) -> Vec<Roles> {
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

    /// (admin, approver, user).
    fn r(admin: bool, approver: bool, user: bool) -> Roles {
        Roles {
            admin,
            approver,
            user,
        }
    }

    #[tokio::test]
    async fn roles() {
        let t = tempfile::tempdir().unwrap();
        let all = [0, 1001, 1002, 1003, 1004, 1005, 1006, 1007];
        // Locked, the dataset's own approvers.
        let c = ctx(
            t.path(),
            Mode::Locked,
            999,
            &format!(
                "{BASE}{}",
                dataset(
                    "\"ann\", \"group:ops\", \"fay\", \"bob\"",
                    "\"bob\", \"group:qa\""
                )
            ),
        );
        let got = roles_of(&c, &all).await;
        assert_eq!(
            got,
            [
                r(true, false, false),  // root, unlisted
                r(false, false, true),  // ann, in users
                r(false, true, true),   // bob, in users and the dataset's approver
                r(false, false, false), // cat: [approval] counts only when the dataset names none
                r(false, false, true),  // dan, through group:ops
                r(true, false, false),  // eve, an [admin] group, unlisted
                r(true, false, true),   // fay, an [admin] group and in users
                r(false, true, false),  // gil, through group:qa in approvers
            ]
        );
        let may: Vec<(bool, bool)> = got.iter().map(|x| (x.may_manage(), x.may_ask())).collect();
        assert_eq!(
            may,
            [
                (true, false), // unlisted root manages, does not ask (R47-3, P47-13)
                (false, true),
                (true, true),
                (false, false),
                (false, true),
                (true, false), // unlisted admin group member: the same
                (true, true),  // a listed admin does both
                (true, true),  // an approver asks too
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
            [
                r(false, false, true),
                r(false, false, false),
                r(false, true, false)
            ]
        );
        // No dataset in policy: admins and `[approval] approvers`.
        assert_eq!(role(&c, &peer(1003), None).await, r(false, true, false));
        assert_eq!(role(&c, &peer(1001), None).await, Roles::default());
        assert_eq!(role(&c, &peer(0), None).await, r(true, false, false));
        // Personal: the own user is all of them; nobody else is anything.
        let t3 = tempfile::tempdir().unwrap();
        let c = ctx(
            t3.path(),
            Mode::Personal,
            1001,
            &format!("{BASE}{}", dataset("\"bob\"", "\"bob\"")),
        );
        assert_eq!(
            roles_of(&c, &[1001, 1002, 0]).await,
            [r(true, true, true), Roles::default(), Roles::default()]
        );
        let own = role(&c, &peer(1001), None).await;
        assert!(own.may_manage() && own.may_ask());
        assert!(!Roles::default().may_ask() && !Roles::default().may_manage());
    }
}
