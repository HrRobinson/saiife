//! The `blind.*` ops (plan 47). Control socket, machine local only: stage 1
//! has no remote surface (R47-3). Tasks 2 to 6 and plan 48 fill in the ops;
//! until then each answers [`not_yet`].

use super::keys::KeyError;
use super::ner::NerState;
use super::{DatasetState, Refusal};
use crate::ops::{Conn, Ctx, Mode};
use saiife_ipc::msg::{ErrorCode, Request};
use saiife_ipc::peer::PeerCred;
use saiife_policy::blind::BlindDataset;
use saiife_shield::dataset::{snapshot_index_columns, MANIFEST_VERSION};
use saiife_shield::methods::{MethodStatus, MethodStore};
use saiife_shield::schema::DatasetName;
use saiife_system::sandbox::{Strength, CALC_LABEL};
use serde_json::json;
use serde_json::Value;
use std::collections::BTreeSet;
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

/// The peer's roles from explicit lists, with no `[approval]` fallback: a
/// dataset whose policy entry is gone keeps the users and approvers it was
/// last built with (fail closed: with empty lists only an admin manages).
/// The personal broker's own user is all three, as in [`role`].
pub(crate) async fn role_listed(
    ctx: &Ctx,
    peer: &PeerCred,
    users: &[String],
    approvers: &[String],
) -> Roles {
    if ctx.mode == Mode::Personal {
        let own = ctx.peer_is_own(peer);
        return Roles {
            admin: own,
            approver: own,
            user: own,
        };
    }
    Roles {
        admin: ctx.peer_is_admin(peer).await,
        approver: crate::approval_ops::peer_listed(ctx, peer, approvers).await,
        user: crate::approval_ops::peer_listed(ctx, peer, users).await,
    }
}

/// The approvers `role` counts for `ds`: its own, or `[approval]
/// approvers` when it names none.
pub(crate) fn effective_approvers(ctx: &Ctx, ds: &BlindDataset) -> Vec<String> {
    if !ds.approvers.is_empty() {
        return ds.approvers.clone();
    }
    match ctx.policy().system {
        Some(s) => s.approval.approvers.clone(),
        None => Vec::new(),
    }
}

/// What an op answers until its task builds it.
pub fn not_yet(op: &str) -> Refusal {
    Refusal::new(
        ErrorCode::Unavailable,
        format!("{op} is not available in this build yet"),
    )
}

fn reply(id: u64, r: Result<Value, Refusal>) -> Value {
    match r {
        Ok(Value::Object(m)) => saiife_ipc::msg::ok(id, m),
        Ok(_) => Refusal::new(ErrorCode::Unavailable, "internal: not an object").to_value(id),
        Err(r) => r.to_value(id),
    }
}

// ----------------------------------------------------------- status ----

/// The datasets the peer has a role on: in policy, or kept on disk with
/// the users and approvers they were last built with (S3).
async fn visible(ctx: &Ctx, peer: &PeerCred) -> Vec<(DatasetName, Roles)> {
    let policy: Vec<BlindDataset> = ctx
        .policy()
        .system
        .map(|s| s.blind.dataset.clone())
        .unwrap_or_default();
    let mut names: BTreeSet<DatasetName> = BTreeSet::new();
    for d in &policy {
        if let Ok(n) = d.name.parse() {
            names.insert(n);
        }
    }
    for n in ctx.blind.state_names() {
        if let Ok(n) = n.parse() {
            names.insert(n);
        }
    }
    let mut out = Vec::new();
    for n in names {
        let r = role_of(ctx, peer, &n).await;
        if r.admin || r.approver || r.user {
            out.push((n, r));
        }
    }
    out
}

/// The peer's roles on `name`: the policy entry, else what the dataset was
/// last built with.
async fn role_of(ctx: &Ctx, peer: &PeerCred, name: &DatasetName) -> Roles {
    let cfg = ctx.policy().system.and_then(|s| {
        s.blind
            .dataset
            .iter()
            .find(|d| d.name == name.as_str())
            .cloned()
    });
    match cfg {
        Some(c) => role(ctx, peer, Some(&c)).await,
        None => {
            let p = ctx
                .blind
                .dataset_dir(name)
                .root
                .join(super::data::ACCESS_FILE);
            let a = super::data::read_small::<super::data::Access>(&p)
                .ok()
                .flatten()
                .unwrap_or_default();
            role_listed(ctx, peer, &a.users, &a.approvers).await
        }
    }
}

/// The calculator's line: the weaker label when it cannot be put in a box.
pub(crate) fn calculator(s: Strength) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("label".into(), CALC_LABEL.into());
    m.insert("landlock".into(), s.as_str().into());
    if let Some(g) = s.gap() {
        m.insert("gap".into(), g.into());
    }
    Value::Object(m)
}

fn ner_json(s: NerState) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("state".into(), s.word().into());
    match s {
        NerState::Ready { labels, .. } => {
            m.insert("labels".into(), json!(labels));
        }
        NerState::Missing(why) | NerState::Failed(why) => {
            m.insert("reason".into(), why.into());
        }
        NerState::NotConfigured => {}
    }
    Value::Object(m)
}

fn role_json(r: Roles) -> Value {
    json!({"admin": r.admin, "approver": r.approver, "user": r.user})
}

fn method_status(s: &MethodStatus) -> Value {
    match s {
        MethodStatus::Active => json!({"state": "active"}),
        MethodStatus::Suspended { reason } => json!({"state": "suspended", "reason": reason}),
    }
}

/// The fixed warning for a build that predates the current floors or
/// indexes.
fn rebuild_warning(name: &DatasetName, why: &str) -> String {
    format!("{name} {why}: saiife blind data refresh --dataset {name}")
}

/// What `status` shows of one dataset; blocking (reads its files).
fn dataset_json(ctx: &Ctx, name: &DatasetName, role: Roles) -> Value {
    let dir = ctx.blind.dataset_dir(name);
    let mut warnings: Vec<String> = Vec::new();
    let mut d = serde_json::Map::new();
    d.insert("name".into(), name.as_str().into());
    let (mut sha, mut built, mut rows) = (Value::Null, Value::Null, json!([]));
    match ctx.blind.state(name) {
        DatasetState::Live { manifest, .. } => {
            d.insert("state".into(), "live".into());
            sha = manifest.snapshot_sha256.clone().into();
            built = manifest.built_at.clone().into();
            rows = manifest
                .rows_bands
                .iter()
                .map(|(t, b)| json!([t, b]))
                .collect();
            warnings.extend(super::data::warnings(ctx, name));
            if manifest.v < MANIFEST_VERSION {
                warnings.push(rebuild_warning(
                    name,
                    "was built when floors counted rows, not people",
                ));
            }
            if lacks_indexes(&dir, &manifest.schema) {
                warnings.push(rebuild_warning(
                    name,
                    "was built without its snapshot indexes",
                ));
            }
        }
        DatasetState::Building {
            phase, done, total, ..
        } => {
            d.insert("state".into(), "refreshing".into());
            d.insert(
                "progress".into(),
                json!({"phase": format!("{phase:?}").to_lowercase(), "done": done, "total": total}),
            );
        }
        DatasetState::Opening => {
            d.insert("state".into(), "opening".into());
            d.insert("reason".into(), super::OPENING.into());
        }
        DatasetState::NeedsRefresh(why) => {
            d.insert("state".into(), "needs_refresh".into());
            d.insert("reason".into(), why.into());
        }
        DatasetState::Absent => {
            d.insert("state".into(), "not_built".into());
        }
    }
    if let Some(e) = ctx.blind.last_build_error(name) {
        warnings.push(format!("the last refresh failed: {e}"));
    }
    d.insert("rows".into(), rows);
    d.insert("snapshot_sha256".into(), sha);
    d.insert("built_at".into(), built);
    // Review Focus 3: a locked vault and damaged keys are told apart; a
    // dataset with no keys (never built) has nothing to warn about.
    let keys_version = match super::keys::load(ctx, name) {
        Ok(k) => Value::from(k.version),
        Err(KeyError::Missing) => Value::Null,
        Err(e) => {
            warnings.push(e.refusal(name).text);
            Value::Null
        }
    };
    d.insert("keys_version".into(), keys_version);
    let (mut active, mut suspended) = (0u32, Vec::new());
    match MethodStore::load(&dir.root.join(super::data::METHODS_FILE)) {
        Ok(s) => {
            for m in &s.methods {
                match &m.status {
                    MethodStatus::Active => active += 1,
                    MethodStatus::Suspended { reason } => {
                        suspended.push(json!({"id": m.id, "reason": reason}));
                    }
                }
            }
        }
        Err(_) => warnings.push(format!("the methods file of {name} cannot be read")),
    }
    d.insert(
        "methods".into(),
        json!({"active": active, "suspended": suspended}),
    );
    d.insert("warnings".into(), json!(warnings));
    d.insert("role".into(), role_json(role));
    Value::Object(d)
}

/// Whether the live snapshot lacks the join indexes the schema wants
/// (built before shield a136ebe8). An unreadable snapshot is not reported
/// here: the open failed already and says so.
fn lacks_indexes(
    dir: &saiife_shield::dataset::DatasetDir,
    schema: &saiife_shield::schema::Schema,
) -> bool {
    let want = snapshot_index_columns(schema).len();
    if want == 0 {
        return false;
    }
    let Ok(c) = saiife_shield::snapshot::open_ro(&dir.snapshot()) else {
        return false;
    };
    let n: Result<i64, _> = c.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' \
         AND name LIKE 'saiife\\_ix:%' ESCAPE '\\'",
        [],
        |r| r.get(0),
    );
    n.is_ok_and(|n| (n as usize) < want)
}

/// `blind.status {}` (R47-3): only the datasets the caller has a role on;
/// admins see all.
async fn status(ctx: &Arc<Ctx>, peer: &PeerCred) -> Result<Value, Refusal> {
    let list = visible(ctx, peer).await;
    let c = Arc::clone(ctx);
    let datasets = tokio::task::spawn_blocking(move || {
        list.into_iter()
            .map(|(n, r)| dataset_json(&c, &n, r))
            .collect::<Vec<_>>()
    })
    .await
    .map_err(|_| Refusal::new(ErrorCode::Internal, "status failed"))?;
    let p = ctx.policy();
    let cloud = p.system.as_ref().and_then(|s| s.blind.cloud.as_ref());
    let model = cloud
        .and_then(|c| c.model.clone())
        .unwrap_or_else(|| saiife_policy::blind::DEFAULT_CLOUD_MODEL.into());
    let secret_present = cloud.is_some_and(|c| super::model::key_present(ctx, &c.secret));
    let yours = super::lock(&ctx.blind.sessions).count_for(peer.uid);
    Ok(json!({
        "datasets": datasets,
        "calculator": calculator(super::calc::strength()),
        "ner": ner_json(ctx.blind.ner.state()),
        "cloud": {"secret_present": secret_present, "model": model},
        "sessions": {"yours": yours},
    }))
}

/// `blind.methods.list {dataset}`: the approved methods' metadata (never
/// their text) to the dataset's users and approvers (R47-3).
async fn methods_list(
    ctx: &Arc<Ctx>,
    peer: &PeerCred,
    args: &serde_json::Map<String, Value>,
) -> Result<Value, Refusal> {
    let name: DatasetName = args
        .get("dataset")
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::new(ErrorCode::BadRequest, "dataset is required"))?
        .parse()
        .map_err(|_| Refusal::new(ErrorCode::BadRequest, "not a dataset name"))?;
    let r = role_of(ctx, peer, &name).await;
    if !r.may_ask() {
        return Err(Refusal::new(
            ErrorCode::Forbidden,
            format!("you have no role on {name}"),
        ));
    }
    let path = ctx
        .blind
        .dataset_dir(&name)
        .root
        .join(super::data::METHODS_FILE);
    let store = tokio::task::spawn_blocking(move || MethodStore::load(&path))
        .await
        .map_err(|_| Refusal::new(ErrorCode::Internal, "methods.list failed"))?
        .map_err(|_| {
            Refusal::new(
                ErrorCode::Unavailable,
                format!("the methods file of {name} cannot be read"),
            )
        })?;
    let methods: Vec<Value> = store
        .methods
        .iter()
        .map(|m| {
            json!({
                "id": m.id,
                "version": m.version,
                "lang": m.lang,
                "template_key": m.template_key,
                "param_tags": m.param_tags,
                "approved_by": m.approved_by,
                "approved_at": m.approved_at,
                "status": method_status(&m.status),
            })
        })
        .collect();
    Ok(json!({"methods": methods}))
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
        saiife_ipc::msg::OP_BLIND_NER_FETCH => Some(super::ner::fetch_op(ctx, &conn.peer).await),
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
        saiife_ipc::msg::OP_BLIND_STATUS => return reply(req.id, status(ctx, &conn.peer).await),
        saiife_ipc::msg::OP_BLIND_METHODS_LIST => {
            return reply(req.id, methods_list(ctx, &conn.peer, &req.args).await)
        }
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

    #[test]
    fn calculator_line_by_strength() {
        assert_eq!(
            calculator(Strength::None),
            json!({"label": CALC_LABEL, "landlock": "none",
                   "gap": "no Landlock: sandboxed servers do not start"})
        );
        let f = calculator(Strength::Filesystem);
        assert!(
            f["label"] == CALC_LABEL && f["landlock"] == "filesystem" && f.get("gap").is_some()
        );
        assert_eq!(
            calculator(Strength::FilesystemAndScopes),
            json!({"label": CALC_LABEL, "landlock": "filesystem+scopes"})
        );
    }
}
