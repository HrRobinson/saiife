//! The control-socket ops (spec §8.7) and the state they share.

use crate::disk;
use crate::limits::Limits;
use crate::writer::WriterHandle;
use saiife_audit::{DecisionKind, NewRecord, Record};
use saiife_ipc::msg::{
    err, ok, ErrorCode, Request, OP_AUDIT_APPEND, OP_AUDIT_ROTATE_KEY, OP_HELLO, OP_STATUS, PROTO,
};
use saiife_ipc::peer::{comm, PeerCred};
use saiife_policy::{
    active_packs, effective_policy, policy_hash, Directory, LoadedPolicy, PackInfo,
};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const MODE: &str = "locked";

/// How long a user or group lookup is trusted.
const LOOKUP_TTL: Duration = Duration::from_secs(60);
/// At most one `rate_limited` / `low_disk` record per uid per this.
const NOTICE_EVERY: Duration = Duration::from_secs(60);

/// The policy in force.
#[derive(Debug, Clone)]
pub struct PolicyState {
    /// `None` while no valid policy was ever loaded.
    pub hash: Option<String>,
    pub ok: bool,
    pub min_free_mb: u64,
    pub admin_groups: Vec<String>,
}

impl PolicyState {
    pub fn from_loaded(l: &LoadedPolicy, catalog: &[PackInfo]) -> PolicyState {
        let (packs, _) = active_packs(&l.config, catalog, None);
        PolicyState {
            hash: Some(policy_hash(&effective_policy(&l.config, &packs, None))),
            ok: true,
            min_free_mb: l.config.audit.min_free_mb,
            admin_groups: l.config.admin.groups.clone(),
        }
    }
}

type Cache<K, V> = Mutex<HashMap<K, (Instant, V)>>;

/// What every connection shares.
pub struct Ctx {
    pub writer: WriterHandle,
    pub limits: Limits,
    pub directory: Arc<dyn Directory + Send + Sync>,
    pub own_uid: u32,
    pub own_user: String,
    pub audit_dir: PathBuf,
    pub key_path: PathBuf,
    pub config_path: PathBuf,
    pub catalog: Vec<PackInfo>,
    pub started: Instant,
    pub policy: Mutex<PolicyState>,
    names: Cache<u32, Option<String>>,
    groups: Cache<String, Vec<String>>,
    notices: Mutex<HashMap<(u32, &'static str), Instant>>,
}

pub struct CtxInit {
    pub writer: WriterHandle,
    pub directory: Arc<dyn Directory + Send + Sync>,
    pub own_uid: u32,
    pub own_user: String,
    pub audit_dir: PathBuf,
    pub key_path: PathBuf,
    pub config_path: PathBuf,
    pub catalog: Vec<PackInfo>,
    pub policy: PolicyState,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Ctx {
    pub fn new(i: CtxInit) -> Ctx {
        Ctx {
            writer: i.writer,
            limits: Limits::new(),
            directory: i.directory,
            own_uid: i.own_uid,
            own_user: i.own_user,
            audit_dir: i.audit_dir,
            key_path: i.key_path,
            config_path: i.config_path,
            catalog: i.catalog,
            started: Instant::now(),
            policy: Mutex::new(i.policy),
            names: Mutex::new(HashMap::new()),
            groups: Mutex::new(HashMap::new()),
            notices: Mutex::new(HashMap::new()),
        }
    }

    pub fn policy(&self) -> PolicyState {
        lock(&self.policy).clone()
    }

    /// A record the daemon writes about itself: `tool` = kind, `input` =
    /// a short summary, its own uid and user, the current policy hash.
    pub fn record(&self, kind: &str, input: &str) -> Record {
        let hash = self.policy().hash;
        let mut r = Record::new(
            NewRecord {
                agent: "",
                project: "",
                session: None,
                tool: kind,
                input,
                decision: DecisionKind::Allow,
                pack: None,
                rule: None,
                reason: None,
                mode: MODE,
                policy: hash.as_deref(),
                permission_mode: None,
            },
            VERSION,
        );
        r.kind = Some(kind.to_string());
        r.uid = Some(self.own_uid);
        r.user = Some(self.own_user.clone());
        r
    }

    /// A `daemon` record with `event`.
    pub fn event(&self, event: &str) -> Record {
        let mut r = self.record("daemon", event);
        r.extra.insert("event".into(), event.into());
        r
    }

    /// `name_of(uid)`, cached per uid: a name for good, a miss for 60 s.
    pub async fn name_of(&self, uid: u32) -> Option<String> {
        if uid == self.own_uid {
            return Some(self.own_user.clone());
        }
        if let Some((at, v)) = lock(&self.names).get(&uid) {
            if v.is_some() || at.elapsed() < LOOKUP_TTL {
                return v.clone();
            }
        }
        let dir = Arc::clone(&self.directory);
        let v = tokio::task::spawn_blocking(move || dir.name_of(uid))
            .await
            .ok()
            .flatten();
        lock(&self.names).insert(uid, (Instant::now(), v.clone()));
        v
    }

    /// The user's groups, cached for at most 60 s. A failed lookup is an
    /// empty list (so: not an admin).
    async fn groups_of(&self, user: &str) -> Vec<String> {
        if let Some((at, v)) = lock(&self.groups).get(user) {
            if at.elapsed() < LOOKUP_TTL {
                return v.clone();
            }
        }
        let dir = Arc::clone(&self.directory);
        let name = user.to_string();
        let v = tokio::task::spawn_blocking(move || dir.groups_of(&name))
            .await
            .unwrap_or_default();
        lock(&self.groups).insert(user.to_string(), (Instant::now(), v.clone()));
        v
    }

    /// uid 0, or a member of an `[admin] groups` group. Any lookup failure
    /// denies.
    pub async fn is_admin(&self, uid: u32) -> bool {
        if uid == 0 {
            return true;
        }
        let admin = self.policy().admin_groups;
        if admin.is_empty() {
            return false;
        }
        let Some(name) = self.name_of(uid).await else {
            return false;
        };
        self.groups_of(&name)
            .await
            .iter()
            .any(|g| admin.iter().any(|a| a == g))
    }

    /// Write a `rate_limited` / `low_disk` record for `uid`, at most once
    /// per uid per minute, without waiting for it.
    pub fn notice(self: &Arc<Self>, uid: u32, event: &'static str) {
        if !notice_due(&mut lock(&self.notices), uid, event, Instant::now()) {
            return;
        }
        let mut r = self.event(event);
        r.reason = Some(match event {
            "rate_limited" => {
                format!("uid {uid} is over its request limits (64 in flight, 1000/s)")
            }
            _ => format!("uid {uid}: audit volume below [audit] min_free_mb"),
        });
        let ctx = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(e) = ctx.writer.append(r).await {
                eprintln!("saiifed: warning: cannot write {event} record: {e}");
            }
        });
    }
}

/// Whether a `rate_limited` / `low_disk` record for `uid` is due at `now`
/// (none in the last minute); records `now` when it is.
fn notice_due(
    last: &mut HashMap<(u32, &'static str), Instant>,
    uid: u32,
    event: &'static str,
    now: Instant,
) -> bool {
    if last
        .get(&(uid, event))
        .is_some_and(|at| now.saturating_duration_since(*at) < NOTICE_EVERY)
    {
        return false;
    }
    last.insert((uid, event), now);
    true
}

pub fn hello(id: u64) -> Value {
    let mut m = Map::new();
    m.insert("proto".into(), PROTO.into());
    m.insert("daemon".into(), VERSION.into());
    m.insert("mode".into(), MODE.into());
    ok(id, m)
}

/// Every op but `hello` (which the connection handles itself).
pub async fn dispatch(ctx: &Arc<Ctx>, peer: &PeerCred, req: Request) -> Value {
    match req.op.as_str() {
        OP_HELLO => hello(req.id),
        OP_AUDIT_APPEND => append(ctx, peer, req).await,
        OP_STATUS => status(ctx, req.id),
        OP_AUDIT_ROTATE_KEY => rotate_key(ctx, peer, req.id).await,
        other => err(
            req.id,
            ErrorCode::UnknownOp,
            &format!("unknown op {other:?}"),
        ),
    }
}

async fn append(ctx: &Arc<Ctx>, peer: &PeerCred, req: Request) -> Value {
    let id = req.id;
    let forbidden = |m: &str| err(id, ErrorCode::Forbidden, m);
    let Some(raw) = req.args.get("rec") else {
        return forbidden("audit.append takes a guard record in rec");
    };
    let Ok(mut rec) = serde_json::from_value::<Record>(raw.clone()) else {
        return forbidden("rec is not an audit record");
    };
    if rec.kind() != "guard" {
        return forbidden("audit.append takes only kind \"guard\"");
    }
    let min_free = ctx.policy().min_free_mb;
    let gate = match disk::free_mb(&ctx.audit_dir) {
        Ok(mb) => disk::disk_gate(mb, min_free, peer.uid, ctx.own_uid),
        // Fail closed: an unknown free space counts as too little.
        Err(_) => disk::disk_gate(0, min_free, peer.uid, ctx.own_uid),
    };
    if let Err(code) = gate {
        ctx.notice(peer.uid, "low_disk");
        return err(id, code, "the audit volume is below [audit] min_free_mb");
    }
    rec.v = saiife_audit::record::RECORD_VERSION;
    rec.kind = Some("guard".into());
    rec.mode = Some(MODE.into());
    rec.uid = Some(peer.uid);
    rec.user = ctx.name_of(peer.uid).await;
    rec.seq = None;
    rec.prev = None;
    rec.host = None;
    rec.extra.insert(
        "peer".into(),
        json!({"pid": peer.pid, "comm": comm(peer.pid)}),
    );
    match ctx.writer.append(rec).await {
        Ok(seq) => {
            let mut m = Map::new();
            m.insert("seq".into(), seq.into());
            ok(id, m)
        }
        Err(e) => err(id, ErrorCode::Internal, &e),
    }
}

fn status(ctx: &Ctx, id: u64) -> Value {
    let snap = ctx.writer.snapshot();
    let p = ctx.policy();
    let mut m = Map::new();
    m.insert("mode".into(), MODE.into());
    m.insert("daemon".into(), VERSION.into());
    m.insert("chain".into(), json!(snap.chain));
    m.insert("head_seq".into(), json!(snap.head.as_ref().map(|h| h.0)));
    m.insert("head".into(), json!(snap.head.as_ref().map(|h| &h.1)));
    m.insert(
        "last_checkpoint_seq".into(),
        json!(snap.last_checkpoint_seq),
    );
    m.insert("policy".into(), json!(p.hash));
    m.insert("policy_ok".into(), p.ok.into());
    m.insert("uptime_s".into(), ctx.started.elapsed().as_secs().into());
    ok(id, m)
}

async fn rotate_key(ctx: &Arc<Ctx>, peer: &PeerCred, id: u64) -> Value {
    if !ctx.is_admin(peer.uid).await {
        return err(
            id,
            ErrorCode::Forbidden,
            "audit.rotate_key is for root and [admin] groups",
        );
    }
    match ctx.writer.rotate_key(ctx.key_path.clone()).await {
        Ok((seq, key)) => {
            let mut m = Map::new();
            m.insert("seq".into(), seq.into());
            m.insert("key".into(), key.into());
            ok(id, m)
        }
        Err(e) => err(id, ErrorCode::Internal, &e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notices_at_most_once_per_uid_and_event_per_minute() {
        let mut m = HashMap::new();
        let t0 = Instant::now();
        assert!(notice_due(&mut m, 1000, "rate_limited", t0));
        assert!(!notice_due(
            &mut m,
            1000,
            "rate_limited",
            t0 + Duration::from_secs(59)
        ));
        // Another uid, or another event, has its own minute.
        assert!(notice_due(&mut m, 1001, "rate_limited", t0));
        assert!(notice_due(&mut m, 1000, "low_disk", t0));
        assert!(notice_due(
            &mut m,
            1000,
            "rate_limited",
            t0 + Duration::from_secs(60)
        ));
        assert!(!notice_due(
            &mut m,
            1000,
            "rate_limited",
            t0 + Duration::from_secs(61)
        ));
    }
}
