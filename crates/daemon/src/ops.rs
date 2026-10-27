//! The control-socket ops (spec §8.7) and the state they share.

use crate::disk;
use crate::limits::{ConnLimits, Limits};
use crate::sessions::{agent_ancestor, Proc, Sessions};
use crate::vault::VaultState;
use crate::writer::{WriterConfig, WriterHandle};
use saiife_audit::{DecisionKind, NewRecord, Record};
use saiife_broker::limits::Limiter;
use saiife_broker::pipeline::{PolicySnapshot, Pools};
use saiife_broker::upstream::Upstream;
use saiife_broker::Catalog;
use saiife_ipc::msg::{
    err, ok, ErrorCode, Request, OP_API_CALL, OP_API_LIST, OP_API_RESULT, OP_API_TOKEN,
    OP_APPROVAL_CREATE, OP_APPROVAL_DECIDE, OP_APPROVAL_LIST, OP_APPROVAL_SHOW, OP_AUDIT_APPEND,
    OP_AUDIT_ROTATE_KEY, OP_GRANT_CONSUME, OP_HELLO, OP_LOCKDOWN_SET, OP_SECRET_ADD,
    OP_SECRET_LEASE, OP_SECRET_LIST, OP_SECRET_REMOVE, OP_SECRET_ROTATE, OP_STATUS, PROTO,
};
use saiife_ipc::peer::{comm, PeerCred};
use saiife_policy::{
    active_packs, effective_policy, policy_hash, Directory, LoadedPolicy, Mode, PackInfo,
    SystemConfig,
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
/// Largest `rec` `audit.append` takes, serialized: the hook's records are
/// a few KiB; 1 MiB ones at 1 000/s per uid would fill the audit volume
/// for everyone. Shared with the hook, which shrinks its records to fit.
pub use saiife_ipc::msg::MAX_RECORD_BYTES;
/// At most one `rate_limited` / `low_disk` record per uid per this.
const NOTICE_EVERY: Duration = Duration::from_secs(60);

/// The connector side of a valid policy: the snapshot every call takes when
/// it starts, and the connector catalog checked against it.
#[derive(Debug)]
pub struct GatewayPolicy {
    pub snap: PolicySnapshot,
    pub catalog: Catalog,
}

/// The policy in force.
#[derive(Debug, Clone)]
pub struct PolicyState {
    /// `None` while no valid policy was ever loaded.
    pub hash: Option<String>,
    pub ok: bool,
    pub min_free_mb: u64,
    pub admin_groups: Vec<String>,
    /// The merged system config (scopes, `[secrets.*] run_allow`); `None`
    /// while no valid policy was ever loaded.
    pub system: Option<Arc<SystemConfig>>,
    /// `None` while no valid policy was ever loaded (connectors are denied
    /// with `policy_invalid`).
    pub gateway: Option<Arc<GatewayPolicy>>,
}

impl PolicyState {
    /// The state of a loaded policy whose services passed
    /// [`check_services`].
    pub fn from_loaded(l: &LoadedPolicy, catalog: &[PackInfo], connectors: Catalog) -> PolicyState {
        let (packs, _) = active_packs(&l.config, catalog, None);
        let hash = policy_hash(&effective_policy(&l.config, &packs, None));
        PolicyState {
            hash: Some(hash.clone()),
            ok: true,
            min_free_mb: l.config.audit.min_free_mb,
            admin_groups: l.config.admin.groups.clone(),
            system: Some(Arc::new(l.config.clone())),
            gateway: Some(Arc::new(GatewayPolicy {
                snap: PolicySnapshot {
                    config: l.config.clone(),
                    hash,
                    mode: Mode::Locked,
                },
                catalog: connectors,
            })),
        }
    }
}

/// The connector catalog for a loaded policy: the built-in manifests plus
/// the admin's in `<config dir>/connectors` (root-owned), with every
/// `[services.*]` checked against it. An error makes the policy invalid
/// (at a reload: `rejected`, the old policy stays). Warnings go to stderr.
pub fn check_services(l: &LoadedPolicy, config_path: &std::path::Path) -> Result<Catalog, String> {
    let dir = config_path
        .parent()
        .unwrap_or(std::path::Path::new("/"))
        .join("connectors");
    let local = saiife_broker::manifest::load_local(&dir).map_err(|e| e.to_string())?;
    let cat = Catalog::new(saiife_broker::builtin(), local);
    let warnings = saiife_broker::catalog::validate(&l.config, &cat).map_err(|e| e.to_string())?;
    for w in warnings {
        eprintln!("saiife: warning: {w}");
    }
    Ok(cat)
}

type Cache<K, V> = Mutex<HashMap<K, (Instant, V)>>;

/// What every connection shares.
pub struct Ctx {
    pub writer: WriterHandle,
    /// The writer settings in force since start (a reload cannot change
    /// them).
    pub writer_cfg: WriterConfig,
    pub limits: Limits,
    pub conns: ConnLimits,
    pub directory: Arc<dyn Directory + Send + Sync>,
    pub own_uid: u32,
    pub own_user: String,
    pub audit_dir: PathBuf,
    pub socket_dir: PathBuf,
    pub key_path: PathBuf,
    pub config_path: PathBuf,
    pub catalog: Vec<PackInfo>,
    pub started: Instant,
    pub policy: Mutex<PolicyState>,
    /// Agent process -> session, for attributing connector requests.
    pub sessions: Sessions,
    pub proc: Box<dyn Proc + Send + Sync>,
    /// The credential vault (plan 10); `Unavailable` keeps the daemon up.
    pub vault: crate::vault::Shared,
    /// Where `vault.bin` lives (named in the `VaultUnavailable` message).
    pub vault_path: PathBuf,
    /// Connector limits, rebuilt at start from the last 24 h of records.
    pub limiter: Limiter,
    /// The upstream client (the native roots plus `<config dir>/ca`), or
    /// why it could not be built.
    pub upstream: Result<Upstream, String>,
    /// At most 4 upstream calls in flight per service.
    pub pools: Pools,
    /// Where `secret.add` keeps the backups of imported files.
    pub backup_dir: PathBuf,
    /// Bearer tokens of the loopback TCP listener (`api.token`).
    pub tokens: Arc<crate::tokens::Tokens>,
    /// The lockdown flag (spec §6.18).
    pub lockdown: crate::lockdown::Store,
    /// The `[gateway] tcp` the daemon started with, and what it bound.
    pub tcp: Mutex<TcpState>,
    /// Connector calls in flight; a stop waits for them (bounded) before
    /// the stop record.
    pub calls: InFlight,
    /// Notifications (webhook, SMTP, command); started by `serve`.
    pub notifier: crate::notifier::Notifier,
    /// The approval request store (`<state>/approvals/`), or why it could
    /// not be opened: then every `ask` is denied (fail closed).
    pub approvals: Result<crate::approvals::Store, String>,
    /// Same-user re-authentication for approvals (polkit `pkcheck`; tests
    /// replace it before the context is shared).
    pub reauth: Arc<dyn crate::reauth::Reauth>,
    /// One-use command grants (`[guard] ask`, spec §6.10.4).
    pub grants: crate::grants::Grants,
    names: Cache<u32, Option<String>>,
    groups: Cache<String, Vec<String>>,
    notices: Mutex<HashMap<(u32, Notice), Instant>>,
}

pub struct CtxInit {
    pub writer: WriterHandle,
    pub writer_cfg: WriterConfig,
    pub directory: Arc<dyn Directory + Send + Sync>,
    pub own_uid: u32,
    pub own_user: String,
    pub audit_dir: PathBuf,
    pub socket_dir: PathBuf,
    pub key_path: PathBuf,
    pub config_path: PathBuf,
    pub catalog: Vec<PackInfo>,
    pub policy: PolicyState,
    pub proc: Box<dyn Proc + Send + Sync>,
    pub vault: VaultState,
    pub vault_path: PathBuf,
    pub limiter: Limiter,
    pub upstream: Result<Upstream, String>,
    pub backup_dir: PathBuf,
    pub tokens: Arc<crate::tokens::Tokens>,
    pub approvals: Result<crate::approvals::Store, String>,
    /// The lockdown flag (spec §6.18).
    pub lockdown: crate::lockdown::Store,
    /// One-use command grants (`<state>/state/grants.json`).
    pub grants: crate::grants::Grants,
}

/// A count of work in flight that a stop waits for.
#[derive(Default)]
pub struct InFlight {
    count: std::sync::atomic::AtomicUsize,
    idle: tokio::sync::Notify,
}

/// One unit of [`InFlight`] work, until dropped.
pub struct Busy<'a>(&'a InFlight);

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        if self
            .0
            .count
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel)
            == 1
        {
            self.0.idle.notify_waiters();
        }
    }
}

impl InFlight {
    pub fn enter(&self) -> Busy<'_> {
        self.count.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Busy(self)
    }

    pub fn count(&self) -> usize {
        self.count.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Wait until nothing is in flight, at most `limit`; `true` when idle.
    pub async fn wait_idle(&self, limit: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            let idle = self.idle.notified();
            tokio::pin!(idle);
            // Registered before the check: a drop in between still wakes us.
            idle.as_mut().enable();
            if self.count() == 0 {
                return true;
            }
            if tokio::time::timeout_at(deadline, idle).await.is_err() {
                return self.count() == 0;
            }
        }
    }
}

/// The optional loopback TCP listener of the gateway.
#[derive(Debug, Clone, Default)]
pub struct TcpState {
    /// `[gateway] tcp` at start (a reload cannot change it).
    pub configured: String,
    /// The address bound (the real port when `:0` was asked for).
    pub bound: Option<std::net::SocketAddr>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Ctx {
    pub fn new(i: CtxInit) -> Ctx {
        Ctx {
            writer: i.writer,
            writer_cfg: i.writer_cfg,
            limits: Limits::new(),
            conns: ConnLimits::from_rlimit(),
            directory: i.directory,
            own_uid: i.own_uid,
            own_user: i.own_user,
            audit_dir: i.audit_dir,
            socket_dir: i.socket_dir,
            key_path: i.key_path,
            config_path: i.config_path,
            catalog: i.catalog,
            started: Instant::now(),
            policy: Mutex::new(i.policy),
            sessions: Sessions::new(),
            proc: i.proc,
            vault: crate::vault::Shared::new(i.vault),
            vault_path: i.vault_path,
            limiter: i.limiter,
            upstream: i.upstream,
            pools: Pools::new(),
            backup_dir: i.backup_dir,
            tokens: i.tokens,
            lockdown: i.lockdown,
            tcp: Mutex::new(TcpState::default()),
            calls: InFlight::default(),
            notifier: crate::notifier::Notifier::new(),
            approvals: i.approvals,
            reauth: Arc::new(crate::reauth::PkCheck::new()),
            grants: i.grants,
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

    /// An `approval` record of `action` for request `r` (§6.10.1): the
    /// requester, the id (`id` and `approval`) and the masked summary.
    pub fn approval_record(&self, r: &crate::approvals::Request, action: &str) -> Record {
        let base = self.record("approval", &crate::approvals::summary(r));
        crate::approvals::record_for(base, r, action)
    }

    /// Write an `approval`/`expired` record for each request a sweep (or
    /// a late decision) expired. A failed write is one stderr line.
    pub async fn record_expired(&self, reqs: Vec<crate::approvals::Request>) {
        for r in reqs {
            if let Err(e) = self
                .writer
                .append(self.approval_record(&r, "expired"))
                .await
            {
                eprintln!(
                    "saiife: warning: cannot record the expiry of approval #{}: {e}",
                    r.id
                );
            }
        }
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
    pub(crate) async fn groups_of(&self, user: &str) -> Vec<String> {
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

    /// Write the record of notice `n` for `uid`, at most once per uid and
    /// notice per minute, without waiting for it.
    pub fn notice(&self, uid: u32, n: Notice) {
        if !notice_due(&mut lock(&self.notices), uid, n, Instant::now()) {
            return;
        }
        let event = n.event();
        let mut r = self.event(event);
        r.reason = Some(n.reason(uid));
        let writer = self.writer.clone();
        tokio::spawn(async move {
            if let Err(e) = writer.append(r).await {
                eprintln!("saiifed: warning: cannot write {event} record: {e}");
            }
        });
    }
}

/// Why a uid was refused, for its `rate_limited` / `low_disk` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Notice {
    /// Over the in-flight or per-second request limit.
    Requests,
    /// Over the open-connection cap (per uid or the daemon's total).
    Connections,
    /// The audit volume is below `[audit] min_free_mb`.
    LowDisk,
    /// The HTTP gateway refused a request before the pipeline (no
    /// `connector` record is written for it).
    Gateway(GatewayRefusal),
}

/// Why the HTTP gateway refused a request before the pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GatewayRefusal {
    /// 400 (or 408): a request that cannot be read as a call.
    BadRequest,
    /// 413: a body over 1 MiB.
    TooLarge,
    /// 401: no valid bearer token on the TCP listener.
    Token,
    /// 403: a browser-like request on the TCP listener.
    Origin,
    /// 405: the wrong method for the route.
    Method,
}

/// The uid of a [`Notice`] about a TCP client that showed no valid token.
pub const UNKNOWN_UID: u32 = u32::MAX;

impl Notice {
    /// The record's `event`.
    pub fn event(self) -> &'static str {
        match self {
            Notice::Requests | Notice::Connections => "rate_limited",
            Notice::LowDisk => "low_disk",
            Notice::Gateway(_) => "gateway_refused",
        }
    }

    /// The record's `reason`.
    pub fn reason(self, uid: u32) -> String {
        match self {
            Notice::Requests => {
                format!("uid {uid} is over its request limits (64 in flight, 1000/s)")
            }
            Notice::Connections => format!(
                "uid {uid} is over its connection limits (32 open per uid, or the daemon's total)"
            ),
            Notice::LowDisk => format!("uid {uid}: audit volume below [audit] min_free_mb"),
            Notice::Gateway(r) => {
                let who = if uid == UNKNOWN_UID {
                    "a TCP client without a valid token".to_string()
                } else {
                    format!("uid {uid}")
                };
                let what = match r {
                    GatewayRefusal::BadRequest => "a request that could not be read (400)",
                    GatewayRefusal::TooLarge => "a request body over 1 MiB (413)",
                    GatewayRefusal::Token => "a missing, expired or unknown token (401)",
                    GatewayRefusal::Origin => "a browser-like request (403 origin)",
                    GatewayRefusal::Method => "a method the route does not take (405)",
                };
                format!("the HTTP gateway refused {what} from {who}; at most one record a minute")
            }
        }
    }
}

/// Whether notice `n` for `uid` is due at `now` (none in the last minute);
/// records `now` when it is.
fn notice_due(
    last: &mut HashMap<(u32, Notice), Instant>,
    uid: u32,
    n: Notice,
    now: Instant,
) -> bool {
    if last
        .get(&(uid, n))
        .is_some_and(|at| now.saturating_duration_since(*at) < NOTICE_EVERY)
    {
        return false;
    }
    last.insert((uid, n), now);
    true
}

/// Now, in the record format: UTC, `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub fn now_ts() -> String {
    const F: &[time::format_description::FormatItem<'static>] = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
    );
    time::OffsetDateTime::now_utc()
        .format(F)
        .unwrap_or_default()
}

pub fn hello(id: u64) -> Value {
    let mut m = Map::new();
    m.insert("proto".into(), PROTO.into());
    m.insert("daemon".into(), VERSION.into());
    m.insert("mode".into(), MODE.into());
    ok(id, m)
}

/// A control connection's caller: its peer credentials, and the peer
/// process's start time read when the connection was accepted (for the
/// re-authentication of a same-user approval; `None` when unknown, which
/// refuses that).
#[derive(Debug, Clone, Copy)]
pub struct Conn {
    pub peer: PeerCred,
    pub start_time: Option<u64>,
}

/// Every op but `hello` (which the connection handles itself), for a
/// caller whose process start time is not known.
pub async fn dispatch(ctx: &Arc<Ctx>, peer: &PeerCred, req: Request) -> Value {
    dispatch_conn(
        ctx,
        &Conn {
            peer: *peer,
            start_time: None,
        },
        req,
    )
    .await
}

/// Every op but `hello`.
pub async fn dispatch_conn(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value {
    let peer = &conn.peer;
    match req.op.as_str() {
        OP_APPROVAL_LIST | OP_APPROVAL_SHOW | OP_APPROVAL_DECIDE | OP_APPROVAL_CREATE
        | OP_GRANT_CONSUME => crate::approval_ops::handle(ctx, conn, req).await,
        OP_HELLO => hello(req.id),
        OP_AUDIT_APPEND => append(ctx, peer, req).await,
        OP_STATUS => status(ctx, req.id),
        OP_AUDIT_ROTATE_KEY => rotate_key(ctx, peer, req.id).await,
        OP_SECRET_LEASE => crate::secret_ops::lease(ctx, peer, req).await,
        OP_SECRET_ADD | OP_SECRET_ROTATE | OP_SECRET_REMOVE | OP_SECRET_LIST => {
            crate::secret_ops::handle(ctx, peer, req).await
        }
        OP_API_CALL | OP_API_LIST | OP_API_RESULT => crate::api_ops::handle(ctx, peer, req).await,
        OP_API_TOKEN => crate::api_ops::token(ctx, peer.uid, req.id).await,
        OP_LOCKDOWN_SET => crate::lockdown::set(ctx, peer, req).await,
        other => err(
            req.id,
            ErrorCode::UnknownOp,
            &format!("unknown op {other:?}"),
        ),
    }
}

/// A client-supplied session id over the cap is not remembered (the
/// record is still accepted).
fn storable_session(s: Option<&str>) -> Option<String> {
    s.filter(|s| s.len() <= crate::sessions::MAX_SESSION_ID)
        .map(str::to_string)
}

async fn append(ctx: &Arc<Ctx>, peer: &PeerCred, req: Request) -> Value {
    let id = req.id;
    let forbidden = |m: &str| err(id, ErrorCode::Forbidden, m);
    let Some(raw) = req.args.get("rec").and_then(Value::as_object) else {
        return err(
            id,
            ErrorCode::BadRequest,
            "audit.append takes a record object in rec",
        );
    };
    if !matches!(serde_json::to_vec(raw), Ok(b) if b.len() <= MAX_RECORD_BYTES) {
        return err(
            id,
            ErrorCode::BadRequest,
            &format!("rec is larger than {MAX_RECORD_BYTES} bytes"),
        );
    }
    if raw
        .get("kind")
        .is_some_and(|k| !k.is_null() && k.as_str() != Some("guard"))
    {
        return forbidden("audit.append takes only kind \"guard\"");
    }
    let mut raw = raw.clone();
    // The daemon stamps the time: a client's far-future or backdated `ts`
    // would move later records to another month file or falsify the
    // timeline. The client's value is kept, bounded, as `client_ts`.
    let client_ts = raw.remove("ts").map(|v| match v {
        Value::String(s) => s,
        other => other.to_string(),
    });
    raw.insert("ts".into(), now_ts().into());
    let mut rec = match serde_json::from_value::<Record>(Value::Object(raw)) {
        Ok(r) => r,
        Err(e) => return err(id, ErrorCode::BadRequest, &format!("rec: {e}")),
    };
    if rec.kind() != "guard" {
        return forbidden("audit.append takes only kind \"guard\"");
    }
    if let Some(t) = client_ts {
        rec.extra.insert(
            "client_ts".into(),
            t.chars().take(32).collect::<String>().into(),
        );
    }
    let min_free = ctx.policy().min_free_mb;
    let gate = match disk::free_mb(&ctx.audit_dir) {
        Ok(mb) => disk::disk_gate(mb, min_free, peer.uid, ctx.own_uid),
        // Fail closed: an unknown free space counts as too little.
        Err(_) => disk::disk_gate(0, min_free, peer.uid, ctx.own_uid),
    };
    if let Err(code) = gate {
        ctx.notice(peer.uid, Notice::LowDisk);
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
    let session = storable_session(rec.session.as_deref());
    // Decision 8: with lockdown `all` the guard record is still written,
    // but as a deny (`rule = lockdown`), and the hook gets `lockdown`.
    let locked = ctx
        .lockdown
        .get()
        .filter(|l| l.scope == saiife_broker::pipeline::LockScope::All)
        .map(|l| format!("saiife lockdown is on: {}", l.reason));
    if locked.is_some() {
        // Keep the verdict the guard reached: `would_have`. A call the
        // guard denied anyway keeps its decision and reason; the rule
        // becomes `lockdown` (`lockdown = true` marks that).
        rec.extra.insert(
            "would_have".into(),
            json!({"decision": rec.decision, "pack": rec.pack, "rule": rec.rule}),
        );
        if matches!(rec.decision, DecisionKind::Deny | DecisionKind::ErrorDenied) {
            rec.extra.insert("lockdown".into(), true.into());
        } else {
            rec.decision = DecisionKind::Deny;
            rec.reason = locked.clone();
        }
        rec.rule = Some("lockdown".into());
    }
    match ctx.writer.append(rec).await {
        Ok(_) if locked.is_some() => err(id, ErrorCode::Lockdown, &locked.unwrap_or_default()),
        Ok(seq) => {
            if let Some(sid) = session {
                if let Some(a) = agent_ancestor(ctx.proc.as_ref(), peer.pid) {
                    ctx.sessions.record(a, &sid);
                }
            }
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
    // The loopback TCP listener's address, `null` when there is none.
    let tcp = lock(&ctx.tcp).bound;
    m.insert("gateway_tcp".into(), json!(tcp.map(|a| a.to_string())));
    m.insert(
        "lockdown".into(),
        crate::lockdown::status_json(ctx.lockdown.get().as_ref()),
    );
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

    #[tokio::test]
    async fn stop_waits_for_calls_in_flight() {
        let f = Arc::new(InFlight::default());
        assert!(f.wait_idle(Duration::from_millis(10)).await);
        let f2 = Arc::clone(&f);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let call = tokio::spawn(async move {
            let _busy = f2.enter();
            let _ = rx.await;
        });
        tokio::task::yield_now().await;
        assert_eq!(f.count(), 1);
        // Bounded: still busy after the limit.
        assert!(!f.wait_idle(Duration::from_millis(50)).await);
        // Woken as soon as the last call ends.
        let waiter = {
            let f = Arc::clone(&f);
            tokio::spawn(async move { f.wait_idle(Duration::from_secs(10)).await })
        };
        tokio::task::yield_now().await;
        tx.send(()).unwrap();
        call.await.unwrap();
        assert!(waiter.await.unwrap());
        assert_eq!(f.count(), 0);
    }

    #[test]
    fn overlong_session_id_is_not_stored() {
        assert_eq!(storable_session(Some("abc")).as_deref(), Some("abc"));
        assert_eq!(storable_session(None), None);
        let long = "x".repeat(crate::sessions::MAX_SESSION_ID + 1);
        assert_eq!(storable_session(Some(&long)), None);
    }

    #[test]
    fn notices_at_most_once_per_uid_and_kind_per_minute() {
        let mut m = HashMap::new();
        let t0 = Instant::now();
        assert!(notice_due(&mut m, 1000, Notice::Requests, t0));
        assert!(!notice_due(
            &mut m,
            1000,
            Notice::Requests,
            t0 + Duration::from_secs(59)
        ));
        // Another uid, or another kind, has its own minute.
        assert!(notice_due(&mut m, 1001, Notice::Requests, t0));
        assert!(notice_due(&mut m, 1000, Notice::LowDisk, t0));
        assert!(notice_due(
            &mut m,
            1000,
            Notice::Requests,
            t0 + Duration::from_secs(60)
        ));
        assert!(!notice_due(
            &mut m,
            1000,
            Notice::Requests,
            t0 + Duration::from_secs(61)
        ));
    }

    #[test]
    fn notice_reasons_are_exact() {
        assert_eq!(
            Notice::Requests.reason(1000),
            "uid 1000 is over its request limits (64 in flight, 1000/s)"
        );
        assert_eq!(
            Notice::Connections.reason(1000),
            "uid 1000 is over its connection limits (32 open per uid, or the daemon's total)"
        );
        assert_eq!(
            Notice::LowDisk.reason(1000),
            "uid 1000: audit volume below [audit] min_free_mb"
        );
        assert_eq!(Notice::Requests.event(), "rate_limited");
        assert_eq!(Notice::Connections.event(), "rate_limited");
        assert_eq!(Notice::LowDisk.event(), "low_disk");
    }

    #[test]
    fn connection_and_request_notices_dedupe_separately() {
        let mut m = HashMap::new();
        let t0 = Instant::now();
        assert!(notice_due(&mut m, 1000, Notice::Connections, t0));
        let t1 = t0 + Duration::from_secs(1);
        assert!(notice_due(&mut m, 1000, Notice::Requests, t1));
        assert!(!notice_due(&mut m, 1000, Notice::Connections, t1));
        assert!(!notice_due(&mut m, 1000, Notice::Requests, t1));
    }
}
