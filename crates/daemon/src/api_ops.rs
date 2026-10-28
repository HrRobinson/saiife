//! `api.call`, `api.list` and `api.result` (spec §6.7, §8.7): connector
//! requests over the control socket. Step 1 of the pipeline happens here
//! (uid from the peer credentials, the session by attribution, the project
//! as the client reports it); steps 3–12 are `saiife_broker::pipeline`.
//! Every call writes one `connector` record before it answers.

use crate::ops::{Ctx, GatewayPolicy, Notice, VERSION};
use crate::sessions::agent_ancestor;
use crate::tokens;
use crate::vault::{Kind, VaultState};
use base64::Engine as _;
use bytes::Bytes;
use saiife_broker::manifest::{AuthSpec, Manifest};
use saiife_broker::pipeline::{
    self, ApprovalFuture, Call, Env, OpRef, Outcome, PendingCall, PolicySnapshot, TokenFuture,
    Trace, Via,
};
use saiife_broker::request::AuthMaterial;
use saiife_ipc::frame::MAX_ANSWER_FRAME;
use saiife_ipc::msg::{err, err_with, ok, ErrorCode, Request, OP_API_LIST, OP_API_RESULT};
use saiife_ipc::peer::{comm, PeerCred};
use saiife_policy::{
    scope_for, Directory, GroupEntry, PolicyError, Scope, ServiceOverlay, SystemConfig, UserEntry,
};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

use tokio::sync::Semaphore;
use zeroize::Zeroizing;

const MAX_PARAMS: usize = 256;
const MAX_KEY: usize = 128;
const MAX_VALUE: usize = 64 * 1024;
const MAX_HEADERS: usize = 64;
const MAX_PATTERNS: usize = 256;
const MAX_PATTERN_BYTES: usize = 256;
const MAX_OVERLAY_SERVICES: usize = 64;
const MAX_PROJECT: usize = 4096;

pub async fn handle(ctx: &Arc<Ctx>, peer: &PeerCred, req: Request) -> Value {
    match req.op.as_str() {
        OP_API_RESULT => crate::approval_ops::api_result(ctx, peer, req).await,
        OP_API_LIST => list(ctx, peer, req).await,
        _ => call(ctx, peer, req).await,
    }
}

/// The caller's directory view for one request: its groups, looked up
/// (cached, off the runtime thread) before the pipeline runs.
pub(crate) struct Groups(pub(crate) Vec<String>);

impl Directory for Groups {
    fn user(&self, _name: &str) -> Option<UserEntry> {
        None
    }
    fn name_of(&self, _uid: u32) -> Option<String> {
        None
    }
    fn group(&self, _name: &str) -> Option<GroupEntry> {
        None
    }
    fn groups_of(&self, _user: &str) -> Vec<String> {
        self.0.clone()
    }
}

pub(crate) struct DaemonEnv<'a> {
    pub(crate) ctx: &'a Arc<Ctx>,
    pub(crate) config: &'a SystemConfig,
    pub(crate) groups: Groups,
    /// The requester's agent (`comm` of its agent process), for an
    /// approval request.
    pub(crate) agent: String,
}

/// The auth entry a vault kind can fill: `basic` the basic one, `token` a
/// bearer, a header or a `basic_token` reading `token`, `header` one reading
/// `value`, `oauth2` the oauth2 one (its access token from daemon memory).
fn spec_for(kind: Kind, auth: &[AuthSpec]) -> Option<&AuthSpec> {
    auth.iter().find(|a| match kind {
        Kind::Basic => a.kind == "basic",
        Kind::Token => {
            matches!(a.kind.as_str(), "bearer" | "header" | "basic_token")
                && a.secret_field == "token"
        }
        Kind::Header => a.kind == "header" && a.secret_field == "value",
        Kind::OAuth2 => a.kind == "oauth2",
        // Signed or minted by the daemon itself (Task 9 wires the cloud auth).
        Kind::Aws | Kind::GcpSa | Kind::AzureSp => false,
    })
}

/// The values the masker hides for a secret before its auth entry is known
/// (step 9 rebuilds the masker from the real credential). A token may be
/// sent as `basic_token`, whose wire form is `base64(token:)`, so a token
/// also yields `token:` (the masker covers its base64 forms).
fn mask_values(kind: Kind, fields: &BTreeMap<String, Zeroizing<String>>) -> Vec<Zeroizing<String>> {
    let kind = match kind {
        Kind::Token => "basic_token",
        k => kind_str(k),
    };
    let mut out = AuthMaterial {
        kind: kind.to_string(),
        name: None,
        fields: fields.clone(),
    }
    .values();
    if let Some(body) = fields.get("private_key").and_then(|k| pem_body(k)) {
        // The key as a bare base64 run: what is left when an upstream
        // echoes it without its framing or line breaks.
        out.push(body);
    }
    out
}

/// The base64 of a PEM block without framing lines and line breaks.
pub(crate) fn pem_body(pem: &str) -> Option<Zeroizing<String>> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.trim().chars())
        .collect();
    (body.len() >= 4).then(|| Zeroizing::new(body))
}

fn kind_str(k: Kind) -> &'static str {
    match k {
        Kind::Token => "token",
        Kind::Basic => "basic",
        Kind::Header => "header",
        Kind::OAuth2 => "oauth2",
        Kind::Aws => "aws",
        Kind::GcpSa => "gcp_sa",
        Kind::AzureSp => "azure_sp",
    }
}

impl Env for DaemonEnv<'_> {
    fn lockdown(&self) -> Option<saiife_broker::pipeline::Lockdown> {
        self.ctx.lockdown.get()
    }

    fn scope(&self, user: &str) -> Result<Option<Scope>, PolicyError> {
        scope_for(self.config, &self.groups, user).map(|s| s.cloned())
    }

    fn secret(
        &self,
        name: &str,
        service: &str,
        auth: &[AuthSpec],
    ) -> Result<AuthMaterial, &'static str> {
        let mut g = self.ctx.vault.lock();
        let VaultState::Ready(v) = &mut *g else {
            return Err("vault_unavailable");
        };
        let e = v.get(name).ok_or("secret_missing")?;
        if !e.allowed_services.iter().any(|s| s == service) {
            return Err("secret_not_allowed_for_service");
        }
        // A secret of a kind the connector cannot use is as good as none.
        let spec = spec_for(e.kind, auth).ok_or("secret_missing")?;
        let material = AuthMaterial::from_spec(spec, e.fields.clone());
        // In memory only: the serve loop's timer writes `last_used` off the
        // runtime thread (no fsync here, under the lock, on a request).
        v.touch(name, &crate::ops::now_ts());
        Ok(material)
    }

    fn secret_values(&self, name: &str) -> Option<Vec<Zeroizing<String>>> {
        let g = self.ctx.vault.lock();
        let VaultState::Ready(v) = &*g else {
            return None;
        };
        let e = v.get(name)?;
        Some(mask_values(e.kind, &e.fields))
    }

    fn pool(&self, service: &str) -> Arc<Semaphore> {
        self.ctx.pools.get(service)
    }

    fn create_approval<'b>(&'b self, p: &'b PendingCall) -> ApprovalFuture<'b> {
        Box::pin(crate::approval_ops::create(self.ctx, p, &self.agent))
    }

    fn oauth_token<'b>(
        &'b self,
        secret: &'b str,
        service: &'b str,
        spec: &'b AuthSpec,
        m: &'b Manifest,
        svc_params: &'b BTreeMap<String, String>,
        force: bool,
    ) -> TokenFuture<'b> {
        Box::pin(crate::oauth::access_token(
            self.ctx,
            crate::oauth::Want {
                secret,
                service,
                spec,
                manifest: m,
                svc_params,
                force,
            },
        ))
    }
}

fn bad(id: u64, m: &str) -> Value {
    err(id, ErrorCode::BadRequest, m)
}

fn string_of(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

pub(crate) fn valid_service(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

/// A collection name (decision 11): `[a-z0-9_-]{1,64}`.
pub(crate) fn valid_collection(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
}

/// Parses `overlay` (`{allow, ask, deny}` lists of strings).
fn parse_overlay(v: Option<&Value>) -> Result<Option<ServiceOverlay>, &'static str> {
    let Some(v) = v.filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let o: ServiceOverlay =
        serde_json::from_value(v.clone()).map_err(|_| "overlay must be {allow, ask, deny}")?;
    check_overlay(&o)?;
    Ok(Some(o))
}

/// Each list at most [`MAX_PATTERNS`] entries of at most
/// [`MAX_PATTERN_BYTES`] bytes.
fn check_overlay(o: &ServiceOverlay) -> Result<(), &'static str> {
    if [&o.allow, &o.ask, &o.deny]
        .iter()
        .any(|l| l.len() > MAX_PATTERNS || l.iter().any(|p| p.len() > MAX_PATTERN_BYTES))
    {
        return Err("overlay too large");
    }
    Ok(())
}

/// `api.list`'s `overlays`: at most [`MAX_OVERLAY_SERVICES`] services, each
/// overlay bounded as in `api.call`.
fn parse_overlays(v: Option<&Value>) -> Result<BTreeMap<String, ServiceOverlay>, &'static str> {
    let Some(v) = v.filter(|v| !v.is_null()) else {
        return Ok(BTreeMap::new());
    };
    let m: BTreeMap<String, ServiceOverlay> = serde_json::from_value(v.clone())
        .map_err(|_| "overlays must map services to {allow, ask, deny}")?;
    if m.len() > MAX_OVERLAY_SERVICES {
        return Err("overlays: too many services");
    }
    for (name, o) in &m {
        if !valid_service(name) {
            return Err("overlays: invalid service name");
        }
        check_overlay(o)?;
    }
    Ok(m)
}

/// The mode connector calls choose their environment under (see
/// [`GatewayPolicy::select_env`]): the daemon's own, as the policy
/// decides it. The locked daemon takes the scope's environment; the
/// personal broker decides as developer mode, so the project `env` the
/// client sends picks the snapshot.
pub(crate) fn gateway_mode(ctx: &Ctx) -> saiife_policy::Mode {
    ctx.mode.policy_mode()
}

/// The optional `env` argument of `api.call` and `api.list`: the project's
/// environment, as the client read it from `.saiife/config.toml`. Only
/// developer mode acts on it, but a malformed one is a bad request in every
/// mode, locked included: the shape is checked before the mode decides
/// whether the value counts.
pub(crate) fn parse_env(args: &Map<String, Value>) -> Result<Option<String>, &'static str> {
    match args.get("env") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if saiife_policy::environment::valid_env_name(s) => {
            Ok(Some(s.clone()))
        }
        Some(_) => Err("env must be an environment name ([a-z0-9_-]{1,64})"),
    }
}

/// The arguments of `api.call`, checked. Errors never quote a value.
pub(crate) fn parse_call(args: &Map<String, Value>) -> Result<(String, OpRef, Call), &'static str> {
    let service = args
        .get("service")
        .and_then(Value::as_str)
        .filter(|s| valid_service(s))
        .ok_or("api.call takes a valid service name")?
        .to_string();
    let op = match args.get("operation") {
        Some(Value::String(s)) if !s.is_empty() && s.len() <= MAX_KEY => OpRef::Named(s.clone()),
        Some(Value::Object(o)) => {
            let method = o
                .get("method")
                .and_then(Value::as_str)
                .filter(|m| {
                    !m.is_empty() && m.len() <= 16 && m.bytes().all(|b| b.is_ascii_uppercase())
                })
                .ok_or("operation.method must be an upper-case HTTP method")?;
            let path = o
                .get("path")
                .and_then(Value::as_str)
                .filter(|p| p.len() <= 8192)
                .ok_or("operation.path must be a string")?;
            OpRef::Proxy {
                method: method.to_string(),
                path: path.to_string(),
            }
        }
        _ => return Err("api.call takes an operation (a name or {method, path})"),
    };
    let mut params = BTreeMap::new();
    match args.get("params") {
        None | Some(Value::Null) => {}
        Some(Value::Object(o)) => {
            if o.len() > MAX_PARAMS {
                return Err("too many params");
            }
            for (k, v) in o {
                let v = string_of(v).ok_or("params values must be strings")?;
                if k.len() > MAX_KEY || v.len() > MAX_VALUE {
                    return Err("a param name or value is too long");
                }
                params.insert(k.clone(), v);
            }
        }
        Some(_) => return Err("params must be an object"),
    }
    let body = match args.get("body_b64") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(Bytes::from(
            base64::engine::general_purpose::STANDARD
                .decode(s)
                .map_err(|_| "body_b64 is not base64")?,
        )),
        Some(_) => return Err("body_b64 must be a string"),
    };
    let mut headers = Vec::new();
    match args.get("headers") {
        None | Some(Value::Null) => {}
        Some(Value::Array(a)) => {
            if a.len() > MAX_HEADERS {
                return Err("too many headers");
            }
            for h in a {
                let pair = h
                    .as_array()
                    .filter(|p| p.len() == 2)
                    .and_then(|p| Some((p[0].as_str()?.to_string(), p[1].as_str()?.to_string())))
                    .ok_or("headers must be [name, value] pairs")?;
                if pair.0.len() > MAX_KEY || pair.1.len() > MAX_VALUE {
                    return Err("a header is too long");
                }
                headers.push(pair);
            }
        }
        Some(_) => return Err("headers must be an array"),
    }
    let overlay = parse_overlay(args.get("overlay"))?;
    let project = match args.get("project") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) if s.len() <= MAX_PROJECT && !s.contains(['\n', '\r', '\0']) => {
            s.clone()
        }
        Some(_) => return Err("project must be a path"),
    };
    let collection = match args.get("collection") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if valid_collection(s) => Some(s.clone()),
        Some(_) => return Err("collection must be a name of [a-z0-9_-], 1 to 64 bytes"),
    };
    // `wait_ms` is accepted and ignored (decision 3): `--wait` polls
    // `api.result` from the client.
    let call = Call {
        uid: 0,
        user: String::new(),
        session: None,
        project,
        service: service.clone(),
        op: op.clone(),
        params,
        body,
        headers,
        overlay,
        via: Via::Cli,
        collection,
    };
    Ok((service, op, call))
}

/// The audit-volume gate (as for `audit.append`): a call that cannot be
/// recorded is not made.
fn disk_ok(ctx: &Ctx, uid: u32) -> Result<(), ErrorCode> {
    let free = crate::disk::free_mb(&ctx.audit_dir).unwrap_or(0);
    crate::disk::disk_gate(free, ctx.policy().min_free_mb, uid, ctx.own_uid)
}

/// A snapshot for the record of a call made without a valid policy.
fn no_policy_snapshot(hash: Option<String>, mode: crate::ops::Mode) -> PolicySnapshot {
    PolicySnapshot {
        config: toml::from_str("version = 2").expect("a minimal config parses"),
        hash: hash.unwrap_or_default(),
        mode: mode.policy_mode(),
        env: None,
    }
}

/// Why a parsed call got no outcome. Neither writes a `connector` record.
pub(crate) enum Refused {
    /// The audit volume is below `[audit] min_free_mb`.
    LowDisk(ErrorCode),
    /// The record could not be written: the result is withheld.
    Unrecorded(String),
}

pub(crate) const LOW_DISK: &str = "the audit volume is below [audit] min_free_mb";

async fn call(ctx: &Arc<Ctx>, peer: &PeerCred, req: Request) -> Value {
    let id = req.id;
    let (_service, _op, call) = match parse_call(&req.args) {
        Ok(x) => x,
        Err(m) => return bad(id, m),
    };
    let project_env = match parse_env(&req.args) {
        Ok(e) => e,
        Err(m) => return bad(id, m),
    };
    match execute_in(ctx, &Caller::Unix(*peer), call, project_env.as_deref()).await {
        // 12. Return.
        Ok((outcome, warning)) => with_warning(answer(id, outcome), warning),
        Err(Refused::LowDisk(code)) => err(id, code, LOW_DISK),
        Err(Refused::Unrecorded(m)) => err(id, ErrorCode::Internal, &m),
    }
}

/// `answer` with a `warning` key when the environment choice left one.
fn with_warning(mut v: Value, warning: Option<String>) -> Value {
    if let (Some(w), Some(o)) = (warning, v.as_object_mut()) {
        o.insert("warning".into(), w.into());
    }
    v
}

/// Who makes a connector call: a Unix-socket peer (uid and pid from the
/// kernel), or a bearer token on the gateway's loopback TCP listener (the
/// uid the token is bound to, and nothing else: no pid, so no session).
#[derive(Debug, Clone, Copy)]
pub(crate) enum Caller {
    Unix(PeerCred),
    Token {
        uid: u32,
        addr: std::net::SocketAddr,
    },
}

impl Caller {
    pub(crate) fn uid(&self) -> u32 {
        match self {
            Caller::Unix(p) => p.uid,
            Caller::Token { uid, .. } => *uid,
        }
    }

    fn pid(&self) -> Option<u32> {
        match self {
            Caller::Unix(p) => Some(p.pid),
            Caller::Token { .. } => None,
        }
    }

    /// The record's `peer`.
    fn record(&self) -> Value {
        match self {
            Caller::Unix(p) => json!({"pid": p.pid, "comm": comm(p.pid)}),
            Caller::Token { addr, .. } => json!({"tcp": addr.to_string(), "auth": "token"}),
        }
    }
}

/// Every entry point (`api.call`, the HTTP gateway) once it has parsed its
/// request into `call`: step 1 (the uid from the caller's identity, the
/// session by attribution), steps 3–12 under the policy in force when the
/// call starts, and its one `connector` record (step 11), written before
/// the outcome is returned. `uid`, `user` and `session` are set here from
/// the caller, whatever the request put there.
pub(crate) async fn execute(
    ctx: &Arc<Ctx>,
    caller: &Caller,
    call: Call,
) -> Result<Outcome, Refused> {
    execute_in(ctx, caller, call, None).await.map(|(o, _)| o)
}

/// [`execute`] with the project's `env` (developer mode only), and the
/// warning the environment choice left.
pub(crate) async fn execute_in(
    ctx: &Arc<Ctx>,
    caller: &Caller,
    mut call: Call,
    project_env: Option<&str>,
) -> Result<(Outcome, Option<String>), Refused> {
    // A stop waits for this call (and its record) before it ends the log.
    let _busy = ctx.calls.enter();
    let uid = caller.uid();
    if let Err(code) = disk_ok(ctx, uid) {
        ctx.notice(uid, Notice::LowDisk);
        return Err(Refused::LowDisk(code));
    }
    // 1. Identify: the caller's uid, the session by attribution.
    call.uid = uid;
    call.user = ctx.name_of(uid).await.unwrap_or_default();
    let ancestor = caller
        .pid()
        .and_then(|pid| agent_ancestor(ctx.proc.as_ref(), pid));
    call.session = ancestor.and_then(|a| ctx.sessions.lookup(a));
    let agent = ancestor
        .and_then(|(pid, _)| ctx.proc.stat(pid))
        .map(|s| s.comm)
        .unwrap_or_default();
    let groups = if call.user.is_empty() {
        Vec::new()
    } else {
        ctx.groups_of(&call.user).await
    };

    // The policy as it is now: a reload while this call runs does not
    // change what it runs under.
    let state = ctx.policy();
    let mut warning = None;
    let (outcome, trace, gw, env_name): (Outcome, Trace, Arc<GatewayPolicy>, Option<String>) =
        match &state.gateway {
            Some(g) => {
                let groups = Groups(groups);
                // The environment snapshot this call runs under (spec §6.11).
                match g.select_env(gateway_mode(ctx), &groups, &call.user, project_env) {
                    Ok((env_name, w)) => {
                        warning = w;
                        let snap = g.snapshot_for(env_name);
                        let env = DaemonEnv {
                            ctx,
                            config: &snap.config,
                            groups,
                            agent: agent.clone(),
                        };
                        // Without an upstream client steps 3–8 still run;
                        // step 9 denies with `upstream_unavailable`.
                        let up = ctx.upstream.as_ref().ok();
                        let (o, t) =
                            pipeline::run(&call, snap, &g.catalog, &ctx.limiter, &env, up).await;
                        (o, t, Arc::clone(g), env_name.map(str::to_string))
                    }
                    Err(rule) => (
                        Outcome::Denied { rule: rule.into() },
                        Trace::default(),
                        Arc::clone(g),
                        None,
                    ),
                }
            }
            None => (
                Outcome::Denied {
                    rule: "policy_invalid".into(),
                },
                Trace::default(),
                Arc::new(GatewayPolicy {
                    snap: no_policy_snapshot(state.hash.clone(), ctx.mode),
                    by_env: Default::default(),
                    catalog: Default::default(),
                }),
                None,
            ),
        };
    let snap = gw.snapshot_for(env_name.as_deref());

    if let Outcome::Limited { limit } = &outcome {
        ctx.notify_limit(
            uid,
            &call.service,
            trace.operation.as_deref().unwrap_or(""),
            limit,
        );
    }

    // 11. Record (before the answer: an unrecorded result is withheld).
    let mut rec = pipeline::record(&call, snap, &trace, &outcome, &agent, VERSION);
    if snap.hash.is_empty() {
        rec.policy = None;
    }
    rec.extra.insert("peer".into(), caller.record());
    if let Err(e) = ctx.writer.append(rec).await {
        // A request that was sent is already counted by the limiter, but a
        // rebuild at the next start will not see it (it has no record). The
        // answer is withheld; the limits are briefly looser after a restart.
        return Err(Refused::Unrecorded(format!(
            "the connector record could not be written: {e}"
        )));
    }
    Ok((outcome, warning))
}

pub(crate) fn answer(id: u64, outcome: Outcome) -> Value {
    let one = |k: &str, v: Value| -> Map<String, Value> {
        let mut m = Map::new();
        m.insert(k.into(), v);
        m
    };
    match outcome {
        Outcome::Done { finished, next } => {
            // base64 grows by 4/3; leave room for the headers.
            if finished.body.len() / 3 * 4 > MAX_ANSWER_FRAME - 1_048_576 {
                return err(
                    id,
                    ErrorCode::UpstreamFailed,
                    "the response is too large for the control socket; lower max_response_bytes",
                );
            }
            let headers: Vec<Value> = finished
                .headers
                .iter()
                .map(|(k, v)| json!([k.as_str(), String::from_utf8_lossy(v.as_bytes())]))
                .collect();
            let mut m = Map::new();
            m.insert("status".into(), finished.status.into());
            m.insert(
                "body_b64".into(),
                base64::engine::general_purpose::STANDARD
                    .encode(&finished.body)
                    .into(),
            );
            m.insert("headers".into(), Value::Array(headers));
            m.insert("truncated".into(), finished.truncated.into());
            if let Some(n) = next {
                m.insert("next".into(), json!(n));
            }
            ok(id, m)
        }
        o @ Outcome::Denied { .. } if o.is_post_send_deny() => {
            let Outcome::Denied { rule } = o else {
                unreachable!()
            };
            err_with(
                id,
                ErrorCode::UpstreamFailed,
                &format!("response withheld ({rule})"),
                one("rule", rule.into()),
            )
        }
        Outcome::Denied { rule } => {
            let why = saiife_broker::pipeline::deny_reason(&rule);
            let msg = match why {
                Some(why) => format!("denied ({rule}): {why}"),
                None => format!("denied ({rule})"),
            };
            let mut m = one("rule", rule.into());
            if let Some(why) = why {
                m.insert("reason".into(), why.into());
            }
            err_with(id, ErrorCode::Denied, &msg, m)
        }
        Outcome::Limited { limit } => err_with(
            id,
            ErrorCode::Limited,
            &format!("limit reached ({limit})"),
            one("limit", limit.into()),
        ),
        Outcome::UpstreamFailed { reason } => err_with(
            id,
            ErrorCode::UpstreamFailed,
            &format!("upstream failed: {reason}"),
            one("reason", reason.into()),
        ),
        // Exit 3: the request waits for approval.
        Outcome::Pending { id: pending } => ok(id, one("pending", pending.into())),
    }
}

/// `api.token`: a bearer token for the gateway's loopback TCP listener,
/// bound to the caller's uid, valid 12 h. Only a uid with a scope gets one
/// (without a scope it could call nothing). The token is in this answer
/// and nowhere else; the daemon keeps its SHA-256.
pub(crate) async fn token(ctx: &Arc<Ctx>, uid: u32, id: u64) -> Value {
    // No record, no token: below the audit floor none is issued.
    if let Err(code) = disk_ok(ctx, uid) {
        ctx.notice(uid, Notice::LowDisk);
        return err(id, code, LOW_DISK);
    }
    // No credential of any kind is handed out during a lockdown.
    if let Some(l) = ctx.lockdown.get() {
        let why = crate::lockdown::message(&l);
        let mut r = ctx.event("gateway_token");
        r.decision = saiife_audit::DecisionKind::Deny;
        r.rule = Some("lockdown".into());
        r.reason = Some(why.clone());
        r.extra.insert("token_uid".into(), uid.into());
        if let Err(e) = ctx.writer.append(r).await {
            eprintln!("saiife: warning: cannot write the gateway_token record: {e}");
        }
        let mut v = err(id, ErrorCode::Denied, &format!("lockdown: {why}"));
        if let Some(o) = v.as_object_mut() {
            o.insert("rule".into(), "lockdown".into());
        }
        return v;
    }
    if !has_scope(ctx, uid).await {
        return err(
            id,
            ErrorCode::Forbidden,
            "api.token is for users in a [[scope]] of the system policy",
        );
    }
    let tokens = Arc::clone(&ctx.tokens);
    let issued = tokens::issue_blocking(tokens, uid).await;
    let issued = match issued {
        Ok(i) => i,
        Err(e) => {
            eprintln!("saiife: warning: cannot store a gateway token: {e}");
            return err(id, ErrorCode::Internal, "the token could not be stored");
        }
    };
    let expires = tokens::rfc3339(issued.expires);
    let mut r = ctx.event("gateway_token");
    r.reason = Some(format!("issued to uid {uid}, expires {expires}"));
    r.extra.insert("token_uid".into(), uid.into());
    if let Err(e) = ctx.writer.append(r).await {
        // No record, no token: it is withdrawn before anyone saw it.
        eprintln!("saiife: warning: cannot write the gateway_token record: {e}");
        let t = Arc::clone(&ctx.tokens);
        let token = issued.token;
        let revoked = tokio::task::spawn_blocking(move || t.revoke(&token)).await;
        if !matches!(revoked, Ok(Ok(()))) {
            eprintln!("saiife: warning: cannot write the gateway tokens after withdrawing one");
        }
        return err(
            id,
            ErrorCode::Internal,
            &format!("the gateway_token record could not be written; no token issued: {e}"),
        );
    }
    let mut m = Map::new();
    m.insert("token".into(), issued.token.as_str().into());
    m.insert("expires".into(), expires.into());
    ok(id, m)
}

/// Whether `uid` has a scope in the policy in force (a scope conflict or no
/// valid policy: no).
async fn has_scope(ctx: &Arc<Ctx>, uid: u32) -> bool {
    let state = ctx.policy();
    let (Some(g), Some(user)) = (&state.gateway, ctx.name_of(uid).await) else {
        return false;
    };
    let groups = Groups(ctx.groups_of(&user).await);
    matches!(scope_for(&g.snap.config, &groups, &user), Ok(Some(_)))
}

/// `api.list`: [`services_for`] the caller.
async fn list(ctx: &Arc<Ctx>, peer: &PeerCred, req: Request) -> Value {
    let id = req.id;
    let overlays = match parse_overlays(req.args.get("overlays")) {
        Ok(o) => o,
        Err(m) => return bad(id, m),
    };
    let project_env = match parse_env(&req.args) {
        Ok(e) => e,
        Err(m) => return bad(id, m),
    };
    let (services, warning) = services_in(ctx, peer.uid, &overlays, project_env.as_deref()).await;
    let mut m = Map::new();
    m.insert("services".into(), Value::Array(services));
    if let Some(w) = warning {
        m.insert("warning".into(), w.into());
    }
    ok(id, m)
}

/// The services of `uid`'s scope and their operations, each with the
/// action the policy (and the client's overlay) gives it. Empty without a
/// valid policy, a name for the uid or a scope.
pub(crate) async fn services_for(
    ctx: &Arc<Ctx>,
    uid: u32,
    overlays: &BTreeMap<String, ServiceOverlay>,
) -> Vec<Value> {
    services_in(ctx, uid, overlays, None).await.0
}

/// [`services_for`] under the environment `api.call` would choose for the
/// same caller and project `env`, so the list matches what a call allows;
/// with the warning that choice left.
pub(crate) async fn services_in(
    ctx: &Arc<Ctx>,
    uid: u32,
    overlays: &BTreeMap<String, ServiceOverlay>,
    project_env: Option<&str>,
) -> (Vec<Value>, Option<String>) {
    let mut services = Vec::new();
    let mut warning = None;
    let state = ctx.policy();
    let user = ctx.name_of(uid).await;
    if let (Some(g), Some(user)) = (&state.gateway, user) {
        let groups = Groups(ctx.groups_of(&user).await);
        // A locked scope env with no snapshot lists nothing (a call is
        // denied `policy_invalid`).
        let chosen = g.select_env(gateway_mode(ctx), &groups, &user, project_env);
        let snap = chosen.as_ref().ok().map(|(e, _)| g.snapshot_for(*e));
        if let Ok((_, w)) = chosen {
            warning = w;
        }
        let scope = snap.and_then(|s| scope_for(&s.config, &groups, &user).ok().flatten());
        if let (Some(snap), Some(scope)) = (snap, scope) {
            for name in &scope.services {
                if let Some(ops) =
                    pipeline::list_operations(name, snap, &g.catalog, overlays.get(name))
                {
                    services.push(json!({"name": name, "operations": ops}));
                }
            }
        }
    }
    (services, warning)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_policy_snapshot_mode_follows_ctx() {
        use crate::ops::Mode;
        use saiife_policy::Mode as PolicyMode;
        let p = no_policy_snapshot(Some("sha256:x".into()), Mode::Personal);
        assert_eq!(p.mode, PolicyMode::Developer);
        assert_eq!(p.hash, "sha256:x");
        let l = no_policy_snapshot(None, Mode::Locked);
        assert_eq!(l.mode, PolicyMode::Locked);
    }

    #[test]
    fn parse_call_refuses_without_echoing_values() {
        let a = json!({"service": "erp", "operation": "x", "params": {"k": ["secret-v"]}});
        let e = parse_call(a.as_object().unwrap()).unwrap_err();
        assert!(!e.contains("secret-v"));
        let a = json!({"service": "Bad Name", "operation": "x"});
        assert!(parse_call(a.as_object().unwrap()).is_err());
        let a = json!({"service": "erp", "operation": {"method": "GET", "path": "/a?b=1"},
                       "params": {"n": 5}, "body_b64": "aGk=", "headers": [["Accept", "x"]],
                       "overlay": {"deny": ["*:write"]}, "project": "/p", "wait_ms": 10});
        let (_, op, c) = parse_call(a.as_object().unwrap()).unwrap();
        assert!(matches!(op, OpRef::Proxy { .. }));
        assert_eq!(parse_env(a.as_object().unwrap()), Ok(None));
        let e = |v: Value| parse_env(json!({ "env": v }).as_object().unwrap());
        assert_eq!(e(json!("staging")), Ok(Some("staging".into())));
        assert!(e(json!("Bad Name")).is_err());
        assert!(e(json!(["prod"])).is_err());
        assert!(e(json!("x".repeat(65))).is_err());
        assert_eq!(c.params["n"], "5");
        assert_eq!(c.body.as_deref(), Some(&b"hi"[..]));
        assert_eq!(c.overlay.unwrap().deny, vec!["*:write"]);
        assert_eq!(c.collection, None);
    }

    #[test]
    fn parse_call_collection_is_a_checked_name() {
        let with = |v: Value| {
            let a = json!({"service": "erp", "operation": "x", "collection": v});
            parse_call(a.as_object().unwrap()).map(|(_, _, c)| c.collection)
        };
        assert_eq!(
            with(json!("open-orders_2")).unwrap().as_deref(),
            Some("open-orders_2")
        );
        assert_eq!(with(Value::Null).unwrap(), None);
        assert_eq!(
            with(json!("a".repeat(64))).unwrap().map(|s| s.len()),
            Some(64)
        );
        for bad in [
            json!(""),
            json!("a".repeat(65)),
            json!("Open"),
            json!("a.b"),
            json!("a b"),
            json!("a/b"),
            json!("x\n"),
            json!(5),
        ] {
            let e = with(bad.clone()).unwrap_err();
            assert!(e.contains("collection"), "{bad}: {e}");
        }
    }

    #[test]
    fn overlays_are_bounded() {
        let ok_list: Vec<String> = (0..256).map(|i| format!("r{i}:read")).collect();
        let o = json!({"deny": ok_list});
        assert!(parse_overlay(Some(&o)).unwrap().is_some());
        let long: Vec<String> = (0..257).map(|i| format!("r{i}:read")).collect();
        assert!(parse_overlay(Some(&json!({"deny": long}))).is_err());
        let big = "x".repeat(257);
        assert!(parse_overlay(Some(&json!({"ask": [big]}))).is_err());
        assert!(parse_overlay(Some(&json!({"ask": ["x".repeat(256)]}))).is_ok());
        // api.call refuses the same.
        let a = json!({"service": "erp", "operation": "x", "overlay": {"deny": long_list(257)}});
        assert!(parse_call(a.as_object().unwrap()).is_err());
        // api.list: 64 services at most, each bounded.
        let m: Map<String, Value> = (0..64).map(|i| (format!("s{i}"), json!({}))).collect();
        assert_eq!(parse_overlays(Some(&Value::Object(m))).unwrap().len(), 64);
        let m: Map<String, Value> = (0..65).map(|i| (format!("s{i}"), json!({}))).collect();
        assert!(parse_overlays(Some(&Value::Object(m))).is_err());
        assert!(parse_overlays(Some(&json!({"erp": {"deny": long_list(257)}}))).is_err());
        assert!(parse_overlays(Some(&json!({"Bad Name": {}}))).is_err());
    }

    fn long_list(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("r{i}:read")).collect()
    }

    #[test]
    fn spec_for_matches_vault_kinds() {
        let header = AuthSpec {
            kind: "header".into(),
            name: Some("X-Api-Key".into()),
            secret_field: "value".into(),
            prefix: None,
            token_path: None,
        };
        let bearer = AuthSpec {
            kind: "bearer".into(),
            name: None,
            secret_field: "token".into(),
            prefix: None,
            token_path: None,
        };
        let both = [header.clone(), bearer.clone()];
        assert_eq!(spec_for(Kind::Header, &both), Some(&header));
        assert_eq!(spec_for(Kind::Token, &both), Some(&bearer));
        assert_eq!(spec_for(Kind::Basic, &both), None);
        // A Segment-style write key is a vault token.
        let basic_token = AuthSpec {
            kind: "basic_token".into(),
            ..bearer.clone()
        };
        let one = [basic_token.clone()];
        assert_eq!(spec_for(Kind::Token, &one), Some(&basic_token));
        assert_eq!(spec_for(Kind::Basic, &one), None);
        // oauth2 serves oauth2 only, and no other kind serves it.
        let oauth = AuthSpec {
            kind: "oauth2".into(),
            name: None,
            secret_field: String::new(),
            prefix: None,
            token_path: Some("/services/oauth2/token".into()),
        };
        let o = [oauth.clone()];
        assert_eq!(spec_for(Kind::OAuth2, &o), Some(&oauth));
        assert_eq!(spec_for(Kind::Token, &o), None);
        assert_eq!(spec_for(Kind::OAuth2, &both), None);
    }

    #[test]
    fn mask_values_cover_every_cloud_field() {
        let pem = concat!(
            "-----BEGIN ",
            "PRIVATE KEY-----\nTESTBODYTESTBODY0001\nTESTBODYTESTBODY0002\n-----END ",
            "PRIVATE KEY-----\n"
        );
        let sets: [(Kind, Vec<(&str, &str)>); 3] = [
            (
                Kind::Aws,
                vec![
                    ("access_key_id", concat!("AKI", "A", "TESTTESTTEST0001")),
                    ("secret_access_key", concat!("test-secret-", "key-0001")),
                    ("session_token", concat!("test-session-", "token-0001")),
                ],
            ),
            (
                Kind::GcpSa,
                vec![
                    ("client_email", "sa@p.iam.gserviceaccount.com"),
                    ("private_key", pem),
                    ("private_key_id", "abcd1234"),
                    ("project_id", "my-proj-1"),
                ],
            ),
            (
                Kind::AzureSp,
                vec![
                    ("tenant_id", "0123abcd-4567-89ab-cdef-0123456789ab"),
                    ("client_id", "1123abcd-4567-89ab-cdef-0123456789ab"),
                    ("client_secret", concat!("client-", "secret-0001")),
                ],
            ),
        ];
        for (kind, set) in sets {
            let fields: BTreeMap<String, Zeroizing<String>> = set
                .iter()
                .map(|(k, v)| (k.to_string(), Zeroizing::new(v.to_string())))
                .collect();
            let vals: Vec<String> = mask_values(kind, &fields)
                .iter()
                .map(|v| v.to_string())
                .collect();
            let refs: Vec<&str> = vals.iter().map(String::as_str).collect();
            let masker = saiife_broker::mask::Masker::new(&refs);
            for (k, v) in &set {
                assert!(vals.contains(&v.to_string()), "{k} not in the mask set");
                let masked = masker.mask_text(&format!("echo {v} end"));
                assert!(!masked.contains(v), "{k}");
            }
            if kind == Kind::GcpSa {
                // The key echoed as one base64 run, framing and breaks gone.
                let run = "TESTBODYTESTBODY0001TESTBODYTESTBODY0002";
                assert!(!masker.mask_text(&format!("k={run}")).contains(run));
            }
        }
    }

    #[test]
    fn token_mask_values_cover_the_basic_token_form() {
        let key = concat!("wk", "_", "mask0042");
        let fields: BTreeMap<String, Zeroizing<String>> =
            [("token".to_string(), Zeroizing::new(key.to_string()))].into();
        let vals: Vec<String> = mask_values(Kind::Token, &fields)
            .iter()
            .map(|v| v.to_string())
            .collect();
        assert!(vals.contains(&key.to_string()), "{vals:?}");
        assert!(vals.contains(&format!("{key}:")), "{vals:?}");
        // The masker built from them hides the wire form.
        let refs: Vec<&str> = vals.iter().map(String::as_str).collect();
        let masker = saiife_broker::mask::Masker::new(&refs);
        let wire = base64::engine::general_purpose::STANDARD.encode(format!("{key}:"));
        let masked = masker.mask_text(&format!("echo Basic {wire}"));
        assert!(!masked.contains(&wire), "{masked}");
        assert!(!masked.contains(key), "{masked}");
        // Basic keeps its own pair.
        let basic: BTreeMap<String, Zeroizing<String>> = [
            ("username".to_string(), Zeroizing::new("ann".to_string())),
            ("password".to_string(), Zeroizing::new("pw-1".to_string())),
        ]
        .into();
        let vals: Vec<String> = mask_values(Kind::Basic, &basic)
            .iter()
            .map(|v| v.to_string())
            .collect();
        assert!(vals.contains(&"ann:pw-1".to_string()), "{vals:?}");
    }
}
