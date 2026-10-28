//! The connector request pipeline (spec §6.7.1 steps 3–12), shared by every
//! entry point (`saiife api` over the control socket, the HTTP gateway).
//!
//! Steps 3–8 never touch the network: a request denied there costs no
//! upstream call. The daemon does step 1 (identity, session, project) and
//! hands over a [`Call`]. Step 8 stores an `ask` request ([`Env::create_approval`]);
//! [`send_approved`] sends it once approved.
//!
//! The policy is the [`PolicySnapshot`] taken when the call starts, so a
//! reload in flight cannot mix two policies, and the `connector` record
//! carries that snapshot's hash.

use crate::amount;
use crate::catalog::Catalog;
use crate::limits::{Event, Key, Limiter};
use crate::manifest::{AuthSpec, Manifest, OpKind, Operation, Pagination, Transport};
use crate::mask::{finish, Finished, Masked, Masker};
use crate::params;
use crate::request::{build, AuthMaterial};
use crate::resolve;
use crate::upstream::Upstream;
use crate::BrokerError;
use bytes::Bytes;
use http::header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_TYPE};
use http::HeaderValue;
use saiife_audit::{DecisionKind, NewRecord, Record};
use saiife_policy::capability::Capability;
use saiife_policy::decide::{decide, Request, Verdict};
use saiife_policy::{Mode, PolicyError, Scope, ServiceOverlay, SystemConfig};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use time::OffsetDateTime;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

/// At most this many upstream calls in flight per service (§4.1).
pub const POOL_SIZE: usize = 4;
/// The body is read this far past `max_response_bytes`, masked, and only
/// then cut (Review focus 1).
pub const READ_SLACK: usize = 65_536;

/// Deny rules given after the request was sent: the response is withheld
/// (HTTP 502, exit 1), and the request counts against the limits.
pub const POST_SEND_RULES: &[&str] = &["redirect_refused", "redact_non_json"];

/// How an operation is named: by id, or by method and raw path (the HTTP
/// gateway's `/v1/proxy`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpRef {
    Named(String),
    Proxy { method: String, path: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Cli,
    Http,
    /// A `tools/call` of `saiife mcp` (plan 17): attribution only.
    Mcp,
    /// The daemon sending a stored request after its approval.
    Approval,
}

impl Via {
    pub fn as_str(self) -> &'static str {
        match self {
            Via::Cli => "cli",
            Via::Http => "http",
            Via::Mcp => "mcp",
            Via::Approval => "approval",
        }
    }
}

/// The exact request kept while it waits for approval (spec §8.10
/// `request_sealed`): what step 8 resolved and validated, from the agent.
/// The daemon serializes it to JSON and seals it with the vault key; after
/// approval [`send_approved`] sends only this, whatever the agent sends
/// later. Values are unmasked: `Debug` shows names and sizes only.
#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StoredCall {
    pub uid: u32,
    pub user: String,
    pub session: Option<String>,
    pub project: String,
    pub service: String,
    /// The resolved operation id (a proxy request is stored by its id).
    pub operation: String,
    /// The parameters as given (proxy captures included), validated at
    /// creation and validated again at send.
    pub params: BTreeMap<String, String>,
    /// Base64 of the agent's body as canonical JSON (the input to
    /// [`prepare_body`], not the bytes sent: for `body = "form"` those are
    /// its form encoding). `None` when the operation builds its body from
    /// the params. At send it is prepared again, and the bytes must hash to
    /// `body_sha256`.
    pub body_b64: Option<String>,
    /// SHA-256 (hex) of the exact body bytes the approver was shown the
    /// hash of. At send the bytes about to go upstream must hash to it,
    /// or nothing is sent (`body_changed`): a change in how a body is
    /// canonicalized between the ask and the send cannot send something
    /// other than what was approved.
    #[serde(default)]
    pub body_sha256: Option<String>,
    pub headers: Vec<(String, String)>,
    /// The project's tightening overlay, applied again at send.
    pub overlay: Option<ServiceOverlay>,
    /// How the request came in (`cli` or `http`).
    pub via: String,
    /// The environment of the snapshot the request was asked under
    /// ([`PolicySnapshot::env`]). Developer mode sends under it again;
    /// locked mode chooses from the scope at send. Either way the daemon
    /// refuses the send (`env_changed`) when that is not this environment.
    /// Absent in requests stored before environments existed (read as
    /// `None`, not checked).
    #[serde(default)]
    pub env: Option<String>,
    /// `env` was recorded at the ask: true for every request asked since,
    /// so `env = None` then means the base config, and the send refuses an
    /// environment chosen since (`env_changed`) for it too. `false` in a
    /// request sealed before (read as the default): not checked.
    #[serde(default)]
    pub env_recorded: bool,
    /// The collection the request was a step of (attribution only).
    /// Absent in a call sealed before collections existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collection: Option<String>,
}

impl std::fmt::Debug for StoredCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredCall")
            .field("uid", &self.uid)
            .field("service", &self.service)
            .field("operation", &self.operation)
            .field("params", &self.params.keys().collect::<Vec<_>>())
            .field("body_len", &self.body_b64.as_ref().map(String::len))
            .finish()
    }
}

impl StoredCall {
    /// The call [`send_approved`] runs: the named operation, `via =
    /// approval`; `false` (and no body) when the stored body is not base64.
    pub fn call(&self) -> (Call, bool) {
        use base64::Engine as _;
        let (body, ok) = match &self.body_b64 {
            Some(b) => match base64::engine::general_purpose::STANDARD.decode(b) {
                Ok(v) => (Some(Bytes::from(v)), true),
                Err(_) => (None, false),
            },
            None => (None, true),
        };
        let call = Call {
            uid: self.uid,
            user: self.user.clone(),
            session: self.session.clone(),
            project: self.project.clone(),
            service: self.service.clone(),
            op: OpRef::Named(self.operation.clone()),
            params: self.params.clone(),
            body,
            headers: self.headers.clone(),
            overlay: self.overlay.clone(),
            via: Via::Approval,
            collection: self.collection.clone(),
        };
        (call, ok)
    }
}

/// What step 8 hands the daemon for a new approval request: the exact
/// request (to seal) and the display copy, masked with every vault value
/// of the service and the v1 patterns.
#[derive(Debug, Clone)]
pub struct PendingCall {
    pub stored: StoredCall,
    /// Masked.
    pub operation: String,
    /// Masked; the qualifier filled from the parameters.
    pub capability: Option<String>,
    pub params: Masked<BTreeMap<String, String>>,
    /// Masked.
    pub project: String,
    /// The body that will be sent (the canonical JSON), masked, whole up
    /// to [`BODY_DISPLAY_MAX`] bytes (then cut with a marker): what the
    /// approver reads.
    pub body_display: Option<String>,
    /// `body_display` was cut: an approval must acknowledge it.
    pub body_truncated: bool,
    /// SHA-256 (hex) of the exact body bytes that will be sent.
    pub body_sha256: Option<String>,
    /// `(minor units, currency)` of an operation that moves money.
    pub amount: Option<(u64, String)>,
    /// The agent's headers (forwarded as the manifest allows), masked.
    pub headers: Vec<(String, String)>,
}

/// The longest masked body an approval request shows, in bytes: the whole
/// body below it, so no field can hide past a cut.
pub const BODY_DISPLAY_MAX: usize = 1024 * 1024;

/// `s` whole, or cut at `max` bytes (on a char boundary) with a marker
/// saying how long it was; `true` when cut.
pub fn cut_display(s: &str, max: usize) -> (String, bool) {
    if s.len() <= max {
        return (s.to_string(), false);
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    (
        format!("{}…[truncated: {} bytes in all]", &s[..end], s.len()),
        true,
    )
}

/// The future of [`Env::create_approval`].
pub type ApprovalFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<u64, String>> + Send + 'a>>;

/// One connector request after step 1 (identity from the peer
/// credentials, the session by attribution, the project as reported).
pub struct Call {
    pub uid: u32,
    pub user: String,
    pub session: Option<String>,
    pub project: String,
    pub service: String,
    pub op: OpRef,
    pub params: BTreeMap<String, String>,
    pub body: Option<Bytes>,
    pub headers: Vec<(String, String)>,
    pub overlay: Option<ServiceOverlay>,
    pub via: Via,
    /// The collection this call is a step of (`saiife api collection
    /// run`), recorded as attribution only: it changes no decision.
    pub collection: Option<String>,
}

/// Parameter values, header values and the body can hold anything the
/// agent sent: `Debug` shows names and sizes only.
impl std::fmt::Debug for Call {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Call")
            .field("uid", &self.uid)
            .field("user", &self.user)
            .field("session", &self.session)
            .field("project", &self.project)
            .field("service", &self.service)
            .field("op", &self.op)
            .field("params", &self.params.keys().collect::<Vec<_>>())
            .field("body_len", &self.body.as_ref().map(Bytes::len))
            .field(
                "headers",
                &self.headers.iter().map(|(k, _)| k).collect::<Vec<_>>(),
            )
            .field("overlay", &self.overlay)
            .field("via", &self.via)
            .field("collection", &self.collection)
            .finish()
    }
}

/// The policy a call runs under: taken once when it starts.
#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    pub config: SystemConfig,
    /// `sha256:<hex>` of the effective policy.
    pub hash: String,
    pub mode: Mode,
    /// The environment applied to `config` (spec §6.11), `None` for the
    /// base config. The record's `env`, so it always matches `hash`.
    pub env: Option<String>,
}

/// What lockdown stops (spec §6.18).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockScope {
    /// Every connector request.
    Connectors,
    /// Connector requests and every hook call.
    All,
}

impl LockScope {
    pub fn as_str(self) -> &'static str {
        match self {
            LockScope::Connectors => "connectors",
            LockScope::All => "all",
        }
    }
}

/// The lockdown flag in force.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Lockdown {
    pub scope: LockScope,
    pub reason: String,
    pub by_uid: u32,
    pub since: String,
}

/// What the pipeline needs from the daemon.
pub trait Env: Sync {
    /// Step 2: the lockdown flag, `None` when it is off. Either scope
    /// denies a connector request.
    fn lockdown(&self) -> Option<Lockdown>;
    /// The caller's single scope (decision 6); `ScopeConflict` when it
    /// matches more than one.
    fn scope(&self, user: &str) -> Result<Option<Scope>, PolicyError>;
    /// The credential of secret `name` for `service`, in the form of one of
    /// the manifest's `auth` entries. Errs with the deny rule
    /// (`vault_unavailable`, `secret_missing`,
    /// `secret_not_allowed_for_service`).
    fn secret(
        &self,
        name: &str,
        service: &str,
        auth: &[AuthSpec],
    ) -> Result<AuthMaterial, &'static str>;
    /// Every value of secret `name`, only to mask the record of a call
    /// (also a denied one); nothing is sent with them. `None` when the
    /// vault cannot be read or there is no such secret.
    fn secret_values(&self, name: &str) -> Option<Vec<Zeroizing<String>>>;
    /// The per-service upstream pool ([`Pools`]).
    fn pool(&self, service: &str) -> Arc<Semaphore>;
    /// Step 8: store `p` as a pending approval request (sealed, with its
    /// `approval`/`created` record); the id, or the deny rule
    /// (`approvals_unavailable`, `vault_unavailable`, ...). Nothing is sent.
    fn create_approval<'a>(&'a self, p: &'a PendingCall) -> ApprovalFuture<'a>;
    /// Step 9 for an `oauth2` credential: the access token of secret
    /// `secret` (from memory, refreshed when due, or always with `force`),
    /// or the deny rule. The default has none (`secret_missing`).
    #[allow(clippy::too_many_arguments)]
    fn oauth_token<'a>(
        &'a self,
        secret: &'a str,
        service: &'a str,
        spec: &'a AuthSpec,
        m: &'a Manifest,
        svc_params: &'a BTreeMap<String, String>,
        force: bool,
    ) -> TokenFuture<'a> {
        let _ = (secret, service, spec, m, svc_params, force);
        Box::pin(async { Err("secret_missing") })
    }
}

/// The future of [`Env::oauth_token`].
pub type TokenFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Zeroizing<String>, &'static str>> + Send + 'a>,
>;

/// Parses a JSON body, refusing a duplicate object key anywhere (two
/// parsers that keep the first and the last value would see different
/// amounts). serde_json's recursion limit applies.
pub fn strict_json(b: &[u8]) -> Option<Value> {
    use serde::de::{DeserializeSeed, Deserializer, Error, MapAccess, SeqAccess, Visitor};

    struct Strict;

    impl<'de> DeserializeSeed<'de> for Strict {
        type Value = Value;
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
            d.deserialize_any(Strict)
        }
    }

    impl<'de> Visitor<'de> for Strict {
        type Value = Value;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("JSON")
        }
        fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
            Ok(Value::Bool(v))
        }
        fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
            Ok(v.into())
        }
        fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
            Ok(v.into())
        }
        fn visit_f64<E: Error>(self, v: f64) -> Result<Value, E> {
            serde_json::Number::from_f64(v)
                .map(Value::Number)
                .ok_or_else(|| E::custom("not a finite number"))
        }
        fn visit_str<E>(self, v: &str) -> Result<Value, E> {
            Ok(Value::String(v.to_string()))
        }
        fn visit_string<E>(self, v: String) -> Result<Value, E> {
            Ok(Value::String(v))
        }
        fn visit_unit<E>(self) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_none<E>(self) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
            let mut out = Vec::new();
            while let Some(v) = a.next_element_seed(Strict)? {
                out.push(v);
            }
            Ok(Value::Array(out))
        }
        fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
            let mut out = Map::new();
            while let Some(k) = a.next_key::<String>()? {
                let v = a.next_value_seed(Strict)?;
                if out.insert(k, v).is_some() {
                    return Err(A::Error::custom("duplicate key"));
                }
            }
            Ok(Value::Object(out))
        }
    }

    let mut de = serde_json::Deserializer::from_slice(b);
    let v = Strict.deserialize(&mut de).ok()?;
    de.end().ok()?;
    Some(v)
}

/// One semaphore of [`POOL_SIZE`] per service.
#[derive(Default)]
pub struct Pools {
    by_service: Mutex<HashMap<String, Arc<Semaphore>>>,
}

impl Pools {
    pub fn new() -> Pools {
        Pools::default()
    }

    pub fn get(&self, service: &str) -> Arc<Semaphore> {
        let mut m = self.by_service.lock().unwrap_or_else(|p| p.into_inner());
        Arc::clone(
            m.entry(service.to_string())
                .or_insert_with(|| Arc::new(Semaphore::new(POOL_SIZE))),
        )
    }
}

#[derive(Debug)]
pub enum Outcome {
    /// The upstream answered (any status); the response is masked.
    Done {
        finished: Finished,
        next: Option<BTreeMap<String, String>>,
    },
    Denied {
        rule: String,
    },
    Limited {
        limit: &'static str,
    },
    UpstreamFailed {
        reason: String,
    },
    /// An `ask` rule matched: the request waits for approval as `id`
    /// (exit 3, HTTP 202). Nothing was sent or counted.
    Pending {
        id: u64,
    },
}

/// Step 8: the body would be shown masked, so it cannot be approved.
/// The body as the approver will see it, when that is exactly what will be
/// sent: `None` if the masker would change it, or it is not UTF-8. The
/// vault forms are compared on the raw bytes (a lossy UTF-8 view would
/// hide a change inside invalid bytes), then the v1 patterns on the text.
fn faithful_display(masker: &Masker, b: &[u8]) -> Option<String> {
    if masker.mask_bytes(b) != b {
        return None;
    }
    // Unreachable for body = "json" today (canonical JSON by now); defence in depth.
    let text = std::str::from_utf8(b).ok()?;
    (masker.mask_text(text) == text).then(|| text.to_string())
}

pub const MASKED_CONTENT_RULE: &str = "masked_content";

/// The fixed explanation a deny rule carries, if any.
pub fn deny_reason(rule: &str) -> Option<&'static str> {
    match rule {
        MASKED_CONTENT_RULE => Some("cannot be approved: the request contains masked content"),
        _ => None,
    }
}

impl Outcome {
    /// A deny given after the request was sent (the response is withheld):
    /// HTTP 502, exit 1.
    pub fn is_post_send_deny(&self) -> bool {
        matches!(self, Outcome::Denied { rule } if POST_SEND_RULES.contains(&rule.as_str()))
    }
}

/// What the pipeline learned about a call, for its `connector` record.
#[derive(Debug, Clone, Default)]
pub struct Trace {
    pub operation: Option<String>,
    pub capability: Option<String>,
    pub op_kind: Option<OpKind>,
    /// `(minor units, currency)`.
    pub amount: Option<(u64, String)>,
    pub env: Option<String>,
    pub secret: Option<String>,
    /// Masked with every vault value in use and the v1 patterns.
    pub params: BTreeMap<String, String>,
    /// Of the bytes sent upstream (the canonical JSON when re-serialized).
    pub body_sha256: Option<String>,
    pub body_bytes: usize,
    /// The operation as the record's `input` names it, masked: the id, or
    /// `{method} {path}` of an unresolved proxy request.
    pub op_label: String,
    /// The project as the client reported it, masked; `None` until [`run`]
    /// set it (the record then masks it with the v1 patterns).
    pub project: Option<String>,
    pub status: Option<u16>,
    pub resp_bytes: Option<usize>,
    pub duration_ms: u64,
    /// The request went to the upstream (it counts against the limits).
    pub sent: bool,
    /// An oauth2 call was sent again after a 401 and a forced refresh.
    pub auth_retry: bool,
}

/// A masker of `values` (and the v1 patterns).
fn masker_of(values: &[Zeroizing<String>]) -> Masker {
    let refs: Vec<&str> = values.iter().map(|v| v.as_str()).collect();
    Masker::new(&refs)
}

/// Steps 3–12; see [`run`] for the trace.
pub async fn handle(
    call: Call,
    cfg: &PolicySnapshot,
    cat: &Catalog,
    lim: &Limiter,
    env: &dyn Env,
    up: Option<&Upstream>,
) -> Outcome {
    run(&call, cfg, cat, lim, env, up).await.0
}

/// Steps 3–12, with what the `connector` record needs.
pub async fn run(
    call: &Call,
    cfg: &PolicySnapshot,
    cat: &Catalog,
    lim: &Limiter,
    env: &dyn Env,
    up: Option<&Upstream>,
) -> (Outcome, Trace) {
    run_stage(call, Stage::New, cfg, cat, lim, env, up).await
}

/// Send a stored request after its approval (spec §6.10.1 step 4): the
/// call is re-run against the policy in force now (`cfg`, decision 2).
/// Lockdown denies (`lockdown`); a scope that no longer lists the service
/// or a `deny` verdict is `policy_changed`; `ask` or `allow` sends. The
/// limits are checked and counted for real (decision 1): over one is
/// `Limited`. Returns the call (`via = approval`) for its record.
pub async fn send_approved(
    stored: &StoredCall,
    cfg: &PolicySnapshot,
    cat: &Catalog,
    lim: &Limiter,
    env: &dyn Env,
    up: Option<&Upstream>,
) -> (Call, Outcome, Trace) {
    let (call, body_ok) = stored.call();
    if !body_ok {
        return (call, denied("stored_request_invalid"), Trace::default());
    }
    let stage = Stage::Approved {
        body_sha256: stored.body_sha256.as_deref(),
    };
    let (o, t) = run_stage(&call, stage, cfg, cat, lim, env, up).await;
    (call, o, t)
}

/// A new request, or one approved earlier (with the hash of the body its
/// approver was shown).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage<'a> {
    New,
    Approved { body_sha256: Option<&'a str> },
}

async fn run_stage(
    call: &Call,
    stage: Stage<'_>,
    cfg: &PolicySnapshot,
    cat: &Catalog,
    lim: &Limiter,
    env: &dyn Env,
    up: Option<&Upstream>,
) -> (Outcome, Trace) {
    let started = Instant::now();
    let mut tr = Trace {
        body_bytes: call.body.as_ref().map_or(0, Bytes::len),
        body_sha256: call.body.as_ref().map(|b| hex(&Sha256::digest(b))),
        ..Trace::default()
    };
    let mut masker = Masker::new(&[]);
    let outcome = steps(call, stage, cfg, cat, lim, env, up, &mut tr, &mut masker).await;
    // Agent-supplied values go into the record masked with every vault
    // value in use (an agent may echo the token) and the v1 patterns: the
    // operation id or proxy request (§8.5), the params, the capability (its
    // qualifier is filled from the params) and the reported project.
    tr.operation = tr.operation.as_deref().map(|o| masker.mask_text(o));
    tr.capability = tr.capability.as_deref().map(|c| masker.mask_text(c));
    tr.project = Some(masker.mask_text(&call.project));
    tr.op_label = match (&tr.operation, &call.op) {
        (Some(id), _) => id.clone(),
        (None, OpRef::Named(id)) => masker.mask_text(id),
        (None, OpRef::Proxy { method, path }) => masker.mask_text(&format!("{method} {path}")),
    };
    tr.params = call
        .params
        .iter()
        .map(|(k, v)| (masker.mask_text(k), masker.mask_text(v)))
        .collect();
    tr.duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    (outcome, tr)
}

fn denied(rule: &str) -> Outcome {
    Outcome::Denied {
        rule: rule.to_string(),
    }
}

/// The rule for a step 4–5 error.
pub(crate) fn rule_of(e: &BrokerError) -> &'static str {
    match e {
        BrokerError::BadPath(_) => "bad_path",
        BrokerError::UnknownOperation(_) => "unknown_operation",
        BrokerError::UnknownParam(_)
        | BrokerError::FixedParam(_)
        | BrokerError::BadValue { .. }
        | BrokerError::MissingParam(_) => "bad_param",
        BrokerError::BadAmount(_) => "bad_amount",
        BrokerError::RedirectRefused => "redirect_refused",
        BrokerError::RedactNonJson => "redact_non_json",
        _ => "policy_invalid",
    }
}

#[allow(clippy::too_many_arguments)]
async fn steps(
    call: &Call,
    stage: Stage<'_>,
    snap: &PolicySnapshot,
    cat: &Catalog,
    lim: &Limiter,
    env: &dyn Env,
    up: Option<&Upstream>,
    tr: &mut Trace,
    masker: &mut Masker,
) -> Outcome {
    let cfg = &snap.config;
    // The record's params are masked with the service's secret values even
    // when the call is denied before step 9 (nothing is sent for this). A
    // vault that cannot be read leaves the v1 patterns only; the agent
    // supplied those params.
    if let Some(name) = cfg
        .services
        .get(&call.service)
        .and_then(|s| s.secret.as_deref())
    {
        if let Some(values) = env.secret_values(name) {
            let refs: Vec<&str> = values.iter().map(|v| v.as_str()).collect();
            *masker = Masker::new(&refs);
        }
    }
    // 2. Lockdown (either scope). The flag is read once, here: a request
    // already past this point when lockdown is turned on runs to its end
    // (it was admitted before the flag); every later request is denied.
    // `lockdown.set` does not wait for requests in flight.
    if env.lockdown().is_some() {
        return denied("lockdown");
    }
    // An approved request the policy in force no longer lets through
    // (decision 2): its scope or its verdict changed since it was asked.
    let changed = |rule: &str| match stage {
        Stage::New => denied(rule),
        Stage::Approved { .. } => denied("policy_changed"),
    };
    // 3. Scope.
    let scope = match env.scope(&call.user) {
        Ok(Some(s)) => s,
        Ok(None) => return changed("no_scope"),
        Err(PolicyError::ScopeConflict { .. }) => return changed("scope_conflict"),
        Err(_) => return denied("policy_invalid"),
    };
    // The environment the snapshot was chosen for (the scope's, in locked
    // mode): the record names the policy the call ran under.
    tr.env = snap.env.clone();
    if !scope.services.iter().any(|s| s == &call.service) {
        return changed("no_scope");
    }
    let Some(svc) = cfg.services.get(&call.service) else {
        // Listed in the scope but not defined: nothing to call.
        return changed("no_scope");
    };
    let m: std::borrow::Cow<'_, Manifest> = match cat.manifest_for(&call.service, svc) {
        Ok(m) => m,
        Err(_) => return denied("policy_invalid"),
    };

    // 4. Resolve the operation; 5. validate the parameters. Proxy captures
    // are agent input like named parameters and are validated the same way.
    let (op, given): (&Operation, BTreeMap<String, String>) = match &call.op {
        OpRef::Named(id) => match resolve::named(&m, id) {
            Some(op) => (op, call.params.clone()),
            None => {
                tr.operation = Some(id.clone());
                return denied("unknown_operation");
            }
        },
        OpRef::Proxy { method, path } => match resolve::proxy(&m, method, path) {
            Ok((op, mut caps)) => {
                for (k, v) in &call.params {
                    if caps.insert(k.clone(), v.clone()).is_some() {
                        tr.operation = Some(op.id.clone());
                        return denied("bad_param");
                    }
                }
                (op, caps)
            }
            Err(e) => return denied(rule_of(&e)),
        },
    };
    tr.operation = Some(op.id.clone());
    tr.op_kind = Some(op.kind);
    let mut params = match params::validate(op, &given, &svc.fixed) {
        Ok(p) => p,
        Err(e) => return denied(rule_of(&e)),
    };
    // Mail: defaults and case are settled before the policy looks.
    crate::mail::normalize(op, &mut params);
    let prepared = match prepare_body(op, &params, call.body.as_ref()) {
        Ok(p) => p,
        Err(rule) => return denied(rule),
    };
    if let Some(b) = &prepared.bytes {
        // The record describes what is sent.
        tr.body_bytes = b.len();
        tr.body_sha256 = prepared.sha256();
    }
    let body = prepared.bytes.clone();
    let json_body = prepared.json.as_ref();

    // An approved request sends only the bytes whose hash its approver saw.
    if let Stage::Approved { body_sha256 } = stage {
        let now = body.as_ref().map(|b| hex(&Sha256::digest(b)));
        if now.as_deref() != body_sha256 {
            return denied("body_changed");
        }
    }

    // 6. Policy.
    let (cap, verdict) =
        match crate::judge::policy_verdict(op, svc, call.overlay.as_ref(), snap.mode, &params) {
            Ok(v) => v,
            Err(rule) => return denied(rule),
        };
    tr.capability = Some(match &cap.qualifier {
        Some(q) => format!("{}:{}:{q}", cap.resource, cap.verb),
        None => format!("{}:{}", cap.resource, cap.verb),
    });
    // Approved: `ask` or `allow` now both send.
    let ask = match verdict {
        Verdict::Deny { rule } => return changed(&rule),
        Verdict::Ask => stage == Stage::New,
        Verdict::Allow => false,
    };

    // 7. Limits. An operation that moves money must carry its amount.
    if let Some(spec) = &op.amount {
        match json_body.map(|v| amount::extract(spec, v, &svc.params)) {
            Some(Ok(a)) => tr.amount = Some(a),
            _ => return denied("bad_amount"),
        }
    }
    let key = Key {
        uid: call.uid,
        service: call.service.clone(),
        session: call.session.clone(),
    };
    let now = OffsetDateTime::now_utc();
    // The limits could not be rebuilt at start: fail closed.
    if lim.unavailable(now) {
        return denied("limits_unavailable");
    }
    // 8. Ask (decision 1): the limits are checked without reserving, so a
    // request that could never be sent is denied now with its limit; the
    // send counts it for real. Then the request is stored and waits.
    if ask {
        if let Err(limit) = lim.would_allow(
            &key,
            op.kind,
            tr.amount.as_ref().map(|(m, c)| (*m, c.as_str())),
            op.amount.is_some(),
            &svc.limits,
            now,
        ) {
            return Outcome::Limited { limit };
        }
        // The approver must see what will be sent: a body the masker
        // changes (a vault value, or a v1 pattern that may swallow JSON
        // after it) cannot be shown faithfully, so it cannot be approved.
        // The same rule as for commands.
        let mut display = None;
        if let Some(b) = body.as_ref() {
            match faithful_display(masker, b) {
                Some(text) => display = Some(cut_display(&text, BODY_DISPLAY_MAX)),
                None => return denied(MASKED_CONTENT_RULE),
            }
        }
        let pending = PendingCall {
            stored: StoredCall {
                uid: call.uid,
                user: call.user.clone(),
                session: call.session.clone(),
                project: call.project.clone(),
                service: call.service.clone(),
                operation: op.id.clone(),
                params: given.clone(),
                // The agent's body as canonical JSON (none for a built
                // body): at send it is prepared again, and the bytes must
                // hash to `body_sha256`.
                body_b64: prepared.input.as_ref().map(|b| {
                    use base64::Engine as _;
                    base64::engine::general_purpose::STANDARD.encode(b)
                }),
                body_sha256: body.as_ref().map(|b| hex(&Sha256::digest(b))),
                headers: call.headers.clone(),
                overlay: call.overlay.clone(),
                via: call.via.as_str().to_string(),
                env: snap.env.clone(),
                env_recorded: true,
                collection: call.collection.clone(),
            },
            operation: masker.mask_text(&op.id),
            capability: tr.capability.as_deref().map(|c| masker.mask_text(c)),
            params: masker.mask_params(&given),
            project: masker.mask_text(&call.project),
            body_display: display.as_ref().map(|d| d.0.clone()),
            body_truncated: display.is_some_and(|d| d.1),
            body_sha256: body.as_ref().map(|b| hex(&Sha256::digest(b))),
            amount: tr.amount.clone(),
            headers: call
                .headers
                .iter()
                .map(|(k, v)| (masker.mask_text(k), masker.mask_text(v)))
                .collect(),
        };
        return match env.create_approval(&pending).await {
            Ok(id) => Outcome::Pending { id },
            Err(rule) => Outcome::Denied { rule },
        };
    }
    let reservation = match lim.check_and_commit(
        &key,
        op.kind,
        tr.amount.as_ref().map(|(m, c)| (*m, c.as_str())),
        op.amount.is_some(),
        &svc.limits,
        now,
    ) {
        Ok(r) => r,
        Err(limit) => return Outcome::Limited { limit },
    };

    // 9. Send. Without an upstream client (it could not be built at start)
    // nothing can be sent: a deny, after every earlier check ran.
    let Some(up) = up else {
        return denied("upstream_unavailable");
    };
    tr.secret = svc.secret.clone();
    let mut auth = match &svc.secret {
        Some(name) => match env.secret(name, &call.service, &m.auth) {
            Ok(a) => a,
            Err(rule) => return denied(rule),
        },
        None if m.auth.is_empty() => AuthMaterial::none(),
        None => return denied("secret_missing"),
    };
    // ---- oauth2 (plan 14, Task 7) ----
    // The access token comes from the daemon's memory (refreshed there when
    // due), never from the vault.
    let oauth: Option<(&str, &AuthSpec)> = match (&svc.secret, auth.kind == "oauth2") {
        (Some(name), true) => match m.auth.iter().find(|a| a.kind == "oauth2") {
            Some(spec) => Some((name.as_str(), spec)),
            None => return denied("secret_missing"),
        },
        _ => None,
    };
    if let Some((name, spec)) = oauth {
        match env
            .oauth_token(name, &call.service, spec, &m, &svc.params, false)
            .await
        {
            Ok(t) => {
                auth.fields.insert("access_token".into(), t);
            }
            Err(rule) => return denied(rule),
        }
    }
    // Every value of the secret in use (each field and the basic pair; for
    // oauth2 the access token, and the refresh token as the vault holds it
    // now, rotated or not).
    let mut mask_values = auth.values();
    if let Some(v) = oauth.and_then(|(name, _)| env.secret_values(name)) {
        mask_values.extend(v);
    }
    *masker = masker_of(&mask_values);
    // ---- end oauth2 ----
    // ---- mail transport (plan 14, Task 6) ----
    // A mail call builds no HTTP request: its params are checked here,
    // before anything counts, and the credential is kept for `mail::run`.
    let mail = m.transport == Transport::Mail;
    if mail {
        if let Err(e) = crate::mail::check_call(op, &svc.params, &params, body.as_ref()) {
            return denied(rule_of(&e));
        }
    }
    let (mut built, mail_auth) = if mail {
        (None, Some(auth))
    } else {
        let b = match build(
            &m,
            op,
            &svc.params,
            &params,
            &call.headers,
            body.clone(),
            &auth,
        ) {
            Ok(b) => b,
            Err(e) => return denied(rule_of(&e)),
        };
        drop(auth);
        (Some(b), None)
    };
    // ---- end mail transport ----
    if let Some(built) = built.as_mut() {
        // Compressed bytes never reach the masker: ask for none.
        built
            .headers
            .insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
        if let Some(ct) = prepared.content_type {
            // The body is the canonical JSON or its form encoding: say so,
            // whatever the agent sent.
            built
                .headers
                .insert(CONTENT_TYPE, HeaderValue::from_static(ct));
        }
    }
    let max = svc
        .limits
        .max_response_bytes
        .unwrap_or(cfg.gateway.max_response_bytes);
    let max = usize::try_from(max).unwrap_or(usize::MAX);
    let read_limit = max.saturating_add(READ_SLACK);
    let pool = env.pool(&call.service);
    // The wait for a pool slot is bounded by the upstream timeout; a full
    // pool is a limit (`concurrency`), and a closed one fails closed: a
    // deny (nothing was sent, so nothing counts, here or at a rebuild).
    // The daemon's worst case is therefore twice the upstream timeout.
    let permit = match tokio::time::timeout(up.timeout(), pool.acquire_owned()).await {
        Ok(Ok(p)) => p,
        Ok(Err(_)) => return denied("upstream_unavailable"),
        Err(_) => {
            return Outcome::Limited {
                limit: "concurrency",
            }
        }
    };
    // Decision 6: what was sent counts, whatever came back. Committed
    // before the send, so a caller that drops this future mid-send (a
    // client gone) cannot release a slot the upstream may have used.
    reservation.commit();
    let sent = {
        let _permit = permit;
        tr.sent = true;
        // ---- mail transport (plan 14, Task 6): SMTP or IMAP, not HTTPS ----
        match (built, mail_auth) {
            (Some(b), _) => up.send(b, read_limit).await,
            (None, Some(a)) => {
                let r = crate::mail::run(
                    up,
                    &m,
                    op,
                    &svc.params,
                    &params,
                    body.clone(),
                    &a,
                    read_limit,
                )
                .await;
                drop(a);
                r
            }
            (None, None) => Err(BrokerError::Upstream("no request was built".into())),
        }
        // ---- end mail transport ----
    };
    let mut resp = match sent {
        Ok(r) => r,
        Err(BrokerError::RedirectRefused) => return denied("redirect_refused"),
        Err(e) => {
            return Outcome::UpstreamFailed {
                reason: e.to_string(),
            }
        }
    };
    // ---- oauth2 retry (plan 14, Task 7) ----
    // A 401 with an oauth2 credential: the session expired or was revoked.
    // One forced refresh and one resend; a second 401 is the answer, and so
    // is the first when the refresh fails (its failure is recorded by the
    // daemon). The resend counts with the first send.
    if resp.status == 401 && !mail {
        if let Some((name, spec)) = oauth {
            if let Ok(t) = env
                .oauth_token(name, &call.service, spec, &m, &svc.params, true)
                .await
            {
                mask_values.push(t.clone());
                // A refresh token rotated by this refresh, too.
                mask_values.extend(env.secret_values(name).unwrap_or_default());
                *masker = masker_of(&mask_values);
                let a = AuthMaterial::from_spec(spec, [("access_token".to_string(), t)].into());
                if let Ok(mut b) = build(
                    &m,
                    op,
                    &svc.params,
                    &params,
                    &call.headers,
                    body.clone(),
                    &a,
                ) {
                    drop(a);
                    b.headers
                        .insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
                    if let Some(ct) = prepared.content_type {
                        b.headers.insert(CONTENT_TYPE, HeaderValue::from_static(ct));
                    }
                    let permit =
                        tokio::time::timeout(up.timeout(), env.pool(&call.service).acquire_owned())
                            .await;
                    if let Ok(Ok(_permit)) = permit {
                        tr.auth_retry = true;
                        resp = match up.send(b, read_limit).await {
                            Ok(r) => r,
                            Err(BrokerError::RedirectRefused) => return denied("redirect_refused"),
                            Err(e) => {
                                return Outcome::UpstreamFailed {
                                    reason: e.to_string(),
                                }
                            }
                        };
                    }
                }
            }
        }
    }
    // ---- end oauth2 retry ----
    tr.status = Some(resp.status);
    if resp
        .headers
        .get_all(CONTENT_ENCODING)
        .iter()
        .any(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"))
    {
        return Outcome::UpstreamFailed {
            reason: "compressed response refused".into(),
        };
    }

    // 10. Mask, redact, cut.
    let finished = match finish(
        resp.status,
        resp.headers,
        resp.body,
        resp.truncated,
        masker,
        &svc.redact.fields,
        max,
    ) {
        Ok(f) => f,
        Err(BrokerError::RedactNonJson) => return denied("redact_non_json"),
        Err(e) => {
            return Outcome::UpstreamFailed {
                reason: e.to_string(),
            }
        }
    };
    tr.resp_bytes = Some(finished.body.len());
    let next = next_page(op, &given, &finished);
    // 11 and 12: the caller writes the record and returns the result.
    Outcome::Done { finished, next }
}

/// The parameters of the next page (decision 8), from a cursor in the
/// masked JSON body or the `rel="next"` link. Only the operation's own
/// query parameters are taken from a link.
fn next_page(
    op: &Operation,
    given: &BTreeMap<String, String>,
    f: &Finished,
) -> Option<BTreeMap<String, String>> {
    match op.pagination.as_ref()? {
        p @ (Pagination::Cursor { .. } | Pagination::Offset { .. }) => {
            let v: Value = serde_json::from_slice(&f.body).ok()?;
            let (param, value) = crate::request::next_cursor(p, &v)?;
            let mut out = given.clone();
            out.insert(param, value);
            Some(out)
        }
        Pagination::LinkHeader => crate::request::next_from_link(op, given, &f.headers),
    }
}

/// The request body of one call, ready to send (step 5).
#[derive(Clone, Default)]
pub struct PreparedBody {
    /// The bytes sent upstream.
    pub bytes: Option<Bytes>,
    /// The JSON the bytes encode, which the amount is read from.
    pub json: Option<Value>,
    /// The agent's body as canonical JSON, stored with an approval request
    /// and prepared again at send. `None` for a built body.
    pub input: Option<Bytes>,
    /// The `Content-Type` the broker sets.
    pub content_type: Option<&'static str>,
}

impl std::fmt::Debug for PreparedBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedBody")
            .field("bytes_len", &self.bytes.as_ref().map(Bytes::len))
            .field("content_type", &self.content_type)
            .finish()
    }
}

impl PreparedBody {
    /// SHA-256 (hex) of the bytes sent.
    pub fn sha256(&self) -> Option<String> {
        self.bytes.as_ref().map(|b| hex(&Sha256::digest(b)))
    }
}

/// Builds the body of `op` (decision 2). An operation with `body_params`,
/// `body_const` or `graphql` builds its body from the validated `params`
/// and refuses one from the agent (`bad_param`); otherwise the agent's body
/// is parsed once, strictly (a duplicate key is `bad_body`), and its
/// canonical JSON, or for `body = "form"` that JSON form-encoded, is what
/// goes upstream: the amount checked is the amount sent, whatever parser
/// the upstream uses.
pub fn prepare_body(
    op: &Operation,
    params: &BTreeMap<String, String>,
    raw: Option<&Bytes>,
) -> Result<PreparedBody, &'static str> {
    let raw = raw.filter(|b| !b.is_empty());
    if raw.is_some() && (op.body.is_none() || op.builds_body()) {
        return Err("bad_param");
    }
    // `text` (mail only): UTF-8, at most 256 KiB, sent as given.
    if op.body.as_deref() == Some("text") {
        let Some(b) = raw else {
            return Ok(PreparedBody::default());
        };
        if b.len() > crate::mail::MAX_BODY || std::str::from_utf8(b).is_err() {
            return Err("bad_body");
        }
        return Ok(PreparedBody {
            bytes: Some(b.clone()),
            json: None,
            input: Some(b.clone()),
            content_type: Some("text/plain; charset=utf-8"),
        });
    }
    let (json, input) = if op.builds_body() {
        (
            crate::request::build_body(op, params).map_err(|e| rule_of(&e))?,
            None,
        )
    } else {
        match raw {
            None => (None, None),
            Some(b) => {
                let v = strict_json(b).ok_or("bad_body")?;
                let canon = serde_json::to_vec(&v).map_err(|_| "bad_body")?;
                (Some(v), Some(Bytes::from(canon)))
            }
        }
    };
    let Some(v) = json else {
        return Ok(PreparedBody::default());
    };
    let (bytes, content_type) = match op.body.as_deref() {
        Some("json") => (
            serde_json::to_vec(&v).map_err(|_| "bad_body")?,
            "application/json",
        ),
        Some("form") => (
            crate::request::form_encode(&v)
                .map_err(|_| "bad_body")?
                .into_bytes(),
            "application/x-www-form-urlencoded",
        ),
        _ => return Err("bad_body"),
    };
    Ok(PreparedBody {
        bytes: Some(Bytes::from(bytes)),
        json: Some(v),
        input,
        content_type: Some(content_type),
    })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn op_kind_str(k: OpKind) -> &'static str {
    match k {
        OpKind::Read => "read",
        OpKind::Write => "write",
        OpKind::Delete => "delete",
        OpKind::Bulk => "bulk",
    }
}

fn parse_op_kind(s: &str) -> Option<OpKind> {
    match s {
        "read" => Some(OpKind::Read),
        "write" => Some(OpKind::Write),
        "delete" => Some(OpKind::Delete),
        "bulk" => Some(OpKind::Bulk),
        _ => None,
    }
}

/// The `connector` record of a call (§8.5), plus `op_kind` and `amount`
/// (`{minor, currency}`), which the limiter is rebuilt from. The caller
/// (the daemon) sets `uid`, `user` and `peer`. `params` are masked; the
/// body is never stored, only its SHA-256 and size.
pub fn record(
    call: &Call,
    snap: &PolicySnapshot,
    tr: &Trace,
    outcome: &Outcome,
    agent: &str,
    saiife_version: &str,
) -> Record {
    // Masked in `run` (agent input).
    let op_name = if tr.op_label.is_empty() {
        tr.operation.clone().unwrap_or_default()
    } else {
        tr.op_label.clone()
    };
    let mut input = format!("{} {op_name}", call.service);
    for (k, v) in &tr.params {
        input.push_str(&format!(" {k}={v}"));
    }
    let (decision, rule, reason, limit) = match outcome {
        Outcome::Done { .. } => (DecisionKind::Allow, None, None, None),
        Outcome::Denied { rule } => (
            DecisionKind::Deny,
            Some(rule.clone()),
            deny_reason(rule).map(str::to_string),
            None,
        ),
        Outcome::Limited { limit } => (
            DecisionKind::Deny,
            None,
            Some(format!("limit reached: {limit}")),
            Some(*limit),
        ),
        Outcome::UpstreamFailed { reason } => (
            DecisionKind::Allow,
            None,
            Some(format!("upstream failed: {reason}")),
            None,
        ),
        Outcome::Pending { id } => (
            DecisionKind::Ask,
            None,
            Some(format!("waiting for approval #{id}")),
            None,
        ),
    };
    let project = match &tr.project {
        Some(p) => p.clone(),
        None => Masker::new(&[]).mask_text(&call.project),
    };
    let mut r = Record::new(
        NewRecord {
            agent,
            project: &project,
            session: call.session.as_deref(),
            // An MCP tool call is recorded as the tool `mcp` (decision 4).
            tool: match call.via {
                Via::Mcp => "mcp",
                Via::Cli | Via::Http | Via::Approval => "api",
            },
            input: &input,
            decision,
            pack: None,
            rule: rule.as_deref(),
            reason: reason.as_deref(),
            mode: match snap.mode {
                Mode::Locked => "locked",
                Mode::Developer => "developer",
            },
            policy: Some(&snap.hash),
            permission_mode: None,
        },
        saiife_version,
    );
    r.kind = Some("connector".into());
    r.uid = Some(call.uid);
    r.user = Some(call.user.clone());
    let e = &mut r.extra;
    e.insert("service".into(), call.service.clone().into());
    e.insert("operation".into(), json!(tr.operation));
    e.insert("capability".into(), json!(tr.capability));
    e.insert("env".into(), json!(tr.env));
    // A collection name is `[a-z0-9_-]{1,64}`; masked like the project all
    // the same (a name can look like a token).
    e.insert(
        "collection".into(),
        json!(call
            .collection
            .as_deref()
            .map(|c| Masker::new(&[]).mask_text(c))),
    );
    e.insert("params".into(), json!(tr.params));
    e.insert("body_sha256".into(), json!(tr.body_sha256));
    e.insert("body_bytes".into(), json!(tr.body_bytes));
    e.insert("status".into(), json!(tr.status));
    e.insert("resp_bytes".into(), json!(tr.resp_bytes));
    e.insert("duration_ms".into(), json!(tr.duration_ms));
    e.insert("secret".into(), json!(tr.secret));
    e.insert("limit".into(), json!(limit));
    e.insert("via".into(), call.via.as_str().into());
    if tr.auth_retry {
        e.insert("auth_retry".into(), true.into());
    }
    if let Outcome::Pending { id } = outcome {
        e.insert("approval".into(), (*id).into());
    }
    e.insert("op_kind".into(), json!(tr.op_kind.map(op_kind_str)));
    e.insert(
        "amount".into(),
        match &tr.amount {
            Some((m, c)) => json!({"minor": m, "currency": c}),
            None => Value::Null,
        },
    );
    r
}

/// The limiter event of a `connector` record of a request that was sent,
/// for the rebuild at start (Task 3). Sent means: allowed (done or failed
/// upstream) or denied after sending ([`POST_SEND_RULES`]).
pub fn limit_event(r: &Record) -> Option<Event> {
    if r.kind() != "connector" {
        return None;
    }
    let sent = r.decision == DecisionKind::Allow
        || r.rule
            .as_deref()
            .is_some_and(|x| POST_SEND_RULES.contains(&x));
    if !sent {
        return None;
    }
    let kind = parse_op_kind(r.extra.get("op_kind")?.as_str()?)?;
    let service = r.extra.get("service")?.as_str()?.to_string();
    let amount_minor = r.extra.get("amount").and_then(|a| {
        Some((
            a.get("minor")?.as_u64()?,
            a.get("currency")?.as_str()?.to_string(),
        ))
    });
    Some(Event {
        at: r.timestamp()?,
        key: Key {
            uid: r.uid?,
            service,
            session: r.session.clone(),
        },
        kind,
        amount_minor,
    })
}

/// `api.list` for one service: `{id, capability, kind, action}` per
/// operation, the action as the policy would decide it with no parameters.
/// With `schema`, also the MCP tool's `title`, `input_schema`
/// ([`crate::tool_schema::input_schema`]) and, when the operation takes an
/// agent body, `body_arg` (`json` or `text`): how its `body` argument is
/// sent, since a param may itself be named `body`.
pub fn list_operations(
    name: &str,
    snap: &PolicySnapshot,
    cat: &Catalog,
    overlay: Option<&ServiceOverlay>,
    schema: bool,
) -> Option<Vec<Value>> {
    let svc = snap.config.services.get(name)?;
    let m = cat.manifest_for(name, svc).ok()?;
    let empty = BTreeMap::new();
    Some(
        m.operation
            .iter()
            .map(|op| {
                let action = match Capability::parse(&op.capability) {
                    Ok(mut cap) => {
                        if op.qualifier.is_some() {
                            cap.qualifier = op.qualifier.clone();
                        }
                        match decide(
                            svc,
                            overlay,
                            snap.mode,
                            &Request {
                                capability: &cap,
                                params: &empty,
                            },
                        ) {
                            Verdict::Allow => "allow",
                            Verdict::Ask => "ask",
                            Verdict::Deny { .. } => "deny",
                        }
                    }
                    Err(_) => "deny",
                };
                let mut o = Map::new();
                o.insert("id".into(), op.id.clone().into());
                o.insert("capability".into(), op.capability.clone().into());
                o.insert("kind".into(), op_kind_str(op.kind).into());
                o.insert("action".into(), action.into());
                if schema {
                    o.insert("title".into(), format!("{}: {}", m.title, op.id).into());
                    o.insert(
                        "input_schema".into(),
                        crate::tool_schema::input_schema(&m, op, svc),
                    );
                    if let Some(b) = crate::tool_schema::body_arg(op) {
                        o.insert("body_arg".into(), b.as_str().into());
                    }
                }
                Value::Object(o)
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn faithful_display_compares_bytes_and_refuses_non_utf8() {
        let m = Masker::new(&["s3cr3t-vault-value"]);
        assert_eq!(
            faithful_display(&m, b"{\"a\":1}").as_deref(),
            Some("{\"a\":1}")
        );
        // Not UTF-8: refused even though nothing is masked.
        assert_eq!(faithful_display(&m, b"{\"a\":\"\xff\xfe\"}"), None);
        // A vault value, also beside invalid bytes (a lossy view would
        // have replaced the bytes and hidden the difference).
        assert_eq!(faithful_display(&m, b"x s3cr3t-vault-value y"), None);
        assert_eq!(faithful_display(&m, b"\xff s3cr3t-vault-value"), None);
        // A v1 pattern.
        assert_eq!(faithful_display(&m, b"API_TOKEN=x"), None);
    }

    #[test]
    fn cut_display_cuts_on_a_char_boundary_and_says_so() {
        assert_eq!(cut_display("abc", 3), ("abc".to_string(), false));
        let (s, cut) = cut_display("aé€", 2);
        assert!(cut);
        assert_eq!(s, "a…[truncated: 6 bytes in all]");
        assert_eq!(BODY_DISPLAY_MAX, 1024 * 1024);
    }

    #[test]
    fn call_debug_hides_values() {
        let c = Call {
            uid: 1,
            user: "u".into(),
            session: None,
            project: "/p".into(),
            service: "s".into(),
            op: OpRef::Named("o".into()),
            params: [("k".to_string(), "secret-param-value".to_string())].into(),
            body: Some(Bytes::from_static(b"secret-body")),
            headers: vec![("X-A".into(), "secret-header".into())],
            overlay: None,
            via: Via::Cli,
            collection: None,
        };
        let d = format!("{c:?}");
        assert!(!d.contains("secret-"), "{d}");
        assert!(d.contains("body_len"), "{d}");
    }
}
