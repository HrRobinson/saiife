//! The connector request pipeline (spec §6.7.1 steps 3–12), shared by every
//! entry point (`saiife api` over the control socket, the HTTP gateway).
//!
//! Steps 3–8 never touch the network: a request denied there costs no
//! upstream call. The daemon does step 1 (identity, session, project) and
//! hands over a [`Call`]; step 2 (lockdown) comes with plan 11.
//!
//! The policy is the [`PolicySnapshot`] taken when the call starts, so a
//! reload in flight cannot mix two policies, and the `connector` record
//! carries that snapshot's hash.

use crate::amount;
use crate::catalog::Catalog;
use crate::limits::{Event, Key, Limiter};
use crate::manifest::{AuthSpec, Manifest, OpKind, Operation, Pagination};
use crate::mask::{finish, Finished, Masker};
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
}

impl Via {
    pub fn as_str(self) -> &'static str {
        match self {
            Via::Cli => "cli",
            Via::Http => "http",
        }
    }
}

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
}

/// What the pipeline needs from the daemon.
pub trait Env: Sync {
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
}

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
    pub status: Option<u16>,
    pub resp_bytes: Option<usize>,
    pub duration_ms: u64,
    /// The request went to the upstream (it counts against the limits).
    pub sent: bool,
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
    let started = Instant::now();
    let mut tr = Trace {
        body_bytes: call.body.as_ref().map_or(0, Bytes::len),
        body_sha256: call.body.as_ref().map(|b| hex(&Sha256::digest(b))),
        ..Trace::default()
    };
    let mut masker = Masker::new(&[]);
    let outcome = steps(call, cfg, cat, lim, env, up, &mut tr, &mut masker).await;
    // Agent-supplied values go into the record masked with every vault
    // value in use (an agent may echo the token) and the v1 patterns: the
    // operation id or proxy request (§8.5) and the params.
    tr.operation = tr.operation.as_deref().map(|o| masker.mask_text(o));
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
fn rule_of(e: &BrokerError) -> &'static str {
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
    // 3. Scope.
    let scope = match env.scope(&call.user) {
        Ok(Some(s)) => s,
        Ok(None) => return denied("no_scope"),
        Err(PolicyError::ScopeConflict { .. }) => return denied("scope_conflict"),
        Err(_) => return denied("policy_invalid"),
    };
    tr.env = scope.env.clone();
    if !scope.services.iter().any(|s| s == &call.service) {
        return denied("no_scope");
    }
    let Some(svc) = cfg.services.get(&call.service) else {
        // Listed in the scope but not defined: nothing to call.
        return denied("no_scope");
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
    let params = match params::validate(op, &given, &svc.fixed) {
        Ok(p) => p,
        Err(e) => return denied(rule_of(&e)),
    };
    let mut body = call.body.clone().filter(|b| !b.is_empty());
    if body.is_some() && op.body.is_none() {
        return denied("bad_param");
    }
    // A JSON body is parsed once, strictly (a duplicate key is refused),
    // and the re-serialized tree is what goes upstream: the amount checked
    // is the amount sent, whatever parser the upstream uses.
    let mut json_body: Option<Value> = None;
    if op.body.as_deref() == Some("json") {
        if let Some(b) = &body {
            match strict_json(b) {
                Some(v) => {
                    match serde_json::to_vec(&v) {
                        Ok(canon) => {
                            // The record describes what is sent.
                            tr.body_bytes = canon.len();
                            tr.body_sha256 = Some(hex(&Sha256::digest(&canon)));
                            body = Some(Bytes::from(canon));
                        }
                        Err(_) => return denied("bad_body"),
                    }
                    json_body = Some(v);
                }
                None => return denied("bad_body"),
            }
        }
    }

    // 6. Policy.
    let Ok(mut cap) = Capability::parse(&op.capability) else {
        return denied("policy_invalid");
    };
    // The manifest's qualifier filled from the parameters; `None` when one
    // is missing (a deny/ask with a qualifier then still matches, an allow
    // does not).
    if op.qualifier.is_some() {
        cap.qualifier = crate::manifest::qualifier_for(op, &params);
    }
    tr.capability = Some(match &cap.qualifier {
        Some(q) => format!("{}:{}:{q}", cap.resource, cap.verb),
        None => format!("{}:{}", cap.resource, cap.verb),
    });
    let verdict = decide(
        svc,
        call.overlay.as_ref(),
        snap.mode,
        &Request {
            capability: &cap,
            params: &params,
        },
    );
    let ask = match verdict {
        Verdict::Deny { rule } => return Outcome::Denied { rule },
        Verdict::Ask => true,
        Verdict::Allow => false,
    };

    // 7. Limits. An operation that moves money must carry its amount.
    if let Some(spec) = &op.amount {
        match json_body.as_ref().map(|v| amount::extract(spec, v)) {
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

    // 8. Ask: approvals come with plan 11 (decision 1). The reservation is
    // dropped, so nothing is counted.
    if ask {
        return denied("approval_not_available");
    }

    // 9. Send. Without an upstream client (it could not be built at start)
    // nothing can be sent: a deny, after every earlier check ran.
    let Some(up) = up else {
        return denied("upstream_unavailable");
    };
    tr.secret = svc.secret.clone();
    let auth = match &svc.secret {
        Some(name) => match env.secret(name, &call.service, &m.auth) {
            Ok(a) => a,
            Err(rule) => return denied(rule),
        },
        None if m.auth.is_empty() => AuthMaterial::none(),
        None => return denied("secret_missing"),
    };
    {
        // Every value of the secret in use (each field and the basic pair).
        let values = auth.values();
        let refs: Vec<&str> = values.iter().map(|v| v.as_str()).collect();
        *masker = Masker::new(&refs);
    }
    let mut built = match build(
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
    // Compressed bytes never reach the masker: ask for none.
    built
        .headers
        .insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
    if json_body.is_some() {
        // The body is the canonical JSON: say so, whatever the agent sent.
        built
            .headers
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    }
    let max = svc
        .limits
        .max_response_bytes
        .unwrap_or(cfg.gateway.max_response_bytes);
    let max = usize::try_from(max).unwrap_or(usize::MAX);
    let read_limit = max.saturating_add(READ_SLACK);
    let pool = env.pool(&call.service);
    // The wait for a pool slot is bounded by the upstream timeout; a full
    // pool is a limit (`concurrency`), and a closed one fails closed. The
    // daemon's worst case is therefore twice the upstream timeout.
    let permit = match tokio::time::timeout(up.timeout(), pool.acquire_owned()).await {
        Ok(Ok(p)) => p,
        Ok(Err(_)) => {
            return Outcome::UpstreamFailed {
                reason: "the upstream pool is closed".into(),
            }
        }
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
        up.send(built, read_limit).await
    };
    let resp = match sent {
        Ok(r) => r,
        Err(BrokerError::RedirectRefused) => return denied("redirect_refused"),
        Err(e) => {
            return Outcome::UpstreamFailed {
                reason: e.to_string(),
            }
        }
    };
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
        p @ Pagination::Cursor { .. } => {
            let v: Value = serde_json::from_slice(&f.body).ok()?;
            let (param, value) = crate::request::next_cursor(p, &v)?;
            let mut out = given.clone();
            out.insert(param, value);
            Some(out)
        }
        Pagination::LinkHeader => {
            let link = f.headers.get_all("link").iter().find_map(|v| {
                v.to_str().ok()?.split(',').find_map(|part| {
                    let (url, attrs) = part.split_once(';')?;
                    let is_next = attrs.split(';').any(|a| {
                        let a = a.trim().to_ascii_lowercase();
                        a == "rel=\"next\"" || a == "rel=next"
                    });
                    is_next.then(|| {
                        url.trim()
                            .trim_start_matches('<')
                            .trim_end_matches('>')
                            .to_string()
                    })
                })
            })?;
            let query = link.split_once('?')?.1;
            let mut out: BTreeMap<String, String> = given
                .iter()
                .filter(|(k, _)| op.path_params.contains_key(*k))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            for pair in query.split('&') {
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                let dec = |s: &str| {
                    percent_encoding::percent_decode_str(&s.replace('+', " "))
                        .decode_utf8()
                        .ok()
                        .map(|c| c.into_owned())
                };
                let (Some(k), Some(v)) = (dec(k), dec(v)) else {
                    continue;
                };
                // `next` reaches a header and a CLI line: printable ASCII
                // without spaces, at most 256 bytes, like `next_cursor`.
                let printable =
                    !v.is_empty() && v.len() <= 256 && v.bytes().all(|b| (0x21..0x7f).contains(&b));
                if op.query.contains_key(&k) && printable {
                    out.insert(k, v);
                }
            }
            Some(out)
        }
    }
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
        Outcome::Denied { rule } => (DecisionKind::Deny, Some(rule.clone()), None, None),
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
    };
    let mut r = Record::new(
        NewRecord {
            agent,
            project: &call.project,
            session: call.session.as_deref(),
            tool: "api",
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
    e.insert("params".into(), json!(tr.params));
    e.insert("body_sha256".into(), json!(tr.body_sha256));
    e.insert("body_bytes".into(), json!(tr.body_bytes));
    e.insert("status".into(), json!(tr.status));
    e.insert("resp_bytes".into(), json!(tr.resp_bytes));
    e.insert("duration_ms".into(), json!(tr.duration_ms));
    e.insert("secret".into(), json!(tr.secret));
    e.insert("limit".into(), json!(limit));
    e.insert("via".into(), call.via.as_str().into());
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
pub fn list_operations(
    name: &str,
    snap: &PolicySnapshot,
    cat: &Catalog,
    overlay: Option<&ServiceOverlay>,
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
                Value::Object(o)
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
        };
        let d = format!("{c:?}");
        assert!(!d.contains("secret-"), "{d}");
        assert!(d.contains("body_len"), "{d}");
    }
}
