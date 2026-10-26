//! `api.call`, `api.list` and `api.result` (spec §6.7, §8.7): connector
//! requests over the control socket. Step 1 of the pipeline happens here
//! (uid from the peer credentials, the session by attribution, the project
//! as the client reports it); steps 3–12 are `saiife_broker::pipeline`.
//! Every call writes one `connector` record before it answers.

use crate::ops::{Ctx, GatewayPolicy, Notice, VERSION};
use crate::sessions::agent_ancestor;
use crate::vault::{Kind, VaultState};
use base64::Engine as _;
use bytes::Bytes;
use saiife_broker::manifest::AuthSpec;
use saiife_broker::pipeline::{self, Call, Env, OpRef, Outcome, PolicySnapshot, Trace, Via};
use saiife_broker::request::AuthMaterial;
use saiife_ipc::frame::MAX_ANSWER_FRAME;
use saiife_ipc::msg::{err, err_with, ok, ErrorCode, Request, OP_API_LIST, OP_API_RESULT};
use saiife_ipc::peer::{comm, PeerCred};
use saiife_policy::{
    scope_for, Directory, GroupEntry, Mode, PolicyError, Scope, ServiceOverlay, SystemConfig,
    UserEntry,
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
        OP_API_RESULT => err(req.id, ErrorCode::Unavailable, "approvals come in plan 11"),
        OP_API_LIST => list(ctx, peer, req).await,
        _ => call(ctx, peer, req).await,
    }
}

/// The caller's directory view for one request: its groups, looked up
/// (cached, off the runtime thread) before the pipeline runs.
struct Groups(Vec<String>);

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

struct DaemonEnv<'a> {
    ctx: &'a Ctx,
    config: &'a SystemConfig,
    groups: Groups,
}

/// The auth entry a vault kind can fill: `basic` the basic one, `token` a
/// bearer or a header reading `token`, `header` one reading `value`.
fn spec_for(kind: Kind, auth: &[AuthSpec]) -> Option<&AuthSpec> {
    auth.iter().find(|a| match kind {
        Kind::Basic => a.kind == "basic",
        Kind::Token => matches!(a.kind.as_str(), "bearer" | "header") && a.secret_field == "token",
        Kind::Header => a.kind == "header" && a.secret_field == "value",
    })
}

fn kind_str(k: Kind) -> &'static str {
    match k {
        Kind::Token => "token",
        Kind::Basic => "basic",
        Kind::Header => "header",
    }
}

impl Env for DaemonEnv<'_> {
    fn scope(&self, user: &str) -> Result<Option<Scope>, PolicyError> {
        scope_for(self.config, &self.groups, user).map(|s| s.cloned())
    }

    fn secret(
        &self,
        name: &str,
        service: &str,
        auth: &[AuthSpec],
    ) -> Result<AuthMaterial, &'static str> {
        let mut g = self.ctx.vault.lock().unwrap_or_else(|p| p.into_inner());
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
        let g = self.ctx.vault.lock().unwrap_or_else(|p| p.into_inner());
        let VaultState::Ready(v) = &*g else {
            return None;
        };
        let e = v.get(name)?;
        let m = AuthMaterial {
            kind: kind_str(e.kind).to_string(),
            name: None,
            fields: e.fields.clone(),
        };
        Some(m.values())
    }

    fn pool(&self, service: &str) -> Arc<Semaphore> {
        self.ctx.pools.get(service)
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

fn valid_service(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
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

/// The arguments of `api.call`, checked. Errors never quote a value.
fn parse_call(args: &Map<String, Value>) -> Result<(String, OpRef, Call), &'static str> {
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
    // `wait_ms` is accepted and ignored until plan 11.
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
    };
    Ok((service, op, call))
}

/// The audit-volume gate (as for `audit.append`): a call that cannot be
/// recorded is not made.
fn disk_ok(ctx: &Ctx, peer: &PeerCred) -> Result<(), ErrorCode> {
    let free = crate::disk::free_mb(&ctx.audit_dir).unwrap_or(0);
    crate::disk::disk_gate(free, ctx.policy().min_free_mb, peer.uid, ctx.own_uid)
}

/// A snapshot for the record of a call made without a valid policy.
fn no_policy_snapshot(hash: Option<String>) -> PolicySnapshot {
    PolicySnapshot {
        config: toml::from_str("version = 2").expect("a minimal config parses"),
        hash: hash.unwrap_or_default(),
        mode: Mode::Locked,
    }
}

async fn call(ctx: &Arc<Ctx>, peer: &PeerCred, req: Request) -> Value {
    let id = req.id;
    let (_service, _op, mut call) = match parse_call(&req.args) {
        Ok(x) => x,
        Err(m) => return bad(id, m),
    };
    if let Err(code) = disk_ok(ctx, peer) {
        ctx.notice(peer.uid, Notice::LowDisk);
        return err(id, code, "the audit volume is below [audit] min_free_mb");
    }
    // 1. Identify: the peer's uid, the session by attribution.
    call.uid = peer.uid;
    call.user = ctx.name_of(peer.uid).await.unwrap_or_default();
    let ancestor = agent_ancestor(ctx.proc.as_ref(), peer.pid);
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
    let (outcome, trace, snap): (Outcome, Trace, Arc<GatewayPolicy>) = match &state.gateway {
        Some(g) => {
            let env = DaemonEnv {
                ctx,
                config: &g.snap.config,
                groups: Groups(groups),
            };
            // Without an upstream client steps 3–8 still run; step 9
            // denies with `upstream_unavailable`.
            let up = ctx.upstream.as_ref().ok();
            let (o, t) = pipeline::run(&call, &g.snap, &g.catalog, &ctx.limiter, &env, up).await;
            (o, t, Arc::clone(g))
        }
        None => (
            Outcome::Denied {
                rule: "policy_invalid".into(),
            },
            Trace::default(),
            Arc::new(GatewayPolicy {
                snap: no_policy_snapshot(state.hash.clone()),
                catalog: Default::default(),
            }),
        ),
    };

    // 11. Record (before the answer: an unrecorded result is withheld).
    let mut rec = pipeline::record(&call, &snap.snap, &trace, &outcome, &agent, VERSION);
    if snap.snap.hash.is_empty() {
        rec.policy = None;
    }
    rec.extra.insert(
        "peer".into(),
        json!({"pid": peer.pid, "comm": comm(peer.pid)}),
    );
    if let Err(e) = ctx.writer.append(rec).await {
        // A request that was sent is already counted by the limiter, but a
        // rebuild at the next start will not see it (it has no record). The
        // answer is withheld; the limits are briefly looser after a restart.
        return err(
            id,
            ErrorCode::Internal,
            &format!("the connector record could not be written: {e}"),
        );
    }

    // 12. Return.
    answer(id, outcome)
}

fn answer(id: u64, outcome: Outcome) -> Value {
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
        Outcome::Denied { rule } => err_with(
            id,
            ErrorCode::Denied,
            &format!("denied ({rule})"),
            one("rule", rule.into()),
        ),
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
    }
}

/// `api.list`: the services of the caller's scope and their operations,
/// each with the action the policy (and the client's overlay) gives it.
async fn list(ctx: &Arc<Ctx>, peer: &PeerCred, req: Request) -> Value {
    let id = req.id;
    let overlays = match parse_overlays(req.args.get("overlays")) {
        Ok(o) => o,
        Err(m) => return bad(id, m),
    };
    let mut services = Vec::new();
    let state = ctx.policy();
    let user = ctx.name_of(peer.uid).await;
    if let (Some(g), Some(user)) = (&state.gateway, user) {
        let groups = Groups(ctx.groups_of(&user).await);
        if let Ok(Some(scope)) = scope_for(&g.snap.config, &groups, &user) {
            for name in &scope.services {
                if let Some(ops) =
                    pipeline::list_operations(name, &g.snap, &g.catalog, overlays.get(name))
                {
                    services.push(json!({"name": name, "operations": ops}));
                }
            }
        }
    }
    let mut m = Map::new();
    m.insert("services".into(), Value::Array(services));
    ok(id, m)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(c.params["n"], "5");
        assert_eq!(c.body.as_deref(), Some(&b"hi"[..]));
        assert_eq!(c.overlay.unwrap().deny, vec!["*:write"]);
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
        };
        let bearer = AuthSpec {
            kind: "bearer".into(),
            name: None,
            secret_field: "token".into(),
        };
        let both = [header.clone(), bearer.clone()];
        assert_eq!(spec_for(Kind::Header, &both), Some(&header));
        assert_eq!(spec_for(Kind::Token, &both), Some(&bearer));
        assert_eq!(spec_for(Kind::Basic, &both), None);
    }
}
