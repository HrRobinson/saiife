//! `cloud.lease {service, exe}` (plan 15, STS mode): short AWS session
//! credentials for one listed command, which `saiife run --cloud` puts in
//! that command's environment.
//!
//! Each lease is its own `sts:AssumeRole` call: [`sts::LEASE_SECONDS`]
//! (900 s), the service's `role_arn` and `external_id`, and an inline
//! session policy built from the saiife policy of the service
//! ([`session_policy::build`]), so the session can do no more than the
//! connector could. A lease is never cached: the signing cache
//! (`Ctx.oauth`) holds sign-mode credentials only.
//!
//! The client sends `service`, `exe` and, optionally, the project's
//! `overlay` (as for `api.call`). The role, the scope of the session and
//! its policy come from the config in force (the caller's environment
//! snapshot, as for `api.call`) and the connector manifest; of the overlay
//! only `ask` and `deny` count, so it can only add `Deny` statements and
//! never widens the session.
//!
//! The record's `sts_session` is the STS session name; its `session` is
//! the agent session, as in every record (the limiter rebuilds the lease's
//! `requests_per_minute` slot from it, `pipeline::limit_event`).
//!
//! The checks, in order (the first that fails is the answer's `rule`):
//! lockdown (`lockdown`), the caller's scope (`no_scope`), the service's
//! mode (`sts_not_enabled`), `cloud.run_allow` (`exe_not_allowed`), the
//! `aws` secret (`secret_missing`, `secret_not_allowed_for_service`),
//! `requests_per_minute` (one per lease, decision 17; `limit`), the session
//! policy (`session_policy_unrepresentable`, `session_policy_too_large`),
//! and `AssumeRole` (`token_mint_failed`).
//!
//! Every answer writes one `secret` record, `event = "cloud_lease"`, with
//! `service`, `exe` and what is known of `role_arn`, `sts_session`, `expires`
//! and `policy_sha256`. It never holds a credential, and a failed
//! `AssumeRole` keeps only the sanitized STS error code (decision 18).
//!
//! Trust boundary: as for `secret.lease`, any process of the caller's uid
//! can ask, and the `exe` check binds only the honest client. The
//! credentials are bounded by the session policy and 15 minutes.

use crate::api_ops::{gateway_mode, parse_overlay, valid_service, Groups};
use crate::ops::{Ctx, Notice};
use crate::secret_ops::{check_exe, MAX_EXE_BYTES};
use crate::sessions::agent_ancestor;
use crate::vault::Kind;
use saiife_audit::DecisionKind;
use saiife_broker::cloud::{session_policy, sts, token, CloudError};
use saiife_broker::limits::Key;
use saiife_broker::manifest::OpKind;
use saiife_ipc::msg::{err, err_with, ok, ErrorCode, Request};
use saiife_ipc::peer::{comm, PeerCred};
use saiife_policy::{is_interpreter, scope_for, CloudMode, LimitsCfg, PolicyError, ServiceOverlay};
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use time::OffsetDateTime;

/// A refused lease: the rule, why, and the answer's error code.
struct Deny {
    rule: &'static str,
    detail: String,
    code: ErrorCode,
}

fn deny(rule: &'static str, detail: impl Into<String>) -> Deny {
    Deny {
        rule,
        detail: detail.into(),
        code: ErrorCode::Denied,
    }
}

/// What the record says beside the verdict, filled as the checks pass.
#[derive(Default)]
struct Facts {
    role_arn: Option<String>,
    session: Option<String>,
    expires: Option<String>,
    policy_sha256: Option<String>,
    agent_session: Option<String>,
}

/// An overlay as a lease counts it: its `allow` dropped, so it can only
/// add `Deny` statements (in every mode).
fn narrowing(o: ServiceOverlay) -> ServiceOverlay {
    ServiceOverlay {
        allow: Vec::new(),
        ..o
    }
}

/// A granted lease: the variables to set and the expiry.
struct Granted {
    env: Map<String, Value>,
    expires: String,
    session: String,
}

/// `YYYY-MM-DDTHH:MM:SSZ`.
fn timestamp(t: OffsetDateTime) -> String {
    const F: &[time::format_description::FormatItem<'static>] =
        time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    t.to_offset(time::UtcOffset::UTC)
        .format(F)
        .unwrap_or_default()
}

pub async fn lease(ctx: &Arc<Ctx>, peer: &PeerCred, req: Request) -> Value {
    let id = req.id;
    let service = match req.args.get("service").and_then(Value::as_str) {
        Some(s) if valid_service(s) => s.to_string(),
        _ => {
            return err(
                id,
                ErrorCode::BadRequest,
                "cloud.lease takes a valid service name",
            )
        }
    };
    let exe = match req.args.get("exe").and_then(Value::as_str) {
        Some(e) if !e.is_empty() && e.len() <= MAX_EXE_BYTES && !e.contains('\0') => e.to_string(),
        _ => return err(id, ErrorCode::BadRequest, "cloud.lease takes an exe path"),
    };
    // The project's overlay (as `api.call` takes it): only its ask and deny
    // count, so it can only narrow the session.
    let overlay = match parse_overlay(req.args.get("overlay")) {
        Ok(o) => o,
        Err(m) => return err(id, ErrorCode::BadRequest, m),
    };
    let mut facts = Facts::default();
    // Lockdown first: under either scope no credential is handed out.
    let verdict = match ctx.lockdown.get() {
        Some(l) => Err(deny("lockdown", crate::lockdown::message(&l))),
        None => {
            let free = crate::disk::free_mb(&ctx.audit_dir);
            if let Err(code) = crate::disk::disk_gate(
                free.unwrap_or(0),
                ctx.policy().min_free_mb,
                peer.uid,
                ctx.own_uid,
            ) {
                ctx.notice(peer.uid, Notice::LowDisk);
                return err(id, code, "the audit volume is below [audit] min_free_mb");
            }
            decide(ctx, peer, &service, &exe, overlay, &mut facts).await
        }
    };
    let mut r = ctx.record("secret", &format!("cloud_lease {service} {exe}"));
    r.uid = Some(peer.uid);
    r.user = ctx.name_of(peer.uid).await;
    r.extra.insert("event".into(), "cloud_lease".into());
    r.extra.insert("service".into(), service.clone().into());
    r.extra.insert("exe".into(), exe.clone().into());
    // The agent session (the limiter bucket); the STS session name is
    // `sts_session` (a record's `session` is the agent session).
    r.session.clone_from(&facts.agent_session);
    for (k, v) in [
        ("role_arn", &facts.role_arn),
        ("sts_session", &facts.session),
        ("expires", &facts.expires),
        ("policy_sha256", &facts.policy_sha256),
    ] {
        if let Some(v) = v {
            r.extra.insert(k.into(), v.clone().into());
        }
    }
    r.extra.insert(
        "peer".into(),
        json!({"pid": peer.pid, "comm": comm(peer.pid)}),
    );
    match verdict {
        Ok(g) => {
            if let Err(e) = ctx.writer.append(r).await {
                // No record, no credentials.
                return err(
                    id,
                    ErrorCode::Internal,
                    &format!("cannot write the audit record: {e}"),
                );
            }
            let mut m = Map::new();
            m.insert("env".into(), Value::Object(g.env));
            m.insert("expires".into(), g.expires.into());
            m.insert("session".into(), g.session.into());
            ok(id, m)
        }
        Err(Deny { rule, detail, code }) => {
            r.decision = DecisionKind::Deny;
            r.rule = Some(rule.to_string());
            r.reason = Some(detail.clone());
            if let Err(e) = ctx.writer.append(r).await {
                eprintln!("saiifed: warning: cannot write a cloud_lease record: {e}");
            }
            let mut extra = Map::new();
            extra.insert("rule".into(), rule.into());
            if code == ErrorCode::Limited {
                ctx.notify_limit(peer.uid, &service, "cloud.lease", rule);
                extra.insert("limit".into(), rule.into());
                return err_with(id, code, &format!("limit reached ({rule})"), extra);
            }
            err_with(id, code, &format!("{rule}: {detail}"), extra)
        }
    }
}

/// The checks of a lease after lockdown, in order, and the `AssumeRole`.
async fn decide(
    ctx: &Arc<Ctx>,
    peer: &PeerCred,
    service: &str,
    exe: &str,
    overlay: Option<ServiceOverlay>,
    facts: &mut Facts,
) -> Result<Granted, Deny> {
    let state = ctx.policy();
    let Some(g) = &state.gateway else {
        return Err(deny("policy_invalid", "no valid policy is loaded"));
    };
    // Scope: the caller's, in the environment snapshot it runs under (the
    // scope's in locked mode; the base config for the personal broker, as
    // the lease names no project environment).
    let Some(user) = ctx.name_of(peer.uid).await else {
        return Err(deny("no_scope", "the caller has no user name"));
    };
    let groups = Groups(ctx.groups_of(&user).await);
    let (env_name, _) = g
        .select_env(gateway_mode(ctx), &groups, &user, None)
        .map_err(|rule| deny(rule, "the caller's environment has no policy"))?;
    let snap = g.snapshot_for(env_name);
    match scope_for(&snap.config, &groups, &user) {
        Ok(Some(s)) if s.services.iter().any(|x| x == service) => {}
        Ok(_) => return Err(deny("no_scope", "the service is not in the caller's scope")),
        Err(PolicyError::ScopeConflict { .. }) => {
            return Err(deny(
                "scope_conflict",
                "the caller is in more than one scope",
            ))
        }
        Err(_) => return Err(deny("policy_invalid", "the scope cannot be read")),
    }
    let Some(svc) = snap.config.services.get(service) else {
        return Err(deny("no_scope", "the service is not in the caller's scope"));
    };
    // The mode.
    if svc.mode != CloudMode::Sts {
        return Err(deny(
            "sts_not_enabled",
            "the service is not in STS mode (mode = \"sts\")",
        ));
    }
    let Some(role_arn) = svc.cloud.role_arn.clone() else {
        return Err(deny(
            "policy_invalid",
            "mode = \"sts\" needs cloud.role_arn",
        ));
    };
    facts.role_arn = Some(role_arn.clone());
    // `cloud.run_allow`, resolved here: the policy load only checked names.
    let allow = svc.cloud.run_allow.clone();
    let exe_path = PathBuf::from(exe);
    tokio::task::spawn_blocking(move || check_cloud_exe(&exe_path, &allow))
        .await
        .map_err(|_| deny("exe_not_allowed", "executable check failed"))??;
    // The `aws` secret, allowed for this service.
    let Some(secret) = svc.secret.as_deref() else {
        return Err(deny("secret_missing", "the service names no secret"));
    };
    let fields =
        crate::oauth::vault_fields(ctx, secret, service, Kind::Aws).map_err(|f| match f.rule {
            "vault_unavailable" => Deny {
                code: ErrorCode::VaultUnavailable,
                ..deny("vault_unavailable", "the vault cannot be read")
            },
            "secret_not_allowed_for_service" => deny(
                "secret_not_allowed_for_service",
                "the secret may not be used by this service",
            ),
            _ => deny("secret_missing", "no aws secret of that name"),
        })?;
    let base = crate::oauth::aws_keys(&fields)
        .map_err(|_| deny("secret_missing", "the aws secret has no keys"))?;
    drop(fields);
    // `requests_per_minute`: one per lease (decision 17). No other limit
    // can bind credentials once they are handed out.
    let now = OffsetDateTime::now_utc();
    if ctx.limiter.unavailable(now) {
        return Err(deny(
            "limits_unavailable",
            "the limits could not be rebuilt",
        ));
    }
    let session_of =
        agent_ancestor(ctx.proc.as_ref(), peer.pid).and_then(|a| ctx.sessions.lookup(a));
    // The record carries it, so a restart rebuilds the same bucket.
    facts.agent_session.clone_from(&session_of);
    let key = Key {
        uid: peer.uid,
        service: service.to_string(),
        session: session_of,
    };
    let rpm = LimitsCfg {
        requests_per_minute: svc.limits.requests_per_minute,
        ..LimitsCfg::default()
    };
    let reservation = ctx
        .limiter
        .check_and_commit(&key, OpKind::Read, None, false, &rpm, now)
        .map_err(|limit| Deny {
            rule: limit,
            detail: format!("limit reached ({limit})"),
            code: ErrorCode::Limited,
        })?;
    // The session policy, from the config and the manifest only.
    let m = g
        .catalog
        .manifest_for(service, svc)
        .map_err(|_| deny("policy_invalid", "the connector manifest is not available"))?;
    let overlay = overlay.map(narrowing);
    let policy =
        session_policy::build(svc, &m, overlay.as_ref(), snap.mode).map_err(|e| match e {
            CloudError::TooLarge => deny(
                "session_policy_too_large",
                "the session policy is over 2048 bytes",
            ),
            other => deny("session_policy_unrepresentable", other.to_string()),
        })?;
    facts.policy_sha256 = Some(policy.sha256.clone());
    let Some(region) = svc.params.get("region") else {
        return Err(deny("policy_invalid", "the service has no params.region"));
    };
    let Ok(up) = ctx.upstream.as_ref() else {
        return Err(deny(
            "upstream_unavailable",
            "the upstream client could not be built",
        ));
    };
    let session = sts::session_name(peer.uid);
    facts.session = Some(session.clone());
    let p = sts::AssumeRole {
        role_arn: &role_arn,
        session_name: session.clone(),
        duration_s: sts::LEASE_SECONDS,
        policy: Some(&policy.json),
        external_id: svc.cloud.external_id.as_deref(),
    };
    let up = up.with_timeout(up.timeout().min(token::MINT_TIMEOUT));
    // What was sent counts, whatever came back.
    reservation.commit();
    let (creds, exp) = sts::assume(&up, &base, region, &p, now)
        .await
        .map_err(|e| {
            let reason = crate::oauth::mint_reason(&e);
            deny(crate::oauth::MINT_FAILED, reason)
        })?;
    drop(base);
    let expires = timestamp(exp);
    facts.expires = Some(expires.clone());
    let mut env = Map::new();
    env.insert(
        "AWS_ACCESS_KEY_ID".into(),
        creds.access_key_id.as_str().into(),
    );
    env.insert(
        "AWS_SECRET_ACCESS_KEY".into(),
        creds.secret_access_key.as_str().into(),
    );
    // `parse_assume_role` always sets one; a lease without it is unusable.
    let Some(token) = creds.session_token.as_deref() else {
        facts.expires = None;
        return Err(deny(crate::oauth::MINT_FAILED, "bad_response"));
    };
    env.insert("AWS_SESSION_TOKEN".into(), token.as_str().into());
    env.insert("AWS_REGION".into(), region.as_str().into());
    env.insert("AWS_DEFAULT_REGION".into(), region.as_str().into());
    Ok(Granted {
        env,
        expires,
        session,
    })
}

/// `cloud.run_allow` at lease time: the executable, resolved, is no
/// interpreter or shell (nor is a listed link to it), and it passes the
/// `secret.lease` check (listed as itself, canonical, a regular file,
/// root-owned along its path). Every refusal is `exe_not_allowed`.
fn check_cloud_exe(exe: &Path, allow: &[PathBuf]) -> Result<(), Deny> {
    let no = |d: &str| deny("exe_not_allowed", d);
    let Ok(real) = std::fs::canonicalize(exe) else {
        return Err(no("the executable cannot be resolved"));
    };
    // A listed link to an interpreter is refused whichever path the
    // client sends: the link (resolved here) or its target.
    if is_interpreter(exe) || is_interpreter(&real) {
        return Err(no(
            "the executable is (or links to) an interpreter or shell",
        ));
    }
    check_exe(exe, allow).map_err(|d| {
        // `check_exe` words it for `[secrets.*] run_allow`.
        let detail = if d.detail.ends_with("in run_allow for this secret") {
            "the executable is not in this service's cloud.run_allow".to_string()
        } else {
            d.detail
        };
        deny("exe_not_allowed", detail)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_are_whole_seconds_utc() {
        let t = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
            + time::Duration::milliseconds(250);
        assert_eq!(timestamp(t), "2027-01-15T08:00:00Z");
    }

    #[test]
    fn overlay_allow_dropped_in_every_mode() {
        let o = ServiceOverlay {
            allow: vec!["s3:*".into()],
            ask: vec!["s3:write".into()],
            deny: vec!["s3:delete".into()],
        };
        let n = narrowing(o);
        assert!(n.allow.is_empty());
        assert_eq!(n.ask, ["s3:write"]);
        assert_eq!(n.deny, ["s3:delete"]);
    }

    #[test]
    fn interpreter_by_resolved_name_refused() {
        let r = check_cloud_exe(
            Path::new("/usr/bin/bash"),
            &[PathBuf::from("/usr/bin/bash")],
        );
        let Err(d) = r else { panic!("not refused") };
        assert_eq!(d.rule, "exe_not_allowed");
        assert!(d.detail.contains("interpreter"), "{}", d.detail);
    }
}
