//! The policy half of a connector request, with no network, vault or limits:
//! scope, operation resolution, parameter validation and the
//! deny > ask > allow decision (spec §6.7.1 steps 3–6). `saiife policy test`
//! runs `[[example]]` requests through it.

use crate::catalog::Catalog;
use crate::manifest::{qualifier_for, Operation};
use crate::pipeline::rule_of;
use crate::{params, resolve};
use saiife_policy::capability::Capability;
use saiife_policy::decide::{decide, Request, Verdict};
use saiife_policy::{Mode, PolicyError, Scope, ServiceCfg, ServiceOverlay, SystemConfig};
use std::collections::BTreeMap;

/// A request that cannot be judged because it names nothing that exists
/// (a typo in an example, not a policy decision).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unjudgeable {
    #[error("no service {0:?} is defined")]
    UnknownService(String),
    #[error("service {service:?} has no operation {op:?}")]
    UnknownOperation { service: String, op: String },
}

/// The verdict the pipeline reaches for `service` `op` with `params`, for a
/// caller whose scope lookup gave `scope`. Deny rules are the pipeline's:
/// `no_scope`, `scope_conflict`, `bad_param`, `policy_invalid`,
/// `deny:<pattern>` and `default_deny`.
pub fn judge(
    cfg: &SystemConfig,
    cat: &Catalog,
    scope: Result<Option<&Scope>, PolicyError>,
    service: &str,
    op: &str,
    params: &BTreeMap<String, String>,
) -> Result<Verdict, Unjudgeable> {
    let deny = |rule: &str| {
        Ok(Verdict::Deny {
            rule: rule.to_string(),
        })
    };
    let svc = cfg
        .services
        .get(service)
        .ok_or_else(|| Unjudgeable::UnknownService(service.to_string()))?;
    let scope = match scope {
        Ok(Some(s)) => s,
        Ok(None) => return deny("no_scope"),
        Err(PolicyError::ScopeConflict { .. }) => return deny("scope_conflict"),
        Err(_) => return deny("policy_invalid"),
    };
    if !scope.services.iter().any(|s| s == service) {
        return deny("no_scope");
    }
    let Ok(m) = cat.manifest_for(service, svc) else {
        return deny("policy_invalid");
    };
    let Some(operation) = resolve::named(&m, op) else {
        return Err(Unjudgeable::UnknownOperation {
            service: service.to_string(),
            op: op.to_string(),
        });
    };
    let checked = match params::validate(operation, params, &svc.fixed) {
        Ok(p) => p,
        Err(e) => return deny(rule_of(&e)),
    };
    match policy_verdict(operation, svc, None, Mode::Locked, &checked) {
        Ok((_, v)) => Ok(v),
        Err(rule) => deny(rule),
    }
}

/// Pipeline step 6, shared with the real pipeline: the operation's
/// capability (its qualifier filled from the validated parameters; `None`
/// when one is missing, so a deny/ask with a qualifier still matches and an
/// allow does not) and the deny > ask > allow verdict. `Err` is the deny
/// rule (`policy_invalid`: the manifest's capability does not parse).
pub(crate) fn policy_verdict(
    op: &Operation,
    svc: &ServiceCfg,
    overlay: Option<&ServiceOverlay>,
    mode: Mode,
    params: &BTreeMap<String, String>,
) -> Result<(Capability, Verdict), &'static str> {
    let mut cap = Capability::parse(&op.capability).map_err(|_| "policy_invalid")?;
    if op.qualifier.is_some() {
        cap.qualifier = qualifier_for(op, params);
    }
    let verdict = decide(
        svc,
        overlay,
        mode,
        &Request {
            capability: &cap,
            params,
        },
    );
    Ok((cap, verdict))
}
