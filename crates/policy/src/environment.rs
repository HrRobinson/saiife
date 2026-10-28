//! `[environments.<name>]` (spec §6.11, plan 14 decision 10): an overlay on
//! the base system config. It adds guard packs and overrides service
//! settings; it can never remove a pack (there is no key for it) and never
//! change what a service talks to (`connector`, `base_url`, `auth` and
//! `operation` are unknown keys here).
//!
//! In locked mode the environment is the one bound to the caller's scope
//! ([`env_for`]); the project path never chooses it.

use crate::load::PolicyError;
use crate::scope::scope_for;
use crate::service::{LimitsCfg, RedactCfg, RuleCfg};
use crate::system::SystemConfig;
use crate::users::Directory;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One `[environments.<name>]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnvironmentCfg {
    pub guard: EnvGuard,
    pub services: BTreeMap<String, ServiceOverride>,
}

/// `[environments.<name>.guard]`: packs added to the base list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnvGuard {
    pub packs: Vec<String>,
}

/// `[environments.<name>.services.<svc>]`. A key that is present replaces
/// the base value, except `params`, `fixed` and `limits`, which merge per
/// field.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServiceOverride {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub fixed: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ask: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<Vec<RuleCfg>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits: Option<LimitsCfg>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redact: Option<RedactCfg>,
}

/// An environment name: `[a-z0-9_-]{1,64}`. It is written into records and
/// into `.saiife/config.toml`.
pub fn valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

fn env_error(env: &str, detail: impl Into<String>) -> PolicyError {
    PolicyError::Environment {
        env: env.to_string(),
        detail: detail.into(),
    }
}

/// `cfg` with environment `env` applied. Packs are `base ∪ env`; each
/// service override must name a service of the base config. The result
/// keeps `environments` (and so the hash covers every definition).
pub fn apply(cfg: &SystemConfig, env: &str) -> Result<SystemConfig, PolicyError> {
    let e = cfg
        .environments
        .get(env)
        .ok_or_else(|| env_error(env, "is not defined in [environments]"))?;
    let mut out = cfg.clone();
    for p in &e.guard.packs {
        if !out.guard.packs.contains(p) {
            out.guard.packs.push(p.clone());
        }
    }
    for (name, o) in &e.services {
        let Some(svc) = out.services.get_mut(name) else {
            return Err(env_error(
                env,
                format!("overrides service {name}, which the base config does not define"),
            ));
        };
        if let Some(s) = &o.secret {
            svc.secret = Some(s.clone());
        }
        for (k, v) in &o.params {
            svc.params.insert(k.clone(), v.clone());
        }
        for (k, v) in &o.fixed {
            svc.fixed.insert(k.clone(), v.clone());
        }
        if let Some(v) = &o.allow {
            svc.allow = v.clone();
        }
        if let Some(v) = &o.ask {
            svc.ask = v.clone();
        }
        if let Some(v) = &o.deny {
            svc.deny = v.clone();
        }
        if let Some(v) = &o.rule {
            svc.rule = v.clone();
        }
        if let Some(l) = &o.limits {
            merge_limits(&mut svc.limits, l);
        }
        if let Some(r) = &o.redact {
            svc.redact = r.clone();
        }
    }
    Ok(out)
}

fn merge_limits(base: &mut LimitsCfg, o: &LimitsCfg) {
    fn set<T: Clone>(into: &mut Option<T>, from: &Option<T>) {
        if from.is_some() {
            into.clone_from(from);
        }
    }
    set(&mut base.requests_per_minute, &o.requests_per_minute);
    set(&mut base.writes_per_hour, &o.writes_per_hour);
    set(&mut base.deletes_per_day, &o.deletes_per_day);
    set(&mut base.bulk_per_session, &o.bulk_per_session);
    set(&mut base.max_response_bytes, &o.max_response_bytes);
    set(&mut base.amount_per_day, &o.amount_per_day);
    set(&mut base.amount_per_request, &o.amount_per_request);
}

/// The environment of `user`'s single scope (`[[scope]] env`), `None` when
/// the user has no scope or the scope binds none. A scope conflict is an
/// error, as in [`scope_for`].
pub fn env_for<'a>(
    cfg: &'a SystemConfig,
    dir: &dyn Directory,
    user: &str,
) -> Result<Option<&'a str>, PolicyError> {
    Ok(scope_for(cfg, dir, user)?.and_then(|s| s.env.as_deref()))
}

/// `cfg` as `user` runs under it: the environment of the user's scope
/// applied, and its name. No environment (no scope, or a scope without
/// `env`) borrows `cfg`. The directory is only asked when some scope binds
/// an environment, so a config without environments costs no lookup.
pub fn applied_for<'a>(
    cfg: &'a SystemConfig,
    dir: &dyn Directory,
    user: &str,
) -> Result<(std::borrow::Cow<'a, SystemConfig>, Option<String>), PolicyError> {
    use std::borrow::Cow;
    if !cfg.scope.iter().any(|s| s.env.is_some()) {
        return Ok((Cow::Borrowed(cfg), None));
    }
    // A failed group lookup is an error, never "no scope": a base policy
    // would be looser than the environment the user is bound to.
    let scope = crate::scope::try_scope_for(cfg, dir, user).map_err(|detail| {
        PolicyError::Environment {
            env: "-".to_string(),
            detail: format!("group lookup failed: {detail}"),
        }
    })??;
    match scope.and_then(|s| s.env.as_deref()) {
        None => Ok((Cow::Borrowed(cfg), None)),
        Some(name) => Ok((Cow::Owned(apply(cfg, name)?), Some(name.to_string()))),
    }
}

/// The effective-policy hash of the base config and of each environment
/// (`(None, hash)` first), for `status` and `policy show`.
pub fn env_hashes(
    cfg: &SystemConfig,
    catalog: &[crate::effective::PackInfo],
) -> Vec<(Option<String>, String)> {
    use crate::effective::{active_packs, effective_policy, policy_hash};
    let hash_of = |c: &SystemConfig, env: Option<&str>| {
        let (packs, _) = active_packs(c, catalog, None);
        policy_hash(&effective_policy(c, &packs, None, env))
    };
    let mut out = vec![(None, hash_of(cfg, None))];
    for name in cfg.environments.keys() {
        if let Ok(applied) = apply(cfg, name) {
            out.push((Some(name.clone()), hash_of(&applied, Some(name))));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_names() {
        assert!(valid_env_name("prod"));
        assert!(valid_env_name("eu-west_2"));
        assert!(valid_env_name(&"a".repeat(64)));
        assert!(!valid_env_name(&"a".repeat(65)));
        for bad in ["", "Prod", "a b", "a/b", "a.b", "a\n"] {
            assert!(!valid_env_name(bad), "{bad:?}");
        }
    }

    /// A directory whose group lookup always fails.
    struct Broken;
    impl Directory for Broken {
        fn user(&self, _: &str) -> Option<crate::users::UserEntry> {
            None
        }
        fn name_of(&self, _: u32) -> Option<String> {
            None
        }
        fn group(&self, _: &str) -> Option<crate::users::GroupEntry> {
            None
        }
        fn groups_of(&self, _: &str) -> Vec<String> {
            Vec::new()
        }
        fn try_groups_of(&self, _: &str) -> Result<Vec<String>, String> {
            Err("boom".into())
        }
    }

    #[test]
    fn applied_for_fails_closed_on_group_lookup_failure() {
        let group_bound: SystemConfig = toml::from_str(
            "version = 2\n[[scope]]\nname = \"s\"\nusers = [\"group:devs\"]\nenv = \"e\"\n\
             [environments.e]\n",
        )
        .unwrap();
        let e = applied_for(&group_bound, &Broken, "alice").unwrap_err();
        assert!(e.to_string().contains("group lookup failed"), "{e}");
        // A user-named scope needs no groups: it still resolves.
        let by_name: SystemConfig = toml::from_str(
            "version = 2\n[[scope]]\nname = \"s\"\nusers = [\"alice\"]\nenv = \"e\"\n\
             [environments.e]\n",
        )
        .unwrap();
        let (_, env) = applied_for(&by_name, &Broken, "alice").unwrap();
        assert_eq!(env.as_deref(), Some("e"));
    }

    #[test]
    fn apply_unknown_env_and_service() {
        let cfg: SystemConfig = toml::from_str(
            "version = 2\n[services.a]\nconnector = \"x\"\n\
             [environments.e]\nservices.b.secret = \"s\"\n",
        )
        .unwrap();
        let e = apply(&cfg, "nope").unwrap_err().to_string();
        assert!(e.contains("nope") && e.contains("not defined"), "{e}");
        let e = apply(&cfg, "e").unwrap_err().to_string();
        assert!(e.contains("service b"), "{e}");
    }
}
