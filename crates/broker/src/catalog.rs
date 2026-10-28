//! The connector catalog: built-in plus admin-local manifests, and the
//! check of `[services.*]` against them.

use crate::manifest::{from_http_service, Manifest, HTTP_CONNECTOR};
use crate::request::bare_hostname;
use crate::BrokerError;
use saiife_policy::capability::{matches_with, Capability};
use saiife_policy::{ServiceCfg, SystemConfig};
use std::borrow::Cow;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
pub struct Catalog {
    manifests: BTreeMap<String, Manifest>,
}

impl Catalog {
    /// Built-in manifests win over a local one with the same id (loading
    /// local manifests already refuses such an id).
    pub fn new(builtin: &[Manifest], local: Vec<Manifest>) -> Catalog {
        let mut manifests: BTreeMap<String, Manifest> = BTreeMap::new();
        for m in builtin.iter().cloned().chain(local) {
            manifests.entry(m.id.clone()).or_insert(m);
        }
        Catalog { manifests }
    }

    /// The manifest of service `name`: its connector's, or for `http` one
    /// built from the service config.
    pub fn manifest_for(
        &self,
        name: &str,
        svc: &ServiceCfg,
    ) -> Result<Cow<'_, Manifest>, BrokerError> {
        if svc.connector == HTTP_CONNECTOR {
            return from_http_service(name, svc).map(Cow::Owned);
        }
        self.manifests
            .get(&svc.connector)
            .map(Cow::Borrowed)
            .ok_or_else(|| BrokerError::UnknownConnector(svc.connector.clone()))
    }
}

/// Checks every service against its manifest. Errors: unknown connector, a
/// required manifest param missing from `params`, a param the manifest does
/// not declare, a param value of the wrong type. Warnings: an
/// `allow`/`ask`/`deny` pattern that matches no operation's capability.
pub fn validate(cfg: &SystemConfig, cat: &Catalog) -> Result<Vec<String>, BrokerError> {
    let mut warnings = Vec::new();
    for (name, svc) in &cfg.services {
        let m = cat.manifest_for(name, svc)?;
        for (p, spec) in &m.params {
            if spec.required && !svc.params.contains_key(p) {
                return Err(BrokerError::MissingParam(format!("{name}.{p}")));
            }
        }
        for (p, v) in &svc.params {
            let spec = m
                .params
                .get(p)
                .ok_or_else(|| BrokerError::UnknownParam(format!("{name}.{p}")))?;
            spec.param_type()?
                .check(v)
                .map_err(|reason| BrokerError::BadValue {
                    name: format!("{name}.{p}"),
                    reason,
                })?;
            // A param that is the whole upstream host: no userinfo, port,
            // path, upper case or trailing dot can ride along (decision 1).
            if m.whole_host_param() == Some(p.as_str()) && !bare_hostname(v) {
                return Err(BrokerError::BadValue {
                    name: format!("{name}.{p}"),
                    reason: "not a bare lower-case hostname".into(),
                });
            }
        }
        let caps: Vec<Capability> = m
            .operation
            .iter()
            .filter_map(|o| {
                Capability::parse(&o.capability).ok().map(|mut c| {
                    if o.qualifier.is_some() {
                        c.qualifier = o.qualifier.clone();
                    }
                    c
                })
            })
            .collect();
        for (list, pats) in [
            ("allow", &svc.allow),
            ("ask", &svc.ask),
            ("deny", &svc.deny),
        ] {
            for pat in pats {
                if !caps.iter().any(|c| matches_with(pat, c, true)) {
                    warnings.push(format!(
                        "service {name}: {list} pattern {pat:?} matches no operation of {}",
                        m.id
                    ));
                }
            }
        }
    }
    Ok(warnings)
}
