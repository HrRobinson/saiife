//! The connector catalog: built-in plus admin-local manifests, and the
//! check of `[services.*]` against them.

use crate::manifest::{from_http_service, Manifest, HTTP_CONNECTOR};
use crate::request::bare_hostname;
use crate::BrokerError;
use saiife_policy::capability::{glob_with, matches_with, Capability};
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
    for sc in &cfg.scope {
        for entry in &sc.services {
            if let Some(srv) = entry.strip_prefix("mcp:") {
                if !cfg.mcp.contains_key(srv) {
                    return Err(BrokerError::UnknownScopeEntry(format!(
                        "scope {}: {entry:?} names no [mcp.{srv}]",
                        sc.name
                    )));
                }
            }
        }
    }
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
            if (m.whole_host_param() == Some(p.as_str()) || m.host_params().contains(&p.as_str()))
                && !bare_hostname(v)
            {
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
                if !caps
                    .iter()
                    .any(|c| matches_with(pat, c, true) || template_matches(pat, c))
                {
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

/// A concrete qualifier pattern (`messages:read:channel=C0123`) against an
/// operation whose qualifier is a template (`channel={channel}`): each
/// `{placeholder}` stands for any value, so the pattern can match at call time.
fn template_matches(pat: &str, cap: &Capability) -> bool {
    let Some(tpl) = cap.qualifier.as_deref().filter(|q| q.contains('{')) else {
        return false;
    };
    let mut it = pat.splitn(3, ':');
    let (Some(res), Some(verb), Some(qual)) = (it.next(), it.next(), it.next()) else {
        return false;
    };
    if (res != "*" && res != cap.resource) || (verb != "*" && verb != cap.verb) {
        return false;
    }
    let mut starred = String::new();
    let mut open = false;
    for c in tpl.chars() {
        match c {
            '{' => {
                open = true;
                starred.push('*');
            }
            '}' => open = false,
            _ if !open => starred.push(c),
            _ => {}
        }
    }
    glob_with(&starred, qual, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn warnings(allow: &str) -> Vec<String> {
        let cfg: SystemConfig = toml::from_str(&format!(
            "version = 2\n[services.chat]\nconnector = \"slack\"\nsecret = \"s\"\nallow = [{allow}]\n"
        ))
        .unwrap();
        validate(&cfg, &Catalog::new(crate::manifest::builtin(), vec![])).unwrap()
    }

    #[test]
    fn concrete_qualifier_matches_a_template() {
        assert!(warnings(r#""messages:read:channel=C0123""#).is_empty());
        assert!(warnings(r#""messages:write:channel=C0123""#).is_empty());
    }

    fn scope_check(entry: &str) -> Result<Vec<String>, BrokerError> {
        let cfg: SystemConfig = toml::from_str(&format!(
            "version = 2\nlocked = true\n[mcp.linear]\ncommand = \"/usr/bin/x\"\n[[scope]]\nname = \"s\"\nusers = [\"u\"]\nservices = [\"{entry}\"]\n"
        ))
        .unwrap();
        validate(&cfg, &Catalog::new(crate::manifest::builtin(), vec![]))
    }

    #[test]
    fn scope_known_mcp_entry_accepted() {
        assert!(scope_check("mcp:linear").is_ok());
    }

    #[test]
    fn scope_unknown_mcp_entry_refused() {
        let e = scope_check("mcp:jira").unwrap_err().to_string();
        assert!(e.contains("mcp:jira") && e.contains("[mcp.jira]"), "{e}");
    }

    #[test]
    fn wrong_key_or_verb_still_warns() {
        assert_eq!(warnings(r#""messages:read:team=C0123""#).len(), 1);
        assert_eq!(warnings(r#""messages:nuke:channel=C0123""#).len(), 1);
        assert_eq!(warnings(r#""nothing:read:channel=C0123""#).len(), 1);
    }
}
