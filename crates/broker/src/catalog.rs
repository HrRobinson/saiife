//! The connector catalog: built-in plus admin-local manifests, and the
//! check of `[services.*]` against them.

use crate::manifest::{dns_label, from_http_service, Manifest, HTTP_CONNECTOR};
use crate::request::bare_hostname;
use crate::BrokerError;
use saiife_policy::capability::{glob_with, matches_with, Capability};
use saiife_policy::{CloudMode, Mode, ServiceCfg, SystemConfig};
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
/// Cloud settings (plan 15): `mode = "sts"` needs an `aws_sigv4` connector
/// and a session policy that builds; `role_arn`/`external_id` are AWS only
/// and `authority_host` Azure only. Warnings: STS limits that do not bind a
/// handed-out credential, an AWS `allow` matching an operation without an
/// `iam_action`, and `writes_per_hour` on a service with deletes but no
/// `deletes_per_day` (it counts writes only).
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
            if (m.whole_host_param() == Some(p.as_str()) || m.host_params().contains(&p.as_str()))
                && !bare_hostname(v)
            {
                return Err(BrokerError::BadValue {
                    name: format!("{name}.{p}"),
                    reason: "not a bare lower-case hostname".into(),
                });
            }
            // A param inside one host label (`s3.{region}.amazonaws.com`):
            // one DNS label, so it can never add a label or a port.
            if m.label_host_params().contains(&p.as_str()) && !dns_label(v) {
                return Err(BrokerError::BadValue {
                    name: format!("{name}.{p}"),
                    reason: "not a single lower-case DNS label".into(),
                });
            }
        }
        check_cloud(name, svc, &m, &mut warnings)?;
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

fn check_cloud(
    name: &str,
    svc: &ServiceCfg,
    m: &Manifest,
    warnings: &mut Vec<String>,
) -> Result<(), BrokerError> {
    let bad = |why: String| Err(BrokerError::Config(format!("service {name}: {why}")));
    let sigv4 = m.signs_sigv4();
    let sts = svc.mode == CloudMode::Sts;
    if sts && !sigv4 {
        return bad(format!(
            "mode = \"sts\" is for AWS connectors only (aws_sigv4); {} signs another way",
            m.id
        ));
    }
    if !sigv4 && (svc.cloud.role_arn.is_some() || svc.cloud.external_id.is_some()) {
        return bad(format!(
            "cloud.role_arn and cloud.external_id are for AWS connectors only; {} is not one",
            m.id
        ));
    }
    if svc.cloud.authority_host.is_some() && !m.auth.iter().any(|a| a.kind == "azure_sp") {
        return bad(format!(
            "cloud.authority_host is for Azure connectors only; {} is not one",
            m.id
        ));
    }
    if sts {
        if let Err(e) = crate::cloud::session_policy::build(svc, m, None, Mode::Locked) {
            return bad(format!("mode = \"sts\" cannot be used: {e}"));
        }
        // A lease counts as one request, so requests_per_minute binds.
        let unbound = saiife_policy::LimitsCfg {
            requests_per_minute: None,
            ..svc.limits.clone()
        };
        if unbound != saiife_policy::LimitsCfg::default() {
            warnings.push(format!(
                "service {name}: limits apply to saiife api calls, not to run --cloud credentials"
            ));
        }
    }
    if sigv4 {
        for pat in &svc.allow {
            let no_action = m.operation.iter().any(|o| {
                o.iam_action.is_none()
                    && Capability::parse(&o.capability).is_ok_and(|mut c| {
                        if o.qualifier.is_some() {
                            c.qualifier = o.qualifier.clone();
                        }
                        matches_with(pat, &c, true) || template_matches(pat, &c)
                    })
            });
            if no_action {
                warnings.push(format!(
                    "service {name}: allow pattern {pat:?} matches an operation without an iam_action"
                ));
            }
        }
    }
    if svc.limits.writes_per_hour.is_some()
        && svc.limits.deletes_per_day.is_none()
        && m.operation
            .iter()
            .any(|o| o.kind == crate::manifest::OpKind::Delete)
    {
        warnings.push(format!(
            "service {name}: {} has delete operations; writes_per_hour counts writes only, so set deletes_per_day to limit them",
            m.id
        ));
    }
    Ok(())
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

    #[test]
    fn wrong_key_or_verb_still_warns() {
        assert_eq!(warnings(r#""messages:read:team=C0123""#).len(), 1);
        assert_eq!(warnings(r#""messages:nuke:channel=C0123""#).len(), 1);
        assert_eq!(warnings(r#""nothing:read:channel=C0123""#).len(), 1);
    }

    const ROLE: &str = "arn:aws:iam::123456789012:role/saiife";

    fn check(svc_toml: &str) -> Result<Vec<String>, BrokerError> {
        let cfg: SystemConfig = toml::from_str(&format!(
            "version = 2\n[services.x]\nsecret = \"s\"\n{svc_toml}"
        ))
        .unwrap();
        validate(&cfg, &Catalog::new(crate::manifest::builtin(), vec![]))
    }

    /// `extra` is a top-level key of the service: it precedes the sub-tables.
    fn sts(extra: &str, allow: &str) -> String {
        format!(
            "connector = \"aws-s3\"\nmode = \"sts\"\nallow = [{allow}]\n{extra}\n\
             [services.x.params]\nregion = \"eu-west-1\"\n\
             [services.x.cloud]\nrole_arn = \"{ROLE}\"\nrun_allow = [\"/usr/bin/aws-sync\"]\n"
        )
    }

    const DOCS_ALLOW: &str =
        r#""s3:read:arn:aws:s3:::acme-logs", "s3:read:arn:aws:s3:::acme-logs/**""#;

    #[test]
    fn sts_ok_on_aws() {
        assert!(check(&sts("", DOCS_ALLOW)).unwrap().is_empty());
    }

    #[test]
    fn sts_on_gcp_refused() {
        let e = check("connector = \"gcp-storage\"\nmode = \"sts\"\n").unwrap_err();
        assert!(e.to_string().contains("AWS connectors only"), "{e}");
    }

    #[test]
    fn role_arn_on_azure_refused() {
        let e = check(&format!(
            "connector = \"azure-arm\"\n[services.x.cloud]\nrole_arn = \"{ROLE}\"\n"
        ));
        assert!(e.unwrap_err().to_string().contains("AWS connectors only"));
        let e = check(
            "connector = \"aws-s3\"\n[services.x.params]\nregion = \"eu-west-1\"\n\
             [services.x.cloud]\nauthority_host = \"login.microsoftonline.com\"\n",
        );
        assert!(e.unwrap_err().to_string().contains("Azure connectors only"));
    }

    #[test]
    fn sts_unrepresentable_pattern_reported() {
        let e = check(&sts("", r#""s3:read:arn:aws:s3:::acme-logs/*""#)).unwrap_err();
        let m = e.to_string();
        assert!(
            m.contains("acme-logs/*") && m.contains("session policy"),
            "{m}"
        );
    }

    #[test]
    fn sts_limits_warned() {
        let w = check(&sts("limits = { writes_per_hour = 5 }", DOCS_ALLOW)).unwrap();
        assert!(
            w.iter()
                .any(|x| x
                    .contains("limits apply to saiife api calls, not to run --cloud credentials")),
            "{w:?}"
        );
    }

    #[test]
    fn sts_requests_per_minute_alone_not_warned() {
        let w = check(&sts("limits = { requests_per_minute = 5 }", DOCS_ALLOW)).unwrap();
        assert!(w.is_empty(), "{w:?}");
        let w = check(&sts(
            "limits = { requests_per_minute = 5, writes_per_hour = 5 }",
            DOCS_ALLOW,
        ))
        .unwrap();
        assert!(w.iter().any(|x| x.contains("limits apply")), "{w:?}");
    }

    #[test]
    fn writes_per_hour_without_deletes_per_day_warned() {
        let on = |lim: &str| {
            check(&format!(
                "connector = \"aws-s3\"\nallow = [\"s3:read:arn:aws:s3:::b\"]\n\
                 limits = {{ {lim} }}\n[services.x.params]\nregion = \"eu-west-1\"\n"
            ))
            .unwrap()
        };
        assert!(on("writes_per_hour = 5")
            .iter()
            .any(|x| x.contains("deletes_per_day")));
        assert!(on("writes_per_hour = 5, deletes_per_day = 1").is_empty());
        assert!(on("requests_per_minute = 5").is_empty());
    }

    #[test]
    fn allow_without_iam_action_warned() {
        let mut m = crate::manifest::builtin()
            .iter()
            .find(|m| m.id == "aws-s3")
            .unwrap()
            .clone();
        for o in &mut m.operation {
            o.iam_action = None;
        }
        let cfg: SystemConfig = toml::from_str(
            "version = 2\n[services.x]\nconnector = \"aws-s3\"\nsecret = \"s\"\n\
             allow = [\"s3:read:arn:aws:s3:::b\"]\n[services.x.params]\nregion = \"eu-west-1\"\n",
        )
        .unwrap();
        let w = validate(&cfg, &Catalog::new(&[m], vec![])).unwrap();
        assert!(
            w.iter().any(|x| x.contains("without an iam_action")),
            "{w:?}"
        );
    }
}
