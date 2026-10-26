//! The deny > ask > allow decision (spec §6.9.1).

use crate::capability::{glob, matches, Capability};
use crate::project::{Mode, ServiceOverlay};
use crate::service::{Action, RuleCfg, ServiceCfg};
use std::collections::BTreeMap;

pub struct Request<'a> {
    pub capability: &'a Capability,
    pub params: &'a BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Ask,
    Deny { rule: String },
}

/// Any matching `deny` wins, then `ask`, then `allow`; nothing matching is
/// `Deny { rule: "default_deny" }`. The overlay's `allow` counts only
/// outside locked mode.
pub fn decide(
    svc: &ServiceCfg,
    overlay: Option<&ServiceOverlay>,
    mode: Mode,
    req: &Request,
) -> Verdict {
    let o_allow: &[String] = match (overlay, mode) {
        (Some(o), Mode::Developer) => &o.allow,
        _ => &[],
    };
    let (o_ask, o_deny): (&[String], &[String]) = match overlay {
        Some(o) => (&o.ask, &o.deny),
        None => (&[], &[]),
    };
    let stage = |action: Action, simple: &[&[String]]| -> Option<String> {
        for list in simple {
            if let Some(p) = list.iter().find(|p| matches(p, req.capability)) {
                return Some(p.clone());
            }
        }
        svc.rule
            .iter()
            .find(|r| r.action == action && rule_matches(r, req))
            .map(|r| r.capability.clone())
    };
    if let Some(p) = stage(Action::Deny, &[&svc.deny, o_deny]) {
        return Verdict::Deny {
            rule: format!("deny:{p}"),
        };
    }
    if stage(Action::Ask, &[&svc.ask, o_ask]).is_some() {
        return Verdict::Ask;
    }
    if stage(Action::Allow, &[&svc.allow, o_allow]).is_some() {
        return Verdict::Allow;
    }
    Verdict::Deny {
        rule: "default_deny".to_string(),
    }
}

/// The capability matches and every `when` entry names a present param
/// whose value matches the glob.
fn rule_matches(r: &RuleCfg, req: &Request) -> bool {
    matches(&r.capability, req.capability)
        && r.when
            .iter()
            .all(|(k, g)| req.params.get(k).is_some_and(|v| glob(g, v)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHOPIFY: &str = r#"
connector = "shopify"
secret = "shopify-prod"
params = { shop = "acme" }
allow = ["orders:read", "products:read"]
ask   = ["products:write", "refunds:write"]
deny  = ["customers:export", "*:delete"]
"#;

    fn svc(text: &str) -> ServiceCfg {
        toml::from_str(text).unwrap()
    }

    fn run(
        s: &ServiceCfg,
        o: Option<&ServiceOverlay>,
        mode: Mode,
        cap: &str,
        params: &[(&str, &str)],
    ) -> Verdict {
        let cap = Capability::parse(cap).unwrap();
        let params: BTreeMap<String, String> = params
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        decide(
            s,
            o,
            mode,
            &Request {
                capability: &cap,
                params: &params,
            },
        )
    }

    fn deny(rule: &str) -> Verdict {
        Verdict::Deny { rule: rule.into() }
    }

    #[test]
    fn order_deny_ask_allow_default() {
        let s = svc(SHOPIFY);
        let d = |c| run(&s, None, Mode::Locked, c, &[]);
        assert_eq!(d("orders:read"), Verdict::Allow);
        assert_eq!(d("products:write"), Verdict::Ask);
        assert_eq!(d("customers:export"), deny("deny:customers:export"));
        assert_eq!(d("products:delete"), deny("deny:*:delete"));
        assert_eq!(d("inventory:read"), deny("default_deny"));
    }

    #[test]
    fn deny_beats_ask_and_allow_in_the_same_service() {
        let s = svc(
            "connector = \"x\"\nallow = [\"a:read\"]\nask = [\"a:read\"]\ndeny = [\"a:read\"]\n",
        );
        assert_eq!(
            run(&s, None, Mode::Locked, "a:read", &[]),
            deny("deny:a:read")
        );
        let s = svc("connector = \"x\"\nallow = [\"a:read\"]\nask = [\"a:read\"]\n");
        assert_eq!(run(&s, None, Mode::Locked, "a:read", &[]), Verdict::Ask);
    }

    const RULES: &str = r#"
connector = "github"
[[rule]]
capability = "issues:write"
when = { repo = "acme/*" }
action = "allow"
[[rule]]
capability = "issues:write"
when = { repo = "acme/secret" }
action = "deny"
[[rule]]
capability = "pulls:write"
when = { repo = "acme/*", base = "main" }
action = "ask"
"#;

    #[test]
    fn rule_when_matches_param_glob() {
        let s = svc(RULES);
        let d = |c, p: &[(&str, &str)]| run(&s, None, Mode::Locked, c, p);
        assert_eq!(d("issues:write", &[("repo", "acme/web")]), Verdict::Allow);
        assert_eq!(
            d("issues:write", &[("repo", "other/web")]),
            deny("default_deny")
        );
        // The deny rule wins over the allow rule.
        assert_eq!(
            d("issues:write", &[("repo", "acme/secret")]),
            deny("deny:issues:write")
        );
        // A missing param means no match.
        assert_eq!(d("issues:write", &[]), deny("default_deny"));
        assert_eq!(
            d("issues:write", &[("org", "acme/web")]),
            deny("default_deny")
        );
        // Every `when` entry must match.
        assert_eq!(
            d("pulls:write", &[("repo", "acme/web"), ("base", "main")]),
            Verdict::Ask
        );
        assert_eq!(
            d("pulls:write", &[("repo", "acme/web"), ("base", "dev")]),
            deny("default_deny")
        );
        // `*` in a `when` does not cross `/`.
        assert_eq!(
            d("issues:write", &[("repo", "acme/web/x")]),
            deny("default_deny")
        );
    }

    fn overlay(allow: &[&str], ask: &[&str], deny: &[&str]) -> ServiceOverlay {
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect();
        ServiceOverlay {
            allow: v(allow),
            ask: v(ask),
            deny: v(deny),
        }
    }

    #[test]
    fn locked_overlay_allow_ignored() {
        let s = svc(SHOPIFY);
        let o = overlay(&["inventory:read"], &[], &[]);
        assert_eq!(
            run(&s, Some(&o), Mode::Locked, "inventory:read", &[]),
            deny("default_deny")
        );
    }

    #[test]
    fn developer_overlay_allow_counts() {
        let s = svc(SHOPIFY);
        let o = overlay(&["inventory:read"], &[], &[]);
        assert_eq!(
            run(&s, Some(&o), Mode::Developer, "inventory:read", &[]),
            Verdict::Allow
        );
    }

    #[test]
    fn overlay_deny_beats_system_allow() {
        let s = svc(SHOPIFY);
        let o = overlay(&[], &[], &["orders:read"]);
        for mode in [Mode::Locked, Mode::Developer] {
            assert_eq!(
                run(&s, Some(&o), mode, "orders:read", &[]),
                deny("deny:orders:read")
            );
        }
    }

    #[test]
    fn overlay_ask_beats_system_allow() {
        let s = svc(SHOPIFY);
        let o = overlay(&[], &["orders:read"], &[]);
        assert_eq!(
            run(&s, Some(&o), Mode::Locked, "orders:read", &[]),
            Verdict::Ask
        );
    }

    #[test]
    fn qualifier_scoped_allow() {
        let s = svc("connector = \"x\"\nallow = [\"issues:write:repo=acme/*\"]\n");
        assert_eq!(
            run(&s, None, Mode::Locked, "issues:write:repo=acme/web", &[]),
            Verdict::Allow
        );
        assert_eq!(
            run(&s, None, Mode::Locked, "issues:write:repo=acme/web/x", &[]),
            deny("default_deny")
        );
    }
}
