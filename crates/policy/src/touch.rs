//! Touch marks (spec §8.2, plan 26 D7): which calls always need a touch.
//! Classes are plain strings here; the policy crate does not know the touch
//! crate. Environments cannot set marks (their keys are closed), so an
//! environment cannot remove one.

use crate::capability::{self, Capability};
use crate::system::SystemConfig;

/// The touch class a call to `service` with capability `cap` is marked
/// with, or `None`. `cfg` is the environment-applied config. First that
/// holds: a `deploy` pattern matches (`"deploy"`); the service's secret is
/// `sensitive` (`"secret:sensitive"`); `real_system` (`"egress:external"`).
pub fn class_for(cfg: &SystemConfig, service: &str, cap: &Capability) -> Option<&'static str> {
    let svc = cfg.services.get(service)?;
    if svc
        .deploy
        .iter()
        .any(|p| capability::matches_with(p, cap, true))
    {
        return Some("deploy");
    }
    if svc
        .secret
        .as_ref()
        .and_then(|s| cfg.secrets.get(s))
        .is_some_and(|s| s.sensitive)
    {
        return Some("secret:sensitive");
    }
    if svc.real_system {
        return Some("egress:external");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::class_for;
    use crate::capability::Capability;
    use crate::effective::{active_packs, effective_policy, policy_hash};
    use crate::environment::apply;
    use crate::system::SystemConfig;

    fn cfg(text: &str) -> SystemConfig {
        toml::from_str(text).unwrap()
    }

    fn cap(s: &str) -> Capability {
        Capability::parse(s).unwrap()
    }

    #[test]
    fn marks_parse() {
        let c = cfg("version = 2\n[services.erp]\nconnector = \"x\"\n\
             deploy = [\"deploy:*\"]\nreal_system = true\n[secrets.k]\nsensitive = true\n");
        assert_eq!(c.services["erp"].deploy, vec!["deploy:*".to_string()]);
        assert!(c.services["erp"].real_system);
        assert!(c.secrets["k"].sensitive);
        let bad = toml::from_str::<SystemConfig>(
            "version = 2\n[services.erp]\nconnector = \"x\"\ndeplyo = []\n",
        );
        assert!(bad.is_err());
    }

    #[test]
    fn class_order() {
        let c = cfg("version = 2\n\
             [services.a]\nconnector = \"x\"\nsecret = \"k\"\nreal_system = true\n\
             deploy = [\"deploy:*\"]\n\
             [services.b]\nconnector = \"x\"\nreal_system = true\n\
             [services.c]\nconnector = \"x\"\n\
             [secrets.k]\nsensitive = true\n");
        assert_eq!(class_for(&c, "a", &cap("deploy:write")), Some("deploy"));
        assert_eq!(
            class_for(&c, "a", &cap("orders:read")),
            Some("secret:sensitive")
        );
        assert_eq!(
            class_for(&c, "b", &cap("orders:read")),
            Some("egress:external")
        );
        assert_eq!(class_for(&c, "c", &cap("orders:read")), None);
        assert_eq!(class_for(&c, "nope", &cap("orders:read")), None);
    }

    #[test]
    fn env_secret_counts() {
        let c = cfg("version = 2\n[services.erp]\nconnector = \"x\"\n\
             [secrets.k]\nsensitive = true\n\
             [environments.prod.services.erp]\nsecret = \"k\"\n");
        assert_eq!(class_for(&c, "erp", &cap("orders:read")), None);
        let applied = apply(&c, "prod").unwrap();
        assert_eq!(
            class_for(&applied, "erp", &cap("orders:read")),
            Some("secret:sensitive")
        );
    }

    #[test]
    fn env_cannot_set_marks() {
        for key in ["real_system = false", "deploy = []", "sensitive = true"] {
            let text = format!(
                "version = 2\n[services.erp]\nconnector = \"x\"\n\
                 [environments.prod.services.erp]\n{key}\n"
            );
            assert!(toml::from_str::<SystemConfig>(&text).is_err(), "{key}");
        }
    }

    #[test]
    fn policy_hash_unchanged_without_marks() {
        let c = cfg(
            "version = 2\n[services.erp]\nconnector = \"x\"\nsecret = \"k\"\n\
             allow = [\"orders:read\"]\nask = [\"deploy:*\"]\n\
             [secrets.k]\nrun_allow = [\"/usr/bin/true\"]\n",
        );
        let (packs, _) = active_packs(&c, &[], None);
        let h = policy_hash(&effective_policy(&c, &packs, None, None));
        // Taken from a run on 053ce31, before ServiceCfg/SecretCfg had marks.
        assert_eq!(
            h,
            "sha256:140b4130584ebed73981cc29b52eef0fad64cfa965b5836eb3a3fffb7fe6d9cb"
        );
    }
}
