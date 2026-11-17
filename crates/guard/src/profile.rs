//! Pack profile selection.
//!
//! The default profile is the **default-on** packs only (`core.*`). Opt-in
//! packs (`cloud.gcloud`, `db.postgres`) are inactive unless explicitly
//! enabled — this mirrors the spec's per-environment `guard.packs` list, which
//! is additive to the default-on set. saiife resolves an environment's
//! enabled list and hands it to the binary; the crate stays app-agnostic.

use crate::pack::{Pack, RuleWhere};

/// Where the guard runs: on the host, or inside a box. A user rule marked
/// `where = "host"` is left out of the box profile; every other rule stays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Profile {
    #[default]
    Host,
    Box,
}

impl Profile {
    pub fn from_name(s: &str) -> Option<Profile> {
        match s {
            "host" => Some(Profile::Host),
            "box" => Some(Profile::Box),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Profile::Host => "host",
            Profile::Box => "box",
        }
    }
}

impl RuleWhere {
    /// Whether a rule marked so is in force under `p`: not a host rule in a box.
    pub fn applies_in(self, p: Profile) -> bool {
        !matches!((self, p), (RuleWhere::Host, Profile::Box))
    }
}

/// Keep the packs that are active under this profile: every `default_on` pack,
/// plus any whose `id` appears in `enabled`.
pub fn select_active(packs: Vec<Pack>, enabled: &[String]) -> Vec<Pack> {
    packs
        .into_iter()
        .filter(|p| p.default_on || enabled.iter().any(|e| e == &p.id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::load_pack_str;

    fn pack(id: &str, default_on: bool) -> Pack {
        let toml = format!(
            r#"
[pack]
id = "{id}"
default_on = {default_on}
[[deny]]
pattern = 'x'
reason = "r"
"#
        );
        let mut w = Vec::new();
        load_pack_str("<t>", &toml, &mut w).unwrap()
    }

    #[test]
    fn default_profile_is_default_on_only() {
        let packs = vec![pack("core.x", true), pack("opt.y", false)];
        let active = select_active(packs, &[]);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, "core.x");
    }

    #[test]
    fn enabling_activates_an_opt_in_pack() {
        let packs = vec![pack("core.x", true), pack("opt.y", false)];
        let active = select_active(packs, &["opt.y".to_string()]);
        assert_eq!(active.len(), 2);
    }

    #[test]
    fn profile_names_round_trip() {
        assert_eq!(Profile::from_name("host"), Some(Profile::Host));
        assert_eq!(Profile::from_name("box"), Some(Profile::Box));
        assert_eq!(Profile::from_name("vm"), None);
        assert_eq!(Profile::Box.name(), "box");
        assert_eq!(Profile::default(), Profile::Host);
    }

    #[test]
    fn host_rules_do_not_apply_in_a_box() {
        assert!(!RuleWhere::Host.applies_in(Profile::Box));
        assert!(RuleWhere::Host.applies_in(Profile::Host));
        assert!(RuleWhere::Everywhere.applies_in(Profile::Box));
        assert!(RuleWhere::Everywhere.applies_in(Profile::Host));
    }
}
