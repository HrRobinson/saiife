//! Pack profile selection.
//!
//! The default profile is the **default-on** packs only (`core.*`). Opt-in
//! packs (`cloud.gcloud`, `db.postgres`) are inactive unless explicitly
//! enabled — this mirrors the spec's per-environment `guard.packs` list, which
//! is additive to the default-on set. localflow resolves an environment's
//! enabled list and hands it to the binary; the crate stays app-agnostic.

use crate::pack::Pack;

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
}
