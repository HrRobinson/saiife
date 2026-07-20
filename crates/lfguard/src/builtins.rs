//! Built-in packs, embedded at compile time so the CLI works standalone with
//! no external pack files. At runtime localflow also loads `guard/packs/*.toml`
//! from userData; the built-ins are the shipped defaults.
//!
//! Ships `core.filesystem` + `core.git` (default-on) and the opt-in packs
//! `cloud.gcloud`, `cloud.aws`, `cloud.azure`, `iac.terraform`, `db.postgres`,
//! `db.mysql`, `db.mongo`, `container.docker`, and `container.k8s` (activated
//! via a profile — see `profile`).

use crate::pack::{load_pack_str, Pack, PackWarning};

/// `(source_label, toml)` for every embedded pack.
const BUILTIN_SOURCES: &[(&str, &str)] = &[
    (
        "<builtin>core.filesystem",
        include_str!("../packs/core.filesystem.toml"),
    ),
    ("<builtin>core.git", include_str!("../packs/core.git.toml")),
    (
        "<builtin>cloud.gcloud",
        include_str!("../packs/cloud.gcloud.toml"),
    ),
    (
        "<builtin>cloud.aws",
        include_str!("../packs/cloud.aws.toml"),
    ),
    (
        "<builtin>iac.terraform",
        include_str!("../packs/iac.terraform.toml"),
    ),
    (
        "<builtin>db.postgres",
        include_str!("../packs/db.postgres.toml"),
    ),
    (
        "<builtin>cloud.azure",
        include_str!("../packs/cloud.azure.toml"),
    ),
    (
        "<builtin>db.mysql",
        include_str!("../packs/db.mysql.toml"),
    ),
    (
        "<builtin>db.mongo",
        include_str!("../packs/db.mongo.toml"),
    ),
    (
        "<builtin>container.docker",
        include_str!("../packs/container.docker.toml"),
    ),
    (
        "<builtin>container.k8s",
        include_str!("../packs/container.k8s.toml"),
    ),
];

/// Load and compile the embedded built-in packs (fail-open: a bad built-in is
/// skipped with a warning, never fatal — though built-ins are covered by tests).
pub fn builtin_packs() -> (Vec<Pack>, Vec<PackWarning>) {
    let mut packs = Vec::new();
    let mut warnings = Vec::new();
    for (source, toml) in BUILTIN_SOURCES {
        match load_pack_str(source, toml, &mut warnings) {
            Ok(p) => packs.push(p),
            Err(e) => warnings.push(PackWarning {
                source: source.to_string(),
                message: format!("built-in pack failed to load: {e}"),
            }),
        }
    }
    (packs, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_builtins_load_clean() {
        let (packs, warnings) = builtin_packs();
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        assert!(!packs.is_empty(), "at least one built-in pack ships");
        assert!(
            packs.iter().any(|p| p.id == "core.git"),
            "core.git always ships"
        );
    }

    /// Naming convention: `core.*` packs are default-on; other namespaces
    /// (`cloud.*`, `db.*`) are opt-in. Holds for whatever subset is registered.
    #[test]
    fn core_packs_default_on_others_opt_in() {
        let (packs, _) = builtin_packs();
        for p in &packs {
            let is_core = p.id.starts_with("core.");
            assert_eq!(
                p.default_on, is_core,
                "pack {} default_on={} but is_core={}",
                p.id, p.default_on, is_core
            );
        }
    }
}
