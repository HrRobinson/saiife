//! Built-in packs, embedded at compile time so the CLI works standalone with
//! no external pack files. At runtime saiife also loads `guard/packs/*.toml`
//! from userData; the built-ins are the shipped defaults.
//!
//! Ships `core.filesystem`, `core.git`, `core.secrets`, `core.self`,
//! `core.process` (default-on),
//! `core.lock` (on in locked mode, opt-in elsewhere) and the opt-in packs
//! `cloud.gcloud`, `cloud.aws`, `cloud.azure`, `iac.terraform`, `db.postgres`,
//! `db.mysql`, `db.mongo`, `container.docker`, and `container.k8s` (activated
//! via a profile — see `profile`).

use crate::pack::{load_pack_str, peek_header, Pack, PackWarning};

/// `(source_label, toml)` for every embedded pack.
const BUILTIN_SOURCES: &[(&str, &str)] = &[
    (
        "<builtin>core.filesystem",
        include_str!("../packs/core.filesystem.toml"),
    ),
    ("<builtin>core.git", include_str!("../packs/core.git.toml")),
    (
        "<builtin>core.secrets",
        include_str!("../packs/core.secrets.toml"),
    ),
    // Before core.self (the first deny wins): in locked mode a write to the
    // system audit dir, bound to `$SAIIFE_AUDIT_DIR` for both packs, is
    // named core.lock. After the other core packs, so their verdicts on
    // `sudo rm -rf /` and the like stay theirs.
    (
        "<builtin>core.lock",
        include_str!("../packs/core.lock.toml"),
    ),
    (
        "<builtin>core.self",
        include_str!("../packs/core.self.toml"),
    ),
    // After core.lock, so a locked-mode kill that names saiifed stays
    // core.lock's verdict.
    (
        "<builtin>core.process",
        include_str!("../packs/core.process.toml"),
    ),
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
    ("<builtin>db.mysql", include_str!("../packs/db.mysql.toml")),
    ("<builtin>db.mongo", include_str!("../packs/db.mongo.toml")),
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
    Catalog::builtin().load_all()
}

/// Pack sources whose headers (`id`, `default_on`) are read up front and
/// whose rules are compiled only on request. Compiling every rule regex is
/// most of a hook call's fixed cost, and a hook needs only the active packs.
pub struct Catalog {
    entries: Vec<Entry>,
}

struct Entry {
    source: &'static str,
    toml: &'static str,
    /// `(id, default_on, version)`; `None` if the header cannot be read.
    /// Such an entry is always loaded (and fails), so its failure is still
    /// reported.
    header: Option<(String, bool, u32)>,
}

impl Catalog {
    /// The embedded built-in packs.
    pub fn builtin() -> Self {
        Self::from_sources(BUILTIN_SOURCES)
    }

    /// `(source_label, toml)` pairs, in load order.
    pub fn from_sources(sources: &[(&'static str, &'static str)]) -> Self {
        let entries = sources
            .iter()
            .map(|&(source, toml)| Entry {
                source,
                toml,
                header: peek_header(toml),
            })
            .collect();
        Self { entries }
    }

    /// True if a pack with this id is in the catalog.
    pub fn knows(&self, id: &str) -> bool {
        self.entries
            .iter()
            .any(|e| e.header.as_ref().is_some_and(|(i, _, _)| i == id))
    }

    /// `(id, version, default_on)` of every pack whose header can be read,
    /// in load order, without compiling any rule.
    pub fn headers(&self) -> Vec<(String, u32, bool)> {
        self.entries
            .iter()
            .filter_map(|e| e.header.as_ref())
            .map(|(id, on, v)| (id.clone(), *v, *on))
            .collect()
    }

    /// Compile every pack.
    pub fn load_all(&self) -> (Vec<Pack>, Vec<PackWarning>) {
        self.load(|_| true)
    }

    /// Compile the packs `select_active` would keep: every default-on pack
    /// plus those whose id is in `enabled`. The others are never compiled.
    pub fn load_active(&self, enabled: &[String]) -> (Vec<Pack>, Vec<PackWarning>) {
        self.load(|(id, default_on, _)| *default_on || enabled.iter().any(|e| e == id))
    }

    fn load(&self, wanted: impl Fn(&(String, bool, u32)) -> bool) -> (Vec<Pack>, Vec<PackWarning>) {
        let mut packs = Vec::new();
        let mut warnings = Vec::new();
        for e in &self.entries {
            if e.header.as_ref().is_some_and(|h| !wanted(h)) {
                continue;
            }
            match load_pack_str(e.source, e.toml, &mut warnings) {
                Ok(p) => packs.push(p),
                Err(err) => {
                    let what = if err.is_broken_rule() {
                        "built-in pack has a broken rule"
                    } else {
                        "built-in pack failed to load"
                    };
                    warnings.push(PackWarning {
                        source: e.source.to_string(),
                        message: format!("{what}: {err}"),
                    });
                }
            }
        }
        (packs, warnings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The headers name exactly the packs a full load compiles, with the
    /// same version and default, without compiling anything.
    #[test]
    fn headers_match_the_compiled_packs() {
        let cat = Catalog::builtin();
        let before = crate::pack::compiled_packs();
        let headers = cat.headers();
        assert_eq!(crate::pack::compiled_packs(), before);
        let (packs, _) = cat.load_all();
        let want: Vec<(String, u32, bool)> = packs
            .iter()
            .map(|p| (p.id.clone(), p.version, p.default_on))
            .collect();
        assert_eq!(headers, want);
    }

    const BROKEN_CORE: &str = r#"
[pack]
id = "core.broken"
default_on = true
triggers = ["rm"]
[[deny]]
pattern = '('
reason = "bad regex"
[[deny]]
pattern = '^rm\s+-rf\s+/$'
reason = "wipes the disk"
"#;
    const OPT_IN: &str = r#"
[pack]
id = "opt.thing"
default_on = false
triggers = ["thing"]
[[deny]]
pattern = '^thing\s+drop'
reason = "drops the thing"
"#;
    const ALL_RULES_BROKEN: &str = r#"
[pack]
id = "opt.allbroken"
default_on = true
triggers = ["x"]
[[deny]]
pattern = '('
reason = "bad regex"
"#;
    const BAD_TOML: &str = "[pack\nid = 'x'";

    fn catalog() -> Catalog {
        Catalog::from_sources(&[
            ("<t>core.broken", BROKEN_CORE),
            ("<t>opt.thing", OPT_IN),
            ("<t>bad", BAD_TOML),
        ])
    }

    /// Only the active packs are compiled, and loading them reports the
    /// same warnings an eager load does.
    #[test]
    fn inactive_opt_in_pack_is_never_compiled() {
        let cat = catalog();
        let before = crate::pack::compiled_packs();
        let (packs, warnings) = cat.load_active(&[]);
        // core.broken compiled, the bad file attempted, opt.thing never.
        assert_eq!(crate::pack::compiled_packs() - before, 2);
        assert_eq!(
            packs.iter().map(|p| p.id.as_str()).collect::<Vec<_>>(),
            ["core.broken"]
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.source == "<t>core.broken" && w.message.contains("uncompilable regex")),
            "{warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.source == "<t>bad"
                && w.message.contains("built-in pack failed to load")),
            "{warnings:?}"
        );
        let (all, all_warnings) = cat.load_all();
        assert_eq!(all.len(), 2);
        assert_eq!(all_warnings.len(), warnings.len());
    }

    #[test]
    fn broken_rule_is_not_reported_as_failed_to_load() {
        let cat = Catalog::from_sources(&[("<t>allbroken", ALL_RULES_BROKEN)]);
        let (_, warnings) = cat.load_all();
        assert!(
            warnings
                .iter()
                .any(|w| w.message.starts_with("built-in pack has a broken rule: ")),
            "{warnings:?}"
        );
        assert!(
            !warnings
                .iter()
                .any(|w| w.message.contains("failed to load")),
            "{warnings:?}"
        );
    }

    #[test]
    fn enabled_opt_in_pack_is_compiled_in_source_order() {
        let cat = catalog();
        let (packs, _) = cat.load_active(&["opt.thing".to_string()]);
        assert_eq!(
            packs.iter().map(|p| p.id.as_str()).collect::<Vec<_>>(),
            ["core.broken", "opt.thing"]
        );
        assert!(cat.knows("opt.thing") && cat.knows("core.broken"));
        assert!(!cat.knows("bad") && !cat.knows("db.oracle"));
    }

    /// The lazy load of the shipped packs is the eager load filtered by
    /// `select_active`, for every single opt-in pack.
    #[test]
    fn builtin_lazy_load_matches_select_active() {
        let (all, _) = builtin_packs();
        let cat = Catalog::builtin();
        let ids = |v: &[Pack]| v.iter().map(|p| p.id.clone()).collect::<Vec<_>>();
        let mut cases = vec![vec![]];
        cases.extend(
            all.iter()
                .filter(|p| !p.default_on)
                .map(|p| vec![p.id.clone()]),
        );
        for enabled in cases {
            let (lazy, w) = cat.load_active(&enabled);
            assert!(w.is_empty(), "{w:?}");
            assert_eq!(
                ids(&lazy),
                ids(&crate::profile::select_active(all.clone(), &enabled)),
                "{enabled:?}"
            );
        }
    }

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
    /// `core.lock` is the exception: locked mode turns it on (spec §6.17).
    #[test]
    fn core_packs_default_on_others_opt_in() {
        let (packs, _) = builtin_packs();
        for p in &packs {
            let is_core = p.id.starts_with("core.") && p.id != "core.lock";
            assert_eq!(
                p.default_on, is_core,
                "pack {} default_on={} but is_core={}",
                p.id, p.default_on, is_core
            );
        }
    }
}
