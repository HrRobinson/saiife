//! Built-in packs, embedded at compile time so the CLI works standalone with
//! no external pack files.
//!
//! Ships `core.filesystem`, `core.git`, `core.secrets`, `core.self`,
//! `core.process` (default-on),
//! `core.lock` (on in locked mode, opt-in elsewhere) and the opt-in packs
//! `cloud.gcloud`, `cloud.aws`, `cloud.azure`, `iac.terraform`, `db.postgres`,
//! `db.mysql`, `db.mongo`, `container.docker`, and `container.k8s` (activated
//! via a profile — see `profile`).

use crate::canon::PathStyle;
use crate::pack::{lazy_pack, load_shipped, peek_header, LazyMeta, Pack, PackWarning};

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

/// Load and compile the embedded built-in packs for this host (fail-open: a bad
/// built-in is skipped with a warning, never fatal — though built-ins are
/// covered by tests).
pub fn builtin_packs() -> (Vec<Pack>, Vec<PackWarning>) {
    Catalog::builtin().load_all()
}

/// [`builtin_packs`] for a host of `style`, so any host can run the Windows rules.
pub fn builtin_packs_for(style: PathStyle) -> (Vec<Pack>, Vec<PackWarning>) {
    Catalog::builtin_for(style).load_all()
}

/// Every built-in pack with every rule, whatever this host is: what a policy may
/// name. A fleet's `[guard] ask` can name a Windows rule and be checked on Linux.
pub fn builtin_packs_every_rule() -> (Vec<Pack>, Vec<PackWarning>) {
    builtin_packs_for(PathStyle::Windows)
}

/// Whether the built-in pack `pack`'s `[[deny]]` rule `id` (alone, with the
/// pack's `[[allow]]` carve-outs) denies `command`. An unknown pack or
/// rule, or an engine over its budget, is `false`.
pub fn builtin_rule_denies(pack: &str, id: &str, command: &str) -> bool {
    // Compiled once per process (the daemon asks for every request).
    static PACKS: std::sync::OnceLock<Vec<Pack>> = std::sync::OnceLock::new();
    let packs = PACKS.get_or_init(|| builtin_packs().0);
    let Some(only) = packs
        .iter()
        .find(|p| p.id == pack)
        .and_then(|p| p.only_deny_id(id))
    else {
        return false;
    };
    let engine = crate::engine::Engine::new(vec![only]);
    match engine.evaluate(command) {
        crate::engine::Decision::Deny {
            pack: p, pattern, ..
        } => p == pack && engine.rule_id(&p, &pattern) == Some(id),
        _ => false,
    }
}

/// Pack sources whose headers (`id`, `default_on`) are read up front and
/// whose rules are compiled only on request. Compiling every rule regex is
/// most of a hook call's fixed cost, and a hook needs only the active packs.
pub struct Catalog {
    entries: Vec<Entry>,
    style: PathStyle,
}

struct Entry {
    source: &'static str,
    toml: &'static str,
    /// `(id, default_on, version)`; `None` if the header cannot be read.
    /// Such an entry is always loaded (and fails), so its failure is still
    /// reported.
    header: Option<(String, bool, u32)>,
    /// `[pack] lazy = true` (with triggers, without path rules): what
    /// `load_active` builds the pack from without compiling its rules.
    lazy: Option<LazyMeta>,
}

impl Catalog {
    /// The embedded built-in packs, for this host.
    pub fn builtin() -> Self {
        Self::builtin_for(PathStyle::host())
    }

    /// The embedded built-in packs, for a host of `style`: `platform` rules for
    /// another style are not compiled. See `pack`'s module docs.
    pub fn builtin_for(style: PathStyle) -> Self {
        Self::from_sources_for(BUILTIN_SOURCES, style)
    }

    /// `(source_label, toml)` pairs, in load order, for this host.
    pub fn from_sources(sources: &[(&'static str, &'static str)]) -> Self {
        Self::from_sources_for(sources, PathStyle::host())
    }

    fn from_sources_for(sources: &[(&'static str, &'static str)], style: PathStyle) -> Self {
        let entries = sources
            .iter()
            .map(|&(source, toml)| {
                let (header, lazy) = match peek_header(toml, style) {
                    Some((h, l)) => (Some(h), l),
                    None => (None, None),
                };
                Entry {
                    source,
                    toml,
                    header,
                    lazy,
                }
            })
            .collect();
        Self { entries, style }
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
        self.load(|_| true, false)
    }

    /// Compile the packs `select_active` would keep: every default-on pack
    /// plus those whose id is in `enabled`. The others are never compiled.
    /// A pack that says `lazy = true` is compiled only when the engine
    /// first sees one of its triggers (`core.process`: most hook calls
    /// never name `kill`).
    pub fn load_active(&self, enabled: &[String]) -> (Vec<Pack>, Vec<PackWarning>) {
        self.load(
            |(id, default_on, _)| *default_on || enabled.iter().any(|e| e == id),
            true,
        )
    }

    fn load(
        &self,
        wanted: impl Fn(&(String, bool, u32)) -> bool,
        allow_lazy: bool,
    ) -> (Vec<Pack>, Vec<PackWarning>) {
        let mut packs = Vec::new();
        let mut warnings = Vec::new();
        for e in &self.entries {
            if e.header.as_ref().is_some_and(|h| !wanted(h)) {
                continue;
            }
            if let (true, Some(h), Some(meta)) = (allow_lazy, &e.header, &e.lazy) {
                packs.push(lazy_pack(e.source, e.toml, h, meta, self.style));
                continue;
            }
            match load_shipped(e.source, e.toml, self.style, &mut warnings) {
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

    #[test]
    fn builtin_rule_denies_only_with_that_rule() {
        let fp = |cmd| builtin_rule_denies("core.git", "force-push", cmd);
        assert!(fp("git push --force origin main"));
        // The pack's carve-out still applies; other commands do not match.
        assert!(!fp("git push --force-with-lease origin main"));
        assert!(!fp("echo hi"));
        assert!(!fp("git reset --hard"));
        assert!(!builtin_rule_denies(
            "core.git",
            "no-such",
            "git push --force"
        ));
        assert!(!builtin_rule_denies(
            "no.pack",
            "force-push",
            "git push --force"
        ));
        assert!(builtin_rule_denies(
            "db.postgres",
            "drop-database",
            "psql -c 'DROP DATABASE prod'"
        ));
    }

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

    const LAZY: &str = r#"
[pack]
id = "core.lazy"
triggers = ["zap"]
lazy = true
[[deny]]
pattern = '^zap\s+-all'
reason = "zaps everything"
"#;

    /// Final review I5c: a `lazy = true` pack is compiled only when a
    /// command line holds one of its triggers, then judges as before.
    #[test]
    fn lazy_pack_compiles_on_its_trigger_only() {
        let cat = Catalog::from_sources(&[("<t>core.lazy", LAZY)]);
        let before = crate::pack::compiled_packs();
        let (packs, warnings) = cat.load_active(&[]);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert!(packs[0].is_lazy() && packs[0].has_deny());
        let e = crate::engine::Engine::new(packs);
        assert!(!e.evaluate("ls -la").is_deny());
        assert!(!e.evaluate("git status && cargo test").is_deny());
        assert_eq!(
            crate::pack::compiled_packs(),
            before,
            "no trigger, no compile"
        );
        assert!(e.evaluate("zap -all").is_deny());
        assert!(e.evaluate("timeout 5 zap -all").is_deny());
        assert_eq!(crate::pack::compiled_packs(), before + 1, "compiled once");
        assert!(!e.evaluate("zap one").is_deny());
        assert_eq!(crate::pack::compiled_packs(), before + 1);
        // An eager load (packs, report) compiles it at once.
        let (all, _) = cat.load_all();
        assert!(!all[0].is_lazy());
        assert_eq!(all[0].deny_rules().len(), 1);
    }

    #[test]
    fn core_process_is_lazy_in_the_hook() {
        let (packs, _) = Catalog::builtin().load_active(&[]);
        let p = packs.iter().find(|p| p.id == "core.process").unwrap();
        assert!(p.is_lazy());
        assert!(p.deny_rules().len() > 5);
    }

    /// A lazy pack keeps the rule and the triggers of its load's host style, and
    /// matches an eager load of the same style.
    #[test]
    fn a_lazy_pack_follows_the_host_style() {
        let has = |p: &Pack| {
            p.deny_rules()
                .iter()
                .any(|r| r.id.as_deref() == Some("windows-kill-saiife"))
        };
        for (style, windows) in [(PathStyle::Posix, false), (PathStyle::Windows, true)] {
            let (lazy, w) = Catalog::builtin_for(style).load_active(&[]);
            assert!(w.is_empty(), "{w:?}");
            let lazy = lazy.iter().find(|p| p.id == "core.process").unwrap();
            assert!(lazy.is_lazy());
            assert_eq!(has(lazy), windows);
            assert_eq!(lazy.triggers.iter().any(|t| t == "(?i)wmic"), windows);
            assert!(lazy.fits(style));
            let (eager, _) = builtin_packs_for(style);
            let eager = eager.iter().find(|p| p.id == "core.process").unwrap();
            assert_eq!(lazy.deny_rules().len(), eager.deny_rules().len());
            assert_eq!(lazy.triggers, eager.triggers);
        }
    }

    /// A bad marker in a lazy pack must not be lost inside `LazyRules::get`: the
    /// header cannot be read, so the catalog loads it at once and reports it.
    #[test]
    fn a_bad_marker_in_a_lazy_pack_is_reported() {
        const BAD: &str = "[pack]\nid = \"t\"\ntriggers = [\"x\"]\nlazy = true\n[[deny]]\npattern = \"x\"\nreason = \"r\"\nplatform = \"plan9\"\n";
        let (packs, warnings) = Catalog::from_sources(&[("<t>", BAD)]).load_active(&[]);
        assert!(packs.is_empty());
        assert!(
            warnings
                .iter()
                .any(|w| w.message.contains("built-in pack failed to load")),
            "{warnings:?}"
        );
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

    /// For both styles: a broken Windows rule fails here on any host.
    #[test]
    fn all_builtins_load_clean() {
        for style in [PathStyle::Posix, PathStyle::Windows] {
            let (packs, warnings) = builtin_packs_for(style);
            assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
            assert!(!packs.is_empty(), "at least one built-in pack ships");
            assert!(
                packs.iter().any(|p| p.id == "core.git"),
                "core.git always ships"
            );
        }
    }

    /// A policy may name a rule of any OS, on any OS.
    #[test]
    fn the_every_rule_load_holds_every_rule() {
        let (every, w) = builtin_packs_every_rule();
        assert!(w.is_empty(), "{w:?}");
        for style in [PathStyle::Posix, PathStyle::Windows] {
            let (packs, _) = builtin_packs_for(style);
            for p in &packs {
                let all = every.iter().find(|e| e.id == p.id).unwrap();
                assert_eq!(all.version, p.version);
                for r in p.deny_rules() {
                    assert!(
                        all.deny_rules().iter().any(|a| a.pattern == r.pattern),
                        "{}: {:?}",
                        p.id,
                        r.id
                    );
                }
            }
        }
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
