//! Built-in packs, embedded at compile time so the CLI works standalone with
//! no external pack files.
//!
//! Ships `core.filesystem`, `core.git`, `core.secrets`, `core.self`,
//! `core.process` (default-on),
//! `core.lock` (on in locked mode, opt-in elsewhere) and the opt-in packs
//! `cloud.gcloud`, `cloud.aws`, `cloud.azure`, `iac.terraform`, `db.postgres`,
//! `db.mysql`, `db.mongo`, `container.docker`, and `container.k8s` (activated
//! via a profile — see `profile`).
//!
//! The packs are written as `packs/*.toml` and shipped as Rust data that
//! `build.rs` makes from them, so no hook parses TOML for them;
//! `builtin_data_is_the_toml` keeps the two the same.

use crate::canon::PathStyle;
use crate::pack::{
    data_header, lazy_pack, load_shipped, peek_header, Compile, LazyMeta, Pack, PackWarning,
    Shipped,
};
use crate::pack_raw::RawPackFile;

/// `(source_label, file)` for every built-in pack, in load order: the first
/// deny wins, so the order is part of every verdict. `file` names its
/// `packs/*.toml`, which `build.rs` turned into [`data::BUILTIN_DATA`].
const BUILTIN_ORDER: &[(&str, &str)] = &[
    ("<builtin>core.filesystem", "core.filesystem.toml"),
    ("<builtin>core.git", "core.git.toml"),
    ("<builtin>core.secrets", "core.secrets.toml"),
    // Before core.self (the first deny wins): in locked mode a write to the
    // system audit dir, bound to `$SAIIFE_AUDIT_DIR` for both packs, is
    // named core.lock. After the other core packs, so their verdicts on
    // `sudo rm -rf /` and the like stay theirs.
    ("<builtin>core.lock", "core.lock.toml"),
    ("<builtin>core.self", "core.self.toml"),
    // After core.lock, so a locked-mode kill that names saiifed stays
    // core.lock's verdict.
    ("<builtin>core.process", "core.process.toml"),
    ("<builtin>cloud.gcloud", "cloud.gcloud.toml"),
    ("<builtin>cloud.aws", "cloud.aws.toml"),
    ("<builtin>iac.terraform", "iac.terraform.toml"),
    ("<builtin>db.postgres", "db.postgres.toml"),
    ("<builtin>cloud.azure", "cloud.azure.toml"),
    ("<builtin>db.mysql", "db.mysql.toml"),
    ("<builtin>db.mongo", "db.mongo.toml"),
    ("<builtin>container.docker", "container.docker.toml"),
    ("<builtin>container.k8s", "container.k8s.toml"),
];

/// The built-in packs as Rust data (`build.rs`, from `packs/*.toml`).
mod data {
    use crate::pack_raw::{
        OperandSyntax, RawMeta, RawPackFile, RawPathRule, RawRule, RuleAccess, RulePlatform,
    };
    use std::borrow::Cow;

    include!(concat!(env!("OUT_DIR"), "/builtin_packs.rs"));
}

/// The data of the built-in pack in `file`.
fn builtin_data(file: &str) -> Option<&'static RawPackFile> {
    data::BUILTIN_DATA
        .iter()
        .find(|(f, _)| *f == file)
        .map(|(_, raw)| raw)
}

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
    src: Shipped,
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
    /// No TOML is parsed: the packs are Rust data (`build.rs`).
    pub fn builtin_for(style: PathStyle) -> Self {
        let entries = BUILTIN_ORDER
            .iter()
            .map(|&(source, file)| match builtin_data(file) {
                Some(raw) => {
                    let (header, lazy) = match data_header(raw, style) {
                        Some((h, l)) => (Some(h), l),
                        None => (None, None),
                    };
                    Entry {
                        source,
                        src: Shipped::Data(raw),
                        header,
                        lazy,
                    }
                }
                // Never (a test pins the list to the data): an entry whose
                // load fails, so a warning names it.
                None => Entry {
                    source,
                    src: Shipped::Toml(""),
                    header: None,
                    lazy: None,
                },
            })
            .collect();
        Self { entries, style }
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
                    src: Shipped::Toml(toml),
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
    /// never name `kill`). A built-in pack's rule regexes are compiled
    /// when a command first reaches the rule (`Compile::OnFirstUse`).
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
        // Only `load_active` (a hook) defers the regexes; `load_all` compiles
        // them all and reports any that does not compile.
        let compile = if allow_lazy {
            Compile::OnFirstUse
        } else {
            Compile::Now
        };
        for e in &self.entries {
            if e.header.as_ref().is_some_and(|h| !wanted(h)) {
                continue;
            }
            if let (true, Some(h), Some(meta)) = (allow_lazy, &e.header, &e.lazy) {
                packs.push(lazy_pack(e.source, e.src, h, meta, self.style, compile));
                continue;
            }
            match load_shipped(e.source, e.src, self.style, compile, &mut warnings) {
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

    fn packs_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("packs")
    }

    /// `packs/*.toml` as they are on disk now, by file name, sorted.
    fn toml_on_disk() -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = std::fs::read_dir(packs_dir())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .map(|p| {
                let name = p.file_name().unwrap().to_string_lossy().into_owned();
                (name, std::fs::read_to_string(&p).unwrap())
            })
            .collect();
        out.sort();
        out
    }

    /// The catalog of the TOML on disk, as `BUILTIN_ORDER` lists it: what
    /// the built-in packs were before they were Rust data.
    fn toml_catalog(style: PathStyle) -> Catalog {
        let disk = toml_on_disk();
        let sources: Vec<(&'static str, &'static str)> = BUILTIN_ORDER
            .iter()
            .map(|&(label, file)| {
                let text = &disk.iter().find(|(f, _)| f == file).unwrap().1;
                (label, &*Box::leak(text.clone().into_boxed_str()))
            })
            .collect();
        Catalog::from_sources_for(&sources, style)
    }

    /// The built-in data is the TOML: each file parses to exactly its data,
    /// and the files, the data and the load order name the same packs. A
    /// TOML edited without a rebuild (or an emitter in `build.rs` that
    /// mixes up two fields) fails here.
    #[test]
    fn builtin_data_is_the_toml() {
        let disk = toml_on_disk();
        let files: Vec<&str> = disk.iter().map(|(f, _)| f.as_str()).collect();
        let data: Vec<&str> = data::BUILTIN_DATA.iter().map(|(f, _)| *f).collect();
        assert_eq!(files, data, "packs/ and the built-in data differ: rebuild");
        for ((file, text), (_, raw)) in disk.iter().zip(data::BUILTIN_DATA) {
            let parsed: RawPackFile = toml::from_str(text).unwrap();
            assert_eq!(&parsed, raw, "{file}");
        }
        let mut order: Vec<&str> = BUILTIN_ORDER.iter().map(|(_, f)| *f).collect();
        order.sort();
        assert_eq!(order, data, "each pack is in BUILTIN_ORDER once");
        for (label, file) in BUILTIN_ORDER {
            let id = &builtin_data(file).unwrap().pack.id;
            assert_eq!(*label, format!("<builtin>{id}"), "{file}");
        }
    }

    /// Loaded from the data, every pack is what it was loaded from the TOML:
    /// the same headers (so the same pack list and policy hash), and every
    /// rule, path rule and trigger the same, for both host styles.
    #[test]
    fn data_packs_load_as_the_toml_did() {
        for style in [PathStyle::Posix, PathStyle::Windows] {
            let (data, toml) = (Catalog::builtin_for(style), toml_catalog(style));
            assert_eq!(data.headers(), toml.headers(), "{style:?}");
            let (a, wa) = data.load_all();
            let (b, wb) = toml.load_all();
            assert!(wa.is_empty() && wb.is_empty(), "{wa:?} {wb:?}");
            assert_eq!(format!("{a:?}"), format!("{b:?}"), "{style:?}");
            for enabled in [vec![], vec!["core.lock".to_string()]] {
                let ids = |c: &Catalog| {
                    let (p, w) = c.load_active(&enabled);
                    assert!(w.is_empty(), "{w:?}");
                    p.iter()
                        .map(|p| (p.id.clone(), p.version, p.triggers.clone()))
                        .collect::<Vec<_>>()
                };
                assert_eq!(ids(&data), ids(&toml), "{style:?} {enabled:?}");
            }
        }
    }

    /// A hook's load compiles no rule regex; a command compiles only the
    /// rules it reaches, once per engine, and judges as an eager load does.
    #[test]
    fn hook_load_compiles_rules_on_first_use() {
        let enabled = ["core.lock".to_string()];
        let (packs, w) = Catalog::builtin().load_active(&enabled);
        assert!(w.is_empty(), "{w:?}");
        let compiled = |packs: &[Pack], id: &str| {
            let p = packs.iter().find(|p| p.id == id).unwrap();
            p.allow_rules()
                .iter()
                .chain(p.deny_rules())
                .filter(|r| r.is_compiled())
                .count()
        };
        // Clones share the regexes: `packs` sees what the engine compiles.
        let engine = crate::engine::Engine::new(packs.clone());
        for p in &packs {
            assert_eq!(compiled(&packs, &p.id), 0, "{}", p.id);
        }
        assert!(!engine.evaluate("ls -la").is_deny());
        for p in &packs {
            assert_eq!(compiled(&packs, &p.id), 0, "ls compiles nothing: {}", p.id);
        }
        let d = engine.evaluate("git push --force origin main");
        assert!(matches!(&d, crate::Decision::Deny { pack, .. } if pack == "core.git"));
        assert!(compiled(&packs, "core.git") > 0);
        assert_eq!(compiled(&packs, "core.secrets"), 0);
        assert_eq!(compiled(&packs, "core.filesystem"), 0);
        // The eager load has every regex compiled, and judges the same.
        let (eager, _) = builtin_packs();
        let eager = crate::profile::select_active(eager, &enabled);
        for p in &eager {
            assert_eq!(
                compiled(&eager, &p.id),
                p.rule_count() - p.allow_path.len() - p.deny_path.len()
            );
        }
        let eager = crate::engine::Engine::new(eager);
        for cmd in [
            "git push --force origin main",
            "git push --force-with-lease",
            "ls -la",
        ] {
            assert_eq!(
                format!("{:?}", engine.evaluate(cmd)),
                format!("{:?}", eager.evaluate(cmd)),
                "{cmd}"
            );
        }
    }

    /// The built-in packs judge alike whether their regexes were compiled at
    /// load or on first use, nested lines and lazy packs included (the
    /// corpora pin this at scale: `tests/prebuilt_packs.rs`).
    #[test]
    fn first_use_compiles_judge_as_compiled_ones() {
        let (lazy, _) = Catalog::builtin().load_active(&[]);
        let (eager, _) = builtin_packs();
        let eager = crate::profile::select_active(eager, &[]);
        let budget = std::time::Duration::from_secs(30);
        let lazy = crate::engine::Engine::new(lazy).with_budget(budget);
        let eager = crate::engine::Engine::new(eager).with_budget(budget);
        for cmd in [
            "rm -rf /",
            "cat ~/.ssh/id_rsa",
            "env",
            "pkill -n",
            "kill -9 -1",
            "git reset --hard",
            "sudo rm -rf --no-preserve-root /",
            "echo $(rm -rf /)",
            "bash -c 'git clean -fdx'",
        ] {
            assert_eq!(
                format!("{:?}", lazy.evaluate(cmd)),
                format!("{:?}", eager.evaluate(cmd)),
                "{cmd}"
            );
        }
    }

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
