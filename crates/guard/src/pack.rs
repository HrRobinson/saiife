//! Pack model + TOML loader.
//!
//! A pack is metadata plus an allow-regex list and a deny-regex list, each deny
//! carrying a human-readable reason, plus optional path rules
//! (`[[deny_path]]` / `[[allow_path]]`, see `crate::pathrule`) judged against
//! the files a tool or command touches. Loading is fail-open at the granularity of
//! the failure: an uncompilable regex drops that *rule* (with a warning), a
//! malformed or duplicate-id file drops that *pack* (with a warning) — neither
//! aborts the load of the rest.
//!
//! Pack file schema (unknown keys are a load error):
//!
//! ```toml
//! [pack]        # id, name, description, default_on, version, triggers,
//!               # substitution_failsafe
//! [[allow]] / [[deny]]
//! pattern = "regex"           # matched against the effective command line
//! reason = "..."              # required for deny
//! whole_segment = true        # match the whole segment instead: wrappers
//!                             # (`env`, `sudo`) and leading `NAME=value`
//!                             # assignments included
//! after_env_change = true     # only after an earlier segment of the same
//!                             # command line changed PATH/HOME/XDG_DATA_HOME
//! [[allow_path]] / [[deny_path]]
//! glob = "~/.ssh/id_*"        # see `crate::pathrule`
//! access = "read|write|any"
//! ancestors = true            # deny_path only: match the proper ancestors
//!                             # of a variable-rooted, wildcard-free glob
//!                             # (write access), e.g. `rm -rf ~/.local/share`
//! ```
//!
//! An `[[allow]]` match exempts the command only from its own pack's
//! `[[deny]]` rules (as `[[allow_path]]` does for paths); other packs still
//! judge it, and their first deny wins.

use std::fs;
use std::path::Path;

use regex::Regex;
use serde::Deserialize;

use crate::pathrule::{validate_ancestors, validate_glob, PathRule, RuleAccess};
use crate::prefilter::Prefilter;

/// A compiled matching rule: a regex plus the reason shown when it fires.
#[derive(Debug, Clone)]
pub struct Rule {
    pub pattern: String,
    pub regex: Regex,
    pub reason: String,
    /// Match against the whole segment (wrappers such as `env`/`sudo` and
    /// leading `NAME=value` assignments included) instead of the effective
    /// command after them.
    pub whole_segment: bool,
    /// Applies only to a command that comes after an earlier segment of the
    /// same command line exported or assigned `PATH` (other than appending
    /// to it), `HOME` or `XDG_DATA_HOME`; matches the effective command.
    pub after_env_change: bool,
}

/// A loaded, compiled pack.
#[derive(Debug, Clone)]
pub struct Pack {
    pub id: String,
    pub name: String,
    pub description: String,
    pub default_on: bool,
    pub version: u32,
    pub triggers: Vec<String>,
    /// A command this pack has deny rules for is blocked when an argument
    /// is a command substitution (`rm -rf $(…)`). Packs whose triggers are
    /// everyday tools (`gh`, `kubectl`) turn this off.
    pub substitution_failsafe: bool,
    pub allow: Vec<Rule>,
    pub deny: Vec<Rule>,
    /// Path carve-outs: a path matching one is exempt from THIS pack's
    /// `deny_path` rules (never from another pack's).
    pub allow_path: Vec<PathRule>,
    pub deny_path: Vec<PathRule>,
    /// Built once from `triggers` at load.
    prefilter: Prefilter,
}

impl Pack {
    /// The pack's pre-filter, built from its literal triggers.
    pub fn prefilter(&self) -> &Prefilter {
        &self.prefilter
    }

    /// Command rules plus path rules.
    pub fn rule_count(&self) -> usize {
        self.allow.len() + self.deny.len() + self.allow_path.len() + self.deny_path.len()
    }
}

/// A non-fatal problem encountered while loading (surfaced, never silent).
#[derive(Debug, Clone)]
pub struct PackWarning {
    pub source: String,
    pub message: String,
}

/// A fatal problem for a single pack file (the file is skipped; others load).
#[derive(Debug, thiserror::Error)]
pub enum PackError {
    #[error("invalid pack TOML: {0}")]
    Toml(String),
    #[error("pack is missing a deny reason for {0:?}")]
    MissingReason(String),
    #[error("pack has no id")]
    MissingId,
    #[error("no usable rules after compilation")]
    NoRules,
}

// ---- Raw (deserialized) shape ------------------------------------------------

#[derive(Debug, Deserialize)]
struct RawPackFile {
    pack: RawMeta,
    #[serde(default)]
    allow: Vec<RawRule>,
    #[serde(default)]
    deny: Vec<RawRule>,
    #[serde(default)]
    allow_path: Vec<RawPathRule>,
    #[serde(default)]
    deny_path: Vec<RawPathRule>,
}

#[derive(Debug, Deserialize)]
struct RawMeta {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default = "default_true")]
    default_on: bool,
    #[serde(default = "default_version")]
    version: u32,
    #[serde(default)]
    triggers: Vec<String>,
    #[serde(default = "default_true")]
    substitution_failsafe: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    pattern: String,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    whole_segment: bool,
    #[serde(default)]
    after_env_change: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPathRule {
    glob: String,
    #[serde(default = "default_access")]
    access: RuleAccess,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    ancestors: bool,
}

fn default_access() -> RuleAccess {
    RuleAccess::Any
}

fn default_true() -> bool {
    true
}
fn default_version() -> u32 {
    1
}

// ---- Loading -----------------------------------------------------------------

/// Compile a rule list. A rule whose regex fails to compile is dropped with a
/// warning. For deny rules, a missing reason is a hard error (fail-open matters
/// only when the guard malfunctions, not when a rule is authored to block
/// without telling the user why). `require_reason` distinguishes deny vs allow.
fn compile_rules(
    source: &str,
    raw: Vec<RawRule>,
    require_reason: bool,
    warnings: &mut Vec<PackWarning>,
) -> Result<Vec<Rule>, PackError> {
    let mut out = Vec::with_capacity(raw.len());
    for r in raw {
        if require_reason && r.reason.as_deref().unwrap_or("").trim().is_empty() {
            return Err(PackError::MissingReason(r.pattern));
        }
        match Regex::new(&r.pattern) {
            Ok(regex) => out.push(Rule {
                pattern: r.pattern,
                regex,
                reason: r.reason.unwrap_or_default(),
                whole_segment: r.whole_segment,
                after_env_change: r.after_env_change,
            }),
            Err(e) => warnings.push(PackWarning {
                source: source.to_string(),
                message: format!("skipping uncompilable regex {:?}: {e}", r.pattern),
            }),
        }
    }
    Ok(out)
}

/// Check a path rule list. A rule with a bad glob is dropped with a warning;
/// a deny rule without a reason is a hard error (as for `[[deny]]`).
fn check_path_rules(
    source: &str,
    raw: Vec<RawPathRule>,
    require_reason: bool,
    warnings: &mut Vec<PackWarning>,
) -> Result<Vec<PathRule>, PackError> {
    let mut out = Vec::with_capacity(raw.len());
    for r in raw {
        if require_reason && r.reason.as_deref().unwrap_or("").trim().is_empty() {
            return Err(PackError::MissingReason(r.glob));
        }
        let valid = if r.ancestors {
            validate_ancestors(&r.glob, r.access)
        } else {
            validate_glob(&r.glob)
        };
        match valid {
            Ok(()) => out.push(PathRule {
                glob: r.glob,
                access: r.access,
                reason: r.reason.unwrap_or_default(),
                ancestors: r.ancestors,
            }),
            Err(e) => warnings.push(PackWarning {
                source: source.to_string(),
                message: format!("skipping path rule: {e}"),
            }),
        }
    }
    Ok(out)
}

/// Load and compile a single pack from a TOML string. `source` labels the pack
/// in any warnings (a filename, or `"<builtin>"`).
pub fn load_pack_str(
    source: &str,
    toml_str: &str,
    warnings: &mut Vec<PackWarning>,
) -> Result<Pack, PackError> {
    let raw: RawPackFile = toml::from_str(toml_str).map_err(|e| PackError::Toml(e.to_string()))?;
    if raw.pack.id.trim().is_empty() {
        return Err(PackError::MissingId);
    }
    let allow = compile_rules(source, raw.allow, false, warnings)?;
    let deny = compile_rules(source, raw.deny, true, warnings)?;
    let allow_path = check_path_rules(source, raw.allow_path, false, warnings)?;
    let deny_path = check_path_rules(source, raw.deny_path, true, warnings)?;
    if allow.is_empty() && deny.is_empty() && allow_path.is_empty() && deny_path.is_empty() {
        return Err(PackError::NoRules);
    }
    Ok(Pack {
        prefilter: Prefilter::new(raw.pack.triggers.clone()),
        id: raw.pack.id,
        name: raw.pack.name,
        description: raw.pack.description,
        default_on: raw.pack.default_on,
        version: raw.pack.version,
        triggers: raw.pack.triggers,
        substitution_failsafe: raw.pack.substitution_failsafe,
        allow,
        deny,
        allow_path,
        deny_path,
    })
}

/// Load every `*.toml` under `dir`, fail-open. A malformed file is skipped with
/// a warning; a duplicate `id` is skipped with a warning (first wins).
pub fn load_packs_dir(dir: &Path) -> (Vec<Pack>, Vec<PackWarning>) {
    let mut packs: Vec<Pack> = Vec::new();
    let mut warnings: Vec<PackWarning> = Vec::new();

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            warnings.push(PackWarning {
                source: dir.display().to_string(),
                message: format!("cannot read packs dir: {e}"),
            });
            return (packs, warnings);
        }
    };

    let mut files: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "toml").unwrap_or(false))
        .collect();
    files.sort();

    for path in files {
        let source = path.display().to_string();
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                warnings.push(PackWarning {
                    source,
                    message: format!("cannot read file: {e}"),
                });
                continue;
            }
        };
        match load_pack_str(&source, &text, &mut warnings) {
            Ok(pack) => {
                if packs.iter().any(|p| p.id == pack.id) {
                    warnings.push(PackWarning {
                        source,
                        message: format!("duplicate pack id {:?}; skipping", pack.id),
                    });
                    continue;
                }
                packs.push(pack);
            }
            Err(e) => warnings.push(PackWarning {
                source,
                message: format!("skipping pack: {e}"),
            }),
        }
    }

    (packs, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
[pack]
id = "test.sample"
name = "Sample"
triggers = ["git"]

[[allow]]
pattern = '^git\s+reset\s+--hard\s+HEAD\b'
reason = "reset to HEAD is fine"

[[deny]]
pattern = '^git\s+reset\s+--hard\b'
reason = "discards uncommitted work"
"#;

    #[test]
    fn loads_valid_pack() {
        let mut w = Vec::new();
        let p = load_pack_str("<t>", VALID, &mut w).expect("loads");
        assert_eq!(p.id, "test.sample");
        assert_eq!(p.allow.len(), 1);
        assert_eq!(p.deny.len(), 1);
        assert!(p.default_on); // defaulted
        assert_eq!(p.version, 1); // defaulted
        assert!(w.is_empty());
    }

    #[test]
    fn deny_without_reason_is_error() {
        let toml = r#"
[pack]
id = "t"
[[deny]]
pattern = 'x'
"#;
        let mut w = Vec::new();
        let err = load_pack_str("<t>", toml, &mut w).unwrap_err();
        assert!(matches!(err, PackError::MissingReason(_)));
    }

    #[test]
    fn uncompilable_regex_drops_rule_with_warning() {
        let toml = r#"
[pack]
id = "t"
[[deny]]
pattern = '('
reason = "bad"
[[deny]]
pattern = 'ok'
reason = "good"
"#;
        let mut w = Vec::new();
        let p = load_pack_str("<t>", toml, &mut w).expect("still loads");
        assert_eq!(p.deny.len(), 1); // the bad one dropped
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn loads_path_rules() {
        let toml = r#"
[pack]
id = "t.paths"

[[deny_path]]
glob = "**/.env"
access = "read"
reason = "secrets"

[[allow_path]]
glob = "**/.env.example"

[[deny_path]]
glob = "relative/path"
reason = "bad glob: dropped with a warning"
"#;
        let mut w = Vec::new();
        let p = load_pack_str("<t>", toml, &mut w).expect("loads");
        assert_eq!(
            p.deny_path,
            vec![PathRule {
                glob: "**/.env".into(),
                access: RuleAccess::Read,
                reason: "secrets".into(),
                ancestors: false,
            }]
        );
        assert_eq!(p.allow_path[0].access, RuleAccess::Any);
        assert_eq!(p.rule_count(), 2);
        assert_eq!(w.len(), 1);
        assert!(w[0].message.contains("relative/path"), "{w:?}");
    }

    #[test]
    fn path_rule_errors() {
        let no_reason = "[pack]\nid = \"t\"\n[[deny_path]]\nglob = \"/x\"\n";
        let mut w = Vec::new();
        assert!(matches!(
            load_pack_str("<t>", no_reason, &mut w),
            Err(PackError::MissingReason(_))
        ));
        let bad_access =
            "[pack]\nid = \"t\"\n[[deny_path]]\nglob = \"/x\"\naccess = \"exec\"\nreason = \"r\"\n";
        assert!(matches!(
            load_pack_str("<t>", bad_access, &mut w),
            Err(PackError::Toml(_))
        ));
    }

    #[test]
    fn unknown_key_in_a_rule_fails_the_load() {
        for table in ["deny", "allow"] {
            let toml = format!(
                "[pack]\nid = \"t\"\n[[{table}]]\npattern = \"x\"\nreason = \"r\"\nwhole_comand = true\n"
            );
            let mut w = Vec::new();
            assert!(
                matches!(load_pack_str("<t>", &toml, &mut w), Err(PackError::Toml(_))),
                "{table}"
            );
        }
        let ok = "[pack]\nid = \"t\"\n[[deny]]\npattern = \"x\"\nreason = \"r\"\nwhole_segment = true\nafter_env_change = true\n";
        let mut w = Vec::new();
        let p = load_pack_str("<t>", ok, &mut w).expect("known keys load");
        assert!(p.deny[0].whole_segment && p.deny[0].after_env_change);
    }

    #[test]
    fn unknown_key_in_a_path_rule_fails_the_load() {
        for table in ["deny_path", "allow_path"] {
            let toml = format!(
                "[pack]\nid = \"t\"\n[[{table}]]\nglob = \"/x\"\nreason = \"r\"\nacess = \"read\"\n"
            );
            let mut w = Vec::new();
            assert!(
                matches!(load_pack_str("<t>", &toml, &mut w), Err(PackError::Toml(_))),
                "{table}"
            );
        }
    }

    #[test]
    fn ancestors_flag_loads_only_on_variable_rooted_literal_write_globs() {
        let ok = "[pack]\nid = \"t\"\n[[deny_path]]\nglob = \"$SAIIFE_DATA_DIR\"\naccess = \"write\"\nancestors = true\nreason = \"r\"\n";
        let mut w = Vec::new();
        let p = load_pack_str("<t>", ok, &mut w).expect("loads");
        assert!(w.is_empty(), "{w:?}");
        assert!(p.deny_path[0].ancestors);
        for bad in [
            "glob = \"/etc/x\"\naccess = \"write\"",
            "glob = \"**/.env\"\naccess = \"write\"",
            "glob = \"$SAIIFE_DATA_DIR/*\"\naccess = \"write\"",
            "glob = \"$SAIIFE_DATA_DIR/**\"\naccess = \"write\"",
            "glob = \"$SAIIFE_DATA_DIR\"\naccess = \"read\"",
            "glob = \"$SAIIFE_DATA_DIR\"",
        ] {
            let t = format!("[pack]\nid = \"t\"\n[[deny]]\npattern = \"x\"\nreason = \"r\"\n[[deny_path]]\n{bad}\nancestors = true\nreason = \"r\"\n");
            let mut w = Vec::new();
            let p = load_pack_str("<t>", &t, &mut w).expect("pack still loads");
            assert!(p.deny_path.is_empty(), "{bad}");
            assert_eq!(w.len(), 1, "{bad}: {w:?}");
            assert!(w[0].message.contains("ancestors"), "{w:?}");
        }
    }

    #[test]
    fn duplicate_id_in_dir_skips_second() {
        let dir = tempdir();
        std::fs::write(dir.join("a.toml"), VALID).unwrap();
        std::fs::write(dir.join("b.toml"), VALID).unwrap();
        let (packs, warnings) = load_packs_dir(&dir);
        assert_eq!(packs.len(), 1);
        assert!(warnings.iter().any(|w| w.message.contains("duplicate")));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_dir_is_fail_open() {
        let (packs, warnings) = load_packs_dir(Path::new("/no/such/dir/saiifeguard"));
        assert!(packs.is_empty());
        assert_eq!(warnings.len(), 1);
    }

    // Minimal unique temp dir without an external crate.
    fn tempdir() -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("saiifeguard-test-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
