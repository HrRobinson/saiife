//! Pack model + TOML loader.
//!
//! A pack is metadata plus an allow-regex list and a deny-regex list, each deny
//! carrying a human-readable reason. Loading is fail-open at the granularity of
//! the failure: an uncompilable regex drops that *rule* (with a warning), a
//! malformed or duplicate-id file drops that *pack* (with a warning) — neither
//! aborts the load of the rest.

use std::fs;
use std::path::Path;

use regex::Regex;
use serde::Deserialize;

use crate::prefilter::Prefilter;

/// A compiled matching rule: a regex plus the reason shown when it fires.
#[derive(Debug, Clone)]
pub struct Rule {
    pub pattern: String,
    pub regex: Regex,
    pub reason: String,
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
    pub allow: Vec<Rule>,
    pub deny: Vec<Rule>,
}

impl Pack {
    /// The pack's pre-filter, built from its literal triggers.
    pub fn prefilter(&self) -> Prefilter {
        Prefilter::new(self.triggers.clone())
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
    #[error("pack is missing [[deny]] reason for pattern {0:?}")]
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
}

#[derive(Debug, Deserialize)]
struct RawRule {
    pattern: String,
    #[serde(default)]
    reason: Option<String>,
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
            }),
            Err(e) => warnings.push(PackWarning {
                source: source.to_string(),
                message: format!("skipping uncompilable regex {:?}: {e}", r.pattern),
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
    if allow.is_empty() && deny.is_empty() {
        return Err(PackError::NoRules);
    }
    Ok(Pack {
        id: raw.pack.id,
        name: raw.pack.name,
        description: raw.pack.description,
        default_on: raw.pack.default_on,
        version: raw.pack.version,
        triggers: raw.pack.triggers,
        allow,
        deny,
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
