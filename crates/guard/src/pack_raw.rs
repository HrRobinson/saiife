//! A pack file as written: the deserialized shape of a pack's TOML, before any
//! rule is checked or compiled (see `crate::pack` for the schema).
//!
//! Shared by the library and `build.rs`. The build script parses the shipped
//! packs (`packs/*.toml`) into these types and writes them out as `static`
//! Rust data, so a hook never parses the built-in TOML. Strings and lists are
//! `Cow`s: borrowed in the generated data, owned when parsed at run time (a
//! pack from `policy.d`). This file uses nothing else of the crate.

use serde::Deserialize;
use std::borrow::Cow;

/// A string: borrowed in the built-in data, owned when parsed.
pub type Str = Cow<'static, str>;
/// A list: borrowed in the built-in data, owned when parsed.
pub type List<T> = Cow<'static, [T]>;

/// `platform` of a rule: the one kind of host it applies on. A value not
/// listed here fails the pack's load; it never means "everywhere" or "nowhere".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RulePlatform {
    Windows,
}

/// `where` of a user rule: which profile it is in force in. A value not listed
/// here fails the pack's load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleWhere {
    /// Only on the host, not inside a box.
    Host,
    /// On the host and inside a box.
    Everywhere,
}

/// Where a user rule was imported from: a line of a file, pinned by its hash.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawSource {
    pub file: Str,
    pub line: u32,
    pub line_sha256: Str,
}

/// The file a user pack was imported from, pinned by its hash.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawImport {
    pub file: Str,
    pub sha256: Str,
}

/// Why a line of an imported file has no rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnenforcedWhy {
    Judgement,
    Skipped,
    Unverified,
}

/// A line of an imported file that no rule enforces.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawUnenforced {
    pub source: RawSource,
    pub text: Str,
    pub why: UnenforcedWhy,
}

/// How a command reads its operands as patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperandSyntax {
    /// A regular expression searched in the name (`pkill`, `killall -r`).
    Regex,
    /// A shell glob matched against the whole name (`systemctl`); only
    /// operands with `*`, `?` or `[` are read as patterns.
    Glob,
}

/// Which accesses a path rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAccess {
    Read,
    /// Every write, a mode, owner or attribute change (`chmod`) included.
    Write,
    Any,
    /// A write that changes what the file holds (`cp x f`, `> f`, `rm f`),
    /// not a mode, owner or attribute change (`chmod 600 f`).
    Replace,
    /// `read` and `replace`: a credential file, which may be neither read
    /// nor overwritten, but may be `chmod`ed.
    Content,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RawPackFile {
    pub pack: RawMeta,
    #[serde(default)]
    pub allow: List<RawRule>,
    #[serde(default)]
    pub deny: List<RawRule>,
    #[serde(default)]
    pub allow_path: List<RawPathRule>,
    #[serde(default)]
    pub deny_path: List<RawPathRule>,
    /// User packs only (`build.rs` refuses it in a built-in pack).
    #[serde(default)]
    pub import: Option<RawImport>,
    /// User packs only.
    #[serde(default)]
    pub unenforced: List<RawUnenforced>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RawMeta {
    pub id: Str,
    #[serde(default)]
    pub name: Str,
    #[serde(default)]
    pub description: Str,
    #[serde(default = "default_true")]
    pub default_on: bool,
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub triggers: List<Str>,
    #[serde(default)]
    pub windows_triggers: List<Str>,
    #[serde(default = "default_true")]
    pub substitution_failsafe: bool,
    /// Compile the rules on first use (a catalog load; see `Pack::lazy`).
    #[serde(default)]
    pub lazy: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRule {
    #[serde(default)]
    pub id: Option<Str>,
    #[serde(default)]
    pub platform: Option<RulePlatform>,
    pub pattern: Str,
    #[serde(default)]
    pub reason: Option<Str>,
    #[serde(default)]
    pub whole_segment: bool,
    #[serde(default)]
    pub after_env_change: bool,
    #[serde(default)]
    pub peeled_wrappers: bool,
    #[serde(default)]
    pub operand_match: Option<OperandSyntax>,
    #[serde(default)]
    pub operand_targets: List<Str>,
    #[serde(default)]
    pub when_option: List<Str>,
    #[serde(default)]
    pub command_options: Option<Str>,
    #[serde(default)]
    pub command_long_options: List<Str>,
    #[serde(default)]
    pub command_signal_word: bool,
    #[serde(default)]
    pub command_long_only: bool,
    #[serde(default)]
    pub when_no_operand: bool,
    #[serde(default)]
    pub target_options: List<Str>,
    #[serde(default)]
    pub operand_match_share: Option<f64>,
    #[serde(default)]
    pub operand_min_len: usize,
    #[serde(default)]
    pub operand_substitution: bool,
    #[serde(default)]
    pub no_redirections: bool,
    /// User packs only: the profile the rule is in force in.
    #[serde(default, rename = "where")]
    pub where_: Option<RuleWhere>,
    /// User packs only: the imported line the rule came from.
    #[serde(default)]
    pub source: Option<RawSource>,
    /// User packs only: a deny that is a request to approve, not a block.
    #[serde(default)]
    pub ask: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawPathRule {
    #[serde(default)]
    pub platform: Option<RulePlatform>,
    pub glob: Str,
    #[serde(default = "default_access")]
    pub access: RuleAccess,
    #[serde(default)]
    pub reason: Option<Str>,
    #[serde(default)]
    pub ancestors: bool,
    /// User packs only (see [`RawRule::where_`]).
    #[serde(default, rename = "where")]
    pub where_: Option<RuleWhere>,
    /// User packs only (see [`RawRule::source`]).
    #[serde(default)]
    pub source: Option<RawSource>,
}

/// The first user-pack-only key a rule sets: a built-in pack may set none.
#[allow(dead_code)] // used by build.rs, which includes this file
pub fn user_key_in_builtin(r: &RawRule) -> Option<&'static str> {
    if r.where_.is_some() {
        Some("where")
    } else if r.source.is_some() {
        Some("source")
    } else if r.ask {
        Some("ask")
    } else {
        None
    }
}

/// [`user_key_in_builtin`] for a path rule.
#[allow(dead_code)] // used by build.rs, which includes this file
pub fn user_key_in_builtin_path(r: &RawPathRule) -> Option<&'static str> {
    if r.where_.is_some() {
        Some("where")
    } else if r.source.is_some() {
        Some("source")
    } else {
        None
    }
}

/// What the build says of a built-in pack that sets a user-pack key.
#[allow(dead_code)] // used by build.rs, which includes this file
pub fn user_key_refusal(source: &str, key: &str) -> String {
    format!("{source}: {key} is a user-pack key; built-in packs may not use it")
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

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(extra: &str) -> RawRule {
        toml::from_str(&format!("pattern = 'x'\n{extra}")).unwrap()
    }

    #[test]
    fn user_keys_in_a_builtin_are_named() {
        assert_eq!(user_key_in_builtin(&rule("")), None);
        assert_eq!(
            user_key_in_builtin(&rule("where = \"host\"")),
            Some("where")
        );
        assert_eq!(user_key_in_builtin(&rule("ask = true")), Some("ask"));
        let src = "source = { file = \"f\", line = 1, line_sha256 = \"a\" }";
        assert_eq!(user_key_in_builtin(&rule(src)), Some("source"));
        let p: RawPathRule = toml::from_str(
            "glob = '/x'\nwhere = \"box\""
                .replace("box", "everywhere")
                .as_str(),
        )
        .unwrap();
        assert_eq!(user_key_in_builtin_path(&p), Some("where"));
        assert_eq!(
            user_key_refusal("core.toml", "ask"),
            "core.toml: ask is a user-pack key; built-in packs may not use it"
        );
    }
}
