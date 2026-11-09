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
    Write,
    Any,
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
