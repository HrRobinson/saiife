//! Typed `[services.*]` and `[secrets.*]` (spec §6.9, §8.1). Every struct
//! rejects unknown keys: a typo in a security config is an error.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// One `[services.<name>]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceCfg {
    pub connector: String,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub params: BTreeMap<String, String>,
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub auth: Option<AuthCfg>,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub ask: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub rule: Vec<RuleCfg>,
    #[serde(default)]
    pub fixed: BTreeMap<String, String>,
    #[serde(default)]
    pub limits: LimitsCfg,
    #[serde(default)]
    pub redact: RedactCfg,
    #[serde(default)]
    pub operation: Vec<HttpOperationCfg>,
    /// `sign` (default) or `sts` (cloud connectors).
    #[serde(default)]
    pub mode: CloudMode,
    #[serde(default)]
    pub cloud: CloudCfg,
}

/// How a cloud connector gets its credential: sign requests with the stored
/// key (`sign`, the default), or hand out short-lived STS credentials to a
/// `run --cloud` child (`sts`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CloudMode {
    #[default]
    Sign,
    Sts,
}

/// `[services.<name>.cloud]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CloudCfg {
    pub role_arn: Option<String>,
    pub external_id: Option<String>,
    pub run_allow: Vec<PathBuf>,
    pub authority_host: Option<String>,
}

/// The Azure authorities a service may use (plan 15 decision 6).
pub const AZURE_AUTHORITIES: &[&str] = &[
    "login.microsoftonline.com",
    "login.microsoftonline.us",
    "login.chinacloudapi.cn",
];

fn all_bytes(s: &str, ok: impl Fn(u8) -> bool) -> bool {
    s.bytes().all(ok)
}

/// `^arn:aws(-cn|-us-gov)?:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$`
pub fn valid_role_arn(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("arn:aws") else {
        return false;
    };
    let rest = rest
        .strip_prefix("-cn")
        .or_else(|| rest.strip_prefix("-us-gov"))
        .unwrap_or(rest);
    let Some(rest) = rest.strip_prefix(":iam::") else {
        return false;
    };
    let Some((acct, role)) = rest.split_once(':') else {
        return false;
    };
    let Some(name) = role.strip_prefix("role/") else {
        return false;
    };
    acct.len() == 12
        && acct.bytes().all(|b| b.is_ascii_digit())
        && (1..=512).contains(&name.len())
        && all_bytes(name, |b| {
            b.is_ascii_alphanumeric() || b"+=,.@_/-".contains(&b)
        })
}

/// `^[A-Za-z0-9+=,.@:/_-]{2,1224}$`
pub fn valid_external_id(s: &str) -> bool {
    (2..=1224).contains(&s.len())
        && all_bytes(s, |b| {
            b.is_ascii_alphanumeric() || b"+=,.@:/_-".contains(&b)
        })
}

/// How the secret is attached to an upstream request. Kinds: `header`,
/// `bearer`, `basic`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthCfg {
    pub kind: String,
    #[serde(default)]
    pub name: Option<String>,
}

/// `[[services.<name>.rule]]`: a capability pattern, conditions on the
/// request parameters (each a glob) and an action.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleCfg {
    pub capability: String,
    #[serde(default)]
    pub when: BTreeMap<String, String>,
    pub action: Action,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Ask,
    Deny,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsCfg {
    pub requests_per_minute: Option<u32>,
    pub writes_per_hour: Option<u32>,
    pub deletes_per_day: Option<u32>,
    pub bulk_per_session: Option<u32>,
    pub max_response_bytes: Option<u64>,
    pub amount_per_day: Option<AmountCap>,
    pub amount_per_request: Option<AmountCap>,
}

/// A cap in major units of `currency`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AmountCap {
    pub max: u64,
    pub currency: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RedactCfg {
    pub fields: Vec<String>,
}

/// `[[services.<name>.operation]]`: one HTTP operation of a manifest-less
/// connector.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpOperationCfg {
    pub id: String,
    pub capability: String,
    pub kind: String,
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub query: Vec<String>,
    #[serde(default)]
    pub body: Option<String>,
}

/// `[secrets.<name>]`: what the admin lets `run --secret` execute.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecretCfg {
    pub run_allow: Vec<PathBuf>,
}

/// Basenames a `run_allow` entry may not have: an interpreter, a shell or a
/// program that runs another program (`xargs`, `find -exec`, `timeout`,
/// `nice`, `sudo`, `make` ...) would let the agent run anything with the
/// secret.
///
/// This denylist is best effort. It cannot know every program that can run
/// code (a pager, an editor, an `--exec` flag, a plugin loader). A
/// `run_allow` list should hold only purpose-built, argument-constrained
/// programs (`psql`, `pg_dump`), never general tools. The daemon applies the
/// same list to the symlink-resolved path at lease time.
const INTERPRETERS: &[&str] = &[
    "sh",
    "bash",
    "dash",
    "zsh",
    "fish",
    "ksh",
    "csh",
    "tcsh",
    "busybox",
    "env",
    "python",
    "python3",
    "perl",
    "ruby",
    "node",
    "nodejs",
    "ipython",
    "pythonw",
    "python3m",
    "pypy",
    "pypy3",
    "deno",
    "bun",
    "php",
    "lua",
    "tclsh",
    "osascript",
    "ash",
    "mksh",
    "rbash",
    "pwsh",
    "awk",
    "gawk",
    "mawk",
    "nawk",
    "xargs",
    "find",
    "timeout",
    "nice",
    "nohup",
    "stdbuf",
    "setsid",
    "sudo",
    "doas",
    "chroot",
    "irb",
    "java",
    "jshell",
    "rscript",
    "expect",
    "wish",
    "vim",
    "vi",
    "ed",
    "gdb",
    "make",
    "coreutils",
];

/// True when `path` names an interpreter or shell (by basename).
pub fn is_interpreter(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    // Lowercase, and a version suffix (digits and dots) does not help:
    // `python2`, `ruby3.2`, `perl5.36`, `lua5.4`, `php8.2`, `python3.12`.
    let lower = name.to_ascii_lowercase();
    let base = lower.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    INTERPRETERS.contains(&lower.as_str())
        || INTERPRETERS.contains(&base)
        || lower.starts_with("perl-")
        || lower.starts_with("python-")
}

/// Auth kinds a service may use.
pub const AUTH_KINDS: &[&str] = &["header", "bearer", "basic"];
