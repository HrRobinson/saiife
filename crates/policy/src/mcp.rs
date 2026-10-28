//! `[mcp.<name>]` (plan 17 decisions 9, 12, 13, 14): a third-party MCP server
//! the daemon runs as a gateway child, judged per tool.
//!
//! Environments cannot override it: [`crate::environment::EnvironmentCfg`]
//! has no `mcp` key and rejects unknown ones, so a gateway server is the same
//! in every environment.

use crate::capability::glob_with;
use crate::decide::Verdict;
use crate::project::{Mode, ServiceOverlay};
use crate::service::LimitsCfg;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Longest a tool call may take (`timeout`).
pub const MAX_TIMEOUT: Duration = Duration::from_secs(300);

/// How the child is confined (decision 12).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Sandbox {
    #[default]
    Landlock,
    Off,
}

/// One `[mcp.<name>]`.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct McpServerCfg {
    pub command: PathBuf,
    pub args: Vec<String>,
    /// Environment variable of the child -> vault secret name.
    pub env: BTreeMap<String, String>,
    pub read_paths: Vec<PathBuf>,
    pub allow: Vec<String>,
    pub ask: Vec<String>,
    pub deny: Vec<String>,
    /// Tools counted as reads for the limiter and `tool_kind`.
    pub read_tools: Vec<String>,
    pub limits: LimitsCfg,
    #[serde(with = "crate::duration::as_secs")]
    pub timeout: Duration,
    pub sandbox: Sandbox,
}

impl Default for McpServerCfg {
    fn default() -> Self {
        McpServerCfg {
            command: PathBuf::new(),
            args: Vec::new(),
            env: BTreeMap::new(),
            read_paths: Vec::new(),
            allow: Vec::new(),
            ask: Vec::new(),
            deny: Vec::new(),
            read_tools: Vec::new(),
            limits: LimitsCfg::default(),
            timeout: Duration::from_secs(30),
            sandbox: Sandbox::Landlock,
        }
    }
}

/// A server name: `[a-z0-9-]{1,32}`, never the reserved `saiife`.
pub fn valid_server_name(s: &str) -> bool {
    s != "saiife"
        && !s.is_empty()
        && s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// saiife's own dirs: a gateway child may never be given read access to
/// them, or to a dir that holds them.
pub const PROTECTED_DIRS: [&str; 4] = [
    "/etc/saiife",
    "/var/lib/saiife",
    "/var/log/saiife",
    "/run/saiife",
];

/// Whether a `read_paths` entry would open saiife's own files to the
/// server: `/`, any `..`, or a path equal to, beneath or above a
/// [`PROTECTED_DIRS`] entry. Compared lexically and, when the path
/// exists, also after resolving symlinks.
fn exposes_saiife(p: &Path) -> bool {
    use std::path::Component;
    let hits = |p: &Path| {
        p == Path::new("/")
            || PROTECTED_DIRS.iter().any(|d| {
                let d = Path::new(d);
                p.starts_with(d) || d.starts_with(p)
            })
    };
    p.components().any(|c| c == Component::ParentDir)
        || hits(p)
        || std::fs::canonicalize(p).is_ok_and(|r| hits(&r))
}

/// Whether `v` may name a child's secret variable: `[A-Z_][A-Z0-9_]*` and
/// not one saiife sets or that changes how a program loads code. The spawn
/// helper checks it again before it execs.
pub fn child_env_var_allowed(v: &str) -> bool {
    valid_env_var(v) && !reserved_env_var(v)
}

fn valid_env_var(v: &str) -> bool {
    let mut b = v.bytes();
    matches!(b.next(), Some(c) if c.is_ascii_uppercase() || c == b'_')
        && b.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
}

fn reserved_env_var(v: &str) -> bool {
    matches!(
        v,
        "PATH"
            | "HOME"
            | "LANG"
            | "NODE_OPTIONS"
            | "PYTHONPATH"
            | "PYTHONHOME"
            | "BASH_ENV"
            | "ENV"
            | "GCONV_PATH"
            | "LOCPATH"
            | "NLSPATH"
            | "HOSTALIASES"
            | "TMPDIR"
    ) || v.starts_with("LD_")
        || v.starts_with("DYLD_")
}

impl McpServerCfg {
    /// The load-time checks. `Err` is a one-line reason.
    pub fn validate(&self, name: &str) -> Result<(), String> {
        let at = |why: String| format!("mcp {name}: {why}");
        if !valid_server_name(name) {
            return Err(format!(
                "mcp server name {name:?} is not [a-z0-9-]{{1,32}} (and not \"saiife\")"
            ));
        }
        if !self.command.is_absolute() {
            return Err(at(format!(
                "command {} must be an absolute path",
                self.command.display()
            )));
        }
        let has_ctl = |s: &str| s.chars().any(char::is_control);
        match self.command.to_str() {
            Some(c) if !has_ctl(c) => {}
            _ => {
                return Err(at(
                    "command holds a control character or is not UTF-8".to_string()
                ))
            }
        }
        if let Some(a) = self.args.iter().find(|a| has_ctl(a)) {
            return Err(at(format!("args entry {a:?} holds a control character")));
        }
        for (var, secret) in &self.env {
            if !valid_env_var(var) {
                return Err(at(format!("env variable {var:?} is not [A-Z_][A-Z0-9_]*")));
            }
            if reserved_env_var(var) {
                return Err(at(format!(
                    "env variable {var} is reserved (PATH, HOME, LANG and LD_* are set by saiife)"
                )));
            }
            if secret.is_empty() {
                return Err(at(format!("env {var}: the secret name is empty")));
            }
        }
        if let Some(p) = self.read_paths.iter().find(|p| !p.is_absolute()) {
            return Err(at(format!(
                "read_paths entry {} must be an absolute path",
                p.display()
            )));
        }
        if let Some(p) = self.read_paths.iter().find(|p| exposes_saiife(p)) {
            return Err(at(format!(
                "read_paths entry {} would let the server read saiife's own files \
                 (it is /, holds a .. component, or equals or contains one of {})",
                p.display(),
                PROTECTED_DIRS.join(", ")
            )));
        }
        for (key, list) in [
            ("allow", &self.allow),
            ("ask", &self.ask),
            ("deny", &self.deny),
            ("read_tools", &self.read_tools),
        ] {
            if let Some(p) = list
                .iter()
                .find(|p| p.is_empty() || p.len() > 128 || p.chars().any(char::is_control))
            {
                return Err(at(format!("{key} pattern {p:?} is not a tool glob")));
            }
        }
        let l = &self.limits;
        for (key, set) in [
            ("deletes_per_day", l.deletes_per_day.is_some()),
            ("bulk_per_session", l.bulk_per_session.is_some()),
            ("amount_per_day", l.amount_per_day.is_some()),
            ("amount_per_request", l.amount_per_request.is_some()),
        ] {
            if set {
                return Err(at(format!(
                    "limits.{key} does not apply to MCP tools (use requests_per_minute, writes_per_hour or max_response_bytes)"
                )));
            }
        }
        if self.timeout < Duration::from_secs(1) || self.timeout > MAX_TIMEOUT {
            return Err(at("timeout must be between 1s and 300s".to_string()));
        }
        Ok(())
    }
}

/// The verdict for `tool` of one server. Any matching `deny` wins, then
/// `ask`, then `allow`; nothing matching is `default_deny`. Deny and ask
/// match broadly (case-insensitive), allow exactly. The overlay's `allow`
/// counts only outside locked mode.
pub fn decide_tool(
    cfg: &McpServerCfg,
    overlay: Option<&ServiceOverlay>,
    mode: Mode,
    tool: &str,
) -> Verdict {
    if tool.is_empty() {
        return Verdict::Deny {
            rule: "default_deny".to_string(),
        };
    }
    let o_allow: &[String] = match (overlay, mode) {
        (Some(o), Mode::Developer) => &o.allow,
        _ => &[],
    };
    let (o_ask, o_deny): (&[String], &[String]) = match overlay {
        Some(o) => (&o.ask, &o.deny),
        None => (&[], &[]),
    };
    let hit = |lists: [&[String]; 2], broad: bool| -> Option<String> {
        lists
            .iter()
            .flat_map(|l| l.iter())
            .find(|p| glob_with(p, tool, broad))
            .cloned()
    };
    if let Some(p) = hit([&cfg.deny, o_deny], true) {
        return Verdict::Deny {
            rule: format!("deny:{p}"),
        };
    }
    if hit([&cfg.ask, o_ask], true).is_some() {
        return Verdict::Ask;
    }
    if hit([&cfg.allow, o_allow], false).is_some() {
        return Verdict::Allow;
    }
    Verdict::Deny {
        rule: "default_deny".to_string(),
    }
}

/// `"read"` for a tool matching `read_tools` (exact case), else `"write"`.
pub fn tool_kind(cfg: &McpServerCfg, tool: &str) -> &'static str {
    if cfg.read_tools.iter().any(|p| glob_with(p, tool, false)) {
        "read"
    } else {
        "write"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(extra: &str) -> McpServerCfg {
        toml::from_str(&format!("command = \"/usr/bin/x\"\n{extra}")).unwrap()
    }

    #[test]
    fn read_paths_never_expose_saiife_dirs() {
        let refused = [
            "/",
            "/etc",
            "/etc/saiife",
            "/etc/saiife/policy.d",
            "/var",
            "/var/lib",
            "/var/lib/saiife",
            "/var/lib/saiife/vault",
            "/var/log/saiife",
            "/var/log",
            "/run",
            "/run/saiife",
            "/run/saiife/sockets",
            "/usr/share/../../etc/saiife",
            "/opt/x/..",
        ];
        for p in refused {
            let c = cfg(&format!("read_paths = [\"{p}\"]"));
            let e = c.validate("linear").unwrap_err();
            assert!(e.contains("saiife's own files"), "{p}: {e}");
        }
        for p in [
            "/usr/share/zoneinfo",
            "/etc/saiifex",
            "/var/lib/node",
            "/srv/mcp",
        ] {
            let c = cfg(&format!("read_paths = [\"{p}\"]"));
            assert!(c.validate("linear").is_ok(), "{p}");
        }
    }

    fn deny(rule: &str) -> Verdict {
        Verdict::Deny { rule: rule.into() }
    }

    #[test]
    fn deny_beats_ask_beats_allow() {
        let c = cfg("allow=[\"*\"]\nask=[\"create_*\"]\ndeny=[\"create_secret\"]");
        let d = |t| decide_tool(&c, None, Mode::Locked, t);
        assert_eq!(d("create_secret"), deny("deny:create_secret"));
        assert_eq!(d("create_issue"), Verdict::Ask);
        assert_eq!(d("list_issues"), Verdict::Allow);
    }

    #[test]
    fn nothing_matches_is_default_deny() {
        let c = cfg("allow=[\"list_*\"]");
        assert_eq!(
            decide_tool(&c, None, Mode::Locked, "drop_db"),
            deny("default_deny")
        );
    }

    #[test]
    fn deny_glob_ignores_case() {
        let c = cfg("allow=[\"*\"]\ndeny=[\"delete_*\"]");
        assert_eq!(
            decide_tool(&c, None, Mode::Locked, "DELETE_all"),
            deny("deny:delete_*")
        );
        // allow is exact: a differently-cased tool is not allowed
        let c = cfg("allow=[\"list_issues\"]");
        assert_eq!(
            decide_tool(&c, None, Mode::Locked, "LIST_ISSUES"),
            deny("default_deny")
        );
    }

    #[test]
    fn overlay_allow_ignored_when_locked() {
        let c = cfg("");
        let o = ServiceOverlay {
            allow: vec!["list_issues".into()],
            ask: vec![],
            deny: vec![],
        };
        assert_eq!(
            decide_tool(&c, Some(&o), Mode::Locked, "list_issues"),
            deny("default_deny")
        );
        assert_eq!(
            decide_tool(&c, Some(&o), Mode::Developer, "list_issues"),
            Verdict::Allow
        );
        let o = ServiceOverlay {
            allow: vec![],
            ask: vec![],
            deny: vec!["list_*".into()],
        };
        let c = cfg("allow=[\"*\"]");
        assert_eq!(
            decide_tool(&c, Some(&o), Mode::Locked, "list_issues"),
            deny("deny:list_*")
        );
    }

    #[test]
    fn empty_and_slashed_tool_names() {
        let c = cfg("allow=[\"*\"]");
        assert_eq!(
            decide_tool(&c, None, Mode::Locked, ""),
            deny("default_deny")
        );
        assert_eq!(
            decide_tool(&c, None, Mode::Locked, "a/b"),
            deny("default_deny")
        );
    }

    #[test]
    fn control_chars_in_command_and_args_refused() {
        let mut c = cfg("");
        c.command = "/usr/bin/x\0y".into();
        assert!(c.validate("x").is_err());
        let mut c = cfg("");
        c.args = vec!["ok".into(), "a\nb".into()];
        assert!(c.validate("x").is_err());
    }

    #[test]
    fn more_reserved_env_vars_refused() {
        for v in [
            "NODE_OPTIONS",
            "PYTHONPATH",
            "PYTHONHOME",
            "BASH_ENV",
            "ENV",
            "GCONV_PATH",
            "LOCPATH",
            "NLSPATH",
            "HOSTALIASES",
            "TMPDIR",
            "DYLD_INSERT_LIBRARIES",
        ] {
            let c = cfg(&format!("env = {{ \"{v}\" = \"s\" }}"));
            assert!(c.validate("x").is_err(), "{v}");
        }
    }

    #[test]
    fn read_tools_kind() {
        let c = cfg("read_tools=[\"list_*\", \"get_issue\"]");
        assert_eq!(tool_kind(&c, "list_issues"), "read");
        assert_eq!(tool_kind(&c, "get_issue"), "read");
        assert_eq!(tool_kind(&c, "create_issue"), "write");
        assert_eq!(tool_kind(&c, "LIST_issues"), "write");
    }

    #[test]
    fn unknown_key_is_error() {
        assert!(toml::from_str::<McpServerCfg>("command=\"/a\"\nbogus=1").is_err());
    }

    #[test]
    fn relative_command_refused() {
        assert!(cfg("").validate("x").is_ok());
        let mut c = cfg("");
        c.command = "npx".into();
        assert!(c.validate("x").unwrap_err().contains("absolute"));
    }

    #[test]
    fn reserved_env_var_refused() {
        for v in ["PATH", "HOME", "LANG", "LD_PRELOAD", "lower", "1X"] {
            let c = cfg(&format!("env = {{ \"{v}\" = \"s\" }}"));
            assert!(c.validate("x").is_err(), "{v}");
        }
        assert!(cfg("env = { LINEAR_TOKEN = \"s\" }").validate("x").is_ok());
    }

    #[test]
    fn bad_server_name_refused() {
        let c = cfg("");
        assert!(c.validate("linear-2").is_ok());
        for n in ["a_b", "saiife", &"a".repeat(33), "", "A"] {
            assert!(c.validate(n).is_err(), "{n}");
        }
    }

    #[test]
    fn amount_cap_refused_for_mcp() {
        for l in [
            "deletes_per_day = 1",
            "bulk_per_session = 1",
            "amount_per_day = { max = 1, currency = \"USD\" }",
            "amount_per_request = { max = 1, currency = \"USD\" }",
        ] {
            let c = cfg(&format!("[limits]\n{l}"));
            assert!(c.validate("x").is_err(), "{l}");
        }
        assert!(
            cfg("[limits]\nrequests_per_minute = 5\nmax_response_bytes = 10")
                .validate("x")
                .is_ok()
        );
    }

    #[test]
    fn timeout_default_and_cap() {
        assert_eq!(cfg("").timeout, Duration::from_secs(30));
        assert!(cfg("timeout = \"301s\"").validate("x").is_err());
        assert!(cfg("timeout = \"5m\"").validate("x").is_ok());
        let mut c = cfg("");
        c.timeout = Duration::ZERO;
        assert!(c.validate("x").is_err());
    }
}
