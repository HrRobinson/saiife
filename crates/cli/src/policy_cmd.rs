//! `saiife policy check|test|show|reload` (spec §7).
//!
//! `check` and `test` read a config file (plus its `policy.d`) and never
//! touch a daemon, so an admin can run them in CI against a policy kept in
//! git. Users are resolved through a [`Directory`]: the host's NSS by
//! default, or `--passwd`/`--group` files (a CI runner has no `agent-shop`).
//!
//! Exit codes: `check` 0 valid, 1 invalid, 2 unreadable. `test` 0 all
//! examples pass, 1 a mismatch or an invalid policy, 2 a malformed
//! example, an unknown user or an unreadable or malformed file. `show`
//! and `reload` (locked mode, Linux): 0 ok, 1 a reload the daemon
//! rejected, 2 refused, 5 the daemon cannot be reached.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Subcommand};
use saiife_broker::judge::{judge, Unjudgeable};
use saiife_broker::{manifest, Catalog};
use saiife_policy::{
    active_packs, check_guard_ask, check_scopes, effective_policy, load_system, merge_project,
    parse_project, policy_hash, scope_for, view::user_view, Directory, Example, FixedDirectory,
    Getent, LoadedPolicy, Mode, PackInfo, PolicyError, SystemConfig, Verdict,
};
use serde_json::Value;

use crate::eval::{judge_with, Verdict as GuardVerdict};
use crate::paths::LockedPaths;

const SYSTEM_CONFIG: &str = "/etc/saiife/config.toml";

/// Where `check` and `test` find users.
#[derive(Args, Clone, Default)]
pub struct DirArgs {
    /// Users from this passwd-format file instead of the host (for CI,
    /// where the agent accounts do not exist).
    #[arg(long, value_name = "FILE", requires = "group")]
    pub passwd: Option<PathBuf>,
    /// Groups from this group-format file (with --passwd).
    #[arg(long, value_name = "FILE", requires = "passwd")]
    pub group: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum PolicyAction {
    /// Validate a config file (and its policy.d) without loading it into a
    /// daemon: scopes (overlaps), connectors, `[guard] ask` rules and
    /// example syntax. Exit 0 valid, 1 invalid, 2 unreadable.
    Check {
        file: PathBuf,
        #[command(flatten)]
        dirs: DirArgs,
    },
    /// Run every `[[example]]` of a config file against its policy. Exit 1
    /// on any mismatch, 2 on a malformed example or an unknown user.
    Test {
        file: PathBuf,
        #[command(flatten)]
        dirs: DirArgs,
    },
    /// Print your policy view (your scope and its services) and the policy
    /// hash. Admins may name any `--user` and ask for the whole merged
    /// policy with `--effective`.
    Show {
        /// Also print the whole merged effective policy (admin only).
        #[arg(long)]
        effective: bool,
        /// Show this user's scope (admin only for anyone but yourself).
        #[arg(long, value_name = "USER")]
        user: Option<String>,
    },
    /// Locked mode (admin): load the policy again, like SIGHUP. Prints
    /// `loaded` or `rejected: <reason>` (the old policy stays).
    Reload,
}

pub fn run(system_config: Option<PathBuf>, action: PolicyAction) -> ExitCode {
    match action {
        PolicyAction::Check { file, dirs } => finish(directory(&dirs).map(|d| check(&file, &*d))),
        PolicyAction::Test { file, dirs } => finish(directory(&dirs).map(|d| test(&file, &*d))),
        PolicyAction::Show { effective, user } => show(system_config, effective, user),
        PolicyAction::Reload => reload(system_config),
    }
}

/// What a command prints and returns.
#[derive(Debug, Default)]
pub struct Outcome {
    pub code: u8,
    pub out: String,
    pub err: String,
}

fn finish(o: Result<Outcome, String>) -> ExitCode {
    match o {
        Ok(o) => {
            out!("{}", o.out);
            if !o.err.is_empty() {
                eprint!("{}", o.err);
            }
            ExitCode::from(o.code)
        }
        Err(m) => {
            eprintln!("saiife: {m}");
            ExitCode::from(2)
        }
    }
}

fn directory(a: &DirArgs) -> Result<Box<dyn Directory>, String> {
    let (Some(p), Some(g)) = (&a.passwd, &a.group) else {
        return Ok(Box::new(Getent));
    };
    let read = |f: &Path| std::fs::read_to_string(f).map_err(|e| format!("{}: {e}", f.display()));
    Ok(Box::new(FixedDirectory::from_text(&read(p)?, &read(g)?)))
}

// ------------------------------------------------------------------ check

/// The parsed form of an `[[example]]`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Case {
    Request {
        service: String,
        op: String,
        params: BTreeMap<String, String>,
    },
    Command {
        command: String,
        tool: &'static str,
    },
}

/// `Err` says what is wrong with the example (not with the policy).
fn parse_example(ex: &Example) -> Result<Case, String> {
    match (&ex.request, &ex.command) {
        (Some(_), Some(_)) => Err("has both request and command".into()),
        (None, None) => Err("has neither request nor command".into()),
        (Some(r), None) => {
            if ex.agent.is_some() {
                return Err("agent goes with command, not request".into());
            }
            let mut words = r.split_whitespace();
            let (Some(service), Some(op)) = (words.next(), words.next()) else {
                return Err(format!(
                    "request {r:?} is not \"<service> <operation> [k=v ...]\""
                ));
            };
            let mut params = BTreeMap::new();
            for kv in words {
                match kv.split_once('=') {
                    Some((k, v)) if !k.is_empty() => {
                        if params.insert(k.to_string(), v.to_string()).is_some() {
                            return Err(format!("parameter {k:?} is given twice"));
                        }
                    }
                    _ => return Err(format!("parameter {kv:?} is not k=v")),
                }
            }
            Ok(Case::Request {
                service: service.to_string(),
                op: op.to_string(),
                params,
            })
        }
        (None, Some(c)) => {
            if c.trim().is_empty() {
                return Err("command is empty".into());
            }
            let tool = match ex.agent.as_deref() {
                None | Some("claude" | "codex") => "Bash",
                Some("gemini") => "run_shell_command",
                Some(other) => {
                    return Err(format!("agent {other:?} is not claude, codex or gemini"))
                }
            };
            Ok(Case::Command {
                command: c.clone(),
                tool,
            })
        }
    }
}

/// The built-in packs with their `[[deny]]` rule ids (for `[guard] ask`).
fn pack_catalog() -> Vec<PackInfo> {
    let (packs, _) = saiifeguard::builtins::builtin_packs();
    packs
        .iter()
        .map(|p| PackInfo {
            id: p.id.clone(),
            version: p.version,
            default_on: p.default_on,
            rules: p.deny_rules().iter().filter_map(|r| r.id.clone()).collect(),
        })
        .collect()
}

/// A policy that loaded, checked as far as `check` and `test` go.
struct Checked {
    loaded: LoadedPolicy,
    catalog: Catalog,
    errors: Vec<String>,
    warnings: Vec<String>,
}

/// Everything `check` looks at besides the file syntax; every problem is
/// collected, none stops the others.
fn validate(file: &Path, loaded: LoadedPolicy, dir: &dyn Directory) -> Checked {
    let cfg = &loaded.config;
    let mut errors = Vec::new();
    let mut warnings = loaded.warnings.clone();

    // Scopes: a uid in two of them, directly or through a group, and (per
    // user, with the primary group) the conflicts the group lists cannot
    // show.
    let mut conflicted = Vec::new();
    if let Err(e) = check_scopes(cfg, dir) {
        if let PolicyError::ScopeConflict { user, .. } = &e {
            conflicted.push(user.clone());
        }
        errors.push(e.to_string());
    }
    let mut named: Vec<&str> = cfg
        .scope
        .iter()
        .flat_map(|s| s.users.iter())
        .filter(|u| !u.starts_with("group:"))
        .map(String::as_str)
        .collect();
    named.sort_unstable();
    named.dedup();
    for u in named {
        if conflicted.iter().any(|c| c == u) {
            continue;
        }
        if let Err(e) = scope_for(cfg, dir, u) {
            errors.push(e.to_string());
        }
    }
    for s in &cfg.scope {
        for svc in &s.services {
            if !cfg.services.contains_key(svc) {
                warnings.push(format!(
                    "scope {:?} lists service {svc:?}, which is not defined (its users get no_scope)",
                    s.name
                ));
            }
        }
    }

    // Connectors. The manifests of `<config dir>/connectors` are checked as
    // the daemon does, except for the owner: a policy kept in git belongs to
    // whoever checked it out.
    let cdir = file.parent().unwrap_or(Path::new("")).join("connectors");
    let me = rustix::process::geteuid().as_raw();
    let local = match manifest::load_local_with(&cdir, manifest::builtin(), me) {
        Ok(l) => l,
        Err(e) => {
            errors.push(e.to_string());
            Vec::new()
        }
    };
    let catalog = Catalog::new(manifest::builtin(), local);
    match saiife_broker::catalog::validate(cfg, &catalog) {
        Ok(w) => warnings.extend(w),
        Err(e) => errors.push(e.to_string()),
    }

    if let Err(e) = check_guard_ask(cfg, &pack_catalog()) {
        errors.push(e);
    }
    Checked {
        loaded,
        catalog,
        errors,
        warnings,
    }
}

fn unreadable(e: &PolicyError) -> bool {
    matches!(e, PolicyError::Io { .. })
}

/// `saiife policy check <file>`.
pub fn check(file: &Path, dir: &dyn Directory) -> Outcome {
    let loaded = match load_system(file) {
        Ok(l) => l,
        Err(e) => {
            return Outcome {
                code: if unreadable(&e) { 2 } else { 1 },
                err: format!("saiife: {e}\n"),
                ..Outcome::default()
            }
        }
    };
    let mut c = validate(file, loaded, dir);
    for (i, ex) in c.loaded.config.example.iter().enumerate() {
        if let Err(why) = parse_example(ex) {
            c.errors.push(format!("example {}: {why}", i + 1));
        }
    }
    let mut o = Outcome::default();
    for w in &c.warnings {
        o.err.push_str(&format!("saiife: warning: {w}\n"));
    }
    for e in &c.errors {
        o.err.push_str(&format!("saiife: error: {e}\n"));
    }
    if c.errors.is_empty() {
        let cfg = &c.loaded.config;
        o.out = format!(
            "ok: {} ({} services, {} scopes, {} examples)\n",
            file.display(),
            cfg.services.len(),
            cfg.scope.len(),
            cfg.example.len()
        );
    } else {
        o.code = 1;
        o.err
            .push_str(&format!("saiife: {} invalid\n", file.display()));
    }
    o
}

// ------------------------------------------------------------------- test

/// `saiife policy test <file>`.
pub fn test(file: &Path, dir: &dyn Directory) -> Outcome {
    let loaded = match load_system(file) {
        Ok(l) => l,
        Err(e) => {
            // A typo in an example (or anywhere) is a parse error: the
            // examples cannot run, which is never a pass.
            let code = if matches!(e, PolicyError::Io { .. } | PolicyError::Parse { .. }) {
                2
            } else {
                1
            };
            return Outcome {
                code,
                err: format!("saiife: {e}\n"),
                ..Outcome::default()
            };
        }
    };
    let c = validate(file, loaded, dir);
    let mut o = Outcome::default();
    if !c.errors.is_empty() {
        // Examples run against a policy the daemon would refuse prove
        // nothing.
        for e in &c.errors {
            o.err.push_str(&format!("saiife: error: {e}\n"));
        }
        o.err.push_str(&format!(
            "saiife: {} is invalid; run `saiife policy check`\n",
            file.display()
        ));
        o.code = 1;
        return o;
    }
    let cfg = &c.loaded.config;
    if cfg.example.is_empty() {
        o.err.push_str(&format!(
            "saiife: warning: {} has no [[example]]\n",
            file.display()
        ));
        return o;
    }
    let (mut malformed, mut failed, mut passed) = (0, 0, 0);
    for (i, ex) in cfg.example.iter().enumerate() {
        let n = i + 1;
        let label = match (&ex.request, &ex.command) {
            (Some(r), _) => format!("{}: {r}", ex.user),
            (_, Some(cmd)) => format!("{}: {cmd}", ex.user),
            _ => ex.user.clone(),
        };
        let case = match parse_example(ex) {
            Ok(c) => c,
            Err(why) => {
                malformed += 1;
                o.out.push_str(&format!("ERROR example {n}: {why}\n"));
                continue;
            }
        };
        if dir.user(&ex.user).is_none() {
            malformed += 1;
            o.out
                .push_str(&format!("ERROR example {n}: unknown user {:?}\n", ex.user));
            continue;
        }
        let actual = match run_case(cfg, &c.catalog, file, dir, &ex.user, &case) {
            Ok(a) => a,
            Err(why) => {
                malformed += 1;
                o.out.push_str(&format!("ERROR example {n}: {why}\n"));
                continue;
            }
        };
        if actual.kind == Some(ex.expect.as_str()) {
            passed += 1;
            o.out
                .push_str(&format!("ok   example {n}: {label}: {}\n", actual.shown));
        } else {
            failed += 1;
            o.out.push_str(&format!(
                "FAIL example {n}: {label}: expected {}, got {}\n",
                ex.expect.as_str(),
                actual.shown
            ));
        }
    }
    o.out.push_str(&format!(
        "{passed} passed, {failed} failed, {malformed} malformed\n"
    ));
    o.code = if malformed > 0 {
        2
    } else {
        u8::from(failed > 0)
    };
    o
}

/// What a case came to: `kind` is allow|ask|deny (`None`: not judged),
/// `shown` adds the rule.
struct Actual {
    kind: Option<&'static str>,
    shown: String,
}

fn run_case(
    cfg: &SystemConfig,
    cat: &Catalog,
    file: &Path,
    dir: &dyn Directory,
    user: &str,
    case: &Case,
) -> Result<Actual, String> {
    match case {
        Case::Request {
            service,
            op,
            params,
        } => {
            let scope = scope_for(cfg, dir, user);
            let v = judge(cfg, cat, scope, service, op, params)
                .map_err(|e: Unjudgeable| e.to_string())?;
            Ok(match v {
                Verdict::Allow => Actual {
                    kind: Some("allow"),
                    shown: "allow".into(),
                },
                Verdict::Ask => Actual {
                    kind: Some("ask"),
                    shown: "ask".into(),
                },
                Verdict::Deny { rule } => Actual {
                    kind: Some("deny"),
                    shown: format!("deny ({rule})"),
                },
            })
        }
        Case::Command { command, tool } => {
            let (active, _) = active_packs(cfg, &pack_catalog(), None);
            let ids: Vec<String> = active.into_iter().map(|p| p.id).collect();
            let payload = serde_json::json!({
                "hook_event_name": "PreToolUse",
                "tool_name": tool,
                "tool_input": {"command": command},
            })
            .to_string();
            let locked = cfg.locked.then(|| LockedPaths {
                etc: file.parent().unwrap_or(Path::new("/")).to_path_buf(),
                audit_dir: cfg.audit.dir.clone(),
                socket_dir: cfg.daemon.socket_dir.clone(),
            });
            // Long enough that a slow runner never fails open.
            let budget = Duration::from_millis(cfg.guard.budget_ms.max(10_000));
            let a = judge_with(&payload, &ids, budget, locked.as_ref(), &cfg.guard.ask);
            let why = a.reason.as_deref().unwrap_or("");
            let rule = a.rule_id.as_deref().or(a.rule.as_deref()).unwrap_or("");
            Ok(match a.verdict {
                GuardVerdict::Allow => Actual {
                    kind: Some("allow"),
                    shown: "allow".into(),
                },
                GuardVerdict::Deny if a.askable => Actual {
                    kind: Some("ask"),
                    shown: format!("ask ({}/{rule})", a.pack.as_deref().unwrap_or("")),
                },
                GuardVerdict::Deny => Actual {
                    kind: Some("deny"),
                    shown: format!("deny ({}: {rule})", a.pack.as_deref().unwrap_or("")),
                },
                GuardVerdict::Unjudged => Actual {
                    kind: None,
                    shown: format!("not judged ({why})"),
                },
            })
        }
    }
}

// ------------------------------------------------------------------- show

/// The user running this command.
fn current_user() -> Option<String> {
    Getent.name_of(rustix::process::getuid().as_raw())
}

/// Locked mode: the system config loads and says `locked = true`.
fn is_locked(config: &Path) -> bool {
    load_system(config).is_ok_and(|l| l.config.locked)
}

fn show(config: Option<PathBuf>, effective: bool, user: Option<String>) -> ExitCode {
    let config = config.unwrap_or_else(|| PathBuf::from(SYSTEM_CONFIG));
    if is_locked(&config) {
        return show_locked(&config, effective, user);
    }
    // Developer mode: the file, as far as there is one.
    let cfg = match load_system(&config) {
        Ok(l) => l.config,
        Err(PolicyError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            match toml::from_str::<SystemConfig>("version = 2") {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("saiife: {e}");
                    return ExitCode::from(2);
                }
            }
        }
        Err(e) => {
            eprintln!("saiife: {e}");
            return ExitCode::from(2);
        }
    };
    let Some(user) = user.or_else(current_user) else {
        eprintln!("saiife: cannot tell which user you are; use --user");
        return ExitCode::from(2);
    };
    let (packs, _) = active_packs(&cfg, &pack_catalog(), None);
    let project = std::env::current_dir()
        .ok()
        .and_then(|d| saiife_agents::config::find_project_root(&d))
        .and_then(|root| {
            saiife_agents::config::read_config_bytes(&root)
                .ok()
                .flatten()
        })
        .and_then(|b| parse_project(&b).ok())
        .map(|p| merge_project(&cfg.guard.packs, &p, Mode::Developer));
    let (packs, _) = match &project {
        Some(m) => active_packs(&cfg, &pack_catalog(), Some(m)),
        None => (packs, Vec::new()),
    };
    let eff = effective_policy(&cfg, &packs, project.as_ref());
    let hash = policy_hash(&eff);
    let view = user_view(&cfg, &Getent, &user);
    print_show(&view, Some(&hash), effective.then_some(&eff));
    ExitCode::SUCCESS
}

#[cfg(not(target_os = "linux"))]
fn show_locked(_config: &Path, _effective: bool, _user: Option<String>) -> ExitCode {
    eprintln!("saiife: locked mode needs Linux in this version (macOS: v2.1)");
    ExitCode::from(5)
}

#[cfg(not(target_os = "linux"))]
fn reload(_config: Option<PathBuf>) -> ExitCode {
    eprintln!("saiife: locked mode needs Linux in this version (macOS: v2.1)");
    ExitCode::from(5)
}

#[cfg(target_os = "linux")]
fn show_locked(config: &Path, effective: bool, user: Option<String>) -> ExitCode {
    use crate::secret_cmd::linux::call;
    let mut args = serde_json::Map::new();
    if let Some(u) = user {
        args.insert("user".into(), u.into());
    }
    if effective {
        args.insert("effective".into(), true.into());
    }
    match call(config, "policy.show", args) {
        Ok(a) => {
            let view = a.get("view").cloned().unwrap_or(Value::Null);
            print_show(
                &view,
                a.get("hash").and_then(Value::as_str),
                a.get("effective"),
            );
            ExitCode::SUCCESS
        }
        Err(s) => stop(s),
    }
}

#[cfg(target_os = "linux")]
fn reload(config: Option<PathBuf>) -> ExitCode {
    use crate::secret_cmd::linux::call;
    let config = config.unwrap_or_else(|| PathBuf::from(SYSTEM_CONFIG));
    match call(&config, "policy.reload", serde_json::Map::new()) {
        Ok(a) => match a.get("result").and_then(Value::as_str) {
            Some("loaded") => {
                outln!("loaded");
                ExitCode::SUCCESS
            }
            other => {
                let reason = a.get("reason").and_then(Value::as_str).unwrap_or("");
                outln!(
                    "rejected: {}",
                    crate::text::sanitize(if reason.is_empty() {
                        other.unwrap_or("no answer")
                    } else {
                        reason
                    })
                );
                ExitCode::from(1)
            }
        },
        Err(s) => stop(s),
    }
}

#[cfg(target_os = "linux")]
fn stop(s: crate::secret_cmd::linux::Stop) -> ExitCode {
    use crate::secret_cmd::linux::Stop;
    match s {
        Stop::Refused(m) | Stop::Forbidden(m) | Stop::Unrecorded(m) => {
            eprintln!("saiife: {m}");
            ExitCode::from(2)
        }
        Stop::Unavailable(m) | Stop::NotFound(m) => {
            eprintln!("saiife: {m}");
            ExitCode::from(5)
        }
    }
}

fn list(v: &Value) -> String {
    let items: Vec<&str> = v
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if items.is_empty() {
        "-".to_string()
    } else {
        items.join(", ")
    }
}

fn print_show(view: &Value, hash: Option<&str>, effective: Option<&Value>) {
    use crate::text::sanitize;
    outln!("policy: {}", hash.unwrap_or("(none loaded)"));
    outln!("user: {}", sanitize(view["user"].as_str().unwrap_or("")));
    match view.get("scope") {
        Some(Value::Object(s)) => {
            let env = s.get("env").and_then(Value::as_str).unwrap_or("-");
            outln!(
                "scope: {} (env {})",
                sanitize(s.get("name").and_then(Value::as_str).unwrap_or("")),
                sanitize(env)
            );
            outln!(
                "  projects: {}",
                sanitize(&list(s.get("projects").unwrap_or(&Value::Null)))
            );
        }
        _ => match view.get("scope_error").and_then(Value::as_str) {
            Some(e) => outln!("scope: none ({})", sanitize(e)),
            None => outln!("scope: none (connector calls are denied: no_scope)"),
        },
    }
    if let Some(Value::Object(svcs)) = view.get("services") {
        for (name, s) in svcs {
            outln!(
                "service {} (connector {}, secret {})",
                sanitize(name),
                sanitize(s["connector"].as_str().unwrap_or("")),
                sanitize(s["secret"].as_str().unwrap_or("-"))
            );
            for k in ["allow", "ask", "deny"] {
                outln!("  {k}: {}", sanitize(&list(&s[k])));
            }
            if let Some(rules) = s["rule"].as_array() {
                for r in rules {
                    outln!(
                        "  rule: {} {} when {}",
                        sanitize(r["action"].as_str().unwrap_or("")),
                        sanitize(r["capability"].as_str().unwrap_or("")),
                        sanitize(&r["when"].to_string())
                    );
                }
            }
        }
    }
    let g = &view["guard"];
    outln!(
        "guard: packs {}; ask {}",
        sanitize(&list(&g["packs"])),
        sanitize(&list(&g["ask"]))
    );
    if let Some(e) = effective {
        outln!("{}", serde_json::to_string_pretty(e).unwrap_or_default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "alice:x:1000:1000::/home/alice:/bin/sh\n\
        bob:x:1001:1001::/home/bob:/bin/sh\n\
        carol:x:1002:2000::/home/carol:/bin/sh\n";
    const GROUP: &str = "devs:x:2000:bob\n";

    fn dir() -> FixedDirectory {
        FixedDirectory::from_text(PASSWD, GROUP)
    }

    const SHOP: &str = r#"
version = 2

[[scope]]
name = "shop"
users = ["alice"]
services = ["shopify"]
env = "prod"

[services.shopify]
connector = "shopify"
secret = "shopify-prod"
params = { shop = "acme" }
allow = ["orders:read", "products:read"]
ask = ["products:write"]
deny = ["customers:export"]
"#;

    /// A config file in a fresh dir.
    fn write(text: &str) -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("config.toml");
        std::fs::write(&f, text).unwrap();
        (d, f)
    }

    #[test]
    fn check_valid_config_exit_0() {
        let (_d, f) = write(SHOP);
        let o = check(&f, &dir());
        assert_eq!(o.code, 0, "{o:?}");
        assert!(o.out.starts_with("ok:"), "{o:?}");
    }

    #[test]
    fn check_overlapping_scopes_exit_1() {
        let text =
            format!("{SHOP}\n[[scope]]\nname = \"other\"\nusers = [\"alice\"]\nservices = []\n");
        let (_d, f) = write(&text);
        let o = check(&f, &dir());
        assert_eq!(o.code, 1, "{o:?}");
        assert!(
            o.err.contains("alice") && o.err.contains("shop") && o.err.contains("other"),
            "{o:?}"
        );
        // Through a group, and through a primary group the list cannot show.
        let text = format!(
            "{SHOP}\n[[scope]]\nname = \"g\"\nusers = [\"group:devs\", \"carol\"]\nservices = []\n\
             [[scope]]\nname = \"h\"\nusers = [\"carol\", \"bob\"]\nservices = []\n"
        );
        let (_d, f) = write(&text);
        let o = check(&f, &dir());
        assert_eq!(o.code, 1, "{o:?}");
        assert!(o.err.contains("bob") && o.err.contains("carol"), "{o:?}");
    }

    #[test]
    fn check_unknown_connector_exit_1() {
        let text = SHOP.replace("connector = \"shopify\"", "connector = \"nope\"");
        let (_d, f) = write(&text);
        let o = check(&f, &dir());
        assert_eq!(o.code, 1, "{o:?}");
        assert!(o.err.contains("nope"), "{o:?}");
    }

    #[test]
    fn check_prints_every_error_and_reads_files() {
        let text = format!("{SHOP}\nversion_typo = 1\n");
        let (_d, f) = write(&text);
        assert_eq!(check(&f, &dir()).code, 1);
        let missing = f.with_file_name("absent.toml");
        assert_eq!(check(&missing, &dir()).code, 2);
        // Two independent problems are both named.
        let text = SHOP.replace("connector = \"shopify\"", "connector = \"nope\"")
            + "\n[[scope]]\nname = \"o\"\nusers = [\"alice\"]\nservices = []\n";
        let (_d, f) = write(&text);
        let o = check(&f, &dir());
        assert!(o.err.contains("nope") && o.err.contains("alice"), "{o:?}");
    }

    #[test]
    fn check_guard_ask_must_name_a_rule() {
        let text = format!("{SHOP}\n[guard]\nask = [\"core.git/no-such-rule\"]\n");
        let (_d, f) = write(&text);
        let o = check(&f, &dir());
        assert_eq!(o.code, 1, "{o:?}");
        assert!(o.err.contains("no-such-rule"), "{o:?}");
    }

    fn with_examples(ex: &str) -> String {
        format!("{SHOP}\n{ex}")
    }

    #[test]
    fn test_examples_pass_and_fail() {
        let text = with_examples(
            r#"
[[example]]
user = "alice"
request = "shopify orders.list status=open"
expect = "allow"
[[example]]
user = "alice"
request = "shopify customers.export"
expect = "deny"
[[example]]
user = "alice"
request = "shopify products.update product_id=7"
expect = "ask"
[[example]]
user = "bob"
request = "shopify orders.list"
expect = "deny"
"#,
        );
        let (_d, f) = write(&text);
        let o = test(&f, &dir());
        assert_eq!(o.code, 0, "{o:?}");
        assert!(o.out.contains("ok   example 1"), "{o:?}");
        assert!(o.out.contains("deny (no_scope)"), "{o:?}");
        // A wrong expectation fails the run and shows the actual verdict.
        let (_d, f) = write(&text.replace(
            "request = \"shopify customers.export\"\nexpect = \"deny\"",
            "request = \"shopify customers.export\"\nexpect = \"allow\"",
        ));
        let o = test(&f, &dir());
        assert_eq!(o.code, 1, "{o:?}");
        assert!(
            o.out.contains("FAIL example 2") && o.out.contains("expected allow, got deny"),
            "{o:?}"
        );
    }

    #[test]
    fn test_unknown_example_field_exit_2() {
        for ex in [
            // A typo in a field name.
            "[[example]]\nuser = \"alice\"\nrequst = \"shopify orders.list\"\nexpect = \"deny\"\n",
            // A typo in the verdict.
            "[[example]]\nuser = \"alice\"\nrequest = \"shopify orders.list\"\nexpect = \"alow\"\n",
            // Neither request nor command.
            "[[example]]\nuser = \"alice\"\nexpect = \"deny\"\n",
            // Both.
            "[[example]]\nuser = \"alice\"\nrequest = \"shopify orders.list\"\ncommand = \"ls\"\nexpect = \"allow\"\n",
            // An operation or service that does not exist.
            "[[example]]\nuser = \"alice\"\nrequest = \"shopify orders.lst\"\nexpect = \"deny\"\n",
            "[[example]]\nuser = \"alice\"\nrequest = \"shopfy orders.list\"\nexpect = \"deny\"\n",
        ] {
            let (_d, f) = write(&with_examples(ex));
            let o = test(&f, &dir());
            assert_eq!(o.code, 2, "{ex}: {o:?}");
        }
    }

    #[test]
    fn test_unknown_user_exit_2() {
        let (_d, f) = write(&with_examples(
            "[[example]]\nuser = \"nobody-here\"\nrequest = \"shopify orders.list\"\nexpect = \"deny\"\n",
        ));
        let o = test(&f, &dir());
        assert_eq!(o.code, 2, "{o:?}");
        assert!(o.out.contains("unknown user"), "{o:?}");
    }

    #[test]
    fn test_invalid_policy_never_passes() {
        // Unknown connector: every request would be denied (policy_invalid),
        // which must not make a `deny` example pass.
        let text = with_examples(
            "[[example]]\nuser = \"alice\"\nrequest = \"shopify customers.export\"\nexpect = \"deny\"\n",
        )
        .replace("connector = \"shopify\"", "connector = \"nope\"");
        let (_d, f) = write(&text);
        assert_eq!(test(&f, &dir()).code, 1);
    }

    #[test]
    fn test_command_example_uses_guard_and_ask() {
        let text = format!(
            "{SHOP}\n[guard]\nask = [\"core.git/force-push\"]\n{}",
            r#"
[[example]]
user = "alice"
command = "ls -la"
expect = "allow"
[[example]]
user = "alice"
command = "git push --force origin main"
agent = "claude"
expect = "ask"
[[example]]
user = "alice"
command = "git reset --hard origin/main"
expect = "deny"
"#
        );
        let (_d, f) = write(&text);
        let o = test(&f, &dir());
        assert_eq!(o.code, 0, "{o:?}");
        // Without the ask rule the force push is a plain deny.
        let (_d, f) = write(&text.replace("ask = [\"core.git/force-push\"]", "ask = []"));
        let o = test(&f, &dir());
        assert_eq!(o.code, 1, "{o:?}");
        assert!(o.out.contains("FAIL example 2"), "{o:?}");
    }
}
