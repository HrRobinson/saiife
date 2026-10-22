//! `saiife check`: hook mode. Read the agent's pre-tool JSON on stdin, decide,
//! audit, and answer in the agent's contract. FAIL OPEN on every error.

use std::cell::OnceCell;
use std::io::Read;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::process::ExitCode;

use saiife_audit::chain::{append_chained, sha256_hex, written_unchained};
use saiife_audit::{store, DecisionKind, NewRecord, Record};
use saiifeguard::builtins::Catalog;
use saiifeguard::canon::PathVars;
use saiifeguard::engine::{AllowTrace, Decision, Engine};
use saiifeguard::payload::{
    context_from_hook_json_bounded, HookContext, PayloadError, MAX_PAYLOAD_BYTES,
};

use crate::eval::{self, Plan, PARSE_MAX_BYTES};
use crate::paths::path_vars;
use crate::project::project_packs_known;
use crate::warn;

/// `cli_packs`: `--pack` ids. The project's own packs are added from the
/// `.saiife/config.toml` at or above the payload's `cwd`. Only the active
/// built-in packs are compiled.
pub fn run(cli_packs: &[String], hook_exit: bool, agent: &str) -> ExitCode {
    let mut buf = String::new();
    let mut stdin = std::io::stdin().lock();
    let read = (&mut stdin)
        .take(PARSE_MAX_BYTES as u64 + 1)
        .read_to_string(&mut buf);
    if read.is_ok() && buf.len() > PARSE_MAX_BYTES {
        // Drain the rest so the agent gets no EPIPE.
        let _ = std::io::copy(&mut stdin, &mut std::io::sink());
        let audit = Audit::new(agent, HookContext::default(), cli_packs);
        let reason = format!("hook payload larger than {PARSE_MAX_BYTES} bytes; not judged");
        warn(&format!("{reason}; failing open (allow)"));
        audit.write("", DecisionKind::ErrorAllowed, None, Some(&reason));
        return allow();
    }
    drop(stdin);
    if read.is_err() {
        let audit = Audit::new(agent, HookContext::default(), cli_packs);
        warn("could not read hook payload; failing open (allow)");
        audit.write(
            "",
            DecisionKind::ErrorAllowed,
            None,
            Some("could not read hook payload"),
        );
        return allow();
    }
    let audit = Audit::new(
        agent,
        context_from_hook_json_bounded(&buf, PARSE_MAX_BYTES),
        cli_packs,
    );
    match eval::plan(&buf) {
        Plan::TooLarge { command } => fail_open(
            &audit,
            &command,
            &PayloadError::TooLarge {
                limit: MAX_PAYLOAD_BYTES,
            },
        ),
        Plan::Shell { command } => {
            // Built inside `decide`'s unwind guard: a panic while reading
            // the project config, building the engine or hashing the policy
            // fails open too.
            decide(&audit, &command, hook_exit, |c| {
                active_engine(&audit, cli_packs).0.evaluate(c)
            })
        }
        Plan::Files(call) => decide(&audit, &call.input(), hook_exit, |_| {
            let (engine, vars) = active_engine(&audit, cli_packs);
            eval::judge_files(&engine, &vars, &call)
        }),
        Plan::NoPath => {
            // A write (an apply_patch without file headers, an Edit
            // without a path): allowed, but never recorded as a judged
            // allow.
            audit.write(
                "",
                DecisionKind::ErrorAllowed,
                None,
                Some("no path to judge"),
            );
            allow()
        }
        Plan::Other => {
            audit.write("", DecisionKind::Allow, None, Some("tool not guarded"));
            allow()
        }
        Plan::Unusable(e) => fail_open(&audit, "", &e),
    }
}

/// `saiife check` got arguments it cannot parse: it fails open, so record
/// that like every other fail-open (spec §1.2 rule 5). Best effort and never
/// panics: the agent is taken from `--agent` in `args` if present, the
/// payload is read up to the usual bound (draining the rest, so the agent
/// gets no EPIPE). The caller exits 0 with nothing on stdout.
pub fn record_arg_error(args: &[String], error: &str) {
    let _ = std::panic::catch_unwind(|| {
        let agent = agent_from_args(args).unwrap_or("unknown");
        let mut bytes = Vec::new();
        let mut stdin = std::io::stdin().lock();
        let _ = (&mut stdin)
            .take(PARSE_MAX_BYTES as u64)
            .read_to_end(&mut bytes);
        let _ = std::io::copy(&mut stdin, &mut std::io::sink());
        let buf = String::from_utf8_lossy(&bytes);
        let audit = Audit::new(
            agent,
            context_from_hook_json_bounded(&buf, PARSE_MAX_BYTES),
            &[],
        );
        audit.write(
            "",
            DecisionKind::ErrorAllowed,
            None,
            Some(&format!("bad hook arguments: {error}")),
        );
    });
}

/// The value of `--agent <name>` or `--agent=<name>`.
pub(crate) fn agent_from_args(args: &[String]) -> Option<&str> {
    args.iter().enumerate().find_map(|(i, a)| {
        if a == "--agent" {
            args.get(i + 1).map(String::as_str)
        } else {
            a.strip_prefix("--agent=")
        }
    })
}

/// `engine_for` the built-in packs and the payload's `cwd`: its warnings
/// printed, its policy hash handed to `audit` for the records of this call.
fn active_engine(audit: &Audit, cli_packs: &[String]) -> (Engine, PathVars) {
    let active = engine_for(&Catalog::builtin(), cli_packs, audit.ctx.cwd.as_deref());
    for w in &active.warnings {
        warn(w);
    }
    let _ = audit.policy.set(active.policy);
    (active.engine, active.vars)
}

/// What `engine_for` built.
struct Active {
    engine: Engine,
    /// The path bindings, for expanding globs.
    vars: PathVars,
    /// Broken packs among those compiled, and problems with the project
    /// config.
    warnings: Vec<String>,
    /// `policy_hash` of exactly the packs compiled and the config bytes
    /// they were chosen from.
    policy: String,
}

/// The engine for this call: default-on packs, `--pack` ids, and the packs
/// of the project that `cwd` (or this process's directory) belongs to,
/// with path rules bound to that directory and this machine's saiife dirs.
/// Only these packs of `catalog` are compiled. The project root is looked
/// up once and its config read once (bounded), for the packs and the
/// policy hash alike.
fn engine_for(catalog: &Catalog, cli_packs: &[String], cwd: Option<&str>) -> Active {
    let start = match cwd {
        Some(c) => PathBuf::from(c),
        None => std::env::current_dir().unwrap_or_default(),
    };
    let project = project_packs_known(&start, |id| catalog.knows(id));
    let mut enabled = cli_packs.to_vec();
    enabled.extend(project.enabled);
    let (packs, pack_warnings) = catalog.load_active(&enabled);
    let mut warnings: Vec<String> = pack_warnings
        .iter()
        .map(|w| format!("pack warning ({}): {}", w.source, w.message))
        .collect();
    warnings.extend(project.warnings);
    let config = match (&project.root, &project.config_sha256) {
        (None, _) => CONFIG_NONE,
        (Some(_), Some(hash)) => hash.as_str(),
        (Some(_), None) => CONFIG_UNAVAILABLE,
    };
    let ids: Vec<&str> = packs.iter().map(|p| p.id.as_str()).collect();
    let policy = policy_hash(env!("CARGO_PKG_VERSION"), &ids, config);
    let vars = path_vars(Some(&start), project.root.as_deref());
    let engine = Engine::new(packs).with_paths(vars.clone());
    Active {
        engine,
        vars,
        warnings,
        policy,
    }
}

/// The payload could not be judged: allow, and record why.
fn fail_open(audit: &Audit, input: &str, e: &PayloadError) -> ExitCode {
    warn(&format!(
        "hook payload not usable ({e}); failing open (allow)"
    ));
    audit.write(
        input,
        DecisionKind::ErrorAllowed,
        None,
        Some(&format!("hook payload not usable: {e}")),
    );
    allow()
}

/// Judge `command` with `evaluate`, audit the decision and answer the hook.
/// Split out so the crash path can be tested with a panicking evaluator.
fn decide(
    audit: &Audit,
    command: &str,
    hook_exit: bool,
    evaluate: impl FnOnce(&str) -> Decision,
) -> ExitCode {
    // A panicking engine must not turn into a non-zero exit the agent may
    // read as "block" or as a hook error: fail open, and say so in the log.
    // (Release keeps the default panic=unwind, so this is reachable.)
    let decision = match std::panic::catch_unwind(AssertUnwindSafe(|| evaluate(command))) {
        Ok(d) => d,
        Err(_) => {
            warn("guard crashed; failing open (allow)");
            audit.write(
                command,
                DecisionKind::ErrorAllowed,
                None,
                Some("guard crashed"),
            );
            return allow();
        }
    };
    match &decision {
        Decision::Deny {
            pack,
            pattern,
            reason,
            ..
        } => audit.write(
            command,
            DecisionKind::Deny,
            Some((pack, pattern)),
            Some(reason),
        ),
        Decision::Allow {
            trace:
                AllowTrace::AllowRule {
                    pack,
                    pattern,
                    reason,
                },
        } => audit.write(
            command,
            DecisionKind::Allow,
            Some((pack, pattern)),
            Some(reason),
        ),
        Decision::Allow {
            trace: AllowTrace::NoMatch,
        } => audit.write(command, DecisionKind::Allow, None, None),
        Decision::Allow {
            trace: AllowTrace::FailedOpenTimeout,
        } => audit.write(
            command,
            DecisionKind::ErrorAllowed,
            None,
            Some("guard exceeded its latency budget"),
        ),
        Decision::Allow {
            trace: AllowTrace::Unjudgeable { reason },
        } => audit.write(command, DecisionKind::ErrorAllowed, None, Some(reason)),
    }

    match decision {
        Decision::Deny {
            pack,
            reason,
            via_inline,
            ..
        } => {
            // Same "BLOCKED by <pack>: <reason> (inline: ...)" shape as
            // `test`/`explain`: the hook path is what a real user hits.
            let where_ = via_inline
                .as_deref()
                .map(|i| format!(" (inline: {i})"))
                .unwrap_or_default();
            let msg = format!("BLOCKED by {pack}: {reason}{where_}");
            if hook_exit {
                warn(&msg);
                ExitCode::from(2)
            } else {
                emit_deny(&msg)
            }
        }
        Decision::Allow { .. } => allow(),
    }
}

/// Everything about this hook call except the decision, so each exit path
/// writes a complete record with one call.
struct Audit {
    dir: Option<PathBuf>,
    agent: String,
    ctx: HookContext,
    project: String,
    /// `--pack` ids, for the policy hash of a call that built no engine.
    cli_packs: Vec<String>,
    /// Set by `active_engine` from the engine it built; a call that built
    /// none gets the `--pack` ids with the config `unavailable` marker.
    policy: OnceCell<String>,
}

impl Audit {
    fn new(agent: &str, ctx: HookContext, cli_packs: &[String]) -> Self {
        let project = ctx.cwd.clone().unwrap_or_else(|| {
            std::env::current_dir()
                .map(|d| d.display().to_string())
                .unwrap_or_default()
        });
        let dir = store::default_dir();
        if dir.is_none() {
            warn("could not determine the audit directory; this decision is not audited");
        }
        Self {
            dir,
            agent: agent.to_string(),
            ctx,
            project,
            cli_packs: cli_packs.to_vec(),
            policy: OnceCell::new(),
        }
    }

    /// `sha256:<hex>` of the rules in force for this call. Never reads a
    /// file: without an engine nothing is known beyond the `--pack` ids.
    fn policy(&self) -> &str {
        self.policy.get_or_init(|| {
            let ids: Vec<&str> = self.cli_packs.iter().map(String::as_str).collect();
            policy_hash(env!("CARGO_PKG_VERSION"), &ids, CONFIG_UNAVAILABLE)
        })
    }

    /// Best-effort: a failed write is reported on stderr and otherwise ignored.
    fn write(
        &self,
        input: &str,
        decision: DecisionKind,
        rule: Option<(&String, &String)>,
        reason: Option<&str>,
    ) {
        let Some(dir) = &self.dir else {
            return;
        };
        let rec = Record::new(
            NewRecord {
                agent: &self.agent,
                project: &self.project,
                session: self.ctx.session.as_deref(),
                tool: self.ctx.tool.as_deref().unwrap_or("unknown"),
                input,
                decision,
                pack: rule.map(|(p, _)| p.as_str()),
                rule: rule.map(|(_, r)| r.as_str()),
                reason,
                mode: "developer",
                policy: Some(self.policy()),
                permission_mode: self.ctx.permission_mode.as_deref(),
            },
            env!("CARGO_PKG_VERSION"),
        );
        if let Err(e) = append_chained(dir, rec) {
            match written_unchained(&e) {
                Some(u) => warn(&format!("{u}; decision unaffected")),
                None => warn(&format!("audit write failed ({e}); decision unaffected")),
            }
        }
    }
}

/// The policy's config part when there is no project config.
const CONFIG_NONE: &str = "none";
/// The policy's config part when the config could not be read (refused,
/// too large, a symlink) or no engine was built for the call.
const CONFIG_UNAVAILABLE: &str = "unavailable";

/// `sha256:<hex>` over the saiife version, the sorted unique active pack ids
/// and `config`: the hex SHA-256 of the project config's bytes, or
/// `CONFIG_NONE` / `CONFIG_UNAVAILABLE`.
fn policy_hash(version: &str, active_pack_ids: &[&str], config: &str) -> String {
    let mut ids: Vec<&str> = active_pack_ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    let text = format!(
        "saiife-policy-v1\nsaiife {version}\npacks {}\nconfig {config}\n",
        ids.join(",")
    );
    format!("sha256:{}", sha256_hex(text.as_bytes()))
}

/// Allow = exit 0 with NOTHING on stdout, for every agent and both modes.
/// An explicit `permissionDecision: "allow"` would skip Claude Code's own
/// permission prompts, and Codex treats an allow without `updatedInput` as a
/// failed hook. Silence means "no objection": the agent's normal flow runs.
fn allow() -> ExitCode {
    ExitCode::SUCCESS
}

/// Emit a PreToolUse "deny" response with a reason and exit 0 (the JSON
/// carries the block decision).
fn emit_deny(reason: &str) -> ExitCode {
    let payload = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    });
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    // The deny only works if the agent can read it. When stdout is gone,
    // fail closed: the reason on stderr and exit 2 (the universal block).
    if writeln!(out, "{payload}")
        .and_then(|()| out.flush())
        .is_err()
    {
        crate::warn(&format!("BLOCKED: {reason}"));
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_is_taken_from_args_when_present() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            agent_from_args(&a(&["check", "--agent", "codex", "--x"])),
            Some("codex")
        );
        assert_eq!(
            agent_from_args(&a(&["check", "--agent=gemini"])),
            Some("gemini")
        );
        assert_eq!(agent_from_args(&a(&["check", "--x", "--agent"])), None);
        assert_eq!(agent_from_args(&a(&["check"])), None);
    }

    fn audit_in(dir: &std::path::Path) -> Audit {
        Audit {
            dir: Some(dir.to_path_buf()),
            agent: "claude".into(),
            ctx: HookContext::default(),
            project: "/p".into(),
            cli_packs: Vec::new(),
            policy: OnceCell::new(),
        }
    }

    const BROKEN_CORE: &str = r#"
[pack]
id = "core.broken"
triggers = ["thing"]
[[deny]]
pattern = '('
reason = "bad regex"
[[deny]]
pattern = '^thing\s+wipe'
reason = "wipes the thing"
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

    /// `check` compiles only the active packs, yet still reports a broken
    /// built-in's warning and judges exactly as before: the default-on pack
    /// denies, the opt-in pack applies only once the project enables it.
    #[test]
    fn lazy_packs_keep_warnings() {
        let cat =
            Catalog::from_sources(&[("<t>core.broken", BROKEN_CORE), ("<t>opt.thing", OPT_IN)]);
        let p = tempfile::tempdir().unwrap();
        let cwd = p.path().to_str().unwrap();
        let Active {
            engine, warnings, ..
        } = engine_for(&cat, &[], Some(cwd));
        assert!(
            warnings.iter().any(
                |w| w.starts_with("pack warning (<t>core.broken): skipping uncompilable regex")
            ),
            "{warnings:?}"
        );
        assert!(engine.evaluate("thing wipe").is_deny());
        assert!(!engine.evaluate("thing drop").is_deny());

        std::fs::create_dir(p.path().join(".saiife")).unwrap();
        std::fs::write(
            p.path().join(".saiife/config.toml"),
            "packs = [\"opt.thing\"]\n",
        )
        .unwrap();
        let Active {
            engine, warnings, ..
        } = engine_for(&cat, &[], Some(cwd));
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(engine.evaluate("thing wipe").is_deny());
        assert!(engine.evaluate("thing drop").is_deny());
        let engine = engine_for(&cat, &["opt.thing".into()], None).engine;
        assert!(engine.evaluate("thing drop").is_deny());
    }

    #[test]
    fn engine_panic_fails_open_and_is_audited() {
        let dir = tempfile::tempdir().unwrap();
        let code = decide(&audit_in(dir.path()), "rm -rf /tmp/x", true, |_| {
            panic!("engine bug")
        });
        assert_eq!(code, ExitCode::SUCCESS);
        let recs = store::read_all(dir.path()).records;
        // Genesis line, then the record.
        assert_eq!(recs.len(), 2);
        let r = &recs[1];
        assert_eq!(r.decision, DecisionKind::ErrorAllowed);
        assert_eq!(r.input, "rm -rf /tmp/x");
        assert_eq!(r.reason.as_deref(), Some("guard crashed"));
    }

    #[test]
    fn normal_decision_still_flows_through_decide() {
        let dir = tempfile::tempdir().unwrap();
        let code = decide(&audit_in(dir.path()), "ls", true, |_| Decision::Allow {
            trace: AllowTrace::NoMatch,
        });
        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(
            store::read_all(dir.path()).records[1].decision,
            DecisionKind::Allow
        );
    }

    /// The policy hash names the packs actually compiled (a broken
    /// default-on pack still counts, an opt-in one only once enabled) and
    /// the exact config bytes they were chosen from.
    #[test]
    fn policy_names_the_compiled_packs_and_config() {
        let cat =
            Catalog::from_sources(&[("<t>core.broken", BROKEN_CORE), ("<t>opt.thing", OPT_IN)]);
        let p = tempfile::tempdir().unwrap();
        let cwd = p.path().to_str().unwrap();
        let v = env!("CARGO_PKG_VERSION");
        assert_eq!(
            engine_for(&cat, &[], Some(cwd)).policy,
            policy_hash(v, &["core.broken"], CONFIG_NONE)
        );
        std::fs::create_dir(p.path().join(".saiife")).unwrap();
        let cfg = "packs = [\"opt.thing\"]\n";
        std::fs::write(p.path().join(".saiife/config.toml"), cfg).unwrap();
        assert_eq!(
            engine_for(&cat, &[], Some(cwd)).policy,
            policy_hash(
                v,
                &["core.broken", "opt.thing"],
                &sha256_hex(cfg.as_bytes())
            )
        );
        // Unparseable bytes are still the config in force: hashed as read.
        std::fs::write(p.path().join(".saiife/config.toml"), "packs = [\n").unwrap();
        assert_eq!(
            engine_for(&cat, &[], Some(cwd)).policy,
            policy_hash(v, &["core.broken"], &sha256_hex(b"packs = [\n"))
        );
    }

    /// A call that built no engine never reads the config: its policy is
    /// the `--pack` ids with the `unavailable` marker.
    #[test]
    fn policy_without_engine_is_the_unavailable_marker() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = audit_in(dir.path());
        a.cli_packs = vec!["db.postgres".into()];
        assert_eq!(
            a.policy(),
            policy_hash(
                env!("CARGO_PKG_VERSION"),
                &["db.postgres"],
                CONFIG_UNAVAILABLE
            )
        );
    }

    #[test]
    fn policy_hash_changes_with_config() {
        let h = |v: &str, ids: &[&str], cfg: Option<&[u8]>| {
            policy_hash(
                v,
                ids,
                &cfg.map_or_else(|| CONFIG_NONE.to_string(), sha256_hex),
            )
        };
        let base = h("0.1.0", &["a", "b"], Some(b"x"));
        assert!(base.starts_with("sha256:") && base.len() == 7 + 64);
        assert_eq!(base, h("0.1.0", &["a", "b"], Some(b"x")));
        assert_ne!(base, h("0.1.0", &["a", "b"], Some(b"y")));
        assert_ne!(base, h("0.1.0", &["a", "b"], None));
        assert_ne!(base, h("0.1.0", &["a", "b", "c"], Some(b"x")));
        assert_ne!(base, h("0.2.0", &["a", "b"], Some(b"x")));
        assert_ne!(base, policy_hash("0.1.0", &["a", "b"], CONFIG_UNAVAILABLE));
        assert_eq!(base, h("0.1.0", &["b", "a", "a"], Some(b"x")));
    }

    #[test]
    fn policy_hash_text_is_exact() {
        let want = format!(
            "sha256:{}",
            sha256_hex(b"saiife-policy-v1\nsaiife 1\npacks a,b\nconfig none\n")
        );
        assert_eq!(policy_hash("1", &["b", "a"], CONFIG_NONE), want);
        let want = format!(
            "sha256:{}",
            sha256_hex(b"saiife-policy-v1\nsaiife 1\npacks a\nconfig unavailable\n")
        );
        assert_eq!(policy_hash("1", &["a"], CONFIG_UNAVAILABLE), want);
    }
}
