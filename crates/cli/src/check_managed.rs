//! `saiife check --managed`: the locked-mode hook (spec §6.1.2). FAIL
//! CLOSED on every error.
//!
//! The guard runs in a worker child (`saiife __eval`), so an abort, a
//! signal or a stack overflow in the engine becomes a clean deny. The
//! masked record goes to the daemon (`audit.append`); the call is allowed
//! only once the daemon has acknowledged it. Every error ends in exit 2, a
//! reason on stderr and, when the daemon can be reached, an `error_denied`
//! record. When it cannot, the reason goes to stderr only: nobody could
//! write the record.
//!
//! A deny by a rule listed in `[guard] ask` (spec §6.10.4) takes one or
//! two more round trips, inside the same 2 s ack budget: `grant.consume`
//! (an approved grant for this exact call: allowed once, record
//! `approved`), else `approval.create` (a pending request: denied with
//! "Needs approval: request #<id>. ..." and record `ask`). The daemon
//! keys the grant from the peer uid and the record's `agent`, `project`,
//! `tool` and `input`, the project root (canonical) and the SHA-256 of the
//! exact command judged (`raw_sha256`); the hook never sends a key or the
//! raw text. Only a command whose record shows it whole (nothing masked,
//! nothing cut) and that only `ask` rules deny (the worker's `askable`)
//! can be approved; any other is a plain deny. Any error there denies as
//! `error_denied`. Other calls make no extra round trip.
//!
//! This path never reads `SAIIFE_AUDIT_DIR` or `SAIIFE_DATA_DIR` and never
//! opens `.chain.lock`: in locked mode the daemon is the only writer.

use std::path::Path;
use std::process::ExitCode;

/// Where the system policy lives; `--system-config` overrides it in tests.
pub const SYSTEM_CONFIG: &str = "/etc/saiife/config.toml";

/// Exit 2 with `saiife: BLOCKED (fail closed): <reason>` on stderr.
fn blocked(reason: &str) -> ExitCode {
    crate::warn(&format!("BLOCKED (fail closed): {reason}"));
    ExitCode::from(2)
}

/// The hook event `--event` names: Claude Code's `ConfigChange`.
pub const EVENT_CONFIG_CHANGE: &str = "config-change";

/// The whole run is inside `catch_unwind`: a panic denies. `event`: the
/// hook event when it is not a tool call (`config-change`).
pub fn run(agent: &str, system_config: &Path, event: Option<&str>) -> ExitCode {
    guarded(|| imp::run_with(agent, system_config, event, None))
}

/// `check --managed` got arguments it cannot parse: deny, and record that
/// when the daemon can be reached (the agent and `--system-config` are
/// taken from `args` if present).
pub fn run_bad_args(args: &[String], error: &str) -> ExitCode {
    let agent = crate::check::agent_from_args(args).unwrap_or("unknown");
    let config = flag_value(args, "--system-config").unwrap_or(SYSTEM_CONFIG);
    let reason = format!("bad hook arguments: {error}");
    // Only to name the tool in the record.
    let event = flag_value(args, "--event").filter(|e| *e == EVENT_CONFIG_CHANGE);
    guarded(|| imp::run_with(agent, Path::new(config), event, Some(reason.clone())))
}

/// Starts the watchdog, then runs `f` inside `catch_unwind`. Without a
/// watchdog there is no overall deadline, and an agent that lets the call
/// run on hook timeout (Codex, Gemini CLI) would get it through: deny
/// before reading stdin.
fn guarded(f: impl FnOnce() -> ExitCode) -> ExitCode {
    if !imp::start_watchdog() {
        return blocked("cannot start the watchdog");
    }
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(code) => code,
        Err(_) => blocked("saiife crashed"),
    }
}

/// The value of `<name> <value>` or `<name>=<value>` in `args`.
pub(crate) fn flag_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().enumerate().find_map(|(i, a)| {
        if a == name {
            args.get(i + 1).map(String::as_str)
        } else {
            a.strip_prefix(name).and_then(|v| v.strip_prefix('='))
        }
    })
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;

    pub fn start_watchdog() -> bool {
        true
    }

    pub fn run_with(
        _agent: &str,
        _config: &Path,
        _event: Option<&str>,
        _forced: Option<String>,
    ) -> ExitCode {
        // Drain stdin so the agent gets no EPIPE.
        let _ = std::io::copy(&mut std::io::stdin().lock(), &mut std::io::sink());
        crate::warn("locked mode needs Linux in this version (macOS: v2.1)");
        ExitCode::from(2)
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;

    use std::io::{BufWriter, Read, Write};
    use std::os::unix::process::ExitStatusExt;
    use std::path::PathBuf;
    use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use saiife_agents::config::{find_project_root, read_config_bytes, CONFIG_REL};
    use saiife_audit::{DecisionKind, NewRecord, Record};
    use saiife_ipc::client::{system_entry, system_uid, Client, ClientError};
    use saiife_ipc::msg::{
        ErrorCode, MAX_RECORD_BYTES, OP_APPROVAL_CREATE, OP_AUDIT_APPEND, OP_GRANT_CONSUME,
    };
    use saiife_policy::{
        active_packs, applied_for, effective_policy, load_system, merge_project, parse_project,
        policy_hash, Mode, PackInfo, SystemConfig,
    };
    use saiifeguard::builtins::Catalog;
    use saiifeguard::payload::{context_from_hook_json_bounded, HookContext};
    use serde_json::{Map, Value};

    use crate::eval::PARSE_MAX_BYTES;
    use crate::eval::{
        self, EvalAnswer, EvalRequest, McpCheck, McpIdentity, Plan, Verdict, MAX_EVAL_BYTES,
    };
    use crate::paths::LockedPaths;
    use crate::warn;

    /// The worker's deadline, from its spawn (§6.1.2).
    const WORKER_TIMEOUT: Duration = Duration::from_secs(3);
    /// Connecting, including `hello`.
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
    /// The daemon's ack of `audit.append`, from the send (§6.1.2).
    const ACK_TIMEOUT: Duration = Duration::from_secs(2);
    /// The whole hook call, whatever hangs (a stat on a dead FUSE mount, a
    /// slow lookup): well inside the agents' 10 s hook timeout, after
    /// which Codex and Gemini CLI would let the call run (§9.3). The
    /// deadlines above add up to about 5 s.
    const OVERALL_TIMEOUT: Duration = Duration::from_secs(7);
    /// Longest `agent`, `project`, `session`, `tool`, `reason` or
    /// `permission_mode` sent, in characters. A record can still serialize
    /// past `MAX_RECORD_BYTES` (a control character is 6 bytes as
    /// `\u00XX`), so `fit` then cuts by serialized bytes.
    const MAX_FIELD_CHARS: usize = 4096;
    const TRUNCATED_MARK: &str = "…[truncated]";
    /// The reason recorded when even the shrunk record does not fit.
    const TOO_LARGE: &str = "record too large";
    /// The fields `fit` may cut: everything the agent or the project
    /// controls. The daemon sets the rest, or it is short and fixed.
    const SHRINKABLE: [&str; 9] = [
        "input",
        "project",
        "session",
        "permission_mode",
        "reason",
        "tool",
        "agent",
        "rule",
        "pack",
    ];

    /// The running worker's pid (0: none), for the watchdog.
    static WORKER_PID: AtomicU32 = AtomicU32::new(0);

    /// After `OVERALL_TIMEOUT`, kill the worker if one runs, say why on
    /// stderr and exit 2, wherever the main thread is stuck. The message is
    /// written to the stderr fd directly: a main thread blocked while
    /// holding the stderr lock cannot stop it. `false`: the thread could
    /// not be started (`RLIMIT_NPROC`, `pids.max`).
    pub fn start_watchdog() -> bool {
        #[cfg(debug_assertions)]
        if eval::fault() == "watchdog_spawn" {
            return false;
        }
        std::thread::Builder::new()
            .name("saiife-watchdog".into())
            .spawn(|| {
                std::thread::sleep(OVERALL_TIMEOUT);
                let pid = WORKER_PID.load(Ordering::SeqCst);
                if let Some(pid) = rustix::process::Pid::from_raw(pid as i32) {
                    let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
                }
                use std::os::fd::AsFd;
                let msg = b"saiife: BLOCKED (fail closed): saiife took too long\n";
                let _ = rustix::io::write(std::io::stderr().as_fd(), msg);
                std::process::exit(2);
            })
            .is_ok()
    }

    /// How the call is answered.
    enum Outcome {
        Allow,
        /// `BLOCKED by <pack>: <reason>`.
        Deny(String),
        /// Fail closed with this reason.
        Error(String),
    }

    /// The fields of the record this call sends.
    struct Judged {
        decision: DecisionKind,
        input: String,
        tool: Option<String>,
        pack: Option<String>,
        rule: Option<String>,
        /// The deny rule's id in its pack (`force-push`), if it has one.
        rule_id: Option<String>,
        /// Denied only by `[guard] ask` rules (the worker's `askable`).
        askable: bool,
        reason: Option<String>,
        outcome: Outcome,
    }

    impl Judged {
        /// `error_denied` with `reason`, for a call the guard did not judge.
        fn error(input: String, reason: String) -> Judged {
            Judged {
                decision: DecisionKind::ErrorDenied,
                input,
                tool: None,
                pack: None,
                rule: None,
                rule_id: None,
                askable: false,
                reason: Some(reason.clone()),
                outcome: Outcome::Error(reason),
            }
        }

        /// An `allow` for the reserved server `saiife`: the daemon judges
        /// its calls.
        fn mcp_brokered(input: String) -> Judged {
            let reason = "brokered: judged by the saiife daemon".to_string();
            Judged {
                decision: DecisionKind::Allow,
                input,
                tool: None,
                pack: Some("guard.mcp".into()),
                rule: Some("mcp_brokered".into()),
                rule_id: None,
                askable: false,
                outcome: Outcome::Allow,
                reason: Some(reason),
            }
        }

        /// A `deny` by `guard.mcp` (spec §6.1.4).
        fn mcp_denied(reason: String) -> Judged {
            Judged {
                decision: DecisionKind::Deny,
                input: String::new(),
                tool: None,
                pack: Some("guard.mcp".into()),
                rule: Some("mcp_server_not_allowed".into()),
                rule_id: None,
                askable: false,
                outcome: Outcome::Deny(format!("BLOCKED by guard.mcp: {reason}")),
                reason: Some(reason),
            }
        }

        fn from_answer(a: EvalAnswer) -> Judged {
            let (decision, outcome) = match a.verdict {
                Verdict::Allow => (DecisionKind::Allow, Outcome::Allow),
                Verdict::Deny => {
                    let msg = format!(
                        "BLOCKED by {}: {}",
                        a.pack.as_deref().unwrap_or("saiife"),
                        a.reason.as_deref().unwrap_or("denied by policy")
                    );
                    (DecisionKind::Deny, Outcome::Deny(msg))
                }
                Verdict::Unjudged => (
                    DecisionKind::ErrorDenied,
                    Outcome::Error(
                        a.reason
                            .clone()
                            .unwrap_or_else(|| "the guard could not judge this call".into()),
                    ),
                ),
            };
            Judged {
                decision,
                input: a.input,
                tool: a.tool,
                pack: a.pack,
                rule: a.rule,
                rule_id: a.rule_id,
                askable: a.askable,
                reason: a.reason,
                outcome,
            }
        }
    }

    /// `event`: the hook event when it is not a tool call. `forced`: fail
    /// closed with this reason without judging (bad arguments).
    pub fn run_with(
        agent: &str,
        config: &Path,
        event: Option<&str>,
        forced: Option<String>,
    ) -> ExitCode {
        // 1. The payload, bounded.
        let input = read_stdin();
        #[cfg(debug_assertions)]
        if eval::fault() == "parent_hang" {
            std::thread::sleep(Duration::from_secs(20));
        }

        // 2. The system policy. Without it there is no daemon to tell.
        let cfg = match load_locked(config) {
            Ok(c) => c,
            Err(e) => return blocked(&format!("saiife policy could not be loaded: {e}")),
        };
        let Some(daemon_uid) = system_uid(&cfg.daemon.user) else {
            return blocked(&format!(
                "the saiife daemon user {:?} does not exist",
                cfg.daemon.user
            ));
        };

        let mut ctx = match &input {
            Ok(buf) => context_from_hook_json_bounded(buf, PARSE_MAX_BYTES),
            Err(_) => HookContext::default(),
        };
        if event == Some(EVENT_CONFIG_CHANGE) {
            // A settings change is no tool call; its record says what it is.
            ctx.tool = Some("ConfigChange".into());
        }
        // A panic from here until the record is built still gets an
        // `error_denied` record, as long as the daemon was reached.
        let mut client: Option<Client> = None;
        let mut policy: Option<String> = None;
        // The canonical cwd and project root, for a grant's scope.
        let mut key_project: Option<(String, String)> = None;
        let judged = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            judge_call(
                (&cfg, config),
                daemon_uid,
                (agent, event),
                &ctx,
                input,
                forced,
                &mut client,
                (&mut policy, &mut key_project),
            )
        }));
        let judged = match judged {
            Ok(Ok(j)) => j,
            // The daemon cannot be reached: stderr only.
            Ok(Err(reason)) => return blocked(&reason),
            Err(_) => Judged::error(String::new(), "saiife crashed".into()),
        };
        let Some(mut client) = client else {
            return blocked("saiife crashed before reaching the audit daemon");
        };

        // 8. The record, within the daemon's size limit; 9. its ack.
        let policy = policy.unwrap_or_else(|| "unavailable".into());
        let mut judged = judged;
        let mut rec = record(agent, &ctx, &policy, &judged);
        if !fit(&mut rec) {
            // Fail closed: the record says error_denied, so must the call.
            judged = Judged::error(String::new(), TOO_LARGE.into());
            rec = minimal_record(agent, &policy);
        }
        // One budget for the approval steps and the ack.
        let deadline = Instant::now() + ACK_TIMEOUT;
        if asked(&cfg, &judged) {
            let shown_whole =
                rec.get("input").and_then(Value::as_str) == Some(judged.input.as_str());
            let raw_sha256 = sha256_hex(judged.input.as_bytes());
            let step = match (judged.askable, shown_whole, &key_project) {
                // Another rule denies too (a compound command): a plain deny.
                (false, _, _) => Ok(()),
                (true, false, _) => {
                    cannot_approve(&mut rec, &mut judged, CANNOT_APPROVE);
                    Ok(())
                }
                (true, true, None) => {
                    cannot_approve(&mut rec, &mut judged, NO_PROJECT_ROOT);
                    Ok(())
                }
                // The daemon checks the scope lexically: it sends the
                // canonical cwd as the record's project.
                (true, true, Some((cwd, root))) => {
                    set_field(&mut rec, "project", cwd).and_then(|()| {
                        ask_step(
                            &mut client,
                            (&mut rec, &mut judged),
                            (&raw_sha256, root),
                            deadline,
                        )
                    })
                }
            };
            match step {
                Ok(()) => {}
                // Lockdown `all`: the deny stands; the ack says why.
                Err(ClientError::Refused { code, .. }) if code == ErrorCode::Lockdown.as_str() => {}
                Err(e) => {
                    let why = format!("the approval step failed ({})", describe(&e));
                    judged = Judged::error(judged.input.clone(), why);
                    rec = record(agent, &ctx, &policy, &judged);
                    if !fit(&mut rec) {
                        judged = Judged::error(String::new(), TOO_LARGE.into());
                        rec = minimal_record(agent, &policy);
                    }
                }
            }
        }
        if let Err(e) = append(&mut client, rec, deadline) {
            // Lockdown `all`: the daemon wrote the record as a deny.
            if let ClientError::Refused { code, message } = &e {
                if code == ErrorCode::Lockdown.as_str() {
                    let _ = writeln!(std::io::stderr(), "{message}");
                    return ExitCode::from(2);
                }
            }
            return blocked(&format!(
                "the audit daemon did not record this call ({})",
                describe(&e)
            ));
        }

        // 10. The answer.
        match judged.outcome {
            Outcome::Allow => ExitCode::SUCCESS,
            Outcome::Deny(msg) => {
                let _ = writeln!(std::io::stderr(), "{msg}");
                ExitCode::from(2)
            }
            Outcome::Error(reason) => blocked(&reason),
        }
    }

    /// Steps 3 to 7: the project, the policy, the worker and the daemon
    /// connection (made while the worker runs). `Err` is a reason for
    /// stderr only: the daemon could not be reached. `cfg` was loaded from
    /// `config`. An MCP tool whose server `[guard.mcp]` does not list is
    /// denied without a worker.
    #[allow(clippy::too_many_arguments)]
    fn judge_call(
        (cfg, config): (&SystemConfig, &Path),
        daemon_uid: u32,
        (agent, event): (&str, Option<&str>),
        ctx: &HookContext,
        input: Result<String, String>,
        forced: Option<String>,
        client: &mut Option<Client>,
        (policy, key_project): (&mut Option<String>, &mut Option<(String, String)>),
    ) -> Result<Judged, String> {
        // An unusable cwd is never looked up: no project, no worker.
        let cwd = eval::check_cwd(ctx.cwd.as_deref());
        let start = match (&cwd, &ctx.cwd) {
            (Err(_), _) => None,
            (Ok(()), Some(c)) => Some(PathBuf::from(c)),
            (Ok(()), None) => std::env::current_dir().ok(),
        };
        // A policy that cannot be resolved for this call (its scope
        // environment's lookups failed) is judged `error_denied` with
        // policy `unavailable`, recorded like any other failure: never a
        // stderr-only block.
        let (packs, unresolved) = match policy_for(cfg, start.as_deref()) {
            Ok((packs, hash)) => {
                *policy = Some(hash);
                (packs, None)
            }
            Err(e) => (
                Vec::new(),
                Some(format!("the policy for this call is unavailable ({e})")),
            ),
        };
        if !cfg.guard.ask.is_empty() {
            // The project in a grant's key: its root as found for the
            // project config (else the cwd), and the cwd, both canonical
            // here (the daemon cannot see this user's files).
            let canon = |p: &Path| {
                std::fs::canonicalize(p)
                    .ok()
                    .and_then(|p| p.to_str().map(str::to_string))
            };
            *key_project = start.as_deref().and_then(|s| {
                let root = find_project_root(s).unwrap_or_else(|| s.to_path_buf());
                Some((canon(s)?, canon(&root)?))
            });
        }

        let failed = unresolved
            .or(forced)
            .or_else(|| input.as_ref().err().cloned())
            .or(cwd.err());
        let mcp_judged = match (&failed, &input, event) {
            (None, Ok(payload), None) => mcp_judgement(agent, ctx, payload, cfg),
            _ => None,
        };
        let mut worker = match (&failed, &mcp_judged, input) {
            (None, None, Ok(payload)) => Some(Worker::spawn(EvalRequest {
                payload,
                // A settings change is judged without packs.
                packs: if event.is_some() { Vec::new() } else { packs },
                budget_ms: cfg.guard.budget_ms,
                locked: Some(locked_paths(cfg, config)),
                event: event.map(str::to_string),
                ask: cfg.guard.ask.clone(),
            })),
            _ => None,
        };

        let connected = Client::connect(
            &cfg.daemon.socket_dir,
            daemon_uid,
            Instant::now() + CONNECT_TIMEOUT,
        );
        let c = match connected {
            Ok(c) => c,
            Err(e) => {
                if let Some(Ok(w)) = &mut worker {
                    w.kill();
                }
                return Err(format!("cannot reach the audit daemon ({})", describe(&e)));
            }
        };
        // Only a daemon in locked mode may take the record.
        if c.hello_answer().get("mode").and_then(Value::as_str) != Some("locked") {
            if let Some(Ok(w)) = &mut worker {
                w.kill();
            }
            return Err("the audit daemon is not in locked mode".into());
        }
        *client = Some(c);

        if let Some(reason) = failed {
            return Ok(Judged::error(String::new(), reason));
        }
        if let Some(judged) = mcp_judged {
            return Ok(judged);
        }
        let (payload, answer) = match worker {
            Some(Ok(w)) => w.finish(),
            Some(Err((payload, e))) => (payload, Err(format!("could not start: {e}"))),
            // A worker is spawned whenever nothing failed; deny regardless.
            None => (String::new(), Err("not started".into())),
        };
        Ok(match answer {
            Ok(a) => Judged::from_answer(a),
            Err(why) => Judged::error(
                recorded_input(&payload),
                format!("guard worker failed ({why})"),
            ),
        })
    }

    /// The `guard.mcp` judgement of this call without a worker, if its tool
    /// is an MCP tool: a deny when `[guard.mcp] allow_servers` does not list
    /// its server, an allow for the brokered server `saiife`.
    fn mcp_judgement(
        agent: &str,
        ctx: &HookContext,
        payload: &str,
        cfg: &SystemConfig,
    ) -> Option<Judged> {
        let tool = ctx.tool.as_deref()?;
        // Claude Code and Codex names are judged alone; only the other
        // agents' payloads are scanned for `mcp_context`.
        let identity = match agent {
            "claude" | "codex" => McpIdentity::Absent,
            _ => eval::mcp_identity(payload),
        };
        match eval::mcp_check(agent, tool, &identity, &cfg.guard.mcp.allow_servers) {
            McpCheck::NotMcp | McpCheck::Allowed => None,
            McpCheck::Brokered => Some(Judged::mcp_brokered(recorded_input(payload))),
            McpCheck::Denied(s) => Some(Judged::mcp_denied(format!(
                "MCP server {s} is not in [guard.mcp] allow_servers"
            ))),
            McpCheck::Unknown => Some(Judged::mcp_denied("MCP server unknown on Gemini".into())),
        }
    }

    /// What the record names when the worker gave no answer: the command
    /// or the paths, as the worker would have.
    fn recorded_input(payload: &str) -> String {
        match eval::plan(payload) {
            Plan::Shell { command } | Plan::TooLarge { command } => command,
            Plan::Files(call) => call.input(),
            Plan::NoPath | Plan::Other | Plan::Unusable(_) => String::new(),
        }
    }

    /// Stdin with the `PARSE_MAX_BYTES` cap. `Err` is the reason to deny.
    fn read_stdin() -> Result<String, String> {
        let mut buf = String::new();
        let mut stdin = std::io::stdin().lock();
        let read = (&mut stdin)
            .take(PARSE_MAX_BYTES as u64 + 1)
            .read_to_string(&mut buf);
        if read.is_ok() && buf.len() > PARSE_MAX_BYTES {
            // Drain the rest so the agent gets no EPIPE.
            let _ = std::io::copy(&mut stdin, &mut std::io::sink());
            return Err(format!(
                "hook payload larger than {PARSE_MAX_BYTES} bytes; not judged"
            ));
        }
        read.map(|_| buf)
            .map_err(|_| "could not read hook payload".to_string())
    }

    /// The paths `core.lock` guards beyond the §5.2 defaults: the system
    /// config's own dir, the audit dir and the socket dir it names.
    fn locked_paths(cfg: &SystemConfig, config: &Path) -> LockedPaths {
        LockedPaths {
            etc: config.parent().unwrap_or(Path::new("/")).to_path_buf(),
            audit_dir: cfg.audit.dir.clone(),
            socket_dir: cfg.daemon.socket_dir.clone(),
        }
    }

    /// `load_system`, which must say `locked = true`.
    fn load_locked(config: &Path) -> Result<SystemConfig, String> {
        let loaded = load_system(config).map_err(|e| e.to_string())?;
        if !loaded.config.locked {
            return Err(format!("{}: locked is not true", config.display()));
        }
        Ok(loaded.config)
    }

    /// The active pack ids and the `policy` hash for a call in `start`. The
    /// project config adds packs and service rules only (add-only merge);
    /// an invalid one is ignored with a warning: the system policy alone
    /// applies.
    fn policy_for(
        cfg: &SystemConfig,
        start: Option<&Path>,
    ) -> Result<(Vec<String>, String), String> {
        // The caller's scope environment adds its packs and is part of the
        // hash. Nothing is read or spawned unless some scope binds one; an
        // environment that cannot be resolved denies the call.
        let (cfg_env, env) = if cfg.scope.iter().any(|s| s.env.is_some()) {
            let read = |p: &str| std::fs::read_to_string(p).unwrap_or_default();
            let nsswitch = std::fs::read_to_string("/etc/nsswitch.conf").ok();
            hook_env(
                cfg,
                rustix::process::getuid().as_raw(),
                (&read("/etc/passwd"), &read("/etc/group")),
                nsswitch.as_deref(),
                &saiife_policy::Getent,
            )?
        } else {
            (std::borrow::Cow::Borrowed(cfg), None)
        };
        let cfg: &SystemConfig = &cfg_env;
        let merged = start.and_then(find_project_root).and_then(|root| {
            let ignored = |why: &str| {
                warn(&format!(
                    "project config {} ignored ({why}); the system policy applies",
                    root.join(CONFIG_REL).display()
                ));
                None
            };
            match read_config_bytes(&root) {
                Ok(None) => None,
                Ok(Some(bytes)) => match parse_project(&bytes) {
                    Ok(p) => Some(merge_project(&cfg.guard.packs, &p, Mode::Locked)),
                    Err(e) => ignored(&e.to_string()),
                },
                Err(e) => ignored(&e.to_string()),
            }
        });
        let catalog: Vec<PackInfo> = Catalog::builtin()
            .headers()
            .into_iter()
            .map(|(id, version, default_on)| PackInfo {
                id,
                version,
                default_on,
                rules: Vec::new(),
            })
            .collect();
        let (packs, warnings) = active_packs(cfg, &catalog, merged.as_ref());
        for w in &warnings {
            warn(w);
        }
        let hash = policy_hash(&effective_policy(
            cfg,
            &packs,
            merged.as_ref(),
            env.as_deref(),
        ));
        Ok((packs.into_iter().map(|p| p.id).collect(), hash))
    }

    /// Whether `nsswitch.conf` takes groups from `files` alone (not compat or
    /// systemd, which can add groups `/etc/group` lacks), so
    /// `/etc/group` is the whole answer and no process needs to run.
    fn groups_are_local(nsswitch: Option<&str>) -> bool {
        let Some(text) = nsswitch else {
            return false;
        };
        text.lines()
            .map(|l| l.split('#').next().unwrap_or("").trim())
            .find_map(|l| l.strip_prefix("group:"))
            .is_some_and(|sources| {
                let mut any = false;
                let local = sources.split_whitespace().all(|s| {
                    any = true;
                    s == "files"
                });
                local && any
            })
    }

    /// The scope environment of `uid`, as the daemon would find it. The
    /// name comes from `/etc/passwd`, else from `nss` (the daemon asks NSS
    /// too). Groups come from `/etc/group` when the user is local and
    /// `nsswitch.conf` has no other group source; otherwise `nss` answers,
    /// and a failed lookup denies.
    fn hook_env<'a>(
        cfg: &'a SystemConfig,
        uid: u32,
        (passwd, group): (&str, &str),
        nsswitch: Option<&str>,
        nss: &dyn saiife_policy::Directory,
    ) -> Result<(std::borrow::Cow<'a, SystemConfig>, Option<String>), String> {
        use saiife_policy::Directory;
        let fixed = saiife_policy::FixedDirectory::from_text(passwd, group);
        let Some(name) = fixed.name_of(uid).or_else(|| nss.name_of(uid)) else {
            return Err("cannot tell which user this is: no environment".into());
        };
        let local = fixed.user(&name).is_some() && groups_are_local(nsswitch);
        let dir: &dyn Directory = if local { &fixed } else { nss };
        applied_for(cfg, dir, &name).map_err(|e| format!("environment: {e}"))
    }

    /// The worker child, running.
    struct Worker {
        child: Child,
        started: Instant,
        /// The payload, kept for the record if the worker fails.
        payload: String,
        /// The reader thread's result: everything on the worker's stdout.
        out: mpsc::Receiver<std::io::Result<Vec<u8>>>,
    }

    impl Worker {
        /// `saiife __eval` with a cleared environment: only `HOME` and
        /// `USER` from the `/etc/passwd` entry of this process's real uid,
        /// `PATH=/usr/bin:/bin` and `LANG=C` (debug builds add the
        /// `SAIIFE_EVAL_FAULT` test seam). An agent started with another
        /// `HOME`, `CLAUDE_CONFIG_DIR`, `CODEX_HOME` or `XDG_*` therefore
        /// cannot move the path rules; the worker derives the agent dirs
        /// from that home. The request is written and the answer read on
        /// threads, so neither a worker that never reads nor one that
        /// never writes can outlast the deadline.
        fn spawn(req: EvalRequest) -> Result<Worker, (String, std::io::Error)> {
            let started = Instant::now();
            let uid = rustix::process::getuid().as_raw();
            let Some(account) = system_entry(uid) else {
                let e = std::io::Error::other(format!("no /etc/passwd entry for uid {uid}"));
                return Err((req.payload, e));
            };
            let exe = match std::env::current_exe() {
                Ok(e) => e,
                Err(e) => return Err((req.payload, e)),
            };
            let mut cmd = Command::new(exe);
            cmd.arg("__eval")
                .env_clear()
                .env("HOME", &account.home)
                .env("USER", &account.name)
                .env("PATH", "/usr/bin:/bin")
                .env("LANG", "C")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null());
            #[cfg(debug_assertions)]
            if let Some(f) = std::env::var_os("SAIIFE_EVAL_FAULT") {
                cmd.env("SAIIFE_EVAL_FAULT", f);
            }
            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => return Err((req.payload, e)),
            };
            WORKER_PID.store(child.id(), Ordering::SeqCst);
            let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
                let _ = child.kill();
                let _ = child.wait();
                return Err((req.payload, std::io::Error::other("no pipes")));
            };
            // The parent keeps a copy for the record; the request owns the
            // one the writer thread sends.
            let payload = req.payload.clone();
            std::thread::spawn(move || {
                let mut w = BufWriter::new(stdin);
                // A worker that dies early closes the pipe: EPIPE, ignored.
                let _ = serde_json::to_writer(&mut w, &req);
                let _ = w.flush();
            });
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(read_bounded(stdout));
            });
            Ok(Worker {
                child,
                started,
                payload,
                out: rx,
            })
        }

        /// Kill and reap (a no-op for a worker already reaped).
        fn kill(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            WORKER_PID.store(0, Ordering::SeqCst);
        }

        /// The answer, or why there is none, within `WORKER_TIMEOUT` of the
        /// spawn. A worker still running then is killed.
        fn finish(mut self) -> (String, Result<EvalAnswer, String>) {
            let deadline = self.started + WORKER_TIMEOUT;
            let r = self.answer(deadline);
            if r.is_err() {
                self.kill();
            }
            (std::mem::take(&mut self.payload), r)
        }

        fn answer(&mut self, deadline: Instant) -> Result<EvalAnswer, String> {
            let timeout = || "no answer within 3 s".to_string();
            let left = deadline.saturating_duration_since(Instant::now());
            let out = match self.out.recv_timeout(left) {
                Ok(out) => out,
                Err(mpsc::RecvTimeoutError::Timeout) => return Err(timeout()),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err("its output was lost".into())
                }
            };
            // Stdout is closed; the exit follows at once.
            let status = loop {
                match self.child.try_wait() {
                    Ok(Some(st)) => break st,
                    Ok(None) if Instant::now() >= deadline => return Err(timeout()),
                    Ok(None) => std::thread::sleep(Duration::from_micros(200)),
                    Err(e) => return Err(format!("wait: {e}")),
                }
            };
            if !status.success() {
                return Err(status_text(status));
            }
            let out = out.map_err(|e| format!("read: {e}"))?;
            if out.len() > MAX_EVAL_BYTES {
                return Err("answer too large".into());
            }
            serde_json::from_slice(&out).map_err(|_| "unparsable answer".into())
        }
    }

    /// A worker is never left behind, also when the parent unwinds.
    impl Drop for Worker {
        fn drop(&mut self) {
            self.kill();
        }
    }

    /// Everything on `r`, up to one byte past `MAX_EVAL_BYTES`. Closing
    /// the pipe then makes a worker that writes more fail with EPIPE.
    fn read_bounded(r: ChildStdout) -> std::io::Result<Vec<u8>> {
        let mut out = Vec::new();
        r.take(MAX_EVAL_BYTES as u64 + 1).read_to_end(&mut out)?;
        Ok(out)
    }

    fn status_text(st: ExitStatus) -> String {
        match (st.signal(), st.code()) {
            (Some(sig), _) => format!("signal {sig}"),
            (None, Some(code)) => format!("exit status {code}"),
            (None, None) => st.to_string(),
        }
    }

    /// The masked record as the daemon takes it. `ts` is left out: the
    /// daemon stamps the time itself, and it sets `uid`, `user`, `host`,
    /// `seq` and `prev`.
    fn record(agent: &str, ctx: &HookContext, policy: &str, j: &Judged) -> Value {
        let project = ctx.cwd.clone().unwrap_or_else(|| {
            std::env::current_dir()
                .map(|d| d.display().to_string())
                .unwrap_or_default()
        });
        let tool = j
            .tool
            .as_deref()
            .or(ctx.tool.as_deref())
            .unwrap_or("unknown");
        let rec = Record::new(
            NewRecord {
                agent,
                project: &project,
                session: ctx.session.as_deref(),
                tool,
                input: &j.input,
                decision: j.decision,
                pack: j.pack.as_deref(),
                rule: j.rule.as_deref(),
                reason: j.reason.as_deref(),
                mode: "locked",
                policy: Some(policy),
                permission_mode: ctx.permission_mode.as_deref(),
            },
            env!("CARGO_PKG_VERSION"),
        );
        // After masking, so a cut never splits a secret out of its mask.
        let mut rec = rec;
        for f in [&mut rec.agent, &mut rec.project, &mut rec.tool] {
            cap(f);
        }
        for f in [&mut rec.session, &mut rec.reason, &mut rec.permission_mode]
            .into_iter()
            .flatten()
        {
            cap(f);
        }
        let mut v = serde_json::to_value(rec).unwrap_or(Value::Null);
        if let Some(m) = v.as_object_mut() {
            m.remove("ts");
            // A pack's own short name for the rule (`force-push`).
            if let Some(id) = &j.rule_id {
                m.insert("rule_id".into(), id.clone().into());
            }
        }
        v
    }

    /// The fallback when `fit` fails: `error_denied` with no input and
    /// nothing the agent controls but a short `agent`.
    fn minimal_record(agent: &str, policy: &str) -> Value {
        let agent = if json_str_len(agent) > 256 {
            cut_to(agent, 256)
        } else {
            agent.to_string()
        };
        let rec = Record::new(
            NewRecord {
                agent: &agent,
                project: "",
                session: None,
                tool: "unknown",
                input: "",
                decision: DecisionKind::ErrorDenied,
                pack: None,
                rule: None,
                reason: Some(TOO_LARGE),
                mode: "locked",
                policy: Some(policy),
                permission_mode: None,
            },
            env!("CARGO_PKG_VERSION"),
        );
        let mut v = serde_json::to_value(rec).unwrap_or(Value::Null);
        if let Some(m) = v.as_object_mut() {
            m.remove("ts");
        }
        v
    }

    /// Shrink the `SHRINKABLE` fields of `rec`, largest serialized first,
    /// until `rec` serializes to at most `MAX_RECORD_BYTES` (the daemon's
    /// limit, measured the same way). `false`: it still does not fit.
    fn fit(rec: &mut Value) -> bool {
        // Each round either fits or cuts a field down to the bare marker,
        // after which that field is no longer a candidate.
        for _ in 0..=SHRINKABLE.len() {
            let total = serde_json::to_vec(&*rec).map_or(usize::MAX, |b| b.len());
            if total <= MAX_RECORD_BYTES {
                return true;
            }
            let excess = total - MAX_RECORD_BYTES;
            let Some(m) = rec.as_object_mut() else {
                return false;
            };
            let largest = SHRINKABLE
                .iter()
                .filter_map(|k| Some((*k, json_str_len(m.get(*k)?.as_str()?))))
                .filter(|(_, len)| *len > json_str_len(TRUNCATED_MARK))
                .max_by_key(|(_, len)| *len);
            let Some((key, len)) = largest else {
                return false;
            };
            let cut = cut_to(m[key].as_str().unwrap_or(""), len.saturating_sub(excess));
            m.insert(key.into(), Value::String(cut));
        }
        false
    }

    /// The bytes `c` takes inside a JSON string as serde_json writes it.
    fn json_char_len(c: char) -> usize {
        match c {
            '"' | '\\' | '\u{8}' | '\u{c}' | '\n' | '\r' | '\t' => 2,
            c if (c as u32) < 0x20 => 6,
            c => c.len_utf8(),
        }
    }

    /// The bytes `s` takes inside a JSON string (without the quotes).
    fn json_str_len(s: &str) -> usize {
        s.chars().map(json_char_len).sum()
    }

    /// The longest prefix of `s` that, with the marker, takes at most
    /// `budget` bytes inside a JSON string (at least the marker).
    fn cut_to(s: &str, budget: usize) -> String {
        let room = budget.saturating_sub(json_str_len(TRUNCATED_MARK));
        let mut used = 0;
        let mut end = 0;
        for (i, c) in s.char_indices() {
            used += json_char_len(c);
            if used > room {
                break;
            }
            end = i + c.len_utf8();
        }
        format!("{}{TRUNCATED_MARK}", &s[..end])
    }

    /// Cut `s` to `MAX_FIELD_CHARS` characters plus a marker.
    fn cap(s: &mut String) {
        if let Some((cut, _)) = s.char_indices().nth(MAX_FIELD_CHARS) {
            s.truncate(cut);
            s.push_str(TRUNCATED_MARK);
        }
    }

    /// A deny by a rule `[guard] ask` lists (`pack/rule_id`).
    fn asked(cfg: &SystemConfig, j: &Judged) -> bool {
        if j.decision != DecisionKind::Deny || cfg.guard.ask.is_empty() {
            return false;
        }
        let (Some(pack), Some(id)) = (&j.pack, &j.rule_id) else {
            return false;
        };
        cfg.guard
            .ask
            .iter()
            .any(|a| saiife_policy::split_ask(a) == Some((pack.as_str(), id.as_str())))
    }

    /// The approval steps for an asked deny (spec §6.10.4), by `deadline`:
    /// a grant makes `rec` `approved` and the call allowed; otherwise a
    /// new request makes `rec` `ask` with its id and the call denied with
    /// the spec's message. `Err`: neither happened; `rec` and `j` are as
    /// they were.
    fn ask_step(
        client: &mut Client,
        (rec, j): (&mut Value, &mut Judged),
        (raw_sha256, project): (&str, &str),
        deadline: Instant,
    ) -> Result<(), ClientError> {
        let mut args = Map::new();
        args.insert("rec".into(), rec.clone());
        args.insert("raw_sha256".into(), raw_sha256.into());
        args.insert("project".into(), project.into());
        let ans = client.call(OP_GRANT_CONSUME, args.clone(), deadline)?;
        let (decision, approval, outcome, reason) = match ans.get("granted") {
            Some(Value::Bool(true)) => {
                let Some(a) = ans.get("approval").and_then(Value::as_u64) else {
                    return Err(ClientError::Protocol("a grant without its approval".into()));
                };
                (DecisionKind::Approved, a, Outcome::Allow, None)
            }
            Some(Value::Bool(false)) => {
                let ans = match client.call(OP_APPROVAL_CREATE, args, deadline) {
                    Err(ClientError::Refused { code, message })
                        if code == ErrorCode::Denied.as_str()
                            && message.starts_with("approvals_full") =>
                    {
                        set_reason(rec, TOO_MANY_PENDING)?;
                        j.outcome = Outcome::Deny(TOO_MANY_PENDING.into());
                        return Ok(());
                    }
                    other => other?,
                };
                let Some(id) = ans.get("request").and_then(Value::as_u64) else {
                    return Err(ClientError::Protocol("the answer has no request".into()));
                };
                let msg = format!(
                    "Needs approval: request #{id}. Run the same command again after it is approved."
                );
                let reason = format!("needs approval: request #{id}");
                (DecisionKind::Ask, id, Outcome::Deny(msg), Some(reason))
            }
            _ => return Err(ClientError::Protocol("the answer has no granted".into())),
        };
        let mut next = rec.clone();
        if let Some(m) = next.as_object_mut() {
            m.insert(
                "decision".into(),
                serde_json::to_value(decision).unwrap_or_default(),
            );
            m.insert("approval".into(), approval.into());
            if let Some(r) = reason {
                m.insert("reason".into(), r.into());
            }
        }
        // The reason changed: still within the limit (only ever cut).
        if !fit(&mut next) {
            return Err(ClientError::Protocol(TOO_LARGE.into()));
        }
        *rec = next;
        j.decision = decision;
        j.outcome = outcome;
        Ok(())
    }

    /// The hook's answer when the requester already has 20 pending requests.
    const TOO_MANY_PENDING: &str =
        "Too many pending approval requests (20); ask an approver to decide the open ones.";
    /// The reason of an ask-rule deny whose record does not show the exact
    /// command: what an approver saw would not be what runs.
    const CANNOT_APPROVE: &str =
        "cannot be approved: the command contains masked or overlong content";

    /// The reason when the project root or cwd cannot be resolved.
    const NO_PROJECT_ROOT: &str = "cannot be approved: project root unavailable";

    /// `rec`'s reason replaced; `Err` if it then does not fit.
    fn set_reason(rec: &mut Value, reason: &str) -> Result<(), ClientError> {
        set_field(rec, "reason", reason)
    }

    /// `rec`'s field `key` set to `value`; `Err` if it then does not fit.
    fn set_field(rec: &mut Value, key: &str, value: &str) -> Result<(), ClientError> {
        let mut next = rec.clone();
        if let Some(m) = next.as_object_mut() {
            m.insert(key.into(), value.into());
        }
        if !fit(&mut next) {
            return Err(ClientError::Protocol(TOO_LARGE.into()));
        }
        *rec = next;
        Ok(())
    }

    /// An ask-rule deny that cannot be approved: a plain deny saying why.
    fn cannot_approve(rec: &mut Value, j: &mut Judged, why: &str) {
        let pack = j.pack.clone().unwrap_or_else(|| "saiife".into());
        // Only ever shorter than the guard's reason plus a record that fit.
        let _ = set_reason(rec, why);
        j.outcome = Outcome::Deny(format!("BLOCKED by {pack}: {why}"));
    }

    /// Lowercase hex SHA-256 (of the exact command the worker judged:
    /// unmasked, uncut).
    fn sha256_hex(b: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        Sha256::digest(b)
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect()
    }

    /// `audit.append`, acknowledged with a `seq` by `deadline` (at most
    /// `ACK_TIMEOUT` from the first send).
    fn append(client: &mut Client, rec: Value, deadline: Instant) -> Result<(), ClientError> {
        let mut args = Map::new();
        args.insert("rec".into(), rec);
        let ans = client.call(OP_AUDIT_APPEND, args, deadline)?;
        match ans.get("seq").and_then(Value::as_u64) {
            Some(_) => Ok(()),
            None => Err(ClientError::Protocol("the ack has no seq".into())),
        }
    }

    fn describe(e: &ClientError) -> String {
        match e {
            ClientError::Owner { .. } => format!("socket owner check failed: {e}"),
            ClientError::Timeout => "no answer within the deadline".into(),
            other => other.to_string(),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        use saiife_policy::{Directory, FixedDirectory};

        const PASSWD: &str = "alice:x:1000:1000::/h:/bin/sh\n";
        const GROUP: &str = "alice:x:1000:\ndevs:x:2000:alice\n";
        const FILES: &str = "passwd: files\ngroup: files\n";

        fn envcfg(users: &str) -> SystemConfig {
            toml::from_str(&format!(
                "version = 2\n[[scope]]\nname = \"s\"\nusers = [{users}]\nenv = \"e\"\n\
                 [environments.e]\nguard.packs = [\"db.postgres\"]\n"
            ))
            .unwrap()
        }

        /// A directory that fails every group lookup and knows no one.
        struct Broken;
        impl Directory for Broken {
            fn user(&self, _: &str) -> Option<saiife_policy::UserEntry> {
                None
            }
            fn name_of(&self, _: u32) -> Option<String> {
                None
            }
            fn group(&self, _: &str) -> Option<saiife_policy::GroupEntry> {
                None
            }
            fn groups_of(&self, _: &str) -> Vec<String> {
                Vec::new()
            }
            fn try_groups_of(&self, _: &str) -> Result<Vec<String>, String> {
                Err("lookup failed".into())
            }
        }

        #[test]
        fn group_bound_env_is_applied_from_local_files() {
            let cfg = envcfg("\"group:devs\"");
            // Broken proves no process or NSS answer is needed.
            let (_, env) = hook_env(&cfg, 1000, (PASSWD, GROUP), Some(FILES), &Broken).unwrap();
            assert_eq!(env.as_deref(), Some("e"));
        }

        #[test]
        fn group_lookup_failure_denies() {
            let cfg = envcfg("\"group:devs\"");
            // A non-local group source sends the lookup to NSS, which fails.
            let nsswitch = "group: files sss\n";
            let e = hook_env(&cfg, 1000, (PASSWD, GROUP), Some(nsswitch), &Broken).unwrap_err();
            assert!(e.contains("group lookup failed"), "{e}");
            // No nsswitch.conf at all: also NSS.
            assert!(hook_env(&cfg, 1000, (PASSWD, GROUP), None, &Broken).is_err());
        }

        #[test]
        fn user_missing_from_passwd_falls_back_to_nss() {
            let cfg = envcfg("\"group:devs\"");
            let nss = FixedDirectory::from_text(PASSWD, GROUP);
            // Local files know nobody; NSS knows alice and her groups.
            let (_, env) = hook_env(&cfg, 1000, ("", ""), Some(FILES), &nss).unwrap();
            assert_eq!(env.as_deref(), Some("e"));
            // Neither knows uid 7: denied.
            assert!(hook_env(&cfg, 7, ("", ""), Some(FILES), &nss).is_err());
        }

        #[test]
        fn local_groups_follow_nsswitch() {
            assert!(groups_are_local(Some("group: files # c\n")));
            // compat (NIS +/- entries) and systemd (userdb, homed) can add
            // groups /etc/group does not list: those go to NSS.
            assert!(!groups_are_local(Some("group: files systemd\n")));
            assert!(!groups_are_local(Some("passwd: sss\ngroup: compat\n")));
            assert!(!groups_are_local(Some("group: files sss\n")));
            assert!(!groups_are_local(Some("passwd: files\n")));
            assert!(!groups_are_local(None));
        }

        fn len(v: &Value) -> usize {
            serde_json::to_vec(v).unwrap().len()
        }

        fn rec_with(input: &str, project: &str) -> Value {
            let mut v = minimal_record("claude", "sha256:00");
            v["input"] = input.into();
            v["project"] = project.into();
            v
        }

        #[test]
        fn json_char_len_matches_serde_json() {
            let mut chars: Vec<char> = (0u32..0x80).filter_map(char::from_u32).collect();
            chars.extend(['é', '…', '\u{2028}', '\u{FEFF}', '\u{1F600}', '\u{7F}']);
            for c in chars {
                let s = c.to_string();
                assert_eq!(
                    json_char_len(c),
                    serde_json::to_string(&s).unwrap().len() - 2,
                    "{c:?}"
                );
            }
        }

        #[test]
        fn exactly_at_the_limit_is_left_alone() {
            let mut v = rec_with("", "/p");
            let pad = MAX_RECORD_BYTES - len(&v);
            v["input"] = "\u{1}".repeat(pad / 6).into();
            v["input"] = format!("{}{}", v["input"].as_str().unwrap(), "x".repeat(pad % 6)).into();
            assert_eq!(len(&v), MAX_RECORD_BYTES);
            let before = v.clone();
            assert!(fit(&mut v));
            assert_eq!(v, before);
        }

        #[test]
        fn one_byte_over_is_cut_to_fit() {
            let mut v = rec_with("", "/p");
            let pad = MAX_RECORD_BYTES - len(&v) + 1;
            v["input"] = "x".repeat(pad).into();
            assert!(fit(&mut v));
            assert!(len(&v) <= MAX_RECORD_BYTES);
            let input = v["input"].as_str().unwrap();
            assert!(input.ends_with(TRUNCATED_MARK), "{input}");
            // Cut by no more than needed for the marker.
            assert!(len(&v) > MAX_RECORD_BYTES - 32, "{}", len(&v));
        }

        #[test]
        fn inflating_fields_are_cut_by_bytes() {
            let ctrl = "\u{1}".repeat(MAX_FIELD_CHARS);
            let wide = "\u{1F600}".repeat(MAX_FIELD_CHARS);
            let mut v = rec_with(&ctrl, &ctrl);
            v["session"] = ctrl.clone().into();
            v["reason"] = wide.clone().into();
            v["tool"] = wide.into();
            assert!(len(&v) > MAX_RECORD_BYTES);
            assert!(fit(&mut v));
            assert!(len(&v) <= MAX_RECORD_BYTES, "{}", len(&v));
            // Each cut field is a prefix plus the marker, on a char boundary.
            for k in ["input", "project", "session", "reason", "tool"] {
                let s = v[k].as_str().unwrap();
                if let Some(p) = s.strip_suffix(TRUNCATED_MARK) {
                    assert!(p.chars().all(|c| c == '\u{1}' || c == '\u{1F600}'), "{k}");
                }
            }
        }

        #[test]
        fn unshrinkable_record_does_not_fit() {
            let mut v = rec_with("", "/p");
            v["saiife"] = "v".repeat(MAX_RECORD_BYTES).into();
            assert!(!fit(&mut v));
        }

        #[test]
        fn minimal_record_is_error_denied_and_small() {
            let v = minimal_record(&"\u{1}".repeat(100_000), "sha256:00");
            assert_eq!(v["decision"], "error_denied");
            assert_eq!(v["reason"], TOO_LARGE);
            assert_eq!(v["input"], "");
            assert!(len(&v) < 1024, "{}", len(&v));
        }

        #[test]
        fn cut_to_respects_the_budget() {
            for budget in [0, 5, 14, 15, 20, 100] {
                let c = cut_to(&"\u{1}é".repeat(50), budget);
                assert!(
                    json_str_len(&c) <= budget.max(json_str_len(TRUNCATED_MARK)),
                    "{budget}: {c:?}"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_value_reads_both_spellings() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let args = a(&["check", "--system-config", "/x.toml"]);
        assert_eq!(flag_value(&args, "--system-config"), Some("/x.toml"));
        let args = a(&["check", "--system-config=/y.toml"]);
        assert_eq!(flag_value(&args, "--system-config"), Some("/y.toml"));
        let args = a(&["check", "--system-configs=/z"]);
        assert_eq!(flag_value(&args, "--system-config"), None);
    }
}
