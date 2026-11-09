//! `saiife check --managed`: the locked-mode hook (spec §6.1.2). FAIL
//! CLOSED on every error.
//!
//! For Codex and Gemini CLI the guard runs in a worker child (`saiife
//! __eval`), so an abort, a signal or a stack overflow in the engine becomes
//! a clean deny: a dead hook would let their call run. Claude Code's calls
//! are judged in this process, on a thread, with the worker's environment
//! (plan 21): a hang or a panic there is a clean deny, and a crash kills the
//! hook, which Claude Code's `onFailure: "block"` blocks and the daemon
//! records as `no_verdict`. That saves starting a process per call. The
//! masked record goes to the daemon (`audit.append`); the call is allowed
//! only once the daemon has acknowledged it. Every error ends in exit 2, a
//! reason on stderr and, when the daemon can be reached, an `error_denied`
//! record. When it cannot, the reason goes to stderr only: nobody could
//! write the record.
//!
//! The hook connects and says `hook.begin` before it reads its input, and
//! binds the call's key (`hook.bind`) while the worker runs (plan 20): the
//! daemon records a hook that ends without its `audit.append`. The bind
//! names the tool; the append names the key beside the record
//! (`tool_use_id`, `input_sha256`, never written), so it settles that key
//! only. A connection made again after an error
//! registers and binds the same key first.
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
pub const SYSTEM_CONFIG: &str = crate::paths::DEV_SYSTEM_CONFIG;

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

/// A managed hook call that must be denied for `why` before anything is judged. It is
/// recorded when the daemon can be reached.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn run_denied(agent: &str, system_config: &Path, event: Option<&str>, why: String) -> ExitCode {
    guarded(|| imp::run_with(agent, system_config, event, Some(why.clone())))
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
    let run = || match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(code) => code,
        Err(_) => blocked("saiife crashed"),
    };
    // Debug builds with SAIIFE_HOOK_TIMING=1 only: each step's time on stderr.
    let code = crate::hook_timing::time("total", run);
    crate::hook_timing::flush();
    code
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

#[cfg(not(any(unix, windows)))]
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
        crate::warn(saiife_system::NOT_SUPPORTED_OS);
        ExitCode::from(2)
    }
}

#[cfg(unix)]
pub(crate) use imp::{hook_env, uid_env};
/// What the service's re-judge pool shares with the hook (plan 21).
#[cfg(any(unix, windows))]
pub(crate) use imp::{load_locked, locked_paths, policy_with, Applied, ScopeEnv};

#[cfg(any(unix, windows))]
mod imp {
    use super::*;

    use std::ffi::OsString;
    use std::io::{BufWriter, Read, Write};
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;
    use std::path::PathBuf;
    use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
    use std::sync::mpsc;
    use std::sync::{Mutex, MutexGuard, TryLockError};
    use std::time::{Duration, Instant};

    use saiife_agents::config::{find_project_root, read_config_bytes, CONFIG_REL};
    use saiife_audit::{DecisionKind, NewRecord, Record};
    #[cfg(unix)]
    use saiife_ipc::client::{system_entry, system_uid};
    use saiife_ipc::client::{Client, ClientError};
    use saiife_ipc::hookkey::{hook_key_bounded, HookKey};
    use saiife_ipc::msg::{
        ErrorCode, MAX_RECORD_BYTES, OP_APPROVAL_CREATE, OP_AUDIT_APPEND, OP_GRANT_CONSUME,
        OP_HOOK_BEGIN, OP_HOOK_BIND,
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
    /// The longest `tool` that `hook.bind` takes (the daemon's limit).
    const MAX_BIND_TOOL: usize = 64;
    /// The longest `tool_use_id` a record shows, in bytes (the daemon's
    /// `hook.bind` limit).
    const MAX_RECORDED_ID: usize = 256;
    /// The longest session that `hook.bind` takes, in bytes (the daemon's
    /// `sessions::MAX_SESSION_ID`).
    const MAX_BIND_SESSION: usize = 128;
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

    /// The running worker, for the watchdog: Windows can stop a child through its
    /// handle only, and the lock is held for a moment at a time, never across a wait.
    static WORKER: Mutex<Option<Child>> = Mutex::new(None);

    fn worker_slot() -> MutexGuard<'static, Option<Child>> {
        WORKER.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The job every worker runs in on Windows: it kills them when its handle closes, so
    /// a worker never outlives this process, whether the watchdog exits while the slot is
    /// busy or the hook crashes.
    #[cfg(windows)]
    static JOB: std::sync::OnceLock<saiife_win::ffi::job::KillOnClose> = std::sync::OnceLock::new();

    /// Puts `child` in [`JOB`], made at the first worker.
    #[cfg(windows)]
    fn join_job(child: &Child) -> std::io::Result<()> {
        let job = match JOB.get() {
            Some(job) => job,
            None => {
                let made = saiife_win::ffi::job::KillOnClose::new()?;
                JOB.get_or_init(|| made)
            }
        };
        job.assign(child)
    }

    /// Writes to stderr without its lock: a main thread blocked while holding that lock
    /// cannot stop the watchdog.
    #[cfg(unix)]
    fn bare_stderr() -> impl FnOnce(&[u8]) {
        |msg| {
            use std::os::fd::AsFd;
            let _ = rustix::io::write(std::io::stderr().as_fd(), msg);
        }
    }

    /// Writes to stderr without its lock, through a copy of the handle taken now. No
    /// stderr to copy costs the message only.
    #[cfg(windows)]
    fn bare_stderr() -> impl FnOnce(&[u8]) {
        use std::os::windows::io::AsHandle;
        let copy = std::io::stderr().as_handle().try_clone_to_owned().ok();
        move |msg| {
            if let Some(handle) = copy {
                let _ = std::fs::File::from(handle).write_all(msg);
            }
        }
    }

    /// After `OVERALL_TIMEOUT`, kill the worker if one runs, say why on
    /// stderr and exit 2, wherever the main thread is stuck. `false`: the
    /// thread could not be started (`RLIMIT_NPROC`, `pids.max`).
    pub fn start_watchdog() -> bool {
        #[cfg(debug_assertions)]
        if eval::fault() == "watchdog_spawn" {
            return false;
        }
        let say = bare_stderr();
        std::thread::Builder::new()
            .name("saiife-watchdog".into())
            .spawn(move || {
                std::thread::sleep(OVERALL_TIMEOUT);
                // Busy: the main thread holds it to look at the worker for a moment.
                // The process is about to exit either way, so never wait for it. On
                // Windows the exit closes the worker's job, which kills it then.
                let child = match WORKER.try_lock() {
                    Ok(mut g) => g.take(),
                    Err(TryLockError::Poisoned(p)) => p.into_inner().take(),
                    Err(TryLockError::WouldBlock) => None,
                };
                if let Some(mut child) = child {
                    let _ = child.kill();
                }
                say(b"saiife: BLOCKED (fail closed): saiife took too long\n");
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
        use crate::hook_timing::time;
        // 1. The system policy. Without it there is no daemon to tell.
        let cfg = match time("config", || load_locked(config)) {
            Ok(c) => c,
            Err(e) => {
                let input = read_stdin();
                let why = format!("saiife policy could not be loaded: {e}");
                record_failed_load(agent, event, &input, &why);
                return blocked(&why);
            }
        };
        let Some(daemon_uid) = daemon_owner(&cfg) else {
            drain_stdin();
            return blocked(&format!(
                "the saiife daemon user {:?} does not exist",
                cfg.daemon.user
            ));
        };

        // The worker process starts now, so that its start (a large part of
        // the call on Windows) overlaps the steps below. It judges nothing
        // until it is sent the request, after the begin. A call denied before
        // it is judged (bad arguments) starts none, and neither does one
        // judged in this process (Claude Code).
        let early = match forced {
            None if !in_process(agent) => Some(time("worker.start", Worker::start)),
            _ => None,
        };

        // 2. Register with the daemon (plan 20) while 3. the payload is read,
        // bounded: a helper thread connects, says hello and sends
        // `hook.begin`, and nothing looks at the payload until it is done, so
        // the daemon has the begin before the hook acts on its input. From
        // the begin on, a hook that ends without a verdict is recorded.
        let (begun, input) = time("begin_and_stdin", || {
            begin_while_reading(&cfg, daemon_uid, agent, event)
        });
        let mut client = match begun {
            Ok(c) => c,
            // The daemon cannot be reached: stderr only.
            Err(reason) => return blocked(&reason),
        };
        #[cfg(debug_assertions)]
        if eval::fault() == "parent_hang" {
            std::thread::sleep(Duration::from_secs(20));
        }

        let mut ctx = match &input {
            Ok(buf) => context_from_hook_json_bounded(buf, PARSE_MAX_BYTES),
            Err(_) => HookContext::default(),
        };
        if event == Some(EVENT_CONFIG_CHANGE) {
            // A settings change is no tool call; its record says what it is.
            ctx.tool = Some("ConfigChange".into());
        }
        // A panic from here until the record is built still gets an
        // `error_denied` record.
        let mut policy: Option<String> = None;
        // The canonical cwd and project root, for a grant's scope.
        let mut key_project: Option<(String, String)> = None;
        // The call's key, bound while the worker runs.
        let mut key: Option<HookKey> = None;
        let judged = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            judge_call(
                (&cfg, config),
                (agent, event),
                &ctx,
                (input, early),
                forced,
                &mut client,
                (&mut policy, &mut key_project, &mut key),
            )
        }));
        let judged =
            judged.unwrap_or_else(|_| Judged::error(String::new(), "saiife crashed".into()));
        // A bind that broke the connection must not cost the approval step
        // or the record.
        if client.is_poisoned() {
            match connect_bound(
                &cfg,
                daemon_uid,
                (agent, event),
                key.as_ref(),
                ctx.tool.as_deref(),
            ) {
                Ok(c) => client = c,
                Err(e) => {
                    return blocked(&format!("the audit daemon did not record this call ({e})"))
                }
            }
        }

        // 6. The record, within the daemon's size limit, and its ack.
        let policy = policy.unwrap_or_else(|| "unavailable".into());
        let mut judged = judged;
        let mut rec = time("record", || {
            let mut rec = record(agent, &ctx, &policy, &judged, key.as_ref());
            if !fit(&mut rec) {
                // Fail closed: the record says error_denied, so must the call.
                judged = Judged::error(String::new(), TOO_LARGE.into());
                rec = minimal_record(agent, &policy);
            }
            rec
        });
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
                    rec = record(agent, &ctx, &policy, &judged, key.as_ref());
                    if !fit(&mut rec) {
                        judged = Judged::error(String::new(), TOO_LARGE.into());
                        rec = minimal_record(agent, &policy);
                    }
                }
            }
        }
        // An approval step that broke the connection (a timeout) must not
        // also cost the record: one fresh connection, with its own
        // deadlines, for the append, registered and bound as the first was.
        // Its error, if any, is what is shown.
        let mut deadline = deadline;
        if client.is_poisoned() {
            match connect_bound(
                &cfg,
                daemon_uid,
                (agent, event),
                key.as_ref(),
                ctx.tool.as_deref(),
            ) {
                Ok(c) => {
                    client = c;
                    deadline = Instant::now() + ACK_TIMEOUT;
                }
                Err(e) => {
                    return blocked(&format!("the audit daemon did not record this call ({e})"))
                }
            }
        }
        if let Err(e) = time("append", || {
            append(&mut client, rec, key.as_ref(), deadline)
        }) {
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

        // 7. The answer.
        match judged.outcome {
            Outcome::Allow => ExitCode::SUCCESS,
            Outcome::Deny(msg) => {
                let _ = writeln!(std::io::stderr(), "{msg}");
                ExitCode::from(2)
            }
            Outcome::Error(reason) => blocked(&reason),
        }
    }

    /// The record of a call denied because the system policy would not load.
    #[cfg_attr(not(windows), allow(dead_code))]
    fn failed_load_record(
        agent: &str,
        event: Option<&str>,
        input: &Result<String, String>,
        why: &str,
    ) -> Value {
        let mut ctx = match input {
            Ok(buf) => context_from_hook_json_bounded(buf, PARSE_MAX_BYTES),
            Err(_) => HookContext::default(),
        };
        if event == Some(EVENT_CONFIG_CHANGE) {
            ctx.tool = Some("ConfigChange".into());
        }
        let shown = input.as_deref().map(recorded_input).unwrap_or_default();
        let judged = Judged::error(shown, why.to_string());
        let mut rec = record(agent, &ctx, "unavailable", &judged, None);
        if !fit(&mut rec) {
            rec = minimal_record(agent, "unavailable");
        }
        rec
    }

    /// On Windows the control pipe and its owner come from the layout, never from the
    /// config (W11), so a call denied over a config that fails its check can still reach
    /// the audit log. The deny stands whether or not this gets through.
    #[cfg(windows)]
    fn record_failed_load(
        agent: &str,
        event: Option<&str>,
        input: &Result<String, String>,
        why: &str,
    ) {
        let connect = Instant::now() + CONNECT_TIMEOUT;
        let Ok(mut client) = crate::broker::system_client(Path::new(""), 0, connect) else {
            return;
        };
        if client.hello_answer().get("mode").and_then(Value::as_str) != Some("locked") {
            return;
        }
        let rec = failed_load_record(agent, event, input, why);
        let _ = append(&mut client, rec, None, Instant::now() + ACK_TIMEOUT);
    }

    /// Off Windows the socket's dir and owner are in the config that failed to load.
    #[cfg(not(windows))]
    fn record_failed_load(
        _agent: &str,
        _event: Option<&str>,
        _input: &Result<String, String>,
        _why: &str,
    ) {
    }

    /// Steps 4 and 5: the project, the policy and the worker, and the
    /// call's key, bound on `client` while the worker runs (`key` is set to
    /// it; a payload that gives no key binds nothing). `cfg` was loaded from
    /// `config`. An MCP tool whose server `[guard.mcp]` does not list is
    /// denied without a worker. `early`: the worker started before the
    /// payload was read, which is sent the request, or killed when nothing
    /// is to be judged; without one a worker is started here. Claude Code's
    /// call is judged in this process instead, after its key is bound, so a
    /// crash there leaves the bound `no_verdict` record.
    fn judge_call(
        (cfg, config): (&SystemConfig, &Path),
        (agent, event): (&str, Option<&str>),
        ctx: &HookContext,
        (input, early): (Result<String, String>, Option<Result<Idle, std::io::Error>>),
        forced: Option<String>,
        client: &mut Client,
        (policy, key_project, key): (
            &mut Option<String>,
            &mut Option<(String, String)>,
            &mut Option<HookKey>,
        ),
    ) -> Judged {
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
        let resolved = crate::hook_timing::time("policy", || policy_for(cfg, start.as_deref()));
        let (packs, unresolved) = match resolved {
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
        // A worker judges the call, or (Claude Code) this process does, once
        // the key is bound.
        let (worker, here, unspawned) = match (&failed, &mcp_judged, input) {
            (None, None, Ok(payload)) => {
                let req = EvalRequest {
                    payload,
                    // A settings change is judged without packs.
                    packs: if event.is_some() { Vec::new() } else { packs },
                    budget_ms: cfg.guard.budget_ms,
                    locked: Some(locked_paths(cfg, config)),
                    event: event.map(str::to_string),
                    ask: cfg.guard.ask.clone(),
                    agent: Some(agent.to_string()),
                    view: eval::View::Host,
                    vars: None,
                };
                if in_process(agent) {
                    drop(early);
                    (None, Some(req), None)
                } else {
                    let started = match early {
                        Some(w) => w,
                        None => crate::hook_timing::time("worker.start", Worker::start),
                    };
                    let sent = match started {
                        Ok(w) => Ok(w.send(req)),
                        Err(e) => Err((req.payload, e)),
                    };
                    (Some(sent), None, None)
                }
            }
            (_, _, input) => {
                // Nothing to judge: an early worker is killed and reaped.
                drop(early);
                (None, None, input.ok())
            }
        };

        // While the worker runs: the record's masks are compiled on a thread
        // (the record needs them once the worker answers; whoever comes
        // first compiles them, the other waits), the key, and its bind. A
        // bind error leaves the call as it is; one that broke the connection
        // is mended by the caller.
        let _ = std::thread::Builder::new()
            .name("saiife-masks".into())
            .spawn(|| crate::hook_timing::time("masks", || saiife_audit::mask::mask("")));
        let payload = match (&worker, &here, &unspawned) {
            (Some(Ok(w)), _, _) => Some(w.payload.as_str()),
            (Some(Err((p, _))), _, _) => Some(p.as_str()),
            (None, Some(req), _) => Some(req.payload.as_str()),
            (None, None, p) => p.as_deref(),
        };
        *key = crate::hook_timing::time("key", || {
            payload.and_then(|p| hook_key_bounded(agent, p, PARSE_MAX_BYTES).ok())
        });
        crate::hook_timing::time("bind", || {
            bind(
                client,
                key.as_ref(),
                ctx.tool.as_deref(),
                Instant::now() + ACK_TIMEOUT,
            )
        });

        if let Some(reason) = failed {
            return Judged::error(String::new(), reason);
        }
        if let Some(judged) = mcp_judged {
            return judged;
        }
        let (payload, answer) = match (worker, here) {
            (Some(Ok(w)), _) => crate::hook_timing::time("worker.wait", || w.finish()),
            (Some(Err((payload, e))), _) => (payload, Err(format!("could not start: {e}"))),
            (None, Some(req)) => {
                let (payload, answer) = judge_here(req);
                return match answer {
                    Ok(a) => Judged::from_answer(a),
                    Err(why) => Judged::error(
                        recorded_input(&payload),
                        format!("{JUDGE_HERE_FAILED} ({why})"),
                    ),
                };
            }
            // A worker is spawned whenever nothing failed; deny regardless.
            (None, None) => (String::new(), Err("not started".into())),
        };
        match answer {
            Ok(a) => Judged::from_answer(a),
            Err(why) => Judged::error(
                recorded_input(&payload),
                format!("guard worker failed ({why})"),
            ),
        }
    }

    /// Whether `agent`'s calls are judged in this process, not in a worker (plan 21,
    /// option B): Claude Code's only. A crash here kills the hook, which Claude Code's
    /// `onFailure: "block"` turns into a block and the daemon records as `no_verdict`.
    /// Codex and Gemini CLI keep the worker: for them a dead hook lets the call run
    /// (§9.3).
    fn in_process(agent: &str) -> bool {
        agent == "claude"
    }

    /// The reason's start when the judgment in this process gave no answer.
    const JUDGE_HERE_FAILED: &str = "the guard failed in the hook";

    /// The stack of the thread that judges in this process: the engine's recursion
    /// gets at least what it has on a worker's main thread.
    const JUDGE_STACK: usize = 8 << 20;

    /// The name of the thread that judges in this process.
    const JUDGE_THREAD: &str = "saiife-judge";

    /// `req` judged in this process, on its own thread, with the environment a worker
    /// would get (never the agent's): the answer, or why there is none, within
    /// `WORKER_TIMEOUT` of the start. A panic there is caught; a judgment still running
    /// then is left behind, and ends with the process.
    fn judge_here(req: EvalRequest) -> (String, Result<EvalAnswer, String>) {
        use crate::hook_timing::time;
        let payload = req.payload.clone();
        let env = match time("judge.env", account_env) {
            Ok(env) => env,
            Err(e) => return (payload, Err(format!("could not start: {e}"))),
        };
        // A panic of the judgment is told by the deny alone: its report would
        // stand before the deny on stderr, which Claude Code shows. Others
        // keep the default report.
        let report = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if std::thread::current().name() != Some(JUDGE_THREAD) {
                report(info);
            }
        }));
        let started = Instant::now();
        let (tx, rx) = mpsc::channel();
        let spawned = time("judge.start", || {
            std::thread::Builder::new()
                .name(JUDGE_THREAD.into())
                .stack_size(JUDGE_STACK)
                .spawn(move || {
                    let judged = std::panic::catch_unwind(|| {
                        time("judge.run", || {
                            #[cfg(debug_assertions)]
                            judge_here_fault();
                            eval::answer(&req, Some(&env))
                        })
                    });
                    let _ = tx.send(judged.map_err(|_| ()));
                })
        });
        if let Err(e) = spawned {
            return (payload, Err(format!("could not start: {e}")));
        }
        let left = (started + WORKER_TIMEOUT).saturating_duration_since(Instant::now());
        let answer = match time("judge.wait", || rx.recv_timeout(left)) {
            Ok(Ok(a)) => Ok(a),
            Ok(Err(())) => Err("it panicked".into()),
            Err(mpsc::RecvTimeoutError::Timeout) => Err("no answer within 3 s".into()),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err("it is gone".into()),
        };
        (payload, answer)
    }

    /// Test seam, debug builds only: `SAIIFE_EVAL_FAULT=hang|panic|abort|segv`
    /// makes the judgment in this process hang, panic, or kill the hook by
    /// SIGABRT or (Unix) SIGSEGV. The worker's other faults are its own and are
    /// ignored here.
    #[cfg(debug_assertions)]
    fn judge_here_fault() {
        let fault = eval::fault();
        // No core dump for the owner's crash reporter (as the worker's seam).
        #[cfg(target_os = "linux")]
        if matches!(fault.as_str(), "abort" | "segv") {
            let _ = rustix::process::set_dumpable_behavior(
                rustix::process::DumpableBehavior::NotDumpable,
            );
        }
        match fault.as_str() {
            "hang" => std::thread::sleep(Duration::from_secs(10)),
            "panic" => panic!("SAIIFE_EVAL_FAULT=panic"),
            "abort" => std::process::abort(),
            #[cfg(unix)]
            "segv" => eval::segv(),
            _ => {}
        }
    }

    /// The `guard.mcp` judgement of this call without a worker, if its tool
    /// is an MCP tool: a deny when `[guard.mcp] allow_servers` does not list
    /// its server, an allow for the brokered server `saiife` on Claude Code
    /// (only there is its command pinned; elsewhere it needs listing).
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
        match eval::mcp_check_pinned(
            agent,
            tool,
            &identity,
            &cfg.guard.mcp.allow_servers,
            &claude_pin_ok,
        ) {
            McpCheck::NotMcp | McpCheck::Allowed => None,
            McpCheck::Brokered => Some(Judged::mcp_brokered(recorded_input(payload))),
            McpCheck::Denied(s) => Some(Judged::mcp_denied(format!(
                "MCP server {s} is not in [guard.mcp] allow_servers"
            ))),
            McpCheck::Unknown => Some(Judged::mcp_denied("MCP server unknown on Gemini".into())),
        }
    }

    /// Debug builds only: the Claude Code MCP drop-in to read instead of
    /// the real one, owned by the test's own uid (tests never read /etc).
    #[cfg(debug_assertions)]
    pub const CLAUDE_MCP_SEAM: &str = "SAIIFE_TEST_CLAUDE_MCP_DROPIN";

    /// Whether Claude Code's managed MCP drop-in pins the `saiife` command
    /// (final review I3): read only for a `saiife` tool call on Claude.
    fn claude_pin_ok() -> bool {
        #[cfg(debug_assertions)]
        if let Some(p) = std::env::var_os(CLAUDE_MCP_SEAM) {
            #[cfg(unix)]
            let owner = rustix::process::getuid().as_raw();
            #[cfg(windows)]
            let owner = 0;
            return eval::claude_pin_ok(Path::new(&p), owner);
        }
        #[cfg(unix)]
        let real = PathBuf::from(saiife_system::layout::CLAUDE_MCP);
        #[cfg(windows)]
        let real = saiife_system::Layout::system().at(saiife_system::layout::CLAUDE_MCP);
        eval::claude_pin_ok(&real, 0)
    }

    /// What the record names when the worker gave no answer: the command
    /// or the paths, as the worker would have.
    fn recorded_input(payload: &str) -> String {
        match eval::plan(payload, None) {
            Plan::Shell { command, .. } | Plan::TooLarge { command, .. } => command,
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
    pub(crate) fn locked_paths(cfg: &SystemConfig, config: &Path) -> LockedPaths {
        LockedPaths {
            etc: config.parent().unwrap_or(Path::new("/")).to_path_buf(),
            audit_dir: cfg.audit.dir.clone(),
            socket_dir: cfg.daemon.socket_dir.clone(),
        }
    }

    /// `load_system`, which must say `locked = true`. A config that fails Windows' DACL
    /// check is no policy: the call is denied, whoever wrote the file.
    pub(crate) fn load_locked(config: &Path) -> Result<SystemConfig, String> {
        crate::hook_timing::time("config.trust", || {
            crate::win_locked::check_trusted(&crate::win_locked::system_file_trust, config)
        })?;
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
        policy_with(cfg, start, &OwnEnv)
    }

    /// A config with the scope environment of some user applied, and its name.
    pub(crate) type Applied<'a> = (std::borrow::Cow<'a, SystemConfig>, Option<String>);

    /// Whose scope environment a policy is resolved for: this process's user
    /// (the hook), or the asking user (the service's re-judgment, plan 21).
    pub(crate) trait ScopeEnv {
        fn applied<'a>(&self, cfg: &'a SystemConfig) -> Result<Applied<'a>, String>;
    }

    /// This process's user.
    struct OwnEnv;

    impl ScopeEnv for OwnEnv {
        fn applied<'a>(&self, cfg: &'a SystemConfig) -> Result<Applied<'a>, String> {
            own_env(cfg)
        }
    }

    /// [`policy_for`] with the scope environment of `who`. `start: None` reads
    /// no project config.
    pub(crate) fn policy_with(
        cfg: &SystemConfig,
        start: Option<&Path>,
        who: &dyn ScopeEnv,
    ) -> Result<(Vec<String>, String), String> {
        // The caller's scope environment adds its packs and is part of the
        // hash. Nothing is read or spawned unless some scope binds one; an
        // environment that cannot be resolved denies the call.
        let (cfg_env, env) = if cfg.scope.iter().any(|s| s.env.is_some()) {
            who.applied(cfg)?
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
        let headers = crate::hook_timing::time("policy.catalog", || Catalog::builtin().headers());
        let catalog: Vec<PackInfo> = headers
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

    /// The running user's scope environment. macOS keeps its accounts in Directory
    /// Services, not in /etc/passwd and /etc/group: `nss` answers there.
    #[cfg(unix)]
    fn own_env(
        cfg: &SystemConfig,
    ) -> Result<(std::borrow::Cow<'_, SystemConfig>, Option<String>), String> {
        uid_env(cfg, rustix::process::getuid().as_raw())
    }

    /// The scope environment of `uid`, from this host's account files (and
    /// `nss` where they are not the whole answer), as the daemon finds it.
    #[cfg(unix)]
    pub(crate) fn uid_env(cfg: &SystemConfig, uid: u32) -> Result<Applied<'_>, String> {
        let linux = cfg!(target_os = "linux");
        let read = |p: &str| {
            linux
                .then(|| std::fs::read_to_string(p).ok())
                .flatten()
                .unwrap_or_default()
        };
        let nsswitch = read("/etc/nsswitch.conf");
        let nsswitch = (!nsswitch.is_empty()).then_some(nsswitch);
        hook_env(
            cfg,
            uid,
            (&read("/etc/passwd"), &read("/etc/group")),
            nsswitch.as_deref(),
            &saiife_policy::Getent,
        )
    }

    /// The running user's scope environment, by the name the daemon has for this SID. A
    /// failed lookup denies.
    #[cfg(windows)]
    fn own_env(
        cfg: &SystemConfig,
    ) -> Result<(std::borrow::Cow<'_, SystemConfig>, Option<String>), String> {
        let name = crate::win_locked::own_account_name()
            .ok_or("cannot tell which user this is: no environment")?;
        applied_for(cfg, &saiife_policy::WinDirectory::system(), &name)
            .map_err(|e| format!("environment: {e}"))
    }

    /// Whom the daemon's endpoint must belong to. On Windows the pipe's owner is the
    /// service's SID whatever the config says, so there is nothing to look up.
    #[cfg(unix)]
    fn daemon_owner(cfg: &SystemConfig) -> Option<u32> {
        system_uid(&cfg.daemon.user)
    }

    #[cfg(windows)]
    fn daemon_owner(_cfg: &SystemConfig) -> Option<u32> {
        Some(0)
    }

    /// Whether `nsswitch.conf` takes groups from `files` alone (not compat or
    /// systemd, which can add groups `/etc/group` lacks), so
    /// `/etc/group` is the whole answer and no process needs to run.
    #[cfg(unix)]
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
    #[cfg(unix)]
    pub(crate) fn hook_env<'a>(
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

    /// The worker child, started and not yet sent its request: it waits on
    /// its stdin and has judged nothing. The child itself is in [`WORKER`].
    /// Dropped unsent, it is killed and reaped.
    struct Idle {
        /// `None` once sent.
        stdin: Option<ChildStdin>,
        /// The reader thread's result: everything on the worker's stdout.
        /// `None` once sent.
        out: Option<mpsc::Receiver<std::io::Result<Vec<u8>>>>,
    }

    /// The worker child, sent its request: the child itself is in [`WORKER`].
    struct Worker {
        /// When the request was handed to the writer thread.
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
        /// from that home. It is started before the payload is known
        /// (creating a process is slow on Windows) and judges nothing until
        /// [`Idle::send`]. The answer is read on a thread, so a worker that
        /// never writes cannot outlast the deadline.
        fn start() -> Result<Idle, std::io::Error> {
            // Test seam: no worker can be started (so a call judged without one shows).
            #[cfg(debug_assertions)]
            if eval::fault() == "worker_spawn" {
                return Err(std::io::Error::other("SAIIFE_EVAL_FAULT=worker_spawn"));
            }
            let exe = std::env::current_exe()?;
            let mut cmd = Command::new(exe);
            cmd.arg("__eval").env_clear();
            crate::hook_timing::time("worker.env", || worker_account(&mut cmd))?;
            cmd.stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null());
            #[cfg(debug_assertions)]
            if let Some(f) = std::env::var_os("SAIIFE_EVAL_FAULT") {
                cmd.env("SAIIFE_EVAL_FAULT", f);
            }
            // SAIIFE_HOOK_TIMING (debug builds only): the worker says what it
            // took, on this process's stderr.
            if crate::hook_timing::on() {
                cmd.env(crate::hook_timing::VAR, "1")
                    .env(
                        crate::hook_timing::SPAWNED_VAR,
                        crate::hook_timing::now_us().to_string(),
                    )
                    .stderr(Stdio::inherit());
            }
            let mut child = crate::hook_timing::time("worker.create", || cmd.spawn())?;
            // A worker that cannot be tied to this process is not run: it could outlive
            // the hook. Joined before it is sent the request, so it has judged nothing yet.
            #[cfg(windows)]
            if let Err(e) = crate::hook_timing::time("worker.job", || join_job(&child)) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
            let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
                let _ = child.kill();
                let _ = child.wait();
                return Err(std::io::Error::other("no pipes"));
            };
            *worker_slot() = Some(child);
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(read_bounded(stdout));
            });
            Ok(Idle {
                stdin: Some(stdin),
                out: Some(rx),
            })
        }

        /// Kill and reap (a no-op for a worker already reaped).
        fn kill(&mut self) {
            let child = worker_slot().take();
            if let Some(mut child) = child {
                let _ = child.kill();
                let _ = child.wait();
            }
        }

        /// The answer, or why there is none, within `WORKER_TIMEOUT` of the
        /// request. A worker still running then is killed.
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
            let reaping = Instant::now();
            let status = loop {
                let looked = match worker_slot().as_mut() {
                    Some(child) => child.try_wait(),
                    None => return Err("it is gone".into()),
                };
                match looked {
                    Ok(Some(st)) => break st,
                    Ok(None) if Instant::now() >= deadline => return Err(timeout()),
                    Ok(None) => std::thread::sleep(Duration::from_micros(200)),
                    Err(e) => return Err(format!("wait: {e}")),
                }
            };
            crate::hook_timing::add("worker.reap", reaping.elapsed());
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

    impl Idle {
        /// Hands `req` to a writer thread, so a worker that never reads cannot
        /// outlast the deadline, which starts now.
        fn send(mut self, req: EvalRequest) -> Worker {
            // The parent keeps a copy for the record; the request owns the
            // one the writer thread sends.
            let payload = req.payload.clone();
            if let Some(stdin) = self.stdin.take() {
                std::thread::spawn(move || {
                    let mut w = BufWriter::new(stdin);
                    // A worker that dies early closes the pipe: EPIPE, ignored.
                    let _ = serde_json::to_writer(&mut w, &req);
                    let _ = w.flush();
                });
            }
            // Always there: only `send` takes it, and it takes `self`. A lost
            // one would read as "its output was lost": a deny.
            let out = self.out.take().unwrap_or_else(|| mpsc::channel().1);
            Worker {
                started: Instant::now(),
                payload,
                out,
            }
        }
    }

    /// Unsent, the worker has judged nothing: it is killed and reaped.
    impl Drop for Idle {
        fn drop(&mut self) {
            if self.out.is_some() {
                let child = worker_slot().take();
                if let Some(mut child) = child {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
    }

    /// Everything on `r`, up to one byte past `MAX_EVAL_BYTES`. Closing
    /// the pipe then makes a worker that writes more fail with EPIPE.
    fn read_bounded(r: ChildStdout) -> std::io::Result<Vec<u8>> {
        let mut out = Vec::new();
        r.take(MAX_EVAL_BYTES as u64 + 1).read_to_end(&mut out)?;
        Ok(out)
    }

    /// The worker's environment on Linux and macOS: only `HOME` and `USER` from the entry
    /// of this process's real uid. See [`Worker::start`].
    fn worker_account(cmd: &mut Command) -> std::io::Result<()> {
        cmd.envs(account_env()?);
        Ok(())
    }

    /// The whole environment of a worker, and of a judgment in this process. On Linux
    /// and macOS: only `HOME` and `USER` from the entry of this process's real uid,
    /// `PATH=/usr/bin:/bin` and `LANG=C`.
    #[cfg(unix)]
    fn account_env() -> std::io::Result<Vec<(OsString, OsString)>> {
        let uid = rustix::process::getuid().as_raw();
        let Some(account) = system_entry(uid) else {
            return Err(std::io::Error::other(format!(
                "no /etc/passwd entry for uid {uid}"
            )));
        };
        Ok(vec![
            ("HOME".into(), account.home.into_os_string()),
            ("USER".into(), account.name.into()),
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("LANG".into(), "C".into()),
        ])
    }

    /// On Windows: the machine's record of this SID, as `/etc/passwd` is on Linux,
    /// never `USERPROFILE`.
    #[cfg(windows)]
    fn account_env() -> std::io::Result<Vec<(OsString, OsString)>> {
        let env = crate::win_locked::worker_environment().map_err(std::io::Error::other)?;
        Ok(env.into_iter().map(|(k, v)| (k.into(), v.into())).collect())
    }

    #[cfg(windows)]
    fn status_text(st: ExitStatus) -> String {
        st.to_string()
    }

    #[cfg(unix)]
    fn status_text(st: ExitStatus) -> String {
        match (st.signal(), st.code()) {
            (Some(sig), _) => format!("signal {sig}"),
            (None, Some(code)) => format!("exit status {code}"),
            (None, None) => st.to_string(),
        }
    }

    /// The masked record as the daemon takes it. `ts` is left out: the
    /// daemon stamps the time itself, and it sets `uid`, `user`, `host`,
    /// `seq` and `prev`. With a bound `key`, it shows the call's
    /// `tool_use_id` (masked and cut); the key itself goes beside the
    /// record ([`append`]).
    fn record(
        agent: &str,
        ctx: &HookContext,
        policy: &str,
        j: &Judged,
        key: Option<&HookKey>,
    ) -> Value {
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
            // The call's id, masked and cut like any agent-controlled
            // field. Never the input hash: that goes beside the record
            // (`append`), as a plain hash in the log would let a reader
            // test guesses.
            if let Some(id) = bindable(key).and_then(|k| k.tool_use_id.as_deref()) {
                m.insert(
                    "tool_use_id".into(),
                    saiife_audit::mask::mask_cut(id, MAX_RECORDED_ID).into(),
                );
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

    /// A connection to the daemon, which must be in locked mode (only it
    /// may take the record). `Err` is the reason, for stderr. On Windows nothing reaches
    /// a pipe owned by anyone but the service (W11).
    fn connect_locked(
        cfg: &SystemConfig,
        daemon_uid: u32,
        deadline: Instant,
    ) -> Result<Client, String> {
        let c = crate::broker::system_client(&cfg.daemon.socket_dir, daemon_uid, deadline)
            .map_err(|e| format!("cannot reach the audit daemon ({})", describe(&e)))?;
        if c.hello_answer().get("mode").and_then(Value::as_str) != Some("locked") {
            return Err("the audit daemon is not in locked mode".into());
        }
        Ok(c)
    }

    /// [`connect_locked`], then `hook.begin {agent, event}` (plan 20), all
    /// within `CONNECT_TIMEOUT`. From the begin on, the daemon records a
    /// connection that ends without an `audit.append`. A refusal of the
    /// begin (a daemon that does not know the op) changes nothing else; a
    /// begin that breaks the connection is a daemon that cannot be reached.
    fn connect_begun(
        cfg: &SystemConfig,
        daemon_uid: u32,
        agent: &str,
        event: Option<&str>,
    ) -> Result<Client, String> {
        let deadline = Instant::now() + CONNECT_TIMEOUT;
        let mut c = crate::hook_timing::time("begin.connect", || {
            connect_locked(cfg, daemon_uid, deadline)
        })?;
        let mut args = Map::new();
        args.insert("agent".into(), agent.into());
        args.insert("event".into(), event.map_or(Value::Null, Value::from));
        let begun =
            crate::hook_timing::time("begin.call", || c.call(OP_HOOK_BEGIN, args, deadline));
        if let Err(e) = begun {
            if c.is_poisoned() {
                return Err(format!("cannot reach the audit daemon ({})", describe(&e)));
            }
        }
        Ok(c)
    }

    /// [`connect_begun`] on a helper thread, started first, and the payload
    /// ([`read_stdin`]) on this one meanwhile; both are done when this
    /// returns. Before plan 20 the connect overlapped the worker; this keeps
    /// it off the hook's serial path. A begin that failed, or a helper that
    /// panicked, is an `Err`: the call fails closed. If no thread can be
    /// started, the begin runs here first.
    fn begin_while_reading(
        cfg: &SystemConfig,
        daemon_uid: u32,
        agent: &str,
        event: Option<&str>,
    ) -> (Result<Client, String>, Result<String, String>) {
        std::thread::scope(|s| {
            let helper = std::thread::Builder::new()
                .name("saiife-begin".into())
                .spawn_scoped(s, || connect_begun(cfg, daemon_uid, agent, event));
            match helper {
                Ok(h) => {
                    let input = crate::hook_timing::time("stdin", read_stdin);
                    let begun = h.join().unwrap_or_else(|_| {
                        Err("cannot reach the audit daemon (saiife crashed)".into())
                    });
                    (begun, input)
                }
                Err(_) => {
                    let begun = connect_begun(cfg, daemon_uid, agent, event);
                    (begun, read_stdin())
                }
            }
        })
    }

    /// `key`, if the daemon's `hook.bind` takes it: a session over
    /// `MAX_BIND_SESSION` bytes or a tool call id over `MAX_RECORDED_ID` is
    /// not sent (the daemon would refuse the bind, and settle nothing with
    /// the append's arguments), and the append does not name it either.
    fn bindable(key: Option<&HookKey>) -> Option<&HookKey> {
        let fits = |s: &Option<String>, max: usize| s.as_ref().is_none_or(|s| s.len() <= max);
        key.filter(|k| fits(&k.session, MAX_BIND_SESSION) && fits(&k.tool_use_id, MAX_RECORDED_ID))
    }

    /// `hook.bind` with `key`, if there is one ([`bindable`]), and `tool`
    /// when it is at most `MAX_BIND_TOOL` bytes. Its result is not looked
    /// at: a refusal leaves the connection in step, and one that broke it
    /// leaves it poisoned, which the caller checks. An unbound call stays
    /// unbound.
    fn bind(client: &mut Client, key: Option<&HookKey>, tool: Option<&str>, deadline: Instant) {
        let Some(Value::Object(mut args)) =
            bindable(key).and_then(|k| serde_json::to_value(k).ok())
        else {
            return;
        };
        // A longer tool would cost the bind: the daemon refuses it whole.
        if let Some(t) = tool.filter(|t| t.len() <= MAX_BIND_TOOL) {
            args.insert("tool".into(), t.into());
        }
        let _ = client.call(OP_HOOK_BIND, args, deadline);
    }

    /// A fresh connection for a call whose first one broke: registered
    /// ([`connect_begun`]) and bound with the same `key` as the first.
    fn connect_bound(
        cfg: &SystemConfig,
        daemon_uid: u32,
        (agent, event): (&str, Option<&str>),
        key: Option<&HookKey>,
        tool: Option<&str>,
    ) -> Result<Client, String> {
        let mut c = connect_begun(cfg, daemon_uid, agent, event)?;
        bind(&mut c, key, tool, Instant::now() + ACK_TIMEOUT);
        Ok(c)
    }

    /// Reads and drops stdin, so an agent still writing the payload of a
    /// call denied before it was read gets no EPIPE.
    fn drain_stdin() {
        let _ = std::io::copy(&mut std::io::stdin().lock(), &mut std::io::sink());
    }

    /// `audit.append`, acknowledged with a `seq` by `deadline` (at most
    /// `ACK_TIMEOUT` from the first send). A bound `key` goes beside the
    /// record as `tool_use_id` and `input_sha256`: the daemon settles that
    /// key with them and writes neither.
    fn append(
        client: &mut Client,
        rec: Value,
        key: Option<&HookKey>,
        deadline: Instant,
    ) -> Result<(), ClientError> {
        let mut args = Map::new();
        args.insert("rec".into(), rec);
        if let Some(k) = bindable(key) {
            if let Some(id) = &k.tool_use_id {
                args.insert("tool_use_id".into(), id.clone().into());
            }
            args.insert("input_sha256".into(), k.input_sha256.clone().into());
        }
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

    // `hook_env` and its tests read passwd text; the rest is the same code on every OS.
    #[cfg(all(test, unix))]
    mod tests {
        use super::*;

        use saiife_policy::{Directory, FixedDirectory};

        const PASSWD: &str = "alice:x:1000:1000::/h:/bin/sh\n";

        #[test]
        fn a_failed_load_is_recorded_as_error_denied() {
            let payload = r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#;
            let rec = failed_load_record(
                "claude",
                None,
                &Ok(payload.to_string()),
                "saiife policy could not be loaded: not protected",
            );
            assert_eq!(rec["decision"], "error_denied");
            assert_eq!(rec["tool"], "Bash");
            assert_eq!(rec["input"], "git status");
            assert_eq!(rec["policy"], "unavailable");
            assert!(rec["reason"].as_str().unwrap().contains("not protected"));

            // No payload to read: still a record, with what is known.
            let rec = failed_load_record("claude", None, &Err("too large".into()), "why");
            assert_eq!(rec["decision"], "error_denied");
            assert_eq!(rec["reason"], "why");
        }
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
