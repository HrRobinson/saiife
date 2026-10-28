//! `saiife approvals`, `saiife approve`, `saiife reject` (spec §6.10.1):
//! the approver's side of ask-gated requests. Linux only.
//!
//! Exit codes: 0 done, 2 refused (the rule is printed), 5 the daemon
//! cannot be reached (or could not record the decision: `unrecorded`).
//! Before `approve` the CLI prints what is approved, then starts
//! `pkttyagent` when the request is the caller's own (so
//! `same_user = "reauth"` applies) and there is no graphical session to
//! ask in (decision 7); it stops it, its own child, afterwards (SIGTERM,
//! then SIGKILL after 1 s). `approvals show --json` prints the whole
//! masked request: `--full` only changes the text output.

#[cfg(not(target_os = "linux"))]
use std::{path::PathBuf, process::ExitCode};

use clap::{Args, Subcommand};

#[derive(Args, Clone, Copy, Default)]
pub struct ListArgs {
    /// Every request, whatever its state.
    #[arg(long, conflicts_with = "pending")]
    pub all: bool,
    /// Only the requests waiting for a decision (the default).
    #[arg(long)]
    pub pending: bool,
    /// Machine-readable output: one JSON array.
    #[arg(long)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum ApprovalsAction {
    /// List the requests (the default).
    List(ListArgs),
    /// Show one request: what would be sent, masked.
    Show {
        /// The request's id.
        id: u64,
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
        /// The whole masked body, not the first 2000 characters (text
        /// output; `--json` always has the whole masked body).
        #[arg(long)]
        full: bool,
    },
}

pub enum Decision {
    Approve {
        id: u64,
        note: Option<String>,
        accept_truncated: bool,
    },
    Reject {
        id: u64,
        note: Option<String>,
    },
}

#[cfg(not(target_os = "linux"))]
pub fn run(
    _config: Option<PathBuf>,
    _list: ListArgs,
    _action: Option<ApprovalsAction>,
) -> ExitCode {
    eprintln!("saiife: locked mode needs Linux in this version (macOS: v2.1)");
    ExitCode::from(5)
}

#[cfg(not(target_os = "linux"))]
pub fn decide(_config: Option<PathBuf>, d: Decision) -> ExitCode {
    match d {
        Decision::Approve {
            id,
            note,
            accept_truncated,
        } => {
            let _ = (id, note, accept_truncated);
        }
        Decision::Reject { id, note } => {
            let _ = (id, note);
        }
    }
    eprintln!("saiife: locked mode needs Linux in this version (macOS: v2.1)");
    ExitCode::from(5)
}

#[cfg(target_os = "linux")]
pub(crate) use linux::start_agent;
#[cfg(target_os = "linux")]
pub use linux::{decide, run};

#[cfg(target_os = "linux")]
mod linux {
    use super::{ApprovalsAction, Decision, ListArgs};
    use crate::broker::{self, Target};
    use crate::text::sanitize;
    use saiife_ipc::client::{Client, ClientError};
    use serde_json::{json, Map, Value};
    use std::path::PathBuf;
    use std::process::{Child, Command, ExitCode, Stdio};
    use std::time::{Duration, Instant};

    const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
    /// A decision may wait for the approver to authenticate (the daemon
    /// gives polkit 120 s).
    const CALL_TIMEOUT: Duration = Duration::from_secs(150);
    #[cfg_attr(debug_assertions, allow(dead_code))]
    const PKTTYAGENT: &str = "/usr/bin/pkttyagent";
    /// The body shown without `--full`, in characters.
    const BODY_CHARS: usize = 2000;
    /// The command / operation column, in characters.
    const WHAT_CHARS: usize = 60;

    /// Exit 2 (`Refused`) or 5 (`Unavailable`).
    enum Stop {
        Refused(Vec<String>),
        Unavailable(String),
    }

    fn unavailable(m: impl Into<String>) -> Stop {
        Stop::Unavailable(m.into())
    }

    fn finish(r: Result<(), Stop>) -> ExitCode {
        match r {
            Ok(()) => ExitCode::SUCCESS,
            Err(Stop::Refused(lines)) => {
                for l in lines {
                    eprintln!("saiife: {l}");
                }
                ExitCode::from(2)
            }
            Err(Stop::Unavailable(m)) => {
                eprintln!("saiife: {m}");
                ExitCode::from(5)
            }
        }
    }

    fn connect(t: &Target) -> Result<Client, Stop> {
        broker::connect(t, Instant::now() + CONNECT_TIMEOUT)
            .map_err(|e| unavailable(broker::unreachable(t, &e)))
    }

    /// One call; a refusal comes back as `Stop::Refused` (with the rule
    /// when there is one), anything else as `Unavailable`.
    fn call(
        c: &mut Client,
        op: &str,
        args: Map<String, Value>,
    ) -> Result<Map<String, Value>, Stop> {
        let ans = c
            .call_answer(op, args, Instant::now() + CALL_TIMEOUT)
            .map_err(|e: ClientError| {
                unavailable(format!("cannot reach the saiife daemon: {e}"))
            })?;
        if ans.get("ok") == Some(&Value::Bool(true)) {
            return Ok(ans);
        }
        let s = |k: &str| ans.get(k).and_then(Value::as_str).unwrap_or_default();
        let message = sanitize(s("message"));
        match s("error") {
            // `unrecorded`: the decision is made but not on record; like
            // an unreachable daemon, the caller must check (exit 5).
            "unavailable" | "unrecorded" => Err(unavailable(message)),
            _ if !s("rule").is_empty() => Err(Stop::Refused(vec![
                format!("refused ({})", sanitize(s("rule"))),
                message,
            ])),
            _ => Err(Stop::Refused(vec![message])),
        }
    }

    /// The locked daemon (a flag or a locked host) or the personal broker.
    fn target(config: Option<PathBuf>) -> Result<Target, Stop> {
        broker::resolve_here(config.as_deref()).map_err(Stop::Unavailable)
    }

    fn args<const N: usize>(a: [(&str, Value); N]) -> Map<String, Value> {
        a.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
    }

    pub fn run(
        config: Option<PathBuf>,
        list: ListArgs,
        action: Option<ApprovalsAction>,
    ) -> ExitCode {
        finish(target(config).and_then(|t| match action {
            None => list_cmd(&t, list),
            Some(ApprovalsAction::List(l)) => list_cmd(&t, l),
            Some(ApprovalsAction::Show { id, json, full }) => show_cmd(&t, id, json, full),
        }))
    }

    fn list_cmd(config: &Target, l: ListArgs) -> Result<(), Stop> {
        let mut c = connect(config)?;
        let mut a = Map::new();
        if !l.all {
            a.insert("states".into(), json!(["pending"]));
        }
        let ans = call(&mut c, "approval.list", a)?;
        let items = ans.get("items").cloned().unwrap_or(json!([]));
        if l.json {
            outln!("{items}");
            return Ok(());
        }
        let now = time::OffsetDateTime::now_utc();
        let rows: Vec<[String; 6]> = items
            .as_array()
            .map(|v| v.iter().map(|i| row(i, now)).collect())
            .unwrap_or_default();
        if rows.is_empty() {
            outln!(
                "{}",
                if l.all {
                    "no requests"
                } else {
                    "no pending requests"
                }
            );
            return Ok(());
        }
        let head = ["ID", "AGE", "USER", "TYPE", "REQUEST", "STATE"].map(String::from);
        let mut w = [0usize; 6];
        for r in std::iter::once(&head).chain(rows.iter()) {
            for (i, c) in r.iter().enumerate() {
                w[i] = w[i].max(c.chars().count());
            }
        }
        for r in std::iter::once(&head).chain(rows.iter()) {
            let mut line = String::new();
            for (i, c) in r.iter().enumerate() {
                if i > 0 {
                    line.push_str("  ");
                }
                line.push_str(c);
                if i < 5 {
                    line.push_str(&" ".repeat(w[i] - c.chars().count()));
                }
            }
            outln!("{}", line.trim_end());
        }
        Ok(())
    }

    fn cut(s: &str, n: usize) -> String {
        if s.chars().count() > n {
            format!("{}…", s.chars().take(n).collect::<String>())
        } else {
            s.to_string()
        }
    }

    /// `service operation`, or the masked command.
    fn what(i: &Value) -> String {
        let s = |k: &str| i[k].as_str().unwrap_or("");
        let w = if i["type"] == "command" {
            s("input").to_string()
        } else if let Some(e) = i["env"].as_str() {
            format!("{} {} (env {e})", s("service"), s("operation"))
        } else if i["env_base"] == true {
            format!("{} {} (env base)", s("service"), s("operation"))
        } else {
            format!("{} {}", s("service"), s("operation"))
        };
        cut(&sanitize(&w), WHAT_CHARS)
    }

    fn row(i: &Value, now: time::OffsetDateTime) -> [String; 6] {
        let s = |k: &str| sanitize(i[k].as_str().unwrap_or(""));
        [
            i["id"].as_u64().map(|n| n.to_string()).unwrap_or_default(),
            age(i["created"].as_str().unwrap_or(""), now),
            s("user"),
            s("type"),
            what(i),
            s("state"),
        ]
    }

    fn age(created: &str, now: time::OffsetDateTime) -> String {
        let Ok(t) =
            time::OffsetDateTime::parse(created, &time::format_description::well_known::Rfc3339)
        else {
            return "?".into();
        };
        match (now - t).whole_seconds().max(0) {
            s @ 0..=59 => format!("{s}s"),
            s @ 60..=3599 => format!("{}m", s / 60),
            s @ 3600..=86_399 => format!("{}h", s / 3600),
            s => format!("{}d", s / 86_400),
        }
    }

    fn show_cmd(config: &Target, id: u64, as_json: bool, full: bool) -> Result<(), Stop> {
        let mut c = connect(config)?;
        let ans = call(&mut c, "approval.show", args([("request", json!(id))]))?;
        let item = ans.get("item").cloned().unwrap_or(Value::Null);
        if as_json {
            outln!("{item}");
            return Ok(());
        }
        let s = |k: &str| sanitize(item[k].as_str().unwrap_or(""));
        outln!("request #{id}  {}", s("state"));
        outln!(
            "  requester  {} (uid {}), agent {}",
            s("user"),
            item["uid"],
            s("agent")
        );
        outln!("  project    {}", s("project"));
        if item["scope"].is_string() {
            // The project tree a command grant covers.
            outln!("  scope      {}", s("scope"));
        }
        outln!("  type       {}", s("type"));
        if item["type"] == "command" {
            outln!("  command    {}", s("input"));
        } else {
            outln!("  request    {} {}", s("service"), s("operation"));
            if item["env"].is_string() {
                // The environment the request was asked under: it is
                // sent under that one or not at all.
                outln!("  env        {}", s("env"));
            } else if item["env_base"] == true {
                // Asked under the base config: sent under it or not at all.
                outln!("  env        base");
            }
            if !item["capability"].is_null() {
                outln!("  capability {}", s("capability"));
            }
        }
        outln!("  created    {}   expires {}", s("created"), s("expires"));
        if let Some(a) = item["amount"].as_object() {
            outln!(
                "  amount     {} {} (minor units)",
                a.get("minor").map(|v| v.to_string()).unwrap_or_default(),
                sanitize(a.get("currency").and_then(Value::as_str).unwrap_or(""))
            );
        }
        if let Some(p) = item["params"].as_object().filter(|p| !p.is_empty()) {
            outln!("  params");
            for (k, v) in p {
                outln!(
                    "    {} = {}",
                    sanitize(k),
                    sanitize(v.as_str().unwrap_or(""))
                );
            }
        }
        if let Some(h) = item["headers"].as_array().filter(|h| !h.is_empty()) {
            outln!("  headers");
            for kv in h {
                outln!(
                    "    {}: {}",
                    sanitize(kv[0].as_str().unwrap_or("")),
                    sanitize(kv[1].as_str().unwrap_or(""))
                );
            }
        }
        if !item["decided_by"].is_null() {
            outln!("  decided by uid {}", item["decided_by"]);
        }
        if !item["note"].is_null() {
            outln!("  note       {}", s("note"));
        }
        if let Some(body) = item["body_display"].as_str() {
            outln!("  body sha256 {}", s("body_sha256"));
            let (shown, was_cut): (String, bool) = if full || body.chars().count() <= BODY_CHARS {
                (body.to_string(), false)
            } else {
                (body.chars().take(BODY_CHARS).collect(), true)
            };
            outln!("  body (masked)");
            for line in shown.split('\n') {
                outln!("    {}", sanitize(line));
            }
            if was_cut {
                outln!("  … (cut; use --full)");
            }
            if item["body_truncated"] == true {
                outln!(
                    "  WARNING: the body is over 1 MiB, so even the full masked body above is cut. Approve it only knowingly, with --accept-truncated."
                );
            }
        }
        Ok(())
    }

    // ------------------------------------------------------- decisions

    pub fn decide(config: Option<PathBuf>, d: Decision) -> ExitCode {
        finish(target(config).and_then(|t| decide_inner(&t, d)))
    }

    fn decide_inner(config: &Target, d: Decision) -> Result<(), Stop> {
        let (id, action, note, ack) = match d {
            Decision::Approve {
                id,
                note,
                accept_truncated,
            } => (id, "approve", note, accept_truncated),
            Decision::Reject { id, note } => (id, "reject", note, false),
        };
        let mut c = connect(config)?;
        let mut a = args([("request", json!(id)), ("action", json!(action))]);
        if let Some(n) = note {
            a.insert("note".into(), json!(n));
        }
        if ack {
            a.insert("ack_truncated".into(), json!(true));
        }
        // The re-authentication prompt is for an approval only, and only
        // when the request is the caller's own (`same_user = "reauth"`).
        // What is approved is printed first, so a password prompt is never
        // answered blind.
        let _agent = if action == "approve" {
            let shown = call(&mut c, "approval.show", args([("request", json!(id))]))?;
            eprintln!("saiife: approving {}", request_summary(id, &shown["item"]));
            let uid = shown["item"]["uid"].as_u64();
            // The personal broker needs no re-authentication for the
            // user's own requests (spec 6.10.2): no prompt agent.
            if config.is_locked() && uid == Some(u64::from(rustix::process::getuid().as_raw())) {
                start_agent()
            } else {
                None
            }
        } else {
            None
        };
        let ans = call(&mut c, "approval.decide", a)?;
        let state = ans.get("state").and_then(Value::as_str).unwrap_or(action);
        outln!("request #{id} {state}");
        Ok(())
    }

    /// `request #<id>: <type> <service operation | command> [amount]`,
    /// sanitized, for the line printed before a password prompt.
    fn request_summary(id: u64, item: &Value) -> String {
        let s = |k: &str| sanitize(item[k].as_str().unwrap_or(""));
        let mut out = format!("request #{id}: {} {}", s("type"), what(item));
        if let Some(a) = item["amount"].as_object() {
            out.push_str(&format!(
                " (amount {} {} minor units)",
                a.get("minor").map(|v| v.to_string()).unwrap_or_default(),
                sanitize(a.get("currency").and_then(Value::as_str).unwrap_or(""))
            ));
        }
        out
    }

    /// `pkttyagent` is for a terminal-only session: `SSH_TTY` is set, or
    /// there is neither `DISPLAY` nor `WAYLAND_DISPLAY`.
    fn wants_agent(var: impl Fn(&str) -> Option<std::ffi::OsString>) -> bool {
        let set = |k: &str| var(k).is_some_and(|v| !v.is_empty());
        set("SSH_TTY") || (!set("DISPLAY") && !set("WAYLAND_DISPLAY"))
    }

    #[cfg(debug_assertions)]
    fn agent_path() -> PathBuf {
        std::env::var_os("SAIIFE_TEST_PKTTYAGENT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(PKTTYAGENT))
    }

    #[cfg(not(debug_assertions))]
    fn agent_path() -> PathBuf {
        PathBuf::from(PKTTYAGENT)
    }

    /// How long a stopped `pkttyagent` gets to exit on SIGTERM.
    const AGENT_STOP: Duration = Duration::from_secs(1);

    /// Our own `pkttyagent` child; stopped and reaped through its handle
    /// when dropped (never by name): SIGTERM, then SIGKILL after 1 s.
    pub(crate) struct Agent(Child);

    impl Drop for Agent {
        fn drop(&mut self) {
            if let Ok(None) = self.0.try_wait() {
                // Our own child's pid (not reaped yet, so not reused).
                if let Some(pid) = rustix::process::Pid::from_raw(self.0.id() as i32) {
                    let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
                }
                let deadline = Instant::now() + AGENT_STOP;
                while Instant::now() < deadline {
                    if !matches!(self.0.try_wait(), Ok(None)) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// Start `pkttyagent` for this process when the session is
    /// terminal-only; `None` when it is not needed or cannot run (then a
    /// hint says how a prompt could appear).
    pub(crate) fn start_agent() -> Option<Agent> {
        if !wants_agent(|k| std::env::var_os(k)) {
            return None;
        }
        let path = agent_path();
        if !path.is_file() {
            eprintln!(
                "saiife: hint: {} is missing, so no password prompt can appear in this terminal; install polkit's pkttyagent, or approve from a graphical session",
                path.display()
            );
            return None;
        }
        let child = Command::new(path)
            .arg("--process")
            .arg(std::process::id().to_string())
            .arg("--fallback")
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .ok()?;
        // Let it register with polkit before the daemon asks. pkttyagent
        // has no readiness signal; 150 ms is enough for a local polkitd,
        // and a late agent only means polkit finds none (reauth_unavailable,
        // the safe side).
        std::thread::sleep(Duration::from_millis(150));
        Some(Agent(child))
    }
}
