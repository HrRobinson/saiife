//! `saiife api`: connector calls through the daemon (spec §6.7.2). Linux
//! only. The upstream data goes to stdout, a one-line summary to stderr.
//! Exit codes: 0 done, 1 upstream status >= 400 or an upstream failure, 2
//! denied, 3 pending approval, 4 limit reached, 5 saiife unavailable.
//! `--wait` polls `api.result` every 2 s (at most 1 h, decision 3);
//! `saiife api result <id>` fetches a result later.
//!
//! `saiife api collection list|run` (spec §6.12, plan 14 decision 11) runs
//! a saved collection: each step is one ordinary `api.call` (`call_one`,
//! the same as a single call), carrying `collection = "<name>"` as
//! attribution only. The run stops at the first step that is not done.
//!
//! The project's `.saiife/config.toml` may tighten a service (`deny`,
//! `ask`); it is read here and sent as `overlay` (decision 4). In locked
//! mode the daemon ignores its `allow`.

use std::path::PathBuf;
use std::process::ExitCode;

#[derive(clap::Args)]
pub struct ApiArgs {
    /// List the services and operations you may call, with their policy
    /// action (optionally for one service).
    #[arg(long)]
    pub list: bool,
    /// Machine-readable output.
    #[arg(long)]
    pub json: bool,
    /// The request body: `@<file>` or `-` for stdin.
    #[arg(long, value_name = "@FILE|-")]
    pub body: Option<String>,
    /// Wait this long (at most 1h) for an approval and the result.
    #[arg(long, value_name = "DURATION")]
    pub wait: Option<String>,
    /// The system config (default /etc/saiife/config.toml).
    #[arg(long = "system-config", hide = true)]
    pub system_config: Option<PathBuf>,
    /// `<service> <operation> [k=v ...]`, `[<service>]` with --list,
    /// `token` (a 12 h bearer token for the gateway's TCP listener), or
    /// `collection list` / `collection run <name> [k=v ...]`.
    #[arg(value_name = "ARGS")]
    pub args: Vec<String>,
}

#[cfg(not(target_os = "linux"))]
pub fn run(_a: ApiArgs) -> ExitCode {
    eprintln!("saiife: locked mode needs Linux in this version (macOS: v2.1)");
    ExitCode::from(5)
}

#[cfg(target_os = "linux")]
pub fn run(a: ApiArgs) -> ExitCode {
    linux::run(a)
}

#[cfg(target_os = "linux")]
pub(crate) mod linux {
    use super::ApiArgs;
    use crate::broker::{self, Target};
    use crate::collection;
    use base64::Engine as _;
    use saiife_agents::config::{find_project_root, read_config_bytes};
    use saiife_ipc::client::Client;
    use saiife_policy::{
        load_system, merge_project, parse_duration, parse_project, Mode, SystemConfig,
    };
    use serde_json::{json, Map, Value};
    use std::collections::BTreeMap;
    use std::io::Read;
    use std::path::Path;
    use std::process::ExitCode;
    use std::time::{Duration, Instant};

    const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
    /// A request frame is at most 1 MiB; base64 grows by 4/3.
    const MAX_BODY: usize = 700 * 1024;

    /// Why the command stops, with its exit code.
    struct Stop(u8, String);

    fn unavailable(m: impl Into<String>) -> Stop {
        Stop(5, m.into())
    }

    fn refused(m: impl Into<String>) -> Stop {
        Stop(2, m.into())
    }

    pub fn run(a: ApiArgs) -> ExitCode {
        match go(a) {
            Ok(code) => ExitCode::from(code),
            Err(Stop(code, m)) => {
                eprintln!("saiife: {m}");
                ExitCode::from(code)
            }
        }
    }

    struct Daemon {
        client: Client,
        cfg: SystemConfig,
        target: Target,
    }

    /// The target's daemon and the config it serves (the system config,
    /// or the personal broker's own, read after the broker answered).
    fn connect(t: &Target) -> Result<Daemon, Stop> {
        let client = broker::connect(t, Instant::now() + CONNECT_TIMEOUT)
            .map_err(|e| unavailable(broker::unreachable(t, &e)))?;
        let what = if t.is_locked() { "system" } else { "broker" };
        let cfg = load_system(t.config())
            .map_err(|e| unavailable(format!("cannot read the {what} config: {e}")))?
            .config;
        Ok(Daemon {
            client,
            cfg,
            target: t.clone(),
        })
    }

    /// The project root (or the cwd) and its service overlays, merged as
    /// the daemon decides: locked mode keeps deny and ask only (an invalid
    /// project config is ignored with a warning; it can only have
    /// tightened); the personal broker decides as developer mode, so a
    /// project `allow` counts too (spec §6.9.1).
    ///
    /// The third value is the project `env` the call asks for: only the
    /// personal broker acts on it (the locked daemon takes the scope's), so
    /// it is sent to the broker only.
    fn project(
        d: &Daemon,
    ) -> (
        String,
        BTreeMap<String, saiife_policy::ServiceOverlay>,
        Option<String>,
    ) {
        project_for(&d.cfg, &d.target)
    }

    /// [`project`] for the config `cfg` that `target` serves (also used by
    /// `saiife run --cloud`, whose lease takes the same overlay).
    pub(crate) fn project_for(
        cfg: &SystemConfig,
        target: &Target,
    ) -> (
        String,
        BTreeMap<String, saiife_policy::ServiceOverlay>,
        Option<String>,
    ) {
        let mode = if target.is_locked() {
            Mode::Locked
        } else {
            Mode::Developer
        };
        let cwd = std::env::current_dir().ok();
        let root = cwd.as_deref().and_then(find_project_root);
        let shown = root
            .as_ref()
            .or(cwd.as_ref())
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let parsed = root.and_then(|r| match read_config_bytes(&r) {
            Ok(Some(b)) => match parse_project(&b) {
                Ok(p) => Some(p),
                Err(e) => {
                    eprintln!("saiife: warning: project config ignored ({e})");
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                eprintln!("saiife: warning: project config ignored ({e})");
                None
            }
        });
        let env = parsed
            .as_ref()
            .filter(|_| !target.is_locked())
            .and_then(|p| p.env.clone());
        let services = parsed
            .map(|p| merge_project(&cfg.guard.packs, &p, mode).services)
            .unwrap_or_default();
        (shown, services, env)
    }

    /// The broker's `warning` (an undefined project `env`: the base config
    /// was used), on stderr.
    fn env_warning(ans: &Map<String, Value>) {
        if let Some(w) = ans.get("warning").and_then(Value::as_str) {
            eprintln!("saiife: warning: {}", crate::text::sanitize(w));
        }
    }

    fn go(a: ApiArgs) -> Result<u8, Stop> {
        let config = broker::resolve_here(a.system_config.as_deref()).map_err(unavailable)?;
        if a.list {
            return list(&config, &a);
        }
        if a.args.len() == 1 && a.args[0] == "token" {
            return token(&config, a.json);
        }
        if a.args.first().map(String::as_str) == Some("collection") {
            return collection_cmd(&config, &a);
        }
        if a.args.first().map(String::as_str) == Some("result") {
            let id = match a.args.as_slice() {
                [_, id] => parse_id(id)?,
                _ => return Err(refused("usage: saiife api result <request-id>")),
            };
            let wait = wait_limit(a.wait.as_deref())?;
            let mut d = connect(&config)?;
            return settle(&mut d, &a, id, wait);
        }
        let [service, operation, rest @ ..] = a.args.as_slice() else {
            return Err(refused(
                "usage: saiife api <service> <operation> [k=v ...] (or saiife api --list)",
            ));
        };
        let mut params = Map::new();
        for kv in rest {
            match kv.split_once('=') {
                Some((k, v)) if !k.is_empty() => {
                    params.insert(k.to_string(), Value::String(v.to_string()));
                }
                _ => return Err(refused(format!("parameter {kv:?} is not k=v"))),
            }
        }
        let wait = wait_limit(a.wait.as_deref())?;
        let body = match a.body.as_deref() {
            None => None,
            Some("-") => Some(read_capped(std::io::stdin().lock(), "stdin")?),
            Some(f) => match f.strip_prefix('@') {
                Some(path) => {
                    let file = std::fs::File::open(path)
                        .map_err(|e| refused(format!("cannot read {path}: {e}")))?;
                    Some(read_capped(file, path)?)
                }
                None => return Err(refused("--body takes @<file> or -")),
            },
        };

        let mut d = connect(&config)?;
        let (code, ans) = call_one(&mut d, service, operation, params, body, None)?;
        if code == 3 {
            let id = ans.get("pending").and_then(Value::as_u64).unwrap_or(0);
            return match wait {
                Some(w) => settle(&mut d, &a, id, Some(w)),
                None => Err(pending(id)),
            };
        }
        let ms = ans.get("ms").and_then(Value::as_u64).map(u128::from);
        done(&a, &format!("{service} {operation}"), &ans, ms)
    }

    /// One `api.call`: the whole pipeline in the daemon (scope, decide,
    /// limits, approvals, audit), for a single call and for each collection
    /// step alike. `Ok((0 | 1, answer))` once done (1: upstream status >=
    /// 400; the answer gains `ms`), `Ok((3, answer))` while it waits for
    /// approval (the answer holds `pending`), `Err` for a refusal with its
    /// exit code. Prints nothing.
    fn call_one(
        d: &mut Daemon,
        service: &str,
        operation: &str,
        params: Map<String, Value>,
        body: Option<Vec<u8>>,
        collection: Option<&str>,
    ) -> Result<(u8, Map<String, Value>), Stop> {
        let (project, overlays, env) = project(d);
        let mut args = Map::new();
        args.insert("service".into(), service.into());
        args.insert("operation".into(), operation.into());
        args.insert("params".into(), Value::Object(params));
        args.insert("project".into(), project.into());
        if let Some(o) = overlays.get(service) {
            args.insert("overlay".into(), json!(o));
        }
        if let Some(b) = &body {
            args.insert(
                "body_b64".into(),
                base64::engine::general_purpose::STANDARD.encode(b).into(),
            );
        }
        if let Some(c) = collection {
            args.insert("collection".into(), c.into());
        }
        if let Some(e) = env {
            args.insert("env".into(), e.into());
        }
        // The daemon waits at most one upstream timeout for a pool slot and
        // one for the upstream; past both, plus slack, it is gone.
        let timeout = d.cfg.gateway.upstream_timeout * 2 + Duration::from_secs(15);
        let started = Instant::now();
        let mut ans = d
            .client
            .call_answer("api.call", args, Instant::now() + timeout)
            .map_err(|e| unavailable(broker::unreachable(&d.target, &e)))?;
        let ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        if ans.get("ok") != Some(&Value::Bool(true)) {
            return Err(refusal(&ans));
        }
        env_warning(&ans);
        if ans.get("pending").and_then(Value::as_u64).is_some() {
            return Ok((3, ans));
        }
        ans.insert("ms".into(), ms.into());
        let status = ans.get("status").and_then(Value::as_u64).unwrap_or(0);
        Ok((if status >= 400 { 1 } else { 0 }, ans))
    }

    /// `saiife api collection list | run <name> [k=v ...]`. The project
    /// root is the nearest saiife project at or above the cwd.
    fn collection_cmd(config: &Target, a: &ApiArgs) -> Result<u8, Stop> {
        const USAGE: &str =
            "usage: saiife api collection list | saiife api collection run <name> [k=v ...]";
        if a.wait.is_some() || a.body.is_some() {
            return Err(refused(
                "--wait and --body do not apply to a collection (a pending step stops the run)",
            ));
        }
        let cwd = std::env::current_dir()
            .map_err(|e| refused(format!("cannot read the current directory: {e}")))?;
        let root = crate::project::project_root(&cwd);
        match a.args.get(1).map(String::as_str) {
            Some("list") if a.args.len() == 2 => collection_list(&root, a.json),
            Some("run") if a.args.len() >= 3 => collection_run(config, &root, a),
            _ => Err(refused(USAGE)),
        }
    }

    /// `name  steps  services`, one line per collection (`--json`: an
    /// array). A file that does not load is a warning.
    fn collection_list(root: &Path, as_json: bool) -> Result<u8, Stop> {
        let mut rows = Vec::new();
        for (stem, c) in collection::list_all(root) {
            match c {
                Ok(c) => {
                    let mut services: Vec<String> = Vec::new();
                    for s in &c.step {
                        if !services.contains(&s.service) {
                            services.push(s.service.clone());
                        }
                    }
                    rows.push((c.name, c.step.len(), services));
                }
                Err(e) => eprintln!(
                    "saiife: warning: collection {}: {}",
                    crate::text::sanitize(&stem),
                    crate::text::sanitize(&e.to_string())
                ),
            }
        }
        if as_json {
            let v: Vec<Value> = rows
                .iter()
                .map(|(n, k, s)| json!({"name": n, "steps": k, "services": s}))
                .collect();
            outln!("{}", Value::Array(v));
            return Ok(0);
        }
        if rows.is_empty() {
            outln!("no collections in {}", collection::dir(root).display());
        }
        for (name, steps, services) in &rows {
            outln!(
                "{name}  {steps}  {}",
                crate::text::sanitize(&services.join(","))
            );
        }
        Ok(0)
    }

    /// Fill the collection (every variable is checked before any step),
    /// then run its steps in order, each as one `call_one`. stdout: a JSON
    /// array of `{step, service, operation, status, data}` for the steps
    /// that were answered; stderr: one summary line per step. The run
    /// stops at the first step that is not done, with that step's exit
    /// code; a pending step prints its id. There is no resume.
    fn collection_run(config: &Target, root: &Path, a: &ApiArgs) -> Result<u8, Stop> {
        let c = collection::load(root, &a.args[2]).map_err(|e| refused(e.to_string()))?;
        let vars = collection::parse_vars(&a.args[3..]).map_err(|e| refused(e.to_string()))?;
        let steps = collection::fill(&c, &vars).map_err(|e| refused(e.to_string()))?;
        let mut bodies = Vec::with_capacity(steps.len());
        for (i, s) in steps.iter().enumerate() {
            let b = match &s.body {
                Some(v) => {
                    let b = serde_json::to_vec(v)
                        .map_err(|e| refused(format!("step {}: body: {e}", i + 1)))?;
                    if b.len() > MAX_BODY {
                        return Err(refused(format!(
                            "step {}: the body is larger than {} KiB",
                            i + 1,
                            MAX_BODY / 1024
                        )));
                    }
                    Some(b)
                }
                None => None,
            };
            bodies.push(b);
        }

        let mut d = connect(config)?;
        let n = steps.len();
        let mut out: Vec<Value> = Vec::new();
        let print = |out: &[Value]| outln!("{}", Value::Array(out.to_vec()));
        for (i, (s, body)) in steps.into_iter().zip(bodies).enumerate() {
            let label =
                crate::text::sanitize(&format!("step {}/{n} {} {}", i + 1, s.service, s.operation));
            let params: Map<String, Value> = s
                .params
                .into_iter()
                .map(|(k, v)| (k, Value::String(v)))
                .collect();
            let r = call_one(
                &mut d,
                &s.service,
                &s.operation,
                params,
                body,
                Some(&c.name),
            );
            let (code, ans) = match r {
                Ok(x) => x,
                Err(Stop(code, m)) => {
                    print(&out);
                    return Err(Stop(code, format!("{label}: {m}")));
                }
            };
            if code == 3 {
                print(&out);
                let id = ans.get("pending").and_then(Value::as_u64).unwrap_or(0);
                return Err(Stop(
                    3,
                    format!(
                        "{label}: pending approval #{id} (saiife api result {id}); \
                         the steps after it were not run"
                    ),
                ));
            }
            let ms = ans.get("ms").and_then(Value::as_u64).map(u128::from);
            let body = summary(&label, &ans, ms);
            let status = ans.get("status").and_then(Value::as_u64).unwrap_or(0);
            out.push(json!({
                "step": i + 1,
                "service": s.service,
                "operation": s.operation,
                "status": status,
                "data": parsed(&body),
            }));
            if code != 0 {
                print(&out);
                eprintln!("saiife: {label}: stopped at upstream status {status}");
                return Ok(code);
            }
        }
        print(&out);
        Ok(0)
    }

    /// A response body as JSON, or as a string when it is not JSON.
    fn parsed(body: &[u8]) -> Value {
        serde_json::from_slice::<Value>(body)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(body).into_owned()))
    }

    /// The longest `--wait` (decision 3).
    const MAX_WAIT: Duration = Duration::from_secs(3600);
    /// How often `--wait` asks again.
    const POLL_EVERY: Duration = Duration::from_secs(2);

    /// `--wait <duration>`, at most an hour.
    fn wait_limit(w: Option<&str>) -> Result<Option<Duration>, Stop> {
        match w {
            None => Ok(None),
            Some(w) => Ok(Some(parse_duration(w).map_err(refused)?.min(MAX_WAIT))),
        }
    }

    fn parse_id(s: &str) -> Result<u64, Stop> {
        let s = s.strip_prefix('#').unwrap_or(s);
        s.parse::<u64>()
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(|| refused(format!("{s:?} is not a request id")))
    }

    /// Exit 3: the request waits for approval.
    fn pending(id: u64) -> Stop {
        Stop(
            3,
            format!("pending approval #{id} (saiife api result {id})"),
        )
    }

    /// The result of request `id` (`api.result`), polled every 2 s until it
    /// is decided or `wait` is over (decision 3), as a direct call's exit
    /// code: 3 while it waits, 2 once rejected or expired.
    fn settle(d: &mut Daemon, a: &ApiArgs, id: u64, wait: Option<Duration>) -> Result<u8, Stop> {
        let deadline = Instant::now() + wait.unwrap_or_default();
        loop {
            let mut args = Map::new();
            args.insert("request".into(), id.into());
            let ans = d
                .client
                .call_answer("api.result", args, Instant::now() + Duration::from_secs(10))
                .map_err(|e| unavailable(broker::unreachable(&d.target, &e)))?;
            if ans.get("ok") != Some(&Value::Bool(true)) {
                return Err(refusal(&ans));
            }
            let state = ans.get("state").and_then(Value::as_str).unwrap_or_default();
            match state {
                "pending" | "approved" => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Err(pending(id));
                    }
                    std::thread::sleep(left.min(POLL_EVERY));
                }
                "rejected" | "expired" => {
                    return Err(refused(format!("request #{id} was {state}")));
                }
                "sent" | "send_failed" => {
                    return match ans.get("result").and_then(Value::as_object) {
                        Some(r) if r.get("ok") == Some(&Value::Bool(true)) => {
                            done(a, &format!("request #{id}"), r, None)
                        }
                        Some(r) => Err(refusal(r)),
                        None if state == "sent" => Err(Stop(
                            1,
                            format!("request #{id} was sent; its result is kept 24 h and is gone"),
                        )),
                        None => Err(refused(format!("request #{id}: send failed"))),
                    };
                }
                other => {
                    return Err(unavailable(format!(
                        "request #{id} is in an unknown state {other:?}"
                    )))
                }
            }
        }
    }

    /// A done `api.call` answer: the body to stdout, a summary to stderr.
    fn done(
        a: &ApiArgs,
        label: &str,
        ans: &Map<String, Value>,
        ms: Option<u128>,
    ) -> Result<u8, Stop> {
        let status = ans.get("status").and_then(Value::as_u64).unwrap_or(0);
        let body = body_of(ans);
        if a.json {
            outln!(
                "{}",
                json!({
                    "status": status,
                    "headers": ans.get("headers").cloned().unwrap_or(json!([])),
                    "truncated": ans.get("truncated") == Some(&Value::Bool(true)),
                    "next": ans.get("next").cloned().unwrap_or(Value::Null),
                    "body": parsed(&body),
                })
            );
        } else {
            use std::io::Write as _;
            let mut out = std::io::stdout().lock();
            let _ = out.write_all(&body);
            if !body.ends_with(b"\n") {
                let _ = out.write_all(b"\n");
            }
        }
        summary(label, ans, ms);
        Ok(if status >= 400 { 1 } else { 0 })
    }

    /// The decoded body of a done answer.
    fn body_of(ans: &Map<String, Value>) -> Vec<u8> {
        ans.get("body_b64")
            .and_then(Value::as_str)
            .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
            .unwrap_or_default()
    }

    /// The stderr summary of a done answer (status, size, time, a cut
    /// response, the next page); returns the body.
    fn summary(label: &str, ans: &Map<String, Value>, ms: Option<u128>) -> Vec<u8> {
        let status = ans.get("status").and_then(Value::as_u64).unwrap_or(0);
        let body = body_of(ans);
        match ms {
            Some(ms) => eprintln!("saiife: {label} → {status} ({} bytes, {ms} ms)", body.len()),
            None => eprintln!("saiife: {label} → {status} ({} bytes)", body.len()),
        }
        if ans.get("truncated") == Some(&Value::Bool(true)) {
            eprintln!("saiife: the response was cut at max_response_bytes");
        }
        if let Some(Value::Object(n)) = ans.get("next") {
            let kv: Vec<String> = n
                .iter()
                .map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or_default()))
                .collect();
            eprintln!("next: {}", kv.join(" "));
        }
        body
    }

    fn read_capped(r: impl Read, what: &str) -> Result<Vec<u8>, Stop> {
        let mut b = Vec::new();
        r.take(MAX_BODY as u64 + 1)
            .read_to_end(&mut b)
            .map_err(|e| refused(format!("cannot read {what}: {e}")))?;
        if b.len() > MAX_BODY {
            return Err(refused(format!(
                "the body is larger than {} KiB",
                MAX_BODY / 1024
            )));
        }
        Ok(b)
    }

    /// An `ok: false` answer as its exit code and message.
    fn refusal(ans: &Map<String, Value>) -> Stop {
        let s = |k: &str| ans.get(k).and_then(Value::as_str).unwrap_or_default();
        match s("error") {
            "denied" if !s("reason").is_empty() => Stop(
                2,
                format!(
                    "denied ({}): {}",
                    s("rule"),
                    crate::text::sanitize(s("reason"))
                ),
            ),
            "denied" => Stop(2, format!("denied ({})", s("rule"))),
            "limited" => Stop(4, format!("limit reached ({})", s("limit"))),
            "upstream_failed" => {
                let why = if s("rule").is_empty() {
                    s("reason")
                } else {
                    s("rule")
                };
                let why = if why.is_empty() { s("message") } else { why };
                Stop(1, format!("upstream failed ({why})"))
            }
            "bad_request" | "forbidden" => Stop(2, s("message").to_string()),
            // Sent, but the result was too large to keep for later.
            "result_too_large" => Stop(
                1,
                format!(
                    "sent (upstream status {}), but the result was too large to keep",
                    ans.get("status").map(|v| v.to_string()).unwrap_or_default()
                ),
            ),
            _ => Stop(5, s("message").to_string()),
        }
    }

    /// `saiife api token`: a bearer token for the gateway's loopback TCP
    /// listener (`[gateway] tcp`), bound to this uid, valid 12 h. The token
    /// goes to stdout (with `--json`: `{"token", "expires"}`), the expiry
    /// to stderr.
    fn token(config: &Target, as_json: bool) -> Result<u8, Stop> {
        let mut d = connect(config)?;
        let ans = d
            .client
            .call_answer(
                "api.token",
                Map::new(),
                Instant::now() + Duration::from_secs(10),
            )
            .map_err(|e| unavailable(broker::unreachable(&d.target, &e)))?;
        if ans.get("ok") != Some(&Value::Bool(true)) {
            return Err(refusal(&ans));
        }
        let s = |k: &str| ans.get(k).and_then(Value::as_str).unwrap_or_default();
        if as_json {
            outln!("{}", json!({"token": s("token"), "expires": s("expires")}));
        } else {
            outln!("{}", s("token"));
        }
        let tcp = if d.cfg.gateway.tcp.is_empty() {
            " ([gateway] tcp is not set: no TCP listener)".to_string()
        } else {
            format!(" for {}", d.cfg.gateway.tcp)
        };
        eprintln!("saiife: gateway token{tcp}, valid until {}", s("expires"));
        Ok(0)
    }

    fn list(config: &Target, a: &ApiArgs) -> Result<u8, Stop> {
        let filter = a.args.first();
        if a.args.len() > 1 {
            return Err(refused("usage: saiife api --list [<service>]"));
        }
        let mut d = connect(config)?;
        let (_, overlays, env) = project(&d);
        let mut args = Map::new();
        args.insert("overlays".into(), json!(overlays));
        if let Some(e) = env {
            args.insert("env".into(), e.into());
        }
        let ans = d
            .client
            .call_answer("api.list", args, Instant::now() + Duration::from_secs(10))
            .map_err(|e| unavailable(broker::unreachable(&d.target, &e)))?;
        if ans.get("ok") != Some(&Value::Bool(true)) {
            return Err(refusal(&ans));
        }
        env_warning(&ans);
        let services: Vec<Value> = ans
            .get("services")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|s| filter.is_none_or(|f| s["name"].as_str() == Some(f.as_str())))
            .collect();
        if a.json {
            outln!("{}", json!({ "services": services }));
            return Ok(0);
        }
        if services.is_empty() {
            outln!("no services (your user is in no scope, or its scope lists none)");
        }
        for s in &services {
            outln!("{}", s["name"].as_str().unwrap_or_default());
            for op in s["operations"].as_array().into_iter().flatten() {
                outln!(
                    "  {:<28} {:<24} {:<6} {}",
                    op["id"].as_str().unwrap_or_default(),
                    op["capability"].as_str().unwrap_or_default(),
                    op["kind"].as_str().unwrap_or_default(),
                    op["action"].as_str().unwrap_or_default()
                );
            }
        }
        Ok(0)
    }
}
