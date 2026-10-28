//! `saiife api`: connector calls through the daemon (spec §6.7.2). Linux
//! only. The upstream data goes to stdout, a one-line summary to stderr.
//! Exit codes: 0 done, 1 upstream status >= 400 or an upstream failure, 2
//! denied, 3 pending approval, 4 limit reached, 5 saiife unavailable.
//! `--wait` polls `api.result` every 2 s (at most 1 h, decision 3);
//! `saiife api result <id>` fetches a result later.
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
    /// `<service> <operation> [k=v ...]`, `[<service>]` with --list, or
    /// `token` (a 12 h bearer token for the gateway's TCP listener).
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
mod linux {
    use super::ApiArgs;
    use crate::broker::{self, Target};
    use base64::Engine as _;
    use saiife_agents::config::{find_project_root, read_config_bytes};
    use saiife_ipc::client::Client;
    use saiife_policy::{
        load_system, merge_project, parse_duration, parse_project, Mode, SystemConfig,
    };
    use serde_json::{json, Map, Value};
    use std::collections::BTreeMap;
    use std::io::Read;
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
    fn project(d: &Daemon) -> (String, BTreeMap<String, saiife_policy::ServiceOverlay>) {
        let cfg = &d.cfg;
        let mode = if d.target.is_locked() {
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
        let services = root
            .and_then(|r| match read_config_bytes(&r) {
                Ok(Some(b)) => match parse_project(&b) {
                    Ok(p) => Some(merge_project(&cfg.guard.packs, &p, mode).services),
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
            })
            .unwrap_or_default();
        (shown, services)
    }

    fn go(a: ApiArgs) -> Result<u8, Stop> {
        let config = broker::resolve_here(a.system_config.as_deref()).map_err(unavailable)?;
        if a.list {
            return list(&config, &a);
        }
        if a.args.len() == 1 && a.args[0] == "token" {
            return token(&config, a.json);
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
        let (project, overlays) = project(&d);
        let mut args = Map::new();
        args.insert("service".into(), service.clone().into());
        args.insert("operation".into(), operation.clone().into());
        args.insert("params".into(), Value::Object(params));
        args.insert("project".into(), project.into());
        if let Some(o) = overlays.get(service.as_str()) {
            args.insert("overlay".into(), json!(o));
        }
        if let Some(b) = &body {
            args.insert(
                "body_b64".into(),
                base64::engine::general_purpose::STANDARD.encode(b).into(),
            );
        }
        if let Some(w) = wait {
            let ms = w.as_millis().min(u128::from(u64::MAX)) as u64;
            args.insert("wait_ms".into(), ms.into());
        }
        // The daemon waits at most one upstream timeout for a pool slot and
        // one for the upstream; past both, plus slack, it is gone.
        let timeout = d.cfg.gateway.upstream_timeout * 2 + Duration::from_secs(15);
        let started = Instant::now();
        let ans = d
            .client
            .call_answer("api.call", args, Instant::now() + timeout)
            .map_err(|e| unavailable(broker::unreachable(&d.target, &e)))?;
        let ms = started.elapsed().as_millis();
        if ans.get("ok") != Some(&Value::Bool(true)) {
            return Err(refusal(&ans));
        }
        if let Some(id) = ans.get("pending").and_then(Value::as_u64) {
            return match wait {
                Some(w) => settle(&mut d, &a, id, Some(w)),
                None => Err(pending(id)),
            };
        }
        done(&a, &format!("{service} {operation}"), &ans, Some(ms))
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
        let body = ans
            .get("body_b64")
            .and_then(Value::as_str)
            .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
            .unwrap_or_default();
        let truncated = ans.get("truncated") == Some(&Value::Bool(true));
        if a.json {
            let parsed = serde_json::from_slice::<Value>(&body)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body).into_owned()));
            outln!(
                "{}",
                json!({
                    "status": status,
                    "headers": ans.get("headers").cloned().unwrap_or(json!([])),
                    "truncated": truncated,
                    "next": ans.get("next").cloned().unwrap_or(Value::Null),
                    "body": parsed,
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
        match ms {
            Some(ms) => eprintln!("saiife: {label} → {status} ({} bytes, {ms} ms)", body.len()),
            None => eprintln!("saiife: {label} → {status} ({} bytes)", body.len()),
        }
        if truncated {
            eprintln!("saiife: the response was cut at max_response_bytes");
        }
        if let Some(Value::Object(n)) = ans.get("next") {
            let kv: Vec<String> = n
                .iter()
                .map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or_default()))
                .collect();
            eprintln!("next: {}", kv.join(" "));
        }
        Ok(if status >= 400 { 1 } else { 0 })
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
        let (_, overlays) = project(&d);
        let mut args = Map::new();
        args.insert("overlays".into(), json!(overlays));
        let ans = d
            .client
            .call_answer("api.list", args, Instant::now() + Duration::from_secs(10))
            .map_err(|e| unavailable(broker::unreachable(&d.target, &e)))?;
        if ans.get("ok") != Some(&Value::Bool(true)) {
            return Err(refusal(&ans));
        }
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
