//! `saiife api`: connector calls through the daemon (spec §6.7.2). Linux
//! only. The upstream data goes to stdout, a one-line summary to stderr.
//! Exit codes: 0 done, 1 upstream status >= 400 or an upstream failure, 2
//! denied, 3 pending (plan 11), 4 limit reached, 5 saiife unavailable.
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
    /// Wait this long for an approval (approvals come with plan 11).
    #[arg(long, value_name = "DURATION")]
    pub wait: Option<String>,
    /// The system config (default /etc/saiife/config.toml).
    #[arg(long = "system-config", hide = true)]
    pub system_config: Option<PathBuf>,
    /// `<service> <operation> [k=v ...]`, or `[<service>]` with --list.
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
    use base64::Engine as _;
    use saiife_agents::config::{find_project_root, read_config_bytes};
    use saiife_ipc::client::{system_uid, Client};
    use saiife_policy::{
        load_system, merge_project, parse_duration, parse_project, Mode, SystemConfig,
    };
    use serde_json::{json, Map, Value};
    use std::collections::BTreeMap;
    use std::io::Read;
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;
    use std::time::{Duration, Instant};

    const SYSTEM_CONFIG: &str = "/etc/saiife/config.toml";
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
    }

    fn connect(config: &Path) -> Result<Daemon, Stop> {
        let loaded = load_system(config)
            .map_err(|e| unavailable(format!("cannot read the system config: {e}")))?;
        if !loaded.config.locked {
            return Err(unavailable(format!(
                "{}: locked is not true",
                config.display()
            )));
        }
        let user = &loaded.config.daemon.user;
        let uid = system_uid(user)
            .ok_or_else(|| unavailable(format!("the daemon user {user} does not exist")))?;
        let client = Client::connect(
            &loaded.config.daemon.socket_dir,
            uid,
            Instant::now() + CONNECT_TIMEOUT,
        )
        .map_err(|e| unavailable(format!("cannot reach the saiife daemon: {e}")))?;
        Ok(Daemon {
            client,
            cfg: loaded.config,
        })
    }

    /// The project root (or the cwd) and its service overlays, merged as
    /// locked mode does (deny and ask only). An invalid project config is
    /// ignored with a warning; it can only have tightened.
    fn project(cfg: &SystemConfig) -> (String, BTreeMap<String, saiife_policy::ServiceOverlay>) {
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
                    Ok(p) => Some(merge_project(&cfg.guard.packs, &p, Mode::Locked).services),
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
        let config = a
            .system_config
            .clone()
            .unwrap_or_else(|| PathBuf::from(SYSTEM_CONFIG));
        if a.list {
            return list(&config, &a);
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
        let wait_ms = match &a.wait {
            Some(w) => Some(
                parse_duration(w)
                    .map_err(refused)?
                    .as_millis()
                    .min(u128::from(u64::MAX)) as u64,
            ),
            None => None,
        };
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
        let (project, overlays) = project(&d.cfg);
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
        if let Some(w) = wait_ms {
            args.insert("wait_ms".into(), w.into());
        }
        // The daemon waits at most one upstream timeout for a pool slot and
        // one for the upstream; past both, plus slack, it is gone.
        let timeout = d.cfg.gateway.upstream_timeout * 2 + Duration::from_secs(15);
        let started = Instant::now();
        let ans = d
            .client
            .call_answer("api.call", args, Instant::now() + timeout)
            .map_err(|e| unavailable(format!("cannot reach the saiife daemon: {e}")))?;
        let ms = started.elapsed().as_millis();
        if ans.get("ok") != Some(&Value::Bool(true)) {
            return Err(refusal(&ans));
        }
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
        eprintln!(
            "saiife: {service} {operation} → {status} ({} bytes, {ms} ms)",
            body.len()
        );
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
            _ => Stop(5, s("message").to_string()),
        }
    }

    fn list(config: &Path, a: &ApiArgs) -> Result<u8, Stop> {
        let filter = a.args.first();
        if a.args.len() > 1 {
            return Err(refused("usage: saiife api --list [<service>]"));
        }
        let mut d = connect(config)?;
        let (_, overlays) = project(&d.cfg);
        let mut args = Map::new();
        args.insert("overlays".into(), json!(overlays));
        let ans = d
            .client
            .call_answer("api.list", args, Instant::now() + Duration::from_secs(10))
            .map_err(|e| unavailable(format!("cannot reach the saiife daemon: {e}")))?;
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
