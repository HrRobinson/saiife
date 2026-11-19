//! `saiife blind ask | status | audit` (plan 48 T4): Data Shield through
//! the daemon's `blind.*` ops. Exit codes: 0 answered (or shown), 2 refused
//! (a refusal, a stop, a firewall block, the checker, a role), 5 unavailable
//! (the daemon, the vault, the name detector, Landlock, not Linux).
//!
//! Every string the daemon sends is printed through [`crate::text::sanitize`]
//! (JSON output through `box_cmd::ascii_json`): a dataset's names, a pick
//! label or the planner's intent never reach the terminal raw.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Subcommand;

#[cfg(target_os = "linux")]
mod ask;
#[cfg(target_os = "linux")]
mod prompt;

/// What `saiife blind` says on any other system (exit 5).
#[cfg(not(target_os = "linux"))]
pub const LINUX_ONLY: &str = "saiife: Data Shield runs on Linux in this release";

#[derive(Subcommand)]
pub enum BlindAction {
    /// Ask a question about a dataset. Names are resolved here, the method
    /// is planned on stand-ins and shown before it runs; the answer is
    /// computed locally and checked.
    Ask {
        /// The question, in English or Danish.
        question: String,
        /// The question needs judgment (the local composer: a later stage).
        #[arg(long)]
        judgment: bool,
        /// Print the exact request sent to the planner.
        #[arg(long)]
        show_sent: bool,
        /// The dataset to ask (default: the only one you may ask).
        #[arg(long)]
        dataset: Option<String>,
        /// Start a new session: earlier questions are forgotten.
        #[arg(long)]
        new_session: bool,
        /// Run the method without asking first (the preview is still the
        /// answer's method line). Refused for a dataset that needs the
        /// preview.
        #[arg(long)]
        yes: bool,
        /// At most this many rows in a list answer.
        #[arg(long)]
        limit: Option<u32>,
        /// The question's language: en or da (default: detected).
        #[arg(long)]
        lang: Option<String>,
    },
    /// The datasets, the calculator (its weaker label), the name detector,
    /// the cloud key and any warnings.
    Status {
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// What left for the planner, per ask: time, user, dataset, envelope
    /// hashes, personal values (always 0), refusals and touches.
    Audit {
        /// Only records newer than this, e.g. 30m, 24h, 7d.
        #[arg(long, default_value = "7d")]
        since: String,
        /// Only this user's asks (needs the auditor role: root or saiife-audit).
        #[arg(long)]
        user: Option<String>,
        /// Print the exact body sent with this sha256 (from the outbox).
        #[arg(long, value_name = "SHA256")]
        sent: Option<String>,
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
    },
}

/// Where `ask` reads its answers: the terminal, or a test's script.
#[cfg(target_os = "linux")]
pub(crate) trait Prompter {
    /// Prints `prompt` and reads one line (trimmed). `Err`: no answer (end
    /// of input, or the read failed).
    fn line(&mut self, prompt: &str) -> Result<String, String>;
    /// Someone can answer: a terminal (or, in debug builds,
    /// `SAIIFE_TEST_BLIND_STDIN=1`).
    fn is_interactive(&self) -> bool;
}

#[cfg(not(target_os = "linux"))]
pub fn run(config: Option<PathBuf>, a: BlindAction) -> ExitCode {
    let _ = (config, a);
    eprintln!("{LINUX_ONLY}");
    ExitCode::from(5)
}

#[cfg(all(test, not(target_os = "linux")))]
mod tests {
    use super::*;

    #[test]
    fn blind_is_linux_only() {
        assert_eq!(
            LINUX_ONLY,
            "saiife: Data Shield runs on Linux in this release"
        );
        let code = run(None, BlindAction::Status { json: false });
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(5)));
    }
}

#[cfg(target_os = "linux")]
pub fn run(config: Option<PathBuf>, a: BlindAction) -> ExitCode {
    let t = match crate::broker::resolve_here(config.as_deref()) {
        Ok(t) => t,
        Err(m) => {
            eprintln!("saiife: {}", crate::text::sanitize(&m));
            return ExitCode::from(5);
        }
    };
    let r = match a {
        BlindAction::Ask {
            question,
            judgment,
            show_sent,
            dataset,
            new_session,
            yes,
            limit,
            lang,
        } => ask::run(
            &t,
            ask::Args {
                question,
                judgment,
                show_sent,
                dataset,
                new_session,
                yes,
                limit,
                lang,
            },
            &mut prompt::Stdin::new(),
        ),
        BlindAction::Status { json } => imp::status(&t, json),
        BlindAction::Audit {
            since,
            user,
            sent,
            json,
        } => match sent {
            Some(sha) => imp::sent(&t, &sha, json),
            None => imp::audit(&t, &since, user.as_deref(), json),
        },
    };
    match r {
        Ok(code) => code,
        Err(imp::Stop::Refused(m)) => {
            eprintln!("saiife: {}", crate::text::sanitize(&m));
            ExitCode::from(2)
        }
        Err(imp::Stop::Unavailable(m)) => {
            eprintln!("saiife: {}", crate::text::sanitize(&m));
            ExitCode::from(5)
        }
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use crate::broker::{self, Target};
    use crate::text::sanitize;
    use saiife_ipc::client::ClientError;
    use serde_json::{json, Map, Value};
    use std::process::ExitCode;
    use std::time::{Duration, Instant};

    const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
    /// Status and audit reads.
    pub(super) const READ_TIMEOUT: Duration = Duration::from_secs(60);
    /// An ask step may call the planner up to four times and run the
    /// calculator.
    pub(super) const ASK_TIMEOUT: Duration = Duration::from_secs(600);
    /// At most this many `audit.query` pages (5000 records each).
    const MAX_PAGES: usize = 20;

    /// Why a command stopped: exit 2 or exit 5.
    pub(crate) enum Stop {
        Refused(String),
        Unavailable(String),
    }

    pub(super) type Args = Map<String, Value>;

    pub(super) fn args<const N: usize>(kv: [(&str, Value); N]) -> Args {
        kv.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
    }

    /// One call on a fresh connection. `unavailable` and a locked vault are
    /// exit 5, like a daemon that cannot be reached; every other refusal
    /// (bad_request, forbidden, busy) is 2.
    pub(super) fn call(t: &Target, op: &str, a: Args, timeout: Duration) -> Result<Args, Stop> {
        let down = |e: &ClientError| Stop::Unavailable(broker::unreachable(t, e));
        let mut c = broker::connect(t, Instant::now() + CONNECT_TIMEOUT).map_err(|e| down(&e))?;
        c.call(op, a, Instant::now() + timeout)
            .map_err(|e| match e {
                ClientError::Refused { code, message }
                    if code == "unavailable" || code == "vault_unavailable" =>
                {
                    Stop::Unavailable(message)
                }
                ClientError::Refused { message, .. } => Stop::Refused(message),
                other => down(&other),
            })
    }

    pub(super) fn s<'a>(v: &'a Value, k: &str) -> &'a str {
        v.get(k).and_then(Value::as_str).unwrap_or("")
    }

    fn u(v: &Value, k: &str) -> u64 {
        v.get(k).and_then(Value::as_u64).unwrap_or(0)
    }

    // ---------------------------------------------------------- status ----

    /// `saiife blind status [--json]`.
    pub(super) fn status(t: &Target, json: bool) -> Result<ExitCode, Stop> {
        let v = Value::Object(call(t, "blind.status", Map::new(), READ_TIMEOUT)?);
        if json {
            outln!("{}", crate::box_cmd::ascii_json(&v));
        } else {
            for l in status_lines(&v) {
                outln!("{l}");
            }
        }
        Ok(ExitCode::SUCCESS)
    }

    /// `1.2 MB` from bytes (decimal, one decimal place).
    fn mb(b: u64) -> String {
        format!("{:.1} MB", b as f64 / 1_000_000.0)
    }

    /// The name detector's line: its state, or a fetch's progress (C3).
    fn ner_line(n: &Value) -> String {
        let state = s(n, "state");
        match state {
            "ready" => {
                let labels: Vec<String> = n
                    .get("labels")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).map(sanitize).collect())
                    .unwrap_or_default();
                if labels.is_empty() {
                    "name detector: ready".into()
                } else {
                    format!("name detector: ready ({})", labels.join(", "))
                }
            }
            "fetching" => {
                let done = u(n, "bytes_done");
                let of = match n.get("bytes_total").and_then(Value::as_u64) {
                    Some(t) => format!("{} of {}", mb(done), mb(t)),
                    None => mb(done),
                };
                format!(
                    "name detector: fetching its {} file, {of}",
                    sanitize(s(n, "file"))
                )
            }
            "not_configured" | "" => {
                "name detector: not set up ([blind.ner] is not in policy)".into()
            }
            other => {
                let why = s(n, "reason");
                if why.is_empty() {
                    format!("name detector: {}", sanitize(other))
                } else {
                    format!("name detector: {}: {}", sanitize(other), sanitize(why))
                }
            }
        }
    }

    /// The role words of a dataset (`approver, user`).
    fn roles(r: &Value) -> String {
        let mut out = Vec::new();
        for k in ["admin", "approver", "user"] {
            if r.get(k).and_then(Value::as_bool) == Some(true) {
                out.push(k);
            }
        }
        if out.is_empty() {
            "none".into()
        } else {
            out.join(", ")
        }
    }

    /// The refresh a dataset needs, as a command.
    fn refresh_hint(name: &str) -> String {
        format!("  run: saiife blind data refresh --dataset {name}")
    }

    /// One dataset's lines.
    fn dataset_lines(d: &Value, out: &mut Vec<String>) {
        let name = sanitize(s(d, "name"));
        let state = s(d, "state");
        let head = match state {
            "live" => {
                let mut x = format!("dataset {name}: live");
                if !s(d, "built_at").is_empty() {
                    x.push_str(&format!(", built {}", sanitize(s(d, "built_at"))));
                }
                x
            }
            "refreshing" => {
                let p = d.get("progress").cloned().unwrap_or(Value::Null);
                format!(
                    "dataset {name}: refreshing ({} {}/{})",
                    sanitize(s(&p, "phase")),
                    u(&p, "done"),
                    u(&p, "total")
                )
            }
            "opening" => format!("dataset {name}: opening ({})", sanitize(s(d, "reason"))),
            "needs_refresh" => {
                format!(
                    "dataset {name}: needs a refresh: {}",
                    sanitize(s(d, "reason"))
                )
            }
            "not_built" => format!("dataset {name}: not built yet"),
            other => format!("dataset {name}: {}", sanitize(other)),
        };
        out.push(head);
        if state == "needs_refresh" || state == "not_built" {
            out.push(refresh_hint(&name));
        }
        if state == "live" {
            let rows: Vec<String> = d
                .get("rows")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|r| {
                            let t = r.get(0)?.as_str()?;
                            let b = r.get(1)?.as_str()?;
                            Some(format!("{} {}", sanitize(t), sanitize(b)))
                        })
                        .collect()
                })
                .unwrap_or_default();
            if !rows.is_empty() {
                out.push(format!("  rows: {}", rows.join(", ")));
            }
            if !s(d, "snapshot_sha256").is_empty() {
                out.push(format!("  snapshot: {}", sanitize(s(d, "snapshot_sha256"))));
            }
        }
        if let Some(k) = d.get("keys_version").and_then(Value::as_u64) {
            out.push(format!("  stand-in keys: version {k}"));
        }
        let m = d.get("methods").cloned().unwrap_or(Value::Null);
        let suspended = m
            .get("suspended")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        out.push(format!(
            "  approved methods: {} active, {suspended} suspended",
            u(&m, "active")
        ));
        out.push(format!(
            "  your role: {}",
            roles(d.get("role").unwrap_or(&Value::Null))
        ));
        for w in d
            .get("warnings")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            out.push(format!("  ! {}", sanitize(w)));
        }
    }

    /// `blind.status` as lines: the calculator first (its weaker label),
    /// the name detector, the cloud, the sessions, then each dataset with
    /// its warnings.
    pub(super) fn status_lines(v: &Value) -> Vec<String> {
        let mut out = Vec::new();
        let c = v.get("calculator").cloned().unwrap_or(Value::Null);
        let mut calc = format!("calculator: {}", sanitize(s(&c, "label")));
        if !s(&c, "landlock").is_empty() {
            calc.push_str(&format!(" (Landlock: {})", sanitize(s(&c, "landlock"))));
        }
        out.push(calc);
        if !s(&c, "gap").is_empty() {
            out.push(format!("  ! {}", sanitize(s(&c, "gap"))));
        }
        out.push(ner_line(v.get("ner").unwrap_or(&Value::Null)));
        let cloud = v.get("cloud").cloned().unwrap_or(Value::Null);
        let key = match cloud.get("secret_present").and_then(Value::as_bool) {
            Some(true) => "API key present",
            _ => "no API key",
        };
        out.push(format!(
            "cloud planner: {}, {key}",
            sanitize(s(&cloud, "model"))
        ));
        let yours = v.get("sessions").map(|x| u(x, "yours")).unwrap_or_default();
        out.push(format!("your sessions: {yours}"));
        let ds = v.get("datasets").and_then(Value::as_array);
        match ds {
            Some(list) if !list.is_empty() => {
                for d in list {
                    dataset_lines(d, &mut out);
                }
            }
            _ => out.push("no dataset you have a role on".into()),
        }
        out
    }

    // ----------------------------------------------------------- audit ----

    /// `saiife blind audit --sent <sha256>`: the outbox entry's body.
    pub(super) fn sent(t: &Target, sha: &str, json: bool) -> Result<ExitCode, Stop> {
        let v = call(
            t,
            "blind.outbox.show",
            args([("sha256", json!(sha))]),
            READ_TIMEOUT,
        )?;
        let e = v.get("entry").cloned().unwrap_or(Value::Null);
        if json {
            outln!("{}", crate::box_cmd::ascii_json(&e));
            return Ok(ExitCode::SUCCESS);
        }
        outln!(
            "sent {} · {} · ask {} · {}",
            sanitize(s(&e, "ts")),
            sanitize(s(&e, "dataset")),
            sanitize(s(&e, "ask")),
            sanitize(s(&e, "sha256"))
        );
        // The body as sent: JSON, re-encoded with every non-ASCII
        // character escaped (same data, nothing raw on the terminal).
        let body = s(&e, "body");
        match serde_json::from_str::<Value>(body) {
            Ok(b) => outln!("{}", crate::box_cmd::ascii_json(&b)),
            Err(_) => outln!("{}", sanitize(body)),
        }
        Ok(ExitCode::SUCCESS)
    }

    /// Every `blind_*` record since `since_secs` (all users with `all`).
    fn blind_records(t: &Target, since_secs: i64, all: bool) -> Result<Vec<Value>, Stop> {
        let mut out = Vec::new();
        let mut after: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let mut a = args([
                ("since", json!(since_secs)),
                ("kind_prefix", json!("blind_")),
                ("limit", json!(5000)),
            ]);
            if all {
                a.insert("all".into(), json!(true));
            }
            if let Some(n) = &after {
                a.insert("after".into(), json!(n));
            }
            let page = call(t, "audit.query", a, READ_TIMEOUT)?;
            if let Some(Value::Array(rs)) = page.get("records") {
                out.extend(rs.iter().cloned());
            }
            let more = page.get("more").and_then(Value::as_bool) == Some(true);
            let next = page.get("next").and_then(Value::as_str).map(str::to_string);
            match (more, next) {
                (true, Some(n)) if after.as_deref() != Some(n.as_str()) => after = Some(n),
                _ => return Ok(out),
            }
        }
        Ok(out)
    }

    /// One ask's records, in log order.
    pub(super) struct AskGroup {
        pub(super) ask: String,
        pub(super) records: Vec<Value>,
    }

    /// The records grouped by their `ask` id (first seen first); the ones
    /// without one (keys, refreshes, approvals, loosenings, touches) apart.
    pub(super) fn group(records: Vec<Value>) -> (Vec<AskGroup>, Vec<Value>) {
        let mut asks: Vec<AskGroup> = Vec::new();
        let mut other = Vec::new();
        for r in records {
            let id = s(&r, "ask").to_string();
            if id.is_empty() {
                other.push(r);
                continue;
            }
            match asks.iter_mut().find(|g| g.ask == id) {
                Some(g) => g.records.push(r),
                None => asks.push(AskGroup {
                    ask: id,
                    records: vec![r],
                }),
            }
        }
        (asks, other)
    }

    /// The first non-empty `k` among `rs`.
    fn first<'a>(rs: &'a [Value], k: &str) -> &'a str {
        rs.iter()
            .map(|r| s(r, k))
            .find(|x| !x.is_empty())
            .unwrap_or("")
    }

    /// One ask's summary as JSON (what `--json` prints and the lines show).
    pub(super) fn ask_json(g: &AskGroup) -> Value {
        let rs = &g.records;
        fn of<'a>(rs: &'a [Value], kind: &'a str) -> impl Iterator<Item = &'a Value> {
            rs.iter().filter(move |r| s(r, "kind") == kind)
        }
        let sends: Vec<Value> = of(rs, "blind_send")
            .map(|r| {
                json!({
                    "envelope_sha256": s(r, "envelope_sha256"),
                    "body_sha256": s(r, "body_sha256"),
                    "personal_values": u(r, "personal_values"),
                    "attempt": u(r, "attempt"),
                })
            })
            .collect();
        let mut refusals: Vec<String> = of(rs, "blind_check_refused")
            .map(|r| s(r, "reason").to_string())
            .collect();
        refusals.extend(
            of(rs, "blind_preview")
                .filter(|r| s(r, "outcome") == "stopped")
                .map(|_| "stopped".to_string()),
        );
        let touches: Vec<Value> = rs
            .iter()
            .filter(|r| !s(r, "touch").is_empty())
            .map(|r| json!({"kind": s(r, "kind"), "touch": s(r, "touch")}))
            .collect();
        let previews: Vec<&str> = of(rs, "blind_preview").map(|r| s(r, "outcome")).collect();
        let answered = of(rs, "blind_run").any(|r| !s(r, "answer_mac").is_empty());
        json!({
            "ask": g.ask,
            "ts": first(rs, "ts"),
            "user": first(rs, "user"),
            "dataset": first(rs, "dataset"),
            "approved_method": first(rs, "approved_method"),
            "sends": sends,
            "personal_values": sends.iter().map(|x| u(x, "personal_values")).sum::<u64>(),
            "preview": previews,
            "answered": answered,
            "refusals": refusals,
            "touches": touches,
        })
    }

    /// The lines of one ask.
    pub(super) fn ask_lines(a: &Value) -> Vec<String> {
        let mut out = vec![format!(
            "ask {}  {}  {}  {}",
            sanitize(s(a, "ask")),
            sanitize(s(a, "ts")),
            sanitize(s(a, "user")),
            sanitize(s(a, "dataset"))
        )];
        let sends = a
            .get("sends")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if sends.is_empty() {
            let how = if s(a, "approved_method").is_empty() {
                "nothing sent".to_string()
            } else {
                format!(
                    "nothing sent (approved method {})",
                    sanitize(s(a, "approved_method"))
                )
            };
            out.push(format!("  {how}"));
        }
        for x in &sends {
            out.push(format!(
                "  sent envelope {} (body {}) · {} personal values",
                sanitize(s(x, "envelope_sha256")),
                sanitize(s(x, "body_sha256")),
                u(x, "personal_values")
            ));
        }
        let preview: Vec<String> = a
            .get("preview")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(sanitize)
            .collect();
        if !preview.is_empty() {
            out.push(format!("  preview: {}", preview.join(", ")));
        }
        if a.get("answered").and_then(Value::as_bool) == Some(true) {
            out.push("  answered (checked)".into());
        }
        for r in a
            .get("refusals")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            out.push(format!("  refused: {}", sanitize(r)));
        }
        for t in a
            .get("touches")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            out.push(format!(
                "  touch ({}): {}",
                sanitize(s(t, "kind")),
                sanitize(s(t, "touch"))
            ));
        }
        out
    }

    /// A record of no ask (keys, refresh, approve, loosen, touch) as a line.
    fn other_line(r: &Value) -> String {
        let mut x = format!(
            "{}  {}  {}  {}",
            sanitize(s(r, "ts")),
            sanitize(s(r, "user")),
            sanitize(s(r, "kind")),
            sanitize(s(r, "dataset"))
        );
        for k in ["action", "method", "column", "purpose", "rule", "touch"] {
            if !s(r, k).is_empty() {
                x.push_str(&format!("  {k} {}", sanitize(s(r, k))));
            }
        }
        x
    }

    /// `saiife blind audit [--since] [--user] [--json]`.
    pub(super) fn audit(
        t: &Target,
        since: &str,
        user: Option<&str>,
        json: bool,
    ) -> Result<ExitCode, Stop> {
        let d = crate::audit_cmd::parse_since(since).map_err(Stop::Refused)?;
        let since_secs = time::OffsetDateTime::now_utc()
            .checked_sub(d)
            .map(|t| t.unix_timestamp())
            .ok_or_else(|| Stop::Refused(format!("invalid --since {since:?}")))?;
        // Another user's asks: only an auditor sees them (`all`); the
        // daemon refuses anyone else.
        let mut records = blind_records(t, since_secs, user.is_some())?;
        if let Some(u) = user {
            records.retain(|r| s(r, "user") == u);
        }
        let (asks, other) = group(records);
        let summaries: Vec<Value> = asks.iter().map(ask_json).collect();
        if json {
            let v = json!({"asks": summaries, "other": other});
            outln!("{}", crate::box_cmd::ascii_json(&v));
            return Ok(ExitCode::SUCCESS);
        }
        if summaries.is_empty() && other.is_empty() {
            outln!("no Data Shield records since {}", sanitize(since));
            return Ok(ExitCode::SUCCESS);
        }
        for a in &summaries {
            for l in ask_lines(a) {
                outln!("{l}");
            }
        }
        if !other.is_empty() {
            outln!("other records:");
            for r in &other {
                outln!("  {}", other_line(r));
            }
        }
        Ok(ExitCode::SUCCESS)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn status_shows_the_weaker_label_opening_fetch_and_refresh() {
            let v = json!({
                "calculator": {"label": "calculator not in a box (weaker)", "landlock": "none",
                               "gap": "no Landlock"},
                "ner": {"state": "fetching", "file": "model", "bytes_done": 1_500_000,
                        "bytes_total": 40_000_000},
                "cloud": {"secret_present": false, "model": "m"},
                "sessions": {"yours": 1},
                "datasets": [
                    {"name": "crm", "state": "opening", "reason": "the dataset is still opening",
                     "methods": {"active": 0, "suspended": []}, "role": {"user": true},
                     "warnings": []},
                    {"name": "old", "state": "live", "rows": [["customers", "100-999"]],
                     "methods": {"active": 2, "suspended": [{"id": "x"}]},
                     "role": {"approver": true, "user": true},
                     "warnings": ["old was built without its snapshot indexes: saiife blind data refresh --dataset old"]},
                    {"name": "gone", "state": "needs_refresh", "reason": "its keys were deleted",
                     "methods": {"active": 0, "suspended": []}, "role": {}, "warnings": []},
                ],
            });
            let l = status_lines(&v);
            assert_eq!(
                l[0],
                "calculator: calculator not in a box (weaker) (Landlock: none)"
            );
            assert_eq!(l[1], "  ! no Landlock");
            assert_eq!(
                l[2],
                "name detector: fetching its model file, 1.5 MB of 40.0 MB"
            );
            assert_eq!(l[3], "cloud planner: m, no API key");
            assert!(l.contains(&"dataset crm: opening (the dataset is still opening)".to_string()));
            assert!(l.contains(&"  your role: approver, user".to_string()));
            assert!(l.contains(&"  approved methods: 2 active, 1 suspended".to_string()));
            assert!(l.contains(&"  ! old was built without its snapshot indexes: saiife blind data refresh --dataset old".to_string()));
            assert!(l.contains(&"dataset gone: needs a refresh: its keys were deleted".to_string()));
            assert!(l.contains(&"  run: saiife blind data refresh --dataset gone".to_string()));
            // A failed fetch and a ready detector.
            assert_eq!(
                ner_line(&json!({"state": "failed", "reason": "bad pin"})),
                "name detector: failed: bad pin"
            );
            assert_eq!(
                ner_line(&json!({"state": "ready", "labels": ["PER"]})),
                "name detector: ready (PER)"
            );
        }

        #[test]
        fn records_group_by_ask() {
            let rs = vec![
                json!({"kind": "blind_ask", "ask": "a1", "ts": "t1", "user": "me", "dataset": "crm"}),
                json!({"kind": "blind_keys", "dataset": "crm", "action": "rotate", "ts": "t2"}),
                json!({"kind": "blind_send", "ask": "a1", "envelope_sha256": "sha256:e",
                       "body_sha256": "sha256:b", "personal_values": 0, "attempt": 1}),
                json!({"kind": "blind_ask", "ask": "a2", "ts": "t3", "user": "me", "dataset": "crm",
                       "approved_method": "m-1"}),
                json!({"kind": "blind_check_refused", "ask": "a1", "reason": "empty_result"}),
                json!({"kind": "blind_name", "ask": "a2", "touch": "ab c1"}),
            ];
            let (asks, other) = group(rs);
            assert_eq!(asks.len(), 2);
            assert_eq!(other.len(), 1);
            let a1 = ask_json(&asks[0]);
            assert_eq!(a1["refusals"], json!(["empty_result"]));
            assert_eq!(a1["personal_values"], 0);
            let l = ask_lines(&a1);
            assert_eq!(l[0], "ask a1  t1  me  crm");
            assert_eq!(
                l[1],
                "  sent envelope sha256:e (body sha256:b) · 0 personal values"
            );
            let l2 = ask_lines(&ask_json(&asks[1]));
            assert!(l2.contains(&"  nothing sent (approved method m-1)".to_string()));
            assert!(l2.contains(&"  touch (blind_name): ab c1".to_string()));
        }
    }
}
