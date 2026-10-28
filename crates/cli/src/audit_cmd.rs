//! `saiife audit`: the audit log as a terminal table.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::audit_locked::{self, Source};
use crate::{report, report_html};
use saiifeguard::Pack;

use crate::text::sanitize;
use saiife_audit::store::{self, Filter};
use saiife_audit::{DecisionKind, Record};
use time::{Duration, OffsetDateTime};

/// What every `--broker` line says (plan 16).
pub const BROKER_LABEL: &str = "personal broker, not a security boundary";

/// The personal broker's audit dir, `$XDG_DATA_HOME/saiife/broker/audit`
/// (its fallback: `~/.local/share`). Reading the log does not need the
/// broker's runtime dir, so `XDG_RUNTIME_DIR` is not required here.
fn broker_audit_dir() -> Result<PathBuf, String> {
    let env = |k: &str| match k {
        "XDG_RUNTIME_DIR" => Some(std::ffi::OsString::from("/")),
        _ => std::env::var_os(k),
    };
    let home = std::env::var_os("HOME").map(PathBuf::from);
    saiife_system::personal::personal_paths(&env, home.as_deref()).map(|p| p.audit_dir)
}

/// `text` with every `audit chain` line labelled [`BROKER_LABEL`].
fn broker_labelled(text: &str) -> String {
    text.lines()
        .map(|l| {
            if l.starts_with("audit chain") {
                format!("{l} ({BROKER_LABEL})")
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `saiife audit verify --broker`: the personal broker's log, with the
/// developer reader, every summary line labelled.
fn verify_broker() -> ExitCode {
    let dir = match broker_audit_dir() {
        Ok(d) => d,
        Err(e) => {
            outln!(
                "audit chain: could not read the log: {} ({BROKER_LABEL})",
                sanitize(&e)
            );
            return ExitCode::from(2);
        }
    };
    let report = saiife_audit::verify(&dir);
    outln!(
        "{}\n  log: {} ({BROKER_LABEL})",
        broker_labelled(render_verify(&report).trim_end()),
        sanitize(&dir.display().to_string())
    );
    ExitCode::from(report.exit_code())
}

/// `saiife audit verify [--external <file|dir>]`: exit 0 intact, 1 broken,
/// 2 unreadable. Prints counts and file names only, never record content.
pub fn verify(external: Option<&Path>, system_config: Option<&Path>, broker: bool) -> ExitCode {
    if broker {
        return verify_broker();
    }
    let config = system_config.unwrap_or(Path::new(audit_locked::SYSTEM_CONFIG));
    let dir = match verify_dir(config) {
        Ok(dir) => dir,
        Err(e) => {
            outln!("audit chain: could not read the log: {}", sanitize(&e));
            return ExitCode::from(2);
        }
    };
    let log_line = format!("  log: {}", sanitize(&dir.display().to_string()));
    let Some(external) = external else {
        let report = saiife_audit::verify(&dir);
        outln!("{}\n{log_line}", render_verify(&report));
        return ExitCode::from(report.exit_code());
    };
    let report = saiife_audit::verify_external(&dir, external);
    outln!("{}", render_external(&report, &dir, external));
    ExitCode::from(report.exit_code())
}

const NOT_AN_AUDITOR: &str = "audit files need the saiife-audit group; ask an auditor";

/// The log `verify` checks, from the one locked-mode decision
/// ([`audit_locked::source`]). In locked mode it is `[audit] dir` of the
/// system config, for root and `saiife-audit` members only;
/// `$SAIIFE_AUDIT_DIR` overrides it in debug builds alone (tests, CI), so
/// a release build always checks the log the daemon writes. Otherwise it
/// is the user's own log (`$SAIIFE_AUDIT_DIR` honoured).
fn verify_dir(config: &Path) -> Result<PathBuf, String> {
    let (dir, auditor) = match audit_locked::source(Some(config))? {
        Source::Developer => {
            return store::default_dir().ok_or_else(|| "no audit directory".to_string());
        }
        Source::Direct { dir, .. } => (dir, true),
        Source::Daemon { dir, .. } => (dir, false),
    };
    if cfg!(debug_assertions) {
        if let Some(d) = std::env::var_os(store::DIR_ENV).filter(|d| Path::new(d).is_absolute()) {
            return Ok(PathBuf::from(d));
        }
    }
    if auditor {
        Ok(dir)
    } else {
        Err(NOT_AN_AUDITOR.into())
    }
}

/// The local report, then how it compares with the forwarded copy. Problems
/// in the copy itself are labelled `external copy damaged`, never blamed
/// on the local log.
pub fn render_external(r: &saiife_audit::ExternalReport, log: &Path, external: &Path) -> String {
    let mut out = render_verify(&r.local);
    out.push_str(&format!(
        "\n  log: {}\nexternal: {}\n",
        sanitize(&log.display().to_string()),
        sanitize(&external.display().to_string())
    ));
    let e = &r.external;
    if !e.read_errors.is_empty() {
        let errs: Vec<String> = e.read_errors.iter().map(|x| sanitize(x)).collect();
        out.push_str(&format!(
            "external copy: could not read it: {}",
            errs.join("; ")
        ));
        return out;
    }
    if !r.local.read_errors.is_empty() {
        out.truncate(out.trim_end().len());
        return out;
    }
    if e.breaks.is_empty() {
        let head = e.head.as_ref().map(|(s, _)| *s).unwrap_or(0);
        out.push_str(&format!(
            "external copy: intact ({} chained records, up to seq {head})\n",
            e.chained
        ));
    } else {
        let n = e.breaks.len();
        let s = if n == 1 { "" } else { "s" };
        out.push_str(&format!("external copy damaged ({n} problem{s})\n"));
        out.push_str(&render_breaks(&e.breaks));
    }
    if e.duplicates > 0 {
        out.push_str(&format!(
            "  {} resent lines skipped (forwarding delivers at least once)\n",
            e.duplicates
        ));
    }
    if e.chain.is_none() {
        out.push_str(
            "  the copy starts mid-chain: its checkpoints are vouched for by the local log\n",
        );
    }
    if let Some(host) = &r.external_host {
        out.push_str(&format!(
            "  note: the copy's files are named for host {}\u{2026}, not this machine\n",
            sanitize(&host.chars().take(12).collect::<String>())
        ));
    }
    let seq_list = |seqs: &[u64]| {
        let shown: Vec<String> = seqs.iter().take(MAX_BREAKS).map(u64::to_string).collect();
        let more = if seqs.len() > MAX_BREAKS {
            ", \u{2026}"
        } else {
            ""
        };
        format!("{}{more}", shown.join(", "))
    };
    let plural = |n: usize| if n == 1 { "" } else { "s" };
    if !r.missing_checkpoints.is_empty() {
        let n = r.missing_checkpoints.len();
        out.push_str(&format!(
            "local log REWRITTEN OR CUT: {n} checkpoint{} of the external copy not in it (head seq {})\n",
            plural(n),
            seq_list(&r.missing_checkpoints)
        ));
    }
    if !r.missing_near_damage.is_empty() {
        let n = r.missing_near_damage.len();
        out.push_str(&format!(
            "{n} checkpoint{} of the external copy missing locally (copy damaged nearby; head seq {})\n",
            plural(n),
            seq_list(&r.missing_near_damage)
        ));
    }
    for h in r.rewritten.iter().take(MAX_BREAKS) {
        if h.vouched {
            let after = h
                .after_checkpoint
                .map(|c| format!(" after seq {c}"))
                .unwrap_or_default();
            out.push_str(&format!(
                "local log REWRITTEN{after}: its seq {} differs from the external copy\n",
                h.seq
            ));
        } else {
            out.push_str(&format!(
                "seq {} differs between the local log and the last line of the external copy (one of them was changed)\n",
                h.seq
            ));
        }
    }
    if r.rewritten.len() > MAX_BREAKS {
        out.push_str(&format!(
            "  \u{2026} and {} more differing lines\n",
            r.rewritten.len() - MAX_BREAKS
        ));
    }
    if let Some((local, ext)) = r.cut_tail {
        out.push_str(&format!(
            "local log CUT OFF: it ends at seq {local}, the external copy reaches seq {ext}\n"
        ));
    }
    if r.missing_checkpoints.is_empty()
        && r.missing_near_damage.is_empty()
        && r.rewritten.is_empty()
        && r.cut_tail.is_none()
    {
        match r.compared {
            0 => out.push_str(
                "local log holds the external copy's lines; no checkpoint of the copy to compare\n",
            ),
            1 => out.push_str("the checkpoint of the external copy is in the local log\n"),
            n => out.push_str(&format!(
                "all {n} checkpoints of the external copy are in the local log\n"
            )),
        }
    }
    out.truncate(out.trim_end().len());
    out
}

const MAX_BREAKS: usize = 20;

fn render_breaks(breaks: &[saiife_audit::Break]) -> String {
    let mut out = String::new();
    for b in breaks.iter().take(MAX_BREAKS) {
        let seq = b.seq.map(|s| format!(", seq {s}")).unwrap_or_default();
        out.push_str(&format!(
            "  {} line {}{}: {}\n",
            sanitize(&b.file),
            b.line,
            seq,
            b.kind.describe()
        ));
    }
    if breaks.len() > MAX_BREAKS {
        out.push_str(&format!(
            "  \u{2026} and {} more\n",
            breaks.len() - MAX_BREAKS
        ));
    }
    out
}

pub fn render_verify(r: &saiife_audit::VerifyReport) -> String {
    if !r.read_errors.is_empty() {
        let errs: Vec<String> = r.read_errors.iter().map(|e| sanitize(e)).collect();
        return format!("audit chain: could not read the log: {}", errs.join("; "));
    }
    let mut out = String::new();
    if r.breaks.is_empty() {
        out.push_str("audit chain: intact\n");
    } else {
        let n = r.breaks.len();
        let s = if n == 1 { "" } else { "s" };
        out.push_str(&format!("audit chain: BROKEN ({n} problem{s})\n"));
        out.push_str(&render_breaks(&r.breaks));
    }
    if r.chained > 0 {
        let head = r.head.as_ref().map(|(s, _)| *s).unwrap_or(0);
        let chain = r
            .chain
            .as_deref()
            .map(|c| {
                format!(
                    ", chain {}\u{2026}",
                    sanitize(&c.chars().take(6).collect::<String>())
                )
            })
            .unwrap_or_default();
        out.push_str(&format!(
            "  records: {} chained (seq 0\u{2013}{head}){chain}\n",
            r.chained
        ));
    }
    if !r.v1_files.is_empty() {
        let files: Vec<String> = r.v1_files.iter().map(|f| sanitize(f)).collect();
        out.push_str(&format!("  not chained (v1): {}\n", files.join(", ")));
    }
    if let Some((seq, ts)) = &r.last_checkpoint {
        out.push_str(&format!(
            "  last checkpoint: seq {seq} at {}\n",
            sanitize(ts)
        ));
    }
    if let Some(key) = &r.key {
        out.push_str(&format!("  signed with key {}\n", sanitize(key)));
    } else if r.breaks.is_empty() {
        // The label follows the chain's genesis: a personal broker's chain
        // has no key either (§6.4.4), and is not developer mode.
        let who = match r.mode.as_deref() {
            Some("personal") => "personal broker",
            Some("locked") => "locked mode",
            _ => "developer mode",
        };
        out.push_str(&format!(
            "  {who}: no signing key, so this catches accidental edits, not deliberate rewrites.\n",
        ));
    }
    out.truncate(out.trim_end().len());
    out
}

const INPUT_WIDTH: usize = 60;

/// The one error text for a bad `--since` value.
fn since_error(s: &str) -> String {
    format!("invalid --since {s:?}: use a whole number with m, h or d, e.g. 30m, 24h, 7d")
}

pub fn parse_since(s: &str) -> Result<Duration, String> {
    let err = || since_error(s);
    if !s.is_ascii() || s.len() < 2 {
        return Err(err());
    }
    let (num, unit) = s.split_at(s.len() - 1);
    let n: i64 = num.parse().map_err(|_| err())?;
    if n <= 0 {
        return Err(err());
    }
    let unit_secs: i64 = match unit {
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return Err(err()),
    };
    // Checked: `Duration::days(n)` panics on overflow.
    n.checked_mul(unit_secs)
        .map(Duration::seconds)
        .ok_or_else(err)
}

pub fn render_table(records: &[&Record]) -> String {
    let row = |time: &str, agent: &str, decision: &str, pack: &str, input: &str| {
        format!("{time:<19}  {agent:<7}  {decision:<15}  {pack:<16}  {input}\n")
    };
    let mut out = row("TIME", "AGENT", "DECISION", "PACK", "INPUT");
    let (mut blocked, mut fail_open) = (0, 0);
    for r in records {
        let label = match r.decision {
            DecisionKind::Allow => "allowed",
            DecisionKind::Deny => {
                blocked += 1;
                "BLOCKED"
            }
            DecisionKind::ErrorAllowed => {
                fail_open += 1;
                "FAIL-OPEN"
            }
            DecisionKind::ErrorDenied => {
                blocked += 1;
                "blocked (error)"
            }
            DecisionKind::Ask => "asked",
            DecisionKind::Approved => "approved",
            DecisionKind::Rejected => "rejected",
            DecisionKind::Expired => "expired",
            DecisionKind::Unknown => "OTHER",
        };
        let time = sanitize(r.ts.get(..19).unwrap_or(&r.ts)).replace('T', " ");
        let input = if r.input.is_empty() {
            one_line(&format!("({})", r.reason.as_deref().unwrap_or("no input")))
        } else {
            one_line(&r.input)
        };
        out.push_str(&row(
            &time,
            &sanitize(&r.agent),
            label,
            &sanitize(r.pack.as_deref().unwrap_or("-")),
            &input,
        ));
    }
    out.push_str(&format!(
        "{} decisions · {blocked} blocked · {fail_open} fail-open\n",
        records.len()
    ));
    out
}

/// `sanitize`, then anything longer than `INPUT_WIDTH` is cut with `…`.
fn one_line(s: &str) -> String {
    let flat = sanitize(s);
    if flat.chars().count() <= INPUT_WIDTH {
        flat
    } else {
        let mut cut: String = flat.chars().take(INPUT_WIDTH - 1).collect();
        cut.push('…');
        cut
    }
}

/// `saiife-report-YYYY-MM-DD.html` for the UTC date of `now`.
pub fn default_report_name(now: OffsetDateTime) -> String {
    format!("saiife-report-{}.html", now.date())
}

/// Write `html` to `path` without ever following or clobbering anything but
/// a regular file: only `.html`/`.htm` names, no symlinks or directories as
/// the target, and a temp file in the same folder renamed into place.
pub fn write_report(path: &Path, html: &str) -> Result<(), String> {
    let ok_ext = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("html") || e.eq_ignore_ascii_case("htm"));
    if !ok_ext {
        return Err("the report file name must end in .html or .htm".to_string());
    }
    let shown = path.display();
    match std::fs::symlink_metadata(path) {
        Ok(m) if !m.is_file() => {
            return Err(format!(
                "{shown} is not a regular file; refusing to write the report"
            ));
        }
        _ => {}
    }
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
    let tmp = path.with_file_name(format!(
        ".{}.saiife-report-{}.tmp",
        name.unwrap_or_default(),
        std::process::id()
    ));
    write_via_temp(path, html, &tmp).map_err(|e| format!("cannot write {shown}: {e}"))
}

/// Create `tmp` (never an existing path), fill it, rename it over `path`.
/// The temp file is removed on failure only if this call created it.
fn write_via_temp(path: &Path, html: &str, tmp: &Path) -> std::io::Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Same sensitivity as the 0600 audit log.
        opts.mode(0o600);
    }
    let mut f = opts.open(tmp)?;
    let result = (|| {
        f.write_all(html.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(tmp);
    }
    result
}

/// The cutoff time for `--since`; an amount too large for the calendar is
/// the same error as any other bad value.
fn since_cutoff(s: &str) -> Result<OffsetDateTime, String> {
    let d = parse_since(s)?;
    OffsetDateTime::now_utc()
        .checked_sub(d)
        .ok_or_else(|| since_error(s))
}

/// `saiife audit [filters]`.
pub struct RunArgs<'a> {
    pub since: Option<&'a str>,
    pub project: Option<&'a str>,
    pub agent: Option<&'a str>,
    pub blocked: bool,
    /// `connector`, `approval` or `guard`.
    pub kind: Option<&'a str>,
    pub service: Option<&'a str>,
    pub report: Option<&'a str>,
    /// The system config (default /etc/saiife/config.toml); locked mode
    /// when it exists with `locked = true`.
    pub system_config: Option<PathBuf>,
    /// `--broker`: the personal broker's log (plan 16).
    pub broker: bool,
}

/// Records read from one place, with what had to be skipped.
struct Loaded {
    records: Vec<Record>,
    skipped_lines: usize,
    unreadable_files: usize,
    /// Shown in "No audit records found in …".
    place: String,
    /// The dir `--report` verifies; `None` through the daemon.
    verify_dir: Option<PathBuf>,
}

/// Every record in `dir`; `Err` (exit 1) when the dir cannot be listed.
fn load_dir(dir: &Path) -> Result<Loaded, ExitCode> {
    let all = store::read_all(dir);
    if let Some(e) = &all.dir_error {
        eprintln!(
            "saiife: the audit directory {} cannot be read: {e}",
            dir.display()
        );
        return Err(ExitCode::from(1));
    }
    Ok(Loaded {
        records: all.records,
        skipped_lines: all.skipped_lines,
        unreadable_files: all.unreadable_files,
        place: dir.display().to_string(),
        verify_dir: Some(dir.to_path_buf()),
    })
}

/// The records of `source`: the files, or the caller's own through the
/// daemon (exit 5 when it cannot be reached).
fn load_main(
    source: &Source,
    home_dir: Option<&Path>,
    q: audit_locked::QueryArgs,
) -> Result<Loaded, ExitCode> {
    match source {
        Source::Developer => {
            let Some(dir) = home_dir else {
                eprintln!("saiife: could not determine the audit directory");
                return Err(ExitCode::from(2));
            };
            load_dir(dir)
        }
        Source::Direct { dir, config } => match std::fs::read_dir(dir) {
            // An auditor by its groups whose read is refused anyway (a
            // group added since login, a changed mode): ask the daemon.
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!(
                    "saiife: cannot read {} directly (permission denied); asking the saiife daemon instead",
                    dir.display()
                );
                let daemon = Source::Daemon {
                    dir: dir.clone(),
                    config: config.clone(),
                };
                load_main(&daemon, home_dir, q)
            }
            _ => load_dir(dir),
        },
        Source::Daemon { config, .. } => match audit_locked::query(config, &q) {
            Ok((records, skipped)) => Ok(Loaded {
                records,
                skipped_lines: skipped,
                unreadable_files: 0,
                place: "your records from the saiife daemon".to_string(),
                verify_dir: None,
            }),
            Err(e) => {
                eprintln!("saiife: {}", sanitize(&e));
                Err(ExitCode::from(5))
            }
        },
    }
}

pub fn run(a: RunArgs<'_>, packs: &[Pack]) -> ExitCode {
    let (since_text, project, agent) = (a.since, a.project, a.agent);
    let (blocked, report_path) = (a.blocked, a.report);
    let since_time = match since_text.map(since_cutoff).transpose() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("saiife: {e}");
            return ExitCode::from(2);
        }
    };
    // `--broker` reads the personal broker's dir as developer mode does.
    let (source, home_dir) = if a.broker {
        match broker_audit_dir() {
            Ok(d) => (Source::Developer, Some(d)),
            Err(e) => {
                eprintln!("saiife: {} ({BROKER_LABEL})", sanitize(&e));
                return ExitCode::from(2);
            }
        }
    } else {
        match audit_locked::source(a.system_config.as_deref()) {
            Ok(s) => (s, store::default_dir()),
            Err(e) => {
                eprintln!("saiife: {}", sanitize(&e));
                return ExitCode::from(2);
            }
        }
    };
    let locked_dir = match &source {
        Source::Developer => None,
        Source::Direct { dir, .. } | Source::Daemon { dir, .. } => Some(dir.clone()),
    };
    // Through the daemon only --since narrows the query: the report's
    // host sections need every record of the period, and the other
    // filters are applied here, as for files read directly.
    let q = audit_locked::QueryArgs {
        since: since_time.map(|t| t.unix_timestamp()),
        ..Default::default()
    };
    let mut main = match load_main(&source, home_dir.as_deref(), q) {
        Ok(m) => m,
        Err(code) => return code,
    };
    if a.broker {
        main.place = format!("{} ({BROKER_LABEL})", main.place);
    }
    // Locked mode: the user's home log too, labelled (spec §6.4.5). A home
    // log that cannot be listed is left out.
    let home = match (&locked_dir, &home_dir) {
        (Some(l), Some(h)) if !audit_locked::same_dir(l, h) => {
            let all = store::read_all(h);
            all.dir_error.is_none().then(|| Loaded {
                records: all.records,
                skipped_lines: all.skipped_lines,
                unreadable_files: all.unreadable_files,
                place: h.display().to_string(),
                verify_dir: None,
            })
        }
        _ => None,
    };
    let filter = Filter {
        since: since_time,
        project: project.map(str::to_string),
        agent: agent.map(str::to_string),
        blocked_only: blocked,
    };
    let keep =
        |r: &&Record| filter.matches(r) && audit_locked::kind_service_match(r, a.kind, a.service);
    let shown: Vec<&Record> = main.records.iter().filter(keep).collect();
    let home_shown: Vec<&Record> = home
        .as_ref()
        .map(|h| h.records.iter().filter(keep).collect())
        .unwrap_or_default();
    if let Some(target) = report_path {
        let now = OffsetDateTime::now_utc();
        let mut filters = Vec::new();
        if let Some(s) = since_text {
            filters.push(format!("last {s}"));
        }
        if let Some(p) = project {
            filters.push(format!("project: {p}"));
        }
        if let Some(a) = agent {
            filters.push(format!("agent: {}", report::agent_label(a)));
        }
        if let Some(k) = a.kind {
            filters.push(format!("kind: {k}"));
        }
        if let Some(s) = a.service {
            filters.push(format!("service: {s}"));
        }
        if blocked {
            filters.push("only blocked actions".to_string());
        }
        let mut model = report::build(&shown, packs, filters, since_time, now);
        model.blocked_only = blocked;
        // Connector, approval, error_denied, restart and outage sections
        // honour --since only; --project/--agent/--blocked do not hide them.
        let host_filter = Filter {
            since: since_time,
            project: None,
            agent: None,
            blocked_only: false,
        };
        let host: Vec<&Record> = main
            .records
            .iter()
            .filter(|r| host_filter.matches(r))
            .collect();
        model.set_host_events(&host, now, project.is_some() || agent.is_some() || blocked);
        // Through the daemon (no dir to verify) the answer holds only the
        // caller's own records: no daemon or forward records to list.
        model.auditors_only_sections = main.verify_dir.is_none();
        model.chain = match &main.verify_dir {
            Some(dir) => report::chain_line(&saiife_audit::verify(dir)),
            None => "not checked: your records come through the saiife daemon (auditors run saiife audit verify)".to_string(),
        };
        if a.broker {
            model.chain = format!("{} ({BROKER_LABEL})", model.chain);
        }
        model.last_checkpoint = report::last_checkpoint(&main.records);
        if main.skipped_lines > 0 {
            model.log_problems.push(format!(
                "{} unreadable log lines were skipped; the log may be damaged or edited.",
                main.skipped_lines
            ));
        }
        if main.unreadable_files > 0 {
            model.log_problems.push(format!(
                "{} log files could not be read.",
                main.unreadable_files
            ));
        }
        if !home_shown.is_empty() {
            model.log_problems.push(format!(
                "{} records of your home log ({}) are not in this report.",
                home_shown.len(),
                audit_locked::V1_LABEL
            ));
        }
        let html = report_html::render(&model);
        let path = if target.is_empty() {
            PathBuf::from(default_report_name(now))
        } else {
            PathBuf::from(target)
        };
        return match write_report(&path, &html) {
            Ok(()) => {
                let abs = std::path::absolute(&path).unwrap_or(path);
                outln!(
                    "Report written: {} ({} decisions)",
                    abs.display(),
                    shown.len()
                );
                for problem in &model.log_problems {
                    outln!("{problem}");
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("saiife: {e}");
                ExitCode::from(2)
            }
        };
    }
    if a.broker && !shown.is_empty() {
        outln!(
            "{BROKER_LABEL}: {}",
            sanitize(
                &home_dir
                    .as_deref()
                    .unwrap_or(Path::new(""))
                    .display()
                    .to_string()
            )
        );
    }
    if shown.is_empty() {
        outln!("No audit records found in {}.", main.place);
    } else {
        out!("{}", render_table(&shown));
    }
    if main.skipped_lines > 0 {
        outln!("{} unreadable lines skipped", main.skipped_lines);
    }
    if main.unreadable_files > 0 {
        outln!("{} unreadable files skipped", main.unreadable_files);
    }
    if let Some(h) = &home {
        if !home_shown.is_empty() {
            outln!("\n{} ({}):", audit_locked::V1_LABEL, sanitize(&h.place));
            out!("{}", render_table(&home_shown));
        }
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use saiife_audit::NewRecord;
    use time::macros::datetime;

    fn rec(input: &str, decision: DecisionKind, pack: Option<&str>) -> Record {
        Record::at(
            NewRecord {
                agent: "claude",
                project: "/p",
                session: None,
                tool: "Bash",
                input,
                decision,
                pack,
                rule: None,
                reason: Some("why"),
                mode: "developer",
                policy: None,
                permission_mode: None,
            },
            "0.1.0",
            datetime!(2026-10-13 08:14:02.381 UTC),
        )
    }

    #[test]
    fn a_planted_temp_file_is_never_deleted() {
        let d = tempfile::tempdir().unwrap();
        let tmp = d.path().join(".r.html.saiife-report-1.tmp");
        std::fs::write(&tmp, "planted").unwrap();
        let target = d.path().join("r.html");
        assert!(write_via_temp(&target, "x", &tmp).is_err());
        assert_eq!(std::fs::read_to_string(&tmp).unwrap(), "planted");
        assert!(!target.exists());
    }

    #[test]
    fn parse_since_units() {
        assert_eq!(parse_since("30m"), Ok(Duration::minutes(30)));
        assert_eq!(parse_since("24h"), Ok(Duration::hours(24)));
        assert_eq!(parse_since("7d"), Ok(Duration::days(7)));
    }

    #[test]
    fn both_since_paths_share_one_text() {
        assert_eq!(parse_since("0x").unwrap_err(), since_error("0x"));
        assert_eq!(
            since_cutoff("99999999999999d").unwrap_err(),
            since_error("99999999999999d")
        );
    }

    #[test]
    fn since_overflow_is_an_error() {
        for bad in ["99999999999d", "9223372036854775807d", "99999999999999h"] {
            let e = since_cutoff(bad).unwrap_err();
            assert!(e.contains("invalid --since"), "{bad}: {e}");
        }
    }

    #[test]
    fn parse_since_rejects_bad_input() {
        for bad in ["", "7", "d", "7w", "-1d", "0d", "7дн", "1.5h"] {
            assert!(parse_since(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn table_rows_labels_and_summary() {
        let a = rec("ls", DecisionKind::Allow, None);
        let d = rec("rm -rf /", DecisionKind::Deny, Some("core.filesystem"));
        let e = rec("", DecisionKind::ErrorAllowed, None);
        let out = render_table(&[&a, &d, &e]);
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("TIME"));
        assert!(lines[1].starts_with("2026-10-13 08:14:02  claude   allowed"));
        assert!(
            lines[2].contains("BLOCKED")
                && lines[2].contains("core.filesystem")
                && lines[2].ends_with("rm -rf /")
        );
        assert!(lines[3].contains("FAIL-OPEN") && lines[3].ends_with("(why)"));
        assert_eq!(lines[4], "3 decisions · 1 blocked · 1 fail-open");
    }

    #[test]
    fn long_and_multiline_input_is_flattened_and_cut() {
        let long = format!("echo 'a\nb' {}", "x".repeat(200));
        let r = rec(&long, DecisionKind::Allow, None);
        let out = render_table(&[&r]);
        let row = out.lines().nth(1).unwrap();
        assert!(row.contains("echo 'a⏎b'"));
        assert!(row.ends_with('…'));
        let input_part = row.rsplit("  ").next().unwrap();
        assert_eq!(input_part.chars().count(), INPUT_WIDTH);
    }

    #[test]
    fn terminal_control_and_bidi_chars_are_escaped_in_every_field() {
        let evil = "\u{1b}[1A\u{1b}[2K\r\u{1b}[8m";
        let mut r = Record::at(
            NewRecord {
                agent: &format!("cl{evil}"),
                project: "/p",
                session: None,
                tool: "Bash",
                input: &format!("ls {evil} \u{202e}txt.exe \u{9b}2J \u{7f}"),
                decision: DecisionKind::Deny,
                pack: Some(&format!("pk{evil}")),
                rule: None,
                reason: Some(&format!("why{evil}\u{2066}")),
                mode: "developer",
                policy: None,
                permission_mode: None,
            },
            "0.1.0",
            datetime!(2026-10-13 08:14:02.381 UTC),
        );
        let out = render_table(&[&r]);
        for bad in ['\u{1b}', '\r', '\u{202e}', '\u{9b}', '\u{7f}', '\u{2066}'] {
            assert!(!out.contains(bad), "{bad:?} reached the terminal: {out:?}");
        }
        let row = out.lines().nth(1).unwrap();
        assert!(row.contains("cl\\x1b[1A"), "{row}");
        assert!(row.contains("pk\\x1b[1A"), "{row}");
        assert!(
            row.contains("ls \\x1b[1A\\x1b[2K\\x0d\\x1b[8m \\u{202E}txt.exe \\x9b2J \\x7f"),
            "{row}"
        );

        // Empty input shows the reason instead, also escaped; ts too.
        r.input.clear();
        r.ts = format!("2026-10-13T08:{evil}");
        let out = render_table(&[&r]);
        assert!(
            !out.contains('\u{1b}') && !out.contains('\u{2066}'),
            "{out:?}"
        );
        assert!(out.contains("(why\\x1b[1A"), "{out}");
    }

    #[test]
    fn width_counts_the_escaped_text() {
        let r = rec(&"\u{1b}".repeat(100), DecisionKind::Allow, None);
        let out = render_table(&[&r]);
        let input_part = out.lines().nth(1).unwrap().rsplit("  ").next().unwrap();
        assert_eq!(input_part.chars().count(), INPUT_WIDTH);
        assert!(input_part.starts_with("\\x1b\\x1b"));
    }

    #[test]
    fn error_denied_is_blocked_and_the_table_stays_aligned() {
        let d = rec("curl x", DecisionKind::ErrorDenied, Some("core.network"));
        let a = rec("ls", DecisionKind::Allow, Some("core.network"));
        let out = render_table(&[&d, &a]);
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[1].contains("blocked (error)"));
        assert_eq!(lines[3], "2 decisions · 1 blocked · 0 fail-open");
        let col = |l: &str, needle: &str| l.find(needle).unwrap();
        let pack = col(lines[0], "PACK");
        assert_eq!(col(lines[1], "core.network"), pack);
        assert_eq!(col(lines[2], "core.network"), pack);
    }
}
