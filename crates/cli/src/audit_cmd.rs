//! `saiife audit`: the audit log as a terminal table.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::{report, report_html};
use saiifeguard::Pack;

use crate::text::sanitize;
use saiife_audit::store::{self, Filter};
use saiife_audit::{DecisionKind, Record};
use time::{Duration, OffsetDateTime};

/// `saiife audit verify [--external <file|dir>]`: exit 0 intact, 1 broken,
/// 2 unreadable. Prints counts and file names only, never record content.
pub fn verify(external: Option<&Path>, system_config: Option<&Path>) -> ExitCode {
    let config = system_config.unwrap_or(Path::new(SYSTEM_CONFIG));
    let dir = match verify_dir(config) {
        Ok(dir) => dir,
        Err(e) => {
            outln!("audit chain: could not read the log: {}", sanitize(&e));
            return ExitCode::from(2);
        }
    };
    let Some(external) = external else {
        let report = saiife_audit::verify(&dir);
        outln!("{}", render_verify(&report));
        return ExitCode::from(report.exit_code());
    };
    let report = saiife_audit::verify_external(&dir, external);
    outln!("{}", render_external(&report));
    ExitCode::from(report.exit_code())
}

const SYSTEM_CONFIG: &str = "/etc/saiife/config.toml";
const LOCKED_AUDIT_DIR: &str = "/var/log/saiife/audit";
const AUDIT_GROUP: &str = "saiife-audit";
const NOT_AN_AUDITOR: &str = "audit files need the saiife-audit group; ask an auditor";

/// The log `verify` checks: `$SAIIFE_AUDIT_DIR` when set; in locked mode
/// `[audit] dir` of the system config, for root and `saiife-audit` members
/// only; else the user's own log.
fn verify_dir(config: &Path) -> Result<PathBuf, String> {
    let explicit = std::env::var_os(store::DIR_ENV).is_some_and(|d| Path::new(&d).is_absolute());
    if !explicit {
        if let Some(dir) = locked_audit_dir(config)? {
            return if is_auditor() {
                Ok(dir)
            } else {
                Err(NOT_AN_AUDITOR.into())
            };
        }
    }
    store::default_dir().ok_or_else(|| "no audit directory".to_string())
}

/// `[audit] dir` when the system config says `locked = true`; `None` when
/// there is no config or it is not locked. Read as a raw table, like the
/// hook's system view, so a policy error elsewhere does not hide the log.
pub(crate) fn locked_audit_dir(config: &Path) -> Result<Option<PathBuf>, String> {
    let bad = |e: &str| format!("{}: {e}", config.display());
    let Some(bytes) =
        crate::system_view::read_regular(config, false, 1024 * 1024).map_err(|e| bad(&e))?
    else {
        return Ok(None);
    };
    let text = String::from_utf8(bytes).map_err(|_| bad("not valid UTF-8"))?;
    let table: toml::Table = text
        .parse()
        .map_err(|e: toml::de::Error| bad(e.message()))?;
    if table.get("locked").and_then(toml::Value::as_bool) != Some(true) {
        return Ok(None);
    }
    let dir = match table.get("audit").and_then(|a| a.get("dir")) {
        None => PathBuf::from(LOCKED_AUDIT_DIR),
        Some(toml::Value::String(d)) if Path::new(d).is_absolute() => PathBuf::from(d),
        Some(_) => return Err(bad("[audit] dir must be an absolute path")),
    };
    Ok(Some(dir))
}

/// Root, or a member of `saiife-audit` in this process's current groups.
#[cfg(target_os = "linux")]
fn is_auditor() -> bool {
    use rustix::process::{getegid, geteuid, getgroups};
    use saiife_policy::users::{Directory, Getent};
    if geteuid().is_root() {
        return true;
    }
    let Some(group) = Getent.group(AUDIT_GROUP) else {
        return false;
    };
    getegid().as_raw() == group.gid
        || getgroups().is_ok_and(|gs| gs.iter().any(|g| g.as_raw() == group.gid))
}

/// Locked mode is Linux-only in this version: only root reads its files.
#[cfg(all(unix, not(target_os = "linux")))]
fn is_auditor() -> bool {
    let _ = AUDIT_GROUP;
    rustix::process::geteuid().is_root()
}

#[cfg(not(unix))]
fn is_auditor() -> bool {
    let _ = AUDIT_GROUP;
    false
}

/// The local report, then how it compares with the forwarded copy. Problems
/// in the copy itself are labelled `external copy damaged`, never blamed
/// on the local log.
pub fn render_external(r: &saiife_audit::ExternalReport) -> String {
    let mut out = render_verify(&r.local);
    out.push('\n');
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
    if !r.missing_checkpoints.is_empty() {
        let n = r.missing_checkpoints.len();
        let seqs: Vec<String> = r
            .missing_checkpoints
            .iter()
            .take(MAX_BREAKS)
            .map(u64::to_string)
            .collect();
        let more = if n > MAX_BREAKS { ", \u{2026}" } else { "" };
        out.push_str(&format!(
            "local log REWRITTEN OR CUT: {n} checkpoint{} of the external copy not in it (head seq {}{more})\n",
            if n == 1 { "" } else { "s" },
            seqs.join(", ")
        ));
    }
    if let Some((local, ext)) = r.cut_tail {
        out.push_str(&format!(
            "local log CUT OFF: it ends at seq {local}, the external copy reaches seq {ext}\n"
        ));
    }
    if r.missing_checkpoints.is_empty() && r.cut_tail.is_none() {
        match r.compared {
            0 => out.push_str(
                "local log reaches the end of the external copy; no checkpoint of the copy to compare\n",
            ),
            1 => out.push_str("the checkpoint of the external copy is in the local log\n"),
            n => out.push_str(&format!(
                "all {n} checkpoints of the external copy are in the local log\n"
            )),
        }
    }
    let skipped = e.checkpoints.saturating_sub(r.compared);
    if skipped > 0 {
        let s = if skipped == 1 { "" } else { "s" };
        out.push_str(&format!(
            "  {skipped} checkpoint{s} of the copy not compared: damaged in the copy\n"
        ));
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
        out.push_str(
            "  developer mode: no signing key, so this catches accidental edits, not deliberate rewrites.\n",
        );
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

pub fn run(
    since_text: Option<&str>,
    project: Option<&str>,
    agent: Option<&str>,
    blocked: bool,
    report_path: Option<&str>,
    packs: &[Pack],
) -> ExitCode {
    let since_time = match since_text.map(since_cutoff).transpose() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("saiife: {e}");
            return ExitCode::from(2);
        }
    };
    let Some(dir) = store::default_dir() else {
        eprintln!("saiife: could not determine the audit directory");
        return ExitCode::from(2);
    };
    let filter = Filter {
        since: since_time,
        project: project.map(str::to_string),
        agent: agent.map(str::to_string),
        blocked_only: blocked,
    };
    let all = store::read_all(&dir);
    if let Some(e) = &all.dir_error {
        eprintln!(
            "saiife: the audit directory {} cannot be read: {e}",
            dir.display()
        );
        return ExitCode::from(1);
    }
    let shown: Vec<&Record> = all.records.iter().filter(|r| filter.matches(r)).collect();
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
        let host: Vec<&Record> = all
            .records
            .iter()
            .filter(|r| host_filter.matches(r))
            .collect();
        model.set_host_events(&host, now, project.is_some() || agent.is_some() || blocked);
        model.chain = report::chain_line(&saiife_audit::verify(&dir));
        model.last_checkpoint = report::last_checkpoint(&all.records);
        if all.skipped_lines > 0 {
            model.log_problems.push(format!(
                "{} unreadable log lines were skipped; the log may be damaged or edited.",
                all.skipped_lines
            ));
        }
        if all.unreadable_files > 0 {
            model.log_problems.push(format!(
                "{} log files could not be read.",
                all.unreadable_files
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
    if shown.is_empty() {
        outln!("No audit records found in {}.", dir.display());
    } else {
        out!("{}", render_table(&shown));
    }
    if all.skipped_lines > 0 {
        outln!("{} unreadable lines skipped", all.skipped_lines);
    }
    if all.unreadable_files > 0 {
        outln!("{} unreadable files skipped", all.unreadable_files);
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
    fn locked_audit_dir_reads_the_system_config() {
        let d = tempfile::tempdir().unwrap();
        let c = d.path().join("config.toml");
        assert_eq!(locked_audit_dir(&c), Ok(None), "no config: developer mode");
        std::fs::write(&c, "version = 2\n[audit]\ndir = \"/srv/a\"\n").unwrap();
        assert_eq!(locked_audit_dir(&c), Ok(None), "not locked");
        std::fs::write(&c, "version = 2\nlocked = true\n").unwrap();
        assert_eq!(
            locked_audit_dir(&c),
            Ok(Some(PathBuf::from("/var/log/saiife/audit")))
        );
        std::fs::write(
            &c,
            "version = 2\nlocked = true\n[audit]\ndir = \"/srv/a\"\n",
        )
        .unwrap();
        assert_eq!(locked_audit_dir(&c), Ok(Some(PathBuf::from("/srv/a"))));
        std::fs::write(&c, "version = 2\nlocked = true\n[audit]\ndir = \"rel\"\n").unwrap();
        assert!(locked_audit_dir(&c).is_err());
        std::fs::write(&c, "locked = [").unwrap();
        assert!(locked_audit_dir(&c).is_err());
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
