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

const INPUT_WIDTH: usize = 60;

pub fn parse_since(s: &str) -> Result<Duration, String> {
    let err =
        || format!("invalid --since {s:?}: use a whole number with m, h or d, e.g. 30m, 24h, 7d");
    if !s.is_ascii() || s.len() < 2 {
        return Err(err());
    }
    let (num, unit) = s.split_at(s.len() - 1);
    let n: i64 = num.parse().map_err(|_| err())?;
    if n <= 0 {
        return Err(err());
    }
    match unit {
        "m" => Ok(Duration::minutes(n)),
        "h" => Ok(Duration::hours(n)),
        "d" => Ok(Duration::days(n)),
        _ => Err(err()),
    }
}

pub fn render_table(records: &[&Record]) -> String {
    let row = |time: &str, agent: &str, decision: &str, pack: &str, input: &str| {
        format!("{time:<19}  {agent:<7}  {decision:<9}  {pack:<16}  {input}\n")
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

pub fn run(
    since: Option<&str>,
    project: Option<&str>,
    agent: Option<&str>,
    blocked: bool,
    report: Option<&str>,
    packs: &[Pack],
) -> ExitCode {
    let since_arg = since;
    let since = match since.map(parse_since).transpose() {
        Ok(d) => d.map(|d| OffsetDateTime::now_utc() - d),
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
        since,
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
    if let Some(target) = report {
        let now = OffsetDateTime::now_utc();
        let mut filters = Vec::new();
        if let Some(s) = since_arg {
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
        let mut model = report::build(&shown, packs, filters, since, now);
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
                println!(
                    "Report written: {} ({} decisions)",
                    abs.display(),
                    shown.len()
                );
                for problem in &model.log_problems {
                    println!("{problem}");
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
        println!("No audit records found in {}.", dir.display());
    } else {
        print!("{}", render_table(&shown));
    }
    if all.skipped_lines > 0 {
        println!("{} unreadable lines skipped", all.skipped_lines);
    }
    if all.unreadable_files > 0 {
        println!("{} unreadable files skipped", all.unreadable_files);
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
}
