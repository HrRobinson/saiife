//! `saiife audit`: the audit log as a terminal table.

use std::process::ExitCode;

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

/// Make log text safe to print: the log is written from agent-controlled
/// input, so terminal escapes (C0, DEL, C1 incl. CSI U+009B) and bidi
/// overrides must not reach the terminal. Newlines become `⏎`; every other
/// such char becomes a visible `\xNN` / `\u{NNNN}` escape.
fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => out.push('⏎'),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' => {
                out.push_str(&format!("\\u{{{:04X}}}", c as u32))
            }
            c => out.push(c),
        }
    }
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

pub fn run(
    since: Option<&str>,
    project: Option<&str>,
    agent: Option<&str>,
    blocked: bool,
) -> ExitCode {
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
    let shown: Vec<&Record> = all.records.iter().filter(|r| filter.matches(r)).collect();
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
