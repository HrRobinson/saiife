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
        };
        let time = r.ts.get(..19).unwrap_or(&r.ts).replace('T', " ");
        let input = if r.input.is_empty() {
            format!("({})", r.reason.as_deref().unwrap_or("no input"))
        } else {
            one_line(&r.input)
        };
        out.push_str(&row(
            &time,
            &r.agent,
            label,
            r.pack.as_deref().unwrap_or("-"),
            &input,
        ));
    }
    out.push_str(&format!(
        "{} decisions · {blocked} blocked · {fail_open} fail-open\n",
        records.len()
    ));
    out
}

/// Newlines become `⏎`; anything longer than `INPUT_WIDTH` is cut with `…`.
fn one_line(s: &str) -> String {
    let flat: String = s.chars().map(|c| if c == '\n' { '⏎' } else { c }).collect();
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
}
