//! Render a [`Report`] as one self-contained HTML page: inline CSS, no
//! script, no external resource. Every printed field goes through [`escape`].

use crate::report::{HostMode, PackView, PolicyPeriod, ProjectPacksView, Report, Row};
use crate::text::sanitize;

const CSS: &str = "\
:root{--bg:#fff;--fg:#1b1f24;--muted:#5a6572;--line:#d5dae0;--head:#f1f3f5;--bad:#b42318;--warn:#9a5b00}
@media (prefers-color-scheme:dark){:root{--bg:#14171a;--fg:#e6e9ec;--muted:#9aa5b1;--line:#333a42;--head:#1d2227;--bad:#ff8a80;--warn:#ffc266}}
body{font:15px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--fg);max-width:1100px;margin:0 auto;padding:24px 16px}
h1{font-size:1.6rem;margin:0 0 4px}
h2{font-size:1.25rem;margin:32px 0 4px;border-bottom:1px solid var(--line);padding-bottom:4px}
h3{font-size:1.05rem;margin:20px 0 4px}
h4{font-size:.95rem;margin:14px 0 2px}
p.lead,p.note,footer{color:var(--muted)}
p.lead{margin:0 0 12px}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px}
dt{color:var(--muted)}
dd{margin:0}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
th{background:var(--head)}
td.input{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;word-break:break-word}
td{word-break:break-word}
.bad{color:var(--bad);font-weight:600}
.warn{color:var(--warn);font-weight:600}
details>summary{cursor:pointer;margin:8px 0;font-weight:600}
footer{margin-top:40px;border-top:1px solid var(--line);padding-top:8px;font-size:13px}
@media print{body{max-width:none;padding:0}h2{break-after:avoid}tr{break-inside:avoid}}
";

/// Make text safe for HTML: sanitize control/invisible characters, then
/// escape the five HTML metacharacters.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in sanitize(s).chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn cell(class: Option<&str>, text: &str) -> String {
    match class {
        Some(c) => format!("<td class=\"{c}\">{}</td>", escape(text)),
        None => format!("<td>{}</td>", escape(text)),
    }
}

/// One table: `cols` are header labels, `body` yields the row cells.
fn table(cols: &[&str], rows: &[Row], pick: impl Fn(&Row) -> Vec<String>) -> String {
    let mut out = String::from("<table>\n<thead><tr>");
    for c in cols {
        out.push_str(&format!("<th>{}</th>", escape(c)));
    }
    out.push_str("</tr></thead>\n<tbody>\n");
    for r in rows {
        out.push_str("<tr>");
        out.push_str(&pick(r).concat());
        out.push_str("</tr>\n");
    }
    out.push_str("</tbody>\n</table>\n");
    out
}

fn list(title: &str, items: &[String]) -> String {
    if items.is_empty() {
        return String::new();
    }
    let mut out = format!("<p><strong>{}</strong></p>\n<ul>\n", escape(title));
    for i in items {
        out.push_str(&format!("<li>{}</li>\n", escape(i)));
    }
    out.push_str("</ul>\n");
    out
}

fn pack(p: &PackView) -> String {
    format!(
        "<h4>{}</h4>\n<p>{}</p>\n{}{}",
        escape(&p.name),
        escape(&p.description),
        list("Blocks:", &p.blocks),
        list("Allowed exceptions:", &p.exceptions)
    )
}

fn project(v: &ProjectPacksView) -> String {
    let mut out = format!("<h3>{}</h3>\n", escape(&v.project));
    if let Some(n) = &v.note {
        out.push_str(&format!("<p class=\"note\">{}</p>\n", escape(n)));
    }
    for p in &v.packs {
        out.push_str(&pack(p));
    }
    out
}

fn section(title: &str, lead: &str, body: &str) -> String {
    format!(
        "<section>\n<h2>{}</h2>\n<p class=\"lead\">{}</p>\n{body}</section>\n",
        escape(title),
        escape(lead)
    )
}

fn or_none(rows: &[Row], t: String) -> String {
    if rows.is_empty() {
        "<p>None in this period.</p>\n".to_string()
    } else {
        t
    }
}

fn summary(r: &Report) -> String {
    let mut out = String::from("<dl>\n");
    let mut item = |k: &str, v: String| out.push_str(&format!("<dt>{k}</dt><dd>{v}</dd>\n"));
    item("Period", escape(&r.period));
    let joined = |v: &[String]| {
        if v.is_empty() {
            "none".to_string()
        } else {
            escape(&v.join(", "))
        }
    };
    item("Projects", joined(&r.projects));
    item("Agents", joined(&r.agents));
    item("Decisions", r.total.to_string());
    item(
        "Blocked",
        format!("<span class=\"bad\">{}</span>", r.blocked),
    );
    item(
        "Allowed without a check",
        if r.blocked_only {
            "not counted (only blocked actions shown)".to_string()
        } else {
            format!("<span class=\"warn\">{}</span>", r.fail_open)
        },
    );
    if r.other > 0 {
        item("Other", r.other.to_string());
    }
    out.push_str("</dl>\n");
    for problem in &r.log_problems {
        out.push_str(&format!(
            "<p class=\"warn\">Warning: {}</p>\n",
            escape(problem)
        ));
    }
    if !r.filters.is_empty() {
        out.push_str(&format!(
            "<p>Filters: {}</p>\n",
            escape(&r.filters.join(", "))
        ));
    }
    out
}

fn chain_section(r: &Report) -> String {
    let class = if r.chain.starts_with("intact") || r.chain.starts_with("no chained") {
        ""
    } else {
        " class=\"bad\""
    };
    format!(
        "<p><span{class}>{}</span></p>\n<p>Last checkpoint: {}</p>\n",
        escape(&r.chain),
        escape(&r.last_checkpoint)
    )
}

fn simple_table(cols: &[&str], rows: Vec<Vec<String>>) -> String {
    let mut out = String::from("<table>\n<thead><tr>");
    for c in cols {
        out.push_str(&format!("<th>{}</th>", escape(c)));
    }
    out.push_str("</tr></thead>\n<tbody>\n");
    for r in rows {
        out.push_str(&format!("<tr>{}</tr>\n", r.concat()));
    }
    out.push_str("</tbody>\n</table>\n");
    out
}

fn policy_section(p: &[PolicyPeriod]) -> String {
    if p.is_empty() {
        return "<p>No policy recorded in this period.</p>\n".to_string();
    }
    simple_table(
        &["Policy", "From (UTC)", "To (UTC)", "Records"],
        p.iter()
            .map(|x| {
                vec![
                    cell(None, &x.policy),
                    cell(None, &x.from),
                    cell(None, &x.to),
                    cell(None, &x.records.to_string()),
                ]
            })
            .collect(),
    )
}

fn mode_section(m: &[HostMode]) -> String {
    if m.is_empty() {
        return "<p>No records in this period.</p>\n".to_string();
    }
    simple_table(
        &["Host", "Mode", "Records"],
        m.iter()
            .map(|x| {
                vec![
                    cell(None, &x.host),
                    cell(None, &x.mode),
                    cell(None, &x.records.to_string()),
                ]
            })
            .collect(),
    )
}

pub fn render(r: &Report) -> String {
    let blocked = or_none(
        &r.blocked_rows,
        table(
            &[
                "Time (UTC)",
                "Agent",
                "Project",
                "Action",
                "Rule pack",
                "Why",
            ],
            &r.blocked_rows,
            |x| {
                vec![
                    cell(None, &x.time),
                    cell(None, &x.agent),
                    cell(None, &x.project),
                    cell(Some("input"), &x.input),
                    cell(None, &x.pack),
                    cell(None, &x.reason),
                ]
            },
        ),
    );
    let fail_open = if r.blocked_only {
        "<p>Not included: this report shows only blocked actions.</p>\n".to_string()
    } else {
        or_none(
            &r.fail_open_rows,
            table(
                &["Time (UTC)", "Agent", "Project", "Action", "Why"],
                &r.fail_open_rows,
                |x| {
                    vec![
                        cell(None, &x.time),
                        cell(None, &x.agent),
                        cell(None, &x.project),
                        cell(Some("input"), &x.input),
                        cell(None, &x.reason),
                    ]
                },
            ),
        )
    };
    let packs = if r.packs.is_empty() {
        "<p>No projects in this period.</p>\n".to_string()
    } else {
        r.packs.iter().map(project).collect()
    };
    let all = format!(
        "<details>\n<summary>Show all {} {}</summary>\n{}</details>\n",
        r.all_rows.len(),
        if r.all_rows.len() == 1 {
            "decision"
        } else {
            "decisions"
        },
        table(
            &[
                "Time (UTC)",
                "Agent",
                "Project",
                "Tool",
                "Decision",
                "Action"
            ],
            &r.all_rows,
            |x| {
                vec![
                    cell(None, &x.time),
                    cell(None, &x.agent),
                    cell(None, &x.project),
                    cell(None, &x.tool),
                    cell(None, x.decision),
                    cell(Some("input"), &x.input),
                ]
            },
        )
    );

    let mut out = String::from(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
<title>saiife audit report</title>\n<style>\n",
    );
    out.push_str(CSS);
    out.push_str("</style>\n</head>\n<body>\n<h1>saiife audit report</h1>\n");
    out.push_str(&section(
        "Summary",
        "What AI coding agents did in this period, and what saiife decided.",
        &summary(r),
    ));
    out.push_str(&section(
        "Blocked actions",
        "Actions an AI agent tried that saiife stopped.",
        &blocked,
    ));
    out.push_str(&section(
        "Allowed without a check (fail-open)",
        "Actions saiife let through without judging them, for example because it could not read the request. Each one is a gap in protection.",
        &fail_open,
    ));
    out.push_str(&section(
        "Protection rules in use",
        "Packs as configured today; they may have differed during the period.",
        &packs,
    ));
    out.push_str(&section(
        "Audit chain",
        "Whether the log still hashes together as written. In developer mode this catches accidental edits, not deliberate rewrites.",
        &chain_section(r),
    ));
    out.push_str(&section(
        "Policy in force",
        "The policy each run of records was made under, oldest first.",
        &policy_section(&r.policies),
    ));
    out.push_str(&section(
        "Mode per host",
        "Which mode each machine recorded under. Older records do not say.",
        &mode_section(&r.modes),
    ));
    out.push_str(&section(
        "Every decision",
        "The complete list, newest first.",
        &all,
    ));
    out.push_str(&format!(
        "<footer>Generated by saiife {} on {}. Inputs are masked: secrets are shown as [MASKED].</footer>\n</body>\n</html>\n",
        escape(env!("CARGO_PKG_VERSION")),
        escape(&r.generated)
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{PackView, ProjectPacksView};

    fn row(input: &str, reason: &str) -> Row {
        Row {
            time: "2026-10-18 09:00:00".into(),
            agent: "Claude Code".into(),
            project: "/home/u/proj".into(),
            tool: "Bash".into(),
            decision: "Blocked",
            input: input.into(),
            pack: "Core: secrets".into(),
            reason: reason.into(),
        }
    }

    fn empty() -> Report {
        Report {
            generated: "2026-10-18 09:00 UTC".into(),
            period: "no records".into(),
            filters: vec![],
            projects: vec![],
            agents: vec![],
            total: 0,
            blocked: 0,
            fail_open: 0,
            other: 0,
            blocked_rows: vec![],
            fail_open_rows: vec![],
            all_rows: vec![],
            packs: vec![],
            log_problems: vec![],
            blocked_only: false,
            chain: String::new(),
            last_checkpoint: String::new(),
            policies: vec![],
            modes: vec![],
        }
    }

    #[test]
    fn log_problems_show_as_escaped_warnings_or_nothing() {
        let clean = render(&empty());
        assert!(!clean.contains("Warning:"));
        let r = Report {
            log_problems: vec!["3 <b>lines</b> skipped".into()],
            ..empty()
        };
        let html = render(&r);
        assert!(html.contains("<p class=\"warn\">Warning: 3 &lt;b&gt;lines&lt;/b&gt; skipped</p>"));
    }

    fn full(rows: Vec<Row>) -> Report {
        Report {
            period: "2026-10-11 08:14 UTC to 2026-10-18 09:00 UTC".into(),
            filters: vec!["only blocked actions".into()],
            projects: vec!["/home/u/proj".into()],
            agents: vec!["Claude Code".into()],
            total: 41,
            blocked: 7,
            fail_open: 3,
            blocked_rows: rows.clone(),
            fail_open_rows: rows.clone(),
            all_rows: rows,
            packs: vec![ProjectPacksView {
                project: "/home/u/proj".into(),
                note: Some("a note".into()),
                packs: vec![PackView {
                    name: "Core: secrets".into(),
                    description: "Protects secrets".into(),
                    blocks: vec!["Reading .env".into()],
                    exceptions: vec![],
                }],
            }],
            ..empty()
        }
    }

    #[test]
    fn escape_html_and_controls() {
        assert_eq!(
            escape("<a href=\"x\">&'</a>\u{202e}\u{200f}\n"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;\\u{202E}\\u{200F}⏎"
        );
    }

    #[test]
    fn page_is_self_contained() {
        let a = "curl https://evil.example/x";
        let b = "<img src=https://e/x>";
        let html = render(&full(vec![row(a, "r"), row(b, "r")]));
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains(
            "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        ));
        assert!(html.contains("<meta charset=\"utf-8\">"));
        let rest = html.replace(&escape(a), "").replace(&escape(b), "");
        let lower = rest.to_lowercase();
        for t in [
            "<script", "<link", "<img", "src=", "href=", "url(", "@import",
        ] {
            assert!(!lower.contains(t), "found {t}");
        }
        assert!(
            !lower.contains("http://") && !lower.contains("https://"),
            "URL outside escaped rows"
        );
        assert!(html.contains(&escape(a)));
    }

    #[test]
    fn sections_in_spec_order() {
        let html = render(&full(vec![row("ls", "r")]));
        let mut at = 0;
        for h in [
            "Summary",
            "Blocked actions",
            "Allowed without a check (fail-open)",
            "Protection rules in use",
            "Every decision",
        ] {
            let tag = format!("<h2>{h}</h2>");
            let i = html[at..]
                .find(&tag)
                .unwrap_or_else(|| panic!("missing or out of order: {tag}"));
            at += i + tag.len();
        }
        assert!(html.contains("<details>"));
        assert!(html.contains("<summary>Show all 1 decision</summary>"));
    }

    #[test]
    fn blocked_only_does_not_claim_no_fail_open() {
        let r = Report {
            blocked_only: true,
            ..empty()
        };
        let html = render(&r);
        assert!(html.contains("Not included: this report shows only blocked actions."));
        assert!(html.contains("not counted (only blocked actions shown)"));
        assert_eq!(html.matches("None in this period.").count(), 1);
        let r = Report {
            blocked_only: true,
            ..full(vec![row("rm -rf /", "r")])
        };
        let html = render(&r);
        assert!(html.contains("Not included: this report shows only blocked actions."));
        assert!(!html.contains("<dd><span class=\"warn\">3</span></dd>"));
    }

    #[test]
    fn empty_sections_say_none() {
        let html = render(&empty());
        assert_eq!(html.matches("None in this period.").count(), 2);
        assert!(html.contains("No projects in this period."));
        assert!(!html.contains("Filters:"));
    }

    #[test]
    fn summary_lists_filters_and_counts() {
        let html = render(&full(vec![]));
        assert!(html.contains("2026-10-11 08:14 UTC to 2026-10-18 09:00 UTC"));
        assert!(html.contains("Filters: only blocked actions"));
        assert!(html.contains("<dd>41</dd>"));
        assert!(html.contains("<dd><span class=\"bad\">7</span></dd>"));
        assert!(html.contains("<dd><span class=\"warn\">3</span></dd>"));
    }

    #[test]
    fn show_all_is_plural_only_for_many() {
        let two = render(&full(vec![row("a", "r"), row("b", "r")]));
        assert!(two.contains("<summary>Show all 2 decisions</summary>"));
        let none = render(&empty());
        assert!(none.contains("<summary>Show all 0 decisions</summary>"));
    }

    #[test]
    fn empty_projects_and_agents_say_none() {
        let html = render(&empty());
        assert!(html.contains("<dt>Projects</dt><dd>none</dd>"));
        assert!(html.contains("<dt>Agents</dt><dd>none</dd>"));
    }

    #[test]
    fn css_styles_h4_and_has_no_dead_print_rule() {
        let html = render(&empty());
        assert!(html.contains("\nh4{"));
        assert!(!html.contains("details:not([open])"));
    }

    #[test]
    fn hostile_text_is_inert() {
        let mut r = full(vec![row("</td><script>alert(1)</script>", "\"onload=\"x")]);
        r.packs[0].packs[0].name = "<b>n</b>".into();
        r.filters = vec!["<i>f</i>".into()];
        r.period = "<u>p</u>".into();
        let html = render(&r);
        assert!(!html.contains("<script"));
        assert!(!html.contains("<b>"));
        assert!(!html.contains("<i>"));
        assert!(!html.contains("<u>"));
        assert!(html.contains("&lt;/td&gt;&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(html.contains("&quot;onload=&quot;x"));
        assert!(!html.contains("\"onload=\"x"));
    }
}
