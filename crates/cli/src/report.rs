//! The model behind `saiife audit --report`: records in, plain-language
//! report out. Text is stored raw; the HTML layer escapes it.

use std::cmp::Reverse;
use std::collections::BTreeSet;
use std::path::Path;

use saiife_audit::{DecisionKind, Record};
use saiifeguard::Pack;
use time::format_description::FormatItem;
use time::macros::format_description;
use time::OffsetDateTime;

use crate::project::project_packs;

const MINUTE_FMT: &[FormatItem<'static>] =
    format_description!("[year]-[month]-[day] [hour]:[minute]");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub generated: String,
    pub period: String,
    pub filters: Vec<String>,
    pub projects: Vec<String>,
    pub agents: Vec<String>,
    pub total: usize,
    pub blocked: usize,
    pub fail_open: usize,
    pub other: usize,
    pub blocked_rows: Vec<Row>,
    pub fail_open_rows: Vec<Row>,
    pub all_rows: Vec<Row>,
    pub packs: Vec<ProjectPacksView>,
    /// Gaps in the audit trail (unreadable lines or files); set by the caller.
    pub log_problems: Vec<String>,
    /// True when `--blocked` filtered the records, so fail-open events are not shown.
    pub blocked_only: bool,
    /// One-line chain status; set by the caller from `verify`.
    pub chain: String,
    /// Minute time of the newest checkpoint record, or `none`.
    pub last_checkpoint: String,
    pub policies: Vec<PolicyPeriod>,
    pub modes: Vec<HostMode>,
}

/// A run of consecutive records under one policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPeriod {
    pub policy: String,
    pub from: String,
    pub to: String,
    pub records: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostMode {
    pub host: String,
    pub mode: String,
    pub records: usize,
}

/// The one-line chain status for the report.
pub fn chain_line(v: &saiife_audit::VerifyReport) -> String {
    if !v.read_errors.is_empty() {
        return "could not be read".to_string();
    }
    if let Some(b) = v.first_break() {
        return format!("broken: {} line {}: {}", b.file, b.line, b.kind.describe());
    }
    if v.chained == 0 {
        return "no chained records yet".to_string();
    }
    format!("intact ({} records)", v.chained)
}

/// Time of the newest checkpoint record among `records` (all kinds).
pub fn last_checkpoint(records: &[Record]) -> String {
    records
        .iter()
        .filter(|r| r.kind() == "checkpoint")
        .filter_map(|r| r.timestamp())
        .max()
        .map_or_else(|| "none".to_string(), fmt_minute)
}

fn short_policy(p: &str) -> String {
    let hex = p.strip_prefix("sha256:").unwrap_or(p);
    format!("sha256:{}", hex.chars().take(12).collect::<String>())
}

fn policy_periods(sorted_asc: &[&Record]) -> Vec<PolicyPeriod> {
    let mut out: Vec<PolicyPeriod> = Vec::new();
    for r in sorted_asc {
        let Some(p) = r.policy.as_deref() else {
            continue;
        };
        let p = short_policy(p);
        let at = r.timestamp().map(fmt_minute).unwrap_or_default();
        match out.last_mut() {
            Some(last) if last.policy == p => {
                last.to = at;
                last.records += 1;
            }
            _ => out.push(PolicyPeriod {
                policy: p,
                from: at.clone(),
                to: at,
                records: 1,
            }),
        }
    }
    out
}

fn host_modes(records: &[&Record]) -> Vec<HostMode> {
    let mut map: std::collections::BTreeMap<(String, String), usize> = Default::default();
    for r in records {
        let host = r
            .host
            .as_deref()
            .map_or_else(|| "unknown".to_string(), |h| h.chars().take(12).collect());
        let mode = r.mode.clone().unwrap_or_else(|| "unknown".to_string());
        *map.entry((host, mode)).or_default() += 1;
    }
    map.into_iter()
        .map(|((host, mode), records)| HostMode {
            host,
            mode,
            records,
        })
        .collect()
}

fn is_blocked(d: DecisionKind) -> bool {
    matches!(d, DecisionKind::Deny | DecisionKind::ErrorDenied)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub time: String,
    pub agent: String,
    pub project: String,
    pub tool: String,
    pub decision: &'static str,
    pub input: String,
    pub pack: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectPacksView {
    pub project: String,
    pub note: Option<String>,
    pub packs: Vec<PackView>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackView {
    pub name: String,
    pub description: String,
    pub blocks: Vec<String>,
    pub exceptions: Vec<String>,
}

/// Display name for an agent id; unknown ids are shown as they are.
pub fn agent_label(id: &str) -> String {
    match id {
        "claude" => "Claude Code",
        "codex" => "Codex",
        "gemini" => "Gemini CLI",
        other => other,
    }
    .to_string()
}

fn fmt_minute(t: OffsetDateTime) -> String {
    t.to_offset(time::UtcOffset::UTC)
        .format(MINUTE_FMT)
        .map(|s| format!("{s} UTC"))
        .unwrap_or_default()
}

fn decision_label(d: DecisionKind) -> &'static str {
    match d {
        DecisionKind::Allow => "Allowed",
        DecisionKind::Deny => "Blocked",
        DecisionKind::ErrorAllowed => "Allowed unchecked (fail-open)",
        DecisionKind::ErrorDenied => "Blocked (error)",
        DecisionKind::Ask => "Asked",
        DecisionKind::Approved => "Approved",
        DecisionKind::Rejected => "Rejected",
        DecisionKind::Expired => "Expired",
        DecisionKind::Unknown => "Other",
    }
}

fn row(r: &Record, packs: &[Pack]) -> Row {
    let pack = match r.pack.as_deref() {
        None => String::new(),
        Some(id) => packs
            .iter()
            .find(|p| p.id == id)
            .map_or_else(|| id.to_string(), |p| p.name.clone()),
    };
    Row {
        time: r.ts.get(..19).unwrap_or(&r.ts).replace('T', " "),
        agent: agent_label(&r.agent),
        project: r.project.clone(),
        tool: r.tool.clone(),
        decision: decision_label(r.decision),
        input: if r.input.is_empty() {
            "(no input recorded)".to_string()
        } else {
            r.input.clone()
        },
        pack,
        reason: r.reason.clone().unwrap_or_default(),
    }
}

fn unique<'a>(reasons: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for r in reasons.filter(|r| !r.is_empty()) {
        if !out.iter().any(|o| o == r) {
            out.push(r.to_string());
        }
    }
    out
}

fn pack_view(p: &Pack) -> PackView {
    PackView {
        name: p.name.clone(),
        description: p.description.clone(),
        blocks: unique(
            p.deny
                .iter()
                .map(|r| r.reason.as_str())
                .chain(p.deny_path.iter().map(|r| r.reason.as_str())),
        ),
        exceptions: unique(
            p.allow
                .iter()
                .map(|r| r.reason.as_str())
                .chain(p.allow_path.iter().map(|r| r.reason.as_str())),
        ),
    }
}

fn same_dir(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

fn project_view(project: &str, packs: &[Pack]) -> ProjectPacksView {
    let path = Path::new(project);
    // Same nearest-parent lookup as the guard (`check`, `status`). An empty
    // project never resolves against the reader's working directory, and a
    // folder that is gone is not walked upward.
    let (enabled, note) = if project.is_empty() || path.is_relative() {
        (
            Vec::new(),
            Some("Unknown project folder; the default packs are shown.".to_string()),
        )
    } else if !path.exists() {
        (
            Vec::new(),
            Some("This folder no longer exists; the default packs are shown.".to_string()),
        )
    } else {
        let found = project_packs(path, packs);
        match found.root.as_deref() {
            None => (
                Vec::new(),
                Some(
                    "No saiife config in this folder now; the default packs are shown.".to_string(),
                ),
            ),
            Some(root) if saiife_agents::config::load(root).is_err() => (
                Vec::new(),
                Some(format!(
                    "The saiife config in {} could not be read; the default packs are shown.",
                    root.display()
                )),
            ),
            Some(root) if same_dir(root, path) => (found.enabled, None),
            Some(root) => (
                found.enabled,
                Some(format!("Uses the saiife config in {}.", root.display())),
            ),
        }
    };
    // Default-on packs in built-in order, then enabled opt-ins in built-in order.
    let active = packs
        .iter()
        .filter(|p| p.default_on)
        .chain(
            packs
                .iter()
                .filter(|p| !p.default_on && enabled.contains(&p.id)),
        )
        .map(pack_view)
        .collect();
    ProjectPacksView {
        project: project.to_string(),
        note,
        packs: active,
    }
}

pub fn build(
    records: &[&Record],
    packs: &[Pack],
    filters: Vec<String>,
    since: Option<OffsetDateTime>,
    now: OffsetDateTime,
) -> Report {
    // Newest first; a record whose ts does not parse sorts last.
    let mut sorted: Vec<&Record> = records.to_vec();
    sorted.sort_by_key(|r| Reverse(r.timestamp()));

    let period = match since {
        Some(s) => format!("{} to {}", fmt_minute(s), fmt_minute(now)),
        None => {
            let times: Vec<OffsetDateTime> = records.iter().filter_map(|r| r.timestamp()).collect();
            match (times.iter().min(), times.iter().max()) {
                (Some(a), Some(b)) => format!("{} to {}", fmt_minute(*a), fmt_minute(*b)),
                _ => "no records".to_string(),
            }
        }
    };

    let all_rows: Vec<Row> = sorted.iter().map(|r| row(r, packs)).collect();
    let rows_of = |want: fn(DecisionKind) -> bool| -> Vec<Row> {
        sorted
            .iter()
            .zip(&all_rows)
            .filter(|(r, _)| want(r.decision))
            .map(|(_, row)| row.clone())
            .collect()
    };
    let blocked_rows = rows_of(is_blocked);
    let fail_open_rows = rows_of(|d| d == DecisionKind::ErrorAllowed);

    let mut ascending: Vec<&Record> = sorted.clone();
    ascending.reverse();
    let policies = policy_periods(&ascending);
    let modes = host_modes(records);

    let projects: BTreeSet<&str> = records.iter().map(|r| r.project.as_str()).collect();
    let agents: BTreeSet<String> = records.iter().map(|r| agent_label(&r.agent)).collect();

    Report {
        generated: fmt_minute(now),
        period,
        filters,
        projects: projects.iter().map(|p| p.to_string()).collect(),
        agents: agents.into_iter().collect(),
        total: records.len(),
        blocked: blocked_rows.len(),
        fail_open: fail_open_rows.len(),
        other: records
            .iter()
            .filter(|r| r.decision == DecisionKind::Unknown)
            .count(),
        blocked_rows,
        fail_open_rows,
        all_rows,
        packs: projects.iter().map(|p| project_view(p, packs)).collect(),
        log_problems: vec![],
        blocked_only: false,
        chain: "no chained records yet".to_string(),
        last_checkpoint: "none".to_string(),
        policies,
        modes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use saiife_agents::config::CONFIG_REL;
    use saiife_audit::NewRecord;
    use saiifeguard::builtins::builtin_packs;
    use time::macros::datetime;

    fn rec(
        project: &str,
        input: &str,
        decision: DecisionKind,
        pack: Option<&str>,
        at: OffsetDateTime,
    ) -> Record {
        Record::at(
            NewRecord {
                agent: "claude",
                project,
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
            at,
        )
    }

    #[test]
    fn summary_counts_and_labels() {
        let (packs, _) = builtin_packs();
        let rs = [
            rec(
                "/p",
                "ls",
                DecisionKind::Allow,
                None,
                datetime!(2026-10-13 08:00:00 UTC),
            ),
            rec(
                "/p",
                "cat .env",
                DecisionKind::Deny,
                Some("core.secrets"),
                datetime!(2026-10-13 08:10:00 UTC),
            ),
            rec(
                "/p",
                "cat .env",
                DecisionKind::Deny,
                Some("core.secrets"),
                datetime!(2026-10-13 08:20:00 UTC),
            ),
            rec(
                "/p",
                "x",
                DecisionKind::ErrorAllowed,
                None,
                datetime!(2026-10-13 08:05:00 UTC),
            ),
        ];
        let refs: Vec<&Record> = rs.iter().collect();
        let r = build(&refs, &packs, vec![], None, datetime!(2026-10-18 09:12 UTC));
        assert_eq!(r.generated, "2026-10-18 09:12 UTC");
        assert_eq!((r.total, r.blocked, r.fail_open, r.other), (4, 2, 1, 0));
        assert_eq!(r.blocked_rows.len(), 2);
        assert_eq!(r.blocked_rows[0].pack, "Core: secrets");
        assert_eq!(r.blocked_rows[0].decision, "Blocked");
        assert_eq!(r.all_rows[0].time, "2026-10-13 08:20:00");
        assert_eq!(
            r.fail_open_rows[0].decision,
            "Allowed unchecked (fail-open)"
        );
        assert_eq!(r.agents, ["Claude Code"]);
        assert_eq!(agent_label("claude"), "Claude Code");
        assert_eq!(agent_label("codex"), "Codex");
        assert_eq!(agent_label("gemini"), "Gemini CLI");
        assert_eq!(agent_label("x"), "x");
    }

    #[test]
    fn period_uses_since_or_record_span() {
        let (packs, _) = builtin_packs();
        let now = datetime!(2026-10-18 09:00 UTC);
        let rs = [
            rec(
                "/p",
                "a",
                DecisionKind::Allow,
                None,
                datetime!(2026-10-13 08:14:02 UTC),
            ),
            rec(
                "/p",
                "b",
                DecisionKind::Allow,
                None,
                datetime!(2026-10-15 10:30:00 UTC),
            ),
        ];
        let refs: Vec<&Record> = rs.iter().collect();
        let since = Some(datetime!(2026-10-11 08:14 UTC));
        assert_eq!(
            build(&refs, &packs, vec![], since, now).period,
            "2026-10-11 08:14 UTC to 2026-10-18 09:00 UTC"
        );
        assert_eq!(
            build(&refs, &packs, vec![], None, now).period,
            "2026-10-13 08:14 UTC to 2026-10-15 10:30 UTC"
        );
        assert_eq!(build(&[], &packs, vec![], None, now).period, "no records");
    }

    #[test]
    fn empty_report() {
        let (packs, _) = builtin_packs();
        let r = build(&[], &packs, vec![], None, datetime!(2026-10-18 09:00 UTC));
        assert_eq!((r.total, r.blocked, r.fail_open, r.other), (0, 0, 0, 0));
        assert!(r.blocked_rows.is_empty() && r.fail_open_rows.is_empty() && r.all_rows.is_empty());
        assert!(r.packs.is_empty() && r.projects.is_empty() && r.agents.is_empty());
    }

    #[test]
    fn unknown_decision_is_listed() {
        let (packs, _) = builtin_packs();
        let base = rec(
            "/p",
            "x",
            DecisionKind::Deny,
            None,
            datetime!(2026-10-13 08:00:00 UTC),
        );
        let json = serde_json::to_string(&base)
            .unwrap()
            .replace("\"deny\"", "\"later\"");
        let parsed: Record = serde_json::from_str(&json).unwrap();
        let r = build(
            &[&parsed],
            &packs,
            vec![],
            None,
            datetime!(2026-10-18 09:00 UTC),
        );
        assert_eq!(r.other, 1);
        assert_eq!(r.all_rows.len(), 1);
        assert_eq!(r.all_rows[0].decision, "Other");
    }

    #[test]
    fn active_packs_per_project() {
        let (packs, _) = builtin_packs();
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".saiife")).unwrap();
        std::fs::write(dir.path().join(CONFIG_REL), "packs = [\"db.postgres\"]\n").unwrap();
        let proj = dir.path().to_str().unwrap();
        let rs = [rec(
            proj,
            "x",
            DecisionKind::Allow,
            None,
            datetime!(2026-10-13 08:00:00 UTC),
        )];
        let refs: Vec<&Record> = rs.iter().collect();
        let r = build(&refs, &packs, vec![], None, datetime!(2026-10-18 09:00 UTC));
        let view = &r.packs[0];
        assert_eq!(view.note, None);
        let mut want: Vec<String> = packs
            .iter()
            .filter(|p| p.default_on)
            .map(|p| p.name.clone())
            .collect();
        want.extend(
            packs
                .iter()
                .filter(|p| p.id == "db.postgres")
                .map(|p| p.name.clone()),
        );
        let got: Vec<String> = view.packs.iter().map(|p| p.name.clone()).collect();
        assert_eq!(got, want);
        let secrets = view
            .packs
            .iter()
            .find(|p| p.name == "Core: secrets")
            .unwrap();
        assert!(secrets
            .blocks
            .iter()
            .any(|b| b == "`.env` files hold secrets"));
        let mut raw: Vec<&str> = Vec::new();
        for p in &packs {
            raw.extend(p.deny.iter().chain(&p.allow).map(|r| r.pattern.as_str()));
            raw.extend(
                p.deny_path
                    .iter()
                    .chain(&p.allow_path)
                    .map(|r| r.glob.as_str()),
            );
        }
        for p in &view.packs {
            for s in p.blocks.iter().chain(&p.exceptions) {
                assert!(!raw.contains(&s.as_str()), "raw rule text leaked: {s}");
            }
        }
    }

    #[test]
    fn missing_project_config_shows_defaults() {
        let (packs, _) = builtin_packs();
        let dir = tempfile::tempdir().unwrap();
        let gone = dir.path().join("gone");
        let bare = tempfile::tempdir().unwrap();
        let at = datetime!(2026-10-13 08:00:00 UTC);
        let rs = [
            rec(
                bare.path().to_str().unwrap(),
                "x",
                DecisionKind::Allow,
                None,
                at,
            ),
            rec(gone.to_str().unwrap(), "x", DecisionKind::Allow, None, at),
        ];
        let refs: Vec<&Record> = rs.iter().collect();
        let r = build(&refs, &packs, vec![], None, datetime!(2026-10-18 09:00 UTC));
        let defaults: Vec<String> = packs
            .iter()
            .filter(|p| p.default_on)
            .map(|p| p.name.clone())
            .collect();
        for v in &r.packs {
            let names: Vec<String> = v.packs.iter().map(|p| p.name.clone()).collect();
            assert_eq!(names, defaults, "{}", v.project);
            let note = if v.project.ends_with("gone") {
                "This folder no longer exists; the default packs are shown."
            } else {
                "No saiife config in this folder now; the default packs are shown."
            };
            assert_eq!(v.note.as_deref(), Some(note));
        }
    }

    #[test]
    fn parent_config_is_used_with_a_note() {
        let (packs, _) = builtin_packs();
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".saiife")).unwrap();
        std::fs::write(dir.path().join(CONFIG_REL), "packs = [\"db.postgres\"]\n").unwrap();
        let child = dir.path().join("child");
        std::fs::create_dir(&child).unwrap();
        let rs = [rec(
            child.to_str().unwrap(),
            "x",
            DecisionKind::Allow,
            None,
            datetime!(2026-10-13 08:00:00 UTC),
        )];
        let refs: Vec<&Record> = rs.iter().collect();
        let r = build(&refs, &packs, vec![], None, datetime!(2026-10-18 09:00 UTC));
        let v = &r.packs[0];
        assert_eq!(
            v.note,
            Some(format!(
                "Uses the saiife config in {}.",
                dir.path().display()
            ))
        );
        assert!(v
            .packs
            .iter()
            .any(|p| p.name.to_lowercase().contains("postgres")));
        let defaults = packs.iter().filter(|p| p.default_on).count();
        assert_eq!(v.packs.len(), defaults + 1);
    }

    #[test]
    fn empty_project_gets_defaults_not_the_cwd_config() {
        let (packs, _) = builtin_packs();
        let rs = [rec(
            "",
            "x",
            DecisionKind::Allow,
            None,
            datetime!(2026-10-13 08:00:00 UTC),
        )];
        let refs: Vec<&Record> = rs.iter().collect();
        let r = build(&refs, &packs, vec![], None, datetime!(2026-10-18 09:00 UTC));
        assert_eq!(
            r.packs[0].note.as_deref(),
            Some("Unknown project folder; the default packs are shown.")
        );
        let defaults = packs.iter().filter(|p| p.default_on).count();
        assert_eq!(r.packs[0].packs.len(), defaults);
    }

    #[test]
    fn relative_project_is_treated_like_an_empty_one() {
        let (packs, _) = builtin_packs();
        let rs = [rec(
            "some/relative",
            "x",
            DecisionKind::Allow,
            None,
            datetime!(2026-10-13 08:00:00 UTC),
        )];
        let refs: Vec<&Record> = rs.iter().collect();
        let r = build(&refs, &packs, vec![], None, datetime!(2026-10-18 09:00 UTC));
        assert_eq!(
            r.packs[0].note.as_deref(),
            Some("Unknown project folder; the default packs are shown.")
        );
    }

    #[test]
    fn hostile_text_is_inert() {
        let (packs, _) = builtin_packs();
        let rs = [rec(
            "/p",
            "<script>alert(1)</script>",
            DecisionKind::Allow,
            None,
            datetime!(2026-10-13 08:00:00 UTC),
        )];
        let refs: Vec<&Record> = rs.iter().collect();
        let r = build(&refs, &packs, vec![], None, datetime!(2026-10-18 09:00 UTC));
        assert_eq!(r.all_rows[0].input, "<script>alert(1)</script>");
    }

    #[test]
    fn broken_config_shows_defaults_with_note() {
        let (packs, _) = builtin_packs();
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".saiife")).unwrap();
        std::fs::write(dir.path().join(CONFIG_REL), "packs = [\n").unwrap();
        let rs = [rec(
            dir.path().to_str().unwrap(),
            "x",
            DecisionKind::Allow,
            None,
            datetime!(2026-10-13 08:00:00 UTC),
        )];
        let refs: Vec<&Record> = rs.iter().collect();
        let r = build(&refs, &packs, vec![], None, datetime!(2026-10-18 09:00 UTC));
        assert_eq!(
            r.packs[0].note.as_deref(),
            Some(
                format!(
                    "The saiife config in {} could not be read; the default packs are shown.",
                    dir.path().display()
                )
                .as_str()
            )
        );
        let n = packs.iter().filter(|p| p.default_on).count();
        assert_eq!(r.packs[0].packs.len(), n);
    }

    #[test]
    fn unknown_pack_id_and_empty_input() {
        let (packs, _) = builtin_packs();
        let at = datetime!(2026-10-13 08:00:00 UTC);
        let rs = [rec("/p", "", DecisionKind::Deny, Some("zzz.unknown"), at)];
        let refs: Vec<&Record> = rs.iter().collect();
        let r = build(&refs, &packs, vec![], None, datetime!(2026-10-18 09:00 UTC));
        assert_eq!(r.all_rows[0].pack, "zzz.unknown");
        assert_eq!(r.all_rows[0].input, "(no input recorded)");
    }

    #[test]
    fn non_utc_times_are_converted() {
        let (packs, _) = builtin_packs();
        let now = datetime!(2026-10-18 11:00 +02:00);
        let r = build(&[], &packs, vec![], None, now);
        assert_eq!(r.generated, "2026-10-18 09:00 UTC");
    }

    fn with(mut r: Record, policy: Option<&str>, host: Option<&str>, mode: Option<&str>) -> Record {
        r.policy = policy.map(str::to_string);
        r.host = host.map(str::to_string);
        r.mode = mode.map(str::to_string);
        r
    }

    #[test]
    fn report_shows_chain_status() {
        use saiife_audit::chain::append_chained;
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            chain_line(&saiife_audit::verify(dir.path())),
            "no chained records yet"
        );
        for i in 0..3 {
            let r = rec(
                "/p",
                &format!("echo secret-{i}"),
                DecisionKind::Allow,
                None,
                datetime!(2026-10-13 08:00:00 UTC),
            );
            append_chained(dir.path(), r).unwrap();
        }
        let line = chain_line(&saiife_audit::verify(dir.path()));
        assert!(line.starts_with("intact ("), "{line}");
        assert!(line.contains("records)"), "{line}");
        let f = dir.path().join("2026-10.jsonl");
        let text = std::fs::read_to_string(&f).unwrap();
        std::fs::write(&f, text.replace("echo secret-1", "echo edited-1")).unwrap();
        let line = chain_line(&saiife_audit::verify(dir.path()));
        assert!(line.starts_with("broken: 2026-10.jsonl line "), "{line}");
        assert!(!line.contains("echo"), "no record content: {line}");
        let bad = saiife_audit::VerifyReport {
            read_errors: vec!["x".into()],
            ..Default::default()
        };
        assert_eq!(chain_line(&bad), "could not be read");
    }

    #[test]
    fn last_checkpoint_defaults_to_none() {
        let mut c = rec(
            "/p",
            "",
            DecisionKind::Allow,
            None,
            datetime!(2026-10-13 08:05:09 UTC),
        );
        c.kind = Some("checkpoint".into());
        let g = rec(
            "/p",
            "x",
            DecisionKind::Allow,
            None,
            datetime!(2026-10-13 08:00:00 UTC),
        );
        assert_eq!(last_checkpoint(std::slice::from_ref(&g)), "none");
        assert_eq!(last_checkpoint(&[g, c]), "2026-10-13 08:05 UTC");
    }

    #[test]
    fn policy_periods_split_on_change() {
        let (packs, _) = builtin_packs();
        let a = "sha256:aaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let b = "sha256:cccccccccccc0000000000000000000000000000000000000000000000000000";
        let rs = [
            with(
                rec(
                    "/p",
                    "1",
                    DecisionKind::Allow,
                    None,
                    datetime!(2026-10-13 08:00:00 UTC),
                ),
                Some(a),
                None,
                None,
            ),
            with(
                rec(
                    "/p",
                    "2",
                    DecisionKind::Allow,
                    None,
                    datetime!(2026-10-13 09:00:00 UTC),
                ),
                Some(a),
                None,
                None,
            ),
            with(
                rec(
                    "/p",
                    "3",
                    DecisionKind::Allow,
                    None,
                    datetime!(2026-10-13 10:00:00 UTC),
                ),
                Some(b),
                None,
                None,
            ),
            with(
                rec(
                    "/p",
                    "4",
                    DecisionKind::Allow,
                    None,
                    datetime!(2026-10-13 11:00:00 UTC),
                ),
                Some(a),
                None,
                None,
            ),
        ];
        let refs: Vec<&Record> = rs.iter().collect();
        let r = build(&refs, &packs, vec![], None, datetime!(2026-10-18 09:00 UTC));
        assert_eq!(r.policies.len(), 3);
        assert_eq!(r.policies[0].policy, "sha256:aaaaaaaaaaaa");
        assert_eq!(r.policies[0].from, "2026-10-13 08:00 UTC");
        assert_eq!(r.policies[0].to, "2026-10-13 09:00 UTC");
        assert_eq!(r.policies[0].records, 2);
        assert_eq!(r.policies[1].policy, "sha256:cccccccccccc");
        assert_eq!(r.policies[2].policy, "sha256:aaaaaaaaaaaa");
        assert_eq!(r.policies[2].from, "2026-10-13 11:00 UTC");
    }

    #[test]
    fn modes_per_host() {
        let (packs, _) = builtin_packs();
        let at = datetime!(2026-10-13 08:00:00 UTC);
        let rs = [
            with(
                rec("/p", "1", DecisionKind::Allow, None, at),
                None,
                None,
                None,
            ),
            with(
                rec("/p", "2", DecisionKind::Allow, None, at),
                None,
                None,
                None,
            ),
            with(
                rec("/p", "3", DecisionKind::Allow, None, at),
                None,
                Some("0123456789abcdef"),
                Some("developer"),
            ),
        ];
        let refs: Vec<&Record> = rs.iter().collect();
        let r = build(&refs, &packs, vec![], None, datetime!(2026-10-18 09:00 UTC));
        assert_eq!(r.modes.len(), 2);
        let unknown = r.modes.iter().find(|m| m.host == "unknown").unwrap();
        assert_eq!((unknown.mode.as_str(), unknown.records), ("unknown", 2));
        let known = r.modes.iter().find(|m| m.host == "0123456789ab").unwrap();
        assert_eq!((known.mode.as_str(), known.records), ("developer", 1));
    }

    #[test]
    fn error_denied_counts_as_blocked() {
        let (packs, _) = builtin_packs();
        let rs = [rec(
            "/p",
            "curl x",
            DecisionKind::ErrorDenied,
            None,
            datetime!(2026-10-13 08:00:00 UTC),
        )];
        let refs: Vec<&Record> = rs.iter().collect();
        let r = build(&refs, &packs, vec![], None, datetime!(2026-10-18 09:00 UTC));
        assert_eq!((r.blocked, r.blocked_rows.len()), (1, 1));
        assert_eq!(r.blocked_rows[0].decision, "Blocked (error)");
    }
}
