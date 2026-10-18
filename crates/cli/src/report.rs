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
    let (enabled, note) = if project.is_empty() {
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
                Some("No saiife config in this folder now; the default packs are shown.".to_string()),
            ),
            Some(root) if saiife_agents::config::load(root).is_err() => (
                Vec::new(),
                Some(
                    "The saiife config in this folder could not be read; the default packs are shown."
                        .to_string(),
                ),
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
    let rows_of = |kind: DecisionKind| -> Vec<Row> {
        sorted
            .iter()
            .zip(&all_rows)
            .filter(|(r, _)| r.decision == kind)
            .map(|(_, row)| row.clone())
            .collect()
    };
    let blocked_rows = rows_of(DecisionKind::Deny);
    let fail_open_rows = rows_of(DecisionKind::ErrorAllowed);

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
            .replace("\"deny\"", "\"error_denied\"");
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
                "The saiife config in this folder could not be read; the default packs are shown."
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
}
