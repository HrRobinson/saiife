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
    /// Connector requests per service (§6.19), "seen by saiife".
    pub connectors: Vec<ConnectorActivity>,
    pub connector_rows: Vec<ConnectorRow>,
    pub approvals: Vec<ApprovalRow>,
    /// Records with decision `error_denied`, of any kind.
    pub error_denied: Vec<ErrorDeniedRow>,
    /// Daemon starts that did not follow a clean stop.
    pub restarts: Vec<RestartRow>,
    pub outages: Vec<Outage>,
    /// `forward` / `backlog_dropped` events.
    pub forward_drops: Vec<ForwardDrop>,
    /// True when --agent/--project/--blocked was given: the connector,
    /// approval, error_denied, restart and outage sections ignore those.
    pub sections_not_narrowed: bool,
    /// True when the records came through the daemon (a non-auditor):
    /// `audit.query` never returns daemon or forward records, so the
    /// restart and outage sections say they are for auditors only
    /// instead of claiming there were none.
    pub auditors_only_sections: bool,
}

/// What the restart and outage sections say in a report built from the
/// daemon's answer (a non-auditor).
pub const AUDITORS_ONLY: &str = "Not shown: auditors only.";

/// Where a record came from, for the labels of §9.4.
pub const SOURCE_GUARD: &str = "reported by the agent's hook";
pub const SOURCE_SAIIFE: &str = "seen by saiife";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorActivity {
    pub service: String,
    pub requests: usize,
    pub denies: usize,
    pub limits_hit: usize,
    pub approvals: usize,
    /// Requests that were sent after an approval (`via` = approval); not
    /// counted in `requests`.
    pub sent_after_approval: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorRow {
    pub time: String,
    pub user: String,
    pub service: String,
    pub request: String,
    pub decision: &'static str,
    pub reason: String,
    pub source: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRow {
    pub id: String,
    pub requester: String,
    pub decider: String,
    pub decision: String,
    pub time_to_decision: String,
    /// What happened after the decision: `sent`, `send_failed`,
    /// `grant_used`; empty when nothing followed.
    pub outcome: String,
    pub kind: String,
    pub summary: String,
    pub time: String,
    pub source: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorDeniedRow {
    pub time: String,
    pub kind: String,
    pub what: String,
    pub reason: String,
    pub source: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartRow {
    pub time: String,
    pub host: String,
    pub version: String,
    pub source: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outage {
    pub target: String,
    pub from: String,
    /// `ongoing` when no `recovered` (or `connected`) follows.
    pub to: String,
    pub duration: String,
    /// Why the outage ended without a `recovered`, or empty.
    pub note: String,
    pub source: &'static str,
}

/// The note on an outage that a later `connected` closed: the worker was
/// started again (daemon restart or config reload) and its first send
/// went through, so no `recovered` was recorded.
pub const RECOVERED_AFTER_RESTART: &str = "recovered after a daemon restart or reload";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardDrop {
    pub time: String,
    pub target: String,
    pub detail: String,
    pub source: &'static str,
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
    pub source: &'static str,
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
        source: SOURCE_GUARD,
    }
}

fn extra_str<'a>(r: &'a Record, k: &str) -> Option<&'a str> {
    r.extra.get(k).and_then(serde_json::Value::as_str)
}

fn at_minute(r: &Record) -> String {
    r.timestamp().map(fmt_minute).unwrap_or_default()
}

fn who(r: &Record) -> String {
    match (r.user.as_deref(), r.uid) {
        (Some(u), _) if !u.is_empty() => u.to_string(),
        (_, Some(uid)) => format!("uid {uid}"),
        _ => "unknown".to_string(),
    }
}

fn fmt_duration(secs: i64) -> String {
    let secs = secs.max(0);
    match (secs / 3600, secs % 3600 / 60, secs % 60) {
        (0, 0, s) => format!("{s}s"),
        (0, m, s) => format!("{m}m {s}s"),
        (h, m, _) => format!("{h}h {m}m"),
    }
}

fn connector_row(r: &Record, service: String) -> ConnectorRow {
    ConnectorRow {
        time: at_minute(r),
        user: who(r),
        service,
        request: if r.input.is_empty() {
            "(no request recorded)".to_string()
        } else {
            r.input.clone()
        },
        decision: decision_label(r.decision),
        reason: r.reason.clone().unwrap_or_default(),
        source: SOURCE_SAIIFE,
    }
}

fn connector_activity(sorted_asc: &[&Record]) -> (Vec<ConnectorActivity>, Vec<ConnectorRow>) {
    let mut map: std::collections::BTreeMap<String, ConnectorActivity> = Default::default();
    let mut rows = Vec::new();
    for r in sorted_asc.iter().filter(|r| r.kind() == "connector") {
        let service = extra_str(r, "service").unwrap_or("unknown").to_string();
        let a = map
            .entry(service.clone())
            .or_insert_with(|| ConnectorActivity {
                service: service.clone(),
                requests: 0,
                denies: 0,
                limits_hit: 0,
                approvals: 0,
                sent_after_approval: 0,
            });
        if extra_str(r, "via") == Some("approval") {
            // The send of an approved request, not a new request.
            a.sent_after_approval += 1;
            rows.push(connector_row(r, service));
            continue;
        }
        a.requests += 1;
        if r.decision == DecisionKind::Deny {
            a.denies += 1;
        }
        if r.extra.get("limit").is_some_and(|l| !l.is_null()) {
            a.limits_hit += 1;
        }
        if r.decision == DecisionKind::Ask {
            a.approvals += 1;
        }
        rows.push(connector_row(r, service));
    }
    rows.reverse();
    (map.into_values().collect(), rows)
}

fn approval_rows(sorted_asc: &[&Record]) -> Vec<ApprovalRow> {
    struct Acc {
        created: Option<OffsetDateTime>,
        row: ApprovalRow,
    }
    let mut order: Vec<String> = Vec::new();
    let mut map: std::collections::HashMap<String, Acc> = Default::default();
    for r in sorted_asc.iter().filter(|r| r.kind() == "approval") {
        let id = r
            .extra
            .get("id")
            .or_else(|| r.extra.get("approval"))
            .map_or_else(
                || "?".to_string(),
                |v| v.to_string().trim_matches('"').to_string(),
            );
        let action = extra_str(r, "action").unwrap_or("");
        let acc = map.entry(id.clone()).or_insert_with(|| {
            order.push(id.clone());
            Acc {
                created: None,
                row: ApprovalRow {
                    id: id.clone(),
                    requester: who(r),
                    decider: String::new(),
                    decision: "pending".to_string(),
                    time_to_decision: "not decided in this period".to_string(),
                    outcome: String::new(),
                    kind: String::new(),
                    summary: String::new(),
                    time: at_minute(r),
                    source: SOURCE_SAIIFE,
                },
            }
        });
        if let Some(t) = extra_str(r, "type") {
            acc.row.kind = t.to_string();
        }
        if !r.input.is_empty() {
            acc.row.summary = r.input.clone();
        }
        if action == "created" {
            acc.created = r.timestamp();
            acc.row.requester = who(r);
            acc.row.time = at_minute(r);
        } else if matches!(action, "approved" | "rejected" | "refused" | "expired") {
            // Only the first deciding record counts.
            if acc.row.decision == "pending" {
                acc.row.decision = action.to_string();
                acc.row.decider = r
                    .extra
                    .get("by_uid")
                    .and_then(serde_json::Value::as_u64)
                    .map_or_else(
                        || {
                            if action == "expired" {
                                "(expired)".to_string()
                            } else {
                                "unknown".to_string()
                            }
                        },
                        |u| format!("uid {u}"),
                    );
                acc.row.time_to_decision = match (acc.created, r.timestamp()) {
                    (Some(a), Some(b)) => fmt_duration((b - a).whole_seconds()),
                    _ => "unknown".to_string(),
                };
            }
        } else if matches!(action, "sent" | "send_failed" | "grant_used") {
            acc.row.outcome = action.to_string();
        }
    }
    let mut out: Vec<ApprovalRow> = order
        .into_iter()
        .filter_map(|id| map.remove(&id).map(|a| a.row))
        .collect();
    out.reverse();
    out
}

fn error_denied_rows(sorted: &[&Record]) -> Vec<ErrorDeniedRow> {
    sorted
        .iter()
        .filter(|r| r.decision == DecisionKind::ErrorDenied)
        .map(|r| ErrorDeniedRow {
            time: at_minute(r),
            kind: r.kind().to_string(),
            what: r.input.clone(),
            reason: r.reason.clone().unwrap_or_default(),
            source: if r.kind() == "guard" {
                SOURCE_GUARD
            } else {
                SOURCE_SAIIFE
            },
        })
        .collect()
}

fn restart_rows(sorted: &[&Record]) -> Vec<RestartRow> {
    sorted
        .iter()
        .filter(|r| {
            r.kind() == "daemon"
                && extra_str(r, "event") == Some("start")
                && r.extra.get("previous_clean_stop") == Some(&serde_json::Value::Bool(false))
        })
        .map(|r| RestartRow {
            time: at_minute(r),
            host: r
                .host
                .as_deref()
                .map_or_else(|| "unknown".to_string(), |h| h.chars().take(12).collect()),
            version: r.saiife.clone(),
            source: SOURCE_SAIIFE,
        })
        .collect()
}

/// `failing` to the next `recovered`, per target; plus dropped backlogs.
/// A `connected` closes an open outage too: a restarted worker records
/// `connected`, not `recovered`, on its first good send.
fn forward_outages(sorted_asc: &[&Record], now: OffsetDateTime) -> (Vec<Outage>, Vec<ForwardDrop>) {
    let mut open: std::collections::BTreeMap<String, OffsetDateTime> = Default::default();
    let mut outages = Vec::new();
    let mut drops = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for r in sorted_asc.iter().filter(|r| r.kind() == "forward") {
        let target = extra_str(r, "target").unwrap_or("unknown").to_string();
        let ts = r.timestamp();
        let first_for_target = seen.insert(target.clone());
        match (extra_str(r, "event"), ts) {
            (Some("failing"), Some(t)) => {
                open.entry(target).or_insert(t);
            }
            (Some("recovered"), Some(t)) => {
                if first_for_target {
                    // The first record we see for this target is a
                    // recovery: the outage began before the report period.
                    outages.push(Outage {
                        target,
                        from: "began before the report period".to_string(),
                        to: fmt_minute(t),
                        duration: "unknown".to_string(),
                        note: String::new(),
                        source: SOURCE_SAIIFE,
                    });
                } else if let Some(from) = open.remove(&target) {
                    outages.push(Outage {
                        target,
                        from: fmt_minute(from),
                        to: fmt_minute(t),
                        duration: fmt_duration((t - from).whole_seconds()),
                        note: String::new(),
                        source: SOURCE_SAIIFE,
                    });
                }
            }
            (Some("connected"), Some(t)) => {
                if let Some(from) = open.remove(&target) {
                    outages.push(Outage {
                        target,
                        from: fmt_minute(from),
                        to: fmt_minute(t),
                        duration: fmt_duration((t - from).whole_seconds()),
                        note: RECOVERED_AFTER_RESTART.to_string(),
                        source: SOURCE_SAIIFE,
                    });
                }
            }
            (Some("backlog_dropped"), _) => drops.push(ForwardDrop {
                time: at_minute(r),
                target,
                detail: drop_detail(r),
                source: SOURCE_SAIIFE,
            }),
            _ => {}
        }
    }
    for (target, from) in open {
        outages.push(Outage {
            target,
            from: fmt_minute(from),
            // Still open at the end of the report: runs to `now`.
            to: "ongoing".to_string(),
            duration: fmt_duration((now - from).whole_seconds()),
            note: String::new(),
            source: SOURCE_SAIIFE,
        });
    }
    outages.reverse();
    drops.reverse();
    (outages, drops)
}

/// A `backlog_dropped` record as one line: the seq range the forwarder
/// wrote (`from_seq`–`to_seq`), then its input and reason.
fn drop_detail(r: &Record) -> String {
    let seq = |k: &str| r.extra.get(k).and_then(serde_json::Value::as_u64);
    let range = match (seq("from_seq"), seq("to_seq")) {
        (Some(a), Some(b)) if a == b => Some(format!("seq {a}")),
        (Some(a), Some(b)) => Some(format!("seq {a}\u{2013}{b}")),
        _ => None,
    };
    [
        range.as_deref(),
        Some(r.input.as_str()),
        r.reason.as_deref(),
    ]
    .into_iter()
    .flatten()
    .filter(|s| !s.is_empty())
    .collect::<Vec<_>>()
    .join("; ")
}

impl Report {
    /// Rebuild the connector, approval, error_denied, restart and outage
    /// sections from `records`. These sections honour --since only, so
    /// the caller passes records filtered by time alone; `narrowed` says
    /// that other filters were given and are not applied to them.
    pub fn set_host_events(&mut self, records: &[&Record], now: OffsetDateTime, narrowed: bool) {
        let mut desc: Vec<&Record> = records.to_vec();
        desc.sort_by_key(|r| Reverse(r.timestamp()));
        let mut asc = desc.clone();
        asc.reverse();
        (self.connectors, self.connector_rows) = connector_activity(&asc);
        self.approvals = approval_rows(&asc);
        self.error_denied = error_denied_rows(&desc);
        self.restarts = restart_rows(&desc);
        (self.outages, self.forward_drops) = forward_outages(&asc, now);
        self.sections_not_narrowed = narrowed;
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
    let mut every: Vec<&Record> = records.to_vec();
    every.sort_by_key(|r| Reverse(r.timestamp()));
    // The guard sections list only what the agent's hook reported; the
    // other kinds have their own sections below.
    let guard_records: Vec<&Record> = records
        .iter()
        .copied()
        .filter(|r| r.kind() == "guard")
        .collect();
    let mut sorted: Vec<&Record> = guard_records.clone();
    sorted.sort_by_key(|r| Reverse(r.timestamp()));
    let host_records = records;
    let records = &guard_records[..];

    let period = match since {
        Some(s) => format!("{} to {}", fmt_minute(s), fmt_minute(now)),
        None => {
            let times: Vec<OffsetDateTime> =
                host_records.iter().filter_map(|r| r.timestamp()).collect();
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

    let mut every_asc = every.clone();
    every_asc.reverse();
    let (connectors, connector_rows) = connector_activity(&every_asc);
    let approvals = approval_rows(&every_asc);
    let error_denied = error_denied_rows(&every);
    let restarts = restart_rows(&every);
    let (outages, forward_drops) = forward_outages(&every_asc, now);

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
        connectors,
        connector_rows,
        approvals,
        error_denied,
        restarts,
        outages,
        forward_drops,
        sections_not_narrowed: false,
        auditors_only_sections: false,
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

    fn kind_rec(kind: &str, at: OffsetDateTime, extra: &[(&str, serde_json::Value)]) -> Record {
        let mut r = rec("/p", "", DecisionKind::Allow, None, at);
        r.kind = Some(kind.into());
        r.uid = Some(1000);
        r.user = Some("alice".into());
        for (k, v) in extra {
            r.extra.insert((*k).into(), v.clone());
        }
        r
    }

    fn conn(service: &str, d: DecisionKind, limit: Option<&str>, at: OffsetDateTime) -> Record {
        let mut r = kind_rec(
            "connector",
            at,
            &[
                ("service", service.into()),
                ("limit", limit.map_or(serde_json::Value::Null, Into::into)),
            ],
        );
        r.decision = d;
        r.input = format!("{service} read");
        r
    }

    #[test]
    fn connector_activity_counts() {
        let t = datetime!(2026-10-20 10:00:00 UTC);
        let rs = [
            conn("shop", DecisionKind::Allow, None, t),
            conn("shop", DecisionKind::Deny, None, t),
            conn("shop", DecisionKind::Deny, Some("per_minute"), t),
            conn("shop", DecisionKind::Ask, None, t),
            conn("mail", DecisionKind::Allow, None, t),
            rec("/p", "ls", DecisionKind::Allow, None, t),
        ];
        let refs: Vec<&Record> = rs.iter().collect();
        let r = build(&refs, &[], vec![], None, t);
        let shop = &r.connectors[1];
        assert_eq!(
            (
                shop.service.as_str(),
                shop.requests,
                shop.denies,
                shop.limits_hit,
                shop.approvals
            ),
            ("shop", 4, 2, 1, 1)
        );
        assert_eq!(r.connectors[0].service, "mail");
        assert_eq!(r.connector_rows.len(), 5);
        // Connector records do not count as guard decisions.
        assert_eq!(r.total, 1);
        assert_eq!(r.all_rows.len(), 1);
    }

    fn appr(id: u64, action: &str, at: OffsetDateTime, by: Option<u64>) -> Record {
        let mut r = kind_rec(
            "approval",
            at,
            &[
                ("id", id.into()),
                ("approval", id.into()),
                ("action", action.into()),
                ("type", "connector".into()),
            ],
        );
        r.input = "shop refund".into();
        if let Some(b) = by {
            r.extra.insert("by_uid".into(), b.into());
        }
        r
    }

    #[test]
    fn approvals_section_latency_and_decider() {
        let rs = [
            appr(1, "created", datetime!(2026-10-20 10:00:00 UTC), None),
            appr(
                1,
                "approved",
                datetime!(2026-10-20 10:02:05 UTC),
                Some(1001),
            ),
            appr(2, "created", datetime!(2026-10-20 11:00:00 UTC), None),
            appr(3, "created", datetime!(2026-10-20 12:00:00 UTC), None),
            appr(3, "expired", datetime!(2026-10-20 13:00:00 UTC), None),
        ];
        let refs: Vec<&Record> = rs.iter().collect();
        let r = build(&refs, &[], vec![], None, datetime!(2026-10-21 00:00 UTC));
        assert_eq!(r.approvals.len(), 3);
        let by_id = |id: &str| r.approvals.iter().find(|a| a.id == id).unwrap();
        let a = by_id("1");
        assert_eq!(
            (
                a.decision.as_str(),
                a.decider.as_str(),
                a.time_to_decision.as_str()
            ),
            ("approved", "uid 1001", "2m 5s")
        );
        assert_eq!(
            (a.requester.as_str(), a.kind.as_str(), a.summary.as_str()),
            ("alice", "connector", "shop refund")
        );
        assert_eq!(a.outcome, "");
        assert_eq!(by_id("2").decision, "pending");
        assert_eq!(by_id("3").decision, "expired");
        assert_eq!(by_id("3").time_to_decision, "1h 0m");
        // Newest first.
        assert_eq!(r.approvals[0].id, "3");
    }

    fn fwd(event: &str, target: &str, at: OffsetDateTime) -> Record {
        kind_rec(
            "forward",
            at,
            &[("event", event.into()), ("target", target.into())],
        )
    }

    #[test]
    fn restarts_and_outages_listed() {
        let start = |clean: bool, at| {
            kind_rec(
                "daemon",
                at,
                &[
                    ("event", "start".into()),
                    ("previous_clean_stop", clean.into()),
                ],
            )
        };
        let rs = [
            start(true, datetime!(2026-10-20 08:00:00 UTC)),
            start(false, datetime!(2026-10-20 09:00:00 UTC)),
            fwd("failing", "siem", datetime!(2026-10-20 10:00:00 UTC)),
            fwd("recovered", "siem", datetime!(2026-10-20 10:45:00 UTC)),
            fwd("failing", "files", datetime!(2026-10-20 11:00:00 UTC)),
            fwd(
                "backlog_dropped",
                "files",
                datetime!(2026-10-20 11:30:00 UTC),
            ),
            fwd("recovered", "orphan", datetime!(2026-10-20 11:40:00 UTC)),
        ];
        let refs: Vec<&Record> = rs.iter().collect();
        let r = build(&refs, &[], vec![], None, datetime!(2026-10-21 00:00 UTC));
        assert_eq!(r.restarts.len(), 1);
        assert_eq!(r.restarts[0].time, "2026-10-20 09:00 UTC");
        assert_eq!(r.outages.len(), 3);
        let orphan = r.outages.iter().find(|o| o.target == "orphan").unwrap();
        assert_eq!(orphan.from, "began before the report period");
        assert_eq!(orphan.to, "2026-10-20 11:40 UTC");
        let siem = r.outages.iter().find(|o| o.target == "siem").unwrap();
        assert_eq!(
            (siem.to.as_str(), siem.duration.as_str()),
            ("2026-10-20 10:45 UTC", "45m 0s")
        );
        let files = r.outages.iter().find(|o| o.target == "files").unwrap();
        // Open at the end: runs to `now` (2026-10-21 00:00), from 11:00.
        assert_eq!(
            (files.to.as_str(), files.duration.as_str()),
            ("ongoing", "13h 0m")
        );
        assert_eq!(r.forward_drops.len(), 1);
        // set_host_events rebuilds both from a record set.
        let mut r2 = r.clone();
        r2.restarts.clear();
        r2.outages.clear();
        r2.set_host_events(&refs, datetime!(2026-10-21 00:00 UTC), false);
        assert_eq!((r2.restarts.len(), r2.outages.len()), (1, 3));
    }

    #[test]
    fn connected_closes_an_open_outage() {
        // A worker restarted (daemon restart or reload) records `connected`
        // on its first good send, never `recovered`.
        let rs = [
            fwd("connected", "siem", datetime!(2026-10-20 09:00:00 UTC)),
            fwd("failing", "siem", datetime!(2026-10-20 10:00:00 UTC)),
            fwd("connected", "siem", datetime!(2026-10-20 10:20:00 UTC)),
            fwd("failing", "siem", datetime!(2026-10-20 11:00:00 UTC)),
            fwd("recovered", "siem", datetime!(2026-10-20 11:05:00 UTC)),
            // A `connected` with no open outage is not an outage.
            fwd("connected", "files", datetime!(2026-10-20 12:00:00 UTC)),
        ];
        let refs: Vec<&Record> = rs.iter().collect();
        let r = build(&refs, &[], vec![], None, datetime!(2026-10-21 00:00 UTC));
        assert_eq!(r.outages.len(), 2, "{:?}", r.outages);
        let by_restart = r.outages.iter().find(|o| !o.note.is_empty()).unwrap();
        assert_eq!(
            (
                by_restart.from.as_str(),
                by_restart.to.as_str(),
                by_restart.duration.as_str(),
                by_restart.note.as_str()
            ),
            (
                "2026-10-20 10:00 UTC",
                "2026-10-20 10:20 UTC",
                "20m 0s",
                "recovered after a daemon restart or reload"
            )
        );
        let plain = r.outages.iter().find(|o| o.note.is_empty()).unwrap();
        assert_eq!(plain.to, "2026-10-20 11:05 UTC");
        let html = crate::report_html::render(&r);
        assert!(
            html.contains("2026-10-20 10:20 UTC (recovered after a daemon restart or reload)"),
            "{html}"
        );
    }

    #[test]
    fn backlog_dropped_shows_the_seq_range() {
        let t = datetime!(2026-10-20 11:30:00 UTC);
        let rs = [
            kind_rec(
                "forward",
                t,
                &[
                    ("event", "backlog_dropped".into()),
                    ("target", "siem".into()),
                    ("from_seq", 6.into()),
                    ("to_seq", 10.into()),
                ],
            ),
            kind_rec(
                "forward",
                t,
                &[
                    ("event", "backlog_dropped".into()),
                    ("target", "one".into()),
                    ("from_seq", 7.into()),
                    ("to_seq", 7.into()),
                ],
            ),
        ];
        let refs: Vec<&Record> = rs.iter().collect();
        let r = build(&refs, &[], vec![], None, t);
        let detail = |target: &str| {
            r.forward_drops
                .iter()
                .find(|d| d.target == target)
                .unwrap()
                .detail
                .clone()
        };
        assert!(
            detail("siem").starts_with("seq 6\u{2013}10"),
            "{}",
            detail("siem")
        );
        assert!(detail("one").starts_with("seq 7"), "{}", detail("one"));
        assert!(!detail("one").contains('\u{2013}'));
        assert!(crate::report_html::render(&r).contains("seq 6\u{2013}10"));
    }

    #[test]
    fn daemon_sourced_report_hides_host_sections() {
        let rs = [fwd("failing", "siem", datetime!(2026-10-20 10:00:00 UTC))];
        let refs: Vec<&Record> = rs.iter().collect();
        let mut r = build(&refs, &[], vec![], None, datetime!(2026-10-21 00:00 UTC));
        let html = crate::report_html::render(&r);
        assert!(!html.contains(AUDITORS_ONLY));
        assert!(html.contains("No unclean daemon restarts in this period."));
        r.outages.clear();
        r.auditors_only_sections = true;
        let html = crate::report_html::render(&r);
        assert_eq!(html.matches(AUDITORS_ONLY).count(), 2, "{html}");
        assert!(!html.contains("No unclean daemon restarts in this period."));
        assert!(!html.contains("No forwarding outages in this period."));
    }

    #[test]
    fn error_denied_listed_for_every_kind() {
        let t = datetime!(2026-10-20 10:00:00 UTC);
        let rs = [
            rec("/p", "x", DecisionKind::ErrorDenied, None, t),
            conn("shop", DecisionKind::ErrorDenied, None, t),
            conn("shop", DecisionKind::Allow, None, t),
        ];
        let refs: Vec<&Record> = rs.iter().collect();
        let r = build(&refs, &[], vec![], None, t);
        assert_eq!(r.error_denied.len(), 2);
        let sources: Vec<&str> = r.error_denied.iter().map(|e| e.source).collect();
        assert!(sources.contains(&SOURCE_GUARD) && sources.contains(&SOURCE_SAIIFE));
    }

    #[test]
    fn record_source_labels() {
        let t = datetime!(2026-10-20 10:00:00 UTC);
        let rs = [
            rec("/p", "ls", DecisionKind::Allow, None, t),
            conn("shop", DecisionKind::Allow, None, t),
            appr(1, "created", t, None),
        ];
        let refs: Vec<&Record> = rs.iter().collect();
        let r = build(&refs, &[], vec![], None, t);
        assert_eq!(r.all_rows[0].source, "reported by the agent's hook");
        assert_eq!(r.connector_rows[0].source, "seen by saiife");
        assert_eq!(r.approvals[0].source, "seen by saiife");
        let html = crate::report_html::render(&r);
        assert!(html.contains("reported by the agent&#39;s hook"));
        assert!(html.contains("seen by saiife"));
    }

    #[test]
    fn approval_outcome_does_not_overwrite_decision() {
        let rs = [
            appr(1, "created", datetime!(2026-10-20 10:00:00 UTC), None),
            appr(
                1,
                "approved",
                datetime!(2026-10-20 10:01:00 UTC),
                Some(1001),
            ),
            appr(1, "sent", datetime!(2026-10-20 10:09:00 UTC), None),
            appr(
                1,
                "rejected",
                datetime!(2026-10-20 10:30:00 UTC),
                Some(1002),
            ),
        ];
        let refs: Vec<&Record> = rs.iter().collect();
        let r = build(&refs, &[], vec![], None, datetime!(2026-10-21 00:00 UTC));
        let a = &r.approvals[0];
        assert_eq!(
            (
                a.decision.as_str(),
                a.outcome.as_str(),
                a.time_to_decision.as_str(),
                a.decider.as_str()
            ),
            ("approved", "sent", "1m 0s", "uid 1001")
        );
    }

    #[test]
    fn send_after_approval_is_not_a_new_request() {
        let t = datetime!(2026-10-20 10:00:00 UTC);
        let mut sent = conn("shop", DecisionKind::Allow, None, t);
        sent.extra.insert("via".into(), "approval".into());
        let rs = [conn("shop", DecisionKind::Ask, None, t), sent];
        let refs: Vec<&Record> = rs.iter().collect();
        let r = build(&refs, &[], vec![], None, t);
        let shop = &r.connectors[0];
        assert_eq!(
            (shop.requests, shop.approvals, shop.sent_after_approval),
            (1, 1, 1)
        );
    }

    #[test]
    fn unnarrowed_note_shows_when_flags_are_set() {
        let t = datetime!(2026-10-20 10:00:00 UTC);
        let rs = [conn("shop", DecisionKind::Allow, None, t)];
        let refs: Vec<&Record> = rs.iter().collect();
        let mut r = build(&refs, &[], vec![], None, t);
        let note = "not narrowed by --agent/--project/--blocked";
        assert!(!crate::report_html::render(&r).contains(note));
        r.set_host_events(&refs, t, true);
        assert_eq!(crate::report_html::render(&r).matches(note).count(), 3);
    }
}
