//! Monthly JSONL files under the user's data dir (spec §6.1).

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use time::OffsetDateTime;

use crate::record::{DecisionKind, Record};

/// Environment variable that overrides the audit directory (tests, admins).
pub const DIR_ENV: &str = "SAIIFE_AUDIT_DIR";

pub fn default_dir() -> Option<PathBuf> {
    match std::env::var_os(DIR_ENV) {
        Some(d) if !d.is_empty() => Some(PathBuf::from(d)),
        _ => dirs::data_dir().map(|d| d.join("saiife").join("audit")),
    }
}

/// Append one record as a single line to `<dir>/<YYYY-MM>.jsonl`, creating the
/// dir and file as needed. New files are owner-only (0600) on unix: commands
/// can reveal what people work on. The whole line goes out in one
/// `write_all` on an `O_APPEND` handle so parallel hooks do not interleave.
pub fn append(dir: &Path, rec: &Record) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(dir.join(format!("{}.jsonl", rec.month())))?;
    let mut line = serde_json::to_string(rec).map_err(io::Error::other)?;
    line.push('\n');
    file.write_all(line.as_bytes())
}

/// Every parseable record from every `YYYY-MM.jsonl` in `dir`, oldest file
/// first. Unparseable lines and other files are skipped silently.
pub fn read_all(dir: &Path) -> Vec<Record> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(is_month_file)
        })
        .collect();
    files.sort();
    files
        .iter()
        .filter_map(|p| fs::read_to_string(p).ok())
        .flat_map(|body| {
            body.lines()
                .filter_map(|l| serde_json::from_str::<Record>(l).ok())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// `YYYY-MM.jsonl`
fn is_month_file(name: &str) -> bool {
    let b = name.as_bytes();
    name.len() == 13
        && name.ends_with(".jsonl")
        && b[..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[5..7].iter().all(u8::is_ascii_digit)
}

#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub since: Option<OffsetDateTime>,
    pub project: Option<String>,
    pub agent: Option<String>,
    pub blocked_only: bool,
}

impl Filter {
    pub fn matches(&self, r: &Record) -> bool {
        if let Some(since) = self.since {
            match r.timestamp() {
                Some(t) if t >= since => {}
                _ => return false,
            }
        }
        if let Some(p) = &self.project {
            let p = p.trim_end_matches('/');
            let under = r.project == p
                || r.project
                    .strip_prefix(p)
                    .is_some_and(|rest| rest.starts_with('/'));
            if !under {
                return false;
            }
        }
        if let Some(a) = &self.agent {
            if &r.agent != a {
                return false;
            }
        }
        !(self.blocked_only && r.decision != DecisionKind::Deny)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::NewRecord;
    use time::macros::datetime;

    fn rec(project: &str, agent: &str, decision: DecisionKind, at: OffsetDateTime) -> Record {
        Record::at(
            NewRecord {
                agent,
                project,
                session: None,
                tool: "Bash",
                input: "ls",
                decision,
                pack: None,
                rule: None,
                reason: None,
            },
            "0.1.0",
            at,
        )
    }

    #[test]
    fn append_then_read_roundtrip_across_months() {
        let dir = tempfile::tempdir().unwrap();
        let a = rec(
            "/p",
            "claude",
            DecisionKind::Allow,
            datetime!(2026-09-30 23:59:59 UTC),
        );
        let b = rec(
            "/p",
            "claude",
            DecisionKind::Deny,
            datetime!(2026-10-01 00:00:01 UTC),
        );
        append(dir.path(), &a).unwrap();
        append(dir.path(), &b).unwrap();
        assert!(dir.path().join("2026-09.jsonl").exists());
        assert!(dir.path().join("2026-10.jsonl").exists());
        assert_eq!(read_all(dir.path()), vec![a, b]);
    }

    #[test]
    fn append_creates_missing_dir() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a/b");
        append(
            &nested,
            &rec(
                "/p",
                "claude",
                DecisionKind::Allow,
                OffsetDateTime::now_utc(),
            ),
        )
        .unwrap();
        assert_eq!(read_all(&nested).len(), 1);
    }

    #[test]
    fn append_to_a_file_path_errors_instead_of_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("not-a-dir");
        fs::write(&file, "x").unwrap();
        assert!(append(
            &file,
            &rec(
                "/p",
                "claude",
                DecisionKind::Allow,
                OffsetDateTime::now_utc()
            )
        )
        .is_err());
    }

    #[test]
    fn read_all_skips_garbage_lines_and_foreign_files() {
        let dir = tempfile::tempdir().unwrap();
        let good = rec(
            "/p",
            "claude",
            DecisionKind::Allow,
            datetime!(2026-10-13 08:00:00 UTC),
        );
        append(dir.path(), &good).unwrap();
        let mut f = OpenOptions::new()
            .append(true)
            .open(dir.path().join("2026-10.jsonl"))
            .unwrap();
        writeln!(f, "{{\"v\":1,\"ts\":\"2026-10-13T08:").unwrap(); // half-written line
        writeln!(f, "not json").unwrap();
        writeln!(f).unwrap();
        fs::write(dir.path().join("notes.txt"), "{\"v\":1}").unwrap();
        fs::write(dir.path().join("backup.jsonl"), "{}").unwrap();
        assert_eq!(read_all(dir.path()), vec![good]);
    }

    #[test]
    fn read_all_of_missing_dir_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_all(&dir.path().join("nope")).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn new_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let r = rec(
            "/p",
            "claude",
            DecisionKind::Allow,
            datetime!(2026-10-13 08:00:00 UTC),
        );
        append(dir.path(), &r).unwrap();
        let mode = fs::metadata(dir.path().join("2026-10.jsonl"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn default_dir_honors_env_override() {
        // Only this test touches DIR_ENV in this test binary.
        std::env::set_var(DIR_ENV, "/tmp/saiife-audit-override");
        assert_eq!(
            default_dir(),
            Some(PathBuf::from("/tmp/saiife-audit-override"))
        );
        std::env::set_var(DIR_ENV, "");
        assert!(default_dir().unwrap().ends_with("saiife/audit"));
        std::env::remove_var(DIR_ENV);
    }

    #[test]
    fn filter_since_project_agent_blocked() {
        let now = datetime!(2026-10-13 12:00:00 UTC);
        let old = rec(
            "/p",
            "claude",
            DecisionKind::Deny,
            datetime!(2026-09-01 00:00:00 UTC),
        );
        let deny = rec("/p/sub", "codex", DecisionKind::Deny, now);
        let allow = rec("/other", "claude", DecisionKind::Allow, now);

        let f = Filter {
            since: Some(datetime!(2026-10-01 00:00:00 UTC)),
            ..Default::default()
        };
        assert!(!f.matches(&old) && f.matches(&deny) && f.matches(&allow));

        let f = Filter {
            project: Some("/p".into()),
            ..Default::default()
        };
        assert!(f.matches(&old) && f.matches(&deny) && !f.matches(&allow));
        let f = Filter {
            project: Some("/p/".into()),
            ..Default::default()
        };
        assert!(f.matches(&deny), "trailing slash is ignored");
        let f = Filter {
            project: Some("/p/su".into()),
            ..Default::default()
        };
        assert!(!f.matches(&deny), "prefix must end on a path boundary");

        let f = Filter {
            agent: Some("codex".into()),
            ..Default::default()
        };
        assert!(!f.matches(&old) && f.matches(&deny));

        let f = Filter {
            blocked_only: true,
            ..Default::default()
        };
        assert!(f.matches(&deny) && !f.matches(&allow));

        let mut broken = deny.clone();
        broken.ts = "garbage".into();
        let f = Filter {
            since: Some(datetime!(2026-10-01 00:00:00 UTC)),
            ..Default::default()
        };
        assert!(
            !f.matches(&broken),
            "unparseable ts is excluded when --since is set"
        );
    }
}
