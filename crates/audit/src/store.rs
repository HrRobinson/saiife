//! Monthly JSONL files under the user's data dir (spec §6.1).

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use time::OffsetDateTime;

use crate::record::{DecisionKind, Record};

/// Environment variable that overrides the audit directory (tests, admins).
pub const DIR_ENV: &str = "SAIIFE_AUDIT_DIR";

/// The audit dir: `SAIIFE_AUDIT_DIR` when it is an absolute path, else the
/// default under the user's data dir. A relative value is ignored: it would
/// put the log under the hook's working directory, usually the project
/// (spec §6.1: never inside the project).
pub fn default_dir() -> Option<PathBuf> {
    dir_from(std::env::var_os(DIR_ENV))
}

fn dir_from(var: Option<std::ffi::OsString>) -> Option<PathBuf> {
    match var {
        Some(d) if Path::new(&d).is_absolute() => Some(PathBuf::from(d)),
        _ => dirs::data_dir().map(|d| d.join("saiife").join("audit")),
    }
}

/// Append one record as a single line to `<dir>/<YYYY-MM>.jsonl`, creating the
/// dir and file as needed. New files are owner-only (0600) on unix: commands
/// can reveal what people work on. The whole line goes out in one
/// `write_all` on an `O_APPEND` handle so parallel hooks do not interleave.
///
/// The hook must never hang or write somewhere unexpected: on unix the file
/// is opened with `O_NONBLOCK | O_NOFOLLOW` (a FIFO or symlink planted at the
/// month path fails instead of blocking or redirecting the write), and
/// anything that is not a regular file is refused.
pub fn append(dir: &Path, rec: &Record) -> io::Result<()> {
    create_private_dir(dir)?;
    let mut file = open_append(&dir.join(format!("{}.jsonl", rec.month())))?;
    let mut line = serde_json::to_string(rec).map_err(io::Error::other)?;
    line.push('\n');
    file.write_all(line.as_bytes())
}

/// Open (creating 0600) `path` for appending, refusing a symlink, FIFO or
/// anything else that is not a regular file.
pub(crate) fn open_append(path: &Path) -> io::Result<fs::File> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let file = opts.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("audit log path is not a regular file"));
    }
    Ok(file)
}

/// `create_dir_all`, with owner-only (0700) permissions on unix for the
/// directories it creates: the log reveals what people work on. An existing
/// loose directory is tightened to 0700 too, best-effort, and only when it is
/// a real directory (not a symlink); a failed chmod (e.g. not the owner) is ignored.
pub(crate) fn create_private_dir(dir: &Path) -> io::Result<()> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)?;
    // `create_dir_all` leaves an existing directory alone: tighten a loose one.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(md) = fs::symlink_metadata(dir) {
            // No owner check (this crate forbids unsafe, so no geteuid): a
            // directory owned by someone else makes chmod fail with EPERM,
            // which is ignored.
            if md.is_dir() && md.permissions().mode() & 0o077 != 0 {
                let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
            }
        }
    }
    Ok(())
}

/// What `read_all` found: the parseable records plus how much it had to skip,
/// so a viewer can say the log is not complete.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReadResult {
    pub records: Vec<Record>,
    /// Non-blank lines that were not a valid record (bad UTF-8, half-written,
    /// hand-edited).
    pub skipped_lines: usize,
    /// Month files that could not be read or are not regular files
    /// (symlinks, FIFOs, directories).
    pub unreadable_files: usize,
    /// Set when the audit directory itself exists but cannot be listed
    /// (permissions, not a directory). A missing directory is not an error:
    /// it only means nothing was recorded yet.
    pub dir_error: Option<String>,
    /// `read_recent` only: it stopped (at `max_files`, or because `want`
    /// asked it to) with older month files left unread, so "no record
    /// found" means "none in the files read", not "none at all".
    pub cut_short: bool,
}

/// The `YYYY-MM.jsonl` files in `dir`, oldest first. A missing directory is an
/// empty list; any other failure to list it is the error text.
pub(crate) fn month_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.to_string()),
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
    Ok(files)
}

/// Parse `p` line by line into `out`, counting what it had to skip.
fn read_month_file(p: &Path, out: &mut ReadResult) {
    let Some(body) = read_regular(p) else {
        out.unreadable_files += 1;
        return;
    };
    for line in body.split(|&b| b == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        match serde_json::from_slice::<Record>(line) {
            Ok(r) => out.records.push(r),
            Err(_) => out.skipped_lines += 1,
        }
    }
}

/// Every parseable record from every `YYYY-MM.jsonl` in `dir`, oldest file
/// first. Lines are parsed one by one from raw bytes, so one bad line never
/// hides the rest of its file. Other file names are ignored.
pub fn read_all(dir: &Path) -> ReadResult {
    let mut out = ReadResult::default();
    match month_files(dir) {
        Ok(files) => files.iter().for_each(|p| read_month_file(p, &mut out)),
        Err(e) => out.dir_error = Some(e),
    }
    out
}

/// Read at most `max_files` month files, newest first (`cut_short` says
/// whether older ones were left unread). `want` sees every record of each file
/// and returns `true` while it still needs older data; after the first file
/// in which it returned `false` the older files are not opened (so their
/// problems are not counted). Records come back newest file first, each file
/// in its own order.
pub fn read_recent(
    dir: &Path,
    max_files: usize,
    mut want: impl FnMut(&Record) -> bool,
) -> ReadResult {
    let mut out = ReadResult::default();
    let files = match month_files(dir) {
        Ok(files) => files,
        Err(e) => {
            out.dir_error = Some(e);
            return out;
        }
    };
    let mut unread = files.len();
    for p in files.iter().rev().take(max_files) {
        let start = out.records.len();
        read_month_file(p, &mut out);
        unread -= 1;
        let mut more = true;
        for r in &out.records[start..] {
            more &= want(r);
        }
        if !more {
            break;
        }
    }
    out.cut_short = unread > 0;
    out
}

/// The file's bytes if it is a regular file. Never follows a symlink and
/// never blocks on a FIFO: checked before opening and again on the handle.
pub(crate) fn read_regular(p: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut f = open_regular(p)?;
    let mut body = Vec::new();
    f.read_to_end(&mut body).ok()?;
    Some(body)
}

/// `p` opened for reading if it is a regular file, with the same checks as
/// `read_regular`.
pub(crate) fn open_regular(p: &Path) -> Option<fs::File> {
    if !fs::symlink_metadata(p).ok()?.is_file() {
        return None;
    }
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let f = opts.open(p).ok()?;
    f.metadata().ok()?.is_file().then_some(f)
}

/// `YYYY-MM.jsonl`
pub(crate) fn is_month_file(name: &str) -> bool {
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
        if r.is_bookkeeping() {
            return false;
        }
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
                mode: "developer",
                policy: None,
                permission_mode: None,
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
        assert_eq!(read_all(dir.path()).records, vec![a, b]);
    }

    #[test]
    fn read_recent_stops_early() {
        let dir = tempfile::tempdir().unwrap();
        let at = |m: u8| {
            OffsetDateTime::from_unix_timestamp(1_700_000_000 + i64::from(m) * 3_000_000).unwrap()
        };
        let old = rec("/p", "claude", DecisionKind::Allow, at(0));
        let new = rec("/p", "claude", DecisionKind::Allow, at(6));
        append(dir.path(), &old).unwrap();
        append(dir.path(), &new).unwrap();
        // A directory named like the oldest month file: unreadable if opened.
        let months = [old.month(), new.month()];
        assert_ne!(months[0], months[1]);
        fs::remove_file(dir.path().join(format!("{}.jsonl", months[0]))).unwrap();
        fs::create_dir(dir.path().join(format!("{}.jsonl", months[0]))).unwrap();

        let stopped = read_recent(dir.path(), usize::MAX, |_| false);
        assert_eq!(stopped.records, vec![new.clone()]);
        assert_eq!(stopped.unreadable_files, 0);

        let all = read_recent(dir.path(), usize::MAX, |_| true);
        assert_eq!(all.records, vec![new]);
        assert_eq!(all.unreadable_files, 1);
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
        assert_eq!(read_all(&nested).records.len(), 1);
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
        let got = read_all(dir.path());
        assert_eq!(got.records, vec![good]);
        assert_eq!(
            got.skipped_lines, 2,
            "half-written + not json; blank ignored"
        );
    }

    #[test]
    fn invalid_utf8_line_skips_only_that_line_and_is_counted() {
        let dir = tempfile::tempdir().unwrap();
        let a = rec(
            "/p",
            "claude",
            DecisionKind::Allow,
            datetime!(2026-10-13 08:00:00 UTC),
        );
        let b = rec(
            "/p",
            "claude",
            DecisionKind::Deny,
            datetime!(2026-10-13 09:00:00 UTC),
        );
        append(dir.path(), &a).unwrap();
        let mut f = OpenOptions::new()
            .append(true)
            .open(dir.path().join("2026-10.jsonl"))
            .unwrap();
        f.write_all(b"{\"v\":1,\"input\":\"\xff\"}\n").unwrap();
        drop(f);
        append(dir.path(), &b).unwrap();
        let got = read_all(dir.path());
        assert_eq!(got.records, vec![a, b]);
        assert_eq!(got.skipped_lines, 1);
        assert_eq!(got.unreadable_files, 0);
    }

    #[test]
    fn read_all_of_missing_dir_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_all(&dir.path().join("nope")), ReadResult::default());
    }

    #[test]
    fn read_all_of_an_unlistable_dir_says_so() {
        // A file where the directory should be: unreadable even as root
        // (the offline CI job runs tests as root in a user namespace).
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("audit");
        fs::write(&file, "x").unwrap();
        let got = read_all(&file);
        assert!(got.records.is_empty());
        assert!(got.dir_error.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn existing_loose_audit_dir_is_tightened() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("audit");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let r = rec(
            "/p",
            "claude",
            DecisionKind::Allow,
            datetime!(2026-10-13 08:00:00 UTC),
        );
        append(&dir, &r).unwrap();
        let mode = fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_audit_dir_target_is_left_alone() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let target = base.path().join("real");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let r = rec(
            "/p",
            "claude",
            DecisionKind::Allow,
            datetime!(2026-10-13 08:00:00 UTC),
        );
        append(&link, &r).unwrap();
        let mode = fs::metadata(&target).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
    }

    /// The size that matters is the serialized line, not the field lengths:
    /// multibyte input stays within 4096 chars but is several times that in
    /// bytes, and the file holds exactly the serialized bytes plus a newline.
    #[test]
    fn record_size_check_measures_serialized_line() {
        let dir = tempfile::tempdir().unwrap();
        let mut r = rec(
            "/p",
            "claude",
            DecisionKind::Allow,
            datetime!(2026-10-13 08:00:00 UTC),
        );
        r.input = "\u{1F600}".repeat(5000);
        let line = serde_json::to_string(&r).unwrap();
        assert!(line.len() > 16 * 1024);
        append(dir.path(), &r).unwrap();
        let file = dir.path().join(format!("{}.jsonl", r.month()));
        assert_eq!(fs::metadata(file).unwrap().len() as usize, line.len() + 1);
    }

    #[cfg(unix)]
    #[test]
    fn audit_dir_is_0700() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("a").join("audit");
        let r = rec(
            "/p",
            "claude",
            DecisionKind::Allow,
            datetime!(2026-10-13 08:00:00 UTC),
        );
        append(&dir, &r).unwrap();
        let mode = fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
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

    #[cfg(unix)]
    fn mkfifo(path: &Path) {
        let ok = std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .unwrap()
            .success();
        assert!(ok, "mkfifo failed");
    }

    #[cfg(unix)]
    #[test]
    fn append_refuses_a_symlinked_month_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.txt");
        fs::write(&target, "original").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("2026-10.jsonl")).unwrap();
        let r = rec(
            "/p",
            "claude",
            DecisionKind::Allow,
            datetime!(2026-10-13 08:00:00 UTC),
        );
        assert!(append(dir.path(), &r).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "original");
    }

    #[cfg(unix)]
    #[test]
    fn append_to_a_fifo_errors_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        mkfifo(&dir.path().join("2026-10.jsonl"));
        let r = rec(
            "/p",
            "claude",
            DecisionKind::Allow,
            datetime!(2026-10-13 08:00:00 UTC),
        );
        let (tx, rx) = std::sync::mpsc::channel();
        let path = dir.path().to_path_buf();
        std::thread::spawn(move || tx.send(append(&path, &r).is_err()).unwrap());
        let errored = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("append blocked on a FIFO");
        assert!(errored);
    }

    #[cfg(unix)]
    #[test]
    fn read_all_skips_fifos_and_symlinks_and_counts_them() {
        let dir = tempfile::tempdir().unwrap();
        let good = rec(
            "/p",
            "claude",
            DecisionKind::Allow,
            datetime!(2026-10-13 08:00:00 UTC),
        );
        append(dir.path(), &good).unwrap();
        mkfifo(&dir.path().join("2026-09.jsonl"));
        std::os::unix::fs::symlink(
            dir.path().join("2026-10.jsonl"),
            dir.path().join("2026-08.jsonl"),
        )
        .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let path = dir.path().to_path_buf();
        std::thread::spawn(move || tx.send(read_all(&path)).unwrap());
        let got = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("read_all blocked on a FIFO");
        assert_eq!(got.records, vec![good]);
        assert_eq!(got.unreadable_files, 2);
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
    fn read_recent_reads_at_most_max_files() {
        let dir = tempfile::tempdir().unwrap();
        for m in ["2026-01", "2026-02", "2026-03"] {
            fs::write(dir.path().join(format!("{m}.jsonl")), "not json\n").unwrap();
        }
        let got = read_recent(dir.path(), 2, |_| true);
        assert_eq!(got.skipped_lines, 2);
    }

    #[test]
    fn read_recent_reads_past_empty_month_files() {
        let dir = tempfile::tempdir().unwrap();
        for m in ["2026-01", "2026-02", "2026-03"] {
            fs::write(dir.path().join(format!("{m}.jsonl")), "").unwrap();
        }
        let mut calls = 0;
        let got = read_recent(dir.path(), 12, |_| {
            calls += 1;
            false
        });
        assert_eq!(calls, 0, "empty files have no records to show");
        assert_eq!(got, ReadResult::default(), "every existing file was read");
        assert!(!got.cut_short, "nothing was left unread");
    }

    #[test]
    fn read_recent_is_cut_short_only_with_files_left_unread() {
        let dir = tempfile::tempdir().unwrap();
        for m in ["2026-01", "2026-02", "2026-03"] {
            fs::write(dir.path().join(format!("{m}.jsonl")), "not json\n").unwrap();
        }
        assert!(
            read_recent(dir.path(), 2, |_| true).cut_short,
            "max_files hit"
        );
        assert!(!read_recent(dir.path(), 3, |_| true).cut_short, "all read");
        assert!(!read_recent(dir.path(), 12, |_| true).cut_short);
        assert!(!read_recent(&dir.path().join("nope"), 12, |_| true).cut_short);

        let a = rec(
            "/p",
            "claude",
            DecisionKind::Allow,
            datetime!(2026-01-02 00:00:00 UTC),
        );
        let b = rec(
            "/p",
            "claude",
            DecisionKind::Allow,
            datetime!(2026-03-02 00:00:00 UTC),
        );
        let dir = tempfile::tempdir().unwrap();
        append(dir.path(), &a).unwrap();
        append(dir.path(), &b).unwrap();
        let stopped = read_recent(dir.path(), 12, |_| false);
        assert_eq!(stopped.records, vec![b]);
        assert!(stopped.cut_short, "want stopped with an older file unread");
        let one = read_recent(dir.path(), 12, |r| r.ts.starts_with("2026-03"));
        assert!(!one.cut_short, "want stopped on the last file");
    }

    #[test]
    fn a_relative_audit_dir_is_ignored() {
        let default = dir_from(None);
        assert!(default.as_ref().unwrap().ends_with("saiife/audit"));
        assert_eq!(dir_from(Some("rel-audit".into())), default);
        assert_eq!(dir_from(Some("".into())), default);
        assert_eq!(
            dir_from(Some("/abs/audit".into())),
            Some(PathBuf::from("/abs/audit"))
        );
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

    #[test]
    fn filter_hides_bookkeeping() {
        let mut g = rec(
            "/p",
            "claude",
            DecisionKind::Allow,
            datetime!(2026-10-13 12:00:00 UTC),
        );
        assert!(Filter::default().matches(&g));
        g.kind = Some("genesis".into());
        assert!(!Filter::default().matches(&g));
    }
}
