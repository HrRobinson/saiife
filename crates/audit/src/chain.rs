//! Hash-chained appender (spec §6.4.1, §6.4.4).
//!
//! Every chained record carries `seq` (one more than the record before it)
//! and `prev`, the SHA-256 of the exact bytes of the previous line. Appends
//! are serialised by a lock file in the audit dir so parallel hooks cannot
//! fork the chain. The audit log stays best-effort: when the lock cannot be
//! had the record is still written, unchained, and the caller is told.

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::record::{DecisionKind, NewRecord, Record};
use crate::store;

/// `prev` of a genesis record: 64 zeros.
pub const ZERO_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Lock file in the audit dir that serialises chained appends.
pub const LOCK_FILE: &str = ".chain.lock";

/// How much of the newest month file is read to find the chain's tail: keeps
/// the hook inside its time budget however big the file grows.
const TAIL_WINDOW: u64 = 256 * 1024;
/// How much the backwards search for the last chained record may read in
/// all, over every month file, before it gives up and starts a new chain.
const MAX_SCAN: u64 = 4 * 1024 * 1024;
const LOCK_WAIT: Duration = Duration::from_millis(1000);
const LOCK_RETRY: Duration = Duration::from_millis(5);

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A stable, non-reversible id of this machine: the SHA-256 of the machine
/// id (never the raw value), or `None` when the platform has none to offer.
pub fn host_id() -> Option<String> {
    raw_machine_id().map(|id| sha256_hex(id.as_bytes()))
}

#[cfg(target_os = "macos")]
fn raw_machine_id() -> Option<String> {
    let out = std::process::Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().find(|l| l.contains("\"IOPlatformUUID\""))?;
    let id = line.split('"').nth(3)?.trim();
    (!id.is_empty()).then(|| id.to_string())
}

#[cfg(not(target_os = "macos"))]
fn raw_machine_id() -> Option<String> {
    ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .iter()
        .find_map(|p| {
            let body = store::read_regular(Path::new(p))?;
            let id = String::from_utf8(body).ok()?.trim().to_string();
            (!id.is_empty()).then_some(id)
        })
}

/// The error `append_chained` returns when the record was written, but
/// without the chain: the caller warns, `verify` reports the gap later.
#[derive(Debug)]
pub struct WrittenUnchained {
    /// Why the chain could not be continued.
    pub reason: String,
}

impl std::fmt::Display for WrittenUnchained {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "audit record written without the chain ({})",
            self.reason
        )
    }
}

impl std::error::Error for WrittenUnchained {}

/// The `WrittenUnchained` inside an error of `append_chained`; `None` when
/// the record was not written at all.
pub fn written_unchained(e: &io::Error) -> Option<&WrittenUnchained> {
    e.get_ref()?.downcast_ref()
}

/// Append `rec` to the hash chain in `dir` and return its `seq`.
///
/// The record is never dropped for the chain's sake: if the lock cannot be
/// opened or taken within a second, or anything fails while it is held, the
/// record is written unchained (no `seq`/`prev`) and a `WrittenUnchained`
/// error is returned so the caller can warn; `verify` reports the gap later.
/// Any other error means the record was not written.
pub fn append_chained(dir: &Path, mut rec: Record) -> io::Result<u64> {
    store::create_private_dir(dir)?;
    fill_identity(&mut rec);
    let err = match take_lock(dir) {
        // The flock is held until `_lock` drops at the end of this arm.
        Some(_lock) => match append_locked(dir, rec.clone()) {
            Ok(seq) => return Ok(seq),
            Err(e) => e,
        },
        None => io::Error::other("audit chain lock unavailable"),
    };
    rec.seq = None;
    rec.prev = None;
    append_unchained(dir, &rec)?;
    Err(io::Error::other(WrittenUnchained {
        reason: err.to_string(),
    }))
}

/// The fallback write: the same target rule as the chained path (never an
/// older file than the newest), else the record's own month file.
fn append_unchained(dir: &Path, rec: &Record) -> io::Result<()> {
    let files = regular_month_files(dir).unwrap_or_default();
    let target = target_file(dir, rec, &files);
    let mut line = serde_json::to_vec(rec).map_err(io::Error::other)?;
    line.push(b'\n');
    match store::open_append(&target).and_then(|mut f| f.write_all(&line)) {
        Ok(()) => Ok(()),
        Err(_) if target != dir.join(format!("{}.jsonl", rec.month())) => store::append(dir, rec),
        Err(e) => Err(e),
    }
}

/// `uid` and `user`, only where the caller left them unset.
fn fill_identity(rec: &mut Record) {
    #[cfg(unix)]
    if rec.uid.is_none() {
        rec.uid = Some(rustix::process::getuid().as_raw());
    }
    if rec.user.is_none() {
        rec.user = ["USER", "LOGNAME"]
            .iter()
            .filter_map(std::env::var_os)
            .filter_map(|v| v.into_string().ok())
            .find(|v| !v.is_empty());
    }
}

/// The lock file, opened 0600 without following a symlink, refused unless it
/// is a regular file, and locked within `LOCK_WAIT`.
fn take_lock(dir: &Path) -> Option<File> {
    let mut opts = fs::OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let file = opts.open(dir.join(LOCK_FILE)).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let deadline = Instant::now() + LOCK_WAIT;
    loop {
        match file.try_lock() {
            Ok(()) => return Some(file),
            Err(fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(LOCK_RETRY);
            }
            Err(_) => return None,
        }
    }
}

/// Where the chain stands: the hash of the last line and the last chained
/// line, if the chain can be continued.
struct Tail {
    prev: String,
    last: Option<TailLine>,
}

/// What the tail scan reads of a line: exactly what `verify` judges a line
/// by (`v`, defaulting to 1, and `seq`), plus the `host` to carry on. A line
/// is not required to parse as a full `Record`.
struct TailLine {
    v: u64,
    seq: Option<u64>,
    host: Option<String>,
}

impl TailLine {
    /// `None` unless `line` is a JSON object (as in `verify`).
    fn parse(line: &[u8]) -> Option<Self> {
        let serde_json::Value::Object(obj) = serde_json::from_slice(line).ok()? else {
            return None;
        };
        Some(Self {
            v: obj
                .get("v")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(1),
            seq: obj.get("seq").and_then(serde_json::Value::as_u64),
            host: obj
                .get("host")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
        })
    }
}

fn append_locked(dir: &Path, mut rec: Record) -> io::Result<u64> {
    let files = regular_month_files(dir)?;
    let target = target_file(dir, &rec, &files);
    // Only the target and the files before it: a planted or clock-skewed
    // later file must not lend its tail to every record written now.
    let target_name = target.file_name();
    let upto: Vec<PathBuf> = files
        .into_iter()
        .filter(|p| p.file_name() <= target_name)
        .collect();
    let tail = find_tail(&upto)?;

    let mut out = Vec::new();
    let next = tail
        .and_then(|t| t.last.map(|r| (r, t.prev)))
        .and_then(|(last, prev)| {
            // A last seq of u64::MAX cannot be followed: start a new chain.
            let seq = last.seq.unwrap_or(0).checked_add(1)?;
            Some((seq, prev, last.host))
        });
    let (seq, prev, host) = match next {
        Some(n) => n,
        None => {
            let g = genesis(&rec)?;
            let line = serde_json::to_vec(&g).map_err(io::Error::other)?;
            let prev = sha256_hex(&line);
            out.extend_from_slice(&line);
            out.push(b'\n');
            (1, prev, g.host)
        }
    };
    rec.seq = Some(seq);
    rec.prev = Some(prev);
    rec.host = host;
    serde_json::to_writer(&mut out, &rec).map_err(io::Error::other)?;
    out.push(b'\n');
    store::open_append(&target)?.write_all(&out)?;
    Ok(seq)
}

/// The month files of `dir` that are regular files (a planted symlink, FIFO
/// or directory is skipped), oldest first.
fn regular_month_files(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = store::month_files(dir).map_err(io::Error::other)?;
    files.retain(|p| fs::symlink_metadata(p).is_ok_and(|m| m.is_file()));
    Ok(files)
}

/// `(year, month)` of a `YYYY-MM` prefix with a real month (01–12).
fn year_month(name: &str) -> Option<(u32, u32)> {
    let y = name.get(..4)?.parse().ok()?;
    let m = name.get(5..7)?.parse().ok()?;
    (name.as_bytes().get(4) == Some(&b'-') && (1..=12).contains(&m)).then_some((y, m))
}

/// `<month>.jsonl` for the record, or the newest existing month file when
/// that is later: a clock that went back must not write into the chain's
/// past. Only a real month at most one month ahead of the record's is
/// followed, so a planted `9999-12.jsonl` cannot divert every later record.
fn target_file(dir: &Path, rec: &Record, files: &[PathBuf]) -> PathBuf {
    let own = dir.join(format!("{}.jsonl", rec.month()));
    let newest = files
        .last()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str());
    let (Some(n), Some((y, m))) = (newest, year_month(rec.month())) else {
        return own;
    };
    let next = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
    match year_month(n) {
        Some(nm) if nm > (y, m) && nm <= next && store::is_month_file(n) => dir.join(n),
        _ => own,
    }
}

/// What the backwards search found.
enum Found {
    /// The last chained line.
    Chained(TailLine),
    /// A v1 line or the read budget ran out: a new chain must start.
    Stop,
    /// The file's first line was reached without a decision.
    More,
}

/// The chain's tail among `files` (the caller passes only those up to the
/// write target). `prev` hashes the physical last line of the newest
/// non-empty one of them; a missing final newline there (a crash mid-write)
/// is added first so the half line stays a line of its own. The last chained
/// record is the newest line, searching backwards through that file and then
/// older ones, that is a JSON object with `v >= 2` and a `seq` (the rules
/// of `verify`; see `TailLine`). Unparseable and
/// unchained lines are passed over; a v1 line ends the search (a v1 writer
/// appended after the chain), and so does reading `MAX_SCAN` bytes in all.
fn find_tail(files: &[PathBuf]) -> io::Result<Option<Tail>> {
    let non_empty: Vec<&PathBuf> = files
        .iter()
        .filter(|p| fs::symlink_metadata(p).is_ok_and(|m| m.len() > 0))
        .collect();
    let Some(newest) = non_empty.last() else {
        return Ok(None);
    };
    terminate(newest)?;
    let mut budget = MAX_SCAN;
    let mut prev = None;
    let mut last = None;
    for path in non_empty.iter().rev() {
        let found = scan_back(path, &mut budget, |line| {
            if prev.is_none() {
                prev = Some(sha256_hex(line));
            }
            match TailLine::parse(line) {
                Some(t) if t.v < 2 => Some(Found::Stop),
                Some(t) if t.seq.is_some() => Some(Found::Chained(t)),
                _ => None,
            }
        })?;
        match found {
            Found::Chained(t) => {
                last = Some(t);
                break;
            }
            Found::Stop => break,
            Found::More => {}
        }
    }
    Ok(prev.map(|prev| Tail { prev, last }))
}

/// Add a `\n` to `path` unless it already ends with one.
fn terminate(path: &Path) -> io::Result<()> {
    let mut f = store::open_regular(path).ok_or_else(not_regular)?;
    let len = f.metadata()?.len();
    let mut end = [0u8];
    if len > 0 {
        f.seek(SeekFrom::Start(len - 1))?;
        f.read_exact(&mut end)?;
        if end[0] != b'\n' {
            store::open_append(path)?.write_all(b"\n")?;
        }
    }
    Ok(())
}

fn not_regular() -> io::Error {
    io::Error::other("audit log path is not a regular file")
}

/// Feed the lines of `path` to `on_line`, last first, reading backwards in
/// `TAIL_WINDOW` chunks and charging every byte read to `budget`. The final
/// newline does not start an empty line. Stops at the first `Some`.
fn scan_back(
    path: &Path,
    budget: &mut u64,
    mut on_line: impl FnMut(&[u8]) -> Option<Found>,
) -> io::Result<Found> {
    let mut f = store::open_regular(path).ok_or_else(not_regular)?;
    let mut pos = f.metadata()?.len();
    let mut carry: Vec<u8> = Vec::new();
    let mut first = true;
    loop {
        let n = TAIL_WINDOW.min(pos).min(*budget);
        if n == 0 && pos > 0 {
            return Ok(Found::Stop);
        }
        pos -= n;
        *budget -= n;
        let mut buf = vec![0u8; n as usize];
        f.seek(SeekFrom::Start(pos))?;
        f.read_exact(&mut buf)?;
        if std::mem::take(&mut first) && buf.last() == Some(&b'\n') {
            buf.pop();
        }
        buf.extend_from_slice(&carry);
        let mut parts: Vec<&[u8]> = buf.split(|&b| b == b'\n').collect();
        // Unless the file start was reached, the first piece may be cut.
        let head = if pos > 0 { Some(parts.remove(0)) } else { None };
        for line in parts.iter().rev() {
            if let Some(found) = on_line(line) {
                return Ok(found);
            }
        }
        match head {
            Some(h) => carry = h.to_vec(),
            None => return Ok(Found::More),
        }
    }
}

/// Record 0 of a new chain (spec §6.4.1).
fn genesis(rec: &Record) -> io::Result<Record> {
    let mut g = Record::new(
        NewRecord {
            agent: "",
            project: "",
            session: None,
            tool: "genesis",
            input: "",
            decision: DecisionKind::Allow,
            pack: None,
            rule: None,
            reason: None,
            mode: "developer",
            policy: None,
            permission_mode: None,
        },
        &rec.saiife,
    );
    g.kind = Some("genesis".into());
    g.seq = Some(0);
    g.prev = Some(ZERO_PREV.into());
    g.host = host_id();
    g.uid = rec.uid;
    g.user = rec.user.clone();
    g.extra.insert("chain".into(), uuid_v4()?.into());
    Ok(g)
}

/// A random UUID v4, lowercase `8-4-4-4-12`.
fn uuid_v4() -> io::Result<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| io::Error::other(e.to_string()))?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{DecisionKind, NewRecord};
    use std::fs;
    use std::io::Write;
    use time::macros::datetime;
    use time::OffsetDateTime;

    fn rec(at: OffsetDateTime) -> Record {
        Record::at(
            NewRecord {
                agent: "claude",
                project: "/p",
                session: None,
                tool: "Bash",
                input: "ls",
                decision: DecisionKind::Allow,
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

    fn lines(p: &Path) -> Vec<Vec<u8>> {
        let body = fs::read(p).unwrap();
        assert!(body.ends_with(b"\n"), "file ends with a newline");
        body[..body.len() - 1]
            .split(|&b| b == b'\n')
            .map(<[u8]>::to_vec)
            .collect()
    }

    fn parse(line: &[u8]) -> Record {
        serde_json::from_slice(line).unwrap()
    }

    fn is_uuid_v4(s: &str) -> bool {
        let b = s.as_bytes();
        s.len() == 36
            && [8, 13, 18, 23].iter().all(|&i| b[i] == b'-')
            && b.iter()
                .enumerate()
                .filter(|(i, _)| ![8, 13, 18, 23].contains(i))
                .all(|(_, c)| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
            && b[14] == b'4'
            && b"89ab".contains(&b[19])
    }

    #[test]
    fn sha256_hex_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn first_append_writes_genesis_then_seq_1() {
        let dir = tempfile::tempdir().unwrap();
        let seq = append_chained(dir.path(), rec(datetime!(2026-10-13 08:00:00 UTC))).unwrap();
        assert_eq!(seq, 1);
        let ls = lines(&dir.path().join("2026-10.jsonl"));
        assert_eq!(ls.len(), 2);
        let g = parse(&ls[0]);
        assert_eq!(g.kind(), "genesis");
        assert_eq!(g.tool, "genesis");
        assert_eq!(g.seq, Some(0));
        assert_eq!(g.prev.as_deref(), Some(ZERO_PREV));
        assert_eq!(g.mode.as_deref(), Some("developer"));
        let chain = g.extra["chain"].as_str().unwrap();
        assert!(is_uuid_v4(chain), "{chain}");
        assert!(!g.extra.contains_key("key"));
        let r = parse(&ls[1]);
        assert_eq!(r.seq, Some(1));
        assert_eq!(r.prev, Some(sha256_hex(&ls[0])));
        assert_eq!(r.host, g.host, "host is carried over from the chain");
        assert!(r.uid.is_some());
        assert_eq!(r.tool, "Bash");
    }

    #[test]
    fn seq_increments_across_month_files() {
        let dir = tempfile::tempdir().unwrap();
        append_chained(dir.path(), rec(datetime!(2026-10-13 08:00:00 UTC))).unwrap();
        let seq = append_chained(dir.path(), rec(datetime!(2026-11-01 00:00:00 UTC))).unwrap();
        assert_eq!(seq, 2);
        let oct = lines(&dir.path().join("2026-10.jsonl"));
        let nov = lines(&dir.path().join("2026-11.jsonl"));
        assert_eq!((oct.len(), nov.len()), (2, 1));
        let r = parse(&nov[0]);
        assert_eq!(r.seq, Some(2));
        assert_eq!(r.prev, Some(sha256_hex(oct.last().unwrap())));
    }

    #[test]
    fn genesis_after_v1_files() {
        let dir = tempfile::tempdir().unwrap();
        let v1 = "{\"v\":1,\"ts\":\"2026-09-13T08:14:02.381Z\",\"agent\":\"codex\",\"project\":\"/p\",\"tool\":\"shell\",\"input\":\"ls\",\"decision\":\"allow\",\"saiife\":\"0.1.0\"}\n";
        fs::write(dir.path().join("2026-09.jsonl"), v1).unwrap();
        let seq = append_chained(dir.path(), rec(datetime!(2026-10-13 08:00:00 UTC))).unwrap();
        assert_eq!(seq, 1);
        assert_eq!(
            fs::read_to_string(dir.path().join("2026-09.jsonl")).unwrap(),
            v1
        );
        let ls = lines(&dir.path().join("2026-10.jsonl"));
        assert_eq!(ls.len(), 2);
        let g = parse(&ls[0]);
        assert_eq!(g.kind(), "genesis");
        assert_eq!(g.prev.as_deref(), Some(ZERO_PREV));
    }

    #[test]
    fn v1_line_after_chain_starts_a_new_chain() {
        let dir = tempfile::tempdir().unwrap();
        append_chained(dir.path(), rec(datetime!(2026-10-13 08:00:00 UTC))).unwrap();
        let file = dir.path().join("2026-10.jsonl");
        let mut f = fs::OpenOptions::new().append(true).open(&file).unwrap();
        f.write_all(b"{\"v\":1,\"ts\":\"2026-10-13T08:14:02.381Z\",\"agent\":\"codex\",\"project\":\"/p\",\"tool\":\"shell\",\"input\":\"ls\",\"decision\":\"allow\",\"saiife\":\"0.1.0\"}\n").unwrap();
        drop(f);
        assert_eq!(
            append_chained(dir.path(), rec(datetime!(2026-10-13 09:00:00 UTC))).unwrap(),
            1
        );
        let ls = lines(&file);
        assert_eq!(ls.len(), 5);
        assert_eq!(parse(&ls[3]).kind(), "genesis");
    }

    #[test]
    fn partial_last_line_is_terminated() {
        let dir = tempfile::tempdir().unwrap();
        for h in 8..10 {
            append_chained(
                dir.path(),
                rec(datetime!(2026-10-13 08:00:00 UTC) + time::Duration::hours(h - 8)),
            )
            .unwrap();
        }
        let file = dir.path().join("2026-10.jsonl");
        let mut f = fs::OpenOptions::new().append(true).open(&file).unwrap();
        f.write_all(b"{\"v\":2,\"se").unwrap();
        drop(f);
        let seq = append_chained(dir.path(), rec(datetime!(2026-10-13 10:00:00 UTC))).unwrap();
        assert_eq!(seq, 3);
        let ls = lines(&file);
        assert_eq!(ls.len(), 5);
        assert_eq!(ls[3], b"{\"v\":2,\"se");
        let r = parse(&ls[4]);
        assert_eq!(r.seq, Some(3));
        assert_eq!(r.prev, Some(sha256_hex(b"{\"v\":2,\"se")));
    }

    #[test]
    fn clock_going_back_writes_to_newest_file() {
        let dir = tempfile::tempdir().unwrap();
        append_chained(dir.path(), rec(datetime!(2026-11-02 08:00:00 UTC))).unwrap();
        let seq = append_chained(dir.path(), rec(datetime!(2026-10-13 08:00:00 UTC))).unwrap();
        assert_eq!(seq, 2);
        assert!(!dir.path().join("2026-10.jsonl").exists());
        let ls = lines(&dir.path().join("2026-11.jsonl"));
        assert_eq!(ls.len(), 3);
        assert_eq!(parse(&ls[2]).ts, "2026-10-13T08:00:00.000Z");
    }

    #[test]
    fn tail_window_finds_the_chain_in_a_big_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut r = rec(datetime!(2026-10-13 08:00:00 UTC));
        r.input = "x".repeat(4000);
        for _ in 0..80 {
            append_chained(dir.path(), r.clone()).unwrap();
        }
        let file = dir.path().join("2026-10.jsonl");
        assert!(fs::metadata(&file).unwrap().len() > 256 * 1024);
        let ls = lines(&file);
        assert_eq!(ls.len(), 81);
        assert_eq!(parse(&ls[80]).seq, Some(80));
    }

    #[test]
    fn huge_last_line_reads_whole_file() {
        let dir = tempfile::tempdir().unwrap();
        append_chained(dir.path(), rec(datetime!(2026-10-13 08:00:00 UTC))).unwrap();
        let file = dir.path().join("2026-10.jsonl");
        let mut junk = "j".repeat(300 * 1024).into_bytes();
        junk.push(b'\n');
        fs::OpenOptions::new()
            .append(true)
            .open(&file)
            .unwrap()
            .write_all(&junk)
            .unwrap();
        let seq = append_chained(dir.path(), rec(datetime!(2026-10-13 09:00:00 UTC))).unwrap();
        assert_eq!(seq, 2);
        let ls = lines(&file);
        assert_eq!(parse(&ls[3]).prev, Some(sha256_hex(&ls[2])));
    }

    #[test]
    fn parallel_appends_keep_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let d = dir.path().to_path_buf();
                std::thread::spawn(move || {
                    for _ in 0..50 {
                        append_chained(&d, rec(datetime!(2026-10-13 08:00:00 UTC))).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let ls = lines(&dir.path().join("2026-10.jsonl"));
        assert_eq!(ls.len(), 401);
        for (i, l) in ls.iter().enumerate() {
            let r = parse(l);
            assert_eq!(r.seq, Some(i as u64), "line {i}");
            let want = if i == 0 {
                ZERO_PREV.to_string()
            } else {
                sha256_hex(&ls[i - 1])
            };
            assert_eq!(r.prev.as_deref(), Some(want.as_str()), "line {i}");
        }
    }

    #[test]
    fn held_lock_times_out_and_falls_back_unchained() {
        let dir = tempfile::tempdir().unwrap();
        let lock = fs::File::create(dir.path().join(LOCK_FILE)).unwrap();
        lock.lock().unwrap();
        let start = std::time::Instant::now();
        let err = append_chained(dir.path(), rec(datetime!(2026-10-13 08:00:00 UTC)));
        assert!(err.is_err());
        assert!(start.elapsed() >= LOCK_WAIT);
        let ls = lines(&dir.path().join("2026-10.jsonl"));
        assert_eq!(ls.len(), 1);
        assert_eq!(parse(&ls[0]).seq, None);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_lock_file_falls_back_unchained() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("elsewhere");
        fs::write(&target, "original").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join(LOCK_FILE)).unwrap();
        let err = append_chained(dir.path(), rec(datetime!(2026-10-13 08:00:00 UTC)));
        assert!(err.is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "original");
        let ls = lines(&dir.path().join("2026-10.jsonl"));
        assert_eq!(ls.len(), 1);
        let r = parse(&ls[0]);
        assert_eq!(r.v, 2);
        assert_eq!((r.seq, r.prev), (None, None));
        assert_eq!(r.tool, "Bash");
    }

    /// M3: the fallback says what happened in words a user can act on.
    #[cfg(unix)]
    #[test]
    fn unchained_fallback_names_the_reason() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join(LOCK_FILE)).unwrap();
        let err = append_chained(dir.path(), rec(datetime!(2026-10-13 08:00:00 UTC))).unwrap_err();
        let u = written_unchained(&err).expect("an unchained write, not a failed one");
        assert_eq!(
            u.to_string(),
            "audit record written without the chain (audit chain lock unavailable)"
        );
        assert_eq!(lines(&dir.path().join("2026-10.jsonl")).len(), 1);
    }

    /// M1: a planted far-future month file is neither written to nor read
    /// for the tail: records of the real months chain on among themselves.
    #[test]
    fn far_future_file_does_not_fork_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            append_chained(dir.path(), rec(datetime!(2026-10-13 08:00:00 UTC))).unwrap(),
            1
        );
        let mut planted = rec(datetime!(2026-10-13 08:00:00 UTC));
        planted.ts = "9999-12-01T00:00:00.000Z".into();
        planted.seq = Some(50);
        planted.prev = Some(ZERO_PREV.into());
        let mut line = serde_json::to_vec(&planted).unwrap();
        line.push(b'\n');
        fs::write(dir.path().join("9999-12.jsonl"), &line).unwrap();
        let seqs: Vec<u64> = (0..3)
            .map(|i| {
                append_chained(
                    dir.path(),
                    rec(datetime!(2026-10-13 09:00:00 UTC) + time::Duration::minutes(i)),
                )
                .unwrap()
            })
            .collect();
        assert_eq!(seqs, [2, 3, 4]);
        assert_eq!(fs::read(dir.path().join("9999-12.jsonl")).unwrap(), line);
        fs::remove_file(dir.path().join("9999-12.jsonl")).unwrap();
        let report = crate::verify::verify(dir.path());
        assert!(report.breaks.is_empty(), "{:?}", report.breaks);
        assert_eq!(report.chained, 5);
    }

    /// M2: the tail scan judges a line by `v`/`seq` alone, as `verify`
    /// does: a chained line with an odd v1 field is still the tail.
    #[test]
    fn tail_with_broken_v1_field_continues_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        append_chained(dir.path(), rec(datetime!(2026-10-13 08:00:00 UTC))).unwrap();
        let file = dir.path().join("2026-10.jsonl");
        let prev = sha256_hex(lines(&file).last().unwrap());
        let hand = format!(
            "{{\"v\":2,\"seq\":2,\"prev\":\"{prev}\",\"ts\":\"2026-10-13T08:30:00.000Z\",\"agent\":5}}\n"
        );
        append_raw(&file, hand.as_bytes());
        assert_eq!(
            append_chained(dir.path(), rec(datetime!(2026-10-13 09:00:00 UTC))).unwrap(),
            3
        );
        let report = crate::verify::verify(dir.path());
        assert!(report.breaks.is_empty(), "{:?}", report.breaks);
    }

    fn append_raw(p: &Path, bytes: &[u8]) {
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }

    fn unchained_line(ts: &str) -> Vec<u8> {
        let mut r = rec(datetime!(2026-10-13 08:00:00 UTC));
        r.ts = ts.into();
        let mut l = serde_json::to_vec(&r).unwrap();
        l.push(b'\n');
        l
    }

    #[test]
    fn unchained_first_line_of_new_month_keeps_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        append_chained(dir.path(), rec(datetime!(2026-10-13 08:00:00 UTC))).unwrap();
        let nov = dir.path().join("2026-11.jsonl");
        let raw = unchained_line("2026-11-01T00:00:00.000Z");
        append_raw(&nov, &raw);
        let seq = append_chained(dir.path(), rec(datetime!(2026-11-02 00:00:00 UTC))).unwrap();
        assert_eq!(seq, 2);
        let ls = lines(&nov);
        assert_eq!(ls.len(), 2, "no new genesis");
        let r = parse(&ls[1]);
        assert_eq!(r.prev, Some(sha256_hex(&raw[..raw.len() - 1])));
        assert_eq!(r.kind(), "guard");
    }

    #[test]
    fn half_line_alone_in_new_month_keeps_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        append_chained(dir.path(), rec(datetime!(2026-10-13 08:00:00 UTC))).unwrap();
        let nov = dir.path().join("2026-11.jsonl");
        append_raw(&nov, b"{\"v\":2,\"se");
        let seq = append_chained(dir.path(), rec(datetime!(2026-11-02 00:00:00 UTC))).unwrap();
        assert_eq!(seq, 2);
        let ls = lines(&nov);
        assert_eq!(ls.len(), 2);
        assert_eq!(parse(&ls[1]).prev, Some(sha256_hex(b"{\"v\":2,\"se")));
    }

    #[test]
    fn unchained_lines_past_the_window_keep_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        append_chained(dir.path(), rec(datetime!(2026-10-13 08:00:00 UTC))).unwrap();
        let oct = dir.path().join("2026-10.jsonl");
        let raw = unchained_line("2026-10-13T08:00:01.000Z");
        let many: Vec<u8> = raw.repeat(300 * 1024 / raw.len() + 1);
        append_raw(&oct, &many);
        let seq = append_chained(dir.path(), rec(datetime!(2026-10-13 09:00:00 UTC))).unwrap();
        assert_eq!(seq, 2);
    }

    #[test]
    fn scan_gives_up_after_4_mib() {
        let dir = tempfile::tempdir().unwrap();
        append_chained(dir.path(), rec(datetime!(2026-10-13 08:00:00 UTC))).unwrap();
        let oct = dir.path().join("2026-10.jsonl");
        let raw = unchained_line("2026-10-13T08:00:01.000Z");
        append_raw(&oct, &raw.repeat(MAX_SCAN as usize / raw.len() + 1));
        let seq = append_chained(dir.path(), rec(datetime!(2026-10-13 09:00:00 UTC))).unwrap();
        assert_eq!(seq, 1, "a new chain starts");
        let ls = lines(&oct);
        assert_eq!(parse(&ls[ls.len() - 2]).kind(), "genesis");
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_newest_month_file_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        append_chained(dir.path(), rec(datetime!(2026-10-13 08:00:00 UTC))).unwrap();
        let target = dir.path().join("elsewhere");
        fs::write(&target, "original\n").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("2026-11.jsonl")).unwrap();
        let seq = append_chained(dir.path(), rec(datetime!(2026-10-14 08:00:00 UTC))).unwrap();
        assert_eq!(seq, 2);
        assert_eq!(fs::read_to_string(&target).unwrap(), "original\n");
        let ls = lines(&dir.path().join("2026-10.jsonl"));
        assert_eq!(ls.len(), 3);
        assert_eq!(parse(&ls[2]).prev, Some(sha256_hex(&ls[1])));
    }

    #[cfg(unix)]
    #[test]
    fn error_after_lock_writes_unchained() {
        use std::os::unix::fs::PermissionsExt;
        if rustix::process::getuid().is_root() {
            return; // root reads a 0000 file anyway
        }
        let dir = tempfile::tempdir().unwrap();
        append_chained(dir.path(), rec(datetime!(2026-10-13 08:00:00 UTC))).unwrap();
        let oct = dir.path().join("2026-10.jsonl");
        fs::set_permissions(&oct, fs::Permissions::from_mode(0o000)).unwrap();
        let got = append_chained(dir.path(), rec(datetime!(2026-11-02 08:00:00 UTC)));
        fs::set_permissions(&oct, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(got.is_err());
        let ls = lines(&dir.path().join("2026-11.jsonl"));
        assert_eq!(ls.len(), 1);
        assert_eq!(parse(&ls[0]).seq, None);
    }

    #[test]
    fn far_future_month_file_does_not_divert() {
        let dir = tempfile::tempdir().unwrap();
        append_raw(
            &dir.path().join("9999-12.jsonl"),
            &unchained_line("9999-12-01T00:00:00.000Z"),
        );
        append_chained(dir.path(), rec(datetime!(2026-10-13 08:00:00 UTC))).unwrap();
        assert_eq!(lines(&dir.path().join("2026-10.jsonl")).len(), 2);
        assert_eq!(lines(&dir.path().join("9999-12.jsonl")).len(), 1);
        // A next-month file (clock skew) is still followed.
        append_raw(
            &dir.path().join("2026-11.jsonl"),
            &unchained_line("2026-11-01T00:00:00.000Z"),
        );
        fs::remove_file(dir.path().join("9999-12.jsonl")).unwrap();
        append_chained(dir.path(), rec(datetime!(2026-10-13 09:00:00 UTC))).unwrap();
        assert_eq!(lines(&dir.path().join("2026-11.jsonl")).len(), 2);
    }

    #[test]
    fn invalid_month_name_does_not_divert() {
        let dir = tempfile::tempdir().unwrap();
        append_raw(
            &dir.path().join("2026-13.jsonl"),
            &unchained_line("2026-10-01T00:00:00.000Z"),
        );
        append_chained(dir.path(), rec(datetime!(2026-10-13 08:00:00 UTC))).unwrap();
        assert_eq!(lines(&dir.path().join("2026-10.jsonl")).len(), 2);
    }

    #[test]
    fn unchained_fallback_never_writes_an_older_file() {
        let dir = tempfile::tempdir().unwrap();
        append_chained(dir.path(), rec(datetime!(2026-11-02 08:00:00 UTC))).unwrap();
        let lock = fs::File::open(dir.path().join(LOCK_FILE)).unwrap();
        lock.lock().unwrap();
        assert!(append_chained(dir.path(), rec(datetime!(2026-10-13 08:00:00 UTC))).is_err());
        assert!(!dir.path().join("2026-10.jsonl").exists());
        assert_eq!(lines(&dir.path().join("2026-11.jsonl")).len(), 3);
    }

    #[test]
    fn genesis_host_is_hashed() {
        let dir = tempfile::tempdir().unwrap();
        append_chained(dir.path(), rec(datetime!(2026-10-13 08:00:00 UTC))).unwrap();
        let g = parse(&lines(&dir.path().join("2026-10.jsonl"))[0]);
        if let Some(h) = &g.host {
            assert_eq!(h.len(), 64, "{h}");
            assert!(
                h.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "{h}"
            );
        }
        assert_eq!(g.host, host_id());
    }

    #[test]
    fn seq_max_does_not_panic() {
        let dir = tempfile::tempdir().unwrap();
        let line = format!(
            "{{\"v\":2,\"seq\":{},\"prev\":\"{ZERO_PREV}\",\"ts\":\"x\"}}\n",
            u64::MAX
        );
        fs::write(dir.path().join("2026-10.jsonl"), line).unwrap();
        let seq = append_chained(dir.path(), rec(datetime!(2026-10-13 08:00:00 UTC))).unwrap();
        assert_eq!(seq, 1);
        let ls = lines(&dir.path().join("2026-10.jsonl"));
        assert_eq!(parse(&ls[1]).kind.as_deref(), Some("genesis"));
    }
}
