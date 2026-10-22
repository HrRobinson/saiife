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

/// Append `rec` to the hash chain in `dir` and return its `seq`.
///
/// If the lock file cannot be opened or taken within a second, the record is
/// written unchained (no `seq`/`prev`) and an error is returned so the caller
/// can warn; `verify` reports the gap later.
pub fn append_chained(dir: &Path, mut rec: Record) -> io::Result<u64> {
    store::create_private_dir(dir)?;
    fill_identity(&mut rec);
    let Some(_lock) = take_lock(dir) else {
        rec.seq = None;
        rec.prev = None;
        store::append(dir, &rec)?;
        return Err(io::Error::other(
            "audit chain lock unavailable; record written unchained",
        ));
    };
    // `_lock` holds the flock until it is dropped at the end of this scope.
    append_locked(dir, rec)
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
/// record, if the chain can be continued.
struct Tail {
    prev: String,
    last: Option<Record>,
}

fn append_locked(dir: &Path, mut rec: Record) -> io::Result<u64> {
    let files = store::month_files(dir).map_err(io::Error::other)?;
    let target = target_file(dir, &rec, &files);
    let tail = find_tail(&files)?;

    let mut out = Vec::new();
    let (seq, prev, host) = match tail.and_then(|t| t.last.map(|r| (r, t.prev))) {
        Some((last, prev)) => (last.seq.unwrap_or(0) + 1, prev, last.host),
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

/// `<month>.jsonl` for the record, but never older than the newest existing
/// month file: a clock that went back must not write into the chain's past.
fn target_file(dir: &Path, rec: &Record, files: &[PathBuf]) -> PathBuf {
    let own = format!("{}.jsonl", rec.month());
    let newest = files
        .last()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str());
    match newest {
        Some(n) if !store::is_month_file(&own) || n > own.as_str() => dir.join(n),
        _ => dir.join(own),
    }
}

/// The tail of the newest non-empty month file. A missing final newline (a
/// crash mid-write) is added first so the half line stays a line of its own.
fn find_tail(files: &[PathBuf]) -> io::Result<Option<Tail>> {
    let Some(path) = files
        .iter()
        .rev()
        .find(|p| fs::symlink_metadata(p).is_ok_and(|m| m.len() > 0))
    else {
        return Ok(None);
    };
    let (mut body, whole) = read_window(path)?;
    if !body.ends_with(b"\n") {
        store::open_append(path)?.write_all(b"\n")?;
        body.push(b'\n');
    }
    if let Some(t) = scan(&body, whole) {
        return Ok(Some(t));
    }
    // The window holds no complete line: one huge last line. Read it all.
    let body = store::read_regular(path).ok_or_else(not_regular)?;
    Ok(scan(&body, true))
}

fn not_regular() -> io::Error {
    io::Error::other("audit log path is not a regular file")
}

/// The last `TAIL_WINDOW` bytes of `path`, and whether that is the whole file.
fn read_window(path: &Path) -> io::Result<(Vec<u8>, bool)> {
    let mut f = store::open_regular(path).ok_or_else(not_regular)?;
    let len = f.metadata()?.len();
    let start = len.saturating_sub(TAIL_WINDOW);
    f.seek(SeekFrom::Start(start))?;
    let mut body = Vec::new();
    f.take(TAIL_WINDOW).read_to_end(&mut body)?;
    Ok((body, start == 0))
}

/// The chain state at the end of `body` (which ends with `\n`). `whole` says
/// `body` starts at a line start; otherwise its first piece is dropped as a
/// possibly cut line, and `None` means no complete line was left.
///
/// `prev` hashes the last line whatever it holds. The chained record is the
/// last line, scanning backwards, that parses as `v >= 2` with a `seq`;
/// unparseable and unchained lines are passed over, and a v1 line ends the
/// search (a v1 writer appended after the chain, so a new chain starts).
fn scan(body: &[u8], whole: bool) -> Option<Tail> {
    let mut lines: Vec<&[u8]> = body[..body.len() - 1].split(|&b| b == b'\n').collect();
    if !whole {
        if lines.len() < 2 {
            return None;
        }
        lines.remove(0);
    }
    let prev = sha256_hex(lines.last()?);
    let mut last = None;
    for line in lines.iter().rev() {
        let Ok(r) = serde_json::from_slice::<Record>(line) else {
            continue;
        };
        if r.v < 2 {
            break;
        }
        if r.seq.is_some() {
            last = Some(r);
            break;
        }
    }
    Some(Tail { prev, last })
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
}
