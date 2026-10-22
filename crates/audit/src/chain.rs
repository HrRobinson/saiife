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
use crate::sign::{checkpoint_message, fingerprint_of, key_rotate_message, AuditKey};
use crate::store;
use crate::verify::{State, VerifyReport};

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
/// Looked up once per process: on macOS that spawns `ioreg`.
pub fn host_id() -> Option<String> {
    static HOST: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    HOST.get_or_init(|| raw_machine_id().map(|id| sha256_hex(id.as_bytes())))
        .clone()
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
    if rec.uid.is_none() {
        rec.uid = own_uid();
    }
    if rec.user.is_none() {
        rec.user = own_user();
    }
}

#[cfg(unix)]
fn own_uid() -> Option<u32> {
    Some(rustix::process::getuid().as_raw())
}

#[cfg(not(unix))]
fn own_uid() -> Option<u32> {
    None
}

fn own_user() -> Option<String> {
    ["USER", "LOGNAME"]
        .iter()
        .filter_map(std::env::var_os)
        .filter_map(|v| v.into_string().ok())
        .find(|v| !v.is_empty())
}

/// The lock file, opened 0600 without following a symlink, refused unless it
/// is a regular file. Not locked yet.
fn open_lock(dir: &Path) -> io::Result<File> {
    let mut opts = fs::OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let file = opts.open(dir.join(LOCK_FILE))?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other(format!(
            "{} is not a regular file",
            dir.join(LOCK_FILE).display()
        )));
    }
    Ok(file)
}

/// The lock file (see `open_lock`), locked within `LOCK_WAIT`.
fn take_lock(dir: &Path) -> Option<File> {
    let file = open_lock(dir).ok()?;
    lock_within(&file).ok().map(|()| file)
}

/// Lock `file` (flock), retrying for up to `LOCK_WAIT` while it is held.
///
/// A flock belongs to the open file, not to the fd, and lasts until every
/// copy of it is closed. A child that another thread forks or spawns gets
/// a copy of every fd, close-on-exec ones included, and keeps it until it
/// execs: for that moment a lock its owner already dropped is still held.
/// On macOS every genesis spawns `ioreg` (`host_id`), so the moment comes
/// up; a held lock is only reported once it outlasts the wait.
fn lock_within(file: &File) -> Result<(), fs::TryLockError> {
    let deadline = Instant::now() + LOCK_WAIT;
    loop {
        match file.try_lock() {
            Err(fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(LOCK_RETRY);
            }
            r => return r,
        }
    }
}

/// Where the chain stands: the hash of the last line and the last chained
/// line, if the chain can be continued.
struct Tail {
    prev: String,
    last: Option<TailLine>,
    /// The `chain` id of the genesis the last chained line belongs to; only
    /// looked for when the caller asks (`find_tail(.., want_chain: true)`).
    chain: Option<String>,
    /// The signing key in force at the tail: the `new_key` of the newest
    /// `key_rotate` or the genesis `key` (`want_chain` only).
    key: Option<String>,
}

impl Tail {
    /// `(seq, hash of the last line)` of a chain that can be continued: a
    /// last seq of `u64::MAX` cannot be followed, so a new chain must start.
    fn head(&self) -> Option<(u64, String)> {
        let seq = self.last.as_ref()?.seq?;
        seq.checked_add(1)?;
        Some((seq, self.prev.clone()))
    }
}

/// What the tail scan reads of a line: exactly what `verify` judges a line
/// by (`v`, defaulting to 1, and `seq`), plus the `host` to carry on and the
/// fields the rollback and genesis checks need. A line is not required to
/// parse as a full `Record`.
struct TailLine {
    v: u64,
    seq: Option<u64>,
    host: Option<String>,
    ts: Option<String>,
    prev: Option<String>,
    kind: Option<String>,
    chain: Option<String>,
    /// A genesis `key`.
    key: Option<String>,
    /// A `key_rotate`'s `new_key`.
    new_key: Option<String>,
}

impl TailLine {
    /// `None` unless `line` is a JSON object (as in `verify`).
    fn parse(line: &[u8]) -> Option<Self> {
        let serde_json::Value::Object(obj) = serde_json::from_slice(line).ok()? else {
            return None;
        };
        let text = |k: &str| {
            obj.get(k)
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        };
        Some(Self {
            v: obj
                .get("v")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(1),
            seq: obj.get("seq").and_then(serde_json::Value::as_u64),
            host: text("host"),
            ts: text("ts"),
            prev: text("prev"),
            kind: text("kind"),
            chain: text("chain"),
            key: text("key"),
            new_key: text("new_key"),
        })
    }

    /// A well-formed genesis, by the rules of `verify`.
    fn is_genesis(&self) -> bool {
        self.kind.as_deref() == Some("genesis")
            && self.seq == Some(0)
            && self.prev.as_deref() == Some(ZERO_PREV)
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
    let tail = find_tail(&upto, MAX_SCAN, false)?;

    let mut out = Vec::new();
    let next = tail.and_then(|t| {
        let (seq, prev) = t.head()?;
        Some((seq + 1, prev, t.last?.host))
    });
    let (seq, prev, host) = match next {
        Some(n) => n,
        None => {
            let g = genesis(&GenesisSpec {
                saiife: &rec.saiife,
                ts: &rec.ts,
                mode: "developer",
                key: None,
                uid: rec.uid,
                user: rec.user.clone(),
            })?;
            let prev = push_line(&mut out, &g)?;
            (1, prev, g.host)
        }
    };
    rec.seq = Some(seq);
    rec.prev = Some(prev);
    rec.host = host;
    push_line(&mut out, &rec)?;
    store::open_append(&target)?.write_all(&out)?;
    Ok(seq)
}

/// Serialise `rec` as one line onto `out` and return the line's hash.
fn push_line(out: &mut Vec<u8>, rec: &Record) -> io::Result<String> {
    let line = serde_json::to_vec(rec).map_err(io::Error::other)?;
    let hash = sha256_hex(&line);
    out.extend_from_slice(&line);
    out.push(b'\n');
    Ok(hash)
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
/// past. A real month at most one month ahead of the record's is followed
/// as it is (clock skew). One further ahead is followed only when its
/// first chained line says the chain wrote it (`written_by_chain`, which
/// names the limits), so a stray `9999-12.jsonl` cannot divert every later
/// record.
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
        Some(nm)
            if nm > (y, m)
                && store::is_month_file(n)
                && (nm <= next || written_by_chain(files)) =>
        {
            dir.join(n)
        }
        _ => own,
    }
}

/// Whether the newest of `files` (oldest first) looks like the chain wrote
/// it, so a clock rollback of more than a month may follow it. The file is
/// judged by its first chained line (searching forward within
/// `TAIL_WINDOW` past unparseable and unchained lines; a v1 line first
/// means no): its `ts` is in the file's own month, and it is a genesis or
/// its `prev` is the hash of the physical line before it (for the file's
/// first line, the last line of the previous non-empty file). That first
/// line was written when the clock was right, and later rolled-back
/// records do not change it.
///
/// This tells a chain-written file from a stray or carelessly planted one,
/// not from a forgery: anyone who can write to a developer-mode audit dir
/// can also write a first line that links. Developer mode does not defend
/// against its own user; in locked mode the daemon owns the dir and its
/// `ChainWriter` does not use this rule.
fn written_by_chain(files: &[PathBuf]) -> bool {
    let Some((newest, older)) = files.split_last() else {
        return false;
    };
    let Some(month) = newest
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.get(..7))
    else {
        return false;
    };
    let Some(head) = head_lines(newest) else {
        return false;
    };
    // Computed lazily: only a first chained line on the file's first line
    // links to the previous file.
    let before = || {
        older
            .iter()
            .rev()
            .find(|p| fs::symlink_metadata(p).is_ok_and(|m| m.len() > 0))
            .and_then(|p| last_line_hash(p))
    };
    let mut line_before: Option<String> = None;
    for (i, line) in head.split(|&b| b == b'\n').enumerate() {
        match TailLine::parse(line) {
            Some(t) if t.v < 2 => return false,
            Some(t) if t.seq.is_some() => {
                if !t.ts.as_deref().is_some_and(|ts| ts.starts_with(month)) {
                    return false;
                }
                if t.is_genesis() {
                    return true;
                }
                let want = if i == 0 { before() } else { line_before };
                return want.is_some() && t.prev == want;
            }
            _ => line_before = Some(sha256_hex(line)),
        }
    }
    false
}

/// The complete lines (without the final newline) within the first
/// `TAIL_WINDOW` bytes of `path`; `None` if there is not one.
fn head_lines(path: &Path) -> Option<Vec<u8>> {
    let f = store::open_regular(path)?;
    let mut buf = Vec::new();
    f.take(TAIL_WINDOW).read_to_end(&mut buf).ok()?;
    let end = buf.iter().rposition(|&b| b == b'\n')?;
    buf.truncate(end);
    Some(buf)
}

/// The hash of the last line of `path` (a missing final newline does not
/// matter: the half line is the last line either way).
fn last_line_hash(path: &Path) -> Option<String> {
    let mut hash = None;
    let mut budget = MAX_SCAN;
    scan_back(path, &mut budget, |line| {
        hash = Some(sha256_hex(line));
        Some(Found::Stop)
    })
    .ok()?;
    hash
}

/// What the backwards search found.
enum Found {
    /// The search is over: the scanner has what it wanted, a v1 line ended
    /// it, or the read budget ran out.
    Stop,
    /// The file's first line was reached without a decision.
    More,
}

/// The chain's tail among `files`. `prev` hashes the physical last line of
/// the newest non-empty one of them; a missing final newline there (a crash
/// mid-write) is added first so the half line stays a line of its own. The
/// last chained record is the newest line, searching backwards through that
/// file and then older ones, that is a JSON object with `v >= 2` and a `seq`
/// (the rules of `verify`; see `TailLine`). Unparseable and unchained lines
/// are passed over; a v1 line ends the search (a v1 writer appended after
/// the chain), and so does reading `budget` bytes in all.
///
/// With `want_chain`, the search goes on past the last chained line to the
/// genesis it belongs to, for its `chain` id (a v1 line or the budget stops
/// that search too, leaving `chain` empty).
fn find_tail(files: &[PathBuf], mut budget: u64, want_chain: bool) -> io::Result<Option<Tail>> {
    let non_empty: Vec<&PathBuf> = files
        .iter()
        .filter(|p| fs::symlink_metadata(p).is_ok_and(|m| m.len() > 0))
        .collect();
    let Some(newest) = non_empty.last() else {
        return Ok(None);
    };
    terminate(newest)?;
    let mut prev = None;
    let mut last: Option<TailLine> = None;
    let mut chain = None;
    let mut key: Option<Option<String>> = None;
    for path in non_empty.iter().rev() {
        let found = scan_back(path, &mut budget, |line| {
            if prev.is_none() {
                prev = Some(sha256_hex(line));
            }
            let t = TailLine::parse(line)?;
            if t.v < 2 {
                return Some(Found::Stop);
            }
            t.seq?; // unchained: passed over
            let genesis = t.kind.as_deref() == Some("genesis");
            if genesis {
                chain.clone_from(&t.chain);
            }
            if key.is_none() {
                match t.kind.as_deref() {
                    Some("genesis") => key = Some(t.key.clone()),
                    Some("key_rotate") => key = Some(t.new_key.clone()),
                    _ => {}
                }
            }
            if last.is_none() {
                last = Some(t);
                return (!want_chain || genesis).then_some(Found::Stop);
            }
            genesis.then_some(Found::Stop)
        })?;
        if let Found::Stop = found {
            break;
        }
    }
    Ok(prev.map(|prev| Tail {
        prev,
        last,
        chain,
        key: key.flatten(),
    }))
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

/// What a genesis record says besides its fixed fields.
struct GenesisSpec<'a> {
    saiife: &'a str,
    /// The `ts` of the record it is written with: the genesis goes into
    /// that record's file, and the rollback rule reads its month.
    ts: &'a str,
    mode: &'a str,
    /// `ed25519:<spki b64>` of the signing key, locked mode only.
    key: Option<&'a str>,
    uid: Option<u32>,
    user: Option<String>,
}

/// Record 0 of a new chain (spec §6.4.1).
fn genesis(spec: &GenesisSpec<'_>) -> io::Result<Record> {
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
            mode: spec.mode,
            policy: None,
            permission_mode: None,
        },
        spec.saiife,
    );
    g.ts = spec.ts.to_string();
    g.kind = Some("genesis".into());
    g.seq = Some(0);
    g.prev = Some(ZERO_PREV.into());
    g.host = host_id();
    g.uid = spec.uid;
    g.user = spec.user.clone();
    g.extra.insert("chain".into(), uuid_v4()?.into());
    if let Some(key) = spec.key {
        g.extra.insert("key".into(), key.into());
    }
    Ok(g)
}

/// How a `ChainWriter` starts a new chain.
#[derive(Debug)]
pub struct WriterOptions {
    /// `mode` of the genesis record (`"locked"` for the daemon).
    pub mode: String,
    /// Version of the saiife binary, for the genesis record.
    pub saiife: String,
    /// The checkpoint signing key; its `spki()` is the genesis `key`.
    pub key: Option<AuditKey>,
}

/// What `ChainWriter::startup_check` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupCheck {
    /// The first break among the recent lines, described.
    pub recent: Result<(), String>,
    /// `seq` of the newest checkpoint among them.
    pub last_checkpoint: Option<u64>,
    /// The last non-checkpoint record is a `daemon` `stop`.
    pub last_clean_stop: bool,
}

/// The single long-lived writer of the hash chain (locked mode): it holds
/// `.chain.lock` for its whole life, so no other process can append chained
/// records, and keeps the chain's head in memory instead of reading the
/// tail on every append.
#[derive(Debug)]
pub struct ChainWriter {
    dir: PathBuf,
    /// Held (flock) until the writer drops.
    _lock: File,
    opts: WriterOptions,
    /// `(seq, hash of the last line)`; `None` until there is a chain to go on.
    head: Option<(u64, String)>,
    chain_id: Option<String>,
    host: Option<String>,
    /// `ed25519:<spki b64>` of the key in force on disk (genesis `key` or
    /// the newest `key_rotate`'s `new_key`).
    key_in_force: Option<String>,
    /// The newest month file, with an append handle on it.
    current: Option<Current>,
    /// Records appended since the last checkpoint.
    since_checkpoint: u64,
    /// The cached head may not match the disk (a failed write, a foreign
    /// line): re-read the tail before the next append.
    stale: bool,
}

/// The month file the writer appends to.
#[derive(Debug)]
struct Current {
    name: String,
    file: File,
    /// Where the writer expects the file to end. Any other length means
    /// someone else wrote to it (a developer-mode fallback line, a hand
    /// edit), and the head no longer hashes the last line.
    end: u64,
}

impl Current {
    fn open(path: &Path) -> io::Result<Current> {
        let new = fs::symlink_metadata(path).is_err();
        let file = store::open_append_mode(path, 0o640)?;
        if new {
            set_mode(&file, 0o640)?;
        }
        Ok(Current {
            name: file_name(path)?,
            end: file.metadata()?.len(),
            file,
        })
    }
}

impl ChainWriter {
    /// Take the chain lock of `dir` (created 0750 when missing; an existing
    /// dir keeps its mode) and find the chain's tail with no read budget. A
    /// lock still held after `LOCK_WAIT` is an error (see `lock_within`).
    pub fn open(dir: &Path, opts: WriterOptions) -> io::Result<ChainWriter> {
        create_writer_dir(dir)?;
        let lock = open_lock(dir)?;
        match lock_within(&lock) {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => {
                return Err(io::Error::other(format!(
                    "another process holds the audit chain lock ({})",
                    dir.join(LOCK_FILE).display()
                )));
            }
            Err(fs::TryLockError::Error(e)) => return Err(e),
        }
        let mut w = ChainWriter {
            dir: dir.to_path_buf(),
            _lock: lock,
            opts,
            head: None,
            chain_id: None,
            host: None,
            key_in_force: None,
            current: None,
            since_checkpoint: 0,
            stale: true,
        };
        w.load()?;
        w.adopt_key()?;
        Ok(w)
    }

    /// Make this writer's key the key in force of an existing chain. When
    /// the chain names another key (the key file was lost or replaced) or
    /// none (a chain started without one), write a `key_rotate` to it with
    /// `sig: null`: there is no old key to sign the change with. A new
    /// chain needs nothing: its genesis will carry the key.
    fn adopt_key(&mut self) -> io::Result<()> {
        let Some(spki) = self.opts.key.as_ref().map(AuditKey::spki) else {
            return Ok(());
        };
        if self.head.is_none() || self.key_in_force.as_deref() == Some(spki.as_str()) {
            return Ok(());
        }
        let old = self.key_in_force.as_deref().and_then(fingerprint_of);
        let mut rec = self.bookkeeping("key_rotate", time::OffsetDateTime::now_utc());
        rec.reason = Some(if self.key_in_force.is_some() {
            "previous signing key missing".into()
        } else {
            "chain had no signing key".into()
        });
        self.append_with(rec, |r, h, _| {
            r.extra
                .insert("head_seq".into(), h.seq.saturating_sub(1).into());
            r.extra.insert("head".into(), h.prev.into());
            r.extra.insert("key".into(), old.clone().into());
            r.extra.insert("new_key".into(), spki.clone().into());
            r.extra.insert("sig".into(), serde_json::Value::Null);
        })?;
        self.key_in_force = Some(spki);
        Ok(())
    }

    /// A bookkeeping record (`checkpoint`, `key_rotate`) of this writer:
    /// `tool` = kind, empty `agent`/`project`/`input`, `decision` allow.
    fn bookkeeping(&self, kind: &str, ts: time::OffsetDateTime) -> Record {
        let mut r = Record::at(
            NewRecord {
                agent: "",
                project: "",
                session: None,
                tool: kind,
                input: "",
                decision: DecisionKind::Allow,
                pack: None,
                rule: None,
                reason: None,
                mode: &self.opts.mode,
                policy: None,
                permission_mode: None,
            },
            &self.opts.saiife,
            ts,
        );
        r.kind = Some(kind.into());
        r.uid = own_uid();
        r.user = own_user();
        r
    }

    /// Read the chain's state from disk (tail, chain id, newest file). A
    /// chain whose genesis cannot be found (a v1 line in between) is not
    /// continued: the next append starts a new one, as `append_chained`
    /// does after a v1 line.
    fn load(&mut self) -> io::Result<()> {
        let files = regular_month_files(&self.dir)?;
        let tail = find_tail(&files, u64::MAX, true)?;
        let (head, chain_id, host, key) = match tail {
            Some(t) => match (t.head(), t.chain) {
                (Some(head), Some(chain)) => {
                    (Some(head), Some(chain), t.last.and_then(|l| l.host), t.key)
                }
                _ => (None, None, None, None),
            },
            None => (None, None, None, None),
        };
        self.head = head;
        self.chain_id = chain_id;
        self.host = host;
        self.key_in_force = key;
        self.current = files.last().map(|p| Current::open(p)).transpose()?;
        self.stale = false;
        Ok(())
    }

    /// Make the file for a record of month file `own` current, and the
    /// cached head match what is on disk.
    fn prepare(&mut self, own: &str) -> io::Result<()> {
        for _ in 0..2 {
            if self.stale {
                self.load()?;
            }
            if self.current.as_ref().is_none_or(|c| c.name.as_str() < own) {
                // fsync = "checkpoint": what went to the old file is synced
                // before its handle goes.
                if let Some(old) = &self.current {
                    old.file.sync_data()?;
                }
                let next = Current::open(&self.dir.join(own))?;
                // A new month file someone else already wrote to.
                self.stale |= next.end > 0;
                self.current = Some(next);
            }
            let c = self.current.as_ref().expect("current file set above");
            self.stale |= c.file.metadata()?.len() != c.end;
            if !self.stale {
                return Ok(());
            }
        }
        Err(io::Error::other(
            "the audit log keeps changing under the chain writer",
        ))
    }

    /// Append `rec` to the chain and return its `seq`. Sets `seq`, `prev`
    /// and `host`; writes a genesis first when there is no chain yet. The
    /// target is the record's month file or the newest file, whichever is
    /// later: the writer owns the dir, so the newest file is the chain's.
    /// A line someone else added to the file since the last append is
    /// noticed (by the file's length) and chained on from.
    pub fn append(&mut self, rec: Record) -> io::Result<u64> {
        self.append_with(rec, |_, _, _| {})
    }

    /// `append`, with `fill` called on the record once its place in the
    /// chain is known (after `seq`, `prev` and `host` are set), with this
    /// writer's key: what a checkpoint or key rotation signs.
    fn append_with(
        &mut self,
        mut rec: Record,
        fill: impl FnOnce(&mut Record, &Place<'_>, Option<&AuditKey>),
    ) -> io::Result<u64> {
        let own = format!("{}.jsonl", rec.month());
        if !store::is_month_file(&own) {
            return Err(io::Error::other(format!(
                "audit record has no usable timestamp: {:?}",
                rec.ts
            )));
        }
        self.prepare(&own)?;

        let mut out = Vec::new();
        let mut started = None;
        let (seq, prev) = match self
            .head
            .as_ref()
            .and_then(|(s, h)| Some((s.checked_add(1)?, h)))
        {
            Some((seq, h)) => (seq, h.clone()),
            None => {
                let spki = self.opts.key.as_ref().map(AuditKey::spki);
                let g = genesis(&GenesisSpec {
                    saiife: &self.opts.saiife,
                    ts: &rec.ts,
                    mode: &self.opts.mode,
                    key: spki.as_deref(),
                    uid: own_uid(),
                    user: own_user(),
                })?;
                let prev = push_line(&mut out, &g)?;
                let chain = g
                    .extra
                    .get("chain")
                    .and_then(|c| c.as_str())
                    .map(String::from);
                started = Some((chain, g.host, spki));
                (1, prev)
            }
        };
        rec.seq = Some(seq);
        rec.prev = Some(prev.clone());
        rec.host = match &started {
            Some((_, host, _)) => host.clone(),
            None => self.host.clone(),
        };
        let chain = match &started {
            Some((chain, _, _)) => chain.as_deref(),
            None => self.chain_id.as_deref(),
        };
        let place = Place {
            seq,
            prev: &prev,
            chain: chain.unwrap_or_default(),
        };
        fill(&mut rec, &place, self.opts.key.as_ref());
        let hash = push_line(&mut out, &rec)?;
        let c = self.current.as_mut().expect("current file set by prepare");
        if let Err(e) = c.file.write_all(&out) {
            // Part of the line may be on disk: find the tail again.
            self.stale = true;
            return Err(e);
        }
        c.end += out.len() as u64;
        if let Some((chain, host, key)) = started {
            self.chain_id = chain;
            self.host = host;
            self.key_in_force = key;
        }
        self.head = Some((seq, hash));
        self.since_checkpoint += 1;
        Ok(seq)
    }

    /// `(seq, hash of the last line)` of the chain, if there is one.
    pub fn head(&self) -> Option<(u64, &str)> {
        self.head.as_ref().map(|(s, h)| (*s, h.as_str()))
    }

    /// The `chain` id of the current chain's genesis.
    pub fn chain_id(&self) -> Option<&str> {
        self.chain_id.as_deref()
    }

    /// The hashed host id the chain carries.
    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    /// Records appended since the last checkpoint.
    pub fn records_since_checkpoint(&self) -> u64 {
        self.since_checkpoint
    }

    /// Write a signed checkpoint over the current head (spec §6.4.2) and
    /// return its `seq`; `None` when nothing was appended since the last
    /// one. The signature covers the record's own `ts` string.
    pub fn checkpoint(&mut self, ts: time::OffsetDateTime) -> io::Result<Option<u64>> {
        if self.opts.key.is_none() {
            return Err(io::Error::other(
                "audit checkpoint needs a signing key, and this chain writer has none",
            ));
        }
        if self.since_checkpoint == 0 {
            return Ok(None);
        }
        let rec = self.bookkeeping("checkpoint", ts);
        let seq = self.append_with(rec, |r, h, key| {
            let key = key.expect("checked above");
            let head_seq = h.seq.saturating_sub(1);
            let msg = checkpoint_message(h.chain, head_seq, h.prev, &r.ts);
            r.extra.insert("head_seq".into(), head_seq.into());
            r.extra.insert("head".into(), h.prev.into());
            r.extra.insert("key".into(), key.fingerprint().into());
            r.extra
                .insert("sig".into(), key.sign_b64(msg.as_bytes()).into());
        })?;
        self.since_checkpoint = 0;
        Ok(Some(seq))
    }

    /// Switch to the signing key `new`: write a `key_rotate` naming it
    /// (`new_key`, its SPKI), signed by the current key, and return its
    /// `seq`. The old key is dropped (and zeroized) once it is written.
    pub fn rotate_key(&mut self, new: AuditKey) -> io::Result<u64> {
        if self.opts.key.is_none() {
            return Err(io::Error::other(
                "audit key rotation needs the current signing key, and this chain writer has none",
            ));
        }
        let new_spki = new.spki();
        let rec = self.bookkeeping("key_rotate", time::OffsetDateTime::now_utc());
        let seq = self.append_with(rec, |r, h, key| {
            let key = key.expect("checked above");
            let head_seq = h.seq.saturating_sub(1);
            let msg = key_rotate_message(h.chain, head_seq, h.prev, &new_spki, &r.ts);
            r.extra.insert("head_seq".into(), head_seq.into());
            r.extra.insert("head".into(), h.prev.into());
            r.extra.insert("key".into(), key.fingerprint().into());
            r.extra.insert("new_key".into(), new_spki.clone().into());
            r.extra
                .insert("sig".into(), key.sign_b64(msg.as_bytes()).into());
        })?;
        self.opts.key = Some(new);
        self.key_in_force = Some(new_spki);
        Ok(seq)
    }

    /// Re-verify the last `records` chained lines (by the rules of
    /// `verify`, signatures included), for the daemon's start. The key in
    /// force before them is found by reading further back, to the newest
    /// `key_rotate` or the genesis (as `open` already did).
    pub fn startup_check(&self, records: usize) -> StartupCheck {
        match self.recent_window(records) {
            Ok(w) => w.check(self.chain_id.clone()),
            Err(e) => StartupCheck {
                recent: Err(format!("cannot read the audit log: {e}")),
                last_checkpoint: None,
                last_clean_stop: false,
            },
        }
    }

    /// The last `records` chained lines (and the lines between them), oldest
    /// first, with what is needed to check them on their own.
    fn recent_window(&self, records: usize) -> io::Result<Window> {
        let mut files = regular_month_files(&self.dir)?;
        files.retain(|p| fs::symlink_metadata(p).is_ok_and(|m| m.len() > 0));
        let mut w = Window {
            lines: Vec::new(),
            before: None,
        };
        if records == 0 {
            return Ok(w);
        }
        let mut chained = 0;
        // `Some(hash of the line before the window)` once the window is full.
        let mut before: Option<String> = None;
        // The key in force before the window, once a line names it.
        let mut key: Option<Option<String>> = None;
        let mut budget = u64::MAX;
        'files: for path in files.iter().rev() {
            let name = file_name(path)?;
            let found = scan_back(path, &mut budget, |line| {
                let t = TailLine::parse(line);
                if before.is_none() {
                    if t.as_ref().is_some_and(|t| t.v >= 2 && t.seq.is_some()) {
                        if chained == records {
                            before = Some(sha256_hex(line));
                        } else {
                            chained += 1;
                        }
                    } else if t.as_ref().is_some_and(|t| t.v < 2) {
                        // The chain starts after a v1 line: check from there.
                        w.lines.push((name.clone(), line.to_vec()));
                        return Some(Found::Stop);
                    }
                    if before.is_none() {
                        w.lines.push((name.clone(), line.to_vec()));
                        return None;
                    }
                }
                // Before the window: look for the key in force there.
                let t = t?;
                if t.v < 2 {
                    key = Some(None);
                    return Some(Found::Stop);
                }
                match t.kind.as_deref() {
                    Some("genesis") => key = Some(t.key),
                    Some("key_rotate") => key = Some(t.new_key),
                    _ => return None,
                }
                Some(Found::Stop)
            })?;
            if let Found::Stop = found {
                break 'files;
            }
        }
        w.lines.reverse();
        w.before = before.map(|hash| (hash, key.flatten()));
        Ok(w)
    }

    /// `fdatasync` the current month file.
    pub fn sync(&self) -> io::Result<()> {
        match &self.current {
            Some(c) => c.file.sync_data(),
            None => Ok(()),
        }
    }
}

/// Where a record goes in the chain, for `ChainWriter::append_with`.
struct Place<'a> {
    seq: u64,
    /// Hash of the line before it: `head` of the record `seq - 1`.
    prev: &'a str,
    chain: &'a str,
}

/// The recent lines `startup_check` re-verifies.
struct Window {
    /// `(file name, line)`, oldest first.
    lines: Vec<(String, Vec<u8>)>,
    /// When the window starts inside the chain: the hash of the line before
    /// it and the key in force there. `None` when it starts at the
    /// beginning of the log (or after a v1 line).
    before: Option<(String, Option<String>)>,
}

impl Window {
    fn check(&self, chain: Option<String>) -> StartupCheck {
        let mut report = VerifyReport::default();
        let mut state = match &self.before {
            Some((hash, key)) => {
                let first = self
                    .lines
                    .iter()
                    .find_map(|(_, l)| TailLine::parse(l).filter(|t| t.v >= 2)?.seq);
                State::resume(Some(hash.clone()), first.unwrap_or(0), chain, key.clone())
            }
            None => State::default(),
        };
        let mut last_checkpoint = None;
        let mut last_clean_stop = false;
        for (file, line) in &self.lines {
            state.check(line, file, 0, &mut report);
            let Ok(serde_json::Value::Object(obj)) = serde_json::from_slice(line) else {
                continue;
            };
            let Some(seq) = obj.get("seq").and_then(serde_json::Value::as_u64) else {
                continue;
            };
            let field = |k: &str| obj.get(k).and_then(serde_json::Value::as_str);
            if field("kind") == Some("checkpoint") {
                last_checkpoint = Some(seq);
            } else {
                last_clean_stop = field("kind") == Some("daemon") && field("event") == Some("stop");
            }
        }
        let recent = match report.first_break() {
            None => Ok(()),
            Some(b) => Err(match b.seq {
                Some(seq) => format!("{} seq {seq}: {}", b.file, b.kind.describe()),
                None => format!("{}: {}", b.file, b.kind.describe()),
            }),
        };
        StartupCheck {
            recent,
            last_checkpoint,
            last_clean_stop,
        }
    }
}

fn file_name(p: &Path) -> io::Result<String> {
    p.file_name()
        .and_then(|n| n.to_str())
        .map(str::to_string)
        .ok_or_else(|| io::Error::other(format!("bad audit file name {}", p.display())))
}

/// Create the writer's audit dir 0750 when missing; an existing one keeps
/// its mode (2750 under systemd).
fn create_writer_dir(dir: &Path) -> io::Result<()> {
    if fs::symlink_metadata(dir).is_ok() {
        return Ok(());
    }
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o750);
    }
    b.create(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o750))?;
    }
    Ok(())
}

/// Set `mode` on a file this process just created (the umask may have
/// taken bits off it).
fn set_mode(file: &File, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = (file, mode);
        Ok(())
    }
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

    fn opts(mode: &str, key: Option<AuditKey>) -> WriterOptions {
        WriterOptions {
            mode: mode.into(),
            saiife: "0.2.0".into(),
            key,
        }
    }

    fn locked_rec(at: OffsetDateTime) -> Record {
        let mut r = rec(at);
        r.mode = Some("locked".into());
        r.uid = Some(1000);
        r.user = Some("bob".into());
        r
    }

    fn verify_ok(dir: &Path) {
        let report = crate::verify::verify(dir);
        assert_eq!(report.exit_code(), 0, "{:?}", report.breaks);
    }

    #[test]
    fn writer_genesis_carries_key_and_mode() {
        let dir = tempfile::tempdir().unwrap();
        let key = AuditKey::generate().unwrap();
        let spki = key.spki();
        let mut w = ChainWriter::open(dir.path(), opts("locked", Some(key))).unwrap();
        assert_eq!(w.head(), None);
        assert_eq!(w.chain_id(), None);
        let seq = w
            .append(locked_rec(datetime!(2026-10-13 08:00:00 UTC)))
            .unwrap();
        assert_eq!(seq, 1);
        let ls = lines(&dir.path().join("2026-10.jsonl"));
        assert_eq!(ls.len(), 2);
        let text = String::from_utf8(ls[0].clone()).unwrap();
        assert!(text.contains("\"mode\":\"locked\""), "{text}");
        assert!(text.contains(&format!("\"key\":\"{spki}\"")), "{text}");
        let g = parse(&ls[0]);
        assert_eq!(g.kind(), "genesis");
        assert_eq!(g.seq, Some(0));
        assert_eq!(g.prev.as_deref(), Some(ZERO_PREV));
        assert_eq!(g.saiife, "0.2.0");
        assert_eq!(w.chain_id(), g.extra["chain"].as_str());
        assert_eq!(w.host(), g.host.as_deref());
        let r = parse(&ls[1]);
        assert_eq!((r.seq, r.prev), (Some(1), Some(sha256_hex(&ls[0]))));
        assert_eq!(r.host, g.host);
        assert_eq!((r.uid, r.user.as_deref()), (Some(1000), Some("bob")));
        verify_ok(dir.path());
    }

    #[test]
    fn writer_genesis_without_key_has_none() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = ChainWriter::open(dir.path(), opts("locked", None)).unwrap();
        w.append(locked_rec(datetime!(2026-10-13 08:00:00 UTC)))
            .unwrap();
        let g = parse(&lines(&dir.path().join("2026-10.jsonl"))[0]);
        assert!(!g.extra.contains_key("key"));
        assert_eq!(g.mode.as_deref(), Some("locked"));
    }

    #[test]
    fn writer_continues_existing_chain() {
        let dir = tempfile::tempdir().unwrap();
        for h in 0..3 {
            append_chained(
                dir.path(),
                rec(datetime!(2026-10-13 08:00:00 UTC) + time::Duration::hours(h)),
            )
            .unwrap();
        }
        let genesis = parse(&lines(&dir.path().join("2026-10.jsonl"))[0]);
        let mut w = ChainWriter::open(dir.path(), opts("locked", None)).unwrap();
        assert_eq!(w.head().map(|h| h.0), Some(3));
        assert_eq!(w.chain_id(), genesis.extra["chain"].as_str());
        assert_eq!(w.host(), genesis.host.as_deref());
        let seqs: Vec<u64> = (0..2)
            .map(|i| {
                w.append(locked_rec(
                    datetime!(2026-10-14 08:00:00 UTC) + time::Duration::minutes(i),
                ))
                .unwrap()
            })
            .collect();
        assert_eq!(seqs, [4, 5]);
        drop(w);
        verify_ok(dir.path());
    }

    #[test]
    fn writer_finds_chain_past_the_scan_budget() {
        let dir = tempfile::tempdir().unwrap();
        append_chained(dir.path(), rec(datetime!(2026-10-13 08:00:00 UTC))).unwrap();
        let oct = dir.path().join("2026-10.jsonl");
        let raw = unchained_line("2026-10-13T08:00:01.000Z");
        append_raw(&oct, &raw.repeat(MAX_SCAN as usize / raw.len() + 1));
        let w = ChainWriter::open(dir.path(), opts("locked", None)).unwrap();
        let ls = lines(&oct);
        let want = sha256_hex(ls.last().unwrap());
        assert_eq!(w.head(), Some((1, want.as_str())));
        assert!(w.chain_id().is_some(), "genesis found past 4 MiB");
    }

    #[test]
    fn writer_follows_newest_file_after_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = ChainWriter::open(dir.path(), opts("locked", None)).unwrap();
        let put = |w: &mut ChainWriter, at| w.append(locked_rec(at)).unwrap();
        assert_eq!(put(&mut w, datetime!(2026-12-02 08:00:00 UTC)), 1);
        assert_eq!(put(&mut w, datetime!(2025-01-02 08:00:00 UTC)), 2);
        drop(w);
        assert!(!dir.path().join("2025-01.jsonl").exists());
        assert_eq!(lines(&dir.path().join("2026-12.jsonl")).len(), 3);
        verify_ok(dir.path());
        // A new writer finds the same newest file.
        let mut w = ChainWriter::open(dir.path(), opts("locked", None)).unwrap();
        assert_eq!(put(&mut w, datetime!(2025-01-02 09:00:00 UTC)), 3);
        assert_eq!(lines(&dir.path().join("2026-12.jsonl")).len(), 4);
        // Moving forward starts the next month file.
        assert_eq!(put(&mut w, datetime!(2027-01-01 00:00:00 UTC)), 4);
        assert_eq!(lines(&dir.path().join("2027-01.jsonl")).len(), 1);
        drop(w);
        verify_ok(dir.path());
    }

    #[test]
    fn second_writer_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let _w = ChainWriter::open(dir.path(), opts("locked", None)).unwrap();
        let Err(err) = ChainWriter::open(dir.path(), opts("locked", None)) else {
            panic!("second writer must be refused");
        };
        let msg = err.to_string();
        assert!(msg.contains("holds the audit chain lock"), "{msg}");
        assert!(msg.contains(LOCK_FILE), "{msg}");
    }

    #[test]
    fn writer_lock_is_released_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        drop(ChainWriter::open(dir.path(), opts("locked", None)).unwrap());
        ChainWriter::open(dir.path(), opts("locked", None)).unwrap();
    }

    /// A copy of the lock's open file outliving the writer, as a child
    /// spawned by another thread holds one until it execs (macOS spawns
    /// `ioreg` for every genesis): the flock stays held for a moment after
    /// the drop, and the next writer waits for it instead of failing.
    #[test]
    fn writer_waits_for_a_briefly_held_lock() {
        let dir = tempfile::tempdir().unwrap();
        let w = ChainWriter::open(dir.path(), opts("locked", None)).unwrap();
        let copy = w._lock.try_clone().unwrap();
        drop(w);
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            drop(copy);
        });
        let start = Instant::now();
        ChainWriter::open(dir.path(), opts("locked", None)).unwrap();
        assert!(start.elapsed() < LOCK_WAIT, "{:?}", start.elapsed());
        release.join().unwrap();
    }

    #[test]
    fn writer_holds_lock_so_dev_append_goes_unchained() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = ChainWriter::open(dir.path(), opts("locked", None)).unwrap();
        w.append(locked_rec(datetime!(2026-10-13 08:00:00 UTC)))
            .unwrap();
        let e = append_chained(dir.path(), rec(datetime!(2026-10-13 09:00:00 UTC))).unwrap_err();
        assert!(written_unchained(&e).is_some(), "{e}");
        // The writer sees the foreign line and chains on from it.
        let seq = w
            .append(locked_rec(datetime!(2026-10-13 10:00:00 UTC)))
            .unwrap();
        assert_eq!(seq, 2);
        let ls = lines(&dir.path().join("2026-10.jsonl"));
        assert_eq!(w.head(), Some((2, sha256_hex(&ls[3]).as_str())));
        let report = crate::verify::verify(dir.path());
        let kinds: Vec<_> = report.breaks.iter().map(|b| b.kind.clone()).collect();
        assert_eq!(kinds, [crate::verify::BreakKind::Unchained]);
    }

    /// A foreign line in the next month's file, written before the writer
    /// gets there, is chained on from too.
    #[test]
    fn writer_chains_on_from_a_foreign_line_in_a_new_month_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = ChainWriter::open(dir.path(), opts("locked", None)).unwrap();
        w.append(locked_rec(datetime!(2026-10-13 08:00:00 UTC)))
            .unwrap();
        let nov = dir.path().join("2026-11.jsonl");
        append_raw(&nov, &unchained_line("2026-11-01T00:00:00.000Z"));
        let seq = w
            .append(locked_rec(datetime!(2026-11-02 08:00:00 UTC)))
            .unwrap();
        assert_eq!(seq, 2);
        let report = crate::verify::verify(dir.path());
        let kinds: Vec<_> = report.breaks.iter().map(|b| b.kind.clone()).collect();
        assert_eq!(kinds, [crate::verify::BreakKind::Unchained]);
    }

    /// M4: a v1 line between the genesis and the tail hides the chain id:
    /// the writer starts a new chain, as `append_chained` would after v1.
    #[test]
    fn writer_starts_fresh_when_v1_line_hides_the_genesis() {
        let dir = tempfile::tempdir().unwrap();
        let oct = dir.path().join("2026-10.jsonl");
        append_chained(dir.path(), rec(datetime!(2026-10-13 08:00:00 UTC))).unwrap();
        append_raw(&oct, b"{\"v\":1,\"ts\":\"2026-10-13T08:14:02.381Z\",\"agent\":\"codex\",\"project\":\"/p\",\"tool\":\"shell\",\"input\":\"ls\",\"decision\":\"allow\",\"saiife\":\"0.1.0\"}\n");
        let prev = sha256_hex(lines(&oct).last().unwrap());
        append_raw(
            &oct,
            format!(
                "{{\"v\":2,\"seq\":2,\"prev\":\"{prev}\",\"ts\":\"2026-10-13T08:30:00.000Z\"}}\n"
            )
            .as_bytes(),
        );
        let mut w = ChainWriter::open(dir.path(), opts("locked", None)).unwrap();
        assert_eq!(w.head(), None);
        assert_eq!(w.chain_id(), None);
        let seq = w
            .append(locked_rec(datetime!(2026-10-13 09:00:00 UTC)))
            .unwrap();
        assert_eq!(seq, 1);
        let ls = lines(&oct);
        assert_eq!(parse(&ls[ls.len() - 2]).kind(), "genesis");
        assert!(w.chain_id().is_some());
    }

    #[cfg(unix)]
    #[test]
    fn writer_files_are_0640() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let mut w = ChainWriter::open(dir.path(), opts("locked", None)).unwrap();
        w.append(locked_rec(datetime!(2026-10-13 08:00:00 UTC)))
            .unwrap();
        w.append(locked_rec(datetime!(2026-11-01 08:00:00 UTC)))
            .unwrap();
        for m in ["2026-10", "2026-11"] {
            let mode = fs::metadata(dir.path().join(format!("{m}.jsonl")))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o640, "{m}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn writer_creates_dir_0750_and_leaves_existing_dir_alone() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("audit");
        drop(ChainWriter::open(&dir, opts("locked", None)).unwrap());
        let mode = fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o750);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        drop(ChainWriter::open(&dir, opts("locked", None)).unwrap());
        let mode = fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o755);
    }

    #[test]
    fn writer_head_is_hash_of_last_line() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = ChainWriter::open(dir.path(), opts("locked", None)).unwrap();
        for i in 0..3 {
            let seq = w
                .append(locked_rec(
                    datetime!(2026-10-13 08:00:00 UTC) + time::Duration::minutes(i),
                ))
                .unwrap();
            let ls = lines(&dir.path().join("2026-10.jsonl"));
            let want = sha256_hex(ls.last().unwrap());
            assert_eq!(w.head(), Some((seq, want.as_str())));
        }
        w.sync().unwrap();
        let report = crate::verify::verify(dir.path());
        let (seq, hash) = w.head().unwrap();
        assert_eq!(report.head, Some((seq, hash.to_string())));
    }

    #[test]
    fn clock_rollback_over_a_month_stays_on_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        append_chained(dir.path(), rec(datetime!(2026-12-02 08:00:00 UTC))).unwrap();
        append_chained(dir.path(), rec(datetime!(2026-12-02 09:00:00 UTC))).unwrap();
        // I1: every rolled-back record, not only the first, stays on the chain.
        for (i, want) in (3..=5).enumerate() {
            let at = datetime!(2026-09-13 08:00:00 UTC) + time::Duration::minutes(i as i64);
            assert_eq!(append_chained(dir.path(), rec(at)).unwrap(), want);
        }
        assert!(!dir.path().join("2026-09.jsonl").exists());
        let ls = lines(&dir.path().join("2026-12.jsonl"));
        assert_eq!(ls.len(), 6);
        assert_eq!(parse(&ls[5]).seq, Some(5));
        verify_ok(dir.path());
    }

    /// The far file is judged by its first chained line, past an unchained
    /// fallback line at its start.
    #[test]
    fn clock_rollback_follows_past_an_unchained_first_line() {
        let dir = tempfile::tempdir().unwrap();
        append_chained(dir.path(), rec(datetime!(2026-08-02 08:00:00 UTC))).unwrap();
        let dec = dir.path().join("2026-12.jsonl");
        append_raw(&dec, &unchained_line("2026-12-01T00:00:00.000Z"));
        assert_eq!(
            append_chained(dir.path(), rec(datetime!(2026-12-02 08:00:00 UTC))).unwrap(),
            2
        );
        for want in 3..=4 {
            let seq = append_chained(dir.path(), rec(datetime!(2026-09-13 08:00:00 UTC))).unwrap();
            assert_eq!(seq, want);
        }
        assert!(!dir.path().join("2026-09.jsonl").exists());
        assert_eq!(lines(&dec).len(), 4);
        let report = crate::verify::verify(dir.path());
        let kinds: Vec<_> = report.breaks.iter().map(|b| b.kind.clone()).collect();
        assert_eq!(kinds, [crate::verify::BreakKind::Unchained]);
    }

    /// The far-ahead file need not hold the genesis: its first line chains
    /// on from the file before it.
    #[test]
    fn clock_rollback_follows_a_file_that_continues_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        append_chained(dir.path(), rec(datetime!(2026-08-02 08:00:00 UTC))).unwrap();
        append_chained(dir.path(), rec(datetime!(2026-12-02 08:00:00 UTC))).unwrap();
        let seq = append_chained(dir.path(), rec(datetime!(2026-09-13 08:00:00 UTC))).unwrap();
        assert_eq!(seq, 3);
        assert!(!dir.path().join("2026-09.jsonl").exists());
        assert_eq!(lines(&dir.path().join("2026-12.jsonl")).len(), 2);
        verify_ok(dir.path());
    }

    #[test]
    fn planted_far_future_file_is_not_followed() {
        let v1 = b"{\"v\":1,\"ts\":\"9999-12-01T00:00:00.000Z\",\"agent\":\"codex\",\"project\":\"/p\",\"tool\":\"shell\",\"input\":\"ls\",\"decision\":\"allow\",\"saiife\":\"0.1.0\"}\n".to_vec();
        let mut other = rec(datetime!(2026-10-13 08:00:00 UTC));
        other.seq = Some(0);
        other.prev = Some(ZERO_PREV.into());
        other.kind = Some("genesis".into());
        let mut other = serde_json::to_vec(&other).unwrap();
        other.push(b'\n');
        for planted in [Vec::new(), v1, other] {
            let dir = tempfile::tempdir().unwrap();
            fs::write(dir.path().join("9999-12.jsonl"), &planted).unwrap();
            append_chained(dir.path(), rec(datetime!(2026-10-13 08:00:00 UTC))).unwrap();
            let seq = append_chained(dir.path(), rec(datetime!(2026-10-13 09:00:00 UTC))).unwrap();
            assert_eq!(seq, 2);
            assert_eq!(lines(&dir.path().join("2026-10.jsonl")).len(), 3);
            assert_eq!(fs::read(dir.path().join("9999-12.jsonl")).unwrap(), planted);
        }
    }
}
