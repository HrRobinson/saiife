//! Audit forwarding (spec §6.5; plan 12 decisions 1 and 2): one worker
//! per `[audit.forward.<name>]` target sends every chain line, in order and
//! at least once, through a [`Transport`].
//!
//! - The worker reads the month files, never the writer's memory, and never
//!   takes the chain lock: the writer and the hooks never wait on a target.
//!   It is woken by the writer after each append and polls every second.
//! - The payload of a record is the exact bytes of its line in the month
//!   file, WITHOUT the trailing `\n` (a transport adds its own framing).
//!   Every non-blank complete line is sent, lines without a `seq` included
//!   (a foreign line the chain goes on from), so the copy verifies.
//! - `state/forward-<name>.cursor` (0600, written atomically) holds the
//!   `seq` and the SHA-256 of the last line the target confirmed (the hash
//!   tells it apart from a same-`seq` line of a later chain, after a new
//!   genesis). It moves only after a confirmed send, so a crash between
//!   the send and the cursor write sends that batch again: delivery is at
//!   least once, and duplicates after a crash or a reload that changed the
//!   target are possible.
//! - A target whose config changes (a new address, say) keeps its cursor
//!   and goes on where it was: the new destination does not get the older
//!   records. To send the whole log to it, give the target a new name (a
//!   new name has no cursor and starts at the oldest line).
//! - A failing send is retried forever, with a backoff from 1 s to 60 s.
//!   The state changes are `forward` records (`connected`, `failing` after
//!   an outage of more than 30 s, `recovered`, `backlog_dropped`); batches
//!   are never recorded. An outage of more than 5 min is one
//!   `forward_failing` notification.
//! - Records are lost only when retention deleted the month file holding
//!   the cursor's next `seq`: the worker goes on at the oldest line left
//!   and records `backlog_dropped` with `from_seq`/`to_seq`.

use bytes::Bytes;
use saiife_audit::{store, Record};
use saiife_policy::{Event, ForwardCfg};
use std::collections::BTreeMap;
use std::future::Future;
use std::io::{self, BufRead, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// A worker with nothing to send looks again after this long.
pub const POLL: Duration = Duration::from_secs(1);
/// The first retry waits this long; each next one twice as long.
pub const BACKOFF_MIN: Duration = Duration::from_secs(1);
/// The longest wait between retries.
pub const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// An outage longer than this is a `failing` record.
pub const FAILING_AFTER: Duration = Duration::from_secs(30);
/// An outage longer than this is one `forward_failing` notification.
pub const NOTIFY_AFTER: Duration = Duration::from_secs(5 * 60);

/// Why a send did not go through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
    /// The target is down or refused this time: try again after a backoff.
    Retry(String),
    /// The target is configured in a way that cannot work: the worker
    /// records it (`failing`) and stops until the target's config changes.
    Fatal(String),
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::Retry(why) => write!(f, "{why}"),
            SendError::Fatal(why) => write!(f, "{why}"),
        }
    }
}

/// What [`Transport::send`] returns (a boxed future: the workspace has no
/// `async_trait`).
pub type SendFuture<'a> = Pin<Box<dyn Future<Output = Result<(), SendError>> + Send + 'a>>;

/// Where a target's batches go (syslog, file, https: Task 3).
pub trait Transport: Send + Sync {
    /// Send `lines` in order; `Ok` only once the target has them all. Each
    /// line is the exact bytes of one record's line, without its `\n`.
    fn send<'a>(&'a self, lines: &'a [Bytes]) -> SendFuture<'a>;
    /// `(records, bytes)`: the most a batch may hold. A single line longer
    /// than the byte limit is sent alone.
    fn max_batch(&self) -> (usize, usize);
}

/// Builds the transport of a target, or says why it cannot.
pub type MakeTransport =
    Arc<dyn Fn(&str, &ForwardCfg) -> Result<Box<dyn Transport>, String> + Send + Sync>;

/// The timeout of one send to a network target (syslog over TLS, https).
pub const SEND_TIMEOUT: Duration = Duration::from_secs(30);

/// The daemon's transports for `[audit.forward.<name>]` (plan 12 decisions
/// 3 to 5). The config was validated when the policy loaded. Nothing here
/// touches the network or the vault: a network target builds its TLS client
/// and reads its secret at each send, so a CA file or a secret fixed later
/// is picked up without a config change.
pub fn transport_for(
    name: &str,
    cfg: &ForwardCfg,
    ctx: &Weak<crate::ops::Ctx>,
) -> Result<Box<dyn Transport>, String> {
    let _ = name;
    match cfg {
        ForwardCfg::Syslog {
            address,
            format,
            facility,
            ca,
        } => {
            let facility = saiife_policy::facility_code(facility.as_deref()).unwrap_or(16);
            let dest = crate::forward_syslog::Dest::parse(address)?;
            Ok(Box::new(crate::forward_syslog::SyslogTransport::new(
                dest,
                *format,
                facility,
                crate::signals::hostname(),
                TargetClient::of_daemon(ctx, ca.clone()),
            )))
        }
        ForwardCfg::File { path } => Ok(Box::new(crate::forward_file::FileTransport::new(
            path.clone(),
            saiife_audit::chain::host_id().unwrap_or_else(|| "unknown".into()),
        ))),
        ForwardCfg::Https {
            url,
            auth_secret,
            format,
            ca,
        } => {
            let weak = ctx.clone();
            let secrets: crate::forward_https::Secrets = Arc::new(move |n: &str| {
                let ctx = weak.upgrade()?;
                crate::notifier::Env::secret(&*ctx, n)
            });
            Ok(Box::new(crate::forward_https::HttpsTransport::new(
                url,
                *format,
                auth_secret.clone(),
                secrets,
                TargetClient::of_daemon(ctx, ca.clone()),
            )?))
        }
    }
}

type MakeUpstream =
    Box<dyn Fn() -> Result<saiife_broker::upstream::Upstream, String> + Send + Sync>;

/// The TLS client of a network target (the broker's `Upstream`: rustls,
/// the system roots plus `/etc/saiife/ca`, or plus the target's own `ca`),
/// built at the first send and kept once it was built. A failure (an
/// unreadable `ca`, say) is a retry, and the next send builds it again.
pub struct TargetClient {
    make: MakeUpstream,
    built: Mutex<Option<Arc<saiife_broker::upstream::Upstream>>>,
}

impl TargetClient {
    pub fn new(
        make: impl Fn() -> Result<saiife_broker::upstream::Upstream, String> + Send + Sync + 'static,
    ) -> TargetClient {
        TargetClient {
            make: Box::new(make),
            built: Mutex::new(None),
        }
    }

    /// The daemon's client with [`SEND_TIMEOUT`]; with `ca`, the native
    /// roots plus that file in place of the CA directory.
    fn of_daemon(ctx: &Weak<crate::ops::Ctx>, ca: Option<PathBuf>) -> TargetClient {
        let ctx = ctx.clone();
        TargetClient::new(move || {
            let ctx = ctx.upgrade().ok_or("the daemon is stopping")?;
            let base = ctx.upstream.as_ref().map_err(|e| e.clone())?;
            match &ca {
                Some(file) => base
                    .with_ca_file(file, SEND_TIMEOUT)
                    .map_err(|e| e.to_string()),
                None => Ok(base.with_timeout(SEND_TIMEOUT)),
            }
        })
    }

    pub fn get(&self) -> Result<Arc<saiife_broker::upstream::Upstream>, String> {
        let mut g = self.built.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(u) = &*g {
            return Ok(Arc::clone(u));
        }
        let u = Arc::new((self.make)()?);
        *g = Some(Arc::clone(&u));
        Ok(u)
    }
}

/// The worker's clock: monotonic time and sleeping (tests replace it, so
/// they never wait 30 s or 5 min).
pub trait Clock: Send + Sync + 'static {
    /// Time since an arbitrary fixed origin.
    fn now(&self) -> Duration;
    fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
}

/// The real clock.
pub struct SystemClock {
    origin: Instant,
}

impl Default for SystemClock {
    fn default() -> Self {
        SystemClock {
            origin: Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }

    fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        Box::pin(tokio::time::sleep(d))
    }
}

/// What a worker needs from the daemon.
pub trait Host: Send + Sync + 'static {
    /// A fresh `forward` record (policy hash, own uid) with `input`.
    fn new_forward_record(&self, input: &str) -> Record;
    /// Hands the record to the audit writer without waiting.
    fn append_forward_record(&self, rec: Record);
    /// Queue the `forward_failing` notification.
    fn notify_forward_failing(&self, target: &str, summary: &str);
}

impl Host for crate::ops::Ctx {
    fn new_forward_record(&self, input: &str) -> Record {
        self.record("forward", input)
    }

    fn append_forward_record(&self, rec: Record) {
        let w = self.writer.clone();
        tokio::spawn(async move {
            if let Err(e) = w.append(rec).await {
                eprintln!("saiife: warning: forward record not written: {e}");
            }
        });
    }

    fn notify_forward_failing(&self, _target: &str, summary: &str) {
        self.notify(Event::ForwardFailing, None, None, None, None, summary);
    }
}

/// `<state>/state/forward-<name>.cursor`.
pub fn cursor_path(state_dir: &Path, name: &str) -> PathBuf {
    state_dir
        .join("state")
        .join(format!("forward-{name}.cursor"))
}

/// The last line a target confirmed: its `seq` and the SHA-256 (hex) of
/// its exact bytes (without the `\n`). The hash tells that line apart from
/// a line with the same `seq` in a later chain (after a new genesis). On
/// disk the hash is always there; `hash: None` exists only in memory, after
/// a `backlog_dropped`, and never matches a line (see [`locate`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    pub seq: u64,
    pub hash: Option<String>,
}

/// The cursor; `None` when there is no file yet. The file holds
/// `"<seq> <sha256 hex>\n"`; anything else is an error (the worker then
/// starts at the oldest line, with a warning).
pub fn read_cursor(path: &Path) -> Result<Option<Cursor>, String> {
    let mut s = String::new();
    match std::fs::File::open(path) {
        Ok(f) => {
            f.take(256)
                .read_to_string(&mut s)
                .map_err(|e| format!("{}: {e}", path.display()))?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    }
    let bad = || format!("{}: not a cursor", path.display());
    let mut parts = s.split_ascii_whitespace();
    let seq = parts
        .next()
        .and_then(|p| p.parse::<u64>().ok())
        .ok_or_else(bad)?;
    let hash = match parts.next() {
        Some(h) if h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) => {
            h.to_string()
        }
        _ => return Err(bad()),
    };
    if parts.next().is_some() {
        return Err(bad());
    }
    Ok(Some(Cursor {
        seq,
        hash: Some(hash),
    }))
}

/// Temp file names are unique per process and write: two workers of the
/// same target (one stopping, one starting) never share one.
static TMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Write the cursor: a 0600 temp file, fsync, rename, fsync of the dir
/// (created 0700 when missing). A cursor without a hash is refused.
pub fn write_cursor(path: &Path, c: &Cursor) -> io::Result<()> {
    let Some(hash) = &c.hash else {
        return Err(io::Error::other("a cursor needs the hash of its line"));
    };
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("cursor path has no directory"))?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let n = TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = dir.join(format!(".{name}.{}.{n}.tmp", std::process::id()));
    let body = format!("{} {hash}\n", c.seq);
    let staged = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = staged {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    std::fs::File::open(dir)?.sync_all()
}

/// A place in the log: a month file and a byte offset at a line start.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pos {
    file: PathBuf,
    offset: u64,
}

/// What [`read_batch`] read.
#[derive(Debug)]
struct Batch {
    lines: Vec<Bytes>,
    /// The last line in the batch that has a `seq`.
    last: Option<Cursor>,
    /// Where the next batch starts.
    next: Pos,
}

#[derive(Debug)]
enum ReadErr {
    /// The file at the position is gone or was replaced (retention): find
    /// the place again from the cursor.
    Gone,
    Io(String),
}

#[derive(serde::Deserialize)]
struct SeqOnly {
    #[serde(default)]
    seq: Option<u64>,
}

fn seq_of(line: &[u8]) -> Option<u64> {
    serde_json::from_slice::<SeqOnly>(line).ok()?.seq
}

fn blank(line: &[u8]) -> bool {
    line.iter().all(u8::is_ascii_whitespace)
}

/// The SHA-256 (hex) a cursor keeps of its line.
fn line_hash(line: &[u8]) -> String {
    saiife_audit::chain::sha256_hex(line)
}

/// Where to go on, and the `(from_seq, to_seq)` retention took if any.
type Located = (Pos, Option<(u64, u64)>);

/// Where to go on after `cursor`, reading the log line by line (oldest
/// file first, never a whole file in memory):
/// - no cursor: the start of the oldest file;
/// - the cursor's line is there (same `seq` and hash): just after it;
/// - else, when the oldest `seq` left is past the cursor, retention took
///   the cursor's line: the oldest line, and `Some((from, to))` names the
///   seqs it took (none when the oldest is the cursor's next `seq`);
/// - else lines with a `seq` at most the cursor's are there but not its
///   line: the chain was restarted (a new genesis), maybe more than once.
///   Go on at the oldest line: at least once allows the duplicates, but no
///   chain between the cursor's and the newest may be skipped. Nothing is
///   recorded.
///
/// `None`: no month file yet.
fn locate(dir: &Path, cursor: Option<&Cursor>) -> Result<Option<Located>, String> {
    let files = store::month_files(dir)?;
    let Some(oldest) = files.first() else {
        return Ok(None);
    };
    let start = Pos {
        file: oldest.clone(),
        offset: 0,
    };
    let Some(c) = cursor else {
        return Ok(Some((start, None)));
    };
    let mut matched: Option<Pos> = None;
    let mut first_seq: Option<u64> = None;
    let mut buf = Vec::new();
    for f in &files {
        let Some(file) = store::open_regular(f) else {
            continue;
        };
        let mut r = io::BufReader::new(file);
        let mut off = 0u64;
        loop {
            buf.clear();
            let n = r
                .read_until(b'\n', &mut buf)
                .map_err(|e| format!("{}: {e}", f.display()))?;
            if n == 0 {
                break;
            }
            off += n as u64;
            let line = buf.strip_suffix(b"\n").unwrap_or(&buf);
            if blank(line) {
                continue;
            }
            let Some(s) = seq_of(line) else {
                continue;
            };
            first_seq.get_or_insert(s);
            if matched.is_none()
                && s == c.seq
                && c.hash.as_deref().is_some_and(|h| line_hash(line) == h)
            {
                matched = Some(Pos {
                    file: f.clone(),
                    offset: off,
                });
            }
        }
    }
    if let Some(p) = matched {
        return Ok(Some((p, None)));
    }
    Ok(Some(match first_seq {
        Some(s) if s > c.seq => {
            let dropped = (s > c.seq.saturating_add(1)).then(|| (c.seq + 1, s - 1));
            (start, dropped)
        }
        Some(_) | None => (start, None),
    }))
}

/// The month file after `file`, if there is one.
fn next_file(dir: &Path, file: &Path) -> Result<Option<PathBuf>, ReadErr> {
    let files = store::month_files(dir).map_err(ReadErr::Io)?;
    Ok(files.into_iter().find(|p| p.file_name() > file.file_name()))
}

/// Read up to `max_n` lines and about `max_bytes` (one longer line goes
/// alone) from `pos` on, into the next month files when this one is done.
///
/// The writer appends to the newest file only, so a file with a newer one
/// after it is complete. In the newest file a line without its `\n` yet is
/// left for later; in a complete file such an unterminated tail (a crash
/// mid-line) is sent as its last line and the reader moves on, so it never
/// waits on a line that will not be finished.
fn read_batch(dir: &Path, pos: &Pos, max_n: usize, max_bytes: usize) -> Result<Batch, ReadErr> {
    let mut lines: Vec<Bytes> = Vec::new();
    let mut bytes = 0usize;
    let mut last_idx: Option<(usize, u64)> = None;
    let mut cur = pos.clone();
    let mut complete = next_file(dir, &cur.file)?.is_some();
    'files: loop {
        let Some(mut f) = store::open_regular(&cur.file) else {
            if lines.is_empty() {
                return Err(ReadErr::Gone);
            }
            break;
        };
        let len = f.metadata().map_err(|e| ReadErr::Io(e.to_string()))?.len();
        if len < cur.offset {
            // Shorter than what was read: not the file it was.
            if lines.is_empty() {
                return Err(ReadErr::Gone);
            }
            break;
        }
        f.seek(SeekFrom::Start(cur.offset))
            .map_err(|e| ReadErr::Io(e.to_string()))?;
        let mut r = io::BufReader::new(f);
        let mut buf = Vec::new();
        loop {
            if lines.len() >= max_n {
                break 'files;
            }
            buf.clear();
            let n = r
                .read_until(b'\n', &mut buf)
                .map_err(|e| ReadErr::Io(e.to_string()))?;
            if n == 0 {
                break;
            }
            let line = match buf.strip_suffix(b"\n") {
                Some(l) => l,
                None if complete => &buf[..],
                // Still being written: next time.
                None => break,
            };
            if !blank(line) {
                if !lines.is_empty() && bytes + line.len() > max_bytes {
                    break 'files;
                }
                bytes += line.len();
                if let Some(s) = seq_of(line) {
                    last_idx = Some((lines.len(), s));
                }
                lines.push(Bytes::copy_from_slice(line));
            }
            cur.offset += n as u64;
        }
        if complete {
            match next_file(dir, &cur.file)? {
                Some(next) => {
                    cur = Pos {
                        file: next,
                        offset: 0,
                    };
                    complete = next_file(dir, &cur.file)?.is_some();
                }
                None => break,
            }
        } else if next_file(dir, &cur.file)?.is_some() {
            // A newer file appeared while this one was read: it is complete
            // now; one more pass reads what landed in it meanwhile.
            complete = true;
        } else {
            break;
        }
    }
    let last = last_idx.map(|(i, seq)| Cursor {
        seq,
        hash: Some(line_hash(&lines[i])),
    });
    Ok(Batch {
        lines,
        last,
        next: cur,
    })
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| format!("forwarder task failed: {e}"))
}

/// The state of an outage, from its first failed send.
#[derive(Default)]
struct Outage {
    since: Option<Duration>,
    failing_recorded: bool,
    notified: bool,
}

/// Resolves once the worker is asked to stop (or its stopper is gone).
async fn stopped(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|v| *v).await;
}

/// One per target name, kept across its workers: cursor reads and writes
/// take `lock`, and a write goes to disk only while its worker's generation
/// is still `gen`. A worker that was aborted (after [`STOP_WAIT`]) in the
/// middle of a cursor write can so never write after its replacement read
/// the cursor: its write either landed before that read or is skipped.
/// The replacement may then start from an older cursor than the one the
/// old worker last confirmed: duplicates, never a gap.
#[derive(Default)]
pub struct CursorGuard {
    lock: Mutex<()>,
    gen: std::sync::atomic::AtomicU64,
}

impl CursorGuard {
    /// Start a new generation (the previous worker's writes are void).
    fn next_gen(&self) -> u64 {
        let _g = lock(&self.lock);
        self.gen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1
    }

    /// Write `c` if `gen` is still current; `Ok(false)` when skipped.
    fn write(&self, gen: u64, path: &Path, c: &Cursor) -> io::Result<bool> {
        let _g = lock(&self.lock);
        if self.gen.load(std::sync::atomic::Ordering::SeqCst) != gen {
            return Ok(false);
        }
        write_cursor(path, c).map(|()| true)
    }

    fn read(&self, path: &Path) -> Result<Option<Cursor>, String> {
        let _g = lock(&self.lock);
        read_cursor(path)
    }
}

struct Worker {
    name: String,
    guard: Arc<CursorGuard>,
    gen: u64,
    transport: Box<dyn Transport>,
    audit_dir: PathBuf,
    cursor_path: PathBuf,
    host: Weak<dyn Host>,
    clock: Arc<dyn Clock>,
    appended: watch::Receiver<u64>,
    stop: watch::Receiver<bool>,
}

impl Worker {
    fn record(&self, event: &str, fill: impl FnOnce(&mut Record)) {
        let Some(h) = self.host.upgrade() else {
            return;
        };
        let mut r = h.new_forward_record(&format!("forward {} {event}", self.name));
        r.extra.insert("event".into(), event.into());
        r.extra.insert("target".into(), self.name.clone().into());
        fill(&mut r);
        h.append_forward_record(r);
    }

    /// Wait for the next append or the poll interval; `true` when asked
    /// to stop.
    async fn idle(&mut self) -> bool {
        let clock = Arc::clone(&self.clock);
        tokio::select! {
            r = self.appended.changed() => {
                if r.is_err() {
                    // The writer is gone: poll only.
                    tokio::select! {
                        _ = clock.sleep(POLL) => {}
                        _ = stopped(&mut self.stop) => return true,
                    }
                }
            }
            _ = clock.sleep(POLL) => {}
            _ = stopped(&mut self.stop) => return true,
        }
        false
    }

    /// Never cancelled half-way: a stop is honoured only between steps.
    async fn save_cursor(&self, c: Cursor) {
        let p = self.cursor_path.clone();
        let (guard, gen) = (Arc::clone(&self.guard), self.gen);
        match blocking(move || guard.write(gen, &p, &c)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => eprintln!(
                "saiife: warning: forward {}: cannot write the cursor: {e}",
                self.name
            ),
            Err(e) => eprintln!("saiife: warning: forward {}: {e}", self.name),
        }
    }

    async fn run(mut self) {
        let p = self.cursor_path.clone();
        let guard = Arc::clone(&self.guard);
        let mut cursor = match blocking(move || guard.read(&p)).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) | Err(e) => {
                // Starting over sends duplicates, never leaves a gap.
                eprintln!(
                    "saiife: warning: forward {}: {e}; going on at the oldest line (the target gets duplicates)",
                    self.name
                );
                None
            }
        };
        let (max_n, max_bytes) = self.transport.max_batch();
        let (max_n, max_bytes) = (max_n.max(1), max_bytes.max(1));
        let mut pos: Option<Pos> = None;
        let mut outage = Outage::default();
        let mut connected = false;
        let mut backoff = BACKOFF_MIN;
        loop {
            if self.host.strong_count() == 0 || *self.stop.borrow() {
                return;
            }
            let Some(at) = pos.clone() else {
                let dir = self.audit_dir.clone();
                let c = cursor.clone();
                match blocking(move || locate(&dir, c.as_ref())).await {
                    Ok(Ok(Some((p, dropped)))) => {
                        if let Some((from, to)) = dropped {
                            self.record("backlog_dropped", |r| {
                                r.extra.insert("from_seq".into(), from.into());
                                r.extra.insert("to_seq".into(), to.into());
                                r.reason = Some(
                                    "retention deleted records this target had not received".into(),
                                );
                            });
                            // In memory only: no line to hash. A restart
                            // before the next confirmed send records the
                            // drop again.
                            cursor = Some(Cursor {
                                seq: to,
                                hash: None,
                            });
                        }
                        pos = Some(p);
                    }
                    Ok(Ok(None)) => {
                        if self.idle().await {
                            return;
                        }
                    }
                    Ok(Err(e)) | Err(e) => {
                        eprintln!("saiife: warning: forward {}: {e}", self.name);
                        if self.idle().await {
                            return;
                        }
                    }
                }
                continue;
            };
            let dir = self.audit_dir.clone();
            let batch = match blocking(move || read_batch(&dir, &at, max_n, max_bytes)).await {
                Ok(Ok(b)) => b,
                Ok(Err(ReadErr::Gone)) => {
                    pos = None;
                    continue;
                }
                Ok(Err(ReadErr::Io(e))) | Err(e) => {
                    eprintln!("saiife: warning: forward {}: {e}", self.name);
                    if self.idle().await {
                        return;
                    }
                    continue;
                }
            };
            if batch.lines.is_empty() {
                pos = Some(batch.next);
                if self.idle().await {
                    return;
                }
                continue;
            }
            // A stop drops a send in flight: its batch goes again next time.
            let sent = tokio::select! {
                r = self.transport.send(&batch.lines) => r,
                _ = stopped(&mut self.stop) => return,
            };
            match sent {
                Ok(()) => {
                    if let Some(c) = batch.last {
                        cursor = Some(c.clone());
                        self.save_cursor(c).await;
                    }
                    pos = Some(batch.next);
                    backoff = BACKOFF_MIN;
                    if outage.failing_recorded {
                        self.record("recovered", |_| {});
                    } else if !connected {
                        self.record("connected", |_| {});
                    }
                    connected = true;
                    outage = Outage::default();
                }
                Err(SendError::Retry(why)) => {
                    let now = self.clock.now();
                    let since = *outage.since.get_or_insert(now);
                    let lasted = now.saturating_sub(since);
                    if !outage.failing_recorded && lasted > FAILING_AFTER {
                        outage.failing_recorded = true;
                        self.record("failing", |r| r.reason = Some(why.clone()));
                    }
                    if !outage.notified && lasted > NOTIFY_AFTER {
                        outage.notified = true;
                        if let Some(h) = self.host.upgrade() {
                            h.notify_forward_failing(
                                &self.name,
                                &format!(
                                    "audit forwarding to {} failing for more than 5 min: {why}",
                                    self.name
                                ),
                            );
                        }
                    }
                    let clock = Arc::clone(&self.clock);
                    tokio::select! {
                        _ = clock.sleep(backoff) => {}
                        _ = stopped(&mut self.stop) => return,
                    }
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                }
                Err(SendError::Fatal(why)) => {
                    eprintln!(
                        "saiife: warning: forward {}: {why}; target stopped",
                        self.name
                    );
                    self.record("failing", |r| r.reason = Some(why.clone()));
                    return;
                }
            }
        }
    }
}

/// What the workers share, set once at start.
pub struct Setup {
    pub audit_dir: PathBuf,
    pub state_dir: PathBuf,
    /// The writer's head `seq`, changed after each append.
    pub appended: watch::Receiver<u64>,
    pub clock: Arc<dyn Clock>,
    pub host: Weak<dyn Host>,
    pub make: MakeTransport,
}

/// How long a stopping worker may take before it is aborted.
pub const STOP_WAIT: Duration = Duration::from_secs(5);

struct Task {
    stop: watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
}

/// Ask all `tasks` to stop at once and wait for them (a worker never stops
/// half-way through a cursor write), all within one [`STOP_WAIT`]; the
/// ones still running then are aborted.
async fn stop_tasks(tasks: Vec<Task>) {
    for t in &tasks {
        let _ = t.stop.send(true);
    }
    let deadline = tokio::time::Instant::now() + STOP_WAIT;
    for t in tasks {
        let abort = t.join.abort_handle();
        if tokio::time::timeout_at(deadline, t.join).await.is_err() {
            abort.abort();
        }
    }
}

struct Running {
    cfg: ForwardCfg,
    /// `None`: the transport could not be built (recorded once).
    task: Option<Task>,
}

#[derive(Default)]
struct Inner {
    setup: Option<Setup>,
    running: BTreeMap<String, Running>,
    guards: BTreeMap<String, Arc<CursorGuard>>,
}

/// The forwarding workers (`Ctx.forwarders`).
#[derive(Default)]
pub struct Forwarders {
    inner: Mutex<Inner>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Forwarders {
    /// Set what the workers share; no worker starts before [`Self::apply`].
    pub fn configure(&self, setup: Setup) {
        lock(&self.inner).setup = Some(setup);
    }

    /// Make the running workers match `targets` (start and reload): a
    /// target that is gone or changed is stopped, and waited for, before a
    /// new or changed one starts from its cursor. A changed target keeps
    /// its cursor. Does nothing before [`Self::configure`].
    pub async fn apply(&self, targets: &BTreeMap<String, ForwardCfg>) {
        let gone: Vec<(String, Running)> = {
            let mut g = lock(&self.inner);
            if g.setup.is_none() {
                return;
            }
            let all = std::mem::take(&mut g.running);
            let (keep, gone): (BTreeMap<_, _>, BTreeMap<_, _>) = all
                .into_iter()
                .partition(|(name, r)| targets.get(name) == Some(&r.cfg));
            g.running = keep;
            gone.into_iter().collect()
        };
        let names: Vec<String> = gone.iter().map(|(n, _)| n.clone()).collect();
        stop_tasks(gone.into_iter().filter_map(|(_, r)| r.task).collect()).await;
        let mut g = lock(&self.inner);
        // A worker aborted mid-write writes nothing more.
        for n in &names {
            if let Some(guard) = g.guards.get(n) {
                guard.next_gen();
            }
        }
        let Inner {
            setup,
            running,
            guards,
        } = &mut *g;
        let Some(setup) = setup.as_ref() else {
            return;
        };
        for (name, cfg) in targets {
            if running.contains_key(name) {
                continue;
            }
            let task = match (setup.make)(name, cfg) {
                Ok(transport) => {
                    let (stop_tx, stop) = watch::channel(false);
                    let guard = Arc::clone(guards.entry(name.clone()).or_default());
                    let w = Worker {
                        name: name.clone(),
                        gen: guard.next_gen(),
                        guard,
                        transport,
                        audit_dir: setup.audit_dir.clone(),
                        cursor_path: cursor_path(&setup.state_dir, name),
                        host: setup.host.clone(),
                        clock: Arc::clone(&setup.clock),
                        appended: setup.appended.clone(),
                        stop,
                    };
                    Some(Task {
                        stop: stop_tx,
                        join: tokio::spawn(w.run()),
                    })
                }
                Err(why) => {
                    eprintln!("saiife: warning: forward {name}: {why}");
                    if let Some(h) = setup.host.upgrade() {
                        let mut r = h.new_forward_record(&format!("forward {name} failing"));
                        r.extra.insert("event".into(), "failing".into());
                        r.extra.insert("target".into(), name.clone().into());
                        r.reason = Some(why);
                        h.append_forward_record(r);
                    }
                    None
                }
            };
            running.insert(
                name.clone(),
                Running {
                    cfg: cfg.clone(),
                    task,
                },
            );
        }
    }

    /// Stop every worker and wait for them (the daemon's stop). The
    /// cursors stay.
    pub async fn stop_all(&self) {
        let all = std::mem::take(&mut lock(&self.inner).running);
        stop_tasks(all.into_values().filter_map(|r| r.task).collect()).await;
        for guard in lock(&self.inner).guards.values() {
            guard.next_gen();
        }
    }

    /// The names of the targets with a running worker.
    pub fn running(&self) -> Vec<String> {
        lock(&self.inner)
            .running
            .iter()
            .filter(|(_, r)| r.task.as_ref().is_some_and(|t| !t.join.is_finished()))
            .map(|(n, _)| n.clone())
            .collect()
    }
}

/// Test transports (plan 12, Task 2).
#[cfg(test)]
pub mod testing {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

    /// Captures every line it is sent.
    #[derive(Clone)]
    pub struct MemoryTransport {
        pub lines: Arc<Mutex<Vec<Bytes>>>,
        pub batch: (usize, usize),
    }

    impl MemoryTransport {
        pub fn new(batch: (usize, usize)) -> MemoryTransport {
            MemoryTransport {
                lines: Arc::default(),
                batch,
            }
        }

        pub fn got(&self) -> Vec<Bytes> {
            lock(&self.lines).clone()
        }
    }

    impl Transport for MemoryTransport {
        fn send<'a>(&'a self, lines: &'a [Bytes]) -> SendFuture<'a> {
            Box::pin(async move {
                lock(&self.lines).extend_from_slice(lines);
                Ok(())
            })
        }

        fn max_batch(&self) -> (usize, usize) {
            self.batch
        }
    }

    /// Fails its first `fails` sends (`Retry`) and while `down` is set,
    /// then works like a [`MemoryTransport`].
    #[derive(Clone)]
    pub struct FlakyTransport {
        pub inner: MemoryTransport,
        pub fails: Arc<AtomicUsize>,
        pub down: Arc<AtomicBool>,
        pub attempts: Arc<AtomicUsize>,
    }

    impl FlakyTransport {
        pub fn new(fails: usize) -> FlakyTransport {
            FlakyTransport {
                inner: MemoryTransport::new((500, 1 << 20)),
                fails: Arc::new(AtomicUsize::new(fails)),
                down: Arc::default(),
                attempts: Arc::default(),
            }
        }
    }

    impl Transport for FlakyTransport {
        fn send<'a>(&'a self, lines: &'a [Bytes]) -> SendFuture<'a> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            // One worker per transport: no race between the load and the sub.
            let fail = self.down.load(Ordering::SeqCst)
                || (self.fails.load(Ordering::SeqCst) > 0
                    && self.fails.fetch_sub(1, Ordering::SeqCst) > 0);
            if fail {
                return Box::pin(async { Err(SendError::Retry("target down".into())) });
            }
            self.inner.send(lines)
        }

        fn max_batch(&self) -> (usize, usize) {
            self.inner.batch
        }
    }

    /// A clock whose sleeps move its time on at once and last a
    /// thousandth of that (at least 1 ms) in real time.
    #[derive(Default)]
    pub struct FakeClock {
        pub ms: AtomicU64,
    }

    impl Clock for FakeClock {
        fn now(&self) -> Duration {
            Duration::from_millis(self.ms.load(Ordering::SeqCst))
        }

        fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
            self.ms.fetch_add(d.as_millis() as u64, Ordering::SeqCst);
            let real = (d / 1000).max(Duration::from_millis(1));
            Box::pin(tokio::time::sleep(real))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use crate::writer::{self, WriterConfig, WriterHandle};
    use saiife_audit::sign::AuditKey;
    use saiife_audit::{ChainWriter, DecisionKind, NewRecord, WriterOptions};
    use saiife_policy::Fsync;
    use std::sync::atomic::Ordering;

    struct TestHost {
        writer: Option<WriterHandle>,
        records: Mutex<Vec<Record>>,
        notes: Mutex<Vec<String>>,
    }

    impl Host for TestHost {
        fn new_forward_record(&self, input: &str) -> Record {
            let mut r = rec_with("forward", input);
            r.kind = Some("forward".into());
            r
        }

        fn append_forward_record(&self, rec: Record) {
            lock(&self.records).push(rec.clone());
            if let Some(w) = self.writer.clone() {
                tokio::spawn(async move {
                    let _ = w.append(rec).await;
                });
            }
        }

        fn notify_forward_failing(&self, target: &str, _summary: &str) {
            lock(&self.notes).push(target.to_string());
        }
    }

    impl TestHost {
        fn events(&self) -> Vec<String> {
            lock(&self.records)
                .iter()
                .map(|r| r.extra["event"].as_str().unwrap().to_string())
                .collect()
        }
    }

    fn rec_with(tool: &str, input: &str) -> Record {
        let mut r = Record::new(
            NewRecord {
                agent: "claude",
                project: "/p",
                session: None,
                tool,
                input,
                decision: DecisionKind::Allow,
                pack: None,
                rule: None,
                reason: None,
                mode: "locked",
                policy: None,
                permission_mode: None,
            },
            "test",
        );
        r.kind = Some("guard".into());
        r
    }

    fn rec(i: usize) -> Record {
        rec_with("Bash", &format!("echo {i} \u{e9}\u{1F600} \"q\" \\ \t tab"))
    }

    struct H {
        _tmp: tempfile::TempDir,
        audit: PathBuf,
        state: PathBuf,
        writer: Option<WriterHandle>,
        join: Option<std::thread::JoinHandle<()>>,
        host: Arc<TestHost>,
        clock: Arc<FakeClock>,
        appended: watch::Receiver<u64>,
    }

    impl H {
        /// A log with a real writer.
        fn new() -> H {
            let tmp = tempfile::tempdir().unwrap();
            let audit = tmp.path().join("audit");
            let state = tmp.path().join("state-root");
            let cw = ChainWriter::open(
                &audit,
                WriterOptions {
                    mode: "locked".into(),
                    saiife: "test".into(),
                    key: Some(AuditKey::generate().unwrap()),
                },
            )
            .unwrap();
            let cfg = WriterConfig {
                checkpoint_every: 25,
                checkpoint_interval: Duration::from_secs(3600),
                fsync: Fsync::Checkpoint,
            };
            let (w, join) = writer::spawn(cw, cfg, None).unwrap();
            let appended = w.appends();
            H {
                _tmp: tmp,
                audit,
                state,
                host: Arc::new(TestHost {
                    writer: Some(w.clone()),
                    records: Mutex::default(),
                    notes: Mutex::default(),
                }),
                writer: Some(w),
                join: Some(join),
                clock: Arc::default(),
                appended,
            }
        }

        /// Hand-written month files and no writer.
        fn bare() -> H {
            let tmp = tempfile::tempdir().unwrap();
            let audit = tmp.path().join("audit");
            std::fs::create_dir_all(&audit).unwrap();
            let state = tmp.path().join("state-root");
            let (tx, appended) = watch::channel(0);
            std::mem::forget(tx);
            H {
                _tmp: tmp,
                audit,
                state,
                writer: None,
                join: None,
                host: Arc::new(TestHost {
                    writer: None,
                    records: Mutex::default(),
                    notes: Mutex::default(),
                }),
                clock: Arc::default(),
                appended,
            }
        }

        fn forwarders(&self, make: MakeTransport) -> Forwarders {
            let f = Forwarders::default();
            let host: Arc<dyn Host> = self.host.clone();
            f.configure(Setup {
                audit_dir: self.audit.clone(),
                state_dir: self.state.clone(),
                appended: self.appended.clone(),
                clock: self.clock.clone(),
                host: Arc::downgrade(&host),
                make,
            });
            f
        }

        async fn append(&self, n: usize) {
            let w = self.writer.as_ref().unwrap();
            for i in 0..n {
                w.append(rec(i)).await.unwrap();
            }
        }

        /// Every non-blank line of the log, without its `\n`.
        fn file_lines(&self) -> Vec<Vec<u8>> {
            let mut out = Vec::new();
            for f in store::month_files(&self.audit).unwrap() {
                let body = std::fs::read(f).unwrap();
                out.extend(
                    body.split(|&b| b == b'\n')
                        .filter(|l| !blank(l))
                        .map(<[u8]>::to_vec),
                );
            }
            out
        }

        fn cursor(&self, name: &str) -> Option<u64> {
            read_cursor(&cursor_path(&self.state, name))
                .unwrap()
                .map(|c| c.seq)
        }
    }

    impl Drop for H {
        fn drop(&mut self) {
            self.writer.take();
            self.host = Arc::new(TestHost {
                writer: None,
                records: Mutex::default(),
                notes: Mutex::default(),
            });
            // Not joined: a spawned append still holding a writer handle
            // would never run while this thread waits (a failed test
            // would hang instead of failing).
            self.join.take();
        }
    }

    fn one(name: &str) -> BTreeMap<String, ForwardCfg> {
        targets(&[name])
    }

    fn targets(names: &[&str]) -> BTreeMap<String, ForwardCfg> {
        names
            .iter()
            .map(|n| {
                (
                    n.to_string(),
                    ForwardCfg::File {
                        path: PathBuf::from("/x"),
                    },
                )
            })
            .collect()
    }

    fn make_with<T: Transport + Clone + 'static>(t: T) -> MakeTransport {
        Arc::new(move |_, _| Ok(Box::new(t.clone()) as Box<dyn Transport>))
    }

    async fn until(what: &str, mut f: impl FnMut() -> bool) {
        let end = Instant::now() + Duration::from_secs(20);
        while !f() {
            assert!(Instant::now() < end, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn seqs(lines: &[Bytes]) -> Vec<u64> {
        lines.iter().filter_map(|l| seq_of(l)).collect()
    }

    fn as_vecs(lines: &[Bytes]) -> Vec<Vec<u8>> {
        lines.iter().map(|l| l.to_vec()).collect()
    }

    #[tokio::test]
    async fn forwards_every_record_in_order() {
        let h = H::new();
        h.append(10).await;
        // Small batches: several sends, across the batch edges.
        let t = MemoryTransport::new((7, 1 << 20));
        let fw = h.forwarders(make_with(t.clone()));
        fw.apply(&one("a")).await;
        h.append(40).await;
        until("every line forwarded", || {
            as_vecs(&t.got()) == h.file_lines()
        })
        .await;
        let s = seqs(&t.got());
        assert!(s.windows(2).all(|w| w[1] == w[0] + 1), "{s:?}");
        assert_eq!(s[0], 0, "from the genesis on");
        assert!(s.len() >= 51);
        // The target's `connected` is a record, and forwarded too.
        assert_eq!(h.host.events(), ["connected"]);
        until("the connected record forwarded", || {
            t.got().iter().any(|l| {
                std::str::from_utf8(l)
                    .unwrap()
                    .contains("\"event\":\"connected\"")
            })
        })
        .await;
        fw.stop_all().await;
    }

    #[tokio::test]
    async fn exact_bytes_forwarded() {
        let h = H::new();
        h.append(5).await;
        let t = MemoryTransport::new((500, 1 << 20));
        let fw = h.forwarders(make_with(t.clone()));
        fw.apply(&one("a")).await;
        h.append(5).await;
        until("every line forwarded", || {
            t.got().len() == h.file_lines().len()
        })
        .await;
        let mut raw = Vec::new();
        for f in store::month_files(&h.audit).unwrap() {
            raw.extend(std::fs::read(f).unwrap());
        }
        let mut joined = Vec::new();
        for l in t.got() {
            assert!(!l.ends_with(b"\n"), "sent without the newline");
            joined.extend_from_slice(&l);
            joined.push(b'\n');
        }
        // Byte for byte the file, with `\n` added back after each line.
        assert_eq!(joined, raw);
        fw.stop_all().await;
    }

    #[tokio::test]
    async fn cursor_survives_restart_no_gap() {
        use std::os::unix::fs::PermissionsExt;
        let h = H::new();
        h.append(20).await;
        let t1 = MemoryTransport::new((500, 1 << 20));
        let fw = h.forwarders(make_with(t1.clone()));
        fw.apply(&one("a")).await;
        // Its own `connected` record included: nothing more is coming.
        until("first run forwarded", || {
            let got = t1.got();
            got.iter().any(|l| {
                std::str::from_utf8(l)
                    .unwrap()
                    .contains("\"event\":\"connected\"")
            }) && as_vecs(&got) == h.file_lines()
        })
        .await;
        let last = *seqs(&t1.got()).last().unwrap();
        until("cursor written", || h.cursor("a") == Some(last)).await;
        fw.stop_all().await;
        let p = cursor_path(&h.state, "a");
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let last_line = t1
            .got()
            .iter()
            .rev()
            .find(|l| seq_of(l).is_some())
            .unwrap()
            .clone();
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            format!("{last} {}\n", line_hash(&last_line))
        );

        // Down for a while: the log goes on.
        h.append(30).await;
        let t2 = MemoryTransport::new((500, 1 << 20));
        let fw = h.forwarders(make_with(t2.clone()));
        fw.apply(&one("a")).await;
        until("second run forwarded", || {
            let mut all = t1.got();
            all.extend(t2.got());
            as_vecs(&all) == h.file_lines()
        })
        .await;
        assert_eq!(seqs(&t2.got())[0], last + 1, "resumes after the cursor");
        fw.stop_all().await;
    }

    #[tokio::test]
    async fn outage_builds_backlog_not_latency() {
        let h = H::new();
        let w = h.writer.clone().unwrap();
        // The median append latency: a busy test machine's hiccups do not
        // move it, a writer waiting on the forwarder would.
        let time = |n: usize| {
            let w = w.clone();
            async move {
                let mut each = Vec::with_capacity(n);
                for i in 0..n {
                    let t = Instant::now();
                    w.append(rec(i)).await.unwrap();
                    each.push(t.elapsed());
                }
                each.sort();
                each[n / 2]
            }
        };
        let base = time(300).await;
        let t = FlakyTransport::new(0);
        t.down.store(true, Ordering::SeqCst);
        let fw = h.forwarders(make_with(t.clone()));
        fw.apply(&one("a")).await;
        until("the target was tried", || {
            t.attempts.load(Ordering::SeqCst) >= 3
        })
        .await;
        let during = time(300).await;
        assert!(
            during < base * 10 + Duration::from_millis(20),
            "appends slowed while forwarding fails: {base:?} -> {during:?}"
        );
        // Nothing went out, nothing is lost: the backlog is on disk.
        assert!(t.inner.got().is_empty());
        assert_eq!(h.cursor("a"), None);
        until("failing recorded", || {
            h.host.events().contains(&"failing".into())
        })
        .await;
        t.down.store(false, Ordering::SeqCst);
        until("the backlog forwarded", || {
            as_vecs(&t.inner.got()) == h.file_lines()
        })
        .await;
        assert_eq!(h.host.events(), ["failing", "recovered"]);
        fw.stop_all().await;
    }

    #[tokio::test]
    async fn failing_recorded_after_30s_recovered_after_success() {
        // Retries at 0, 1, 3, 7, 15 s fail, 31 s works: under 30 s down.
        let h = H::new();
        h.append(3).await;
        let t = FlakyTransport::new(5);
        let fw = h.forwarders(make_with(t.clone()));
        fw.apply(&one("a")).await;
        until("forwarded", || !t.inner.got().is_empty()).await;
        until("connected", || !h.host.events().is_empty()).await;
        assert_eq!(h.host.events(), ["connected"]);
        fw.stop_all().await;

        // Six failures: the one at 31 s is past 30 s.
        let h = H::new();
        h.append(3).await;
        let t = FlakyTransport::new(6);
        let fw = h.forwarders(make_with(t.clone()));
        fw.apply(&one("a")).await;
        until("forwarded", || !t.inner.got().is_empty()).await;
        until("recovered", || h.host.events().len() == 2).await;
        assert_eq!(h.host.events(), ["failing", "recovered"]);
        let failing = lock(&h.host.records)[0].clone();
        assert_eq!(failing.kind.as_deref(), Some("forward"));
        assert_eq!(failing.extra["target"], "a");
        assert_eq!(failing.reason.as_deref(), Some("target down"));
        // The forward records are in the log (and so forwarded too).
        until("records forwarded", || {
            t.inner.got().iter().any(|l| {
                std::str::from_utf8(l)
                    .unwrap()
                    .contains("\"event\":\"recovered\"")
            })
        })
        .await;
        assert!(h.host.notes.lock().unwrap().is_empty());
        fw.stop_all().await;
    }

    #[tokio::test]
    async fn forward_failing_notified_after_5min_once() {
        // Failures at 0, 1, 3, 7, 15, 31, 63, 123, 183, 243 s: not yet 5 min.
        let h = H::new();
        h.append(2).await;
        let t = FlakyTransport::new(10);
        let fw = h.forwarders(make_with(t.clone()));
        fw.apply(&one("a")).await;
        until("forwarded", || !t.inner.got().is_empty()).await;
        assert!(lock(&h.host.notes).is_empty());
        fw.stop_all().await;

        // 30 failures: past 5 min at the 11th, one notification only.
        let h = H::new();
        h.append(2).await;
        let t = FlakyTransport::new(30);
        let fw = h.forwarders(make_with(t.clone()));
        fw.apply(&one("a")).await;
        until("forwarded", || !t.inner.got().is_empty()).await;
        assert_eq!(*lock(&h.host.notes), ["a"]);
        until("recovered", || h.host.events().len() == 2).await;
        assert_eq!(h.host.events(), ["failing", "recovered"]);
        fw.stop_all().await;
    }

    /// The cursor on `line(seq)`.
    fn at(seq: u64) -> Cursor {
        Cursor {
            seq,
            hash: Some(line_hash(line(seq).trim_end().as_bytes())),
        }
    }

    /// A line of chain `tag` (lines of two chains with the same seq differ,
    /// as real ones do by `prev` and `ts`).
    fn line_in(tag: &str, seq: u64) -> String {
        format!("{{\"v\":2,\"seq\":{seq},\"ts\":\"x\",\"chain\":\"{tag}\"}}\n")
    }

    fn hashed(tag: &str, seq: u64) -> Cursor {
        let l = line_in(tag, seq);
        Cursor {
            seq,
            hash: Some(line_hash(l.trim_end_matches('\n').as_bytes())),
        }
    }

    fn chain(tag: &str, seqs: std::ops::RangeInclusive<u64>) -> String {
        seqs.map(|s| line_in(tag, s)).collect()
    }

    fn lines_of_str(log: &str) -> Vec<Vec<u8>> {
        log.lines().map(|l| l.as_bytes().to_vec()).collect()
    }

    #[tokio::test]
    async fn chain_restart_resumes_on_the_new_chain() {
        let old_new = chain("old", 0..=10) + &chain("new", 0..=3);
        // Chain A is gone (retention); B and C, each after a restart, are
        // there.
        let b_c = chain("B", 0..=5) + &chain("new", 0..=3);
        // `None`: a cursor file that is not a cursor ("7\n").
        type Case<'a> = (&'a str, Option<Cursor>, Vec<Vec<u8>>);
        let cases: [Case<'_>; 4] = [
            // The cursor at the old chain's end: the whole new chain goes.
            (
                &old_new,
                Some(hashed("old", 10)),
                lines_of_str(&chain("new", 0..=3)),
            ),
            // In the middle: the old chain's rest, then the new one.
            (
                &old_new,
                Some(hashed("old", 5)),
                lines_of_str(&(chain("old", 6..=10) + &chain("new", 0..=3))),
            ),
            // The cursor's line is gone but lower seqs are there: restarted
            // chains. Everything from the oldest line goes; no middle chain
            // is lost, nothing is recorded as dropped.
            (&b_c, Some(hashed("A", 9)), lines_of_str(&b_c)),
            // An unparseable cursor: the oldest line on, with a warning.
            (&old_new, None, lines_of_str(&old_new)),
        ];
        for (log, cursor, want) in cases {
            let h = H::bare();
            std::fs::write(h.audit.join("2000-01.jsonl"), log).unwrap();
            let p = cursor_path(&h.state, "a");
            match &cursor {
                Some(c) => write_cursor(&p, c).unwrap(),
                None => {
                    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                    std::fs::write(&p, "7\n").unwrap();
                }
            }
            let t = MemoryTransport::new((2, 1 << 20));
            let fw = h.forwarders(make_with(t.clone()));
            fw.apply(&one("a")).await;
            until("the lines forwarded", || as_vecs(&t.got()) == want).await;
            until("connected", || !h.host.events().is_empty()).await;
            assert_eq!(h.host.events(), ["connected"], "{cursor:?}");
            until("the cursor on the newest chain's last line", || {
                read_cursor(&p).ok().flatten() == Some(hashed("new", 3))
            })
            .await;
            fw.stop_all().await;
            // After a restart: nothing more goes (the hash places it).
            let t2 = MemoryTransport::new((2, 1 << 20));
            let fw = h.forwarders(make_with(t2.clone()));
            fw.apply(&one("a")).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(t2.got().is_empty(), "{cursor:?}");
            fw.stop_all().await;
        }
    }

    #[test]
    fn a_stale_workers_cursor_write_is_skipped() {
        let d = tempfile::tempdir().unwrap();
        let p = cursor_path(d.path(), "a");
        let g = CursorGuard::default();
        let old = g.next_gen();
        assert!(g.write(old, &p, &hashed("x", 1)).unwrap());
        // The replacement starts: the old worker's late write is void.
        let new = g.next_gen();
        assert_eq!(g.read(&p).unwrap(), Some(hashed("x", 1)));
        assert!(!g.write(old, &p, &hashed("x", 9)).unwrap());
        assert_eq!(g.read(&p).unwrap(), Some(hashed("x", 1)));
        assert!(g.write(new, &p, &hashed("x", 2)).unwrap());
        assert_eq!(g.read(&p).unwrap(), Some(hashed("x", 2)));
    }

    #[test]
    fn unterminated_tail_in_an_older_file_is_sent_and_passed() {
        let d = tempfile::tempdir().unwrap();
        let old = d.path().join("2000-01.jsonl");
        std::fs::write(&old, format!("{}{{\"v\":2,\"seq\":2", line(1))).unwrap();
        std::fs::write(d.path().join("2000-02.jsonl"), line(3)).unwrap();
        let dir = d.path().to_path_buf();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let b = read_batch(
                &dir,
                &Pos {
                    file: old,
                    offset: 0,
                },
                500,
                1 << 20,
            );
            let _ = tx.send(b);
        });
        let b = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("read_batch must not spin on an unterminated tail")
            .unwrap();
        assert_eq!(b.lines.len(), 3);
        assert_eq!(&b.lines[1][..], b"{\"v\":2,\"seq\":2");
        assert_eq!(b.last.map(|c| c.seq), Some(3));
        assert_eq!(b.next.file, d.path().join("2000-02.jsonl"));
        assert_eq!(b.next.offset, line(3).len() as u64);
    }

    fn line(seq: u64) -> String {
        format!("{{\"v\":2,\"seq\":{seq},\"ts\":\"x\",\"kind\":\"guard\",\"n\":{seq}}}\n")
    }

    fn month(h: &H, name: &str, seqs: std::ops::RangeInclusive<u64>) {
        let body: String = seqs.map(line).collect();
        std::fs::write(h.audit.join(name), body).unwrap();
    }

    #[tokio::test]
    async fn retention_drop_is_recorded() {
        // At start: the cursor's next seq went with a deleted file.
        let h = H::bare();
        month(&h, "2000-02.jsonl", 11..=20);
        write_cursor(&cursor_path(&h.state, "a"), &at(5)).unwrap();
        let t = MemoryTransport::new((500, 1 << 20));
        let fw = h.forwarders(make_with(t.clone()));
        fw.apply(&one("a")).await;
        until("forwarded", || t.got().len() == 10).await;
        assert_eq!(seqs(&t.got()), (11..=20).collect::<Vec<_>>());
        until("cursor", || h.cursor("a") == Some(20)).await;
        until("connected", || h.host.events().len() == 2).await;
        let recs = lock(&h.host.records).clone();
        assert_eq!(h.host.events(), ["backlog_dropped", "connected"]);
        assert_eq!(recs[0].extra["from_seq"], 6);
        assert_eq!(recs[0].extra["to_seq"], 10);
        fw.stop_all().await;

        // While running: the target is down, retention deletes the file
        // the worker was reading.
        let h = H::bare();
        month(&h, "2000-01.jsonl", 1..=10);
        month(&h, "2000-02.jsonl", 11..=20);
        write_cursor(&cursor_path(&h.state, "a"), &at(5)).unwrap();
        let t = FlakyTransport::new(0);
        t.down.store(true, Ordering::SeqCst);
        let fw = h.forwarders(make_with(t.clone()));
        fw.apply(&one("a")).await;
        until("tried", || t.attempts.load(Ordering::SeqCst) >= 2).await;
        std::fs::remove_file(h.audit.join("2000-01.jsonl")).unwrap();
        // Each retry reads its batch again: the next one finds the file gone.
        until("drop noticed", || {
            h.host.events().contains(&"backlog_dropped".to_string())
        })
        .await;
        t.down.store(false, Ordering::SeqCst);
        until("forwarded", || t.inner.got().len() == 10).await;
        assert_eq!(seqs(&t.inner.got()), (11..=20).collect::<Vec<_>>());
        let events = h.host.events();
        assert_eq!(
            events.iter().filter(|e| *e == "backlog_dropped").count(),
            1,
            "{events:?}"
        );
        let recs = lock(&h.host.records).clone();
        let d = recs
            .iter()
            .find(|r| r.extra["event"] == "backlog_dropped")
            .unwrap();
        assert_eq!(
            (d.extra["from_seq"].clone(), d.extra["to_seq"].clone()),
            (6.into(), 10.into())
        );
        fw.stop_all().await;
    }

    #[tokio::test]
    async fn no_drop_when_the_cursor_file_is_still_there() {
        let h = H::bare();
        month(&h, "2000-01.jsonl", 1..=10);
        month(&h, "2000-02.jsonl", 11..=20);
        write_cursor(&cursor_path(&h.state, "a"), &at(12)).unwrap();
        let t = MemoryTransport::new((3, 1 << 20));
        let fw = h.forwarders(make_with(t.clone()));
        fw.apply(&one("a")).await;
        until("forwarded", || t.got().len() == 8).await;
        assert_eq!(seqs(&t.got()), (13..=20).collect::<Vec<_>>());
        until("connected", || !h.host.events().is_empty()).await;
        assert_eq!(h.host.events(), ["connected"]);
        // A month file written later is followed into.
        month(&h, "2000-03.jsonl", 21..=22);
        until("next month", || t.got().len() == 10).await;
        fw.stop_all().await;
    }

    #[tokio::test]
    async fn reload_adds_and_removes_targets() {
        let h = H::new();
        h.append(3).await;
        let made: Arc<Mutex<BTreeMap<String, Vec<MemoryTransport>>>> = Arc::default();
        let m = Arc::clone(&made);
        let make: MakeTransport = Arc::new(move |name, _| {
            let t = MemoryTransport::new((500, 1 << 20));
            lock(&m)
                .entry(name.to_string())
                .or_default()
                .push(t.clone());
            Ok(Box::new(t) as Box<dyn Transport>)
        });
        let got = |name: &str| -> Vec<Bytes> {
            lock(&made)
                .get(name)
                .map(|v| v.iter().flat_map(|t| t.got()).collect())
                .unwrap_or_default()
        };
        let fw = h.forwarders(make);
        fw.apply(&targets(&["a"])).await;
        assert_eq!(fw.running(), ["a"]);
        until("a forwarded", || !got("a").is_empty()).await;

        fw.apply(&targets(&["a", "b"])).await;
        assert_eq!(fw.running(), ["a", "b"]);
        until("b forwarded", || {
            as_vecs(&got("b")) == h.file_lines() && as_vecs(&got("a")) == h.file_lines()
        })
        .await;

        // `a` is gone: it stops, `b` goes on.
        fw.apply(&targets(&["b"])).await;
        assert_eq!(fw.running(), ["b"]);
        let a_before = got("a").len();
        h.append(5).await;
        until("b caught up", || as_vecs(&got("b")) == h.file_lines()).await;
        assert_eq!(got("a").len(), a_before, "a removed target sends nothing");

        // Unchanged: not restarted. Changed: restarted from its cursor.
        fw.apply(&targets(&["b"])).await;
        assert_eq!(lock(&made)["b"].len(), 1);
        let mut changed = targets(&["b"]);
        changed.insert(
            "b".into(),
            ForwardCfg::File {
                path: PathBuf::from("/y"),
            },
        );
        fw.apply(&changed).await;
        assert_eq!(lock(&made)["b"].len(), 2);
        h.append(2).await;
        // At least once: the restart may send the last batch again.
        until("restarted b caught up", || {
            let g = as_vecs(&got("b"));
            let f = h.file_lines();
            let set: std::collections::BTreeSet<_> = g.iter().cloned().collect();
            g.last() == f.last() && f.iter().all(|l| set.contains(l))
        })
        .await;
        fw.stop_all().await;
        assert!(fw.running().is_empty());
    }

    #[tokio::test]
    async fn fatal_and_unbuildable_targets_are_recorded_and_stop() {
        struct Fatal;
        impl Transport for Fatal {
            fn send<'a>(&'a self, _: &'a [Bytes]) -> SendFuture<'a> {
                Box::pin(async { Err(SendError::Fatal("bad config".into())) })
            }
            fn max_batch(&self) -> (usize, usize) {
                (500, 1 << 20)
            }
        }
        let h = H::new();
        h.append(2).await;
        let fw = h.forwarders(Arc::new(|name, _| {
            if name == "x" {
                Ok(Box::new(Fatal) as Box<dyn Transport>)
            } else {
                Err("cannot build".into())
            }
        }));
        fw.apply(&targets(&["x", "y"])).await;
        until("x stopped", || fw.running().is_empty()).await;
        let recs = lock(&h.host.records).clone();
        assert_eq!(recs.len(), 2);
        for r in &recs {
            assert_eq!(r.extra["event"], "failing");
        }
        // The same config again: not retried, not recorded again.
        fw.apply(&targets(&["x", "y"])).await;
        assert_eq!(lock(&h.host.records).len(), 2);
        fw.stop_all().await;
    }

    #[test]
    fn real_transports_build_for_each_type() {
        let cfgs = [
            ForwardCfg::File {
                path: PathBuf::from("/x"),
            },
            ForwardCfg::Syslog {
                address: "unix:/dev/log".into(),
                format: saiife_policy::SyslogFormat::Rfc5424Json,
                facility: None,
                ca: None,
            },
            ForwardCfg::Syslog {
                address: "tls://[::1]:6514".into(),
                format: saiife_policy::SyslogFormat::Rfc5424,
                facility: Some("local3".into()),
                ca: Some(PathBuf::from("/etc/saiife/ca/x.pem")),
            },
            ForwardCfg::Https {
                url: "https://siem.example.test/in".into(),
                auth_secret: Some("hec".into()),
                format: saiife_policy::HttpsFormat::SplunkHec,
                ca: None,
            },
        ];
        for cfg in &cfgs {
            assert!(transport_for("a", cfg, &Weak::new()).is_ok(), "{cfg:?}");
        }
    }

    #[test]
    fn cursor_garbage_is_an_error_missing_is_none() {
        let d = tempfile::tempdir().unwrap();
        let p = cursor_path(d.path(), "a");
        assert_eq!(read_cursor(&p).unwrap(), None);
        let c = Cursor {
            seq: 42,
            hash: Some(line_hash(b"x")),
        };
        write_cursor(&p, &c).unwrap();
        assert_eq!(read_cursor(&p).unwrap(), Some(c.clone()));
        let body = std::fs::read_to_string(&p).unwrap();
        assert_eq!(body, format!("42 {}\n", c.hash.unwrap()));
        // A bare seq is not a cursor; nor is one without a hash.
        assert!(write_cursor(&p, &Cursor { seq: 7, hash: None }).is_err());
        for junk in ["7\n", "x", "7 nothex", "7 abc", ""] {
            std::fs::write(&p, junk).unwrap();
            assert!(read_cursor(&p).is_err(), "{junk:?}");
        }
        // No temp file is left next to it.
        let names: Vec<_> = std::fs::read_dir(p.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
    }

    #[test]
    fn a_line_without_its_newline_waits() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("2000-01.jsonl");
        std::fs::write(&f, format!("{}{{\"v\":2,\"seq\":2", line(1))).unwrap();
        let b = read_batch(
            d.path(),
            &Pos {
                file: f.clone(),
                offset: 0,
            },
            500,
            1 << 20,
        )
        .unwrap();
        assert_eq!(b.lines.len(), 1);
        assert_eq!(b.last.map(|c| c.seq), Some(1));
        assert_eq!(b.next.offset, line(1).len() as u64);
        // The byte limit: one line longer than it still goes, alone.
        let b = read_batch(d.path(), &Pos { file: f, offset: 0 }, 500, 1).unwrap();
        assert_eq!(b.lines.len(), 1);
    }
}
