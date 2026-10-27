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
//!   last `seq` the target confirmed. It moves only after a confirmed send,
//!   so a crash between the send and the cursor write sends that batch
//!   again: delivery is at least once, and duplicates after a crash or a
//!   reload that changed the target are possible.
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

/// The daemon's transports for `[audit.forward.<name>]`. Task 3 fills this
/// in; until then every type is refused, which the worker records as a
/// `failing` target.
pub fn transport_for(
    name: &str,
    cfg: &ForwardCfg,
    ctx: &Weak<crate::ops::Ctx>,
) -> Result<Box<dyn Transport>, String> {
    let _ = (name, ctx);
    let kind = match cfg {
        ForwardCfg::Syslog { .. } => "syslog",
        ForwardCfg::File { .. } => "file",
        ForwardCfg::Https { .. } => "https",
    };
    Err(format!(
        "forward type `{kind}` is not supported by this build"
    ))
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

/// The cursor's `seq`; `None` when there is no file yet.
pub fn read_cursor(path: &Path) -> Result<Option<u64>, String> {
    let mut s = String::new();
    match std::fs::File::open(path) {
        Ok(f) => {
            f.take(64)
                .read_to_string(&mut s)
                .map_err(|e| format!("{}: {e}", path.display()))?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    }
    s.trim()
        .parse::<u64>()
        .map(Some)
        .map_err(|_| format!("{}: not a seq", path.display()))
}

/// Write the cursor: a 0600 temp file, fsync, rename, fsync of the dir
/// (created 0700 when missing).
pub fn write_cursor(path: &Path, seq: u64) -> io::Result<()> {
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
    let tmp = dir.join(format!(".{name}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let staged = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(format!("{seq}\n").as_bytes())?;
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
    /// The `seq` of the last line in the batch that has one.
    last_seq: Option<u64>,
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

/// The non-blank lines of `body` with the offset just after each.
fn lines_of(body: &[u8]) -> impl Iterator<Item = (&[u8], u64)> {
    let mut at = 0usize;
    std::iter::from_fn(move || loop {
        let rest = &body[at..];
        let end = rest.iter().position(|&b| b == b'\n')?;
        let line = &rest[..end];
        at += end + 1;
        if !blank(line) {
            return Some((line, at as u64));
        }
    })
}

fn read_file(p: &Path) -> Option<Vec<u8>> {
    let mut f = store::open_regular(p)?;
    let mut body = Vec::new();
    f.read_to_end(&mut body).ok()?;
    Some(body)
}

/// Where to go on, and the `(from_seq, to_seq)` retention took if any.
type Located = (Pos, Option<(u64, u64)>);

/// Where to go on after `cursor`: just after the last line (in log order)
/// whose `seq` is at most `cursor`; with no cursor, the start of the
/// oldest file. When no such line is left, the oldest line is where to go
/// on, and `Some((from, to))` names the seqs retention took. `None`: no
/// month file yet.
fn locate(dir: &Path, cursor: Option<u64>) -> Result<Option<Located>, String> {
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
    let mut first_seq = None;
    for f in files.iter().rev() {
        let Some(body) = read_file(f) else {
            continue;
        };
        let mut found = None;
        for (line, end) in lines_of(&body) {
            let Some(s) = seq_of(line) else {
                continue;
            };
            if s <= c {
                found = Some(end);
            }
        }
        if let Some(offset) = found {
            return Ok(Some((
                Pos {
                    file: f.clone(),
                    offset,
                },
                None,
            )));
        }
        // Read newest first: the last file's first seq is the oldest.
        if let Some(s) = first_seq_in(&body) {
            first_seq = Some(s);
        }
    }
    let dropped = first_seq
        .filter(|&s| s > c.saturating_add(1))
        .map(|s| (c + 1, s - 1));
    Ok(Some((start, dropped)))
}

fn first_seq_in(body: &[u8]) -> Option<u64> {
    lines_of(body).find_map(|(l, _)| seq_of(l))
}

/// Read up to `max_n` lines and about `max_bytes` (one longer line goes
/// alone) from `pos` on, into the next month files when this one is done.
/// A line without its `\n` yet is left for later.
fn read_batch(dir: &Path, pos: &Pos, max_n: usize, max_bytes: usize) -> Result<Batch, ReadErr> {
    let mut lines: Vec<Bytes> = Vec::new();
    let mut bytes = 0usize;
    let mut last_seq = None;
    let mut cur = pos.clone();
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
            if n == 0 || buf.last() != Some(&b'\n') {
                break;
            }
            let line = &buf[..n - 1];
            if !blank(line) {
                if !lines.is_empty() && bytes + line.len() > max_bytes {
                    break 'files;
                }
                bytes += line.len();
                if let Some(s) = seq_of(line) {
                    last_seq = Some(s);
                }
                lines.push(Bytes::copy_from_slice(line));
            }
            cur.offset += n as u64;
        }
        // The end of this file: go on in the next one, if there is one. The
        // writer appends to the newest file only, so once a newer file
        // exists this one is complete, but it may have grown since it was
        // read: read it to its end first.
        let files = store::month_files(dir).map_err(ReadErr::Io)?;
        let Some(next) = files
            .into_iter()
            .find(|p| p.file_name() > cur.file.file_name())
        else {
            break;
        };
        let grown = std::fs::symlink_metadata(&cur.file).is_ok_and(|m| m.len() > cur.offset);
        if !grown {
            cur = Pos {
                file: next,
                offset: 0,
            };
        }
    }
    Ok(Batch {
        lines,
        last_seq,
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

struct Worker {
    name: String,
    transport: Box<dyn Transport>,
    audit_dir: PathBuf,
    cursor_path: PathBuf,
    host: Weak<dyn Host>,
    clock: Arc<dyn Clock>,
    appended: watch::Receiver<u64>,
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

    /// Wait for the next append or the poll interval.
    async fn idle(&mut self) {
        let clock = Arc::clone(&self.clock);
        tokio::select! {
            r = self.appended.changed() => {
                if r.is_err() {
                    // The writer is gone: poll only.
                    clock.sleep(POLL).await;
                }
            }
            _ = clock.sleep(POLL) => {}
        }
    }

    async fn save_cursor(&self, seq: u64) {
        let p = self.cursor_path.clone();
        match blocking(move || write_cursor(&p, seq)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => eprintln!(
                "saiife: warning: forward {}: cannot write the cursor: {e}",
                self.name
            ),
            Err(e) => eprintln!("saiife: warning: forward {}: {e}", self.name),
        }
    }

    async fn run(mut self) {
        let p = self.cursor_path.clone();
        let mut cursor = match blocking(move || read_cursor(&p)).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) | Err(e) => {
                // Starting over sends duplicates, never leaves a gap.
                eprintln!(
                    "saiife: warning: forward {}: {e}; sending the whole log again",
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
            if self.host.strong_count() == 0 {
                return;
            }
            let Some(at) = pos.clone() else {
                let dir = self.audit_dir.clone();
                match blocking(move || locate(&dir, cursor)).await {
                    Ok(Ok(Some((p, dropped)))) => {
                        if let Some((from, to)) = dropped {
                            self.record("backlog_dropped", |r| {
                                r.extra.insert("from_seq".into(), from.into());
                                r.extra.insert("to_seq".into(), to.into());
                                r.reason = Some(
                                    "retention deleted records this target had not received".into(),
                                );
                            });
                            cursor = Some(to);
                            self.save_cursor(to).await;
                        }
                        pos = Some(p);
                    }
                    Ok(Ok(None)) => self.idle().await,
                    Ok(Err(e)) | Err(e) => {
                        eprintln!("saiife: warning: forward {}: {e}", self.name);
                        self.idle().await;
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
                    self.idle().await;
                    continue;
                }
            };
            if batch.lines.is_empty() {
                pos = Some(batch.next);
                self.idle().await;
                continue;
            }
            match self.transport.send(&batch.lines).await {
                Ok(()) => {
                    if let Some(s) = batch.last_seq {
                        cursor = Some(s);
                        self.save_cursor(s).await;
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
                    self.clock.sleep(backoff).await;
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

struct Running {
    cfg: ForwardCfg,
    /// `None`: the transport could not be built (recorded once).
    task: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Default)]
struct Inner {
    setup: Option<Setup>,
    running: BTreeMap<String, Running>,
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
    /// target that is gone or changed stops, a new or changed one starts
    /// from its cursor. Needs the runtime. Does nothing before
    /// [`Self::configure`].
    pub fn apply(&self, targets: &BTreeMap<String, ForwardCfg>) {
        let mut g = lock(&self.inner);
        let Inner { setup, running } = &mut *g;
        let Some(setup) = setup.as_ref() else {
            return;
        };
        running.retain(|name, r| {
            let keep = targets.get(name) == Some(&r.cfg);
            if !keep {
                if let Some(t) = &r.task {
                    t.abort();
                }
            }
            keep
        });
        for (name, cfg) in targets {
            if running.contains_key(name) {
                continue;
            }
            let task = match (setup.make)(name, cfg) {
                Ok(transport) => {
                    let w = Worker {
                        name: name.clone(),
                        transport,
                        audit_dir: setup.audit_dir.clone(),
                        cursor_path: cursor_path(&setup.state_dir, name),
                        host: setup.host.clone(),
                        clock: Arc::clone(&setup.clock),
                        appended: setup.appended.clone(),
                    };
                    Some(tokio::spawn(w.run()))
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

    /// Stop every worker (the daemon's stop). The cursors stay.
    pub fn stop_all(&self) {
        let mut g = lock(&self.inner);
        for r in g.running.values() {
            if let Some(t) = &r.task {
                t.abort();
            }
        }
        g.running.clear();
    }

    /// The names of the targets with a running worker.
    pub fn running(&self) -> Vec<String> {
        lock(&self.inner)
            .running
            .iter()
            .filter(|(_, r)| r.task.as_ref().is_some_and(|t| !t.is_finished()))
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
                out.extend(lines_of(&body).map(|(l, _)| l.to_vec()));
            }
            out
        }

        fn cursor(&self, name: &str) -> Option<u64> {
            read_cursor(&cursor_path(&self.state, name)).unwrap()
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
        fw.apply(&one("a"));
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
        fw.stop_all();
    }

    #[tokio::test]
    async fn exact_bytes_forwarded() {
        let h = H::new();
        h.append(5).await;
        let t = MemoryTransport::new((500, 1 << 20));
        let fw = h.forwarders(make_with(t.clone()));
        fw.apply(&one("a"));
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
        fw.stop_all();
    }

    #[tokio::test]
    async fn cursor_survives_restart_no_gap() {
        use std::os::unix::fs::PermissionsExt;
        let h = H::new();
        h.append(20).await;
        let t1 = MemoryTransport::new((500, 1 << 20));
        let fw = h.forwarders(make_with(t1.clone()));
        fw.apply(&one("a"));
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
        fw.stop_all();
        let p = cursor_path(&h.state, "a");
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read_to_string(&p).unwrap(), format!("{last}\n"));

        // Down for a while: the log goes on.
        h.append(30).await;
        let t2 = MemoryTransport::new((500, 1 << 20));
        let fw = h.forwarders(make_with(t2.clone()));
        fw.apply(&one("a"));
        until("second run forwarded", || {
            let mut all = t1.got();
            all.extend(t2.got());
            as_vecs(&all) == h.file_lines()
        })
        .await;
        assert_eq!(seqs(&t2.got())[0], last + 1, "resumes after the cursor");
        fw.stop_all();
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
        fw.apply(&one("a"));
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
        fw.stop_all();
    }

    #[tokio::test]
    async fn failing_recorded_after_30s_recovered_after_success() {
        // Retries at 0, 1, 3, 7, 15 s fail, 31 s works: under 30 s down.
        let h = H::new();
        h.append(3).await;
        let t = FlakyTransport::new(5);
        let fw = h.forwarders(make_with(t.clone()));
        fw.apply(&one("a"));
        until("forwarded", || !t.inner.got().is_empty()).await;
        until("connected", || !h.host.events().is_empty()).await;
        assert_eq!(h.host.events(), ["connected"]);
        fw.stop_all();

        // Six failures: the one at 31 s is past 30 s.
        let h = H::new();
        h.append(3).await;
        let t = FlakyTransport::new(6);
        let fw = h.forwarders(make_with(t.clone()));
        fw.apply(&one("a"));
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
        fw.stop_all();
    }

    #[tokio::test]
    async fn forward_failing_notified_after_5min_once() {
        // Failures at 0, 1, 3, 7, 15, 31, 63, 123, 183, 243 s: not yet 5 min.
        let h = H::new();
        h.append(2).await;
        let t = FlakyTransport::new(10);
        let fw = h.forwarders(make_with(t.clone()));
        fw.apply(&one("a"));
        until("forwarded", || !t.inner.got().is_empty()).await;
        assert!(lock(&h.host.notes).is_empty());
        fw.stop_all();

        // 30 failures: past 5 min at the 11th, one notification only.
        let h = H::new();
        h.append(2).await;
        let t = FlakyTransport::new(30);
        let fw = h.forwarders(make_with(t.clone()));
        fw.apply(&one("a"));
        until("forwarded", || !t.inner.got().is_empty()).await;
        assert_eq!(*lock(&h.host.notes), ["a"]);
        until("recovered", || h.host.events().len() == 2).await;
        assert_eq!(h.host.events(), ["failing", "recovered"]);
        fw.stop_all();
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
        write_cursor(&cursor_path(&h.state, "a"), 5).unwrap();
        let t = MemoryTransport::new((500, 1 << 20));
        let fw = h.forwarders(make_with(t.clone()));
        fw.apply(&one("a"));
        until("forwarded", || t.got().len() == 10).await;
        assert_eq!(seqs(&t.got()), (11..=20).collect::<Vec<_>>());
        until("cursor", || h.cursor("a") == Some(20)).await;
        until("connected", || h.host.events().len() == 2).await;
        let recs = lock(&h.host.records).clone();
        assert_eq!(h.host.events(), ["backlog_dropped", "connected"]);
        assert_eq!(recs[0].extra["from_seq"], 6);
        assert_eq!(recs[0].extra["to_seq"], 10);
        fw.stop_all();

        // While running: the target is down, retention deletes the file
        // the worker was reading.
        let h = H::bare();
        month(&h, "2000-01.jsonl", 1..=10);
        month(&h, "2000-02.jsonl", 11..=20);
        write_cursor(&cursor_path(&h.state, "a"), 5).unwrap();
        let t = FlakyTransport::new(0);
        t.down.store(true, Ordering::SeqCst);
        let fw = h.forwarders(make_with(t.clone()));
        fw.apply(&one("a"));
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
        fw.stop_all();
    }

    #[tokio::test]
    async fn no_drop_when_the_cursor_file_is_still_there() {
        let h = H::bare();
        month(&h, "2000-01.jsonl", 1..=10);
        month(&h, "2000-02.jsonl", 11..=20);
        write_cursor(&cursor_path(&h.state, "a"), 12).unwrap();
        let t = MemoryTransport::new((3, 1 << 20));
        let fw = h.forwarders(make_with(t.clone()));
        fw.apply(&one("a"));
        until("forwarded", || t.got().len() == 8).await;
        assert_eq!(seqs(&t.got()), (13..=20).collect::<Vec<_>>());
        until("connected", || !h.host.events().is_empty()).await;
        assert_eq!(h.host.events(), ["connected"]);
        // A month file written later is followed into.
        month(&h, "2000-03.jsonl", 21..=22);
        until("next month", || t.got().len() == 10).await;
        fw.stop_all();
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
        fw.apply(&targets(&["a"]));
        assert_eq!(fw.running(), ["a"]);
        until("a forwarded", || !got("a").is_empty()).await;

        fw.apply(&targets(&["a", "b"]));
        assert_eq!(fw.running(), ["a", "b"]);
        until("b forwarded", || {
            as_vecs(&got("b")) == h.file_lines() && as_vecs(&got("a")) == h.file_lines()
        })
        .await;

        // `a` is gone: it stops, `b` goes on.
        fw.apply(&targets(&["b"]));
        assert_eq!(fw.running(), ["b"]);
        let a_before = got("a").len();
        h.append(5).await;
        until("b caught up", || as_vecs(&got("b")) == h.file_lines()).await;
        assert_eq!(got("a").len(), a_before, "a removed target sends nothing");

        // Unchanged: not restarted. Changed: restarted from its cursor.
        fw.apply(&targets(&["b"]));
        assert_eq!(lock(&made)["b"].len(), 1);
        let mut changed = targets(&["b"]);
        changed.insert(
            "b".into(),
            ForwardCfg::File {
                path: PathBuf::from("/y"),
            },
        );
        fw.apply(&changed);
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
        fw.stop_all();
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
        fw.apply(&targets(&["x", "y"]));
        until("x stopped", || fw.running().is_empty()).await;
        let recs = lock(&h.host.records).clone();
        assert_eq!(recs.len(), 2);
        for r in &recs {
            assert_eq!(r.extra["event"], "failing");
        }
        // The same config again: not retried, not recorded again.
        fw.apply(&targets(&["x", "y"]));
        assert_eq!(lock(&h.host.records).len(), 2);
        fw.stop_all();
    }

    #[test]
    fn real_transports_wait_for_task_3() {
        for cfg in targets(&["a"]).values() {
            assert!(transport_for("a", cfg, &Weak::new()).is_err());
        }
    }

    #[test]
    fn cursor_garbage_is_an_error_missing_is_none() {
        let d = tempfile::tempdir().unwrap();
        let p = cursor_path(d.path(), "a");
        assert_eq!(read_cursor(&p).unwrap(), None);
        write_cursor(&p, 42).unwrap();
        assert_eq!(read_cursor(&p).unwrap(), Some(42));
        std::fs::write(&p, "x").unwrap();
        assert!(read_cursor(&p).is_err());
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
        assert_eq!(b.last_seq, Some(1));
        assert_eq!(b.next.offset, line(1).len() as u64);
        // The byte limit: one line longer than it still goes, alone.
        let b = read_batch(d.path(), &Pos { file: f, offset: 0 }, 500, 1).unwrap();
        assert_eq!(b.lines.len(), 1);
    }
}
