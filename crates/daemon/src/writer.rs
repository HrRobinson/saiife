//! The single audit writer (spec §4.1): one dedicated thread owns the
//! `ChainWriter`, fed by a bounded channel. One writer means records are
//! ordered and the chain needs no lock; file IO stays off the runtime.

use saiife_audit::sign::AuditKey;
use saiife_audit::{ChainWriter, Record};
use saiife_policy::Fsync;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{oneshot, watch};

/// Jobs queued before the writer refuses more.
pub const QUEUE: usize = 1024;
/// How long a stop waits for room in a full queue.
pub const STOP_SEND_WAIT: Duration = Duration::from_secs(5);
/// The writer wakes at least this often (interval checkpoints, fsync).
const TICK: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy)]
pub struct WriterConfig {
    pub checkpoint_every: u64,
    pub checkpoint_interval: Duration,
    pub fsync: Fsync,
}

/// What the writer last saw, for `status`.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub chain: Option<String>,
    pub head: Option<(u64, String)>,
    pub last_checkpoint_seq: Option<u64>,
    /// `sync()` calls so far (a test hook for the fsync mode).
    pub syncs: u64,
}

type Reply<T> = oneshot::Sender<Result<T, String>>;

pub enum Job {
    Append {
        rec: Box<Record>,
        reply: Reply<u64>,
    },
    Checkpoint {
        reply: Reply<Option<u64>>,
    },
    /// Rotate to a fresh key saved at `key_path`; answers `(seq, fingerprint)`.
    RotateKey {
        key_path: PathBuf,
        reply: Reply<(u64, String)>,
    },
    /// Append `rec` (the stop record) if any, checkpoint, sync, and exit.
    Stop {
        rec: Option<Box<Record>>,
        reply: Reply<()>,
    },
}

#[derive(Debug, Clone)]
pub struct WriterHandle {
    tx: SyncSender<Job>,
    state: Arc<Mutex<Snapshot>>,
    /// Closed when the writer thread ends (its sender is dropped then,
    /// also when the thread unwinds from a panic).
    alive: watch::Receiver<()>,
    /// The head `seq`, changed after each write (the forwarder's wake-up).
    appended: watch::Receiver<u64>,
}

impl WriterHandle {
    async fn send<T>(&self, make: impl FnOnce(Reply<T>) -> Job) -> Result<T, String> {
        let (reply, rx) = oneshot::channel();
        match self.tx.try_send(make(reply)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return Err("the audit writer queue is full".into()),
            Err(TrySendError::Disconnected(_)) => return Err("the audit writer has stopped".into()),
        }
        rx.await
            .unwrap_or_else(|_| Err("the audit writer has stopped".into()))
    }

    /// Append `rec` to the chain; the `seq` it got.
    pub async fn append(&self, rec: Record) -> Result<u64, String> {
        self.send(|reply| Job::Append {
            rec: Box::new(rec),
            reply,
        })
        .await
    }

    pub async fn checkpoint(&self) -> Result<Option<u64>, String> {
        self.send(|reply| Job::Checkpoint { reply }).await
    }

    pub async fn rotate_key(&self, key_path: PathBuf) -> Result<(u64, String), String> {
        self.send(|reply| Job::RotateKey { key_path, reply }).await
    }

    /// Stop the writer. Unlike the other jobs this one waits for room in a
    /// full queue (at most `STOP_SEND_WAIT`, off the runtime), so the stop
    /// record is not lost behind a burst of appends.
    pub async fn stop(&self, rec: Option<Record>) -> Result<(), String> {
        let (reply, rx) = oneshot::channel();
        let job = Job::Stop {
            rec: rec.map(Box::new),
            reply,
        };
        let tx = self.tx.clone();
        let sent = tokio::task::spawn_blocking(move || send_within(&tx, job, STOP_SEND_WAIT))
            .await
            .unwrap_or_else(|e| Err(format!("stop: {e}")));
        sent?;
        rx.await
            .unwrap_or_else(|_| Err("the audit writer has stopped".into()))
    }

    /// Resolves once the writer thread has ended, however it ended.
    pub async fn exited(&self) {
        let mut rx = self.alive.clone();
        while rx.changed().await.is_ok() {}
    }

    /// Changes after each record the writer puts in the log (its value is
    /// the head `seq`); the forwarder waits on it instead of polling only.
    pub fn appends(&self) -> watch::Receiver<u64> {
        self.appended.clone()
    }

    pub fn snapshot(&self) -> Snapshot {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

/// `try_send` until `job` fits or `limit` passes (`SyncSender` has no
/// stable `send_timeout`).
fn send_within(tx: &SyncSender<Job>, mut job: Job, limit: Duration) -> Result<(), String> {
    let end = Instant::now() + limit;
    loop {
        match tx.try_send(job) {
            Ok(()) => return Ok(()),
            Err(TrySendError::Disconnected(_)) => return Err("the audit writer has stopped".into()),
            Err(TrySendError::Full(j)) => {
                if Instant::now() >= end {
                    return Err("the audit writer queue stayed full".into());
                }
                job = j;
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

/// Start the writer thread on `cw`. `last_checkpoint` is the newest
/// checkpoint `seq` already in the log, for `status`.
pub fn spawn(
    cw: ChainWriter,
    cfg: WriterConfig,
    last_checkpoint: Option<u64>,
) -> std::io::Result<(WriterHandle, std::thread::JoinHandle<()>)> {
    let (tx, rx) = sync_channel(QUEUE);
    let state = Arc::new(Mutex::new(Snapshot {
        last_checkpoint_seq: last_checkpoint,
        ..Snapshot::default()
    }));
    let (appended_tx, appended) = watch::channel(0);
    let w = Writer {
        cw,
        cfg,
        appended: appended_tx,
        state: Arc::clone(&state),
        last_checkpoint_at: Instant::now(),
        unsynced: false,
        last_sync: Instant::now(),
    };
    w.publish();
    let (alive_tx, alive) = watch::channel(());
    let join = std::thread::Builder::new()
        .name("saiife-audit-writer".into())
        .spawn(move || {
            // Dropped when the thread ends or unwinds: `exited` resolves.
            let _alive = alive_tx;
            w.run(rx)
        })?;
    Ok((
        WriterHandle {
            tx,
            state,
            alive,
            appended,
        },
        join,
    ))
}

struct Writer {
    cw: ChainWriter,
    cfg: WriterConfig,
    appended: watch::Sender<u64>,
    state: Arc<Mutex<Snapshot>>,
    last_checkpoint_at: Instant,
    /// Writes not yet synced (fsync = "checkpoint").
    unsynced: bool,
    last_sync: Instant,
}

impl Writer {
    fn run(mut self, rx: Receiver<Job>) {
        loop {
            match rx.recv_timeout(self.next_wake()) {
                Ok(Job::Stop { rec, reply }) => {
                    let _ = reply.send(self.stop(rec));
                    return;
                }
                Ok(job) => self.handle(job),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    if let Err(e) = self.sync() {
                        eprintln!("saiifed: warning: audit sync failed: {e}");
                    }
                    return;
                }
            }
            self.housekeeping();
        }
    }

    fn handle(&mut self, job: Job) {
        match job {
            Job::Append { rec, reply } => {
                let r = self.append(*rec);
                let _ = reply.send(r);
                if self.cw.records_since_checkpoint() >= self.cfg.checkpoint_every.max(1) {
                    self.checkpoint_logged();
                }
            }
            Job::Checkpoint { reply } => {
                let _ = reply.send(self.checkpoint());
            }
            Job::RotateKey { key_path, reply } => {
                let _ = reply.send(self.rotate_key(&key_path));
            }
            Job::Stop { .. } => unreachable!("handled by run"),
        }
    }

    /// How long to wait for the next job: at most a tick, less when an
    /// interval checkpoint falls due sooner.
    fn next_wake(&self) -> Duration {
        let mut wait = TICK;
        if self.cw.records_since_checkpoint() > 0 {
            let due = self.last_checkpoint_at + self.cfg.checkpoint_interval;
            wait = wait.min(due.saturating_duration_since(Instant::now()));
        }
        wait.max(Duration::from_millis(5))
    }

    /// Interval checkpoint, and the 1 s fsync of `fsync = "checkpoint"`.
    fn housekeeping(&mut self) {
        let now = Instant::now();
        if self.cw.records_since_checkpoint() > 0
            && now.duration_since(self.last_checkpoint_at) >= self.cfg.checkpoint_interval
        {
            self.checkpoint_logged();
        }
        if self.unsynced && now.duration_since(self.last_sync) >= TICK {
            if let Err(e) = self.sync() {
                eprintln!("saiifed: warning: audit sync failed: {e}");
            }
        }
    }

    fn append(&mut self, rec: Record) -> Result<u64, String> {
        // Test seam, debug builds only: the writer dies on a guard record.
        #[cfg(debug_assertions)]
        if rec.kind() == "guard"
            && std::env::var_os("SAIIFE_DAEMON_FAULT").is_some_and(|v| v == "writer_panic")
        {
            panic!("SAIIFE_DAEMON_FAULT=writer_panic");
        }
        let r = self.cw.append(rec);
        self.publish();
        let seq = r.map_err(|e| format!("audit write failed: {e}"))?;
        self.written()?;
        Ok(seq)
    }

    /// After a write: `fsync = "always"` syncs before the ack.
    fn written(&mut self) -> Result<(), String> {
        self.unsynced = true;
        if self.cfg.fsync == Fsync::Always {
            self.sync().map_err(|e| format!("audit sync failed: {e}"))?;
        }
        Ok(())
    }

    fn sync(&mut self) -> std::io::Result<()> {
        self.cw.sync()?;
        self.unsynced = false;
        self.last_sync = Instant::now();
        self.state.lock().unwrap_or_else(|p| p.into_inner()).syncs += 1;
        Ok(())
    }

    fn checkpoint(&mut self) -> Result<Option<u64>, String> {
        self.last_checkpoint_at = Instant::now();
        let r = self.cw.checkpoint(time::OffsetDateTime::now_utc());
        self.publish();
        let seq = r.map_err(|e| format!("audit checkpoint failed: {e}"))?;
        if let Some(seq) = seq {
            self.state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .last_checkpoint_seq = Some(seq);
            // Both fsync modes sync at a checkpoint.
            self.sync().map_err(|e| format!("audit sync failed: {e}"))?;
        }
        Ok(seq)
    }

    fn checkpoint_logged(&mut self) {
        if let Err(e) = self.checkpoint() {
            eprintln!("saiifed: warning: {e}");
        }
    }

    /// Rotate the signing key. Order matters: the new key is saved to a
    /// pending file first, then the `key_rotate` record (signed by the old
    /// key) is written and synced, and only then is the pending file renamed
    /// over the key file. Renaming first would let a crash between the
    /// rename and the record leave a key on disk the chain does not name,
    /// and the next start would write an unsigned `key_rotate` for it. If
    /// the record cannot be written, the pending file is removed and the
    /// old key stays in force on disk and in the chain.
    fn rotate_key(&mut self, key_path: &Path) -> Result<(u64, String), String> {
        let new = AuditKey::generate().map_err(|e| format!("cannot generate a key: {e}"))?;
        let fp = new.fingerprint();
        let pending = pending_key_path(key_path);
        AuditKey::save_new(&pending, &new).map_err(|e| e.to_string())?;
        let r = self.cw.rotate_key(new);
        self.publish();
        let seq = match r {
            Ok(seq) => seq,
            Err(e) => {
                let _ = std::fs::remove_file(&pending);
                return Err(format!("key rotation record failed, old key kept: {e}"));
            }
        };
        // The record is written: the chain now names the new key, so the
        // rename is attempted even when the sync fails (both are reported).
        self.unsynced = true;
        let synced = self.sync();
        let renamed = std::fs::rename(&pending, key_path);
        let mut problems = Vec::new();
        if let Err(e) = synced {
            problems.push(format!("audit sync after key rotation failed: {e}"));
        }
        if let Err(e) = renamed {
            problems.push(format!(
                "{} could not be renamed to {}: {e}",
                pending.display(),
                key_path.display()
            ));
        }
        if !problems.is_empty() {
            return Err(format!(
                "key_rotate written (seq {seq}), but {}",
                problems.join("; ")
            ));
        }
        if let Some(parent) = key_path.parent() {
            if let Ok(d) = std::fs::File::open(parent) {
                let _ = d.sync_all();
            }
        }
        Ok((seq, fp))
    }

    /// The stop sequence: the stop record, a checkpoint, a sync.
    fn stop(&mut self, rec: Option<Box<Record>>) -> Result<(), String> {
        let mut first_err = None;
        if let Some(rec) = rec {
            if let Err(e) = self.append(*rec) {
                first_err.get_or_insert(e);
            }
        }
        if let Err(e) = self.checkpoint() {
            first_err.get_or_insert(e);
        }
        if let Err(e) = self.sync() {
            first_err.get_or_insert(format!("audit sync failed: {e}"));
        }
        first_err.map_or(Ok(()), Err)
    }

    fn publish(&self) {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        s.chain = self.cw.chain_id().map(str::to_string);
        s.head = self.cw.head().map(|(n, h)| (n, h.to_string()));
        drop(s);
        // The line is in the file (one `write_all`) before this: a woken
        // reader finds it.
        if let Some((seq, _)) = self.cw.head() {
            self.appended.send_if_modified(|v| {
                let new = *v != seq;
                *v = seq;
                new
            });
        }
    }
}

/// `<dir>/.<name>.rotating`: where a new key waits for its `key_rotate`.
pub fn pending_key_path(key_path: &Path) -> PathBuf {
    let name = key_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    key_path.with_file_name(format!(".{name}.rotating"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use saiife_audit::chain::ChainWriter;
    use saiife_audit::{DecisionKind, NewRecord, WriterOptions};

    fn rec(i: usize) -> Record {
        let input = format!("echo {i}");
        let mut r = Record::new(
            NewRecord {
                agent: "claude",
                project: "/p",
                session: None,
                tool: "Bash",
                input: &input,
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

    fn open(dir: &Path) -> ChainWriter {
        ChainWriter::open(
            dir,
            WriterOptions {
                mode: "locked".into(),
                saiife: "test".into(),
                key: Some(AuditKey::generate().unwrap()),
            },
        )
        .unwrap()
    }

    fn kinds(dir: &Path) -> Vec<String> {
        let mut out = Vec::new();
        let mut files: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
            .collect();
        files.sort();
        for f in files {
            for l in std::fs::read_to_string(f).unwrap().lines() {
                let v: serde_json::Value = serde_json::from_str(l).unwrap();
                out.push(v["kind"].as_str().unwrap_or("guard").to_string());
            }
        }
        out
    }

    fn run_appends(dir: &Path, fsync: Fsync, n: usize) -> Snapshot {
        let cfg = WriterConfig {
            checkpoint_every: 5,
            checkpoint_interval: Duration::from_secs(3600),
            fsync,
        };
        let (h, join) = spawn(open(dir), cfg, None).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let mut seqs = Vec::new();
        for i in 0..n {
            seqs.push(rt.block_on(h.append(rec(i))).unwrap());
        }
        let mut sorted = seqs.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), n);
        let snap = h.snapshot();
        drop(h);
        join.join().unwrap();
        snap
    }

    #[test]
    fn checkpoint_after_every_n() {
        let d = tempfile::tempdir().unwrap();
        let snap = run_appends(d.path(), Fsync::Always, 12);
        let k = kinds(d.path());
        assert_eq!(k.iter().filter(|k| *k == "checkpoint").count(), 2, "{k:?}");
        assert_eq!(k.iter().filter(|k| *k == "guard").count(), 12);
        // fsync = "always": one sync per write before its ack (12 appends
        // and the 2 checkpoints).
        assert_eq!(snap.syncs, 14);
        let r = saiife_audit::verify(d.path());
        assert!(r.breaks.is_empty(), "{:?}", r.breaks);
        assert_eq!(r.checkpoints, 2);
        assert_eq!(snap.last_checkpoint_seq, r.last_checkpoint.map(|c| c.0));
    }

    #[test]
    fn fsync_checkpoint_syncs_at_checkpoints_not_per_append() {
        let d = tempfile::tempdir().unwrap();
        let snap = run_appends(d.path(), Fsync::Checkpoint, 12);
        assert!(
            (2..12).contains(&snap.syncs),
            "syncs {} should be per checkpoint (and tick), not per append",
            snap.syncs
        );
    }

    /// `exited` stays pending while the thread runs and resolves once it
    /// ends, however it ends (I4).
    #[test]
    fn exited_resolves_when_the_thread_ends() {
        let d = tempfile::tempdir().unwrap();
        let cfg = WriterConfig {
            checkpoint_every: 1000,
            checkpoint_interval: Duration::from_secs(3600),
            fsync: Fsync::Checkpoint,
        };
        let (h, join) = spawn(open(d.path()), cfg, None).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let short = Duration::from_millis(100);
        assert!(rt
            .block_on(async { tokio::time::timeout(short, h.exited()).await })
            .is_err());
        rt.block_on(h.stop(None)).unwrap();
        join.join().unwrap();
        rt.block_on(async { tokio::time::timeout(Duration::from_secs(1), h.exited()).await })
            .expect("exited must resolve after the thread ended");
    }

    #[test]
    fn stop_writes_record_checkpoint_and_exits() {
        let d = tempfile::tempdir().unwrap();
        let cfg = WriterConfig {
            checkpoint_every: 1000,
            checkpoint_interval: Duration::from_secs(3600),
            fsync: Fsync::Checkpoint,
        };
        let (h, join) = spawn(open(d.path()), cfg, None).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(h.append(rec(0))).unwrap();
        let mut stop = rec(1);
        stop.kind = Some("daemon".into());
        stop.extra.insert("event".into(), "stop".into());
        rt.block_on(h.stop(Some(stop))).unwrap();
        join.join().unwrap();
        let k = kinds(d.path());
        assert_eq!(k[k.len() - 2..], ["daemon", "checkpoint"]);
        // A job after stop is refused, not lost silently.
        assert!(rt.block_on(h.append(rec(2))).is_err());
    }

    #[test]
    fn stop_waits_for_room_in_a_full_queue() {
        let d = tempfile::tempdir().unwrap();
        let cfg = WriterConfig {
            checkpoint_every: 100_000,
            checkpoint_interval: Duration::from_secs(3600),
            fsync: Fsync::Checkpoint,
        };
        let (h, join) = spawn(open(d.path()), cfg, None).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // Fill the queue without waiting for answers.
        let mut pending = Vec::new();
        for i in 0..QUEUE * 2 {
            let (reply, rx) = oneshot::channel();
            if h.tx
                .try_send(Job::Append {
                    rec: Box::new(rec(i)),
                    reply,
                })
                .is_ok()
            {
                pending.push(rx);
            }
        }
        let mut stop = rec(0);
        stop.kind = Some("daemon".into());
        stop.extra.insert("event".into(), "stop".into());
        rt.block_on(h.stop(Some(stop))).unwrap();
        join.join().unwrap();
        let k = kinds(d.path());
        assert_eq!(k[k.len() - 2..], ["daemon", "checkpoint"]);
    }

    #[test]
    fn rotate_key_saves_key_after_record() {
        let d = tempfile::tempdir().unwrap();
        let audit = d.path().join("audit");
        let key_path = d.path().join("keys/audit.ed25519");
        let (old, _) = AuditKey::load_or_create(&key_path).unwrap();
        let cw = ChainWriter::open(
            &audit,
            WriterOptions {
                mode: "locked".into(),
                saiife: "test".into(),
                key: Some(old),
            },
        )
        .unwrap();
        let cfg = WriterConfig {
            checkpoint_every: 1000,
            checkpoint_interval: Duration::from_secs(3600),
            fsync: Fsync::Checkpoint,
        };
        let (h, join) = spawn(cw, cfg, None).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(h.append(rec(0))).unwrap();
        let (seq, fp) = rt.block_on(h.rotate_key(key_path.clone())).unwrap();
        assert!(seq >= 2);
        let (on_disk, created) = AuditKey::load_or_create(&key_path).unwrap();
        assert!(!created);
        assert_eq!(on_disk.fingerprint(), fp);
        rt.block_on(h.checkpoint()).unwrap();
        drop(h);
        join.join().unwrap();
        let r = saiife_audit::verify(&audit);
        assert!(r.breaks.is_empty(), "{:?}", r.breaks);
        assert_eq!(r.key.as_deref(), Some(fp.as_str()));
        // No temp key file is left next to it.
        let names: Vec<String> = std::fs::read_dir(d.path().join("keys"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["audit.ed25519"]);
    }
}
