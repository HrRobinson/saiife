//! The `file` forwarding target (plan 12 decision 4): each record's exact
//! line is appended to `<path>/<host id>-YYYY-MM.jsonl`, opened append-only.
//!
//! - The month is the record's own (`ts`), as in the local month files, so
//!   the copy's files mirror the local ones. A line without a readable `ts`
//!   goes to the month of the line before it in the batch, else the
//!   current month.
//! - The directory must exist: saiife never creates it (a share that is not
//!   mounted must not fill the local disk instead). A missing directory is
//!   a failing target, retried with backoff.
//! - The directory is opened without following a symlink (its last
//!   component) and refused when group or others may write to it, unless it
//!   has the sticky bit. Month files are opened relative to it (`openat`),
//!   without following a symlink and without blocking on a FIFO, and
//!   refused unless they are regular files with one link, owned by the
//!   daemon's user: a file someone planted (a hard link to another file, a
//!   file of another user) is never written to.
//! - Each file written is fsynced after each batch, and the directory after
//!   a month file was created, before the send is confirmed.
//! - A file that ends without a `\n` (a write cut short before) gets one
//!   first, so the next record starts on a line of its own.
//! - A write that hangs (a dead NFS server) keeps its thread; until it ends,
//!   every send is a retry ("previous write still running") and no second
//!   write is started. The worker's own send timeout turns the hang into a
//!   failing target.

use crate::forwarder::{SendError, SendFuture, Transport};
use bytes::Bytes;
use rustix::fs::{Mode, OFlags};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Records per batch.
pub const MAX_RECORDS: usize = 500;
/// Bytes per batch.
pub const MAX_BYTES: usize = 1 << 20;

/// Appends to `<dir>/<host>-YYYY-MM.jsonl`.
pub struct FileTransport {
    dir: PathBuf,
    host: String,
    /// The owner a month file must have: the daemon's effective uid.
    owner: u32,
    /// A blocking write is running (possibly hung).
    busy: Arc<AtomicBool>,
    /// Test seam: runs in the blocking write before anything else.
    #[cfg(test)]
    before_write: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl std::fmt::Debug for FileTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileTransport")
            .field("dir", &self.dir)
            .field("host", &self.host)
            .finish()
    }
}

impl FileTransport {
    /// `host` is this machine's host id (`saiife_audit::chain::host_id`).
    pub fn new(dir: PathBuf, host: String) -> FileTransport {
        FileTransport {
            dir,
            host,
            owner: rustix::process::geteuid().as_raw(),
            busy: Arc::default(),
            #[cfg(test)]
            before_write: None,
        }
    }
}

/// `YYYY-MM` of a line's `ts`, if it has a well-formed one.
fn month_of(line: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Ts {
        ts: Option<String>,
    }
    let ts = serde_json::from_slice::<Ts>(line).ok()?.ts?;
    let m = ts.get(..7)?;
    let b = m.as_bytes();
    let ok = b[..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[5..].iter().all(u8::is_ascii_digit)
        && matches!(
            &m[5..],
            "01" | "02" | "03" | "04" | "05" | "06" | "07" | "08" | "09" | "10" | "11" | "12"
        );
    ok.then(|| m.to_string())
}

fn this_month() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!("{:04}-{:02}", now.year(), u8::from(now.month()))
}

/// The target directory: no symlink, not writable by group or others
/// unless sticky.
fn open_dir(dir: &Path) -> Result<OwnedFd, String> {
    let fd = rustix::fs::open(
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| match e {
        rustix::io::Errno::NOENT => format!(
            "directory {} does not exist (saiife does not create it)",
            dir.display()
        ),
        rustix::io::Errno::NOTDIR | rustix::io::Errno::LOOP => format!(
            "{} is not a directory (a symlink is not followed)",
            dir.display()
        ),
        e => format!("{}: {e}", dir.display()),
    })?;
    let st = rustix::fs::fstat(&fd).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mode = st.st_mode;
    if mode & 0o022 != 0 && mode & 0o1000 == 0 {
        return Err(format!(
            "directory {} is writable by group or others without the sticky bit; refused",
            dir.display()
        ));
    }
    Ok(fd)
}

/// Opens `name` in `dir` for appending, creating it (then fsyncing `dir`)
/// when it is not there. Refuses anything but a regular file with one link
/// owned by `owner`.
fn open_month(
    dir: &OwnedFd,
    dir_path: &Path,
    name: &str,
    owner: u32,
) -> Result<std::fs::File, String> {
    let path = dir_path.join(name);
    let what = |e: rustix::io::Errno| format!("{}: {e}", path.display());
    // No symlink; a FIFO planted there does not block the open.
    let flags =
        OFlags::RDWR | OFlags::APPEND | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let mut created = false;
    let fd = loop {
        match rustix::fs::openat(dir, name, flags, Mode::empty()) {
            Ok(fd) => break fd,
            Err(rustix::io::Errno::NOENT) => {}
            Err(e) => return Err(what(e)),
        }
        match rustix::fs::openat(
            dir,
            name,
            flags | OFlags::CREATE | OFlags::EXCL,
            Mode::from_raw_mode(0o640),
        ) {
            Ok(fd) => {
                created = true;
                break fd;
            }
            // Created by someone else in between: open that one (and judge it).
            Err(rustix::io::Errno::EXIST) => continue,
            Err(e) => return Err(what(e)),
        }
    };
    let st = rustix::fs::fstat(&fd).map_err(what)?;
    if st.st_mode & 0o170000 != 0o100000 {
        return Err(format!("{} is not a regular file; refused", path.display()));
    }
    if st.st_nlink > 1 {
        return Err(format!(
            "{} has {} hard links (a planted file?); refused",
            path.display(),
            st.st_nlink
        ));
    }
    if st.st_uid != owner {
        return Err(format!(
            "{} is owned by uid {}, not {owner} (a planted file?); refused",
            path.display(),
            st.st_uid
        ));
    }
    if created {
        rustix::fs::fsync(dir.as_fd()).map_err(|e| format!("{}: {e}", dir_path.display()))?;
    }
    Ok(std::fs::File::from(fd))
}

fn append(mut f: std::fs::File, path: &Path, body: &[u8]) -> Result<(), String> {
    let what = |e: std::io::Error| format!("{}: {e}", path.display());
    let len = f.metadata().map_err(what)?.len();
    let mut out = Vec::with_capacity(body.len() + 1);
    if len > 0 {
        let mut last = [0u8; 1];
        f.seek(SeekFrom::Start(len - 1)).map_err(what)?;
        f.read_exact(&mut last).map_err(what)?;
        if last[0] != b'\n' {
            out.push(b'\n');
        }
    }
    out.extend_from_slice(body);
    f.write_all(&out).map_err(what)?;
    f.sync_all().map_err(what)
}

fn write_batch(dir: &Path, host: &str, owner: u32, lines: &[Bytes]) -> Result<(), String> {
    let dfd = open_dir(dir)?;
    // Consecutive runs of one month, in order; each file fsynced once.
    let mut month: Option<String> = None;
    let mut runs: Vec<(String, Vec<u8>)> = Vec::new();
    for line in lines {
        let m = month_of(line)
            .or_else(|| month.clone())
            .unwrap_or_else(this_month);
        match runs.last_mut() {
            Some((rm, body)) if *rm == m => {
                body.extend_from_slice(line);
                body.push(b'\n');
            }
            _ => {
                let mut body = line.to_vec();
                body.push(b'\n');
                runs.push((m.clone(), body));
            }
        }
        month = Some(m);
    }
    for (m, body) in runs {
        let name = format!("{host}-{m}.jsonl");
        let f = open_month(&dfd, dir, &name, owner)?;
        append(f, &dir.join(&name), &body)?;
    }
    Ok(())
}

/// Clears the busy flag when the blocking write ends, however it ends.
struct Busy(Arc<AtomicBool>);

impl Drop for Busy {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl Transport for FileTransport {
    fn send<'a>(&'a self, lines: &'a [Bytes]) -> SendFuture<'a> {
        Box::pin(async move {
            if self.busy.swap(true, Ordering::SeqCst) {
                return Err(SendError::Retry(format!(
                    "{}: previous write still running",
                    self.dir.display()
                )));
            }
            let busy = Busy(Arc::clone(&self.busy));
            let dir = self.dir.clone();
            let host = self.host.clone();
            let owner = self.owner;
            let lines = lines.to_vec();
            #[cfg(test)]
            let before = self.before_write.clone();
            // The flag goes with the blocking task: if this future is
            // dropped (a timeout), the write still counts as running.
            tokio::task::spawn_blocking(move || {
                let _busy = busy;
                #[cfg(test)]
                if let Some(f) = before {
                    f();
                }
                write_batch(&dir, &host, owner, &lines)
            })
            .await
            .map_err(|e| SendError::Retry(format!("file target: {e}")))?
            .map_err(SendError::Retry)
        })
    }

    fn max_batch(&self) -> (usize, usize) {
        (MAX_RECORDS, MAX_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(seq: u64, ts: &str) -> Bytes {
        Bytes::from(format!(
            r#"{{"v":1,"seq":{seq},"ts":"{ts}","kind":"guard","input":"a \"q\" ü"}}"#
        ))
    }

    #[tokio::test]
    async fn file_target_per_host_month_append_fsync() {
        let d = tempfile::tempdir().unwrap();
        let t = FileTransport::new(d.path().to_path_buf(), "abc123".into());
        assert_eq!(t.max_batch(), (500, 1 << 20));
        let a = line(1, "2026-09-30T23:59:59.999Z");
        let b = line(2, "2026-10-01T00:00:00.000Z");
        // A line without a ts follows the month of the line before it.
        let c = Bytes::from_static(b"{\"note\":\"no ts\"}");
        t.send(&[a.clone(), b.clone(), c.clone()]).await.unwrap();
        let sep = std::fs::read(d.path().join("abc123-2026-09.jsonl")).unwrap();
        assert_eq!(sep, [&a[..], b"\n"].concat());
        let oct = d.path().join("abc123-2026-10.jsonl");
        assert_eq!(
            std::fs::read(&oct).unwrap(),
            [&b[..], b"\n", &c[..], b"\n"].concat()
        );
        // Appends, never truncates; a cut-short last line is ended first.
        let mut f = std::fs::OpenOptions::new().append(true).open(&oct).unwrap();
        f.write_all(b"{\"cut\":").unwrap();
        drop(f);
        let e = line(3, "2026-10-02T00:00:00.000Z");
        t.send(std::slice::from_ref(&e)).await.unwrap();
        assert_eq!(
            std::fs::read(&oct).unwrap(),
            [&b[..], b"\n", &c[..], b"\n{\"cut\":\n", &e[..], b"\n"].concat()
        );
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&oct).unwrap().permissions(),
        );
        assert_eq!(mode & 0o007, 0, "not readable by others");
        // The copy is what verify --external reads.
        let names: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names.len(), 2, "{names:?}");
    }

    #[tokio::test]
    async fn file_target_missing_dir_is_failing_not_created() {
        let d = tempfile::tempdir().unwrap();
        let gone = d.path().join("share");
        let t = FileTransport::new(gone.clone(), "h".into());
        let err = t
            .send(&[line(1, "2026-10-01T00:00:00.000Z")])
            .await
            .unwrap_err();
        assert!(
            matches!(&err, SendError::Retry(w) if w.contains("does not exist")),
            "{err:?}"
        );
        assert!(!gone.exists());
        // Once it is there (the share is mounted), the same target delivers.
        std::fs::create_dir(&gone).unwrap();
        t.send(&[line(1, "2026-10-01T00:00:00.000Z")])
            .await
            .unwrap();
        assert!(gone.join("h-2026-10.jsonl").exists());
    }

    #[tokio::test]
    async fn file_target_refuses_a_symlinked_month_file() {
        let d = tempfile::tempdir().unwrap();
        let elsewhere = d.path().join("elsewhere");
        std::fs::write(&elsewhere, b"").unwrap();
        let share = d.path().join("share");
        std::fs::create_dir(&share).unwrap();
        std::os::unix::fs::symlink(&elsewhere, share.join("h-2026-10.jsonl")).unwrap();
        let t = FileTransport::new(share, "h".into());
        assert!(t
            .send(&[line(1, "2026-10-01T00:00:00.000Z")])
            .await
            .is_err());
        assert_eq!(std::fs::read(&elsewhere).unwrap(), b"");
    }
    fn one() -> Bytes {
        line(1, "2026-10-01T00:00:00.000Z")
    }

    #[tokio::test]
    async fn file_target_refuses_a_planted_hard_link() {
        let d = tempfile::tempdir().unwrap();
        let share = d.path().join("share");
        std::fs::create_dir(&share).unwrap();
        let victim = d.path().join("victim");
        std::fs::write(&victim, b"keep\n").unwrap();
        std::fs::hard_link(&victim, share.join("h-2026-10.jsonl")).unwrap();
        let t = FileTransport::new(share, "h".into());
        let err = t.send(&[one()]).await.unwrap_err();
        assert!(
            matches!(&err, SendError::Retry(w) if w.contains("hard links")),
            "{err:?}"
        );
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep\n");
    }

    #[tokio::test]
    async fn file_target_refuses_a_file_of_another_owner() {
        // Not root: a foreign-owned file cannot be made, so the expected
        // owner is moved instead.
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("h-2026-10.jsonl"), b"").unwrap();
        let mut t = FileTransport::new(d.path().to_path_buf(), "h".into());
        t.owner = t.owner.wrapping_add(1);
        let err = t.send(&[one()]).await.unwrap_err();
        assert!(
            matches!(&err, SendError::Retry(w) if w.contains("owned by uid")),
            "{err:?}"
        );
        assert_eq!(
            std::fs::read(d.path().join("h-2026-10.jsonl")).unwrap(),
            b""
        );
    }

    #[tokio::test]
    async fn file_target_refuses_a_world_writable_dir_without_sticky() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let share = d.path().join("share");
        std::fs::create_dir(&share).unwrap();
        let t = FileTransport::new(share.clone(), "h".into());
        for (mode, ok) in [
            (0o777, false),
            (0o770, false),
            (0o1777, true),
            (0o755, true),
        ] {
            std::fs::set_permissions(&share, std::fs::Permissions::from_mode(mode)).unwrap();
            let r = t.send(&[one()]).await;
            assert_eq!(r.is_ok(), ok, "{mode:o}: {r:?}");
            if !ok {
                assert!(
                    matches!(&r, Err(SendError::Retry(w)) if w.contains("sticky")),
                    "{r:?}"
                );
            }
        }
        // A symlink to the directory is not followed.
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&share, &link).unwrap();
        let t = FileTransport::new(link, "h".into());
        assert!(t.send(&[one()]).await.is_err());
    }

    #[tokio::test]
    async fn file_target_hung_write_blocks_the_next_one() {
        let d = tempfile::tempdir().unwrap();
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let rx = std::sync::Mutex::new(rx);
        let mut t = FileTransport::new(d.path().to_path_buf(), "h".into());
        let first = Arc::new(AtomicBool::new(true));
        t.before_write = Some(Arc::new(move || {
            if first.swap(false, Ordering::SeqCst) {
                let _ = rx.lock().unwrap().recv();
            }
        }));
        // The worker gives up on the hung send (its timeout drops it).
        let r = tokio::time::timeout(std::time::Duration::from_millis(100), t.send(&[one()])).await;
        assert!(r.is_err(), "the first write hangs");
        let err = t.send(&[one()]).await.unwrap_err();
        assert!(
            matches!(&err, SendError::Retry(w) if w.contains("previous write still running")),
            "{err:?}"
        );
        // Once it ends, writing goes on.
        tx.send(()).unwrap();
        let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match t.send(&[one()]).await {
                Ok(()) => break,
                Err(e) => assert!(std::time::Instant::now() < end, "{e:?}"),
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }
}
