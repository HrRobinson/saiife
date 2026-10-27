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
//! - Each file written is fsynced after each batch, before the send is
//!   confirmed. A file is opened without following a symlink.
//! - A file that ends without a `\n` (a write cut short before) gets one
//!   first, so the next record starts on a line of its own.

use crate::forwarder::{SendError, SendFuture, Transport};
use bytes::Bytes;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Records per batch.
pub const MAX_RECORDS: usize = 500;
/// Bytes per batch.
pub const MAX_BYTES: usize = 1 << 20;

/// Appends to `<dir>/<host>-YYYY-MM.jsonl`.
#[derive(Debug, Clone)]
pub struct FileTransport {
    dir: PathBuf,
    host: String,
}

impl FileTransport {
    /// `host` is this machine's host id (`saiife_audit::chain::host_id`).
    pub fn new(dir: PathBuf, host: String) -> FileTransport {
        FileTransport { dir, host }
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

fn append(path: &Path, body: &[u8]) -> Result<(), String> {
    let what = |e: std::io::Error| format!("{}: {e}", path.display());
    let mut f = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o640)
        // No symlink; a FIFO planted there does not block the open.
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)
        .map_err(what)?;
    let meta = f.metadata().map_err(what)?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    let len = meta.len();
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

fn write_batch(dir: &Path, host: &str, lines: &[Bytes]) -> Result<(), String> {
    match std::fs::metadata(dir) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => return Err(format!("{} is not a directory", dir.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
                "directory {} does not exist (saiife does not create it)",
                dir.display()
            ))
        }
        Err(e) => return Err(format!("{}: {e}", dir.display())),
    }
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
        append(&dir.join(format!("{host}-{m}.jsonl")), &body)?;
    }
    Ok(())
}

impl Transport for FileTransport {
    fn send<'a>(&'a self, lines: &'a [Bytes]) -> SendFuture<'a> {
        let dir = self.dir.clone();
        let host = self.host.clone();
        let lines = lines.to_vec();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || write_batch(&dir, &host, &lines))
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
        let mut f = OpenOptions::new().append(true).open(&oct).unwrap();
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
}
