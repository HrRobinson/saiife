//! The outbox (plan 47 R47-9, spec §6.5): every request body that leaves
//! for the model is kept here before it is sent, one JSON line per request,
//! in `<blind>/outbox/YYYY-MM.jsonl` (0600 in a 0700 dir). Readable by root
//! and the daemon only. A month's file goes when the whole month is older
//! than the retention.

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{self, BufRead, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// One request as sent.
#[derive(Clone, Serialize, Deserialize)]
pub struct OutboxEntry {
    /// UTC, `YYYY-MM-DDTHH:MM:SS.mmmZ` (its first seven bytes name the file).
    pub ts: String,
    /// The sha256 of `body`, hex.
    pub sha256: String,
    pub uid: u32,
    pub dataset: String,
    pub ask: String,
    /// The exact request body (UTF-8 JSON as a string).
    pub body: String,
}

// The body is the point of the outbox and must not leak through a `{:?}`.
impl std::fmt::Debug for OutboxEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboxEntry")
            .field("ts", &self.ts)
            .field("sha256", &self.sha256)
            .field("uid", &self.uid)
            .field("ask", &self.ask)
            .finish_non_exhaustive()
    }
}

/// The outbox directory.
#[derive(Debug, Clone)]
pub struct Outbox {
    dir: PathBuf,
}

/// `YYYY-MM` at the start of `ts`, as numbers; anything else is no month.
fn month_of(ts: &str) -> Option<(i64, u32)> {
    let b = ts.as_bytes();
    if b.len() < 7 || b[4] != b'-' {
        return None;
    }
    let digits = |s: &[u8]| s.iter().all(u8::is_ascii_digit);
    if !digits(&b[..4]) || !digits(&b[5..7]) {
        return None;
    }
    let y: i64 = ts[..4].parse().ok()?;
    let m: u32 = ts[5..7].parse().ok()?;
    (1..=12).contains(&m).then_some((y, m))
}

/// Days since 1970-01-01 of the civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

impl Outbox {
    pub fn new(dir: PathBuf) -> Outbox {
        Outbox { dir }
    }

    /// Appends `e` to its month's file (`O_APPEND`, never through a link),
    /// then `fsync`s the file (and the dir when the file is new). A failure
    /// of any step is an error: the caller must not send.
    pub fn append(&self, e: &OutboxEntry) -> io::Result<()> {
        let (y, m) = month_of(&e.ts).ok_or_else(|| io::Error::other("the entry has no month"))?;
        let mut line = serde_json::to_vec(e).map_err(io::Error::other)?;
        line.push(b'\n');
        super::private_dir(&self.dir)?;
        let path = self.dir.join(format!("{y:04}-{m:02}.jsonl"));
        let existed = std::fs::symlink_metadata(&path).is_ok();
        let mut f = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&path)?;
        let md = f.metadata()?;
        if !md.is_file() {
            return Err(io::Error::other("the outbox file is not a regular file"));
        }
        if md.mode() & 0o777 != 0o600 {
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(&line)?;
        f.sync_all()?;
        if !existed {
            crate::fsx::sync_dir(&self.dir)?;
        }
        Ok(())
    }

    /// The month files `YYYY-MM.jsonl` of the dir, with their month.
    fn months(&self) -> io::Result<Vec<(i64, u32, PathBuf)>> {
        let rd = match std::fs::read_dir(&self.dir) {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut out = Vec::new();
        for ent in rd {
            let ent = ent?;
            let name = ent.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(stem) = name.strip_suffix(".jsonl") else {
                continue;
            };
            if stem.len() != 7 {
                continue;
            }
            if let Some((y, m)) = month_of(stem) {
                out.push((y, m, ent.path()));
            }
        }
        out.sort();
        Ok(out)
    }

    /// Removes each month file whose whole month ended at least `days` days
    /// before `now`. Returns how many went.
    pub fn purge(&self, now: SystemTime, days: u32) -> io::Result<u32> {
        let secs = match now.duration_since(UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
            Err(_) => return Ok(0),
        };
        let cutoff = secs.div_euclid(86_400) - i64::from(days);
        let mut n = 0;
        for (y, m, path) in self.months()? {
            let (ny, nm) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
            if days_from_civil(ny, nm, 1) <= cutoff {
                std::fs::remove_file(&path)?;
                n += 1;
            }
        }
        if n > 0 {
            crate::fsx::sync_dir(&self.dir)?;
        }
        Ok(n)
    }

    /// The entry whose body has this sha256, if any. A line that does not
    /// parse is skipped (a crash can leave one partial line).
    pub fn find(&self, sha256: &str) -> io::Result<Option<OutboxEntry>> {
        for (_, _, path) in self.months()? {
            let f = open_regular(&path)?;
            for line in io::BufReader::new(f).lines() {
                let line = line?;
                if !line.contains(sha256) {
                    continue;
                }
                if let Ok(e) = serde_json::from_str::<OutboxEntry>(&line) {
                    if e.sha256 == sha256 {
                        return Ok(Some(e));
                    }
                }
            }
        }
        Ok(None)
    }
}

fn open_regular(path: &Path) -> io::Result<std::fs::File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::other("the outbox file is not a regular file"));
    }
    Ok(f)
}
