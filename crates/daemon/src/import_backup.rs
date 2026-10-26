//! Backups of the files `saiife secret import` rewrites (spec §6.6): the
//! original bytes go to `<state>/state/import-backup/<UTC ts>-<sanitized
//! path>`, 0600 in a 0700 dir owned by the daemon user, and are purged
//! after 7 days (at start and daily). A backup is a secret too: its bytes
//! are never logged, echoed or put in a record.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How long a backup is kept.
pub const KEEP: Duration = Duration::from_secs(7 * 24 * 3600);
/// The longest sanitized source path in a backup's name.
pub const MAX_NAME_PATH: usize = 200;
/// The largest source a backup takes (it travels base64 in one frame).
pub const MAX_BACKUP_BYTES: usize = 700 * 1024;

/// The backup dir below the daemon's state dir.
pub fn dir_in(state_dir: &Path) -> PathBuf {
    state_dir.join("state").join("import-backup")
}

/// The clock. Test seam, debug builds only: `SAIIFE_DAEMON_NOW` (Unix
/// seconds) replaces it.
pub fn now() -> SystemTime {
    #[cfg(debug_assertions)]
    if let Some(s) = std::env::var("SAIIFE_DAEMON_NOW")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        return UNIX_EPOCH + Duration::from_secs(s);
    }
    SystemTime::now()
}

/// `[A-Za-z0-9._-]`, every other byte (`/` included) as `_`, cut at
/// [`MAX_NAME_PATH`] bytes.
pub fn sanitize(source: &str) -> String {
    source
        .bytes()
        .take(MAX_NAME_PATH)
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-') {
                b as char
            } else {
                '_'
            }
        })
        .collect()
}

/// `20261026T101112.123Z`.
fn stamp(t: SystemTime) -> String {
    const F: &[time::format_description::FormatItem<'static>] = time::macros::format_description!(
        "[year][month][day]T[hour][minute][second].[subsecond digits:3]Z"
    );
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    time::OffsetDateTime::from_unix_timestamp_nanos(d.as_nanos() as i128)
        .ok()
        .and_then(|o| o.format(F).ok())
        .unwrap_or_else(|| "00000000T000000.000Z".into())
}

/// The dir, created 0700 when missing; a symlink or a non-dir is refused.
fn ensure_dir(dir: &Path) -> io::Result<()> {
    DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    let m = fs::symlink_metadata(dir)?;
    if !m.file_type().is_dir() {
        return Err(io::Error::other("the backup dir is not a directory"));
    }
    if m.permissions().mode() & 0o777 != 0o700 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Writes `bytes` as a new backup of `source`, 0600 and synced. Returns
/// its path. A partly written file is removed.
pub fn write(dir: &Path, t: SystemTime, source: &str, bytes: &[u8]) -> io::Result<PathBuf> {
    ensure_dir(dir)?;
    let base = format!("{}-{}", stamp(t), sanitize(source));
    let mut last = None;
    for n in 0..100u32 {
        let name = if n == 0 {
            base.clone()
        } else {
            format!("{base}-{n}")
        };
        let path = dir.join(name);
        let f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&path);
        match f {
            Ok(mut f) => {
                let done = f.write_all(bytes).and_then(|()| f.sync_all());
                if let Err(e) = done {
                    drop(f);
                    let _ = fs::remove_file(&path);
                    return Err(e);
                }
                File::open(dir)?.sync_all()?;
                return Ok(path);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("no free backup name")))
}

/// Removes the regular files in `dir` last modified more than [`KEEP`]
/// before `t`. Returns how many went. A missing dir is no error.
pub fn purge(dir: &Path, t: SystemTime) -> usize {
    let Ok(rd) = fs::read_dir(dir) else {
        return 0;
    };
    let mut n = 0;
    for e in rd.flatten() {
        let Ok(m) = fs::symlink_metadata(e.path()) else {
            continue;
        };
        if !m.file_type().is_file() {
            continue;
        }
        let old = m
            .modified()
            .ok()
            .and_then(|mt| t.duration_since(mt).ok())
            .is_some_and(|age| age > KEEP);
        if old && fs::remove_file(e.path()).is_ok() {
            n += 1;
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn tmp() -> tempfile::TempDir {
        let dir = std::env::var_os("SAIIFE_TEST_TMP")
            .map(PathBuf::from)
            .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp"));
        fs::create_dir_all(&dir).unwrap();
        tempfile::tempdir_in(dir).unwrap()
    }

    #[test]
    fn sanitize_maps_and_caps() {
        assert_eq!(
            sanitize("/home/al ice/.env;rm"),
            "_home_al_ice_.env_rm".to_string()
        );
        assert_eq!(sanitize("../../etc"), ".._.._etc");
        assert_eq!(sanitize(&"x".repeat(500)).len(), MAX_NAME_PATH);
        assert_eq!(sanitize("é").len(), 2);
    }

    #[test]
    fn write_is_0600_in_a_0700_dir_and_never_overwrites() {
        let t = tmp();
        let dir = dir_in(t.path());
        let at = UNIX_EPOCH + Duration::from_secs(1_793_000_000);
        let a = write(&dir, at, "/h/.env", b"A=1\n").unwrap();
        let b = write(&dir, at, "/h/.env", b"B=2\n").unwrap();
        assert_ne!(a, b);
        assert_eq!(fs::read(&a).unwrap(), b"A=1\n");
        assert_eq!(fs::read(&b).unwrap(), b"B=2\n");
        assert_eq!(fs::metadata(&a).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        let name = a.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.ends_with("Z-_h_.env"), "{name}");
    }

    #[test]
    fn purge_keeps_seven_days_with_an_injected_clock() {
        let t = tmp();
        let dir = dir_in(t.path());
        let p = write(&dir, SystemTime::now(), "/h/.env", b"x").unwrap();
        let day = Duration::from_secs(24 * 3600);
        assert_eq!(purge(&dir, SystemTime::now() + 6 * day), 0);
        assert!(p.exists());
        assert_eq!(purge(&dir, SystemTime::now() + 8 * day), 1);
        assert!(!p.exists());
        assert_eq!(purge(&t.path().join("missing"), SystemTime::now()), 0);
    }
}
