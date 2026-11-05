//! Free space on the audit volume (spec §6.2 back-pressure).

use saiife_ipc::msg::ErrorCode;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const CACHE_FOR: Duration = Duration::from_secs(1);

/// `(dir, when, free MB)` of the last `statvfs`.
static CACHE: Mutex<Option<(PathBuf, Instant, u64)>> = Mutex::new(None);

/// Free MB for unprivileged users on the volume of `dir`
/// (`f_bavail * f_frsize`), cached for 1 s.
pub fn free_mb(dir: &Path) -> io::Result<u64> {
    let now = Instant::now();
    let mut c = CACHE.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((d, at, mb)) = c.as_ref() {
        if d == dir && now.duration_since(*at) < CACHE_FOR {
            return Ok(*mb);
        }
    }
    let mb = free_bytes(dir)? / (1024 * 1024);
    *c = Some((dir.to_path_buf(), now, mb));
    Ok(mb)
}

#[cfg(unix)]
fn free_bytes(dir: &Path) -> io::Result<u64> {
    let st = rustix::fs::statvfs(dir)?;
    Ok(st.f_bavail.saturating_mul(st.f_frsize))
}

#[cfg(windows)]
fn free_bytes(dir: &Path) -> io::Result<u64> {
    saiife_win::ffi::process::disk_free_bytes(dir)
}

/// Below the floor, appends from anyone but the daemon itself are refused. `is_own` comes
/// from [`crate::ops::Ctx::is_own`]: on Windows a uid is a label two SIDs can share.
pub fn disk_gate(free_mb: u64, min_free_mb: u64, is_own: bool) -> Result<(), ErrorCode> {
    if free_mb < min_free_mb && !is_own {
        return Err(ErrorCode::LowDisk);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_refuses_only_non_daemon_uids() {
        assert_eq!(disk_gate(100, 512, false), Err(ErrorCode::LowDisk));
        assert_eq!(disk_gate(511, 512, false), Err(ErrorCode::LowDisk));
        assert_eq!(disk_gate(512, 512, false), Ok(()));
        assert_eq!(disk_gate(100, 512, true), Ok(()));
        assert_eq!(disk_gate(0, 512, true), Ok(()));
    }

    #[test]
    fn free_mb_of_a_tempdir_is_cached() {
        let d = tempfile::tempdir().unwrap();
        let a = free_mb(d.path()).unwrap();
        let b = free_mb(d.path()).unwrap();
        assert_eq!(a, b);
    }
}
