//! The box vault (S3, ruling R18): a daemon-owned directory no VMM can write.
//! Personal: `<state>/box-vault` (0700, created here when missing). Locked:
//! `/var/lib/saiife-box/vault` (saiife:saiife-box 2750, made by the install).
//! Per box: `<id>.marker` and `<id>.snap/` (the verified snapshot, see
//! `crate::snapshot`) and `<id>.pid` (the liveness record, ruling R19).

use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use saiife_wire::source::BoxId;
use serde::{Deserialize, Serialize};

const MAX_RECORD: u64 = 4096;
const MAX_PROC_STAT: u64 = 4096;

pub fn marker_path(vault: &Path, id: &BoxId) -> PathBuf {
    vault.join(format!("{}.marker", id.as_str()))
}

pub fn snap_dir(vault: &Path, id: &BoxId) -> PathBuf {
    vault.join(format!("{}.snap", id.as_str()))
}

pub fn pid_path(vault: &Path, id: &BoxId) -> PathBuf {
    vault.join(format!("{}.pid", id.as_str()))
}

pub fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Create the vault 0700 when missing; refuse one that is a symlink, not a
/// directory, or not owned by this process's euid.
pub fn ensure(vault: &Path) -> Result<(), String> {
    if std::fs::symlink_metadata(vault).is_err() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(vault)
            .map_err(|e| format!("box vault {}: {e}", vault.display()))?;
    }
    let m = std::fs::symlink_metadata(vault)
        .map_err(|e| format!("box vault {}: {e}", vault.display()))?;
    if !m.file_type().is_dir() {
        return Err(format!(
            "box vault {} is not a directory (or is a symlink)",
            vault.display()
        ));
    }
    if m.uid() != euid() {
        return Err(format!(
            "box vault {} is not owned by this user",
            vault.display()
        ));
    }
    Ok(())
}

/// A regular file of at most `cap` bytes, opened without following links or
/// blocking.
pub fn read_bounded(p: &Path, cap: u64) -> Result<Vec<u8>, String> {
    let name = p
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    let flags = (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(p)
        .map_err(|e| format!("{name}: {e}"))?;
    let m = f.metadata().map_err(|e| format!("{name}: {e}"))?;
    if !m.file_type().is_file() {
        return Err(format!("{name}: not a regular file"));
    }
    if m.len() > cap {
        return Err(format!("{name}: larger than {cap} bytes"));
    }
    let mut buf = Vec::new();
    f.take(cap + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("{name}: {e}"))?;
    if buf.len() as u64 > cap {
        return Err(format!("{name}: larger than {cap} bytes"));
    }
    Ok(buf)
}

/// `body` to `dest` through `<dest>.tmp` (0600, O_NOFOLLOW, fsync, rename).
pub fn write_atomic(dest: &Path, body: &[u8]) -> Result<(), String> {
    let mut tmp = dest.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let _ = std::fs::remove_file(&tmp);
    let write = || -> std::io::Result<()> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&tmp)?;
        f.write_all(body)?;
        f.sync_all()?;
        std::fs::rename(&tmp, dest)
    };
    write().map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("{}: {e}", dest.display())
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PidRecord {
    pub pid: u32,
    /// Field 22 of `/proc/<pid>/stat`: tells a reused pid from ours.
    pub starttime: u64,
}

/// Field 22 (`starttime`) of a `/proc/<pid>/stat` line. The `comm` field is
/// in parentheses and may itself contain `)` and spaces, so fields are
/// counted from the last `)`.
pub fn parse_starttime(stat: &str) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    // after comm: field 3 (state) is index 0, so field 22 is index 19
    rest.split_ascii_whitespace().nth(19)?.parse().ok()
}

/// The start time of a live (or not yet reaped) process. `Ok(None)`: no
/// such process. `Err`: it may exist but cannot be read.
pub fn proc_starttime(pid: u32) -> Result<Option<u64>, String> {
    let p = PathBuf::from(format!("/proc/{pid}/stat"));
    match std::fs::symlink_metadata(&p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("/proc/{pid}/stat: {e}")),
        Ok(_) => {}
    }
    let mut f = match std::fs::File::open(&p) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("/proc/{pid}/stat: {e}")),
    };
    let mut buf = Vec::new();
    (&mut f)
        .take(MAX_PROC_STAT)
        .read_to_end(&mut buf)
        .map_err(|e| format!("/proc/{pid}/stat: {e}"))?;
    let s = String::from_utf8_lossy(&buf);
    parse_starttime(&s)
        .map(Some)
        .ok_or_else(|| format!("/proc/{pid}/stat: no start time"))
}

pub fn write_pid(vault: &Path, id: &BoxId, rec: PidRecord) -> Result<(), String> {
    ensure(vault)?;
    let body = serde_json::to_vec(&rec).map_err(|e| e.to_string())?;
    write_atomic(&pid_path(vault, id), &body)
}

/// Written before the spawn (L2): a daemon that dies between the spawn and
/// `write_pid` leaves this, which reads as alive (fail closed) until the
/// owner confirms no VMM runs and removes it.
pub fn write_starting(vault: &Path, id: &BoxId) -> Result<(), String> {
    ensure(vault)?;
    write_atomic(&pid_path(vault, id), br#"{"starting":true}"#)
}

pub fn remove_pid(vault: &Path, id: &BoxId) {
    let _ = std::fs::remove_file(pid_path(vault, id));
}

/// Liveness from the record (ruling R19): `None` when there is no record;
/// `Some(true)` when its process is gone (no such pid, or a pid reused by a
/// process with another start time); `Some(false)` when it is alive, or
/// when anything is unreadable or inconsistent, or a `starting` record
/// has no pid yet (fail closed).
pub fn pid_exited(vault: &Path, id: &BoxId) -> Option<bool> {
    let p = pid_path(vault, id);
    match std::fs::symlink_metadata(&p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(_) => return Some(false),
        Ok(_) => {}
    }
    let Ok(raw) = read_bounded(&p, MAX_RECORD) else {
        return Some(false);
    };
    let Ok(rec) = serde_json::from_slice::<PidRecord>(&raw) else {
        return Some(false);
    };
    match proc_starttime(rec.pid) {
        Ok(None) => Some(true),
        Ok(Some(t)) => Some(t != rec.starttime),
        Err(_) => Some(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir_in(
            std::env::var_os("SAIIFE_TEST_TMP")
                .unwrap_or_else(|| "/".into())
                .as_os_str(),
        )
        .unwrap()
    }

    #[test]
    fn ensure_creates_0700_and_refuses_a_symlink() {
        use std::os::unix::fs::PermissionsExt;
        let t = tmp();
        let v = t.path().join("vault");
        ensure(&v).unwrap();
        let mode = std::fs::metadata(&v).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        ensure(&v).unwrap();
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&v, &link).unwrap();
        assert!(ensure(&link).unwrap_err().contains("symlink"));
        let file = t.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        assert!(ensure(&file).is_err());
    }

    #[test]
    #[cfg_attr(not(target_os = "linux"), ignore = "reads /proc")]
    fn own_process_is_alive_by_its_start_time() {
        let t = tmp();
        let v = t.path().join("vault");
        let id = BoxId::parse("b1").unwrap();
        assert_eq!(pid_exited(&v, &id), None);
        let me = std::process::id();
        let st = proc_starttime(me).unwrap().unwrap();
        write_pid(
            &v,
            &id,
            PidRecord {
                pid: me,
                starttime: st,
            },
        )
        .unwrap();
        assert_eq!(pid_exited(&v, &id), Some(false));
        write_pid(
            &v,
            &id,
            PidRecord {
                pid: me,
                starttime: st + 1,
            },
        )
        .unwrap();
        assert_eq!(pid_exited(&v, &id), Some(true));
        std::fs::write(pid_path(&v, &id), b"{").unwrap();
        assert_eq!(pid_exited(&v, &id), Some(false));
        write_starting(&v, &id).unwrap();
        assert_eq!(pid_exited(&v, &id), Some(false), "starting: fail closed");
        remove_pid(&v, &id);
        assert_eq!(pid_exited(&v, &id), None);
    }
}
