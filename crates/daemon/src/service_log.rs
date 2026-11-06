//! The daemon's log under the service manager (W10): its stderr, in a dir of its own.
//! A file over the limit moves to `daemon.log.1` at start, replacing the last one. The
//! rename needs the service SID's rights on that dir, which W14's table grants.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

/// Over this, the log moves aside at start.
pub const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;

/// Opens `path` for appending, after moving a file over `max` bytes aside. A log that
/// cannot be moved is still used: losing old lines beats losing new ones.
pub fn open(path: &Path, max: u64) -> io::Result<File> {
    if std::fs::metadata(path).is_ok_and(|m| m.len() > max) {
        let mut old = path.as_os_str().to_owned();
        old.push(".1");
        if let Err(e) = std::fs::rename(path, &old) {
            let f = append(path)?;
            use std::io::Write;
            let mut w = &f;
            let _ = writeln!(w, "saiife: warning: cannot move the log aside: {e}");
            return Ok(f);
        }
    }
    append(path)
}

fn append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn a_small_log_stays_and_is_appended_to() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("daemon.log");
        std::fs::write(&p, b"one\n").unwrap();
        let mut f = open(&p, 100).unwrap();
        f.write_all(b"two\n").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"one\ntwo\n");
        assert!(!d.path().join("daemon.log.1").exists());
    }

    #[test]
    fn a_log_over_the_limit_moves_aside_replacing_the_last_one() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("daemon.log");
        std::fs::write(&p, b"0123456789").unwrap();
        std::fs::write(d.path().join("daemon.log.1"), b"older").unwrap();
        let mut f = open(&p, 9).unwrap();
        f.write_all(b"new\n").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"new\n");
        assert_eq!(
            std::fs::read(d.path().join("daemon.log.1")).unwrap(),
            b"0123456789"
        );
    }

    #[test]
    fn no_log_yet_is_created() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("daemon.log");
        open(&p, MAX_LOG_BYTES).unwrap();
        assert!(p.exists());
    }

    #[test]
    fn the_limit_is_10_mib() {
        assert_eq!(MAX_LOG_BYTES, 10_485_760);
    }
}
