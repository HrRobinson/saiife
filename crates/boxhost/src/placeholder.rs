//! The per-box model placeholder (plan 40, C1, rulings R1/R2).
//!
//! The box holds only this stand-in for the model credential; the gateway's
//! model forwarder checks it in constant time and swaps in the real one. It
//! has the login kind's usual prefix (so a client-side format check passes),
//! `saiife`, and 64 random hex characters. It is not a secret: it only works
//! on that box's own listener.
//!
//! The file lives in the box's record dir (daemon-only, see
//! `layout::record_dir`), never in the runtime dir the VMM shares. Every
//! spawn gets a fresh, never-reused record dir (`claim_id`), so creating the
//! file once per record dir is a fresh placeholder per spawn; no rotation
//! code is needed. Reads treat the dir as hostile: no symlink or FIFO is
//! followed, and only a small regular file of this user is accepted, whose
//! content has the exact shape for the login kind.

use std::io::{self, Read, Write};
use std::path::Path;

use ring::rand::{SecureRandom, SystemRandom};
use rustix::fs::{Mode, OFlags, CWD};
use saiife_boxes::template::Login;

use crate::paths::PLACEHOLDER;

const API_KEY_PREFIX: &str = concat!("sk-", "ant-", "api03-", "saiife");
const SUBSCRIPTION_PREFIX: &str = concat!("sk-", "ant-", "oat01-", "saiife");
const HEX_LEN: usize = 64;
/// More than the longest placeholder plus a newline; anything larger is not ours.
const MAX_FILE_BYTES: u64 = 256;

fn prefix(login: Login) -> &'static str {
    match login {
        Login::ApiKey => API_KEY_PREFIX,
        Login::Subscription => SUBSCRIPTION_PREFIX,
    }
}

/// A new random placeholder for `login`.
pub fn placeholder(login: Login) -> String {
    let mut raw = [0u8; HEX_LEN / 2];
    // A failing system RNG is not recoverable.
    SystemRandom::new()
        .fill(&mut raw)
        .expect("the system random source failed");
    let mut s = String::from(prefix(login));
    for b in raw {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn shaped(login: Login, s: &str) -> bool {
    s.strip_prefix(prefix(login)).is_some_and(|h| {
        h.len() == HEX_LEN && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

fn bad(why: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("the box placeholder file {why}"),
    )
}

/// Read the placeholder back; `None` when the file does not exist.
pub fn read_placeholder(record_dir: &Path, login: Login) -> io::Result<Option<String>> {
    let fd = match rustix::fs::openat(
        CWD,
        record_dir.join(PLACEHOLDER),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let st = rustix::fs::fstat(&fd)?;
    if rustix::fs::FileType::from_raw_mode(st.st_mode) != rustix::fs::FileType::RegularFile
        || st.st_nlink != 1
        || st.st_uid != rustix::process::geteuid().as_raw()
    {
        return Err(bad("is not a plain file of the daemon"));
    }
    if u64::try_from(st.st_size).map_or(true, |n| n > MAX_FILE_BYTES) {
        return Err(bad("is too big"));
    }
    let mut buf = Vec::new();
    std::fs::File::from(fd)
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut buf)?;
    let text = std::str::from_utf8(&buf).map_err(|_| bad("is not text"))?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    if !shaped(login, text) {
        return Err(bad("does not have the placeholder shape for this login"));
    }
    Ok(Some(text.to_string()))
}

/// The box's placeholder: created once (0600, `O_EXCL`), then read back.
/// Losing the create race reads the winner's file.
pub fn read_or_make_placeholder(record_dir: &Path, login: Login) -> io::Result<String> {
    for _ in 0..2 {
        if let Some(p) = read_placeholder(record_dir, login)? {
            return Ok(p);
        }
        let made = rustix::fs::openat(
            CWD,
            record_dir.join(PLACEHOLDER),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        );
        match made {
            Ok(fd) => {
                let p = placeholder(login);
                let mut f = std::fs::File::from(fd);
                f.write_all(p.as_bytes())?;
                f.write_all(b"\n")?;
                f.sync_all()?;
                return Ok(p);
            }
            // The winner's file is there now: read it.
            Err(rustix::io::Errno::EXIST) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(bad("could not be created or read"))
}

/// Whether `got` (a header value from the box) is exactly `expected`, in
/// constant time for equal lengths.
// ring 0.17 marks the function deprecated ("to be removed") but offers no
// replacement; it is the constant-time compare the plan names, and ring is
// pinned, so a removal cannot arrive unnoticed.
#[allow(deprecated)]
pub fn placeholder_matches(expected: &str, got: &[u8]) -> bool {
    ring::constant_time::verify_slices_are_equal(expected.as_bytes(), got).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn placeholder_shape() {
        for login in [Login::ApiKey, Login::Subscription] {
            let a = placeholder(login);
            let b = placeholder(login);
            assert_ne!(a, b);
            assert!(shaped(login, &a));
            assert_eq!(a.len(), prefix(login).len() + 64);
        }
        assert!(placeholder(Login::ApiKey).starts_with(concat!("sk-", "ant-", "api03-")));
        assert!(placeholder(Login::Subscription).starts_with(concat!("sk-", "ant-", "oat01-")));
        assert!(!shaped(Login::ApiKey, &placeholder(Login::Subscription)));
    }

    #[test]
    fn placeholder_file_is_created_once() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(read_placeholder(d.path(), Login::ApiKey).unwrap(), None);
        let a = read_or_make_placeholder(d.path(), Login::ApiKey).unwrap();
        let b = read_or_make_placeholder(d.path(), Login::ApiKey).unwrap();
        assert_eq!(a, b);
        assert_eq!(
            read_placeholder(d.path(), Login::ApiKey).unwrap(),
            Some(a.clone())
        );
        let m = std::fs::metadata(d.path().join(PLACEHOLDER)).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o600);
        // Another box (dir) gets another one.
        let d2 = tempfile::tempdir().unwrap();
        assert_ne!(
            read_or_make_placeholder(d2.path(), Login::ApiKey).unwrap(),
            a
        );
    }

    #[test]
    fn placeholder_matches_rules() {
        let e = placeholder(Login::ApiKey);
        assert!(placeholder_matches(&e, e.as_bytes()));
        let mut off = e.clone().into_bytes();
        *off.last_mut().unwrap() ^= 1;
        assert!(!placeholder_matches(&e, &off));
        assert!(!placeholder_matches(&e, &e.as_bytes()[..e.len() - 1]));
        let mut longer = e.clone().into_bytes();
        longer.push(b'0');
        assert!(!placeholder_matches(&e, &longer));
        assert!(!placeholder_matches(&e, b""));
    }

    #[test]
    fn hostile_files_are_refused() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join(PLACEHOLDER);
        // A symlink is not followed.
        std::fs::write(d.path().join("x"), placeholder(Login::ApiKey)).unwrap();
        std::os::unix::fs::symlink(d.path().join("x"), &f).unwrap();
        assert!(read_placeholder(d.path(), Login::ApiKey).is_err());
        assert!(read_or_make_placeholder(d.path(), Login::ApiKey).is_err());
        std::fs::remove_file(&f).unwrap();
        // Wrong shape, wrong login, too big, a directory.
        std::fs::write(&f, "not a placeholder\n").unwrap();
        assert!(read_placeholder(d.path(), Login::ApiKey).is_err());
        std::fs::write(&f, placeholder(Login::Subscription)).unwrap();
        assert!(read_placeholder(d.path(), Login::ApiKey).is_err());
        std::fs::write(&f, "a".repeat(10_000)).unwrap();
        assert!(read_placeholder(d.path(), Login::ApiKey).is_err());
        std::fs::remove_file(&f).unwrap();
        std::fs::create_dir(&f).unwrap();
        assert!(read_placeholder(d.path(), Login::ApiKey).is_err());
    }
}
