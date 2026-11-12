//! The `saiife` side of `saiife-fido/1` (plan 41, Linux): check the helper
//! file (F2), run it, read its hello, send one request and wait for one
//! answer, bounded in time (F4) and in bytes (F1). No printing: the CLI
//! words every `HelperError`.

use std::io::{BufReader, Read, Write};
use std::path::{Component, Path};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::helper::read_line;
use crate::proto::{decode, encode, Answer, Hello, Request, MAX_LINE, PROTO};

/// The hello must come this soon after the spawn.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// After its answer (or a closed stdin) the helper has this long to exit.
pub const EXIT_GRACE: Duration = Duration::from_secs(2);
/// The bytes of the helper's stderr kept (the rest is read and dropped).
pub const STDERR_KEEP: usize = 4096;
/// Answer field caps, in bytes (else `Protocol`).
pub const MAX_CREDENTIAL_ID: usize = 1023;
pub const AUTH_DATA: std::ops::RangeInclusive<usize> = 37..=4096;
pub const MAX_SIGNATURE: usize = 512;

/// Why the helper gave no usable answer. `stderr` is the kept stderr, raw:
/// the CLI shows its first line, sanitized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperError {
    /// No file at the path: no helper installed.
    Missing,
    /// The file or a directory above it fails F2; the text says why.
    Unsafe(String),
    /// The exec failed.
    Spawn(String),
    /// No hello: it exited (`exit`), or sent none within `HELLO_TIMEOUT`
    /// (`exit: None`, killed).
    NoHello { exit: Option<i32>, stderr: String },
    /// Another protocol or version (a mixed install).
    Skew { proto: u32, version: String },
    /// No answer within the caller's limit (killed).
    Timeout,
    /// A line too long, not JSON, of the wrong shape, or over a field cap.
    Protocol(String),
    /// It exited without an answer, or did not exit within `EXIT_GRACE` of
    /// it (killed, `exit: None`).
    Exited { exit: Option<i32>, stderr: String },
}

/// F2: `path` is a regular file owned by `owner_uid`, not writable by group
/// or others, not setuid or setgid, executable; every directory above it up
/// to and including `trusted_root` is a real directory (not a symlink)
/// owned by `owner_uid` and not writable by group or others. `Missing` when
/// nothing is at `path`.
pub fn check_helper(path: &Path, owner_uid: u32, trusted_root: &Path) -> Result<(), HelperError> {
    use std::os::unix::fs::MetadataExt;
    if !plain(path) || !plain(trusted_root) {
        return Err(HelperError::Unsafe("not a plain absolute path".into()));
    }
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(HelperError::Missing),
        Err(e) => return Err(HelperError::Unsafe(format!("cannot inspect it: {e}"))),
    };
    let ft = meta.file_type();
    let mode = meta.mode();
    let why = if ft.is_symlink() {
        Some("a symlink".to_string())
    } else if !ft.is_file() {
        Some("not a regular file".to_string())
    } else if meta.uid() != owner_uid {
        Some(format!("owned by uid {}, not {owner_uid}", meta.uid()))
    } else if mode & 0o022 != 0 {
        Some("writable by group or others".to_string())
    } else if mode & 0o6000 != 0 {
        Some("setuid or setgid".to_string())
    } else if mode & 0o111 == 0 {
        Some("not executable".to_string())
    } else {
        None
    };
    if let Some(why) = why {
        return Err(HelperError::Unsafe(why));
    }
    if !path.starts_with(trusted_root) || path == trusted_root {
        return Err(HelperError::Unsafe(format!(
            "not under {}",
            trusted_root.display()
        )));
    }
    let mut dir = path.parent();
    while let Some(d) = dir {
        let shown = d.display();
        let meta = std::fs::symlink_metadata(d)
            .map_err(|e| HelperError::Unsafe(format!("cannot inspect {shown}: {e}")))?;
        let why = if meta.file_type().is_symlink() {
            Some(format!("{shown} is a symlink"))
        } else if !meta.is_dir() {
            Some(format!("{shown} is not a directory"))
        } else if meta.uid() != owner_uid {
            Some(format!(
                "{shown} is owned by uid {}, not {owner_uid}",
                meta.uid()
            ))
        } else if meta.mode() & 0o022 != 0 {
            Some(format!("{shown} is writable by group or others"))
        } else {
            None
        };
        if let Some(why) = why {
            return Err(HelperError::Unsafe(why));
        }
        if d == trusted_root {
            return Ok(());
        }
        dir = d.parent();
    }
    // `path` starts with `trusted_root`: the loop met it.
    Err(HelperError::Unsafe(format!(
        "not under {}",
        trusted_root.display()
    )))
}

/// One line read from the helper's stdout, or why reading stopped.
type Line = Result<Zeroizing<Vec<u8>>, String>;

/// A running helper: its stdin, a thread that sends its stdout lines, and
/// one that keeps the first `STDERR_KEEP` bytes of its stderr.
pub struct Running {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    lines: Receiver<Line>,
    stderr: Arc<Mutex<Vec<u8>>>,
    stderr_done: Receiver<()>,
}

impl Running {
    /// Runs `path` with no arguments, an empty environment and `/` as its
    /// directory, and reads its hello within `HELLO_TIMEOUT`. A hello of
    /// another protocol or version is `Skew` (the helper's stdin is closed
    /// first, so it exits without touching the key). Any device count is
    /// given back: D2 is the caller's.
    pub fn start(path: &Path) -> Result<(Running, Hello), HelperError> {
        let mut child = Command::new(path)
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| HelperError::Spawn(e.to_string()))?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let errout = child.stderr.take();

        let (tx, lines) = mpsc::channel::<Line>();
        if let Some(out) = stdout {
            std::thread::spawn(move || {
                let mut r = BufReader::new(out);
                loop {
                    match read_line(&mut r) {
                        Ok(None) => return,
                        Ok(Some(l)) if l.len() > MAX_LINE => {
                            let _ = tx.send(Err("line too long".into()));
                            return;
                        }
                        Ok(Some(l)) => {
                            if tx.send(Ok(l)).is_err() {
                                return;
                            }
                        }
                        Err(e) => {
                            let _ = tx.send(Err(format!("cannot read: {e}")));
                            return;
                        }
                    }
                }
            });
        }
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let (done_tx, stderr_done) = mpsc::channel();
        if let Some(mut err) = errout {
            let keep = Arc::clone(&stderr);
            std::thread::spawn(move || {
                let mut buf = [0u8; 1024];
                loop {
                    match err.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let mut k = keep.lock().unwrap_or_else(|p| p.into_inner());
                            let room = STDERR_KEEP.saturating_sub(k.len());
                            k.extend_from_slice(&buf[..n.min(room)]);
                        }
                    }
                }
                let _ = done_tx.send(());
            });
        }
        let mut run = Running {
            child: Some(child),
            stdin,
            lines,
            stderr,
            stderr_done,
        };

        let hello = match run.lines.recv_timeout(HELLO_TIMEOUT) {
            Ok(Ok(line)) => match decode::<Answer>(&line) {
                Ok(Answer::Hello(h)) => h,
                Ok(_) => {
                    run.kill();
                    return Err(HelperError::Protocol("no hello first".into()));
                }
                Err(why) => {
                    run.kill();
                    return Err(HelperError::Protocol(why));
                }
            },
            Ok(Err(why)) => {
                run.kill();
                return Err(HelperError::Protocol(why));
            }
            Err(RecvTimeoutError::Timeout) => {
                run.kill();
                return Err(HelperError::NoHello {
                    exit: None,
                    stderr: run.stderr_text(),
                });
            }
            Err(RecvTimeoutError::Disconnected) => {
                let exit = run.reap(EXIT_GRACE);
                return Err(HelperError::NoHello {
                    exit,
                    stderr: run.stderr_text(),
                });
            }
        };
        if hello.proto != PROTO || hello.version != env!("CARGO_PKG_VERSION") {
            run.close();
            return Err(HelperError::Skew {
                proto: hello.proto,
                version: hello.version,
            });
        }
        Ok((run, hello))
    }

    /// Sends `req` and waits at most `limit` for the answer. Past the limit
    /// the helper is killed (`Timeout`). After the answer it has
    /// `EXIT_GRACE` to exit, or it is killed and the answer is dropped
    /// (`Exited { exit: None }`).
    pub fn call(mut self, req: &Request, limit: Duration) -> Result<Answer, HelperError> {
        if let Some(mut stdin) = self.stdin.take() {
            let line = encode(req);
            // A helper that has exited is seen below, through its stdout.
            let _ = stdin.write_all(&line).and_then(|()| stdin.flush());
            // One request: closing stdin is the helper's EOF.
            drop(stdin);
        }
        let answer = match self.lines.recv_timeout(limit) {
            Ok(Ok(line)) => match decode::<Answer>(&line) {
                Ok(a) => a,
                Err(why) => {
                    self.kill();
                    return Err(HelperError::Protocol(why));
                }
            },
            Ok(Err(why)) => {
                self.kill();
                return Err(HelperError::Protocol(why));
            }
            Err(RecvTimeoutError::Timeout) => {
                self.kill();
                return Err(HelperError::Timeout);
            }
            Err(RecvTimeoutError::Disconnected) => {
                let exit = self.reap(EXIT_GRACE);
                return Err(HelperError::Exited {
                    exit,
                    stderr: self.stderr_text(),
                });
            }
        };
        if let Err(why) = caps(&answer) {
            self.kill();
            return Err(HelperError::Protocol(why));
        }
        match self.reap(EXIT_GRACE) {
            Some(_) => Ok(answer),
            // Killed at the grace: no answer is taken from a helper that
            // does not behave.
            None => Err(HelperError::Exited {
                exit: None,
                stderr: self.stderr_text(),
            }),
        }
    }

    /// Closes stdin (the helper exits without a request), waits
    /// `EXIT_GRACE`, kills it if needed.
    pub fn close(mut self) {
        drop(self.stdin.take());
        self.reap(EXIT_GRACE);
    }

    /// Waits up to `grace` for the child to exit, then kills and reaps it.
    /// Its exit code, or `None` when killed (or ended by a signal).
    fn reap(&mut self, grace: Duration) -> Option<i32> {
        let mut child = self.child.take()?;
        let end = Instant::now() + grace;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return status.code(),
                Ok(None) if Instant::now() < end => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                _ => {
                    // Our own child: the only signal sent.
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
            }
        }
    }

    /// Kills and reaps the child now.
    fn kill(&mut self) {
        drop(self.stdin.take());
        self.reap(Duration::ZERO);
    }

    /// The kept stderr, once the pipe ended (or after a short wait: a
    /// grandchild may hold it open).
    fn stderr_text(&self) -> String {
        let _ = self.stderr_done.recv_timeout(Duration::from_millis(500));
        let k = self.stderr.lock().unwrap_or_else(|p| p.into_inner());
        String::from_utf8_lossy(&k).into_owned()
    }
}

impl Drop for Running {
    /// A `Running` never outlives its child: dropped unused (a panic, an
    /// early return), the helper is killed and reaped.
    fn drop(&mut self) {
        self.kill();
    }
}

/// The answer field caps.
fn caps(a: &Answer) -> Result<(), String> {
    match a {
        Answer::Assertion {
            credential_id,
            auth_data,
            signature,
        } => {
            if credential_id.len() > MAX_CREDENTIAL_ID {
                return Err("credential_id too long".into());
            }
            if !AUTH_DATA.contains(&auth_data.len()) {
                return Err("auth_data of a bad length".into());
            }
            if signature.len() > MAX_SIGNATURE {
                return Err("signature too long".into());
            }
            Ok(())
        }
        Answer::Attestation { auth_data } if !AUTH_DATA.contains(&auth_data.len()) => {
            Err("auth_data of a bad length".into())
        }
        _ => Ok(()),
    }
}

/// Lexical: no `.` or `..` components, absolute.
fn plain(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::PathBuf;

    /// A fresh dir under `$SAIIFE_TEST_TMP` (never /tmp), mode 0700.
    fn dir(name: &str) -> PathBuf {
        let base = std::env::var_os("SAIIFE_TEST_TMP")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let d = base.join(format!("client-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        mode(&d, 0o700);
        d
    }

    fn mode(p: &Path, m: u32) {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    }

    fn uid(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().uid()
    }

    fn unsafe_why(r: Result<(), HelperError>) -> String {
        match r {
            Err(HelperError::Unsafe(why)) => why,
            other => panic!("not Unsafe: {other:?}"),
        }
    }

    /// Review Focus 2, one row per rule.
    #[test]
    fn check_helper_rules() {
        let top = dir("rules");
        let d = top.join("libexec");
        std::fs::create_dir(&d).unwrap();
        mode(&d, 0o700);
        let f = d.join("saiife-fido");
        std::fs::write(&f, b"#!/bin/sh\n").unwrap();
        mode(&f, 0o755);
        let me = uid(&f);

        // A 0755 file in a 0700 dir.
        assert_eq!(check_helper(&f, me, &d), Ok(()));
        assert_eq!(check_helper(&f, me, &top), Ok(()));

        // Nothing there.
        assert_eq!(
            check_helper(&d.join("missing"), me, &d),
            Err(HelperError::Missing)
        );

        // Group-writable file.
        mode(&f, 0o775);
        assert!(unsafe_why(check_helper(&f, me, &d)).contains("writable"));
        // Others-writable file.
        mode(&f, 0o757);
        assert!(unsafe_why(check_helper(&f, me, &d)).contains("writable"));
        // Not executable.
        mode(&f, 0o644);
        assert!(unsafe_why(check_helper(&f, me, &d)).contains("not executable"));
        // Setuid, setgid.
        mode(&f, 0o4755);
        assert!(unsafe_why(check_helper(&f, me, &d)).contains("setuid"));
        mode(&f, 0o2755);
        assert!(unsafe_why(check_helper(&f, me, &d)).contains("setuid"));
        mode(&f, 0o755);
        // Another owner.
        assert!(unsafe_why(check_helper(&f, me + 1, &d)).contains("owned by"));

        // Others-writable parent.
        mode(&d, 0o707);
        let why = unsafe_why(check_helper(&f, me, &d));
        assert!(
            why.contains("writable") && why.contains(&*d.to_string_lossy()),
            "{why}"
        );
        mode(&d, 0o700);

        // An ancestor above the parent, group-writable: checked only when
        // the trusted root is above it.
        mode(&top, 0o770);
        assert_eq!(check_helper(&f, me, &d), Ok(()));
        let why = unsafe_why(check_helper(&f, me, &top));
        assert!(why.contains(&*top.to_string_lossy()), "{why}");
        mode(&top, 0o700);

        // A symlink at the path (to a good file).
        let link = d.join("link");
        std::os::unix::fs::symlink(&f, &link).unwrap();
        assert!(unsafe_why(check_helper(&link, me, &d)).contains("symlink"));

        // A directory at the path.
        let sub = d.join("sub");
        std::fs::create_dir(&sub).unwrap();
        mode(&sub, 0o755);
        assert!(unsafe_why(check_helper(&sub, me, &d)).contains("not a regular file"));

        // A symlinked directory above the file.
        let ld = top.join("ld");
        std::os::unix::fs::symlink(&d, &ld).unwrap();
        assert!(unsafe_why(check_helper(&ld.join("saiife-fido"), me, &top)).contains("symlink"));

        // A relative path, or one with `..`.
        assert!(matches!(
            check_helper(Path::new("saiife-fido"), me, &d),
            Err(HelperError::Unsafe(_))
        ));
        assert!(matches!(
            check_helper(&d.join("../libexec/saiife-fido"), me, &d),
            Err(HelperError::Unsafe(_))
        ));
        // A trusted root that is not above the path.
        assert!(matches!(
            check_helper(&f, me, &sub),
            Err(HelperError::Unsafe(_))
        ));

        let _ = std::fs::remove_dir_all(&top);
    }

    #[test]
    fn answer_caps() {
        let ok = Answer::Assertion {
            credential_id: vec![0; 1023],
            auth_data: vec![0; 37],
            signature: vec![0; 512],
        };
        assert_eq!(caps(&ok), Ok(()));
        for bad in [
            Answer::Assertion {
                credential_id: vec![0; 1024],
                auth_data: vec![0; 37],
                signature: vec![],
            },
            Answer::Assertion {
                credential_id: vec![],
                auth_data: vec![0; 36],
                signature: vec![],
            },
            Answer::Assertion {
                credential_id: vec![],
                auth_data: vec![0; 37],
                signature: vec![0; 513],
            },
            Answer::Attestation {
                auth_data: vec![0; 4097],
            },
        ] {
            assert!(caps(&bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            caps(&Answer::Attestation {
                auth_data: vec![0; 4096]
            }),
            Ok(())
        );
    }

    #[test]
    fn fixed_values() {
        assert_eq!(HELLO_TIMEOUT, Duration::from_secs(5));
        assert_eq!(EXIT_GRACE, Duration::from_secs(2));
        assert_eq!(STDERR_KEEP, 4096);
    }
}
