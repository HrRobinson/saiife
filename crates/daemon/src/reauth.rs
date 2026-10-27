//! Same-user re-authentication through polkit (spec §6.10.2, plan 11
//! decision 7). The daemon runs
//! `pkcheck --action-id com.saiife.approve --process <pid>,<start>,<uid>
//! --allow-user-interaction` for the approving CLI process, with an empty
//! environment except `PATH`, and kills it (its own child) at the timeout.
//! Exit 0 is authorized; any other exit is denied; a spawn failure or a
//! timeout is an error. Every non-`Authorized` result refuses the approval.

use crate::sessions::Proc;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The polkit action id `system install` registers.
pub const ACTION_ID: &str = "com.saiife.approve";
/// Where `system install` writes the polkit action file.
pub const ACTION_FILE: &str = "/usr/share/polkit-1/actions/com.saiife.approve.policy";
/// The production `pkcheck`.
pub const PKCHECK: &str = "/usr/bin/pkcheck";
/// How long a password prompt may take (decision 7).
pub const REAUTH_TIMEOUT: Duration = Duration::from_secs(120);
/// The only environment `pkcheck` gets.
pub const PKCHECK_PATH_ENV: &str = "/usr/bin:/bin";

/// How often a running `pkcheck` is polled for its exit.
const POLL: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReauthResult {
    Authorized,
    Denied,
    Unavailable,
    Error(String),
}

/// The re-authentication seam: production is [`PkCheck`], tests use fakes.
pub trait Reauth: Send + Sync {
    /// Whether re-authentication can run at all on this host.
    fn available(&self) -> bool;
    /// Asks whether the process `pid` (started at `start`, running as `uid`)
    /// proved a human is present, within `timeout`.
    fn check(&self, pid: u32, start: u64, uid: u32, timeout: Duration) -> ReauthResult;
}

/// `pkcheck` from polkit.
#[derive(Debug, Clone)]
pub struct PkCheck {
    pkcheck: PathBuf,
    action_file: PathBuf,
}

impl Default for PkCheck {
    fn default() -> Self {
        PkCheck::new()
    }
}

impl PkCheck {
    /// `/usr/bin/pkcheck` and the installed action file.
    pub fn new() -> PkCheck {
        PkCheck::with_paths(PKCHECK, ACTION_FILE)
    }

    /// Other paths, for tests (a fake `pkcheck` in a tempdir).
    pub fn with_paths(pkcheck: impl Into<PathBuf>, action_file: impl Into<PathBuf>) -> PkCheck {
        PkCheck {
            pkcheck: pkcheck.into(),
            action_file: action_file.into(),
        }
    }

    /// The argv after the program name (decision 7).
    pub fn argv(pid: u32, start: u64, uid: u32) -> Vec<String> {
        vec![
            "--action-id".to_string(),
            ACTION_ID.to_string(),
            "--process".to_string(),
            format!("{pid},{start},{uid}"),
            "--allow-user-interaction".to_string(),
        ]
    }
}

impl Reauth for PkCheck {
    /// The binary is a regular file whose whole path is root-owned and not
    /// group/other-writable, and the action file exists.
    fn available(&self) -> bool {
        is_regular(&self.pkcheck)
            && saiife_system::fsops::root_owned_chain(&self.pkcheck).is_ok()
            && is_regular(&self.action_file)
    }

    fn check(&self, pid: u32, start: u64, uid: u32, timeout: Duration) -> ReauthResult {
        let mut cmd = Command::new(&self.pkcheck);
        cmd.args(PkCheck::argv(pid, start, uid))
            .env_clear()
            .env("PATH", PKCHECK_PATH_ENV)
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = match spawn(&mut cmd) {
            Ok(c) => c,
            Err(e) => {
                return ReauthResult::Error(format!("{}: {e}", self.pkcheck.display()));
            }
        };
        let deadline = Instant::now() + timeout;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    return if status.success() {
                        ReauthResult::Authorized
                    } else {
                        ReauthResult::Denied
                    };
                }
                Ok(None) => {}
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return ReauthResult::Error(format!("waiting for pkcheck: {e}"));
                }
            }
            let now = Instant::now();
            if now >= deadline {
                // Our own child: kill and reap it.
                let _ = child.kill();
                let _ = child.wait();
                return ReauthResult::Error(format!(
                    "pkcheck timed out after {} ms",
                    timeout.as_millis()
                ));
            }
            std::thread::sleep(POLL.min(deadline - now));
        }
    }
}

/// Spawns `cmd`, retrying a few times on `ETXTBSY` (a binary just written
/// while another thread's fork briefly held it open for writing).
fn spawn(cmd: &mut Command) -> std::io::Result<std::process::Child> {
    const ETXTBSY: i32 = 26;
    let mut tries = 0;
    loop {
        match cmd.spawn() {
            Err(e) if e.raw_os_error() == Some(ETXTBSY) && tries < 5 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(20));
            }
            other => return other,
        }
    }
}

fn is_regular(p: &Path) -> bool {
    std::fs::symlink_metadata(p)
        .map(|m| m.file_type().is_file())
        .unwrap_or(false)
}

/// The start time (field 22 of `/proc/<pid>/stat`) of the approving CLI,
/// for `--process <pid>,<start>,<uid>`. `None` when the process is gone.
pub fn start_time_of(proc: &dyn Proc, pid: u32) -> Option<u64> {
    proc.stat(pid).map(|s| s.start_time)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    /// A fake `pkcheck`: records its argv and its initial environment (from
    /// `/proc/$$/environ`, so nothing the shell adds), then exits `code`, or
    /// sleeps `sleep` seconds when that is not 0.
    fn fake(dir: &Path, code: i32, sleep: u32) -> PathBuf {
        let script = dir.join("pkcheck");
        let out = dir.display();
        // `exec` so the timeout kill reaches the sleeper itself.
        let tail = if sleep > 0 {
            format!("exec sleep {sleep}")
        } else {
            format!("exit {code}")
        };
        fs::write(
            &script,
            format!(
                "#!/bin/sh\n\
                 printf '%s\\n' \"$@\" > '{out}/argv'\n\
                 tr '\\000' '\\n' < /proc/$$/environ > '{out}/env'\n\
                 {tail}\n"
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        script
    }

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn pkcheck_argv_exact() {
        let d = tmp();
        let pk = PkCheck::with_paths(fake(d.path(), 0, 0), d.path().join("action"));
        let r = pk.check(4242, 987654, 1000, Duration::from_secs(10));
        assert_eq!(r, ReauthResult::Authorized);
        let argv = fs::read_to_string(d.path().join("argv")).unwrap();
        assert_eq!(
            argv,
            "--action-id\ncom.saiife.approve\n--process\n4242,987654,1000\n--allow-user-interaction\n"
        );
        let env = fs::read_to_string(d.path().join("env")).unwrap();
        assert_eq!(env, "PATH=/usr/bin:/bin\n");
    }

    #[test]
    fn pkcheck_nonzero_is_denied() {
        let d = tmp();
        for code in [1, 2, 3, 127] {
            let pk = PkCheck::with_paths(fake(d.path(), code, 0), d.path().join("action"));
            assert_eq!(
                pk.check(1, 2, 3, Duration::from_secs(10)),
                ReauthResult::Denied,
                "{code}"
            );
        }
    }

    #[test]
    fn pkcheck_timeout_is_error() {
        let d = tmp();
        let pk = PkCheck::with_paths(fake(d.path(), 0, 30), d.path().join("action"));
        let t0 = Instant::now();
        let r = pk.check(1, 2, 3, Duration::from_millis(200));
        assert!(t0.elapsed() < Duration::from_secs(10), "{:?}", t0.elapsed());
        match r {
            ReauthResult::Error(e) => assert!(e.contains("timed out"), "{e}"),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn missing_pkcheck_is_error() {
        let d = tmp();
        let pk = PkCheck::with_paths(d.path().join("nope"), d.path().join("action"));
        assert!(matches!(
            pk.check(1, 2, 3, Duration::from_secs(1)),
            ReauthResult::Error(_)
        ));
    }

    #[test]
    fn available_needs_root_owned_binary_and_action_file() {
        let d = tmp();
        let action = d.path().join("action");
        // Missing binary and action file.
        assert!(!PkCheck::with_paths(d.path().join("nope"), &action).available());
        // A binary owned by the test user is not root-owned.
        let bin = fake(d.path(), 0, 0);
        fs::write(&action, "<policyconfig/>").unwrap();
        assert!(!PkCheck::with_paths(&bin, &action).available());
        // Relative paths never pass the chain check.
        assert!(!PkCheck::with_paths("pkcheck", &action).available());
    }

    #[test]
    fn start_time_from_proc() {
        use crate::sessions::RealProc;
        let d = tmp();
        let p = d.path().join("77");
        fs::create_dir(&p).unwrap();
        fs::write(
            p.join("stat"),
            format!("77 (saiife) S 1 {}31337 0 0", "0 ".repeat(17)),
        )
        .unwrap();
        let rp = RealProc::new(d.path());
        assert_eq!(start_time_of(&rp, 77), Some(31337));
        assert_eq!(start_time_of(&rp, 78), None);
    }
}
