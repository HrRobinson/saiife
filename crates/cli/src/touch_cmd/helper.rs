//! A FIDO2 key through the packaged helper (plan 41): the static Linux
//! `saiife` has no libudev, so `/usr/libexec/saiife/saiife-fido` talks to
//! the key. One helper process per operation (F1): `devices` starts it and
//! reads its hello, the following `assert` or `enrol` sends its one request.
//! Everything the helper sends is untrusted: bounded, and sanitized before
//! it is classified or printed.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use saiife_fido::client::{check_helper, HelperError, Running};
use saiife_fido::proto::{
    Answer, AssertParts, AssertReq, EnrolReq, Request, MAX_ERROR_CHARS, PROTO,
};
use saiife_touch::TouchError;

use super::{KeySupport, Transport, NO_KEY_SUPPORT};
use crate::text::sanitize;

/// The longest helper version shown, in chars.
const VERSION_CHARS: usize = 64;

/// The helper to run, the uid that must own it and every directory above
/// it, and the highest directory checked (F2). Debug builds only: the seam
/// `SAIIFE_TEST_FIDO_HELPER` (tests cannot make root-owned files) is owned
/// by the caller and checked up to its own directory.
fn located() -> (PathBuf, u32, PathBuf) {
    #[cfg(debug_assertions)]
    if let Some(p) = std::env::var_os("SAIIFE_TEST_FIDO_HELPER").filter(|p| !p.is_empty()) {
        let p = PathBuf::from(p);
        let root = p.parent().map(Path::to_path_buf).unwrap_or_default();
        return (p, rustix::process::getuid().as_raw(), root);
    }
    (
        PathBuf::from(saiife_system::layout::FIDO_HELPER),
        0,
        PathBuf::from("/"),
    )
}

/// F2 on the helper: its path, or the line that refuses it (the no-support
/// line when there is none, plan 27 D1).
pub(crate) fn checked() -> Result<PathBuf, String> {
    let (path, owner, root) = located();
    match check_helper(&path, owner, &root) {
        Ok(()) => Ok(path),
        Err(e) => Err(describe(&path, &e, Duration::ZERO)),
    }
}

/// What `doctor` reports (plan 41 Task 4): F2, then a hello (no request:
/// the key is never asked).
// `doctor` (plan 41 Task 4) calls it, through `touch_cmd::support`.
#[allow(dead_code)]
pub(crate) fn support() -> KeySupport {
    let (path, owner, root) = located();
    match check_helper(&path, owner, &root) {
        Err(HelperError::Missing) => return KeySupport::None,
        Err(e) => return KeySupport::HelperBroken(describe(&path, &e, Duration::ZERO)),
        Ok(()) => {}
    }
    match Running::start(&path) {
        Ok((run, hello)) => {
            run.close();
            KeySupport::Helper {
                version: shown(&hello.version, VERSION_CHARS),
                devices: hello.devices,
            }
        }
        Err(e) => KeySupport::HelperBroken(describe(&path, &e, Duration::ZERO)),
    }
}

/// Untrusted text, cut to `n` chars (on a char boundary) and sanitized.
fn shown(s: &str, n: usize) -> String {
    sanitize(&s.chars().take(n).collect::<String>())
}

/// The first line of the helper's stderr, as shown.
fn first(stderr: &str) -> String {
    shown(stderr.lines().next().unwrap_or_default(), MAX_ERROR_CHARS)
}

/// The line for a helper error (F4, and the plan's fixed values). `path`
/// is the one checked: `FIDO_HELPER` in release builds. `limit` is the
/// answer limit (only `Timeout` names it).
pub(crate) fn describe(path: &Path, e: &HelperError, limit: Duration) -> String {
    const NO_ANSWER: &str = "the FIDO helper did not answer";
    match e {
        HelperError::Missing => NO_KEY_SUPPORT.into(),
        HelperError::Unsafe(why) => format!(
            "the FIDO helper {} is not safe to run ({}); reinstall the saiife package",
            sanitize(&path.display().to_string()),
            sanitize(why)
        ),
        HelperError::Spawn(why) => {
            format!(
                "the FIDO helper cannot start: {}",
                shown(why, MAX_ERROR_CHARS)
            )
        }
        HelperError::NoHello {
            exit: Some(code),
            stderr,
        } => {
            let line = first(stderr);
            let mut s = if line.is_empty() {
                format!("the FIDO helper cannot start: exit code {code}")
            } else {
                format!("the FIDO helper cannot start: {line}")
            };
            // The loader's code for a missing shared library.
            if *code == 127 {
                s.push_str("; is libudev installed?");
            }
            s
        }
        HelperError::NoHello { exit: None, .. } => NO_ANSWER.into(),
        HelperError::Skew { proto, version } => format!(
            "the FIDO helper is version {} (protocol {proto}), this saiife is {} (protocol {PROTO}); reinstall the saiife package",
            shown(version, VERSION_CHARS),
            env!("CARGO_PKG_VERSION")
        ),
        HelperError::Timeout => format!("no touch within {} s", limit.as_secs()),
        HelperError::Protocol(why) => format!("{NO_ANSWER}: {}", shown(why, MAX_ERROR_CHARS)),
        HelperError::Exited { exit, stderr } => {
            let line = first(stderr);
            match exit {
                _ if !line.is_empty() => format!("{NO_ANSWER}: {line}"),
                Some(code) => format!("{NO_ANSWER} (exit code {code})"),
                None => NO_ANSWER.into(),
            }
        }
    }
}

/// The `Transport` over the helper at `path` (already checked, F2).
pub(crate) struct Helper {
    path: PathBuf,
    /// The uid that must own the helper and the highest directory checked.
    owner: u32,
    root: PathBuf,
    /// The helper `devices` started, for the next `assert` or `enrol`.
    running: Mutex<Option<Running>>,
}

impl Helper {
    pub(crate) fn new(path: PathBuf) -> Self {
        let (_, owner, root) = located();
        Self::with_owner(path, owner, root)
    }

    fn with_owner(path: PathBuf, owner: u32, root: PathBuf) -> Self {
        Self {
            path,
            owner,
            root,
            running: Mutex::new(None),
        }
    }

    fn slot(&self) -> MutexGuard<'_, Option<Running>> {
        self.running.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Prints the error's line and gives `Unavailable` (D5).
    fn fail(&self, e: &HelperError, limit: Duration) -> TouchError {
        eprintln!("saiife: {}", describe(&self.path, e, limit));
        TouchError::Unavailable
    }

    /// The helper `devices` started; `KeyTouch` always asks `devices` first.
    fn take(&self) -> Result<Running, TouchError> {
        self.slot().take().ok_or_else(|| {
            eprintln!("saiife: the FIDO helper did not answer");
            TouchError::Unavailable
        })
    }

    /// Closes a helper left from an operation that never sent its request.
    fn close_left(&self) {
        if let Some(run) = self.slot().take() {
            run.close();
        }
    }
}

/// An error answer's text: the helper's (raw) library text, cut and
/// sanitized before `KeyTouch` classifies and prints it.
/// Lines stay lines (each sanitized), so `KeyTouch` prints only the first.
fn ctap_text(error: &str) -> String {
    let capped: String = error.chars().take(MAX_ERROR_CHARS).collect();
    capped.lines().map(sanitize).collect::<Vec<_>>().join("\n")
}

impl Transport for Helper {
    /// Starts the helper and reads its hello (protocol and version, F1.2).
    /// Kept for the request only with one key plugged in: otherwise it is
    /// closed now, and `KeyTouch` refuses (D2) before the PIN.
    fn devices(&self) -> Result<usize, TouchError> {
        self.close_left();
        // F2 is before every run: check again, as `checked` did.
        check_helper(&self.path, self.owner, &self.root)
            .map_err(|e| self.fail(&e, Duration::ZERO))?;
        let (run, hello) = Running::start(&self.path).map_err(|e| self.fail(&e, Duration::ZERO))?;
        if hello.devices == 1 {
            *self.slot() = Some(run);
        } else {
            run.close();
        }
        Ok(hello.devices)
    }

    fn assert(
        &self,
        r: AssertReq,
        limit: Duration,
    ) -> Result<Result<AssertParts, String>, TouchError> {
        let run = self.take()?;
        match run.call(&Request::Assert(r), limit) {
            Ok(Answer::Assertion {
                credential_id,
                auth_data,
                signature,
            }) => Ok(Ok((credential_id, auth_data, signature))),
            Ok(Answer::Error { error }) => Ok(Err(ctap_text(&error))),
            Ok(_) => Err(self.fail(
                &HelperError::Protocol("an answer of the wrong type".into()),
                limit,
            )),
            Err(e) => Err(self.fail(&e, limit)),
        }
    }

    fn enrol(&self, r: EnrolReq, limit: Duration) -> Result<Result<Vec<u8>, String>, TouchError> {
        let run = self.take()?;
        match run.call(&Request::Enrol(r), limit) {
            Ok(Answer::Attestation { auth_data }) => Ok(Ok(auth_data)),
            Ok(Answer::Error { error }) => Ok(Err(ctap_text(&error))),
            Ok(_) => Err(self.fail(
                &HelperError::Protocol("an answer of the wrong type".into()),
                limit,
            )),
            Err(e) => Err(self.fail(&e, limit)),
        }
    }
}

impl Drop for Helper {
    /// A helper started for a request that was never sent (the PIN was not
    /// given): closed, so it exits without touching the key.
    fn drop(&mut self) {
        self.close_left();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: &str = "/usr/libexec/saiife/saiife-fido";

    fn d(e: HelperError) -> String {
        describe(Path::new(P), &e, Duration::from_secs(120))
    }

    #[test]
    fn helper_lines_are_the_plan_s() {
        assert_eq!(d(HelperError::Missing), NO_KEY_SUPPORT);
        assert_eq!(
            d(HelperError::Unsafe("writable by group or others".into())),
            "the FIDO helper /usr/libexec/saiife/saiife-fido is not safe to run (writable by group or others); reinstall the saiife package"
        );
        assert_eq!(
            d(HelperError::Skew {
                proto: 1,
                version: "0.1.0".into()
            }),
            format!(
                "the FIDO helper is version 0.1.0 (protocol 1), this saiife is {} (protocol 1); reinstall the saiife package",
                env!("CARGO_PKG_VERSION")
            )
        );
        assert_eq!(
            d(HelperError::NoHello {
                exit: Some(127),
                stderr: "saiife-fido: error while loading shared libraries: libudev.so.1\nmore"
                    .into()
            }),
            "the FIDO helper cannot start: saiife-fido: error while loading shared libraries: libudev.so.1; is libudev installed?"
        );
        assert_eq!(
            d(HelperError::NoHello {
                exit: Some(1),
                stderr: String::new()
            }),
            "the FIDO helper cannot start: exit code 1"
        );
        assert_eq!(
            d(HelperError::NoHello {
                exit: None,
                stderr: "x".into()
            }),
            "the FIDO helper did not answer"
        );
        assert_eq!(d(HelperError::Timeout), "no touch within 120 s");
        assert_eq!(
            d(HelperError::Exited {
                exit: Some(3),
                stderr: String::new()
            }),
            "the FIDO helper did not answer (exit code 3)"
        );
    }

    /// Review Focus 4: helper text is cut and has no escapes.
    #[test]
    fn helper_text_is_cut_and_sanitized() {
        let long = format!("\u{1b}[31m{}", "é".repeat(2000));
        let t = ctap_text(&long);
        assert!(!t.contains('\u{1b}'), "{t:?}");
        assert!(t.starts_with("\\x1b[31m"), "{t:?}");
        assert_eq!(t.matches('é').count(), MAX_ERROR_CHARS - 5);
        let s = d(HelperError::Exited {
            exit: Some(1),
            stderr: format!("\u{1b}]0;title\u{7}{}\nsecond", "x".repeat(5000)),
        });
        assert!(!s.contains('\u{1b}') && !s.contains("second"), "{s:?}");
        assert!(s.len() < 700, "{}", s.len());
        let v = d(HelperError::Skew {
            proto: 9,
            version: "\u{1b}[2J".repeat(100),
        });
        assert!(!v.contains('\u{1b}'), "{v:?}");
        // The classifier still finds the status in a sanitized text.
        assert_eq!(
            saiife_fido::errors::classify(&ctap_text("0x31 CTAP2_ERR_PIN_INVALID   PIN Invalid."))
                .1,
            "wrong PIN"
        );
    }

    /// F2 is "before every run": a helper made unsafe after `checked` is
    /// not started by `devices`.
    #[test]
    fn devices_checks_the_helper_again() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("ran");
        let path = dir.path().join("saiife-fido");
        std::fs::write(&path, format!("#!/bin/sh\ntouch {}\n", marker.display())).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).unwrap();
        let uid = rustix::process::getuid().as_raw();
        let h = Helper::with_owner(path, uid, dir.path().to_path_buf());
        assert!(matches!(h.devices(), Err(TouchError::Unavailable)));
        assert!(!marker.exists(), "the unsafe helper was started");
    }

    /// The printed line is the first line; the classifier still sees the rest.
    #[test]
    fn ctap_text_keeps_lines_for_the_first_line_cut() {
        let t = ctap_text("0x31 CTAP2_ERR_PIN_INVALID\n\u{1b}[31msecond");
        assert_eq!(
            saiife_fido::errors::first_line(&t),
            "0x31 CTAP2_ERR_PIN_INVALID"
        );
        assert!(
            !t.contains('\u{1b}') && t.contains("\\x1b[31msecond"),
            "{t:?}"
        );
        assert_eq!(t.lines().count(), 2);
    }
}
