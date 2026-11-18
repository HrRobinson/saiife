//! The calculator client (plan 47 Task 5, R47-11): runs one method in
//! `saiife __blind-calc` (plan 45, `crates/cli/src/blind_calc.rs`), a child
//! process that confines itself before it touches the snapshot.
//!
//! **Always a child, one job per process** (plan 45 carry 1): SQLite's
//! `hard_heap_limit`, the resource limits and the sandbox are process-wide
//! and for good, so the executor never runs in the daemon, including any
//! weaker fallback a later plan adds
//! ([`saiife_system::sandbox::CALC_LABEL`]).
//!
//! Order: no Landlock refuses at once ([`NO_LANDLOCK`], nothing starts) →
//! the job's names are stripped (`params[*].display` is `""`: the calculator
//! needs none) and its snapshot path must be absolute (the child's cwd is
//! `/`; `getcwd` is not allowed in its sandbox) → spawn the calculator with
//! an empty environment, cwd `/`, stdin/stdout pipes and stderr drained to
//! 4 KiB (its first line is logged; it never holds request text) → write
//! the job frame → read one answer frame (at most 64 MiB) under the daemon's
//! own wall timer, `caps.wall_ms` + 5 s.
//!
//! **No answer frame:** a timeout kills the child (`Child::kill`; it is also
//! `kill_on_drop`) and answers [`CLASS_TIME_CAP`]; so does a child killed by
//! any signal (SIGXCPU from its `RLIMIT_CPU`, SIGKILL). Any other exit
//! answers [`CLASS_RUNTIME_ERROR`]. The calculator's own answers come back
//! unchanged; [`outcome`] sorts them for plan 48 by class constant, never by
//! a string literal.
//!
//! The snapshot a job names comes from the live manifest
//! ([`live_snapshot`]: `Manifest::snapshot_sha256`, the indexed file's
//! hash), never from a staging build.

use crate::ops::{Ctx, Mode};
use saiife_shield::calc::ResultSet;
use saiife_shield::calc_proto::{
    read_frame, write_frame, CalcAnswer, CalcJob, ConfinementInfo, MAX_ANSWER_BYTES, MAX_JOB_BYTES,
};
pub use saiife_shield::calc_proto::{CLASS_SANDBOX_UNAVAILABLE, CLASS_SNAPSHOT_MISMATCH};
use saiife_shield::dataset::Manifest;
use saiife_shield::schema::DatasetName;
use saiife_system::sandbox::{sandbox_strength, Strength};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

/// What [`run`] answers when the kernel has no Landlock: nothing starts.
pub const NO_LANDLOCK: &str = "the calculator needs Landlock, which this kernel lacks";
/// What [`run`] answers for a job whose snapshot path is relative.
pub const NOT_ABSOLUTE: &str = "the calculator needs an absolute snapshot path";

/// The method ran past its time: the calculator's wall cap or `RLIMIT_CPU`,
/// or the daemon's own timer killed it (`ErrorClass::TimeCap`).
pub const CLASS_TIME_CAP: &str = "time_cap";
/// The calculator failed without a usable answer (`ErrorClass::RuntimeError`).
pub const CLASS_RUNTIME_ERROR: &str = "runtime_error";
/// The method ran and found nothing for the entity
/// (`ErrorClass::EmptyResult`); `empty_for` names the parameter.
pub const CLASS_EMPTY_RESULT: &str = "empty_result";

/// What the user sees for [`CLASS_SNAPSHOT_MISMATCH`]: the dataset changed
/// under the job. Never retried by itself.
pub const SNAPSHOT_MISMATCH_TEXT: &str =
    "the dataset changed while this question ran; ask again, or refresh the dataset first";

/// Debug builds only: the calculator binary to run instead of saiife's own.
pub const CALC_SEAM: &str = "SAIIFE_TEST_BLIND_CALC";
/// Debug builds only: `1` makes [`run`] see a kernel without Landlock.
pub const NO_LANDLOCK_SEAM: &str = "SAIIFE_TEST_BLIND_NO_LANDLOCK";

/// The hidden command that is the calculator.
const CALC_ARG: &str = "__blind-calc";
/// The daemon's wall timer is the job's cap plus this.
const WALL_SLACK_MS: u64 = 5_000;
/// The calculator's stderr kept (the rest is read and dropped).
const STDERR_CAP: usize = 4096;
/// The longest stderr line logged, in chars.
const LOG_CHARS: usize = 200;

/// A calculator answer as plan 48 handles it.
#[derive(Debug, PartialEq)]
pub enum Outcome<'a> {
    /// The method ran; its result and the sandbox it ran in.
    Ran {
        result: &'a ResultSet,
        confinement: ConfinementInfo,
    },
    /// [`CLASS_SNAPSHOT_MISMATCH`]: show [`SNAPSHOT_MISMATCH_TEXT`]; never
    /// retried blindly.
    SnapshotMismatch,
    /// [`CLASS_EMPTY_RESULT`]: plan 48 shows the empty-for reason.
    EmptyResult { empty_for: Option<&'a str> },
    /// [`CLASS_TIME_CAP`].
    TimeCap,
    /// [`CLASS_SANDBOX_UNAVAILABLE`]: the calculator could not confine
    /// itself; no method ran.
    SandboxUnavailable,
    /// Any other class (a validator refusal, `runtime_error`, a cap).
    Refused {
        class: &'a str,
        empty_for: Option<&'a str>,
    },
}

/// Sorts an answer by its class constant.
pub fn outcome(a: &CalcAnswer) -> Outcome<'_> {
    match a {
        CalcAnswer::Ok {
            result,
            confinement,
        } => Outcome::Ran {
            result,
            confinement: *confinement,
        },
        CalcAnswer::Err {
            class, empty_for, ..
        } => match class.as_str() {
            CLASS_SNAPSHOT_MISMATCH => Outcome::SnapshotMismatch,
            CLASS_EMPTY_RESULT => Outcome::EmptyResult {
                empty_for: empty_for.as_deref(),
            },
            CLASS_TIME_CAP => Outcome::TimeCap,
            CLASS_SANDBOX_UNAVAILABLE => Outcome::SandboxUnavailable,
            c => Outcome::Refused {
                class: c,
                empty_for: empty_for.as_deref(),
            },
        },
    }
}

/// The snapshot a job on `name`'s live build names (carries 2 and 7): the
/// absolute path of the live `snapshot.sqlite` and the live manifest's
/// `snapshot_sha256`.
pub fn live_snapshot(
    blind: &super::Blind,
    name: &DatasetName,
    manifest: &Manifest,
) -> Result<(PathBuf, String), String> {
    let path = std::path::absolute(blind.dataset_dir(name).snapshot())
        .map_err(|_| NOT_ABSOLUTE.to_string())?;
    Ok((path, manifest.snapshot_sha256.clone()))
}

/// Runs `job` in a calculator child and returns its answer. `Err` only when
/// nothing could run: no Landlock ([`NO_LANDLOCK`]), a relative snapshot
/// path, a job over 1 MiB, or a calculator that cannot be started.
pub async fn run(ctx: &Ctx, mut job: CalcJob) -> Result<CalcAnswer, String> {
    if strength() == Strength::None {
        return Err(NO_LANDLOCK.into());
    }
    if !job.snapshot.is_absolute() {
        return Err(NOT_ABSOLUTE.into());
    }
    for p in &mut job.params {
        p.display.clear();
    }
    let mut frame = Vec::new();
    write_frame(&mut frame, &job, MAX_JOB_BYTES)
        .map_err(|_| "the calculator job is too large".to_string())?;
    let exe = calculator(ctx.mode)?;
    let wall = Duration::from_millis(job.caps.wall_ms.saturating_add(WALL_SLACK_MS));
    run_child(exe, frame, wall).await
}

/// The Landlock strength; debug builds honour [`NO_LANDLOCK_SEAM`].
fn strength() -> Strength {
    #[cfg(debug_assertions)]
    if std::env::var_os(NO_LANDLOCK_SEAM).is_some_and(|v| v == "1") {
        return Strength::None;
    }
    sandbox_strength()
}

/// R47-11: `layout::BINARY` in locked mode, this binary in personal mode;
/// debug builds honour [`CALC_SEAM`].
fn calculator(mode: Mode) -> Result<PathBuf, String> {
    #[cfg(debug_assertions)]
    if let Some(p) = std::env::var_os(CALC_SEAM).filter(|p| !p.is_empty()) {
        return Ok(PathBuf::from(p));
    }
    match mode {
        Mode::Locked => Ok(PathBuf::from(saiife_system::layout::BINARY)),
        Mode::Personal => std::env::current_exe().map_err(|e| {
            format!(
                "cannot find the saiife binary for the calculator: {}",
                e.kind()
            )
        }),
    }
}

fn no_frame(class: &str) -> CalcAnswer {
    CalcAnswer::Err {
        class: class.to_string(),
        empty_for: None,
        confinement: None,
    }
}

async fn run_child(exe: PathBuf, frame: Vec<u8>, wall: Duration) -> Result<CalcAnswer, String> {
    let mut child = match tokio::process::Command::new(&exe)
        .arg(CALC_ARG)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return Err(format!("cannot start the calculator: {}", e.kind())),
    };
    let (Some(mut stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        return Err("cannot start the calculator: no pipes".into());
    };
    let talk = async {
        let write = async move {
            // A calculator that stops reading early answers on its own.
            let _ = stdin.write_all(&frame).await;
            drop(stdin);
        };
        let ((), out, err) = tokio::join!(write, read_capped(stdout), drain(stderr));
        let status = child.wait().await;
        (out, err, status)
    };
    let (out, err, status) = match tokio::time::timeout(wall, talk).await {
        Ok(r) => r,
        Err(_) => {
            // Our own child only (it is also kill_on_drop).
            let _ = child.kill().await;
            eprintln!("saiife: the calculator ran past its time and was stopped");
            return Ok(no_frame(CLASS_TIME_CAP));
        }
    };
    log_first_line(&err);
    if let Some(a) = parse(&out) {
        return Ok(a);
    }
    Ok(match status {
        Ok(s) if s.signal().is_some() => no_frame(CLASS_TIME_CAP),
        _ => no_frame(CLASS_RUNTIME_ERROR),
    })
}

/// One whole answer frame and nothing after it, or None.
fn parse(out: &[u8]) -> Option<CalcAnswer> {
    let mut r = out;
    let a = read_frame::<CalcAnswer>(&mut r, MAX_ANSWER_BYTES).ok()?;
    if !r.is_empty() {
        return None;
    }
    // Belt and braces: the calculator fails closed, so an answer from an
    // unconfined run must not exist; refuse one if it does.
    if let CalcAnswer::Ok { confinement, .. } = &a {
        if confinement.landlock_abi == 0 || !confinement.seccomp {
            return Some(no_frame(CLASS_SANDBOX_UNAVAILABLE));
        }
    }
    Some(a)
}

/// Stdout up to one largest frame (and a byte to tell it was more); then
/// the pipe is closed, so a calculator writing on gets `EPIPE`.
async fn read_capped(stdout: impl AsyncRead + Unpin) -> Vec<u8> {
    let mut out = Vec::new();
    let cap = (4 + MAX_ANSWER_BYTES + 1) as u64;
    let _ = stdout.take(cap).read_to_end(&mut out).await;
    out
}

/// Stderr to its end, keeping the first [`STDERR_CAP`] bytes.
async fn drain(mut stderr: impl AsyncRead + Unpin) -> Vec<u8> {
    let mut kept = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stderr.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let room = STDERR_CAP.saturating_sub(kept.len());
                kept.extend_from_slice(&buf[..n.min(room)]);
            }
        }
    }
    kept
}

/// Logs the calculator's first stderr line (its lines are fixed texts; it
/// never has request text), printable ASCII only and cut.
fn log_first_line(err: &[u8]) {
    let line = err.split(|b| *b == b'\n').next().unwrap_or_default();
    let shown: String = line
        .iter()
        .map(|b| match b {
            0x20..=0x7e => *b as char,
            _ => '?',
        })
        .take(LOG_CHARS)
        .collect();
    if !shown.trim().is_empty() {
        eprintln!("saiife: calculator: {shown}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use saiife_shield::sql::ErrorClass;

    #[test]
    fn class_consts_match_the_shield() {
        assert_eq!(CLASS_TIME_CAP, ErrorClass::TimeCap.as_str());
        assert_eq!(CLASS_RUNTIME_ERROR, ErrorClass::RuntimeError.as_str());
        assert_eq!(CLASS_EMPTY_RESULT, ErrorClass::EmptyResult.as_str());
    }

    fn err(class: &str, empty_for: Option<&str>) -> CalcAnswer {
        CalcAnswer::Err {
            class: class.into(),
            empty_for: empty_for.map(str::to_string),
            confinement: None,
        }
    }

    #[test]
    fn outcomes_by_class() {
        assert_eq!(
            outcome(&err(CLASS_SNAPSHOT_MISMATCH, None)),
            Outcome::SnapshotMismatch
        );
        assert_eq!(
            outcome(&err(CLASS_EMPTY_RESULT, Some("p1"))),
            Outcome::EmptyResult {
                empty_for: Some("p1")
            }
        );
        assert_eq!(outcome(&err(CLASS_TIME_CAP, None)), Outcome::TimeCap);
        assert_eq!(
            outcome(&err(CLASS_SANDBOX_UNAVAILABLE, None)),
            Outcome::SandboxUnavailable
        );
        assert_eq!(
            outcome(&err("check_failed", Some("p1"))),
            Outcome::Refused {
                class: "check_failed",
                empty_for: Some("p1")
            }
        );
    }

    #[test]
    fn frames_parse_strictly() {
        let a = err(CLASS_TIME_CAP, None);
        let mut f = Vec::new();
        write_frame(&mut f, &a, MAX_ANSWER_BYTES).unwrap();
        assert_eq!(parse(&f), Some(a));
        let mut extra = f.clone();
        extra.push(0);
        assert_eq!(parse(&extra), None);
        assert_eq!(parse(&f[..f.len() - 1]), None);
        assert_eq!(parse(&[]), None);
        // An unconfined `Ok` is refused.
        let ok = CalcAnswer::Ok {
            result: ResultSet {
                columns: vec![],
                rows: vec![],
                total_rows: None,
                truncated: false,
                ms: 0,
                row_band: String::new(),
            },
            confinement: ConfinementInfo {
                landlock_abi: 0,
                net_denied: false,
                scopes: false,
                seccomp: true,
                netns: false,
            },
        };
        let mut f = Vec::new();
        write_frame(&mut f, &ok, MAX_ANSWER_BYTES).unwrap();
        assert_eq!(parse(&f), Some(err(CLASS_SANDBOX_UNAVAILABLE, None)));
    }
}
