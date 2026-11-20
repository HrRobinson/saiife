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
//! **The snapshot is the ask's, fixed at its begin** (plan 48 C2, P47-37
//! I4): [`run`] takes a [`HeldSnapshot`] (from
//! `data::live_snapshot`, whose `LiveHandles` own it) and writes its path
//! and the live manifest's `snapshot_sha256` into the job; what the job
//! named is replaced. The held path is a hard link to the very file the
//! build opened, under the dataset's `held/` dir, so a refresh that swaps
//! `live/` (and unlinks the old snapshot) during the ask leaves the job
//! reading the old snapshot through its own name: no `snapshot_mismatch`,
//! no `runtime_error`. The calculator itself is unchanged (it opens the
//! path once, checks SQLite holds that inode, hashes through its fd).

use crate::ops::{Ctx, Mode};
use saiife_shield::calc::ResultSet;
use saiife_shield::calc_proto::{
    read_frame, write_frame, CalcAnswer, CalcJob, ConfinementInfo, MAX_ANSWER_BYTES, MAX_JOB_BYTES,
};
pub use saiife_shield::calc_proto::{CLASS_SANDBOX_UNAVAILABLE, CLASS_SNAPSHOT_MISMATCH};
use saiife_system::sandbox::{sandbox_strength, Strength};
use std::fs::File;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
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

/// A calculator answer as plan 48 handles it. `Debug` prints the kind,
/// the classes and counts only: a result holds real aggregates.
#[derive(PartialEq)]
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

impl std::fmt::Debug for Outcome<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Outcome::Ran {
                result,
                confinement,
            } => f
                .debug_struct("Ran")
                .field("columns", &result.columns.len())
                .field("rows", &result.rows.len())
                .field("truncated", &result.truncated)
                .field("confinement", confinement)
                .finish_non_exhaustive(),
            Outcome::SnapshotMismatch => f.write_str("SnapshotMismatch"),
            Outcome::EmptyResult { empty_for } => f
                .debug_struct("EmptyResult")
                .field("empty_for", &empty_for.is_some())
                .finish(),
            Outcome::TimeCap => f.write_str("TimeCap"),
            Outcome::SandboxUnavailable => f.write_str("SandboxUnavailable"),
            Outcome::Refused { class, empty_for } => f
                .debug_struct("Refused")
                .field("class", class)
                .field("empty_for", &empty_for.is_some())
                .finish(),
        }
    }
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

/// The dir, under a dataset's root, of the held snapshot names.
pub const HELD_DIR: &str = "held";

/// A process-wide counter: each held name is new.
static HELD_SEQ: AtomicU64 = AtomicU64::new(0);

/// One build's snapshot file, held open for the asks on that build (plan
/// 48 C2, P47-37 I4). The file stays open, and a hard link to its inode
/// under `<dataset>/held/` (absolute, `<pid>-<n>.sqlite`) is the name the
/// calculator opens: no refresh swap renames or unlinks it. Dropping the
/// last holder (the `LiveHandles` it lives in, once no ask holds them)
/// removes the name; the daemon start clears names a crash left.
pub struct HeldSnapshot {
    file: File,
    path: PathBuf,
    sha256: String,
}

impl std::fmt::Debug for HeldSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldSnapshot")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl HeldSnapshot {
    /// Holds the snapshot at `src`, whose SHA-256 is `sha256` (the live
    /// manifest's; the caller verified it just before, with no swap
    /// possible in between): opens it (never through a link), links its
    /// inode into `held_dir` (made 0700) and checks the link is that inode.
    pub fn hold(src: &Path, held_dir: &Path, sha256: String) -> io::Result<HeldSnapshot> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(src)?;
        super::private_dir(held_dir)?;
        let dir = std::path::absolute(held_dir)?;
        let n = HELD_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!("{}-{n}.sqlite", std::process::id()));
        // A name a crash left (pid reuse): ours to replace.
        match std::fs::remove_file(&path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        std::fs::hard_link(src, &path)?;
        let held = HeldSnapshot { file, path, sha256 };
        // `src` swapped between the open and the link: refused (dropping
        // `held` removes the name).
        let (a, b) = (
            held.file.metadata()?,
            std::fs::symlink_metadata(&held.path)?,
        );
        if !b.is_file() || (a.dev(), a.ino()) != (b.dev(), b.ino()) {
            return Err(io::Error::other("the snapshot changed while it was held"));
        }
        Ok(held)
    }

    /// The absolute held name the calculator opens.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `sha256:` + hex of the held file (the live manifest's).
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// The open file itself.
    pub fn file(&self) -> &File {
        &self.file
    }
}

impl AsRef<HeldSnapshot> for HeldSnapshot {
    fn as_ref(&self) -> &HeldSnapshot {
        self
    }
}

impl Drop for HeldSnapshot {
    fn drop(&mut self) {
        // Gone already (the dataset was removed): nothing to do.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Runs `job` on the snapshot `snap` (a `data::LiveSnapshot`, or a
/// [`HeldSnapshot`] itself) in a calculator child and returns its answer.
/// `job.snapshot` and `job.snapshot_sha256` are set from `snap`; what the
/// job held there is ignored. `Err` only when nothing could run: no
/// Landlock ([`NO_LANDLOCK`]), a relative snapshot path, a job over 1 MiB,
/// or a calculator that cannot be started.
pub async fn run(
    ctx: &Ctx,
    snap: &impl AsRef<HeldSnapshot>,
    mut job: CalcJob,
) -> Result<CalcAnswer, String> {
    if strength() == Strength::None {
        return Err(NO_LANDLOCK.into());
    }
    let held = snap.as_ref();
    job.snapshot = held.path().to_path_buf();
    job.snapshot_sha256 = held.sha256().to_string();
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
pub(crate) fn strength() -> Strength {
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
    fn outcome_debug_holds_no_value() {
        use saiife_shield::calc::CellValue;
        let a = CalcAnswer::Ok {
            result: ResultSet {
                columns: vec!["revenue_of_soeren".into()],
                rows: vec![vec![
                    CellValue::Text("Østergård".into()),
                    CellValue::Int(987_654_321),
                ]],
                total_rows: None,
                truncated: false,
                ms: 3,
                row_band: "1-9".into(),
            },
            confinement: ConfinementInfo {
                landlock_abi: 6,
                net_denied: true,
                scopes: true,
                seccomp: true,
                netns: true,
            },
        };
        let d = format!("{:?}", outcome(&a));
        assert!(d.starts_with("Ran { columns: 1, rows: 1,"), "{d}");
        for v in ["Østergård", "987654321", "soeren"] {
            assert!(!d.contains(v), "{v} in {d}");
        }
        let d = format!("{:?}", outcome(&err("check_failed", Some("p1"))));
        assert_eq!(d, "Refused { class: \"check_failed\", empty_for: true }");
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
