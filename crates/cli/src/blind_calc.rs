//! `saiife __blind-calc` (hidden): the Data Shield calculator process (plan
//! 45 R45-12). The daemon starts it once per method run.
//!
//! Order: read one job frame from stdin (at most 1 MiB; a bigger or bad
//! frame is answered `runtime_error` before any confinement work) → resource
//! limits (CPU 15 s, address space 1 GiB, a few open files, no file writes,
//! no core, no new process) → [`confine_helper`] (no_new_privs, a best-effort
//! empty network namespace, Landlock read-only on the snapshot file and
//! nothing else, the calculator's seccomp allowlist: no socket, tracing,
//! exec, namespace or io_uring call) → open the
//! snapshot read-only (`immutable=1`: SQLite touches no `-journal`/`-wal`
//! file) → check its SHA-256 against the job's (`snapshot_mismatch`) →
//! re-validate the method and its self-checks against the job's schema,
//! public values and parameters (a refusal answers its class) → run it with
//! the job's caps → write one answer frame (at most 64 MiB) → exit 0.
//!
//! **Fails closed** (spec §9): when the sandbox cannot be applied in full
//! the answer is `sandbox_unavailable` and no method runs; the reason goes
//! to stderr as a fixed line. Exit 70 only when no answer frame can be
//! written. Answers carry error classes only, never a library's error text.
//!
//! **One job per process, always.** SQLite's `hard_heap_limit` is
//! process-wide and only ever lowered, and the resource limits and the
//! sandbox are for good: the executor must always run in its own process,
//! including any weaker fallback a later plan adds
//! ([`saiife_system::sandbox::CALC_LABEL`]); never in the daemon.

use saiife_shield::calc::{self, Caps, ResultSet};
use saiife_shield::calc_proto::{
    read_frame, write_frame, CalcAnswer, CalcJob, ConfinementInfo, CALC_JOB_VERSION,
    CLASS_SANDBOX_UNAVAILABLE, CLASS_SNAPSHOT_MISMATCH, MAX_ANSWER_BYTES, MAX_JOB_BYTES,
    PROBE_JOB_VERSION,
};
use saiife_shield::snapshot;
use saiife_shield::sql::{validate, validate_check, ErrorClass};
use saiife_system::sandbox::{
    apply_rlimits, confine_helper, Confinement, Profile, Rlimits, SandboxError,
};
use std::io::Write;
use std::process::ExitCode;

/// The exit code when no answer frame could be written (`EX_SOFTWARE`).
pub const EXIT_NO_ANSWER: u8 = 70;

/// R45-7: the calculator's process limits.
const CALC_RLIMITS: Rlimits = Rlimits {
    cpu_secs: 15,
    as_bytes: 1024 * 1024 * 1024,
    // stdin, stdout, stderr, the ruleset, the snapshot (SQLite and the
    // hash check) and some slack.
    nofile: 16,
};

pub fn run() -> ExitCode {
    let answer = {
        let mut stdin = std::io::stdin().lock();
        answer(&mut stdin)
    };
    let mut out = std::io::stdout().lock();
    let written = match write_frame(&mut out, &answer, MAX_ANSWER_BYTES) {
        Ok(()) => Ok(()),
        // Too large an answer: say so in a small frame instead.
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
            let confinement = match &answer {
                CalcAnswer::Ok { confinement, .. } => Some(*confinement),
                CalcAnswer::Err { confinement, .. } => *confinement,
            };
            write_frame(&mut out, &runtime_error(confinement), MAX_ANSWER_BYTES)
        }
        Err(e) => Err(e),
    };
    match written.and_then(|()| out.flush()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            eprintln!("saiife: __blind-calc: cannot write the answer");
            ExitCode::from(EXIT_NO_ANSWER)
        }
    }
}

fn refuse(class: &str, confinement: Option<ConfinementInfo>) -> CalcAnswer {
    CalcAnswer::Err {
        class: class.to_string(),
        empty_for: None,
        confinement,
    }
}

fn runtime_error(confinement: Option<ConfinementInfo>) -> CalcAnswer {
    refuse(ErrorClass::RuntimeError.as_str(), confinement)
}

fn info(c: Confinement) -> ConfinementInfo {
    ConfinementInfo {
        landlock_abi: c.landlock_abi,
        net_denied: c.net_denied,
        scopes: c.scopes,
        seccomp: c.seccomp,
        netns: c.netns,
    }
}

fn answer(input: &mut dyn std::io::Read) -> CalcAnswer {
    let Ok(job) = read_frame::<CalcJob>(input, MAX_JOB_BYTES) else {
        return runtime_error(None);
    };
    let probe = cfg!(debug_assertions) && job.v == PROBE_JOB_VERSION;
    if job.v != CALC_JOB_VERSION && !probe {
        return runtime_error(None);
    }
    if let Err(e) = apply_rlimits(&CALC_RLIMITS) {
        eprintln!("saiife: __blind-calc: {e}");
        return refuse(CLASS_SANDBOX_UNAVAILABLE, None);
    }
    let conf = match confine_helper(Profile::Calc, &[job.snapshot.as_path()], &[]) {
        Ok(c) => info(c),
        // The snapshot is missing or not a file: nothing to run on (no
        // method ran, nothing was allowed).
        Err(SandboxError::ReadPath(_)) => return runtime_error(None),
        Err(e) => {
            eprintln!("saiife: __blind-calc: {e}");
            return refuse(CLASS_SANDBOX_UNAVAILABLE, None);
        }
    };
    #[cfg(debug_assertions)]
    if probe {
        return CalcAnswer::Ok {
            result: probe::run(&job.snapshot),
            confinement: conf,
        };
    }
    match run_job(&job, conf) {
        Ok(result) => CalcAnswer::Ok {
            result,
            confinement: conf,
        },
        Err(a) => a,
    }
}

/// The confined part: open, check the hash, re-validate, run.
fn run_job(job: &CalcJob, conf: ConfinementInfo) -> Result<ResultSet, CalcAnswer> {
    let conf = Some(conf);
    let mut conn = snapshot::open_ro(&job.snapshot).map_err(|_| runtime_error(conf))?;
    match snapshot::hash_file(&job.snapshot) {
        Ok(h) if h == job.snapshot_sha256 => {}
        Ok(_) => return Err(refuse(CLASS_SNAPSHOT_MISMATCH, conf)),
        Err(_) => return Err(runtime_error(conf)),
    }
    let method_err = |e: saiife_shield::sql::MethodError| refuse(e.class.as_str(), conf);
    let v = validate(&job.method, &job.schema, &job.public, &job.params).map_err(method_err)?;
    let checks = job
        .checks
        .iter()
        .map(|c| validate_check(c, &job.schema, &job.public, &job.params))
        .collect::<Result<Vec<_>, _>>()
        .map_err(method_err)?;
    let caps: &Caps = &job.caps;
    calc::run(&mut conn, &v, &checks, &job.params, caps).map_err(|f| CalcAnswer::Err {
        class: f.class.as_str().to_string(),
        empty_for: f.empty_for,
        confinement: conf,
    })
}

/// Debug builds only (`calc_cannot_escape`): what the confined calculator
/// can still do. Each probe is `denied` when it fails with a sandbox error
/// (`EPERM` from seccomp, `EACCES` from Landlock, `EAGAIN` from the process
/// limit), `allowed` when it works, else `failed`.
#[cfg(debug_assertions)]
mod probe {
    use saiife_shield::calc::{CellValue, ResultSet};
    use std::io;
    use std::path::Path;

    fn outcome<T>(r: io::Result<T>) -> &'static str {
        match r {
            Ok(_) => "allowed",
            Err(e) => match rustix::io::Errno::from_io_error(&e) {
                Some(rustix::io::Errno::PERM | rustix::io::Errno::ACCESS) => "denied",
                Some(rustix::io::Errno::AGAIN) => "denied",
                _ => "failed",
            },
        }
    }

    /// rustix's safe `unshare` (deprecated for `unshare_unsafe`): no
    /// `FILES` flag, one thread.
    #[allow(deprecated)]
    fn unshare_net() -> rustix::io::Result<()> {
        rustix::thread::unshare(rustix::thread::UnshareFlags::NEWNET)
    }

    pub(super) fn run(snapshot: &Path) -> ResultSet {
        let probes = [
            ("read /etc/passwd", outcome(std::fs::read("/etc/passwd"))),
            (
                "open a TCP socket",
                outcome(std::net::TcpListener::bind(("127.0.0.1", 0))),
            ),
            (
                "write $TMPDIR/x",
                outcome(std::fs::write(std::env::temp_dir().join("x"), b"x")),
            ),
            (
                "exec /bin/true",
                outcome(std::process::Command::new("/bin/true").status()),
            ),
            (
                "unshare a namespace",
                outcome(unshare_net().map_err(io::Error::from)),
            ),
            (
                "open a pidfd",
                outcome(
                    rustix::process::pidfd_open(
                        rustix::process::getpid(),
                        rustix::process::PidfdFlags::empty(),
                    )
                    .map_err(io::Error::from),
                ),
            ),
            ("read the snapshot", outcome(std::fs::read(snapshot))),
        ];
        let rows: Vec<Vec<CellValue>> = probes
            .iter()
            .map(|(p, o)| {
                vec![
                    CellValue::Text(p.to_string()),
                    CellValue::Text(o.to_string()),
                ]
            })
            .collect();
        ResultSet {
            columns: vec!["probe".into(), "outcome".into()],
            total_rows: None,
            truncated: false,
            ms: 0,
            row_band: String::new(),
            rows,
        }
    }
}
