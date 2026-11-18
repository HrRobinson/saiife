//! Data Shield's calculator client (plan 47 Task 5, R47-11): the daemon runs
//! `saiife __blind-calc` (plan 45) in a child process, one job per process.
//! The real calculator is the debug `saiife` binary of this target dir
//! (`cargo build -p saiife` first), reached through the debug-only seam
//! `SAIIFE_TEST_BLIND_CALC`; the fake calculators are shell scripts in
//! `$SAIIFE_TEST_TMP`. The seams are environment variables, so the tests
//! take one lock and run one at a time.
#![cfg(target_os = "linux")]

// The shield executor tests' fixture (it allows its own dead code).
#[path = "../../shield/tests/common/mod.rs"]
mod common;

use saiife_audit::{ChainWriter, WriterOptions};
use saiife_daemon::blind::calc::{self, Outcome, CALC_SEAM, NO_LANDLOCK, NO_LANDLOCK_SEAM};
use saiife_daemon::ops::{Ctx, CtxInit, Mode};
use saiife_daemon::writer::{self, WriterConfig};
use saiife_policy::{Directory, FixedDirectory, Fsync};
use saiife_shield::calc::{Caps, CellValue};
use saiife_shield::calc_proto::{read_frame, CalcAnswer, CalcJob, CALC_JOB_VERSION, MAX_JOB_BYTES};
use saiife_shield::snapshot::hash_file;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

const BALANCE: &str = "SELECT SUM(i.amount) AS owed, c.credit_limit FROM invoices i \
    JOIN customers c ON c.id = i.customer_id WHERE c.id = :p1 AND i.status = 'open'";

/// R45-13: grouped by the FK without outputting it; on 200 000 invoices it
/// runs far past a 50 ms cap.
const HEAVY: &str = "SELECT SUM(i.amount) AS s FROM invoices i \
    GROUP BY i.customer_id ORDER BY s DESC";

/// Customer 1 exists and has invoices, none this late: `empty_result`.
const NOTHING: &str = "SELECT SUM(i.amount) AS owed FROM invoices i \
    JOIN customers c ON c.id = i.customer_id WHERE c.id = :p1 AND i.issued > '2030-01-01'";

/// The name the daemon must strip before the job is written (carry 8).
const NAME: &str = "Soren Hansen p47-t5-name";

/// The env seams are process-wide: one test at a time.
static SEAMS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn scratch() -> tempfile::TempDir {
    let base = std::env::var_os("SAIIFE_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    std::fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

/// The debug `saiife` beside this test binary (`target/debug/deps/..`).
fn saiife_bin() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let p = exe.parent().unwrap().parent().unwrap().join("saiife");
    assert!(
        p.is_file(),
        "{} is missing: run `cargo build -p saiife` first",
        p.display()
    );
    p
}

/// Points the seams: the calculator to run, and whether Landlock is hidden.
fn seams(calc: &Path, no_landlock: bool) {
    std::env::set_var(CALC_SEAM, calc);
    if no_landlock {
        std::env::set_var(NO_LANDLOCK_SEAM, "1");
    } else {
        std::env::remove_var(NO_LANDLOCK_SEAM);
    }
}

fn landlock() -> bool {
    saiife_system::sandbox::landlock_abi() > 0
}

/// A personal-mode context in `root`.
fn ctx(root: &Path) -> Arc<Ctx> {
    let audit = root.join("audit");
    std::fs::create_dir_all(&audit).unwrap();
    let state = root.join("state");
    std::fs::create_dir_all(&state).unwrap();
    let cw = ChainWriter::open(
        &audit,
        WriterOptions {
            mode: Mode::Personal.as_str().into(),
            saiife: "test".into(),
            key: None,
        },
    )
    .unwrap();
    let cfg = WriterConfig {
        checkpoint_every: 1000,
        checkpoint_interval: Duration::from_secs(900),
        fsync: Fsync::Always,
    };
    let (handle, _join) = writer::spawn(cw, cfg, None).unwrap();
    let dirs: Arc<dyn Directory + Send + Sync> = Arc::new(FixedDirectory::from_text(
        "me:x:1000:1000::/home/me:/bin/sh\n",
        "",
    ));
    Arc::new(Ctx::new(CtxInit {
        audit_dir: audit,
        mode: Mode::Personal,
        own_uid: 1000,
        own_user: "me".into(),
        ..CtxInit::minimal(handle, cfg, dirs, &state)
    }))
}

/// The shield executor fixture (plus `heavy` extra invoices), written to a
/// snapshot file.
fn snapshot(dir: &Path, heavy: i64) -> PathBuf {
    let path = dir.join("snapshot.sqlite");
    let db = common::fixture();
    if heavy > 0 {
        common::heavy(&db, heavy);
    }
    db.execute("VACUUM INTO ?1", [path.to_str().unwrap()])
        .unwrap();
    path
}

/// A job as plan 48 will build it, the entity's display name still in it:
/// `run` strips it.
fn job(snapshot: &Path, method: &str) -> CalcJob {
    let mut p = common::entity(1);
    p.display = NAME.into();
    CalcJob {
        v: CALC_JOB_VERSION,
        snapshot: snapshot.to_path_buf(),
        snapshot_sha256: hash_file(snapshot).unwrap(),
        schema: common::schema(),
        public: common::public(),
        method: method.into(),
        checks: vec![],
        params: vec![p],
        caps: Caps::default(),
    }
}

/// A fake calculator: `/bin/sh` running `body` (empty environment: absolute
/// paths only).
fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

fn class(a: &CalcAnswer) -> &str {
    match a {
        CalcAnswer::Err { class, .. } => class,
        CalcAnswer::Ok { result, .. } => panic!("expected a refusal, got {result:?}"),
    }
}

#[tokio::test]
async fn runs_job_in_child() {
    let _g = SEAMS.lock().await;
    let d = scratch();
    let ctx = ctx(d.path());
    seams(&saiife_bin(), false);
    let snap = snapshot(d.path(), 0);
    let r = calc::run(&ctx, job(&snap, BALANCE)).await;
    if !landlock() {
        eprintln!("runs_job_in_child: skipped: this kernel has no Landlock");
        assert_eq!(r.unwrap_err(), NO_LANDLOCK);
        return;
    }
    let a = r.unwrap();
    let CalcAnswer::Ok {
        result,
        confinement,
    } = &a
    else {
        panic!("refused: {a:?}");
    };
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0][0], CellValue::Real(600.0));
    assert_eq!(result.rows[0][1], CellValue::Real(5000.0));
    assert!(confinement.landlock_abi > 0);
    assert!(confinement.seccomp);
    assert!(matches!(calc::outcome(&a), Outcome::Ran { .. }));
}

#[tokio::test]
async fn child_timeout_kills() {
    let _g = SEAMS.lock().await;
    let d = scratch();
    let ctx = ctx(d.path());
    if !landlock() {
        eprintln!("child_timeout_kills: skipped: this kernel has no Landlock");
        return;
    }
    // The real calculator, a 50 ms cap on a heavy grouping: its own timer
    // answers `time_cap`.
    seams(&saiife_bin(), false);
    let snap = snapshot(d.path(), 200_000);
    let mut j = job(&snap, HEAVY);
    j.params.clear();
    j.caps.wall_ms = 50;
    let a = calc::run(&ctx, j).await.unwrap();
    assert_eq!(class(&a), "time_cap");
    assert!(matches!(calc::outcome(&a), Outcome::TimeCap));

    // A calculator that hangs: the daemon's own timer (cap + 5 s) kills it.
    let pidfile = d.path().join("pid");
    let hang = script(
        d.path(),
        "hang.sh",
        &format!("echo $$ > {}\nexec /bin/sleep 60", pidfile.display()),
    );
    seams(&hang, false);
    let mut j = job(&snap, BALANCE);
    j.caps.wall_ms = 50;
    let t = Instant::now();
    let a = calc::run(&ctx, j).await.unwrap();
    let took = t.elapsed();
    assert_eq!(class(&a), "time_cap");
    assert!(
        took >= Duration::from_millis(5_050) && took < Duration::from_secs(20),
        "{took:?}"
    );
    // Killed and reaped: no such process any more.
    let pid = std::fs::read_to_string(&pidfile).unwrap();
    assert!(
        !Path::new("/proc").join(pid.trim()).exists(),
        "the hung calculator still runs"
    );
}

#[tokio::test]
async fn signal_exit_is_time_cap() {
    let _g = SEAMS.lock().await;
    let d = scratch();
    let ctx = ctx(d.path());
    if !landlock() {
        eprintln!("signal_exit_is_time_cap: skipped: this kernel has no Landlock");
        return;
    }
    // RLIMIT_CPU's SIGXCPU, as the calculator's 15 s limit sends it.
    let spin = script(d.path(), "spin.sh", "ulimit -t 1\nwhile :; do :; done");
    seams(&spin, false);
    let snap = snapshot(d.path(), 0);
    let a = calc::run(&ctx, job(&snap, BALANCE)).await.unwrap();
    assert_eq!(class(&a), "time_cap");
}

#[tokio::test]
async fn no_landlock_refuses() {
    let _g = SEAMS.lock().await;
    let d = scratch();
    let ctx = ctx(d.path());
    let marker = d.path().join("started");
    let fake = script(
        d.path(),
        "marker.sh",
        &format!("echo x > {}", marker.display()),
    );
    seams(&fake, true);
    let snap = snapshot(d.path(), 0);
    let r = calc::run(&ctx, job(&snap, BALANCE)).await;
    std::env::remove_var(NO_LANDLOCK_SEAM);
    assert_eq!(r.unwrap_err(), NO_LANDLOCK);
    assert!(!marker.exists(), "a calculator started without Landlock");
}

#[tokio::test]
async fn job_has_no_names() {
    let _g = SEAMS.lock().await;
    let d = scratch();
    let ctx = ctx(d.path());
    if !landlock() {
        eprintln!("job_has_no_names: skipped: this kernel has no Landlock");
        return;
    }
    // A fake calculator that keeps the frame it was sent and answers
    // nothing: a plain exit without a frame is `runtime_error`.
    let dump = d.path().join("job.bin");
    let fake = script(
        d.path(),
        "dump.sh",
        &format!("exec /bin/cat > {}", dump.display()),
    );
    seams(&fake, false);
    let snap = snapshot(d.path(), 0);
    let a = calc::run(&ctx, job(&snap, BALANCE)).await.unwrap();
    assert_eq!(class(&a), "runtime_error");
    let bytes = std::fs::read(&dump).unwrap();
    let mut r: &[u8] = &bytes;
    let sent: CalcJob = read_frame(&mut r, MAX_JOB_BYTES).unwrap();
    assert!(r.is_empty(), "one job frame only");
    assert!(!sent.params.is_empty());
    assert!(sent.params.iter().all(|p| p.display.is_empty()));
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains("Soren Hansen"), "the name reached the child");
    // Carry 2: the path the child gets is absolute.
    assert!(sent.snapshot.is_absolute());
}

#[tokio::test]
async fn relative_snapshot_refused() {
    let _g = SEAMS.lock().await;
    let d = scratch();
    let ctx = ctx(d.path());
    let marker = d.path().join("started");
    let fake = script(
        d.path(),
        "marker.sh",
        &format!("echo x > {}", marker.display()),
    );
    seams(&fake, false);
    let snap = snapshot(d.path(), 0);
    let mut j = job(&snap, BALANCE);
    j.snapshot = PathBuf::from("live/snapshot.sqlite");
    let r = calc::run(&ctx, j).await;
    if landlock() {
        assert_eq!(
            r.unwrap_err(),
            "the calculator needs an absolute snapshot path"
        );
    }
    assert!(!marker.exists());
}

#[tokio::test]
async fn snapshot_mismatch_passes_through() {
    let _g = SEAMS.lock().await;
    let d = scratch();
    let ctx = ctx(d.path());
    if !landlock() {
        eprintln!("snapshot_mismatch_passes_through: skipped: this kernel has no Landlock");
        return;
    }
    seams(&saiife_bin(), false);
    let snap = snapshot(d.path(), 0);
    let mut j = job(&snap, BALANCE);
    j.snapshot_sha256 = format!("sha256:{}", "0".repeat(64));
    let a = calc::run(&ctx, j).await.unwrap();
    assert!(matches!(calc::outcome(&a), Outcome::SnapshotMismatch));
    // The method ran and found nothing: `empty_result`, unchanged.
    let a = calc::run(&ctx, job(&snap, NOTHING)).await.unwrap();
    assert!(
        matches!(calc::outcome(&a), Outcome::EmptyResult { .. }),
        "{a:?}"
    );
}

/// Carry 6: how long `hash_file` takes on a 200 MB snapshot (the calculator
/// hashes inside its 15 s CPU limit). Run by hand:
/// `cargo test -p saiife-daemon --test blind_calc -- --ignored hash_time`.
#[test]
#[ignore]
fn hash_time_200mb() {
    let d = scratch();
    let p = d.path().join("big.bin");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&p).unwrap();
        let block: Vec<u8> = (0..(1 << 20)).map(|i| (i * 31 % 251) as u8).collect();
        for _ in 0..200 {
            f.write_all(&block).unwrap();
        }
        f.sync_all().unwrap();
    }
    let t = Instant::now();
    hash_file(&p).unwrap();
    let cold = t.elapsed();
    let t = Instant::now();
    hash_file(&p).unwrap();
    eprintln!(
        "hash_file 200 MiB: {cold:?} (first), {:?} (second)",
        t.elapsed()
    );
}

#[tokio::test]
async fn missing_calculator_is_an_error() {
    let _g = SEAMS.lock().await;
    let d = scratch();
    let ctx = ctx(d.path());
    if !landlock() {
        eprintln!("missing_calculator_is_an_error: skipped: this kernel has no Landlock");
        return;
    }
    seams(&d.path().join("no-such-calculator"), false);
    let snap = snapshot(d.path(), 0);
    let e = calc::run(&ctx, job(&snap, BALANCE)).await.unwrap_err();
    assert!(e.starts_with("cannot start the calculator"), "{e}");
}
