//! `saiife __box-vmm` (plan 35, Task 4): checks vm.json, then execs the VMM.
//! The VMM here is a script that records its argv; nothing real runs.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use saiife_boxhost::launch::{self, Boot, LaunchSpec};
use saiife_boxhost::paths::BoxPaths;
use saiife_wire::source::BoxId;

struct Fx {
    _t: tempfile::TempDir,
    root: PathBuf,
    paths: BoxPaths,
    spec: LaunchSpec,
    ch: PathBuf,
    out: PathBuf,
}

/// A fake personal layout. The box dir is kept short: socket paths are
/// capped at 100 bytes.
fn fx() -> Fx {
    let base = std::env::var_os("SAIIFE_TEST_TMP").expect("SAIIFE_TEST_TMP");
    let t = tempfile::Builder::new()
        .prefix("h")
        .rand_bytes(2)
        .tempdir_in(base)
        .unwrap();
    let root = std::fs::canonicalize(t.path()).unwrap();
    let state = root.join("s/saiife/broker");
    let data = root.join("d/saiife/vmm");
    for d in [state.join("box-run/b1"), state.join("images"), data.clone()] {
        std::fs::create_dir_all(&d).unwrap();
    }
    let base_img = state.join("images/base.qcow2");
    std::fs::write(&base_img, b"x").unwrap();
    let fw = data.join("CLOUDHV.fd");
    std::fs::write(&fw, b"x").unwrap();
    let out = root.join("argv.txt");
    let ch = root.join("ch.sh");
    std::fs::write(
        &ch,
        format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\n", out.display()),
    )
    .unwrap();
    std::fs::set_permissions(&ch, std::fs::Permissions::from_mode(0o755)).unwrap();
    let paths = BoxPaths::new(state.join("box-run/b1"));
    let spec = LaunchSpec {
        version: 1,
        id: BoxId::parse("b1").unwrap(),
        vcpus: 2,
        mem_mib: 1024,
        base: base_img,
        repo: false,
        boot: Boot::Firmware { fw },
        landlock: true,
        restore: None,
    };
    launch::write_spec(&spec, &paths).unwrap();
    Fx {
        _t: t,
        root,
        paths,
        spec,
        ch,
        out,
    }
}

fn run(f: &Fx, no_pin: bool) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_saiife"));
    c.args(["__box-vmm"])
        .arg(&f.paths.dir)
        .env_clear()
        .env("HOME", f.root.join("home"))
        .env("XDG_STATE_HOME", f.root.join("s"))
        .env("XDG_DATA_HOME", f.root.join("d"))
        .env("XDG_RUNTIME_DIR", f.root.join("r"))
        .env("PATH", "/usr/bin:/bin")
        .env("SAIIFE_TOOL_CH", &f.ch)
        .stdin(Stdio::null());
    if no_pin {
        c.env("SAIIFE_TEST_NO_PIN", "1");
    }
    c.output().unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
#[cfg(debug_assertions)]
fn helper_execs_the_tool_with_argv() {
    let f = fx();
    let o = run(&f, true);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let got = std::fs::read_to_string(&f.out).unwrap();
    let want: Vec<String> = launch::argv(&f.spec, &f.paths)
        .into_iter()
        .map(|s| s.into_string().unwrap())
        .collect();
    assert_eq!(got.lines().collect::<Vec<_>>(), want);
    assert!(Path::new(&f.paths.ch_log()).exists());
    let mode = std::fs::metadata(f.paths.ch_log())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o640);
}

#[test]
#[cfg(debug_assertions)]
fn helper_refuses_unpinned_binary() {
    let f = fx();
    let o = run(&f, false);
    assert_eq!(o.status.code(), Some(3));
    assert!(stderr(&o).contains("sha256"), "{}", stderr(&o));
    assert!(stderr(&o).starts_with("saiife __box-vmm:"));
    assert!(!f.out.exists());
}

#[test]
fn helper_refuses_a_tampered_spec_before_exec() {
    let f = fx();
    let mut s = f.spec.clone();
    s.base = PathBuf::from("/etc/shadow");
    launch::write_spec(&s, &f.paths).unwrap();
    let o = run(&f, true);
    assert_eq!(o.status.code(), Some(3));
    assert!(stderr(&o).contains("base"), "{}", stderr(&o));
    assert!(!f.out.exists());
}

/// Runs the helper with a bound: a stuck open would hang it forever.
#[cfg(all(debug_assertions, target_os = "linux"))]
fn run_bounded(f: &Fx) -> Option<std::process::ExitStatus> {
    let mut c = Command::new(env!("CARGO_BIN_EXE_saiife"));
    c.args(["__box-vmm"])
        .arg(&f.paths.dir)
        .env_clear()
        .env("HOME", f.root.join("home"))
        .env("XDG_STATE_HOME", f.root.join("s"))
        .env("XDG_DATA_HOME", f.root.join("d"))
        .env("XDG_RUNTIME_DIR", f.root.join("r"))
        .env("PATH", "/usr/bin:/bin")
        .env("SAIIFE_TOOL_CH", &f.ch)
        .env("SAIIFE_TEST_NO_PIN", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = c.spawn().unwrap();
    let t = std::time::Instant::now();
    while t.elapsed() < std::time::Duration::from_secs(10) {
        if let Some(s) = child.try_wait().unwrap() {
            return Some(s);
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    // our own child
    let _ = child.kill();
    let _ = child.wait();
    None
}

#[test]
#[cfg(all(debug_assertions, target_os = "linux"))]
fn helper_replaces_a_fifo_log() {
    let f = fx();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        f.paths.ch_log(),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    let s = run_bounded(&f).expect("the helper blocked on a FIFO ch.log");
    if s.code() == Some(0) {
        let m = std::fs::symlink_metadata(f.paths.ch_log()).unwrap();
        assert!(m.file_type().is_file());
        assert!(f.out.exists());
    } else {
        assert_eq!(s.code(), Some(3));
        assert!(!f.out.exists());
    }
}

#[test]
#[cfg(debug_assertions)]
fn helper_refuses_a_symlinked_log() {
    let f = fx();
    let target = f.root.join("target");
    std::fs::write(&target, b"keep").unwrap();
    std::os::unix::fs::symlink(&target, f.paths.ch_log()).unwrap();
    let o = run(&f, true);
    assert_eq!(o.status.code(), Some(3), "{}", stderr(&o));
    assert!(stderr(&o).contains("ch.log"), "{}", stderr(&o));
    assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    assert!(!f.out.exists());
}

#[test]
#[cfg(debug_assertions)]
fn helper_restores_only_from_the_vault() {
    let f = fx();
    let mut s = f.spec.clone();
    // the VMM-writable snapshot in the box dir is never a restore source
    std::fs::create_dir(f.paths.snapshot_dir()).unwrap();
    s.restore = Some(f.paths.snapshot_dir());
    launch::write_spec(&s, &f.paths).unwrap();
    let o = run(&f, true);
    assert_eq!(o.status.code(), Some(3), "{}", stderr(&o));
    assert!(stderr(&o).contains("restore"), "{}", stderr(&o));
    assert!(!f.out.exists());
    // the vault copy is
    let vault = f.root.join("s/saiife/broker/box-vault");
    let snap = vault.join("b1.snap");
    std::fs::create_dir_all(&snap).unwrap();
    s.restore = Some(snap.clone());
    launch::write_spec(&s, &f.paths).unwrap();
    let o = run(&f, true);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let got = std::fs::read_to_string(&f.out).unwrap();
    assert!(
        got.contains(&format!("source_url=file://{}", snap.display())),
        "{got}"
    );
}

/// The Landlock rule names `<dir>/snapshot`: the helper makes it (0770, as
/// the VMM user) before the exec, and refuses a symlink there.
#[test]
#[cfg(debug_assertions)]
fn helper_makes_the_snapshot_dir_and_refuses_a_symlink() {
    use std::os::unix::fs::MetadataExt;
    let f = fx();
    let o = run(&f, true);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let m = std::fs::symlink_metadata(f.paths.snapshot_dir()).unwrap();
    assert!(m.file_type().is_dir());
    assert_eq!(m.mode() & 0o7777, 0o770);
    std::fs::remove_dir(f.paths.snapshot_dir()).unwrap();
    std::fs::remove_file(&f.out).unwrap();
    let target = f.root.join("elsewhere");
    std::fs::create_dir(&target).unwrap();
    std::os::unix::fs::symlink(&target, f.paths.snapshot_dir()).unwrap();
    let o = run(&f, true);
    assert_eq!(o.status.code(), Some(3), "{}", stderr(&o));
    assert!(stderr(&o).contains("snapshot"), "{}", stderr(&o));
    assert!(!f.out.exists());
}

/// `__box-vmm` with `args` after the box dir.
fn run_args(f: &Fx, args: &[&str]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_saiife"));
    c.args(["__box-vmm"])
        .arg(&f.paths.dir)
        .args(args)
        .env_clear()
        .env("HOME", f.root.join("home"))
        .env("XDG_STATE_HOME", f.root.join("s"))
        .env("XDG_DATA_HOME", f.root.join("d"))
        .env("XDG_RUNTIME_DIR", f.root.join("r"))
        .env("PATH", "/usr/bin:/bin")
        .env("SAIIFE_TOOL_CH", &f.ch)
        .env("SAIIFE_TEST_NO_PIN", "1")
        .stdin(Stdio::null());
    c.output().unwrap()
}

/// Fail closed even if the daemon's rebuild of the spec regressed: a
/// locked VMM never starts without Landlock, and no VMM above the
/// template ceilings (32 vCPUs, 256 GiB).
#[test]
fn helper_refuses_landlock_off_locked_and_oversize() {
    let f = fx();
    let off = LaunchSpec {
        landlock: false,
        ..f.spec.clone()
    };
    launch::write_spec(&off, &f.paths).unwrap();
    for args in [&[][..], &["--locked"][..]] {
        let o = run_args(&f, args);
        assert_eq!(o.status.code(), Some(3), "{}", stderr(&o));
        assert!(!f.out.exists(), "the VMM was not started");
    }
    let o = run_args(&f, &[]);
    assert!(stderr(&o).contains("landlock"), "{}", stderr(&o));
    for (vcpus, mem_mib) in [(64, 1024), (2, 1 << 20)] {
        let big = LaunchSpec {
            vcpus,
            mem_mib,
            ..f.spec.clone()
        };
        launch::write_spec(&big, &f.paths).unwrap();
        let o = run(&f, true);
        assert_eq!(o.status.code(), Some(3), "{}", stderr(&o));
        let e = stderr(&o);
        assert!(e.contains("vcpus") || e.contains("mem_mib"), "{e}");
        assert!(!f.out.exists(), "the VMM was not started");
    }
}

/// Locked, the daemon writes vm.json and the VMM user runs the helper: a
/// vm.json the helper's own user owns (made or replaced by a VMM in the
/// group-writable runtime dir) is refused, checked on the open file.
#[test]
fn helper_refuses_a_spec_its_own_user_wrote_when_locked() {
    let f = fx();
    let o = run_args(&f, &["--locked"]);
    assert_eq!(o.status.code(), Some(3), "{}", stderr(&o));
    assert!(stderr(&o).contains("owned by"), "{}", stderr(&o));
    assert!(!f.out.exists(), "the VMM was not started");
}
