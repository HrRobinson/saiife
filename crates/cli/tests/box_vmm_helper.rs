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
    for d in [state.join("boxes/b1"), state.join("images"), data.clone()] {
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
    let paths = BoxPaths::new(state.join("boxes/b1"));
    let spec = LaunchSpec {
        version: 1,
        id: BoxId::parse("b1").unwrap(),
        vcpus: 2,
        mem_mib: 1024,
        base: base_img,
        repo: false,
        boot: Boot::Firmware { fw },
        landlock: true,
        restore: false,
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
#[cfg(debug_assertions)]
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
#[cfg(debug_assertions)]
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
