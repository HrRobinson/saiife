#![cfg(all(unix, feature = "fake"))]
use saiife_boxhost::ch::{Action, Api, ApiError, VmState};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

struct Fake {
    child: Child,
    dir: PathBuf,
}
impl Fake {
    fn start(env: &[(&str, &str)]) -> Fake {
        let base = std::env::var_os("TMPDIR").map_or_else(std::env::temp_dir, PathBuf::from);
        let dir = tempfile::Builder::new()
            .prefix("c")
            .tempdir_in(base)
            .unwrap()
            .keep();
        let sock = dir.join("api.sock");
        let mut c = Command::new(env!("CARGO_BIN_EXE_saiife-fake-ch"));
        c.args([
            "--kernel",
            "/k",
            "--cmdline",
            "console=hvc0 quiet",
            "--disk",
        ])
        .args(["path=/a", "path=/b", "--cpus", "boot=1", "--landlock"])
        .arg("--api-socket")
        .arg(format!("path={}", sock.display()));
        for (k, v) in env {
            c.env(k, v);
        }
        let child = c.spawn().unwrap();
        let f = Fake { child, dir };
        let t = Instant::now();
        while !sock.exists() && t.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(10));
        }
        f
    }
    fn api(&self) -> Api {
        Api::new(self.dir.join("api.sock"))
    }
}
impl Drop for Fake {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

const T: Duration = Duration::from_secs(5);

#[test]
fn ping_state_pause_resume() {
    let f = Fake::start(&[]);
    let a = f.api();
    assert_eq!(a.ping().unwrap(), "v54.0");
    assert_eq!(a.state().unwrap(), VmState::Running);
    a.put(Action::Pause, None, T).unwrap();
    assert_eq!(a.state().unwrap(), VmState::Paused);
    let snap = f.dir.join("snap");
    a.snapshot(&snap).unwrap();
    assert!(snap.join("config.json").exists());
    a.put(Action::Resume, None, T).unwrap();
    assert_eq!(a.state().unwrap(), VmState::Running);
    let argv = std::fs::read_to_string(f.dir.join("fake-ch.argv")).unwrap();
    assert!(argv.contains("\"--landlock\"\n"));
}

#[test]
fn pause_when_paused_is_http_500() {
    let f = Fake::start(&[]);
    let a = f.api();
    a.put(Action::Pause, None, T).unwrap();
    assert_eq!(
        a.put(Action::Pause, None, T),
        Err(ApiError::Http {
            status: 500,
            body: "InvalidStateTransition".into()
        })
    );
}

#[test]
fn hung_api_times_out() {
    let f = Fake::start(&[("FAKE_CH_HANG", "1")]);
    let t = Instant::now();
    assert_eq!(f.api().state(), Err(ApiError::Timeout));
    assert!(t.elapsed() < Duration::from_secs(3));
}

#[test]
fn power_button_exits_the_fake() {
    let mut f = Fake::start(&[]);
    f.api().put(Action::PowerButton, None, T).unwrap();
    let t = Instant::now();
    loop {
        if let Some(st) = f.child.try_wait().unwrap() {
            assert!(st.success());
            break;
        }
        assert!(t.elapsed() < Duration::from_secs(5), "fake did not exit");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn snapshot_when_running_is_http_500() {
    let f = Fake::start(&[]);
    let r = f.api().snapshot(&f.dir.join("snap"));
    assert_eq!(
        r,
        Err(ApiError::Http {
            status: 500,
            body: "InvalidStateTransition".into()
        })
    );
    assert!(!f.dir.join("snap").exists());
}

#[test]
fn argv_is_written_before_exit_at_start() {
    let mut f = Fake::start(&[("FAKE_CH_EXIT_AT_START", "3")]);
    assert_eq!(f.child.wait().unwrap().code(), Some(3));
    assert!(f.dir.join("fake-ch.argv").exists());
}
