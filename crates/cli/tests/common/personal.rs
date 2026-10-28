//! A `saiife daemon --user` (personal broker) under test, as the current
//! user with every path in one temp dir: `XDG_RUNTIME_DIR` (0700),
//! `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_DATA_HOME`, `HOME`, the test
//! keychain (`SAIIFE_TEST_KEYCHAIN`) and a locked-host marker that does not
//! exist. `DBUS_SESSION_BUS_ADDRESS` names a dead path, so a test that
//! drops the keychain seam fails with "no session bus" and never reaches
//! the desktop keyring. Never root, never /etc, /run or the real home.
#![allow(dead_code)]

use saiife_ipc::client::{Client, ClientError};
use serde_json::{json, Map, Value};
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

pub use super::daemon::{dl, own_uid, wait_for};

pub struct TestBroker {
    pub tmp: TempDir,
    pub child: Option<Child>,
    /// Extra environment for every start (`None` removes the variable).
    pub env: Vec<(String, Option<OsString>)>,
}

impl TestBroker {
    /// The temp dirs, no config and no broker yet.
    pub fn prepare() -> TestBroker {
        let tmp = super::tmp::short_tempdir();
        let b = TestBroker {
            tmp,
            child: None,
            env: Vec::new(),
        };
        fs::create_dir(b.runtime_dir()).unwrap();
        fs::set_permissions(b.runtime_dir(), fs::Permissions::from_mode(0o700)).unwrap();
        for d in ["h", "c", "s", "d", "hookdata", "hookaudit"] {
            fs::create_dir_all(b.path().join(d)).unwrap();
        }
        b
    }

    /// Prepare, write `config` (when `Some`), spawn and wait for the socket.
    pub fn start(config: Option<&str>) -> TestBroker {
        let mut b = TestBroker::prepare();
        if let Some(c) = config {
            b.write_config(c);
        }
        b.spawn_and_wait();
        b
    }

    pub fn path(&self) -> &Path {
        self.tmp.path()
    }
    pub fn runtime_dir(&self) -> PathBuf {
        self.path().join("r")
    }
    pub fn socket_dir(&self) -> PathBuf {
        self.runtime_dir().join("saiife")
    }
    pub fn socket(&self) -> PathBuf {
        self.socket_dir().join("saiife.sock")
    }
    pub fn gateway_socket(&self) -> PathBuf {
        self.socket_dir().join("gateway.sock")
    }
    pub fn home(&self) -> PathBuf {
        self.path().join("h")
    }
    pub fn config_dir(&self) -> PathBuf {
        self.path().join("c/saiife/broker")
    }
    pub fn config(&self) -> PathBuf {
        self.config_dir().join("config.toml")
    }
    pub fn state_dir(&self) -> PathBuf {
        self.path().join("s/saiife/broker")
    }
    pub fn vault_file(&self) -> PathBuf {
        self.state_dir().join("vault/vault.bin")
    }
    pub fn audit_dir(&self) -> PathBuf {
        self.path().join("d/saiife/broker/audit")
    }
    pub fn keychain_dir(&self) -> PathBuf {
        self.path().join("k")
    }
    /// The locked-host marker the broker checks; absent unless a test
    /// writes it.
    pub fn locked_marker(&self) -> PathBuf {
        self.path().join("installed.toml")
    }
    pub fn stderr_path(&self) -> PathBuf {
        self.path().join("broker.stderr")
    }
    pub fn stderr_text(&self) -> String {
        fs::read_to_string(self.stderr_path()).unwrap_or_default()
    }

    /// Write `text` as the config, in a 0700 dir, 0600.
    pub fn write_config(&self, text: &str) {
        fs::create_dir_all(self.config_dir()).unwrap();
        for d in [self.path().join("c/saiife"), self.config_dir()] {
            fs::set_permissions(d, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(self.config(), text).unwrap();
        fs::set_permissions(self.config(), fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// `saiife daemon --user` with the test environment.
    pub fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_saiife"));
        cmd.args(["daemon", "--user", "--locked-marker"])
            .arg(self.locked_marker())
            .env("HOME", self.home())
            .env("PATH", "/usr/bin:/bin")
            .env("XDG_RUNTIME_DIR", self.runtime_dir())
            .env("XDG_CONFIG_HOME", self.path().join("c"))
            .env("XDG_STATE_HOME", self.path().join("s"))
            .env("XDG_DATA_HOME", self.path().join("d"))
            .env("SAIIFE_TEST_KEYCHAIN", self.keychain_dir())
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}", self.path().join("no-bus").display()),
            )
            .env("SAIIFE_DATA_DIR", self.path().join("hookdata"))
            .env("SAIIFE_AUDIT_DIR", self.path().join("hookaudit"))
            .env_remove("NOTIFY_SOCKET")
            .env_remove("SAIIFE_TEST_CA_OWNER")
            .env_remove("STATE_DIRECTORY")
            .env_remove("CREDENTIALS_DIRECTORY")
            .stdin(Stdio::null());
        for (k, v) in &self.env {
            match v {
                Some(v) => cmd.env(k, v),
                None => cmd.env_remove(k),
            };
        }
        cmd
    }

    /// Run the broker to its exit (for refusals), killed after 10 s.
    pub fn run_to_exit(&self) -> Output {
        let mut child = self
            .command()
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let end = Instant::now() + Duration::from_secs(10);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() > end {
                let _ = child.kill();
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        child.wait_with_output().unwrap()
    }

    /// Spawn without waiting; stderr goes to [`Self::stderr_path`].
    pub fn spawn(&mut self) {
        let log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.stderr_path())
            .unwrap();
        let child = self
            .command()
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        self.child = Some(child);
    }

    pub fn spawn_and_wait(&mut self) {
        self.spawn();
        let up = wait_for(Duration::from_secs(10), || self.try_client().is_ok());
        if !up {
            self.stop();
            panic!("broker did not come up in 10 s: {}", self.stderr_text());
        }
    }

    /// Stop the broker (its own child) and wait for it.
    pub fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    /// Stop with SIGTERM (a clean stop: the stop record), through the
    /// test's own child only.
    pub fn stop_clean(&mut self) {
        let Some(mut c) = self.child.take() else {
            return;
        };
        let pid = rustix::process::Pid::from_raw(c.id() as i32).unwrap();
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
        let end = Instant::now() + Duration::from_secs(10);
        while c.try_wait().unwrap().is_none() {
            if Instant::now() > end {
                let _ = c.kill();
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = c.wait();
    }

    pub fn try_client(&self) -> Result<Client, ClientError> {
        Client::connect(&self.socket_dir(), own_uid(), dl())
    }

    pub fn client(&self) -> Client {
        self.try_client().unwrap()
    }

    pub fn call(&self, op: &str, args: Value) -> Result<Map<String, Value>, ClientError> {
        let Value::Object(args) = args else {
            panic!("args must be an object")
        };
        self.client().call(op, args, dl())
    }

    /// Every line of the broker's audit log, parsed, in file order.
    pub fn records(&self) -> Vec<Value> {
        let Ok(rd) = fs::read_dir(self.audit_dir()) else {
            return Vec::new();
        };
        let mut files: Vec<PathBuf> = rd
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
            .collect();
        files.sort();
        let mut out = Vec::new();
        for f in files {
            let text = fs::read_to_string(f).unwrap();
            for l in super::complete_lines(&text) {
                out.push(serde_json::from_str(l).unwrap());
            }
        }
        out
    }

    pub fn events(&self, event: &str) -> Vec<Value> {
        self.records()
            .into_iter()
            .filter(|r| r["kind"] == json!("daemon") && r["event"] == json!(event))
            .collect()
    }

    /// Wait (at most 5 s) for a `daemon` record with `event`.
    pub fn wait_event(&self, event: &str) -> Value {
        assert!(
            wait_for(Duration::from_secs(5), || !self.events(event).is_empty()),
            "no {event} record; stderr: {}",
            self.stderr_text()
        );
        self.events(event).remove(0)
    }

    /// `saiife audit verify` on the broker's audit dir (developer mode,
    /// no /etc/saiife).
    pub fn verify(&self) -> Output {
        Command::new(env!("CARGO_BIN_EXE_saiife"))
            .args(["audit", "verify", "--system-config"])
            .arg(super::absent_system_config(self.path()))
            .env("HOME", self.home())
            .env("PATH", "/usr/bin:/bin")
            .env("SAIIFE_DATA_DIR", self.path().join("hookdata"))
            .env("SAIIFE_AUDIT_DIR", self.audit_dir())
            .output()
            .unwrap()
    }
}

impl Drop for TestBroker {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The mode bits of `p`.
pub fn mode(p: &Path) -> u32 {
    fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
}
