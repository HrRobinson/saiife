//! A `saiife daemon --system` under test, running as the current user with
//! every path in a temp dir: config, policy.d, state (keys), socket and
//! audit dirs. Never root, never the real /etc, /run or /var.
#![allow(dead_code)]

use saiife_ipc::client::{Client, ClientError};
use serde_json::{json, Map, Value};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

pub struct Opts {
    pub checkpoint_every: u64,
    pub checkpoint_interval: String,
    /// `[daemon] user`; the current user when `None`.
    pub user: Option<String>,
    /// TOML appended to the config (e.g. `[guard]\nbogus = 1\n`).
    pub extra: String,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            checkpoint_every: 1000,
            checkpoint_interval: "15m".into(),
            user: None,
            extra: String::new(),
        }
    }
}

pub struct TestDaemon {
    pub tmp: TempDir,
    pub child: Option<Child>,
}

fn sh(cmd: &str, args: &[&str]) -> String {
    let o = Command::new(cmd).args(args).output().unwrap();
    assert!(o.status.success(), "{cmd} {args:?} failed");
    String::from_utf8(o.stdout).unwrap().trim().to_string()
}

pub fn own_user() -> String {
    sh("id", &["-un"])
}

pub fn own_group() -> String {
    sh("id", &["-gn"])
}

pub fn own_uid() -> u32 {
    sh("id", &["-u"]).parse().unwrap()
}

pub fn wait_for(limit: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + limit;
    while Instant::now() < end {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    cond()
}

pub fn dl() -> Instant {
    Instant::now() + Duration::from_secs(3)
}

/// A guard record as the managed hook would send it.
pub fn guard_rec(input: &str) -> Value {
    let r = saiife_audit::Record::new(
        saiife_audit::NewRecord {
            agent: "claude",
            project: "/p",
            session: None,
            tool: "Bash",
            input,
            decision: saiife_audit::DecisionKind::Allow,
            pack: None,
            rule: None,
            reason: None,
            mode: "locked",
            policy: None,
            permission_mode: None,
        },
        "test",
    );
    serde_json::to_value(r).unwrap()
}

pub fn append(c: &mut Client, rec: Value) -> Result<Map<String, Value>, ClientError> {
    let mut args = Map::new();
    args.insert("rec".into(), rec);
    c.call("audit.append", args, dl())
}

pub fn refused_code(e: &ClientError) -> &str {
    match e {
        ClientError::Refused { code, .. } => code,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

impl TestDaemon {
    /// A temp dir with the config written, no daemon yet.
    pub fn prepare(opts: &Opts) -> TestDaemon {
        let tmp = super::tmp::short_tempdir();
        let d = TestDaemon { tmp, child: None };
        fs::create_dir_all(d.path().join("etc")).unwrap();
        fs::create_dir_all(d.path().join("home")).unwrap();
        fs::create_dir_all(d.path().join("data")).unwrap();
        fs::create_dir_all(d.creds_dir()).unwrap();
        let key = d.creds_dir().join(saiife_daemon::VAULT_KEY_FILE);
        fs::write(&key, [42u8; 32]).unwrap();
        // macOS: the vault refuses a key open to group or others.
        fs::set_permissions(&key, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        d.write_config(opts);
        d
    }

    /// Prepare, spawn and wait (at most 5 s) for the socket.
    pub fn start(opts: Opts) -> TestDaemon {
        let mut d = TestDaemon::prepare(&opts);
        d.spawn_and_wait();
        d
    }

    pub fn path(&self) -> &Path {
        self.tmp.path()
    }
    pub fn config(&self) -> PathBuf {
        self.path().join("etc/config.toml")
    }
    pub fn socket_dir(&self) -> PathBuf {
        self.path().join("run")
    }
    pub fn socket(&self) -> PathBuf {
        self.socket_dir().join("saiife.sock")
    }
    pub fn audit_dir(&self) -> PathBuf {
        self.path().join("audit")
    }
    pub fn state_dir(&self) -> PathBuf {
        self.path().join("state")
    }

    pub fn creds_dir(&self) -> PathBuf {
        self.path().join("creds")
    }

    pub fn config_text(&self, opts: &Opts) -> String {
        let user = opts.user.clone().unwrap_or_else(own_user);
        format!(
            "version = 2\nlocked = true\n\n[daemon]\nuser = {user:?}\nsocket_dir = {:?}\n\n[audit]\ndir = {:?}\ncheckpoint_every = {}\ncheckpoint_interval = {:?}\n\n{}",
            self.socket_dir().display().to_string(),
            self.audit_dir().display().to_string(),
            opts.checkpoint_every,
            opts.checkpoint_interval,
            opts.extra
        )
    }

    pub fn write_config(&self, opts: &Opts) {
        fs::write(self.config(), self.config_text(opts)).unwrap();
    }

    pub fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_saiife"));
        cmd.args(["daemon", "--system", "--config"])
            .arg(self.config())
            .arg("--state-dir")
            .arg(self.state_dir())
            .arg("--credentials-dir")
            .arg(self.creds_dir())
            .env("HOME", self.path().join("home"))
            .env("PATH", "/usr/bin:/bin")
            .env("SAIIFE_DATA_DIR", self.path().join("data"))
            .env("SAIIFE_AUDIT_DIR", self.audit_dir())
            .env("XDG_RUNTIME_DIR", self.path().join("no-runtime"))
            // The test runs the daemon and its clients as one user: the
            // debug-build seam lets the locked daemon serve its own uid
            // (gateway children are still refused by pid).
            .env("SAIIFE_TEST_OWN_UID_PEERS", "allow")
            // The MCP gateway runs this binary's `__mcp-spawn`.
            .env("SAIIFE_TEST_MCP_SPAWN", env!("CARGO_BIN_EXE_saiife"))
            .env_remove("NOTIFY_SOCKET")
            .env_remove("STATE_DIRECTORY")
            .env_remove("CREDENTIALS_DIRECTORY")
            .stdin(Stdio::null());
        cmd
    }

    /// Run the daemon to its exit (for refusals), killed after 10 s.
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

    /// The daemon's stderr goes to a file (appended across restarts), so a
    /// chatty daemon can never block on a full pipe.
    pub fn stderr_path(&self) -> PathBuf {
        self.path().join("daemon.stderr")
    }

    pub fn stderr_text(&self) -> String {
        fs::read_to_string(self.stderr_path()).unwrap_or_default()
    }

    pub fn spawn_and_wait(&mut self) {
        self.spawn_and_wait_with(&[]);
    }

    /// `spawn_and_wait` with extra environment (debug-build fault seams).
    pub fn spawn_and_wait_with(&mut self, env: &[(&str, &str)]) {
        let log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.stderr_path())
            .unwrap();
        let mut cmd = self.command();
        for (k, v) in env {
            cmd.env(k, v);
        }
        let child = cmd
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        self.child = Some(child);
        let sock = self.socket();
        let up = wait_for(Duration::from_secs(15), || {
            fs::symlink_metadata(&sock).is_ok() && self.try_client().is_ok()
        });
        if !up {
            let mut child = self.child.take().unwrap();
            let _ = child.kill();
            let _ = child.wait();
            panic!("daemon did not come up in 15 s: {}", self.stderr_text());
        }
    }

    pub fn pid(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }

    /// Send `sig` to this test's own daemon child, by its pid, without
    /// running a `kill` binary.
    pub fn signal(&self, sig: &str) {
        use rustix::process::{kill_process, Pid, Signal};
        let sig = match sig {
            "HUP" => Signal::HUP,
            "INT" => Signal::INT,
            "KILL" => Signal::KILL,
            "TERM" => Signal::TERM,
            other => panic!("unsupported test signal {other}"),
        };
        let pid = Pid::from_raw(self.pid() as i32).expect("child pid");
        kill_process(pid, sig).unwrap();
    }

    /// Wait (at most `limit`) for the daemon to exit.
    pub fn wait_exit(&mut self, limit: Duration) -> Option<ExitStatus> {
        let child = self.child.as_mut()?;
        let end = Instant::now() + limit;
        loop {
            if let Some(st) = child.try_wait().unwrap() {
                self.child = None;
                return Some(st);
            }
            if Instant::now() > end {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn try_client(&self) -> Result<Client, ClientError> {
        let uid = fs::metadata(self.path()).unwrap().uid();
        Client::connect(&self.socket_dir(), uid, dl())
    }

    pub fn client(&self) -> Client {
        self.try_client().unwrap()
    }

    pub fn status(&self) -> Map<String, Value> {
        self.client().call("status", Map::new(), dl()).unwrap()
    }

    /// `saiife audit verify` on this daemon's audit dir, in developer mode
    /// (the system config named does not exist: never /etc/saiife).
    pub fn verify(&self) -> Output {
        Command::new(env!("CARGO_BIN_EXE_saiife"))
            .args(["audit", "verify", "--system-config"])
            .arg(super::absent_system_config(self.path()))
            .env("HOME", self.path().join("home"))
            .env("PATH", "/usr/bin:/bin")
            .env("SAIIFE_DATA_DIR", self.path().join("data"))
            .env("SAIIFE_AUDIT_DIR", self.audit_dir())
            .env("XDG_RUNTIME_DIR", self.path().join("no-runtime"))
            .output()
            .unwrap()
    }

    /// Every line of the audit log, parsed, in file and line order.
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

    pub fn of_kind(&self, kind: &str) -> Vec<Value> {
        self.records()
            .into_iter()
            .filter(|r| r["kind"] == json!(kind))
            .collect()
    }

    pub fn events(&self, event: &str) -> Vec<Value> {
        self.of_kind("daemon")
            .into_iter()
            .filter(|r| r["event"] == json!(event))
            .collect()
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}
