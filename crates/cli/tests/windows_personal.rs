//! `saiife daemon --user` on Windows, end to end: plan 16's personal-broker tests that make
//! sense without Unix modes and signals, and the CLI's clients through the pipe (plan 19b,
//! Tasks 11 and integration). These run in CI's `test` job only: no Windows machine runs
//! this file locally.
//!
//! A real broker as the runner, every path in one temp tree, and the debug-build seams: the
//! test keychain (`SAIIFE_TEST_KEYCHAIN`), so the runner's Credential Manager is never
//! touched, and a test pipe `\\.\pipe\saiife-test-<random>`, owned by the runner's SID. The
//! seam also lets an elevated runner start a broker, so what `personal_start_problem`
//! refuses is checked by its unit test, not here.
//!
//! The broker stops by `Child::kill` on the test's own child: Windows has no SIGTERM, so
//! plan 16's clean-stop record is not checked here.
#![cfg(windows)]

use saiife_ipc::client::{Client, ClientError};
use saiife_win::ffi::{account, acl, token};
use serde_json::{json, Map, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

const SAIIFE: &str = env!("CARGO_BIN_EXE_saiife");

/// A fake secret value, built at run time (no token-shaped literal).
fn secret_value() -> String {
    concat!("personal", "-broker-", "value-", "4711").to_string()
}

fn me() -> String {
    token::current().unwrap().sid
}

fn pipe_name(test: &str) -> String {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    format!(r"\\.\pipe\saiife-test-{}-{n}-{test}", std::process::id())
}

fn dl() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

struct TestBroker {
    _root: tempfile::TempDir,
    top: PathBuf,
    pipe: String,
    child: Option<Child>,
}

impl TestBroker {
    /// The temp tree, no config and no broker yet. Only the runner and SYSTEM can use it, as
    /// `check_private_dir` asks of the broker's own dirs.
    fn prepare(test: &str) -> TestBroker {
        let root = tempfile::tempdir_in(std::env::temp_dir()).unwrap();
        let me = me();
        let top = root.path().join("t");
        acl::create_dir_with_sddl(
            &top,
            &format!("O:{me}D:PAI(A;OICI;FA;;;{me})(A;OICI;FA;;;SY)"),
        )
        .unwrap();
        let top = saiife_system::wintrust::plain_path(&fs::canonicalize(&top).unwrap());
        for d in ["hookdata", "hookaudit", "p"] {
            fs::create_dir_all(top.join(d)).unwrap();
        }
        fs::create_dir_all(top.join("h").join("AppData").join("Local")).unwrap();
        TestBroker {
            _root: root,
            top,
            pipe: pipe_name(test),
            child: None,
        }
    }

    fn start(test: &str) -> TestBroker {
        let mut b = TestBroker::prepare(test);
        b.spawn_and_wait();
        b
    }

    fn home(&self) -> PathBuf {
        self.top.join("h")
    }
    fn personal_dir(&self) -> PathBuf {
        self.home()
            .join("AppData")
            .join("Local")
            .join("saiife")
            .join("personal")
    }
    fn config(&self) -> PathBuf {
        self.personal_dir().join("config.toml")
    }
    fn audit_dir(&self) -> PathBuf {
        self.personal_dir().join("audit")
    }
    fn vault_file(&self) -> PathBuf {
        self.personal_dir()
            .join("state")
            .join("vault")
            .join("vault.bin")
    }
    fn keychain_dir(&self) -> PathBuf {
        self.top.join("k")
    }
    fn locked_marker(&self) -> PathBuf {
        self.top.join("installed.toml")
    }
    fn stderr_path(&self) -> PathBuf {
        self.top.join("broker.stderr")
    }
    fn stderr_text(&self) -> String {
        fs::read_to_string(self.stderr_path()).unwrap_or_default()
    }

    fn write_config(&self, text: &str) {
        fs::create_dir_all(self.personal_dir()).unwrap();
        fs::write(self.config(), text).unwrap();
    }

    fn env_of(&self, cmd: &mut Command) {
        cmd.env("USERPROFILE", self.home())
            .env("HOME", self.home())
            .env("LOCALAPPDATA", self.home().join("AppData").join("Local"))
            .env("APPDATA", self.home().join("AppData").join("Roaming"))
            .env("SAIIFE_TEST_PIPE", &self.pipe)
            .env("SAIIFE_DATA_DIR", self.top.join("hookdata"))
            .env("SAIIFE_AUDIT_DIR", self.top.join("hookaudit"))
            .env("SAIIFE_TEST_SYSTEM_CONFIG", self.top.join("absent.toml"))
            .stdin(Stdio::null());
    }

    /// `saiife daemon --user` with the test environment.
    fn command(&self) -> Command {
        let mut cmd = Command::new(SAIIFE);
        cmd.args(["daemon", "--user", "--locked-marker"])
            .arg(self.locked_marker())
            .env("SAIIFE_TEST_KEYCHAIN", self.keychain_dir());
        self.env_of(&mut cmd);
        cmd
    }

    /// A CLI command with the broker's environment. No `--system-config`, so the resolver
    /// picks the personal broker, and `SAIIFE_TEST_SYSTEM_CONFIG` names an absent file.
    fn cli(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(SAIIFE);
        cmd.args(args)
            .current_dir(self.top.join("p"))
            .env_remove("SAIIFE_TEST_KEYCHAIN")
            .env_remove("SAIIFE_TEST_TRUST_SID");
        self.env_of(&mut cmd);
        cmd
    }

    fn run_cli(&self, args: &[&str]) -> Output {
        self.cli(args).output().unwrap()
    }

    /// Run the broker to its exit (for refusals), killed after 10 s.
    fn run_to_exit(&self, mut cmd: Command) -> Output {
        let mut child = cmd
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

    fn spawn(&mut self) {
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

    fn spawn_and_wait(&mut self) {
        self.spawn();
        let end = Instant::now() + Duration::from_secs(60);
        while self.try_client().is_err() {
            if Instant::now() > end {
                self.stop();
                panic!("broker did not come up in 60 s: {}", self.stderr_text());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    fn try_client(&self) -> Result<Client, ClientError> {
        Client::connect_pipe(&self.pipe, &me(), Instant::now() + Duration::from_secs(2))
    }

    fn call(&self, op: &str, args: Value) -> Result<Map<String, Value>, ClientError> {
        let Value::Object(args) = args else {
            panic!("args must be an object")
        };
        self.try_client().unwrap().call(op, args, dl())
    }

    /// Every line of the broker's audit log, parsed, in file order.
    fn records(&self) -> Vec<Value> {
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
            // The last line may still be being written.
            let done = text.rfind('\n').map_or("", |i| &text[..i]);
            for l in done.lines() {
                out.push(serde_json::from_str(l).unwrap());
            }
        }
        out
    }
}

impl Drop for TestBroker {
    fn drop(&mut self) {
        self.stop();
    }
}

fn add_secret(b: &TestBroker, name: &str, services: &[&str]) {
    b.call(
        "secret.add",
        json!({"name": name, "kind": "header", "fields": {"value": secret_value()},
               "allowed_services": services}),
    )
    .unwrap_or_else(|e| panic!("secret.add: {e:?}; {}", b.stderr_text()));
}

fn names(b: &TestBroker) -> Vec<String> {
    let l = b.call("secret.list", json!({})).unwrap();
    l["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap().to_string())
        .collect()
}

fn all_bytes_under(dir: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(dir) else {
        return out;
    };
    for e in rd {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(all_bytes_under(&p));
        } else if let Ok(b) = fs::read(&p) {
            out.extend(b);
        }
    }
    out
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn hello_mode_personal() {
    let b = TestBroker::start("hello");
    let c = b.try_client().unwrap();
    assert_eq!(c.hello_answer()["mode"], json!("personal"));
    let s = b.call("status", json!({})).unwrap();
    assert_eq!(s["mode"], json!("personal"));
}

#[test]
fn config_created_on_first_start() {
    let b = TestBroker::start("config");
    let text = fs::read_to_string(b.config()).unwrap();
    assert!(text.contains("version = 2"), "{text}");
    assert!(text.contains("not a security boundary"), "{text}");
    assert_eq!(b.call("status", json!({})).unwrap()["policy_ok"], true);
}

#[test]
fn secret_add_list_through_broker() {
    let b = TestBroker::start("secrets");
    add_secret(&b, "gh", &["github"]);
    assert_eq!(names(&b), ["gh"]);
    // The value is in neither the audit log nor the vault file.
    let audit = all_bytes_under(&b.audit_dir());
    assert!(!audit.is_empty());
    assert!(!contains(&audit, &secret_value()));
    let vault = fs::read(b.vault_file()).unwrap();
    assert!(!contains(&vault, &secret_value()));
    // The key is the test keychain's only item: the seam held, so nothing reached the
    // runner's Credential Manager.
    assert_eq!(fs::read_dir(b.keychain_dir()).unwrap().count(), 1);
}

#[test]
fn vault_survives_restart_same_key() {
    let mut b = TestBroker::start("restart");
    add_secret(&b, "gh", &["github"]);
    let item = |b: &TestBroker| {
        let p = fs::read_dir(b.keychain_dir())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        fs::read(p).unwrap()
    };
    let key = item(&b);
    b.stop();
    b.spawn_and_wait();
    assert_eq!(item(&b), key, "the vault key changed");
    assert_eq!(names(&b), ["gh"]);
}

#[test]
fn personal_without_keychain_serves_audit() {
    let mut b = TestBroker::prepare("nokey");
    // A file where the test keychain dir should be: the keychain errors.
    fs::write(b.keychain_dir(), b"not a dir").unwrap();
    b.spawn_and_wait();
    let e = b
        .call(
            "secret.add",
            json!({"name": "gh", "kind": "header", "fields": {"value": secret_value()},
                   "allowed_services": ["github"]}),
        )
        .unwrap_err();
    assert!(matches!(e, ClientError::Refused { .. }), "{e:?}");
    // Audit still works.
    assert!(b.call("status", json!({})).unwrap()["head_seq"].is_u64());
    assert!(!b.vault_file().exists());
}

#[test]
fn audit_chain_has_no_key_and_verifies() {
    let mut b = TestBroker::start("chain");
    add_secret(&b, "gh", &["github"]);
    b.stop();
    let recs = b.records();
    assert_eq!(recs[0]["kind"], "genesis", "{}", recs[0]);
    assert!(recs[0]["key"].is_null(), "{}", recs[0]);
    assert!(!recs.iter().any(|r| r["kind"] == "checkpoint"), "{recs:?}");
    let mut c = b.cli(&["audit", "verify", "--system-config"]);
    c.arg(b.top.join("absent.toml"))
        .env("SAIIFE_AUDIT_DIR", b.audit_dir());
    let o = c.output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}{}", out(&o), err(&o));
    // The label is the chain's own mode, not "developer mode".
    assert!(
        out(&o).contains("personal broker: no signing key, so this catches accidental edits"),
        "{}",
        out(&o)
    );
}

#[test]
fn user_refuses_path_flags() {
    let b = TestBroker::prepare("flags");
    for flag in ["--config", "--state-dir", "--credentials-dir"] {
        let mut cmd = b.command();
        cmd.arg(flag).arg(b.top.join("elsewhere"));
        let o = b.run_to_exit(cmd);
        assert_eq!(o.status.code(), Some(2), "{flag}: {}", err(&o));
        assert!(err(&o).contains(flag), "{flag}: {}", err(&o));
        assert!(!b.keychain_dir().exists());
        assert!(!b.top.join("elsewhere").exists());
    }
}

#[test]
fn personal_refused_as_locked_config() {
    let b = TestBroker::prepare("lockedcfg");
    b.write_config("version = 2\nlocked = true\n");
    let o = b.run_to_exit(b.command());
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
    assert!(err(&o).contains("locked = true"), "{}", err(&o));
    assert!(!b.keychain_dir().exists());
}

#[test]
fn personal_refused_on_locked_host() {
    let b = TestBroker::prepare("lockedhost");
    fs::write(b.locked_marker(), "installed = true\n").unwrap();
    let o = b.run_to_exit(b.command());
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
    assert!(err(&o).contains("locked mode"), "{}", err(&o));
    // Refused before the keychain was opened, which would have made its dir.
    assert!(!b.keychain_dir().exists());
}

#[test]
fn second_broker_refused_before_keychain() {
    let b = TestBroker::start("second");
    // A second broker of the same user, with a fresh keychain: refused by the state lock
    // before it reads or stores any key.
    let other = b.top.join("k2");
    let mut cmd = b.command();
    cmd.env("SAIIFE_TEST_KEYCHAIN", &other);
    let o = b.run_to_exit(cmd);
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
    assert!(err(&o).contains("another personal broker"), "{}", err(&o));
    let items = fs::read_dir(&other).map(|r| r.count()).unwrap_or(0);
    assert_eq!(items, 0);
    // The first broker still answers.
    assert!(b.call("status", json!({})).is_ok());
}

// ------------------------------------------------------------ the CLI's clients

/// No broker: the client says where it looked and how to start one, exit 5, and it does not
/// fall through to the system daemon.
#[test]
fn clients_without_a_broker_say_start_it() {
    let b = TestBroker::prepare("nobroker");
    let o = b.run_cli(&["secret", "list"]);
    assert_eq!(o.status.code(), Some(5), "{}", err(&o));
    assert!(
        err(&o).contains("cannot reach the personal broker"),
        "{}",
        err(&o)
    );
    assert!(err(&o).contains(&b.pipe), "{}", err(&o));
    assert!(err(&o).contains("saiife daemon --user"), "{}", err(&o));
}

#[test]
fn secret_add_list_rotate_remove_through_the_pipe() {
    let b = TestBroker::start("clisecret");
    let v1 = secret_value();
    let v2 = concat!("personal", "-rotated-", "value-", "0815").to_string();
    let f1 = b.top.join("v1");
    let f2 = b.top.join("v2");
    fs::write(&f1, &v1).unwrap();
    fs::write(&f2, &v2).unwrap();
    let add = b.run_cli(&[
        "secret",
        "add",
        "gh",
        "--kind",
        "token",
        "--service",
        "github",
        "--from-file",
        f1.to_str().unwrap(),
    ]);
    assert_eq!(add.status.code(), Some(0), "{}", err(&add));
    let list = b.run_cli(&["secret", "list", "--json"]);
    assert_eq!(list.status.code(), Some(0), "{}", err(&list));
    let v: Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(v["secrets"][0]["name"], "gh");
    assert_eq!(v["secrets"][0]["allowed_services"], json!(["github"]));
    let rot = b.run_cli(&[
        "secret",
        "rotate",
        "gh",
        "--from-file",
        f2.to_str().unwrap(),
    ]);
    assert_eq!(rot.status.code(), Some(0), "{}", err(&rot));
    let rm = b.run_cli(&["secret", "remove", "gh"]);
    assert_eq!(rm.status.code(), Some(0), "{}", err(&rm));
    assert!(names(&b).is_empty());
    for (o, value) in [(&add, &v1), (&list, &v1), (&rot, &v2), (&rm, &v2)] {
        assert!(!out(o).contains(value.as_str()), "stdout leaked the value");
        assert!(!err(o).contains(value.as_str()), "stderr leaked the value");
    }
    let audit = all_bytes_under(&b.audit_dir());
    assert!(!contains(&audit, &v1) && !contains(&audit, &v2));
}

#[test]
fn connect_writes_policy_and_secret_through_the_pipe() {
    let b = TestBroker::start("connect");
    let o = b
        .cli(&[
            "connect",
            "shopify",
            "--param",
            "shop=acme",
            "--from-env",
            "PB_TOKEN",
        ])
        .env("PB_TOKEN", secret_value())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    let file = b.personal_dir().join("policy.d").join("shopify.toml");
    assert!(out(&o).contains("added shopify"), "{}", out(&o));
    let text = fs::read_to_string(&file).unwrap();
    assert!(text.contains("[services.shopify]"), "{text}");
    assert_eq!(names(&b), ["shopify"]);
    assert!(!err(&o).contains(&secret_value()) && !out(&o).contains(&secret_value()));
    // The broker loads it.
    let r = b.run_cli(&["policy", "reload"]);
    assert_eq!(r.status.code(), Some(0), "{}{}", out(&r), err(&r));
}

#[test]
fn connect_without_config_says_start_broker() {
    let b = TestBroker::prepare("connectcold");
    let o = b
        .cli(&[
            "connect",
            "shopify",
            "--param",
            "shop=acme",
            "--from-env",
            "PB_TOKEN",
        ])
        .env("PB_TOKEN", secret_value())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(5), "{}", err(&o));
    assert!(
        err(&o).contains("start the broker first: saiife daemon --user"),
        "{}",
        err(&o)
    );
    assert!(!b.personal_dir().join("policy.d").exists());
}

#[test]
fn status_names_a_running_broker() {
    let b = TestBroker::start("status");
    let o = b.run_cli(&["status"]);
    assert!(out(&o).contains("personal broker: running"), "{}", out(&o));
}

/// Task 10's table: a system file on a tree that is not ours decides nothing, so the client
/// warns and goes on to the broker.
#[test]
fn a_planted_system_config_goes_to_the_broker() {
    let b = TestBroker::start("planted");
    let planted = b.top.join("planted.toml");
    fs::write(&planted, "version = 2\nlocked = true\n").unwrap();
    let o = b
        .cli(&["secret", "list"])
        .env("SAIIFE_TEST_SYSTEM_CONFIG", &planted)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert!(err(&o).contains("not protected"), "{}", err(&o));
}

/// A locked config wins, and a personal broker answering on the pipe is no locked daemon:
/// the hello's mode refuses it before any call.
#[test]
fn a_locked_host_never_uses_the_broker() {
    let b = TestBroker::start("lockedwins");
    let user = account::lookup_sid(&me()).unwrap();
    let audit = b.top.join("locked-audit");
    fs::create_dir(&audit).unwrap();
    let config = b.top.join("locked.toml");
    let text = format!(
        "version = 2\nlocked = true\n[daemon]\nuser = {user:?}\n[audit]\ndir = {:?}\nmin_free_mb = 0\n",
        audit.display().to_string()
    );
    fs::write(&config, text).unwrap();
    let o = b
        .cli(&["secret", "list"])
        .env("SAIIFE_TEST_SYSTEM_CONFIG", &config)
        .env("SAIIFE_TEST_TRUST_SID", me())
        .env(
            "SAIIFE_TEST_TRUST_BELOW",
            config.parent().unwrap().parent().unwrap(),
        )
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(5), "{}", err(&o));
    assert!(
        err(&o).contains("not the locked-mode daemon"),
        "{}",
        err(&o)
    );
}
