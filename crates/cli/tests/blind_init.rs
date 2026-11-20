//! `saiife blind init` and `saiife blind data add` (plan 48 T6) end to end:
//! a personal broker (`saiife daemon --user`) with every path in a temp
//! dir, a synthetic `crm` SQLite file (made-up Danish and English names
//! only), the pinned name-detector files and the fake detector, the
//! scripted planner (`SAIIFE_TEST_BLIND_PLANNER`), this `saiife` as the
//! calculator and the answers on a pipe (`SAIIFE_TEST_BLIND_STDIN=1`, debug
//! builds). No network, no real Postgres.
//!
//! The fake detector is `target/debug/saiife-fake-ner`: run
//! `cargo build -p saiife-shield-ner --features fake --bin saiife-fake-ner`
//! first.
#![cfg(target_os = "linux")]

mod common;

use common::blind::{fixture_sqlite, ner_policy, seams, NER_URLS};
use common::personal::TestBroker;
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::time::{Duration, Instant};

const MARKER: &str = "# written by saiife blind";
const ENTITY: &str = "customers:id:first_name+last_name:city:customer:kunde";
const SECRET: &str = "anthropic";
const NO_PIN: &str = "no name detector is pinned yet: pass --ner-model-url and --ner-model-sha256 (and vocab, labels); see docs/data-shield.md";
const NOT_ROOT: &str = "saiife blind init writes policy: run it as root (sudo saiife blind init)";

/// The test question's method: the planner counts the customers.
fn count_reply() -> String {
    json!({"method": "SELECT COUNT(*) AS n FROM customers c",
           "template": "There are {int(n)} customers.",
           "intent": "counts the customers"})
    .to_string()
}

struct W {
    b: TestBroker,
    pins: Vec<String>,
}

impl Drop for W {
    fn drop(&mut self) {
        self.b.stop();
    }
}

/// How the broker starts.
#[derive(Default, Clone, Copy)]
struct Opts {
    /// `[blind.ner]` (the pins) already in config.toml.
    ner_in_config: bool,
    /// A token secret allowing `blind-model` in the vault.
    secret: bool,
}

fn world(o: Opts, replies: &[String]) -> W {
    let mut b = TestBroker::prepare();
    let pins = seams(&mut b, replies);
    if o.ner_in_config {
        b.write_config(&ner_policy(&pins));
    } else {
        b.write_config("version = 2\n");
    }
    b.spawn_and_wait();
    let w = W { b, pins };
    if o.secret {
        w.add_secret(SECRET);
    }
    if o.ner_in_config {
        w.wait_ner("ready");
    }
    w
}

impl W {
    fn status(&self) -> Value {
        Value::Object(self.b.call("blind.status", json!({})).unwrap())
    }

    fn wait_ner(&self, want: &str) {
        let end = Instant::now() + Duration::from_secs(30);
        loop {
            let s = self.status();
            if s["ner"]["state"] == want {
                return;
            }
            assert!(Instant::now() < end, "ner is not {want}: {s}");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn add_secret(&self, name: &str) {
        let token = concat!("fake", "-planner-", "key-0000");
        self.b
            .call(
                "secret.add",
                json!({"name": name, "kind": "token", "fields": {"token": token},
                       "allowed_services": ["blind-model"]}),
            )
            .unwrap_or_else(|e| panic!("secret.add: {e:?}"));
    }

    /// The `crm` file: the fixture plus a `segment` category (3 values,
    /// many customers each) and, with `email`, a made-up email column.
    fn crm(&self, email: bool) -> PathBuf {
        let db = self.b.path().join("crm.sqlite");
        if !db.exists() {
            fixture_sqlite(&db, email);
            let c = rusqlite::Connection::open(&db).unwrap();
            c.execute_batch(
                "ALTER TABLE customers ADD COLUMN segment TEXT;
                 UPDATE customers SET segment = CASE id % 3 WHEN 0 THEN 'retail'
                     WHEN 1 THEN 'business' ELSE 'wholesale' END;",
            )
            .unwrap();
        }
        db
    }

    fn ner_flags(&self) -> Vec<String> {
        let mut v = Vec::new();
        for (i, part) in ["model", "vocab", "labels"].iter().enumerate() {
            v.push(format!("--ner-{part}-url"));
            v.push(NER_URLS[i].to_string());
            v.push(format!("--ner-{part}-sha256"));
            v.push(self.pins[i].clone());
        }
        v
    }

    /// `saiife blind <args>` with `stdin`; `seam` sets
    /// `SAIIFE_TEST_BLIND_STDIN=1`.
    fn blind(&self, args: &[String], stdin: &str, seam: bool) -> Output {
        let mut all = vec!["blind"];
        all.extend(args.iter().map(String::as_str));
        let mut cmd = self.b.cli(&all);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if seam {
            cmd.env("SAIIFE_TEST_BLIND_STDIN", "1");
        }
        let mut child = cmd.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    fn dropin_dir(&self) -> PathBuf {
        self.b.config_dir().join("policy.d")
    }

    fn crm_status(&self) -> Value {
        self.status()["datasets"]
            .as_array()
            .and_then(|l| l.iter().find(|d| d["name"] == "crm").cloned())
            .unwrap_or(Value::Null)
    }
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

fn text(o: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

fn toml_of(p: &Path) -> toml::Value {
    toml::from_str(&fs::read_to_string(p).unwrap()).unwrap()
}

fn class_of(p: &Path, column: &str) -> String {
    toml_of(p)["blind"]["dataset"][0]["columns"][column]["class"]
        .as_str()
        .unwrap_or_else(|| panic!("{column} has no class in {}", p.display()))
        .to_string()
}

#[test]
fn init_scripted_end_to_end() {
    let w = world(
        Opts {
            ner_in_config: false,
            secret: true,
        },
        &[count_reply()],
    );
    let db = w.crm(false);
    let mut args = s(&[
        "init",
        "--dataset",
        "crm",
        "--file",
        db.to_str().unwrap(),
        "--accept-guesses",
        "--entity",
        ENTITY,
        "--cloud-secret",
        SECRET,
        "--yes",
        "--show-sent",
    ]);
    args.extend(w.ner_flags());
    let o = w.blind(&args, "", false);
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    // --show-sent: the envelope the planner got, after the Test head.
    let test_at = out.find("6/6 Test").unwrap_or(0);
    assert!(out[test_at..].contains("── sent to the planner:"), "{out}");
    // The six steps, in order.
    let mut at = 0;
    for head in [
        "1/6 Data      crm.sqlite  →  2 tables",
        "2/6 Columns   ",
        "3/6 Models    name detector  m  sha256 ",
        "4/6 Cloud     Claude, API key in vault: anthropic ✓",
        "5/6 Rules     exact mode by default · k = 10 · preview before every run unless --yes · English, Danish",
        "6/6 Test      \"How many customers are there?\"",
        "Done. Ask with: saiife blind ask \"…\"",
    ] {
        let i = out[at..]
            .find(head)
            .unwrap_or_else(|| panic!("no {head:?} after byte {at}:\n{out}\n{err}"));
        at += i + head.len();
    }
    assert!(out.contains("Snapshot made."), "{out}");
    assert!(out.contains(" columns classified. "), "{out}");
    assert!(
        out.contains(
            "              sent to cloud:   schema + synthetic rows + 1 question, 0 personal values"
        ),
        "{out}"
    );
    assert!(
        out.contains(
            "              answer:          There are 123 customers. (checked: 1/1 numbers from the calculator)"
        ),
        "{out}"
    );
    assert!(out.contains("              method:          "), "{out}");
    // The policy files, each with the marker.
    let g = w.dropin_dir().join("blind.toml");
    let d = w.dropin_dir().join("blind-crm.toml");
    for p in [&g, &d] {
        let t = fs::read_to_string(p).unwrap();
        assert_eq!(t.lines().next(), Some(MARKER), "{t}");
    }
    let gt = toml_of(&g);
    assert_eq!(
        gt["blind"]["ner"]["model_sha256"].as_str(),
        Some(&*w.pins[0])
    );
    assert_eq!(gt["blind"]["cloud"]["secret"].as_str(), Some(SECRET));
    assert!(gt["blind"].get("dataset").is_none(), "{gt}");
    let dt = toml_of(&d);
    let ds = &dt["blind"]["dataset"][0];
    assert_eq!(ds["name"].as_str(), Some("crm"));
    assert_eq!(ds["source"]["kind"].as_str(), Some("sqlite"));
    assert_eq!(ds["source"]["file_name"].as_str(), Some("crm.sqlite"));
    assert_eq!(ds["entity"][0]["word"].as_str(), Some("customer"));
    assert_eq!(ds["entity"][0]["word_da"].as_str(), Some("kunde"));
    assert_eq!(class_of(&d, "customers.first_name"), "identifier");
    // Every column has its class written down.
    assert!(ds["columns"].as_table().unwrap().len() >= 9, "{dt}");
    // The daemon has it live.
    let st = w.crm_status();
    assert_eq!(st["state"], "live", "{st}");
    // One envelope went to the planner, holding no name.
    let ob = fs::read_dir(w.b.state_dir().join("blind/outbox"))
        .unwrap()
        .map(|e| fs::read_to_string(e.unwrap().path()).unwrap())
        .collect::<String>();
    assert_eq!(ob.lines().count(), 1, "{ob}");
    assert!(!ob.contains("Østergård") && !ob.contains("Anna"), "{ob}");
}

#[test]
fn init_interactive_columns() {
    let w = world(
        Opts {
            ner_in_config: true,
            secret: true,
        },
        &[],
    );
    let db = w.crm(true);
    let args = s(&[
        "init",
        "--dataset",
        "crm",
        "--file",
        db.to_str().unwrap(),
        "--cloud-secret",
        SECRET,
        "--skip-test",
    ]);
    // The uncertain columns in order (customers.segment,
    // invoices.customer_id, invoices.status): segment made public, the
    // other two kept; then email asked public (refused) and nothing more;
    // no aliases; the entity guess kept.
    let stdin = "public\n\n\ny\ncustomers.email\n\nn\n\n";
    let o = w.blind(&args, stdin, true);
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(out.contains(" columns classified. 3 need you:"), "{out}");
    assert!(
        err.contains("customers.segment") && err.contains("looks like: sensitive?"),
        "{err}"
    );
    assert!(err.contains("(3 of 3 values pass k = 10)"), "{err}");
    assert!(err.contains("Mark more columns public? (y/N) "), "{err}");
    assert!(
        err.contains("customers.email cannot be public: it holds names or IDs"),
        "{err}"
    );
    assert!(
        err.contains("Alias column names for the cloud? (y/N) "),
        "{err}"
    );
    assert!(
        err.contains("customers:id:first_name+last_name:city:customer:"),
        "{err}"
    );
    let d = w.dropin_dir().join("blind-crm.toml");
    assert_eq!(class_of(&d, "customers.segment"), "public");
    assert_eq!(class_of(&d, "customers.email"), "identifier");
    assert_eq!(class_of(&d, "invoices.status"), "public");
    assert_eq!(class_of(&d, "invoices.customer_id"), "sensitive");
    let dt = toml_of(&d);
    assert_eq!(
        dt["blind"]["dataset"][0]["entity"][0]["names"],
        toml::Value::Array(vec!["first_name".into(), "last_name".into()])
    );
    assert_eq!(w.crm_status()["state"], "live");
    assert!(!out.contains("6/6 Test      \""), "{out}");
}

#[test]
fn init_stops_without_ner_pin() {
    let w = world(
        Opts {
            ner_in_config: false,
            secret: true,
        },
        &[],
    );
    let db = w.crm(false);
    let o = w.blind(
        &s(&[
            "init",
            "--dataset",
            "crm",
            "--file",
            db.to_str().unwrap(),
            "--accept-guesses",
            "--entity",
            ENTITY,
            "--cloud-secret",
            SECRET,
            "--yes",
        ]),
        "",
        false,
    );
    let (out, err) = text(&o);
    assert_eq!(code(&o), 2, "{out}\n{err}");
    assert!(out.contains(NO_PIN) || err.contains(NO_PIN), "{out}\n{err}");
    assert!(!out.contains("4/6 Cloud"), "{out}");
    assert!(!w.dropin_dir().join("blind.toml").exists());
    assert!(!w.dropin_dir().join("blind-crm.toml").exists());
    assert_eq!(w.crm_status()["state"], Value::Null);
}

#[test]
fn init_stops_without_cloud_secret() {
    // The pins come from the flags, so Models writes blind.toml first:
    // the stop at Cloud puts it back (removes it).
    let w = world(
        Opts {
            ner_in_config: false,
            secret: false,
        },
        &[],
    );
    let db = w.crm(false);
    let mut args = s(&[
        "init",
        "--dataset",
        "crm",
        "--file",
        db.to_str().unwrap(),
        "--accept-guesses",
        "--entity",
        ENTITY,
        "--yes",
    ]);
    args.extend(w.ner_flags());
    let o = w.blind(&args, "", false);
    let (out, err) = text(&o);
    assert_eq!(code(&o), 2, "{out}\n{err}");
    assert!(out.contains("3/6 Models"), "{out}");
    assert!(
        out.contains("saiife secret add anthropic --kind token --service blind-model"),
        "{out}\n{err}"
    );
    assert!(!out.contains("5/6 Rules"), "{out}");
    assert!(!w.dropin_dir().join("blind.toml").exists());
    assert!(!w.dropin_dir().join("blind-crm.toml").exists());
    // The daemon has the policy it had: no name detector pinned.
    w.wait_ner("not configured");
}

#[test]
fn init_refuses_non_root_locked() {
    use std::os::unix::fs::MetadataExt;
    if fs::metadata("/proc/self").unwrap().uid() == 0 {
        return;
    }
    let tmp = common::tmp::short_tempdir();
    let cfg = tmp.path().join("config.toml");
    fs::write(
        &cfg,
        format!(
            "version = 2\nlocked = true\n\n[daemon]\nuser = {:?}\nsocket_dir = {:?}\n",
            common::daemon::own_user(),
            tmp.path().join("run").display().to_string()
        ),
    )
    .unwrap();
    let db = tmp.path().join("crm.sqlite");
    fixture_sqlite(&db, false);
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["blind", "--system-config"])
        .arg(&cfg)
        .args(["init", "--dataset", "crm", "--file"])
        .arg(&db)
        .args(["--accept-guesses", "--yes"])
        .env("HOME", tmp.path())
        .env("PATH", "/usr/bin:/bin")
        .env("XDG_RUNTIME_DIR", tmp.path().join("no-runtime"))
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let (out, err) = text(&o);
    assert_eq!(code(&o), 2, "{out}\n{err}");
    assert_eq!(err, format!("saiife: {NOT_ROOT}\n"));
    assert!(out.is_empty(), "{out}");
    assert!(!tmp.path().join("policy.d").exists());
}

#[test]
fn init_rolls_back_on_bad_reload() {
    let w = world(
        Opts {
            ner_in_config: true,
            secret: true,
        },
        &[],
    );
    let db = w.crm(false);
    // Another drop-in that does not load: the reload is rejected.
    let dir = w.dropin_dir();
    common::blind::private(&dir);
    let broken = dir.join("zz-broken.toml");
    fs::write(&broken, "[[[ not toml\n").unwrap();
    let o = w.blind(
        &s(&[
            "init",
            "--dataset",
            "crm",
            "--file",
            db.to_str().unwrap(),
            "--accept-guesses",
            "--entity",
            ENTITY,
            "--cloud-secret",
            SECRET,
            "--yes",
        ]),
        "",
        false,
    );
    let (out, err) = text(&o);
    assert_eq!(code(&o), 2, "{out}\n{err}");
    assert!(out.contains("5/6 Rules"), "{out}");
    assert!(err.contains("saiife: the policy did not load"), "{err}");
    assert!(err.contains("zz-broken.toml"), "{err}");
    assert!(!dir.join("blind-crm.toml").exists());
    assert!(!dir.join("blind.toml").exists());
    assert!(broken.exists());
    assert_eq!(w.crm_status()["state"], Value::Null);
}

#[test]
fn init_refuses_remote_postgres() {
    let w = world(
        Opts {
            ner_in_config: true,
            secret: true,
        },
        &[],
    );
    let o = w.blind(
        &s(&[
            "init",
            "--dataset",
            "crm",
            "--postgres-host",
            "db.example.test",
            "--postgres-db",
            "crm",
            "--postgres-user",
            "reader",
            "--postgres-password-secret",
            "pg",
            "--postgres-tables",
            "customers",
            "--yes",
        ]),
        "",
        false,
    );
    let (out, err) = text(&o);
    assert_eq!(code(&o), 2, "{out}\n{err}");
    assert!(
        err.contains("saiife: remote Postgres needs TLS, which is a later stage"),
        "{err}"
    );
    assert!(!w.dropin_dir().join("blind-crm.toml").exists());
}

#[test]
fn init_asks_for_the_identifier() {
    // `visits` holds a city (personal data) but no column that the
    // classifier takes for the person: the wizard asks which one is.
    let w = world(
        Opts {
            ner_in_config: true,
            secret: true,
        },
        &[],
    );
    let db = w.crm(false);
    let c = rusqlite::Connection::open(&db).unwrap();
    c.execute_batch("CREATE TABLE visits (visitor TEXT, city TEXT);")
        .unwrap();
    for i in 0..60 {
        c.execute(
            "INSERT INTO visits VALUES (?1, ?2)",
            rusqlite::params![format!("v{}", i % 40), ["Vejle", "Leeds"][i % 2]],
        )
        .unwrap();
    }
    drop(c);
    let base = s(&[
        "init",
        "--dataset",
        "crm",
        "--file",
        db.to_str().unwrap(),
        "--accept-guesses",
        "--entity",
        ENTITY,
        "--cloud-secret",
        SECRET,
        "--skip-test",
        "--yes",
    ]);
    // A script without the answer: refused, nothing written.
    let o = w.blind(&base, "", false);
    let (out, err) = text(&o);
    assert_eq!(code(&o), 2, "{out}\n{err}");
    assert!(
        err.contains("Which column identifies the person in visits?")
            && err.contains("--identifier visits:<column>"),
        "{err}"
    );
    assert!(!w.dropin_dir().join("blind-crm.toml").exists());
    // At the prompt.
    let o = w.blind(&base, "visitor\n", true);
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(
        err.contains("Which column identifies the person in visits? "),
        "{err}"
    );
    let d = w.dropin_dir().join("blind-crm.toml");
    assert_eq!(class_of(&d, "visits.visitor"), "identifier");
    assert_eq!(w.crm_status()["state"], "live");
    // The flag does the same for a script.
    let mut args = base.clone();
    args.extend(s(&["--identifier", "visits:visitor"]));
    let o = w.blind(&args, "", false);
    assert_eq!(code(&o), 0, "{:?}", text(&o));
}

#[test]
fn data_add_writes_and_commits() {
    let w = world(
        Opts {
            ner_in_config: true,
            secret: false,
        },
        &[],
    );
    let db = w.crm(false);
    let o = w.blind(
        &s(&[
            "data",
            "add",
            "--dataset",
            "crm",
            "--file",
            db.to_str().unwrap(),
            "--accept-guesses",
            "--entity",
            ENTITY,
            "--class",
            "invoices.customer_id=identifier",
            "--public",
            "customers.segment",
        ]),
        "",
        false,
    );
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(out.contains("1/2 Data      crm.sqlite"), "{out}");
    assert!(out.contains("crm is live"), "{out}");
    let d = w.dropin_dir().join("blind-crm.toml");
    assert_eq!(class_of(&d, "invoices.customer_id"), "identifier");
    assert_eq!(class_of(&d, "customers.segment"), "public");
    assert!(!w.dropin_dir().join("blind.toml").exists());
    assert_eq!(w.crm_status()["state"], "live");
    // A name or ID is never public, by flag either.
    let o = w.blind(
        &s(&[
            "data",
            "add",
            "--dataset",
            "crm2",
            "--file",
            db.to_str().unwrap(),
            "--accept-guesses",
            "--public",
            "customers.first_name",
        ]),
        "",
        false,
    );
    let (out, err) = text(&o);
    assert_eq!(code(&o), 2, "{out}\n{err}");
    assert!(
        err.contains("customers.first_name cannot be public: it holds names or IDs"),
        "{err}"
    );
    assert!(!w.dropin_dir().join("blind-crm2.toml").exists());
}

#[test]
fn rerun_keeps_the_dataset_settings() {
    // T6 review I1: a second init or data add keeps k, preview_required,
    // users, entities and classes; a loosening is refused.
    let w = world(
        Opts {
            ner_in_config: true,
            secret: true,
        },
        &[],
    );
    let db = w.crm(false);
    let me = common::daemon::own_user();
    let mut first = s(&[
        "init",
        "--dataset",
        "crm",
        "--file",
        db.to_str().unwrap(),
        "--accept-guesses",
        "--entity",
        ENTITY,
        "--cloud-secret",
        SECRET,
        "--k",
        "20",
        "--preview-required",
        "--class",
        "invoices.customer_id=identifier",
        "--skip-test",
        "--yes",
    ]);
    first.extend(s(&["--users", &me]));
    let o = w.blind(&first, "", false);
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    // The ruling: verbatim when the preview is required.
    assert!(
        out.contains(
            "5/6 Rules     exact mode by default · k = 20 · preview before every run · English, Danish"
        ),
        "{out}"
    );
    let d = w.dropin_dir().join("blind-crm.toml");
    let kept = |d: &Path| {
        let t = toml_of(d);
        let ds = t["blind"]["dataset"][0].clone();
        assert_eq!(ds["k"].as_integer(), Some(20), "{t}");
        assert_eq!(ds["preview_required"].as_bool(), Some(true), "{t}");
        assert_eq!(
            ds["users"],
            toml::Value::Array(vec![me.clone().into()]),
            "{t}"
        );
        assert_eq!(ds["entity"][0]["word_da"].as_str(), Some("kunde"), "{t}");
        assert_eq!(class_of(d, "invoices.customer_id"), "identifier");
    };
    kept(&d);
    // data add again, no flags: all kept.
    let add = s(&[
        "data",
        "add",
        "--dataset",
        "crm",
        "--file",
        db.to_str().unwrap(),
    ]);
    let o = w.blind(&add, "", false);
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(out.contains("None need you."), "{out}");
    kept(&d);
    // init again, no dataset flags: all kept, the preview still required.
    let o = w.blind(
        &s(&[
            "init",
            "--dataset",
            "crm",
            "--file",
            db.to_str().unwrap(),
            "--skip-test",
            "--yes",
        ]),
        "",
        false,
    );
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(
        out.contains("k = 20 · preview before every run · "),
        "{out}"
    );
    kept(&d);
    // A lower k, or a user added: refused, the file as it was.
    let before = fs::read(&d).unwrap();
    for extra in [vec!["--k", "5"], vec!["--users", "someone-else"]] {
        let mut args = add.clone();
        args.extend(s(&extra));
        let o = w.blind(&args, "", false);
        let (out, err) = text(&o);
        assert_eq!(code(&o), 2, "{out}\n{err}");
        assert!(
            err.contains("crm is in policy already, and ") && err.contains("would loosen it"),
            "{err}"
        );
        assert!(!out.contains("1/2 Data"), "{out}");
        assert_eq!(fs::read(&d).unwrap(), before);
    }
}
