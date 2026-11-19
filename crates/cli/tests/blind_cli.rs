//! `saiife blind ask | status | audit` end to end (plan 48 T4): a personal
//! broker (`saiife daemon --user`) with every path in a temp dir, a
//! synthetic `crm` dataset (made-up Danish and English names only) staged
//! and committed through the plan 47 ops, the scripted planner
//! (`SAIIFE_TEST_BLIND_PLANNER`), the fake name detector
//! (`SAIIFE_TEST_NER_HELPER` = `saiife-fake-ner`), this `saiife` as the
//! calculator (`SAIIFE_TEST_BLIND_CALC`) and the answers on a pipe
//! (`SAIIFE_TEST_BLIND_STDIN=1`, debug builds). No network: the planner
//! is a script.
//!
//! The fake detector is `target/debug/saiife-fake-ner`: run
//! `cargo build -p saiife-shield-ner --features fake --bin saiife-fake-ner`
//! first.
#![cfg(target_os = "linux")]

mod common;

use common::personal::{dl, TestBroker};
use serde_json::{json, Value};
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::time::{Duration, Instant};

const M_BAL: &str = "SELECT SUM(i.amount) AS owed, COUNT(*) AS n FROM invoices i \
    JOIN customers c ON c.id = i.customer_id WHERE c.id = :p1";
const T_BAL: &str = "{param(p1)} owes {money(owed, NOK)} across {int(n)} invoices.";

const Q_SOREN: &str = "What is the balance of Søren Østergård?";
const Q_ANNA: &str = "What is the balance of Anna Berg?";
const SOREN_ANSWER: &str = "Søren Østergård owes 600.00 NOK across 3 invoices.";
const ANNA_ANSWER: &str = "Anna Berg owes 1,500.50 NOK across 2 invoices.";
/// R48-3.
const NEEDS_ANSWER: &str =
    "the method preview needs an answer: run saiife blind ask in a terminal, or pass --yes";
const WEAKER: &str = "calculator not in a box (weaker)";

fn reply(intent: &str) -> String {
    json!({"method": M_BAL, "template": T_BAL, "intent": intent}).to_string()
}

fn balance() -> String {
    reply("sums the invoices of the customer")
}

const FIRST: &[&str] = &[
    "Mette", "Jens", "Lars", "Freja", "Mads", "Ida", "Niels", "Karen", "Emil", "Oliver", "Emma",
    "James", "Sophie", "Thomas", "Lucy",
];
const LAST: &[&str] = &[
    "Jensen", "Nielsen", "Hansen", "Pedersen", "Andersen", "Larsen", "Møller", "Smith",
];
const CITY: &[&str] = &["Aalborg", "Esbjerg", "London", "Leeds", "Vejle"];

/// The synthetic `crm`: customers 1 Søren Østergård (København), 2 Anna
/// Berg (Aarhus), 3 Anna Berg (Odense), then made-up names that are each
/// unique; every customer has invoices, both statuses held by many.
fn fixture_sqlite(path: &Path) {
    let c = rusqlite::Connection::open(path).unwrap();
    c.execute_batch(
        "CREATE TABLE customers (id INTEGER PRIMARY KEY, first_name TEXT, last_name TEXT, city TEXT);
         CREATE TABLE invoices (id INTEGER PRIMARY KEY, customer_id INTEGER, amount REAL, status TEXT);",
    )
    .unwrap();
    let mut people: Vec<(String, String, String)> = vec![
        ("Søren".into(), "Østergård".into(), "København".into()),
        ("Anna".into(), "Berg".into(), "Aarhus".into()),
        ("Anna".into(), "Berg".into(), "Odense".into()),
    ];
    for (i, l) in LAST.iter().enumerate() {
        for (j, f) in FIRST.iter().enumerate() {
            people.push((
                f.to_string(),
                l.to_string(),
                CITY[(i + j) % CITY.len()].to_string(),
            ));
        }
    }
    let mut inv = 1000;
    for (n, (f, l, city)) in people.iter().enumerate() {
        let id = n as i64 + 1;
        c.execute(
            "INSERT INTO customers VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![id, f, l, city],
        )
        .unwrap();
        let amounts: Vec<(f64, &str)> = match id {
            1 => vec![(100.0, "paid"), (200.0, "open"), (300.0, "open")],
            2 => vec![(1000.0, "open"), (500.5, "paid")],
            3 => vec![(42.0, "open")],
            _ => vec![(10.0 + id as f64, "paid"), (20.0 + id as f64, "open")],
        };
        for (a, st) in amounts {
            inv += 1;
            c.execute(
                "INSERT INTO invoices VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![inv, id, a, st],
            )
            .unwrap();
        }
    }
}

/// `[blind.ner]` pinning the three files the test wrote, then `crm`.
fn policy(pins: &[String], extra: &str) -> String {
    format!(
        "version = 2\n\n[blind.ner]\nmodel_url = \"https://ner.example.test/m\"\nmodel_sha256 = \"{}\"\n\
         vocab_url = \"https://ner.example.test/v\"\nvocab_sha256 = \"{}\"\n\
         labels_url = \"https://ner.example.test/l\"\nlabels_sha256 = \"{}\"\n\n\
         [[blind.dataset]]\nname = \"crm\"\n\
         source = {{ kind = \"sqlite\", file_name = \"crm.sqlite\" }}\n{extra}\n\
         [blind.dataset.columns]\n\
         \"customers.id\" = {{ class = \"identifier\" }}\n\
         \"customers.first_name\" = {{ class = \"identifier\" }}\n\
         \"customers.last_name\" = {{ class = \"identifier\" }}\n\
         \"customers.city\" = {{ class = \"quasi\" }}\n\
         \"invoices.id\" = {{ class = \"identifier\" }}\n\
         \"invoices.customer_id\" = {{ class = \"identifier\" }}\n\
         \"invoices.amount\" = {{ class = \"sensitive\" }}\n\
         \"invoices.status\" = {{ class = \"public\" }}\n\n\
         [[blind.dataset.entity]]\ntable = \"customers\"\nkey = \"id\"\n\
         names = [\"first_name\", \"last_name\"]\nshow = [\"city\"]\n\
         word = \"customer\"\nword_da = \"kunde\"\n",
        pins[0], pins[1], pins[2]
    )
}

/// `target/debug/saiife-fake-ner`, beside this test's binary dir.
fn fake_ner() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let p = exe
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("saiife-fake-ner");
    assert!(
        p.is_file(),
        "{} is missing: run `cargo build -p saiife-shield-ner --features fake --bin saiife-fake-ner` first",
        p.display()
    );
    p
}

fn private(p: &Path) {
    fs::create_dir_all(p).unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
}

struct Fx {
    b: TestBroker,
}

impl Drop for Fx {
    fn drop(&mut self) {
        self.b.stop();
    }
}

/// A broker with `crm` live, the detector ready and `replies` as the
/// planner's script.
fn fx(replies: &[String]) -> Fx {
    fx_with(replies, "")
}

fn fx_with(replies: &[String], extra: &str) -> Fx {
    use sha2::{Digest, Sha256};
    let mut b = TestBroker::prepare();
    // The NER files, pinned by sha256 (R-C8), where a fetch would put them.
    for d in ["s/saiife", "s/saiife/broker", "s/saiife/broker/blind"] {
        private(&b.path().join(d));
    }
    let models = b.state_dir().join("blind/models");
    private(&models);
    let mut pins = Vec::new();
    for x in [&b"model"[..], b"vocab", b"labels"] {
        let h = format!("{:x}", Sha256::digest(x));
        fs::write(models.join(&h), x).unwrap();
        pins.push(h);
    }
    // The fake detector: one made-up stranger is a person.
    let helper_dir = b.path().join("ner");
    private(&helper_dir);
    let phrases = helper_dir.join("phrases.txt");
    fs::write(&phrases, "PER\tZed Quorra\n").unwrap();
    let helper = helper_dir.join("ner");
    fs::write(
        &helper,
        format!(
            "#!/bin/sh\nexec '{}' --phrases '{}'\n",
            fake_ner().display(),
            phrases.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
    let script = b.path().join("planner.txt");
    fs::write(&script, replies.join("\n") + "\n").unwrap();
    let seams: [(&str, OsString); 3] = [
        ("SAIIFE_TEST_NER_HELPER", helper.into()),
        ("SAIIFE_TEST_BLIND_PLANNER", script.into()),
        (
            "SAIIFE_TEST_BLIND_CALC",
            env!("CARGO_BIN_EXE_saiife").into(),
        ),
    ];
    for (k, v) in seams {
        b.env.push((k.to_string(), Some(v)));
    }
    b.write_config(&policy(&pins, extra));
    b.spawn_and_wait();
    let f = Fx { b };
    f.wait_ner_ready();
    f.load_crm();
    f
}

impl Fx {
    fn status(&self) -> Value {
        Value::Object(self.b.call("blind.status", json!({})).unwrap())
    }

    fn wait_ner_ready(&self) {
        let end = Instant::now() + Duration::from_secs(30);
        loop {
            let s = self.status();
            if s["ner"]["state"] == "ready" {
                return;
            }
            assert!(
                Instant::now() < end,
                "the name detector did not come up: {s}\n{}",
                self.b.stderr_text()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Stage (the file passed as a descriptor) and commit `crm`.
    fn load_crm(&self) {
        let db = self.b.path().join("crm.sqlite");
        fixture_sqlite(&db);
        let file = fs::File::open(&db).unwrap();
        let mut c = self.b.client();
        let args = json!({"dataset": "crm", "kind": "sqlite", "file_name": "crm.sqlite"});
        let Value::Object(args) = args else {
            unreachable!()
        };
        c.call_with_fds("blind.data.stage", args, &[file.as_fd()], dl())
            .unwrap_or_else(|e| panic!("stage: {e}"));
        let r = self.b.call("blind.data.commit", json!({"dataset": "crm"}));
        assert!(r.is_ok(), "commit: {r:?}");
        let end = Instant::now() + Duration::from_secs(60);
        loop {
            let s = self.status();
            if s["datasets"][0]["state"] == "live" {
                return;
            }
            assert!(Instant::now() < end, "crm is not live: {s}");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// `saiife blind <args>` with `stdin` as its input; `seam` sets
    /// `SAIIFE_TEST_BLIND_STDIN=1`.
    fn blind(&self, args: &[&str], stdin: &str, seam: bool) -> Output {
        let mut all = vec!["blind"];
        all.extend_from_slice(args);
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

    fn outbox(&self) -> Vec<Value> {
        let dir = self.b.state_dir().join("blind/outbox");
        let mut out = Vec::new();
        let Ok(rd) = fs::read_dir(&dir) else {
            return out;
        };
        for e in rd {
            let text = fs::read_to_string(e.unwrap().path()).unwrap();
            out.extend(
                text.lines()
                    .map(|l| serde_json::from_str::<Value>(l).unwrap()),
            );
        }
        out
    }
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

#[test]
fn ask_pick_preview_answer() {
    let f = fx(&[balance()]);
    let o = f.blind(&["ask", Q_ANNA], "1\ny\n", true);
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    // The pick list and the preview on stderr, never a key.
    assert!(err.contains("Found 2 customers named Anna Berg:"), "{err}");
    assert!(err.contains("  1) Anna Berg, Aarhus"), "{err}");
    assert!(err.contains("  2) Anna Berg, Odense"), "{err}");
    assert!(err.contains("Which one? "), "{err}");
    assert!(err.contains("Run it? (Y/n) "), "{err}");
    assert!(
        err.contains("the planner says: sums the invoices of the customer"),
        "{err}"
    );
    // R48-4 on stdout: the answer, the method line, the footer.
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], ANNA_ANSWER, "{out}");
    assert!(lines[1].starts_with("── method: "), "{out}");
    assert_eq!(
        lines[2], "── exact · new method · 0 personal values sent · 2/2 numbers checked",
        "{out}"
    );
    // Personal mode: the own user approves, so the hint is shown.
    assert!(
        err.contains("approve this method for reuse: saiife blind methods approve "),
        "{err}"
    );
}

#[test]
fn ask_without_terminal_refuses() {
    let f = fx(&[balance()]);
    let o = f.blind(&["ask", Q_SOREN], "y\n", false);
    let (out, err) = text(&o);
    assert_eq!(code(&o), 2, "{out}\n{err}");
    assert_eq!(err.trim_end(), format!("saiife: {NEEDS_ANSWER}"));
    assert!(out.is_empty(), "{out}");
    // Refused before anything was sent.
    assert!(f.outbox().is_empty());
}

#[test]
fn ask_yes_answers() {
    let f = fx(&[balance()]);
    let o = f.blind(&["ask", "--yes", Q_SOREN], "", false);
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], SOREN_ANSWER, "{out}");
    assert!(lines[1].starts_with("── method: "), "{out}");
    assert!(
        lines[2].starts_with("── exact · new method · 0 personal values sent"),
        "{out}"
    );
    // No envelope without --show-sent.
    assert!(!out.contains("sent to the planner"), "{out}");
    assert_eq!(f.outbox().len(), 1);
    // A pick needs a terminal even with --yes: the count only.
    let o = f.blind(&["ask", "--yes", Q_ANNA], "", false);
    let (out, err) = text(&o);
    assert_eq!(code(&o), 2, "{out}\n{err}");
    assert!(
        err.contains("Found 2 customers named Anna Berg: choosing one needs a terminal"),
        "{err}"
    );
    assert!(!err.contains("Aarhus") && !err.contains("Odense"), "{err}");
}

#[test]
fn ask_judgment_says_later_stage() {
    let f = fx(&[balance()]);
    let o = f.blind(&["ask", "--judgment", "--yes", Q_SOREN], "", false);
    let (out, err) = text(&o);
    assert_eq!(code(&o), 2, "{out}\n{err}");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "refused, nothing sent", "{out}");
    assert_eq!(
        lines[1],
        "this question needs judgment, which needs the local composer (a later stage); exact mode cannot answer it",
        "{out}"
    );
    assert!(f.outbox().is_empty());
}

#[test]
fn ask_show_sent_prints_envelope() {
    let f = fx(&[balance()]);
    let o = f.blind(&["ask", "--yes", "--show-sent", Q_SOREN], "", false);
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "── sent to the planner:", "{out}");
    let printed: Value = serde_json::from_str(lines[1]).unwrap();
    let ob = f.outbox();
    assert_eq!(ob.len(), 1);
    let body: Value = serde_json::from_str(ob[0]["body"].as_str().unwrap()).unwrap();
    let sent: Value =
        serde_json::from_str(body["messages"][0]["content"].as_str().unwrap()).unwrap();
    assert_eq!(printed, sent);
    assert_eq!(lines[2], SOREN_ANSWER, "{out}");
    // The envelope holds stand-ins, never the name.
    assert!(
        !lines[1].contains("Østergård") && !lines[1].contains("\\u00d8"),
        "{}",
        lines[1]
    );
}

#[test]
fn status_prints_weaker_label() {
    let f = fx(&[]);
    let o = f.blind(&["status"], "", false);
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    let lines: Vec<&str> = out.lines().collect();
    assert!(
        lines[0].starts_with(&format!("calculator: {WEAKER}")),
        "{out}"
    );
    assert!(out.contains("name detector: ready"), "{out}");
    assert!(out.contains("cloud planner: "), "{out}");
    assert!(out.contains("dataset crm: live"), "{out}");
    assert!(out.contains("  your role: admin, approver, user"), "{out}");
    let o = f.blind(&["status", "--json"], "", false);
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["calculator"]["label"], WEAKER);
    assert_eq!(v["datasets"][0]["name"], "crm");
}

#[test]
fn audit_groups_by_ask() {
    let f = fx(&[balance(), balance()]);
    assert_eq!(code(&f.blind(&["ask", "--yes", Q_SOREN], "", false)), 0);
    assert_eq!(code(&f.blind(&["ask", Q_ANNA], "2\nn\n", true)), 2);
    let o = f.blind(&["audit"], "", false);
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    let heads: Vec<&str> = out.lines().filter(|l| l.starts_with("ask ")).collect();
    assert_eq!(heads.len(), 2, "{out}");
    for h in &heads {
        assert!(h.ends_with("  crm"), "{h}");
    }
    let sends: Vec<&str> = out
        .lines()
        .filter(|l| l.starts_with("  sent envelope sha256:"))
        .collect();
    assert_eq!(sends.len(), 2, "{out}");
    assert!(
        sends.iter().all(|l| l.ends_with("· 0 personal values")),
        "{out}"
    );
    assert!(out.contains("  answered (checked)"), "{out}");
    assert!(out.contains("  refused: stopped"), "{out}");
    // The JSON groups the same, and never holds a name or an amount.
    let o = f.blind(&["audit", "--json"], "", false);
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["asks"].as_array().unwrap().len(), 2);
    let raw = String::from_utf8_lossy(&o.stdout);
    for leak in ["Anna", "Berg", "Søren", "S\\u00f8ren", "1,500.50", "600.00"] {
        assert!(!raw.contains(leak), "{leak} in {raw}");
    }
    // `--sent` shows that body from the outbox.
    let ob = f.outbox();
    let sha = ob[0]["sha256"].as_str().unwrap();
    let o = f.blind(&["audit", "--sent", sha], "", false);
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    let body: Value = serde_json::from_str(ob[0]["body"].as_str().unwrap()).unwrap();
    let printed: Value = serde_json::from_str(out.lines().nth(1).unwrap()).unwrap();
    assert_eq!(printed, body);
}

#[test]
fn audit_user_needs_auditor() {
    let f = fx(&[]);
    let o = f.blind(&["audit", "--user", "someone"], "", false);
    let (out, err) = text(&o);
    assert_eq!(code(&o), 2, "{out}\n{err}");
    assert_eq!(
        err.trim_end(),
        "saiife: audit.query with all is for root and the saiife-audit group"
    );
    assert!(out.is_empty(), "{out}");
}

#[test]
fn daemon_text_is_sanitized() {
    // The planner's intent line (cloud text) with a terminal escape.
    let f = fx(&[reply("sums the invoices \u{1b}[m of the customer")]);
    let o = f.blind(&["ask", Q_SOREN], "y\n", true);
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(
        err.contains("the planner says: sums the invoices \\x1b[m of the customer"),
        "{err}"
    );
    assert!(!err.contains('\u{1b}') && !out.contains('\u{1b}'), "{err}");
}

/// A soft key file for the `SAIIFE_TEST_TOUCH_SOFT` seam (debug builds).
fn soft_key(p: &Path) -> PathBuf {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    let (_, pkcs8, id, counter) = saiife_touch::soft::SoftAuthenticator::new_es256().parts();
    let f = json!({
        "alg": "es256",
        "pkcs8": URL_SAFE_NO_PAD.encode(pkcs8),
        "credential_id": URL_SAFE_NO_PAD.encode(id),
        "counter": counter,
    });
    fs::write(p, f.to_string()).unwrap();
    p.to_path_buf()
}

#[test]
fn ask_keep_name_takes_a_touch() {
    const M_COUNT: &str = "SELECT COUNT(*) AS n FROM customers c";
    const T_COUNT: &str = "There are {int(n)} customers.";
    let f = fx(&[
        json!({"method": M_COUNT, "template": T_COUNT, "intent": "counts the customers"})
            .to_string(),
    ]);
    let key = soft_key(&f.b.path().join("soft.json"));
    let o =
        f.b.cli(&["touch", "enrol", "--label", "k1"])
            .env("SAIIFE_TEST_TOUCH_SOFT", &key)
            .output()
            .unwrap();
    assert_eq!(code(&o), 0, "{:?}", text(&o));
    let mut cmd =
        f.b.cli(&["blind", "ask", "What is the balance of Zed Quorra?"]);
    cmd.env("SAIIFE_TEST_BLIND_STDIN", "1")
        .env("SAIIFE_TEST_TOUCH_SOFT", &key)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"y\ny\n").unwrap();
    let o = child.wait_with_output().unwrap();
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(
        err.contains(
            "\"Zed Quorra\" is not in crm. Send it as plain text to the planner? This needs a touch (blind:name). (y/N) "
        ),
        "{err}"
    );
    assert!(
        err.contains(
            "saiife: touch your key to keep \"Zed Quorra\" as plain text in a question about crm (code "
        ),
        "{err}"
    );
    assert_eq!(
        out.lines().next(),
        Some("There are 123 customers."),
        "{out}"
    );
    // Kept as plain text: in the envelope the planner saw.
    let ob = f.outbox();
    assert_eq!(ob.len(), 1);
    assert!(ob[0]["body"].as_str().unwrap().contains("Zed Quorra"));
    // A no keeps nothing and sends nothing.
    let o = f.blind(&["ask", "What is the balance of Zed Quorra?"], "n\n", true);
    let (out, err) = text(&o);
    assert_eq!(code(&o), 2, "{out}\n{err}");
    assert!(out.starts_with("refused, nothing sent\n"), "{out}");
    assert_eq!(f.outbox().len(), 1);
}
