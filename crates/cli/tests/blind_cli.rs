//! `saiife blind ask | status | audit` (plan 48 T4) and `keys | methods |
//! data` (T5) end to end: a personal
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

use common::blind::{fixture_sqlite, ner_policy, private, seams};
use common::personal::{dl, TestBroker};
use serde_json::{json, Value};
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

/// The `crm` dataset (with `email`: its column, Identifier-class).
fn dataset_policy(extra: &str, email: bool) -> String {
    let email = if email {
        "\"customers.email\" = { class = \"identifier\" }\n"
    } else {
        ""
    };
    format!(
        "[[blind.dataset]]\nname = \"crm\"\n\
         source = {{ kind = \"sqlite\", file_name = \"crm.sqlite\" }}\n{extra}\n\
         [blind.dataset.columns]\n\
         \"customers.id\" = {{ class = \"identifier\" }}\n\
         \"customers.first_name\" = {{ class = \"identifier\" }}\n\
         \"customers.last_name\" = {{ class = \"identifier\" }}\n\
         \"customers.city\" = {{ class = \"quasi\" }}\n{email}\
         \"invoices.id\" = {{ class = \"identifier\" }}\n\
         \"invoices.customer_id\" = {{ class = \"identifier\" }}\n\
         \"invoices.amount\" = {{ class = \"sensitive\" }}\n\
         \"invoices.status\" = {{ class = \"public\" }}\n\n\
         [[blind.dataset.entity]]\ntable = \"customers\"\nkey = \"id\"\n\
         names = [\"first_name\", \"last_name\"]\nshow = [\"city\"]\n\
         word = \"customer\"\nword_da = \"kunde\"\n"
    )
}

/// The first line of the drop-ins `saiife blind` writes.
const MARKER: &str = "# written by saiife blind";

/// How the fixture is laid out.
#[derive(Default, Clone, Copy)]
struct Opts {
    /// `crm` in `policy.d/blind-crm.toml` instead of `config.toml`; `true`
    /// with the marker (as `saiife blind` writes it), `false` without (a
    /// hand-written file).
    dropin: Option<bool>,
    /// customers have an `email` column.
    email: bool,
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
    fx_opts(replies, extra, Opts::default())
}

fn fx_opts(replies: &[String], extra: &str, o: Opts) -> Fx {
    let mut b = TestBroker::prepare();
    let pins = seams(&mut b, replies);
    match o.dropin {
        None => b.write_config(&format!(
            "{}{}",
            ner_policy(&pins),
            dataset_policy(extra, o.email)
        )),
        Some(marker) => {
            b.write_config(&ner_policy(&pins));
            let dir = b.config_dir().join("policy.d");
            private(&dir);
            let head = if marker {
                MARKER
            } else {
                "# my own crm policy"
            };
            let p = dir.join("blind-crm.toml");
            fs::write(&p, format!("{head}\n{}", dataset_policy(extra, o.email))).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    b.spawn_and_wait();
    let f = Fx { b };
    f.wait_ner_ready();
    f.load_crm(o.email);
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
    fn load_crm(&self, email: bool) {
        let db = self.b.path().join("crm.sqlite");
        fixture_sqlite(&db, email);
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
        self.blind_key(args, stdin, seam, None)
    }

    /// [`Fx::blind`] with `key` as the touch key (`SAIIFE_TEST_TOUCH_SOFT`).
    fn blind_key(&self, args: &[&str], stdin: &str, seam: bool, key: Option<&Path>) -> Output {
        let mut all = vec!["blind"];
        all.extend_from_slice(args);
        let mut cmd = self.b.cli(&all);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if seam {
            cmd.env("SAIIFE_TEST_BLIND_STDIN", "1");
        }
        if let Some(k) = key {
            cmd.env("SAIIFE_TEST_TOUCH_SOFT", k);
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

// ------------------------------------------------- keys, methods, data ----

/// A soft key enrolled for the broker's user (`saiife touch enrol`).
fn enrol(f: &Fx, name: &str) -> PathBuf {
    let key = soft_key(&f.b.path().join(name));
    let o =
        f.b.cli(&["touch", "enrol", "--label", name])
            .env("SAIIFE_TEST_TOUCH_SOFT", &key)
            .output()
            .unwrap();
    assert_eq!(code(&o), 0, "{:?}", text(&o));
    key
}

fn crm_status(f: &Fx) -> Value {
    f.status()["datasets"][0].clone()
}

fn dropin(f: &Fx) -> PathBuf {
    f.b.config_dir().join("policy.d/blind-crm.toml")
}

/// The class of `column` in `policy.d/blind-crm.toml`.
fn dropin_class(f: &Fx, column: &str) -> String {
    let t: toml::Value = toml::from_str(&fs::read_to_string(dropin(f)).unwrap()).unwrap();
    t["blind"]["dataset"][0]["columns"][column]["class"]
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn keys_rotate_with_soft_key() {
    let f = fx(&[]);
    let key = enrol(&f, "k1");
    assert_eq!(crm_status(&f)["keys_version"], 1);
    let o = f.blind_key(&["keys", "rotate"], "", false, Some(&key));
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(
        err.contains("saiife: touch your key to rotate the stand-in key of crm (code "),
        "{err}"
    );
    assert_eq!(out, "rotated the stand-in key of crm: version 2\n");
    assert_eq!(crm_status(&f)["keys_version"], 2);
    // Without a key enrolled for the touch: nothing rotated.
    let other = soft_key(&f.b.path().join("other.json"));
    let o = f.blind_key(
        &["keys", "rotate", "--dataset", "crm"],
        "",
        false,
        Some(&other),
    );
    assert_ne!(code(&o), 0, "{:?}", text(&o));
    assert_eq!(crm_status(&f)["keys_version"], 2);
}

#[test]
fn keys_delete_confirms_name() {
    let f = fx(&[]);
    let key = enrol(&f, "k1");
    // A wrong name: nothing done, no touch asked.
    let o = f.blind_key(
        &["keys", "delete", "--dataset", "crm"],
        "crn\n",
        true,
        Some(&key),
    );
    let (out, err) = text(&o);
    assert_eq!(code(&o), 2, "{out}\n{err}");
    assert!(
        err.contains("This deletes the stand-in keys of crm: its stand-ins can never be linked back to anyone, and it needs a refresh. Type the dataset name to go on: "),
        "{err}"
    );
    assert!(
        err.contains("saiife: that is not crm; nothing was done"),
        "{err}"
    );
    assert!(!err.contains("touch your key"), "{err}");
    assert!(out.is_empty(), "{out}");
    // No terminal: refused before anything.
    let o = f.blind_key(
        &["keys", "delete", "--dataset", "crm"],
        "crm\n",
        false,
        Some(&key),
    );
    assert_eq!(code(&o), 2, "{:?}", text(&o));
    let s = crm_status(&f);
    assert_eq!(s["keys_version"], 1, "{s}");
    assert_eq!(s["state"], "live", "{s}");
    // The name typed, then the touch: the keys are gone.
    let o = f.blind_key(
        &["keys", "delete", "--dataset", "crm"],
        "crm\n",
        true,
        Some(&key),
    );
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(
        err.contains("saiife: touch your key to delete the keys of crm"),
        "{err}"
    );
    assert_eq!(
        out,
        "deleted the stand-in keys of crm\nit needs a refresh: saiife blind data refresh --dataset crm\n"
    );
    let s = crm_status(&f);
    assert_eq!(s["state"], "needs_refresh", "{s}");
    assert!(s["keys_version"].is_null(), "{s}");
}

#[test]
fn methods_ls_approve_rm() {
    let f = fx(&[balance()]);
    let key = enrol(&f, "k1");
    let o = f.blind(&["methods", "ls"], "", false);
    assert_eq!(code(&o), 0, "{:?}", text(&o));
    assert_eq!(text(&o).0, "no approved methods for crm\n");
    // An answered ask; the hint names it.
    let o = f.blind(&["ask", "--yes", Q_SOREN], "", false);
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    let hint = "approve this method for reuse: saiife blind methods approve ";
    let ask = err
        .lines()
        .find_map(|l| l.strip_prefix(hint))
        .unwrap_or_else(|| panic!("no hint in {err}"))
        .to_string();
    let o = f.blind_key(&["methods", "approve", &ask], "", false, Some(&key));
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(
        err.contains("saiife: touch your key to approve for reuse: "),
        "{err}"
    );
    let id = out
        .strip_prefix("approved method ")
        .and_then(|r| r.strip_suffix(" (version 1) for reuse\n"))
        .unwrap_or_else(|| panic!("{out}"))
        .to_string();
    assert!(id.starts_with("m-"), "{id}");
    // `ls` shows it: metadata, never the method's text.
    let o = f.blind(&["methods", "ls", "--dataset", "crm"], "", false);
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 2, "{out}");
    assert!(
        lines[0].starts_with(&format!("{id}  v1  en  active  approved by ")),
        "{out}"
    );
    assert!(lines[1].starts_with("  template \""), "{out}");
    assert!(!out.contains("SELECT"), "{out}");
    // `rm` removes it.
    let o = f.blind_key(&["methods", "rm", &id], "", false, Some(&key));
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(
        err.contains(&format!(
            "saiife: touch your key to remove approved method {id}"
        )),
        "{err}"
    );
    assert_eq!(out, format!("removed approved method {id} from crm\n"));
    let o = f.blind(&["methods", "ls"], "", false);
    assert_eq!(text(&o).0, "no approved methods for crm\n");
}

#[test]
fn data_refresh_progress_then_live() {
    let f = fx(&[]);
    let before = crm_status(&f)["built_at"].clone();
    let db = f.b.path().join("crm.sqlite");
    let o = f.blind(
        &["data", "refresh", "--file", db.to_str().unwrap()],
        "",
        false,
    );
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(err.starts_with("refreshing crm\n"), "{err}");
    assert_eq!(out.lines().next(), Some("crm is live"), "{out}");
    let s = crm_status(&f);
    assert_eq!(s["state"], "live", "{s}");
    assert!(s["built_at"].is_string() && before.is_string(), "{s}");
    // No terminal and no --file: refused before anything.
    let o = f.blind(&["data", "refresh", "--dataset", "crm"], "", false);
    let (out, err) = text(&o);
    assert_eq!(code(&o), 2, "{out}\n{err}");
    assert!(
        err.contains("the refresh of crm reads its source file: pass --file <path>"),
        "{err}"
    );
    // The file asked for at the prompt.
    let o = f.blind(&["data", "refresh"], &format!("{}\n", db.display()), true);
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(
        err.contains("The source file of crm (crm.sqlite): "),
        "{err}"
    );
    assert_eq!(out.lines().next(), Some("crm is live"), "{out}");
    // A file that is not the dataset's: the refresh fails, and the wait
    // ends with the daemon's reason (the old build stays live).
    let junk = f.b.path().join("junk.sqlite");
    fs::write(&junk, "not a database").unwrap();
    let o = f.blind(
        &["data", "refresh", "--file", junk.to_str().unwrap()],
        "",
        false,
    );
    let (out, err) = text(&o);
    assert_eq!(code(&o), 5, "{out}\n{err}");
    assert!(err.contains("saiife: the refresh of crm failed: "), "{err}");
    assert!(out.is_empty(), "{out}");
    assert_eq!(crm_status(&f)["state"], "live");
    // A missing file: refused, nothing sent.
    let o = f.blind(
        &["data", "refresh", "--file", "/nonexistent/crm.sqlite"],
        "",
        false,
    );
    assert_eq!(code(&o), 2, "{:?}", text(&o));
}

/// Plan 48 C5 (D51-4): a refresh whose new data repeats an entity key
/// fails with the fixed reason (names and a count, no value); the old
/// build stays live.
#[test]
fn data_refresh_prints_the_repeated_key_reason() {
    let f = fx(&[]);
    let before = crm_status(&f)["snapshot_sha256"].clone();
    let dup = f.b.path().join("dup.sqlite");
    fs::copy(f.b.path().join("crm.sqlite"), &dup).unwrap();
    let c = rusqlite::Connection::open(&dup).unwrap();
    // The fixture's `id` is a primary key: copy the table without it.
    c.execute_batch(
        "CREATE TABLE c2 AS SELECT * FROM customers; DROP TABLE customers; \
         ALTER TABLE c2 RENAME TO customers; \
         UPDATE customers SET id = (SELECT MIN(id) FROM customers) \
         WHERE id = (SELECT MAX(id) FROM customers);",
    )
    .unwrap();
    drop(c);
    let o = f.blind(
        &["data", "refresh", "--file", dup.to_str().unwrap()],
        "",
        false,
    );
    let (out, err) = text(&o);
    assert_eq!(code(&o), 5, "{out}\n{err}");
    let want = saiife_shield::error::repeated_key_reason("customers", "id", 2);
    assert!(
        err.contains(&format!("saiife: the refresh of crm failed: {want}")),
        "{err}"
    );
    assert!(out.is_empty(), "{out}");
    let s = crm_status(&f);
    assert_eq!(s["state"], "live", "{s}");
    assert_eq!(s["snapshot_sha256"], before, "{s}");
}

#[test]
fn data_rm_confirms_name() {
    let f = fx(&[]);
    let key = enrol(&f, "k1");
    // A wrong name: nothing done, no touch asked.
    let o = f.blind_key(
        &["data", "rm", "--dataset", "crm"],
        "crn\n",
        true,
        Some(&key),
    );
    let (out, err) = text(&o);
    assert_eq!(code(&o), 2, "{out}\n{err}");
    assert!(
        err.contains("This removes crm: its snapshot, its stand-in keys and its approved methods. Type the dataset name to go on: "),
        "{err}"
    );
    assert!(!err.contains("touch your key"), "{err}");
    assert_eq!(crm_status(&f)["state"], "live");
    // The name typed, then the blind:keys touch (plan 48 final review I1).
    let o = f.blind_key(
        &["data", "rm", "--dataset", "crm"],
        "crm\n",
        true,
        Some(&key),
    );
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(
        err.contains("saiife: touch your key to remove crm and delete its keys"),
        "{err}"
    );
    assert_eq!(out.lines().next(), Some("removed crm"), "{out}");
    assert_eq!(crm_status(&f)["state"], "not_built");
}

/// I1: without a touch key, `data rm` removes nothing.
#[test]
fn data_rm_needs_a_touch() {
    let f = fx(&[]);
    let o = f.blind(&["data", "rm", "--dataset", "crm"], "crm\n", true);
    let (out, err) = text(&o);
    assert_ne!(code(&o), 0, "{out}\n{err}");
    assert!(!out.contains("removed crm"), "{out}");
    assert_eq!(crm_status(&f)["state"], "live");
}

#[test]
fn data_class_tighten_writes_policy() {
    let f = fx_opts(
        &[],
        "",
        Opts {
            dropin: Some(true),
            email: false,
        },
    );
    let o = f.blind(
        &["data", "class", "crm", "customers.city", "sensitive"],
        "",
        false,
    );
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(!err.contains("touch your key"), "{err}");
    let path = dropin(&f);
    assert_eq!(
        out,
        format!(
            "customers.city is now sensitive in {} (stricter, so no touch was needed; it was quasi)\n\
             it applies at the next refresh: saiife blind data refresh --dataset crm\n",
            path.display()
        )
    );
    let written = fs::read_to_string(&path).unwrap();
    assert_eq!(written.lines().next(), Some(MARKER), "{written}");
    assert_eq!(dropin_class(&f, "customers.city"), "sensitive");
    // Everything else is as it was.
    assert_eq!(dropin_class(&f, "invoices.amount"), "sensitive");
    assert_eq!(dropin_class(&f, "customers.city"), "sensitive");
    assert_eq!(mode_of(&path), 0o600);
    // The daemon loaded it: no warning, still live.
    let s = crm_status(&f);
    assert_eq!(s["state"], "live", "{s}");
    assert_eq!(s["warnings"], json!([]), "{s}");
    // The same class again changes nothing.
    let o = f.blind(
        &["data", "class", "crm", "customers.city", "sensitive"],
        "",
        false,
    );
    assert_eq!(code(&o), 0);
    assert_eq!(
        text(&o).0,
        "customers.city is sensitive in policy already; nothing was changed\n"
    );
    // Not a class, not a column: refused.
    let o = f.blind(
        &["data", "class", "crm", "customers.city", "secret"],
        "",
        false,
    );
    assert_eq!(code(&o), 2);
    let o = f.blind(&["data", "class", "crm", "city", "quasi"], "", false);
    assert_eq!(code(&o), 2);
}

#[test]
fn data_class_restores_on_bad_reload() {
    let f = fx_opts(
        &[],
        "",
        Opts {
            dropin: Some(true),
            email: false,
        },
    );
    let before = fs::read(dropin(&f)).unwrap();
    // Another drop-in that does not load: the reload is rejected.
    let broken = f.b.config_dir().join("policy.d/zz-broken.toml");
    fs::write(&broken, "[[[ not toml\n").unwrap();
    let o = f.blind(
        &["data", "class", "crm", "customers.city", "sensitive"],
        "",
        false,
    );
    let (out, err) = text(&o);
    assert_eq!(code(&o), 2, "{out}\n{err}");
    assert!(
        err.contains("saiife: the policy did not load, so the change was not made: "),
        "{err}"
    );
    assert!(err.contains("was put back as it was"), "{err}");
    assert_eq!(fs::read(dropin(&f)).unwrap(), before);
    fs::remove_file(&broken).unwrap();
}

/// m6 (plan 48 final review): a loosening whose policy did not load
/// withdraws its grant, so a later hand edit cannot spend it untouched.
#[test]
fn data_class_loosen_bad_reload_withdraws_the_grant() {
    let f = fx_opts(
        &[],
        "",
        Opts {
            dropin: Some(true),
            email: false,
        },
    );
    let before = fs::read(dropin(&f)).unwrap();
    let key = enrol(&f, "k1");
    let broken = f.b.config_dir().join("policy.d/zz-broken.toml");
    fs::write(&broken, "[[[ not toml\n").unwrap();
    let o = f.blind_key(
        &["data", "class", "crm", "invoices.amount", "quasi"],
        "",
        false,
        Some(&key),
    );
    let (out, err) = text(&o);
    assert_eq!(code(&o), 2, "{out}\n{err}");
    assert!(
        err.contains("saiife: touch your key to make invoices.amount quasi"),
        "{err}"
    );
    assert!(err.contains("was put back as it was"), "{err}");
    assert!(
        err.contains("the blind:loosen grant was withdrawn"),
        "{err}"
    );
    assert_eq!(fs::read(dropin(&f)).unwrap(), before);
    let grants = f.b.state_dir().join("blind/datasets/crm/loosen.json");
    let g: Value = serde_json::from_str(&fs::read_to_string(&grants).unwrap()).unwrap();
    assert_eq!(g["grants"], json!([]), "{g}");
    fs::remove_file(&broken).unwrap();
}

#[test]
fn data_class_in_config_toml_is_refused() {
    // `crm` is in config.toml, which saiife blind never writes.
    let f = fx(&[]);
    let o = f.blind(
        &["data", "class", "crm", "customers.city", "sensitive"],
        "",
        false,
    );
    let (out, err) = text(&o);
    assert_eq!(code(&o), 2, "{out}\n{err}");
    assert!(err.contains("crm is not defined in "), "{err}");
    assert!(!dropin(&f).exists());
}

#[test]
fn data_class_loosen_needs_touch() {
    let f = fx_opts(
        &[],
        "",
        Opts {
            dropin: Some(true),
            email: false,
        },
    );
    let before = fs::read(dropin(&f)).unwrap();
    // A key that is not enrolled: the daemon refuses the touch.
    let stranger = soft_key(&f.b.path().join("stranger.json"));
    let o = f.blind_key(
        &["data", "class", "crm", "invoices.amount", "quasi"],
        "",
        false,
        Some(&stranger),
    );
    let (out, err) = text(&o);
    assert_eq!(code(&o), 2, "{out}\n{err}");
    assert!(
        err.contains("refused: loosen needs a touch (blind:loosen) and no touch device is enrolled for you: saiife touch enrol"),
        "{err}"
    );
    assert_eq!(fs::read(dropin(&f)).unwrap(), before);
    let grants = f.b.state_dir().join("blind/datasets/crm/loosen.json");
    assert!(!grants.exists());
    // With the touch: the grant, then the policy.
    let key = enrol(&f, "k1");
    let o = f.blind_key(
        &["data", "class", "crm", "invoices.amount", "quasi"],
        "",
        false,
        Some(&key),
    );
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(
        err.contains("saiife: touch your key to make invoices.amount quasi (now sensitive) (code "),
        "{err}"
    );
    assert!(
        out.contains("(looser, with a blind:loosen touch; it was sensitive)"),
        "{out}"
    );
    assert_eq!(dropin_class(&f, "invoices.amount"), "quasi");
    let g: Value = serde_json::from_str(&fs::read_to_string(&grants).unwrap()).unwrap();
    assert_eq!(g["grants"][0]["column"], "invoices.amount", "{g}");
    assert_eq!(g["grants"][0]["class"], "quasi", "{g}");
    // The grant covers it: no "without a blind:loosen touch" warning.
    let s = crm_status(&f);
    assert_eq!(s["warnings"], json!([]), "{s}");
}

#[test]
fn data_class_public_refused_for_email() {
    let f = fx_opts(
        &[],
        "",
        Opts {
            dropin: Some(true),
            email: true,
        },
    );
    let key = enrol(&f, "k1");
    let before = fs::read(dropin(&f)).unwrap();
    let o = f.blind_key(
        &["data", "class", "crm", "customers.email", "public"],
        "",
        false,
        Some(&key),
    );
    let (out, err) = text(&o);
    assert_eq!(code(&o), 2, "{out}\n{err}");
    assert_eq!(
        err.trim_end(),
        "saiife: customers.email cannot be public: it holds names or IDs"
    );
    assert!(out.is_empty(), "{out}");
    assert_eq!(fs::read(dropin(&f)).unwrap(), before);
    assert!(!f
        .b
        .state_dir()
        .join("blind/datasets/crm/loosen.json")
        .exists());
}

#[test]
fn policy_file_marker_protects_hand_written() {
    let f = fx_opts(
        &[],
        "",
        Opts {
            dropin: Some(false),
            email: false,
        },
    );
    let before = fs::read(dropin(&f)).unwrap();
    let o = f.blind(
        &["data", "class", "crm", "customers.city", "sensitive"],
        "",
        false,
    );
    let (out, err) = text(&o);
    assert_eq!(code(&o), 2, "{out}\n{err}");
    assert!(
        err.contains(&format!(
            "{} was not written by saiife blind (its first line is not \"{MARKER}\"), so it is left as it is",
            dropin(&f).display()
        )),
        "{err}"
    );
    assert_eq!(fs::read(dropin(&f)).unwrap(), before);
}

#[test]
fn context_follow_up_shows_no_approve_hint() {
    // T4 M1: the hint follows the daemon's `approvable`, not the footer.
    let f = fx(&[balance()]);
    let hint = "approve this method for reuse: saiife blind methods approve ";
    let o = f.blind(&["ask", "--yes", "--show-sent", Q_SOREN], "", false);
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(err.contains(hint), "{err}");
    let ob = f.outbox();
    let body: Value = serde_json::from_str(ob[0]["body"].as_str().unwrap()).unwrap();
    let sent: Value =
        serde_json::from_str(body["messages"][0]["content"].as_str().unwrap()).unwrap();
    let sym = sent["params"][0]["symbol"].as_str().unwrap().to_string();
    // The follow-up's reply binds that stand-in (added to the script now).
    let hers = json!({
        "method": "SELECT COUNT(*) AS n FROM invoices i \
                   JOIN customers c ON c.id = i.customer_id WHERE c.id = :p1",
        "template": "There are {int(n)} invoices for {param(p1)}.",
        "intent": "counts her invoices",
        "context": [{"name": "p1", "symbol": sym}]});
    let script = f.b.path().join("planner.txt");
    let mut lines = fs::read_to_string(&script).unwrap();
    lines.push_str(&format!("{hers}\n"));
    fs::write(&script, lines).unwrap();
    let o = f.blind(&["ask", "--yes", "And his invoices?"], "", false);
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert_eq!(
        out.lines().next(),
        Some("There are 3 invoices for the customer."),
        "{out}"
    );
    assert!(out.contains("new method"), "{out}");
    assert!(!err.contains(hint), "{err}");
}

#[test]
fn keep_name_touch_failure_ends_the_ask() {
    // T4 M2: a touch that fails after `blind.touch.begin` ends the ask, so
    // its slot is free at once (at most 4 open asks per user, R48-1).
    let f = fx(&[]);
    enrol(&f, "k1");
    let stranger = soft_key(&f.b.path().join("stranger.json"));
    for _ in 0..5 {
        let o = f.blind_key(
            &["ask", "What is the balance of Zed Quorra?"],
            "y\n",
            true,
            Some(&stranger),
        );
        let (out, err) = text(&o);
        assert_ne!(code(&o), 0, "{out}\n{err}");
        assert!(err.contains("saiife: touch your key to keep"), "{err}");
    }
    // Five failed touches later, a new ask still gets a step (not busy).
    let o = f.blind(&["ask", Q_ANNA], "0\n", true);
    let (out, err) = text(&o);
    assert!(
        err.contains("Found 2 customers named Anna Berg:"),
        "{out}\n{err}"
    );
    assert!(f.outbox().is_empty());
}

fn mode_of(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn refresh_brings_needs_refresh_back_live() {
    // T5 review: a dataset in needs_refresh (its keys deleted) is live
    // again after `data refresh`, with new keys.
    let f = fx(&[]);
    let key = enrol(&f, "k1");
    let o = f.blind_key(
        &["keys", "delete", "--dataset", "crm"],
        "crm\n",
        true,
        Some(&key),
    );
    assert_eq!(code(&o), 0, "{:?}", text(&o));
    let s = crm_status(&f);
    assert_eq!(s["state"], "needs_refresh", "{s}");
    let db = f.b.path().join("crm.sqlite");
    let o = f.blind(
        &["data", "refresh", "--file", db.to_str().unwrap()],
        "",
        false,
    );
    let (out, err) = text(&o);
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert_eq!(out.lines().next(), Some("crm is live"), "{out}");
    let s = crm_status(&f);
    assert_eq!(s["state"], "live", "{s}");
    assert!(s["keys_version"].is_u64(), "{s}");
}

#[test]
fn data_class_on_a_locked_host_needs_root_before_the_touch() {
    // T5 review m1: a user who is not root is refused before any touch or
    // grant, even for a loosening.
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
    let dir = tmp.path().join("policy.d");
    fs::create_dir(&dir).unwrap();
    let file = dir.join("blind-crm.toml");
    let body = format!("{MARKER}\n{}", dataset_policy("", false));
    fs::write(&file, &body).unwrap();
    let key = soft_key(&tmp.path().join("soft.json"));
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["blind", "--system-config"])
        .arg(&cfg)
        .args(["data", "class", "crm", "invoices.amount", "quasi"])
        .env("HOME", tmp.path())
        .env("PATH", "/usr/bin:/bin")
        .env("XDG_RUNTIME_DIR", tmp.path().join("no-runtime"))
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
        .env("SAIIFE_TEST_TOUCH_SOFT", &key)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let (out, err) = text(&o);
    assert_eq!(code(&o), 2, "{out}\n{err}");
    assert_eq!(
        err,
        format!(
            "saiife: {} is root's on a locked host: run this as root (sudo saiife blind …)\n",
            dir.display()
        )
    );
    assert!(!err.contains("touch your key"), "{err}");
    assert_eq!(fs::read_to_string(&file).unwrap(), body);
}
