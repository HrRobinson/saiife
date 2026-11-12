//! A static Linux `saiife` touches a key through the FIDO helper (plan 41,
//! Task 3), end to end against the daemon world of tests/approvals_cmd.rs.
//! The helper is the fake (`saiife-fake-fido`): each test puts it in its
//! own directory with its knobs file (`<path>.json`) and points the debug
//! seam `SAIIFE_TEST_FIDO_HELPER` at it; `SAIIFE_TEST_TOUCH_PIN` types the
//! PIN (tests have no terminal).
// The fake binary exists only with its feature; the seams only in debug builds.
#![cfg(all(target_os = "linux", feature = "fake-fido"))]
#![cfg(debug_assertions)]
#![allow(dead_code)]

#[path = "common/approvals_world.rs"]
mod approvals_world;
mod common;

use approvals_world::*;

use common::daemon::own_user;
use saiife_daemon::approvals::State;
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

/// The PIN the seam types.
const PIN: &str = "qzxwvkpin";
const VERSION: &str = env!("CARGO_PKG_VERSION");
const NO_HELPER: &str = "this saiife build has no FIDO2 key support (a static Linux build without the FIDO helper); install the saiife deb or rpm, see docs/touch.md";
const ONLY_ONE: &str = "more than one FIDO key is plugged in; leave only the one to use";
const DEPLOY: &str = "deploy = [\"invoices:write\"]";

/// One fake helper: its path, knobs file, log and soft key file.
struct Fake {
    path: PathBuf,
    log: PathBuf,
    key: PathBuf,
}

impl Fake {
    /// Writes the knobs file with this mode and device count.
    fn knobs(&self, mode: &str, devices: usize) {
        let k = json!({
            "key": self.key,
            "devices": devices,
            "mode": mode,
            "log": self.log,
        });
        let mut p = self.path.clone().into_os_string();
        p.push(".json");
        fs::write(p, k.to_string()).unwrap();
    }

    /// The log's lines.
    fn lines(&self) -> Vec<Value> {
        fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// The start lines (`{"pid","argv","env"}`).
    fn starts(&self) -> Vec<Value> {
        self.lines()
            .into_iter()
            .filter(|l| l.get("pid").is_some())
            .collect()
    }

    /// The request lines (`{"op","pin_len"}`).
    fn ops(&self) -> Vec<Value> {
        self.lines()
            .into_iter()
            .filter(|l| l.get("op").is_some())
            .collect()
    }

    /// Every helper this fake started has exited and been reaped.
    fn none_left(&self) {
        for s in self.starts() {
            let pid = s["pid"].as_u64().unwrap();
            assert!(
                !Path::new(&format!("/proc/{pid}")).exists(),
                "helper {pid} is still there"
            );
        }
    }
}

/// The fake helper in `<world>/helper-<name>/saiife-fido` (a 0700 dir),
/// mode `ok`. `copy`: a copy of its own (the tests that change its mode);
/// else a hard link to the built binary, so no test holds a file open for
/// writing that another test's child then cannot exec (ETXTBSY).
fn fake_in(w: &World, name: &str, copy: bool) -> Fake {
    let dir = w.path().join(format!("helper-{name}"));
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let path = dir.join("saiife-fido");
    let bin = env!("CARGO_BIN_EXE_saiife-fake-fido");
    if copy || fs::hard_link(bin, &path).is_err() {
        fs::copy(bin, &path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let f = Fake {
        log: dir.join("log"),
        key: dir.join("key.json"),
        path,
    };
    f.knobs("ok", 1);
    f
}

fn fake(w: &World) -> Fake {
    fake_in(w, "a", false)
}

/// The world with the own user an approver (who may manage touch devices).
fn touch_world() -> World {
    let w = world();
    let text = config_text(w.path(), w.m.port, "").replace(
        "approvers = [\"boss\"]",
        &format!("approvers = [\"boss\", {:?}]", own_user()),
    );
    *w.ctx.policy.lock().unwrap() = policy_of(w.path(), w.m.port, &text);
    w
}

/// `saiife <cmd> ... <args>` through the helper `helper`, with the PIN seam.
fn cmd_at(w: &World, helper: &Path, cmd: &str, args: &[&str]) -> Command {
    let mut c = w.cli_cmd(cmd, args);
    c.env("SAIIFE_TEST_FIDO_HELPER", helper)
        .env("SAIIFE_TEST_TOUCH_PIN", PIN);
    c
}

fn touch(w: &World, f: &Fake, args: &[&str]) -> Output {
    cmd_at(w, &f.path, "touch", args).output().unwrap()
}

fn enrol(w: &World, f: &Fake) -> Output {
    touch(w, f, &["enrol", "--label", "key1"])
}

fn text(o: &Output) -> String {
    stdout(o) + &stderr(o)
}

fn code(o: &Output) -> Option<i32> {
    o.status.code()
}

fn listed(w: &World, f: &Fake) -> Vec<Value> {
    let o = touch(w, f, &["ls", "--json"]);
    ok(&o);
    json_out(&o).as_array().cloned().expect("an array")
}

/// A world whose `invoices.create` needs a touch (deploy: with its PIN), the
/// own user an approver who re-authenticates (the fake says yes), with the
/// fake's soft key enrolled through the helper. The credential id.
fn marked_world() -> (World, Fake, String) {
    let w = world_with(DEPLOY);
    w.serial
        .get_or_init(|| REAUTH_SERIAL.lock().unwrap_or_else(|p| p.into_inner()));
    w.reauth
        .allow
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let text = config_text(w.path(), w.m.port, DEPLOY).replace(
        "approvers = [\"boss\"]",
        &format!(
            "approvers = [\"boss\", {:?}]\nsame_user = \"reauth\"",
            own_user()
        ),
    );
    *w.ctx.policy.lock().unwrap() = policy_of(w.path(), w.m.port, &text);
    let f = fake(&w);
    let o = enrol(&w, &f);
    ok(&o);
    let id = listed(&w, &f)[0]["id"].as_str().unwrap().to_string();
    (w, f, id)
}

fn approve(w: &World, f: &Fake, id: u64) -> Output {
    cmd_at(w, &f.path, "approve", &[&id.to_string()])
        .output()
        .unwrap()
}

fn no_refusal(w: &World, id: u64) {
    let refused: Vec<Value> = w
        .approval_records(id)
        .into_iter()
        .filter(|r| r["action"] == "refused")
        .collect();
    assert!(refused.is_empty(), "{refused:?}");
}

/// Exit 5 with `line` on stderr, no PIN asked, no request sent to the
/// helper, and no helper left running.
fn refused_before_the_pin(o: &Output, f: &Fake, line: &str) {
    assert_eq!(code(o), Some(5), "{}", text(o));
    assert!(
        stderr(o).contains(&format!("saiife: {line}\n")),
        "{}",
        text(o)
    );
    assert!(
        !stderr(o).contains("PIN for your security key"),
        "{}",
        text(o)
    );
    assert!(f.ops().is_empty(), "{:?}", f.lines());
    f.none_left();
}

#[test]
fn enrol_test_and_approve_through_the_helper() {
    let (w, f, cred) = marked_world();
    assert_eq!(f.ops().len(), 2, "enrol and its proof: {:?}", f.lines());

    // A safe helper: `ls` has no note.
    let o = touch(&w, &f, &["ls"]);
    ok(&o);
    assert!(!stderr(&o).contains("no FIDO2 key support"), "{}", text(&o));

    let o = touch(&w, &f, &["test"]);
    ok(&o);
    assert!(
        stdout(&o).contains("ok: \"key1\" answered (user verified: yes, counter"),
        "{}",
        text(&o)
    );

    let id = w.ask(BODY_A);
    let o = approve(&w, &f, id);
    ok(&o);
    assert!(
        stdout(&o).contains(&format!("request #{id} approved")),
        "{}",
        text(&o)
    );
    let rec = w.wait_record(id, "approved");
    assert_eq!(rec["touch"]["cred_id"], cred.as_str(), "{rec}");
    assert_eq!(rec["touch"]["uv"], true, "{rec}");
    w.wait_state(id, State::Sent);
    assert_eq!(w.m.hits().len(), 1);
    f.none_left();
}

/// Review Focus 5: the helper gets no arguments and an empty environment;
/// the PIN goes only in the request line.
#[test]
fn pin_goes_only_over_stdin() {
    let w = touch_world();
    let f = fake(&w);
    ok(&enrol(&w, &f));
    let starts = f.starts();
    assert_eq!(starts.len(), 2, "{:?}", f.lines());
    for s in starts {
        assert_eq!(s["argv"], json!([f.path]), "{s}");
        assert_eq!(s["env"], json!([]), "{s}");
    }
    let ops = f.ops();
    assert_eq!(ops.len(), 2, "{ops:?}");
    for op in ops {
        assert_eq!(op["pin_len"], PIN.len(), "{op}");
    }
    assert!(!fs::read_to_string(&f.log).unwrap().contains(PIN));
}

/// Review Focus 3: a helper of another version or protocol is refused after
/// its hello and before the PIN.
#[test]
fn version_skew_is_refused_before_the_pin() {
    let w = touch_world();
    let f = fake(&w);
    f.knobs("version:0.0.1", 1);
    let o = enrol(&w, &f);
    refused_before_the_pin(
        &o,
        &f,
        &format!(
            "the FIDO helper is version 0.0.1 (protocol 1), this saiife is {VERSION} (protocol 1); reinstall the saiife package"
        ),
    );
    assert_eq!(f.starts().len(), 1);

    let f = fake_in(&w, "b", false);
    f.knobs("proto:2", 1);
    let o = enrol(&w, &f);
    refused_before_the_pin(
        &o,
        &f,
        &format!(
            "the FIDO helper is version {VERSION} (protocol 2), this saiife is {VERSION} (protocol 1); reinstall the saiife package"
        ),
    );
}

/// D2 through the helper: its hello counts the keys.
#[test]
fn two_keys_refused_before_the_pin() {
    let w = touch_world();
    let f = fake(&w);
    f.knobs("ok", 2);
    let o = enrol(&w, &f);
    refused_before_the_pin(&o, &f, ONLY_ONE);
}

/// Review Focus 1: a helper that never answers is killed at the limit, and
/// the request stays pending.
#[test]
fn hung_helper_is_killed_at_the_limit() {
    let (w, f, _) = marked_world();
    f.knobs("hang_after_hello", 1);
    let id = w.ask(BODY_A);
    let mut c = cmd_at(&w, &f.path, "approve", &[&id.to_string()]);
    c.env("SAIIFE_TEST_TOUCH_TIMEOUT_MS", "300");
    let t = Instant::now();
    let o = c.output().unwrap();
    assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
    assert_eq!(code(&o), Some(5), "{}", text(&o));
    assert!(stderr(&o).contains("no touch within"), "{}", text(&o));
    // The hung one was started (it never reads its request) and is gone.
    assert_eq!(f.starts().len(), 3, "{:?}", f.lines());
    assert_eq!(f.ops().len(), 2, "{:?}", f.lines());
    f.none_left();
    assert_eq!(w.state(id), Some(State::Pending));
    no_refusal(&w, id);
    assert!(w.reauth.details.lock().unwrap().is_empty());
    assert!(w.m.hits().is_empty());
}

/// Review Focus 1: no hello within 5 s.
#[test]
fn silent_helper_fails_the_hello() {
    let w = touch_world();
    let f = fake(&w);
    f.knobs("no_hello", 1);
    let t = Instant::now();
    let o = enrol(&w, &f);
    assert!(t.elapsed() < Duration::from_secs(6), "{:?}", t.elapsed());
    refused_before_the_pin(&o, &f, "the FIDO helper did not answer");
}

/// Review Focus 4: non-JSON, a line over the limit, the wrong answer.
#[test]
fn garbage_answers_are_unavailable() {
    let w = touch_world();
    for (i, mode) in ["garbage", "long_line", "wrong_type"].iter().enumerate() {
        let f = fake_in(&w, &i.to_string(), false);
        f.knobs(mode, 1);
        let o = enrol(&w, &f);
        assert_eq!(code(&o), Some(5), "{mode}: {}", text(&o));
        assert!(
            stderr(&o).contains("saiife: the FIDO helper did not answer"),
            "{mode}: {}",
            text(&o)
        );
        assert!(stderr(&o).len() < 4096, "{mode}: {}", text(&o));
        assert_eq!(f.ops().len(), 1, "{mode}: {:?}", f.lines());
        f.none_left();
    }
    assert!(listed(&w, &fake_in(&w, "ls", false)).is_empty());
}

/// The helper's CTAP error text goes through the same table: a wrong PIN
/// is exit 2, and nothing is decided.
#[test]
fn ctap_errors_are_classified() {
    let (w, f, _) = marked_world();
    f.knobs("ctap_error:0x31 CTAP2_ERR_PIN_INVALID   PIN Invalid.", 1);
    let id = w.ask(BODY_A);
    let o = approve(&w, &f, id);
    assert_eq!(code(&o), Some(2), "{}", text(&o));
    assert!(stderr(&o).contains("saiife: wrong PIN\n"), "{}", text(&o));
    assert_eq!(w.state(id), Some(State::Pending));
    no_refusal(&w, id);
    assert!(w.reauth.details.lock().unwrap().is_empty());
    assert!(w.m.hits().is_empty());
}

/// Review Focus 4: a 2 KiB error with an ANSI escape is cut and sanitized.
#[test]
fn error_text_is_sanitized() {
    let w = touch_world();
    let f = fake(&w);
    f.knobs(&format!("ctap_error:\u{1b}[31m{}", "A".repeat(2000)), 1);
    let o = enrol(&w, &f);
    assert_eq!(code(&o), Some(5), "{}", text(&o));
    let e = stderr(&o);
    assert!(!e.contains('\u{1b}'), "{e:?}");
    let line = e
        .lines()
        .find(|l| l.starts_with("saiife: the key did not answer: "))
        .unwrap_or_else(|| panic!("{e:?}"));
    assert!(line.contains("\\x1b[31mAAA"), "{line}");
    let a = line.matches('A').count();
    assert!(a > 400 && a <= 512, "{a}: {line}");
}

#[test]
fn cannot_start_names_stderr() {
    let w = touch_world();
    let f = fake(&w);
    f.knobs("exit_at_start:127", 1);
    let o = enrol(&w, &f);
    refused_before_the_pin(
        &o,
        &f,
        "the FIDO helper cannot start: saiife-fake-fido: exit at start; is libudev installed?",
    );
    f.knobs("exit_at_start:3", 1);
    let o = enrol(&w, &f);
    refused_before_the_pin(
        &o,
        &f,
        "the FIDO helper cannot start: saiife-fake-fido: exit at start",
    );
}

/// Review Focus 2: a group-writable helper is refused before exec.
#[test]
fn unsafe_helper_never_runs() {
    let w = touch_world();
    let f = fake_in(&w, "a", true);
    fs::set_permissions(&f.path, fs::Permissions::from_mode(0o775)).unwrap();
    let o = enrol(&w, &f);
    assert_eq!(code(&o), Some(5), "{}", text(&o));
    let lead = format!(
        "saiife: the FIDO helper {} is not safe to run (",
        f.path.display()
    );
    let e = stderr(&o);
    let line = e
        .lines()
        .find(|l| l.starts_with(&lead))
        .unwrap_or_else(|| panic!("{e}"));
    assert!(line.ends_with("); reinstall the saiife package"), "{line}");
    assert!(!f.log.exists(), "the helper ran");
    // `touch test` is refused the same way, before any daemon op.
    let o = cmd_at(&w, &f.path, "touch", &["test"]).output().unwrap();
    assert_eq!(code(&o), Some(5), "{}", text(&o));
    assert!(stderr(&o).contains(&lead), "{}", text(&o));
    assert!(!f.log.exists(), "the helper ran");
}

/// Plan 27 D1: no helper is the no-support line; `ls` still lists, with
/// the line as a note.
#[test]
fn missing_helper_names_the_package() {
    let w = touch_world();
    let missing = w.path().join("no-helper/saiife-fido");
    let o = cmd_at(&w, &missing, "touch", &["enrol", "--label", "k"])
        .output()
        .unwrap();
    assert_eq!(code(&o), Some(5), "{}", text(&o));
    assert!(
        stderr(&o).contains(&format!("saiife: {NO_HELPER}\n")),
        "{}",
        text(&o)
    );
    let o = cmd_at(&w, &missing, "touch", &["ls"]).output().unwrap();
    ok(&o);
    assert!(
        stdout(&o).contains("no touch devices enrolled"),
        "{}",
        text(&o)
    );
    assert!(
        stderr(&o).contains(&format!("saiife: {NO_HELPER}\n")),
        "{}",
        text(&o)
    );
}
