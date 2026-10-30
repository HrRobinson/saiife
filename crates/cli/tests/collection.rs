//! Collections (plan 14 Task 5, decision 11): parsing and filling, and
//! `saiife api collection run` against a fake daemon socket that records
//! every frame, so each step is seen to be one ordinary `api.call`.
//! Nothing leaves loopback; the fake daemon is a thread in this test.

#[path = "../src/collection.rs"]
#[allow(dead_code)]
mod collection;

mod common;

use collection::{fill, load, Collection, CollectionError, FilledStep};
use serde_json::json;
#[cfg(unix)]
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

const SPEC_EXAMPLE: &str = r#"name = "open-orders-report"
[[step]]
service = "shopify"
operation = "orders.list"
params = { status = "open", limit = "250" }
"#;

fn write(root: &Path, name: &str, text: &str) {
    let d = root.join(".saiife/collections");
    fs::create_dir_all(&d).unwrap();
    fs::write(d.join(format!("{name}.toml")), text).unwrap();
}

fn vars(kv: &[(&str, &str)]) -> BTreeMap<String, String> {
    kv.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn parse(text: &str) -> Collection {
    toml::from_str(text).unwrap()
}

#[test]
fn spec_example_parses() {
    let t = common::tmp::short_tempdir();
    write(t.path(), "open-orders-report", SPEC_EXAMPLE);
    let c = load(t.path(), "open-orders-report").unwrap();
    assert_eq!(c.name, "open-orders-report");
    assert_eq!(c.step.len(), 1);
    assert_eq!(c.step[0].service, "shopify");
    assert_eq!(c.step[0].operation, "orders.list");
    assert_eq!(
        c.step[0].params,
        vars(&[("status", "open"), ("limit", "250")])
    );
    assert_eq!(c.step[0].body, None);
    let f = fill(&c, &BTreeMap::new()).unwrap();
    assert_eq!(
        f,
        vec![FilledStep {
            service: "shopify".into(),
            operation: "orders.list".into(),
            params: vars(&[("status", "open"), ("limit", "250")]),
            body: None,
        }]
    );
    // Unknown keys are refused, at the top and in a step.
    assert!(toml::from_str::<Collection>("name = \"x\"\nflow = 1\n").is_err());
    assert!(toml::from_str::<Collection>(
        "name = \"x\"\n[[step]]\nservice = \"a\"\noperation = \"b\"\nheaders = {}\n"
    )
    .is_err());
}

#[test]
fn fill_params_and_body_strings() {
    let c = parse(
        r#"name = "notify"
[[step]]
service = "slack"
operation = "chat.post"
params = { channel = "{{channel}}", note = "for {{who}} at {{who}}" }
body = { text = "hi {{who}}", n = 3, ok = true, f = 1.5, tags = ["{{channel}}", "x"], meta = { by = "{{who}}" } }
[[step]]
service = "linear"
operation = "issues.list"
params = { team = "eng" }
"#,
    );
    let f = fill(&c, &vars(&[("channel", "C01"), ("who", "ann")])).unwrap();
    assert_eq!(f.len(), 2);
    assert_eq!(
        f[0].params,
        vars(&[("channel", "C01"), ("note", "for ann at ann")])
    );
    assert_eq!(
        f[0].body,
        Some(json!({"text": "hi ann", "n": 3, "ok": true, "f": 1.5,
                    "tags": ["C01", "x"], "meta": {"by": "ann"}}))
    );
    assert_eq!(f[1].params, vars(&[("team", "eng")]));
    // A single brace or a lone `}}` is plain text.
    let c = parse(
        "name = \"x\"\n[[step]]\nservice = \"a\"\noperation = \"b\"\nparams = { q = \"{a} }} {{v}}\" }\n",
    );
    let f = fill(&c, &vars(&[("v", "1")])).unwrap();
    assert_eq!(f[0].params["q"], "{a} }} 1");
}

#[test]
fn filled_value_is_literal() {
    let c = parse(
        r#"name = "x"
[[step]]
service = "a"
operation = "b"
params = { q = "{{first}}", r = "{{other}}" }
body = { t = "{{first}}" }
"#,
    );
    let hostile = "}}{{other}}\r\nservice=evil {{first}}";
    let f = fill(&c, &vars(&[("first", hostile), ("other", "o")])).unwrap();
    assert_eq!(f[0].params["q"], hostile);
    assert_eq!(f[0].params["r"], "o");
    assert_eq!(f[0].body, Some(json!({"t": hostile})));
    // A value never becomes structure: the step's service, operation and
    // keys are what the file says.
    assert_eq!(f[0].service, "a");
    assert_eq!(f[0].operation, "b");
    assert_eq!(f[0].params.keys().collect::<Vec<_>>(), ["q", "r"]);
}

#[test]
fn missing_var_error_before_any_call() {
    let c = parse(
        "name = \"x\"\n[[step]]\nservice = \"a\"\noperation = \"b\"\n\
         [[step]]\nservice = \"a\"\noperation = \"c\"\nparams = { q = \"{{late}} {{also}}\" }\n",
    );
    let e = fill(&c, &BTreeMap::new()).unwrap_err();
    assert_eq!(
        e,
        CollectionError::Missing(vec!["also".into(), "late".into()])
    );
    // End to end: the run stops before it sends anything, step 1 included.
    #[cfg(unix)]
    {
        let w = World::new(&[], "x", &collection_text_missing());
        let o = w.run(&["x"]);
        assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
        assert!(stderr(&o).contains("{{late}}"), "{}", stderr(&o));
        assert!(w.api_calls().is_empty(), "{:?}", w.frames());
        // So does an unused one.
        let o = w.run(&["x", "late=1", "extra=2"]);
        assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
        assert!(w.api_calls().is_empty(), "{:?}", w.frames());
    }
}

#[cfg_attr(not(unix), allow(dead_code))]
fn collection_text_missing() -> String {
    "name = \"x\"\n[[step]]\nservice = \"erp\"\noperation = \"a\"\n\
     [[step]]\nservice = \"erp\"\noperation = \"b\"\nparams = { q = \"{{late}}\" }\n"
        .into()
}

#[test]
fn unused_var_error() {
    let c = parse(
        "name = \"x\"\n[[step]]\nservice = \"a\"\noperation = \"b\"\nparams = { q = \"{{v}}\" }\n",
    );
    let e = fill(&c, &vars(&[("v", "1"), ("extra", "2")])).unwrap_err();
    assert_eq!(e, CollectionError::Unused(vec!["extra".into()]));
    // A name outside the grammar is refused as such.
    let e = fill(&c, &vars(&[("v", "1"), ("Bad", "2")])).unwrap_err();
    assert!(matches!(e, CollectionError::BadVar(_)), "{e:?}");
    // The error names the variable, never a value.
    let e = fill(&c, &vars(&[("v", "1"), ("extra", "value-xyz")])).unwrap_err();
    assert!(!e.to_string().contains("value-xyz"), "{e}");
}

#[test]
fn placeholder_in_operation_refused() {
    let t = common::tmp::short_tempdir();
    for (field, text) in [
        ("operation", "service = \"a\"\noperation = \"{{op}}\"\n"),
        ("service", "service = \"{{svc}}\"\noperation = \"b\"\n"),
        (
            "a params key",
            "service = \"a\"\noperation = \"b\"\nparams = { \"{{k}}\" = \"v\" }\n",
        ),
        (
            "a body key",
            "service = \"a\"\noperation = \"b\"\nbody = { \"{{k}}\" = \"v\" }\n",
        ),
    ] {
        write(t.path(), "p", &format!("name = \"p\"\n[[step]]\n{text}"));
        let e = load(t.path(), "p").unwrap_err();
        assert_eq!(
            e,
            CollectionError::PlaceholderNotAllowed {
                step: 1,
                field: field.into()
            },
            "{text}"
        );
    }
    // Any `{{` that is not a placeholder is an error, wherever it is.
    for v in [
        "{{", "{{ x }}", "{{X}}", "{{1a}}", "{{{a}}}", "{{a", "{{a-b}}",
    ] {
        let text = format!(
            "name = \"p\"\n[[step]]\nservice = \"a\"\noperation = \"b\"\nparams = {{ q = {v:?} }}\n"
        );
        write(t.path(), "p", &text);
        let e = load(t.path(), "p").unwrap_err();
        assert!(
            matches!(e, CollectionError::BadPlaceholder { step: 1, .. }),
            "{v}: {e:?}"
        );
    }
    let long = format!("{{{{{}}}}}", "a".repeat(33));
    write(
        t.path(),
        "p",
        &format!("name = \"p\"\n[[step]]\nservice = \"a\"\noperation = \"b\"\nbody = {{ q = {long:?} }}\n"),
    );
    assert!(matches!(
        load(t.path(), "p").unwrap_err(),
        CollectionError::BadPlaceholder { .. }
    ));
    // A date has no JSON form.
    write(
        t.path(),
        "p",
        "name = \"p\"\n[[step]]\nservice = \"a\"\noperation = \"b\"\nbody = { d = 2026-10-28 }\n",
    );
    assert!(matches!(
        load(t.path(), "p").unwrap_err(),
        CollectionError::BadBody { .. }
    ));
}

#[test]
fn name_must_match_file_stem() {
    let t = common::tmp::short_tempdir();
    write(
        t.path(),
        "weekly",
        &SPEC_EXAMPLE.replace("open-orders-report", "other"),
    );
    assert!(matches!(
        load(t.path(), "weekly").unwrap_err(),
        CollectionError::NameMismatch { .. }
    ));
    // The name itself is checked before any path is built.
    for bad in ["", "../x", "A", "a.b", "a/b", &"a".repeat(65)] {
        assert_eq!(
            load(t.path(), bad).unwrap_err(),
            CollectionError::BadName,
            "{bad}"
        );
    }
    assert!(matches!(
        load(t.path(), "absent").unwrap_err(),
        CollectionError::NotFound(_)
    ));
}

#[test]
fn too_many_steps_refused() {
    let t = common::tmp::short_tempdir();
    let step = "[[step]]\nservice = \"a\"\noperation = \"b\"\n";
    write(t.path(), "s", &format!("name = \"s\"\n{}", step.repeat(32)));
    assert_eq!(load(t.path(), "s").unwrap().step.len(), 32);
    write(t.path(), "s", &format!("name = \"s\"\n{}", step.repeat(33)));
    assert_eq!(
        load(t.path(), "s").unwrap_err(),
        CollectionError::TooManySteps(33)
    );
    write(t.path(), "s", "name = \"s\"\n");
    assert_eq!(load(t.path(), "s").unwrap_err(), CollectionError::NoSteps);
}

#[test]
fn oversize_file_refused() {
    let t = common::tmp::short_tempdir();
    let pad = 64 * 1024 - SPEC_EXAMPLE.len() - 2;
    write(
        t.path(),
        "open-orders-report",
        &format!("{SPEC_EXAMPLE}#{}\n", "x".repeat(pad)),
    );
    assert!(load(t.path(), "open-orders-report").is_ok());
    write(
        t.path(),
        "open-orders-report",
        &format!("{SPEC_EXAMPLE}#{}\n", "x".repeat(pad + 1)),
    );
    assert!(matches!(
        load(t.path(), "open-orders-report").unwrap_err(),
        CollectionError::TooLarge(_)
    ));
}

#[test]
fn reserved_name_collection_not_a_service() {
    let t = common::tmp::short_tempdir();
    for name in ["collection", "result", "token", "saiife"] {
        let cfg = t.path().join("config.toml");
        fs::write(
            &cfg,
            format!(
                "version = 2\nlocked = true\n[services.{name}]\nconnector = \"http\"\n\
                 base_url = \"https://api.test\"\n"
            ),
        )
        .unwrap();
        let e = saiife_policy::load_system(&cfg).unwrap_err().to_string();
        assert!(e.contains("reserved"), "{name}: {e}");
    }
    // `saiife api collection ...` is the subcommand: it never becomes a call
    // to a service named `collection`.
    #[cfg(unix)]
    {
        let w = World::new(&[], "x", &collection_text_missing());
        let o = w.cmd(&["collection", "list"]).output().unwrap();
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert!(String::from_utf8_lossy(&o.stdout).contains("x  2  erp"));
        let o = w.cmd(&["collection", "orders.list"]).output().unwrap();
        assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
        assert!(w.api_calls().is_empty(), "{:?}", w.frames());
    }
}

// ------------------------------------------------- fake daemon, end to end

#[cfg_attr(not(unix), allow(dead_code))]
fn stderr(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[cfg(unix)]
use fake::World;

#[cfg(unix)]
mod fake {
    use super::common;
    use base64::Engine as _;
    use saiife_ipc::frame::{read_frame, write_frame};
    use serde_json::{json, Map, Value};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::process::{Command, Output, Stdio};
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    /// Every frame the fake daemon got: its op and its args.
    type Frames = Arc<Mutex<Vec<(String, Map<String, Value>)>>>;

    /// What the fake daemon answers the n-th `api.call` with.
    #[derive(Clone)]
    pub enum Answer {
        Done(u16, &'static str),
        Denied(&'static str),
        Pending(u64),
    }

    pub struct World {
        pub tmp: TempDir,
        frames: Frames,
    }

    impl World {
        pub fn new(answers: &[Answer], name: &str, text: &str) -> World {
            let tmp = common::tmp::short_tempdir();
            let p = tmp.path();
            for d in ["home", "data", "audit", "xdg", "project", "run"] {
                fs::create_dir_all(p.join(d)).unwrap();
            }
            fs::set_permissions(p.join("run"), fs::Permissions::from_mode(0o700)).unwrap();
            super::write(&p.join("project"), name, text);
            fs::write(
                p.join("config.toml"),
                format!(
                    "version = 2\nlocked = true\n\n[daemon]\nuser = {:?}\nsocket_dir = {:?}\n\n[audit]\ndir = {:?}\n",
                    common_user(),
                    p.join("run").display().to_string(),
                    p.join("audit").display().to_string(),
                ),
            )
            .unwrap();
            let listener = UnixListener::bind(p.join("run/saiife.sock")).unwrap();
            let frames = Arc::new(Mutex::new(Vec::new()));
            let (f, answers) = (frames.clone(), answers.to_vec());
            std::thread::spawn(move || serve(listener, f, answers));
            World { tmp, frames }
        }

        pub fn cmd(&self, args: &[&str]) -> Command {
            let p = self.tmp.path();
            let mut c = Command::new(env!("CARGO_BIN_EXE_saiife"));
            c.arg("api")
                .arg("--system-config")
                .arg(p.join("config.toml"))
                .args(args)
                .current_dir(p.join("project"))
                .env("HOME", p.join("home"))
                .env("PATH", "/usr/bin:/bin")
                .env("SAIIFE_DATA_DIR", p.join("data"))
                .env("SAIIFE_AUDIT_DIR", p.join("audit"))
                .env("XDG_CONFIG_HOME", p.join("xdg"))
                .env("XDG_DATA_HOME", p.join("xdg"))
                .env("XDG_STATE_HOME", p.join("xdg"))
                .env("XDG_RUNTIME_DIR", p.join("xdg"))
                .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
                .stdin(Stdio::null());
            c
        }

        pub fn run(&self, args: &[&str]) -> Output {
            let mut a = vec!["collection", "run"];
            a.extend_from_slice(args);
            self.cmd(&a).output().unwrap()
        }

        pub fn frames(&self) -> Vec<(String, Map<String, Value>)> {
            self.frames.lock().unwrap().clone()
        }

        pub fn api_calls(&self) -> Vec<Map<String, Value>> {
            self.frames()
                .into_iter()
                .filter(|(op, _)| op == "api.call")
                .map(|(_, a)| a)
                .collect()
        }
    }

    fn common_user() -> String {
        let o = Command::new("id").arg("-un").output().unwrap();
        String::from_utf8(o.stdout).unwrap().trim().to_string()
    }

    fn serve(listener: UnixListener, frames: Frames, answers: Vec<Answer>) {
        let mut calls = 0usize;
        for mut s in listener.incoming().flatten() {
            while let Ok(req) = read_frame(&mut s) {
                let id = req.get("id").and_then(Value::as_u64).unwrap_or(0);
                let op = req
                    .get("op")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                // A request frame is flat: its args sit beside id and op.
                let mut args = req.clone();
                args.remove("id");
                args.remove("op");
                frames.lock().unwrap().push((op.clone(), args));
                let ans = match op.as_str() {
                    "hello" => json!({"id": id, "ok": true, "proto": 1, "mode": "locked"}),
                    "api.call" => {
                        let a = answers
                            .get(calls)
                            .cloned()
                            .unwrap_or(Answer::Denied("no_script"));
                        calls += 1;
                        match a {
                            Answer::Done(status, body) => json!({
                                "id": id, "ok": true, "status": status, "headers": [],
                                "truncated": false,
                                "body_b64": base64::engine::general_purpose::STANDARD.encode(body),
                            }),
                            Answer::Denied(rule) => json!({
                                "id": id, "ok": false, "error": "denied",
                                "message": format!("denied ({rule})"), "rule": rule,
                            }),
                            Answer::Pending(p) => json!({"id": id, "ok": true, "pending": p}),
                        }
                    }
                    _ => {
                        json!({"id": id, "ok": false, "error": "bad_request", "message": "unexpected op"})
                    }
                };
                if write_frame(&mut s, &ans).is_err() {
                    break;
                }
            }
        }
    }
}

#[cfg(unix)]
use fake::Answer;

#[cfg(unix)]
const THREE_STEPS: &str = r#"name = "report"
[[step]]
service = "erp"
operation = "invoices.list"
params = { status = "{{status}}" }
[[step]]
service = "erp"
operation = "invoices.create"
body = { customer = "{{who}}", lines = [1, 2] }
[[step]]
service = "other"
operation = "things.list"
"#;

#[cfg(unix)]
#[test]
fn each_step_is_one_api_call() {
    let w = World::new(
        &[
            Answer::Done(200, r#"{"items":[1]}"#),
            Answer::Done(201, r#"{"id":"inv-9"}"#),
            Answer::Done(200, "plain text"),
        ],
        "report",
        THREE_STEPS,
    );
    let o = w.run(&["report", "status=open", "who=}}{{status}}"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let calls = w.api_calls();
    assert_eq!(calls.len(), 3, "{:?}", w.frames());
    // Only hello and the three calls: no other op, no shortcut.
    let ops: Vec<String> = w.frames().into_iter().map(|(op, _)| op).collect();
    assert_eq!(ops, ["hello", "api.call", "api.call", "api.call"]);
    for c in &calls {
        assert_eq!(c.get("collection"), Some(&json!("report")), "{c:?}");
        assert!(c["project"].is_string());
    }
    assert_eq!(
        (&calls[0]["service"], &calls[0]["operation"]),
        (&json!("erp"), &json!("invoices.list"))
    );
    assert_eq!(calls[0]["params"], json!({"status": "open"}));
    assert!(calls[0].get("body_b64").is_none());
    assert_eq!(calls[1]["operation"], "invoices.create");
    use base64::Engine as _;
    let body = base64::engine::general_purpose::STANDARD
        .decode(calls[1]["body_b64"].as_str().unwrap())
        .unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    // The value went in literally.
    assert_eq!(body, json!({"customer": "}}{{status}}", "lines": [1, 2]}));
    assert_eq!(calls[2]["service"], "other");
    assert_eq!(calls[2]["params"], json!({}));
    // stdout: one JSON array; stderr: one summary line per step.
    let out: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(
        out,
        json!([
            {"step": 1, "service": "erp", "operation": "invoices.list", "status": 200, "data": {"items": [1]}},
            {"step": 2, "service": "erp", "operation": "invoices.create", "status": 201, "data": {"id": "inv-9"}},
            {"step": 3, "service": "other", "operation": "things.list", "status": 200, "data": "plain text"},
        ])
    );
    let err = stderr(&o);
    let lines: Vec<&str> = err.lines().filter(|l| l.contains("→")).collect();
    assert_eq!(lines.len(), 3, "{err}");
    assert!(
        lines[0].contains("step 1/3 erp invoices.list → 200"),
        "{err}"
    );
    assert!(
        lines[2].contains("step 3/3 other things.list → 200"),
        "{err}"
    );
}

#[cfg(unix)]
#[test]
fn stops_at_first_non_done_with_its_exit_code() {
    let args = ["report", "status=open", "who=ann"];
    // A deny: exit 2, step 3 never sent.
    let w = World::new(
        &[Answer::Done(200, "{}"), Answer::Denied("default_deny")],
        "report",
        THREE_STEPS,
    );
    let o = w.run(&args);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert_eq!(w.api_calls().len(), 2);
    assert!(stderr(&o).contains("step 2"), "{}", stderr(&o));
    assert!(stderr(&o).contains("default_deny"), "{}", stderr(&o));
    let out: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(out.as_array().unwrap().len(), 1, "{out}");

    // A pending step: exit 3 with its id, and no resume.
    let w = World::new(
        &[Answer::Done(200, "{}"), Answer::Pending(77)],
        "report",
        THREE_STEPS,
    );
    let o = w.run(&args);
    assert_eq!(o.status.code(), Some(3), "{}", stderr(&o));
    assert_eq!(w.api_calls().len(), 2);
    assert!(stderr(&o).contains("#77"), "{}", stderr(&o));
    assert!(
        !w.frames().iter().any(|(op, _)| op == "api.result"),
        "{:?}",
        w.frames()
    );

    // An upstream status >= 400: exit 1, the step's data is in the output.
    let w = World::new(
        &[Answer::Done(404, r#"{"error":"nope"}"#)],
        "report",
        THREE_STEPS,
    );
    let o = w.run(&args);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert_eq!(w.api_calls().len(), 1);
    let out: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(out[0]["status"], 404);
    assert_eq!(out[0]["data"], json!({"error": "nope"}));

    // --wait and --body do not apply to a collection.
    let w = World::new(&[], "report", THREE_STEPS);
    let o = w
        .cmd(&[
            "--wait",
            "1m",
            "collection",
            "run",
            "report",
            "status=a",
            "who=b",
        ])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(w.api_calls().is_empty());
}

/// Runs `cmd` to its exit, at most 10 s; a hang kills the test's own child
/// and fails.
#[cfg(unix)]
fn output_within(mut cmd: std::process::Command) -> (std::process::Output, std::time::Duration) {
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    let started = Instant::now();
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > Duration::from_secs(10) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the command hung on a FIFO");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    (child.wait_with_output().unwrap(), started.elapsed())
}

/// A FIFO, or a symlink, planted in `.saiife/collections/` is refused
/// before it is opened: `load`, `collection list` and `collection run`
/// answer at once instead of blocking on the FIFO.
#[cfg(unix)]
#[test]
fn collection_files_must_be_regular_files() {
    use std::time::Duration;
    let w = World::new(
        &[],
        "good",
        SPEC_EXAMPLE.replace("open-orders-report", "good").as_str(),
    );
    let root = w.tmp.path().join("project");
    let dir = root.join(".saiife/collections");
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{mknodat, FileType, Mode, CWD};
        mknodat(
            CWD,
            dir.join("pipe.toml"),
            FileType::Fifo,
            Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
    }
    // rustix has no mknodat on Apple targets.
    #[cfg(not(target_os = "linux"))]
    assert!(std::process::Command::new("mkfifo")
        .arg(dir.join("pipe.toml"))
        .status()
        .unwrap()
        .success());
    std::os::unix::fs::symlink(dir.join("good.toml"), dir.join("link.toml")).unwrap();

    for name in ["pipe", "link"] {
        let e = load(&root, name).unwrap_err();
        assert!(
            matches!(&e, CollectionError::Io(_, why) if why == "not a regular file"),
            "{name}: {e:?}"
        );
    }
    assert!(load(&root, "good").is_ok());

    let (o, took) = output_within(w.cmd(&["collection", "list"]));
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(took < Duration::from_secs(5), "{took:?}");
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert_eq!(out.trim(), "good  1  shopify", "{out}");
    assert!(stderr(&o).contains("pipe"), "{}", stderr(&o));
    assert!(stderr(&o).contains("not a regular file"), "{}", stderr(&o));

    let (o, took) = output_within(w.cmd(&["collection", "run", "pipe"]));
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(took < Duration::from_secs(5), "{took:?}");
    assert!(stderr(&o).contains("not a regular file"), "{}", stderr(&o));
    assert!(w.api_calls().is_empty(), "{:?}", w.frames());
}
