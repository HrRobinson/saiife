//! `saiife connect <service>` against a real daemon on temp dirs (plan 10,
//! Task 15). The daemon runs as the test user; admin ops authorize through
//! `[admin] groups = [<primary group>]`.
#![cfg(target_os = "linux")]

mod common;

use common::daemon::{own_group, Opts, TestDaemon};
use saiife_broker::catalog::{validate, Catalog};
use saiife_broker::manifest::builtin;
use saiife_policy::{decide, load_system, Capability, Mode, Request, Verdict};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output, Stdio};

const TOKEN: &str = "shpat_connect_test_value_123";

fn admin() -> TestDaemon {
    TestDaemon::start(Opts {
        extra: format!("[admin]\ngroups = [{:?}]\n", own_group()),
        ..Opts::default()
    })
}

fn connect(d: &TestDaemon, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_saiife"))
        .arg("connect")
        .args(args)
        .arg("--config")
        .arg(d.config())
        .env("HOME", d.path().join("home"))
        .env("PATH", "/usr/bin:/bin")
        .env("SAIIFE_DATA_DIR", d.path().join("data"))
        .env("SAIIFE_AUDIT_DIR", d.audit_dir())
        .env("CONNECT_TEST_TOKEN", TOKEN)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn secrets(d: &TestDaemon) -> Vec<String> {
    let o = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["secret", "list", "--json", "--system-config"])
        .arg(d.config())
        .env("HOME", d.path().join("home"))
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", err(&o));
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    v["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap().to_string())
        .collect()
}

fn policy_file(d: &TestDaemon, name: &str) -> std::path::PathBuf {
    d.path().join("etc/policy.d").join(name)
}

#[test]
fn generated_file_denies_everything() {
    let d = admin();
    let o = connect(
        &d,
        &[
            "shopify",
            "--param",
            "shop=acme",
            "--from-env",
            "CONNECT_TEST_TOKEN",
        ],
    );
    assert!(o.status.success(), "{}", err(&o));
    let out = String::from_utf8_lossy(&o.stdout);
    let path = policy_file(&d, "shopify.toml");
    assert!(
        out.contains(&format!(
            "next: edit {}, then saiife policy reload",
            path.display()
        )),
        "{out}"
    );
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert_eq!(secrets(&d), vec!["shopify".to_string()]);

    let text = fs::read_to_string(&path).unwrap();
    for h in ["# allow = [", "# ask = [", "# deny = ["] {
        assert!(text.contains(h), "{h}");
    }
    assert!(text.contains("# refunds.create write"), "{text}");
    assert!(!text.contains(TOKEN));
    // No active list.
    assert!(!text.lines().any(|l| {
        let l = l.trim_start();
        l.starts_with("allow") || l.starts_with("ask") || l.starts_with("deny")
    }));

    let loaded = load_system(&d.config()).expect("loads");
    let cat = Catalog::new(builtin(), vec![]);
    validate(&loaded.config, &cat).expect("validates");
    let svc = &loaded.config.services["shopify"];
    assert_eq!(svc.params["shop"], "acme");
    assert_eq!(svc.secret.as_deref(), Some("shopify"));
    let m = builtin().iter().find(|m| m.id == "shopify").unwrap();
    assert!(!m.operation.is_empty());
    for o in &m.operation {
        let cap = Capability::parse(&o.capability).unwrap();
        let params = BTreeMap::new();
        let v = decide(
            svc,
            None,
            Mode::Locked,
            &Request {
                capability: &cap,
                params: &params,
            },
        );
        assert_eq!(
            v,
            Verdict::Deny {
                rule: "default_deny".into()
            },
            "{}",
            o.id
        );
    }
}

#[test]
fn existing_file_refused() {
    let d = admin();
    fs::create_dir_all(d.path().join("etc/policy.d")).unwrap();
    let p = policy_file(&d, "shopify.toml");
    fs::write(&p, "# mine\n").unwrap();
    let o = connect(
        &d,
        &[
            "shopify",
            "--param",
            "shop=acme",
            "--from-env",
            "CONNECT_TEST_TOKEN",
        ],
    );
    assert_eq!(o.status.code(), Some(2));
    assert!(
        err(&o).contains("policy.d/shopify.toml exists; edit it"),
        "{}",
        err(&o)
    );
    assert_eq!(fs::read_to_string(&p).unwrap(), "# mine\n");
    assert!(secrets(&d).is_empty(), "nothing is stored");
}

#[test]
fn unknown_connector_refused() {
    let d = admin();
    let o = connect(&d, &["nope", "--from-env", "CONNECT_TEST_TOKEN"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("unknown connector nope"), "{}", err(&o));

    let o = connect(
        &d,
        &[
            "web",
            "--connector",
            "http",
            "--from-env",
            "CONNECT_TEST_TOKEN",
        ],
    );
    assert_eq!(o.status.code(), Some(2));
    assert!(
        err(&o).contains("the http connector is configured by hand: see docs/connectors/http.md"),
        "{}",
        err(&o)
    );
    assert!(secrets(&d).is_empty());
    assert!(!policy_file(&d, "nope.toml").exists());
    assert!(!policy_file(&d, "web.toml").exists());
}

#[test]
fn required_param_prompted_or_refused() {
    let d = admin();
    // No terminal: refused by name.
    let o = connect(&d, &["shopify", "--from-env", "CONNECT_TEST_TOKEN"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("missing --param shop"), "{}", err(&o));
    // A value that fails the manifest pattern.
    let o = connect(
        &d,
        &[
            "shopify",
            "--param",
            "shop=Bad Shop",
            "--from-env",
            "CONNECT_TEST_TOKEN",
        ],
    );
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("--param shop"), "{}", err(&o));
    // A parameter the manifest does not declare.
    let o = connect(
        &d,
        &[
            "shopify",
            "--param",
            "x=1",
            "--from-env",
            "CONNECT_TEST_TOKEN",
        ],
    );
    assert_eq!(o.status.code(), Some(2));
    assert!(secrets(&d).is_empty());
    assert!(!policy_file(&d, "shopify.toml").exists());
    // GitHub has no required parameter: no prompt, no refusal.
    let o = connect(&d, &["github", "--from-env", "CONNECT_TEST_TOKEN"]);
    assert!(o.status.success(), "{}", err(&o));
    assert!(policy_file(&d, "github.toml").exists());
}

#[test]
fn unwritable_policy_dir_stores_nothing() {
    let d = admin();
    let dir = d.path().join("etc/policy.d");
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o555)).unwrap();
    let o = connect(
        &d,
        &[
            "shopify",
            "--param",
            "shop=acme",
            "--from-env",
            "CONNECT_TEST_TOKEN",
        ],
    );
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(secrets(&d).is_empty());
}

fn add_secret(d: &TestDaemon, name: &str, service: &str) {
    let o = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args([
            "secret",
            "add",
            name,
            "--kind",
            "token",
            "--service",
            service,
        ])
        .args(["--from-env", "CONNECT_TEST_TOKEN", "--system-config"])
        .arg(d.config())
        .env("HOME", d.path().join("home"))
        .env("PATH", "/usr/bin:/bin")
        .env("CONNECT_TEST_TOKEN", TOKEN)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", err(&o));
}

#[test]
fn existing_secret_is_reused_when_it_allows_the_service() {
    let d = admin();
    add_secret(&d, "imported", "shopify");
    let o = connect(
        &d,
        &["shopify", "--param", "shop=acme", "--secret", "imported"],
    );
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert_eq!(secrets(&d), vec!["imported".to_string()]);
    let text = fs::read_to_string(policy_file(&d, "shopify.toml")).unwrap();
    assert!(text.contains("secret = \"imported\""), "{text}");
}

#[test]
fn existing_secret_for_another_service_is_refused() {
    let d = admin();
    add_secret(&d, "imported", "github");
    let o = connect(
        &d,
        &["shopify", "--param", "shop=acme", "--secret", "imported"],
    );
    assert_eq!(o.status.code(), Some(2));
    assert!(
        err(&o).contains("secret imported exists but does not allow shopify; use another name"),
        "{}",
        err(&o)
    );
    assert!(!policy_file(&d, "shopify.toml").exists());
}
