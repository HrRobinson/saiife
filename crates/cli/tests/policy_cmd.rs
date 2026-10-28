//! `saiife policy show|reload` against a real daemon on temp dirs, and the
//! `check`/`test` commands as a CI would run them (users from files, so no
//! host account is needed). Nothing leaves the temp dirs.
#![cfg(target_os = "linux")]

mod common;

use common::daemon::{own_group, own_user, Opts, TestDaemon};
use std::fs;
use std::process::{Command, Output, Stdio};

fn services() -> &'static str {
    r#"
[services.erp]
connector = "http"
base_url = "https://127.0.0.1:9/api"
secret = "erp-key"
auth = { kind = "header", name = "X-Api-Key" }
allow = ["invoices:read"]

[[services.erp.operation]]
id = "invoices.list"
capability = "invoices:read"
kind = "read"
method = "GET"
path = "/echo"

[services.crm]
connector = "http"
base_url = "https://127.0.0.1:9/crm"
secret = "crm-key"
auth = { kind = "header", name = "X-Api-Key" }
allow = ["contacts:read"]

[[services.crm.operation]]
id = "contacts.list"
capability = "contacts:read"
kind = "read"
method = "GET"
path = "/contacts"
"#
}

fn policy(admin: bool) -> String {
    let admin = if admin {
        format!("[admin]\ngroups = [{:?}]\n\n", own_group())
    } else {
        String::new()
    };
    format!(
        r#"{admin}[[scope]]
name = "mine"
users = [{user:?}]
services = ["erp"]
env = "prod"

[environments.prod]

[[scope]]
name = "theirs"
users = ["somebody-else"]
services = ["crm"]
{services}"#,
        user = own_user(),
        services = services(),
    )
}

fn world(admin: bool) -> TestDaemon {
    TestDaemon::start(Opts {
        extra: policy(admin),
        ..Opts::default()
    })
}

fn saiife(d: &TestDaemon, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_saiife"))
        .arg("policy")
        .args(args)
        .arg("--system-config")
        .arg(d.config())
        .env("HOME", d.path().join("home"))
        .env("XDG_RUNTIME_DIR", d.path().join("no-runtime"))
        .env("PATH", "/usr/bin:/bin")
        .env("SAIIFE_DATA_DIR", d.path().join("data"))
        .env("SAIIFE_AUDIT_DIR", d.audit_dir())
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// A `[daemon]` section no real daemon answers on: a socket dir under the
/// test's temp dir and a user that does not exist, so a fixture never
/// reaches a daemon running on the host.
fn no_daemon(dir: &std::path::Path) -> String {
    format!(
        "[daemon]\nuser = \"saiife-test-none\"\nsocket_dir = {:?}\n",
        dir.join("run")
    )
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}
fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn show_own_scope_only_for_non_admin() {
    let d = world(false);
    let o = saiife(&d, &["show"]);
    assert_eq!(code(&o), 0, "{} / {}", stderr(&o), d.stderr_text());
    let out = stdout(&o);
    assert!(out.contains("policy: sha256:"), "{out}");
    assert!(out.contains("scope: mine (env prod)"), "{out}");
    assert!(out.contains("service erp"), "{out}");
    // Nothing of the other scope.
    assert!(
        !out.contains("crm") && !out.contains("theirs") && !out.contains("somebody-else"),
        "{out}"
    );
    // Naming yourself is fine; anyone else, and the whole policy, are not.
    assert_eq!(code(&saiife(&d, &["show", "--user", &own_user()])), 0);
    let o = saiife(&d, &["show", "--user", "root"]);
    assert_eq!(code(&o), 2, "{}", stderr(&o));
    assert!(stderr(&o).contains("[admin]"), "{}", stderr(&o));
    assert_eq!(code(&saiife(&d, &["show", "--effective"])), 2);
}

#[test]
fn admin_sees_effective_policy_and_any_user() {
    let d = world(true);
    let o = saiife(&d, &["show", "--effective"]);
    assert_eq!(code(&o), 0, "{} / {}", stderr(&o), d.stderr_text());
    let out = stdout(&o);
    assert!(out.contains("\"saiife_policy\": 1"), "{out}");
    assert!(out.contains("somebody-else"), "{out}");
    let o = saiife(&d, &["show", "--user", "root"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).contains("scope: none"), "{}", stdout(&o));
    // The hash printed is the daemon's.
    let hash = d.status()["policy"].as_str().unwrap().to_string();
    assert!(stdout(&saiife(&d, &["show"])).contains(&hash));
}

#[test]
fn reload_admin_only() {
    let d = world(false);
    let o = saiife(&d, &["reload"]);
    assert_eq!(code(&o), 2, "{}", stderr(&o));
    assert!(
        stderr(&o).contains("policy.reload is for"),
        "{}",
        stderr(&o)
    );
    assert!(d.events("policy").is_empty());

    let d = world(true);
    let before = d.status()["policy"].as_str().unwrap().to_string();
    // A changed policy is loaded.
    let opts = Opts {
        extra: format!("{}\n[guard]\nbudget_ms = 51\n", policy(true)),
        ..Opts::default()
    };
    fs::write(d.config(), d.config_text(&opts)).unwrap();
    let o = saiife(&d, &["reload"]);
    assert_eq!(code(&o), 0, "{} / {}", stderr(&o), d.stderr_text());
    assert_eq!(stdout(&o).trim(), "loaded");
    let after = d.status()["policy"].as_str().unwrap().to_string();
    assert_ne!(before, after);
    // An invalid one is rejected with its reason; the old one stays.
    let bad = Opts {
        extra: format!("{}\n[services.bad]\nconnector = \"nope\"\n", policy(true)),
        ..Opts::default()
    };
    fs::write(d.config(), d.config_text(&bad)).unwrap();
    let o = saiife(&d, &["reload"]);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stdout(&o).starts_with("rejected: "), "{}", stdout(&o));
    assert!(stdout(&o).contains("nope"), "{}", stdout(&o));
    assert_eq!(d.status()["policy"].as_str().unwrap(), after);
}

#[test]
fn show_asks_the_daemon_even_when_the_file_is_broken() {
    let d = world(false);
    let hash = d.status()["policy"].as_str().unwrap().to_string();
    // The file no longer loads (an unknown key), the daemon still runs.
    let mut text = fs::read_to_string(d.config()).unwrap();
    text.push_str("\n[guard]\nbogus = 1\n");
    fs::write(d.config(), text).unwrap();
    let o = saiife(&d, &["show"]);
    assert_eq!(code(&o), 0, "{} / {}", stderr(&o), d.stderr_text());
    assert!(stdout(&o).contains(&hash), "{}", stdout(&o));
    assert!(stdout(&o).contains("scope: mine"), "{}", stdout(&o));
}

#[test]
fn developer_mode_show_reads_the_file() {
    let tmp = common::tmp::short_tempdir();
    let cfg = tmp.path().join("config.toml");
    fs::write(&cfg, format!("version = 2\n{}", no_daemon(tmp.path()))).unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["policy", "show", "--user", "nobody-x", "--system-config"])
        .arg(&cfg)
        .env("HOME", tmp.path())
        .current_dir(tmp.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let out = stdout(&o);
    assert!(
        out.contains("policy: sha256:") && out.contains("scope: none"),
        "{out}"
    );
    // No daemon to reload.
    let o = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["policy", "reload", "--system-config"])
        .arg(&cfg)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(code(&o), 5, "{}", stderr(&o));
}

#[test]
fn locked_show_without_a_daemon_exits_5_not_the_file() {
    let tmp = common::tmp::short_tempdir();
    let cfg = tmp.path().join("config.toml");
    fs::write(
        &cfg,
        format!(
            "version = 2\nlocked = true\n{}[[scope]]\nname = \"from-the-file\"\nusers = [\"nobody-x\"]\n",
            no_daemon(tmp.path())
        ),
    )
    .unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["policy", "show", "--user", "nobody-x", "--system-config"])
        .arg(&cfg)
        .env("HOME", tmp.path())
        .current_dir(tmp.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(code(&o), 5, "{} / {}", stdout(&o), stderr(&o));
    assert!(stdout(&o).is_empty(), "{}", stdout(&o));
    assert!(
        stderr(&o).contains("cannot reach the saiife daemon")
            && stderr(&o).contains("locked = true"),
        "{}",
        stderr(&o)
    );
    // A locked config that cannot be parsed is not developer mode either.
    fs::write(&cfg, "version = 2\nlocked = [\n").unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["policy", "show", "--user", "nobody-x", "--system-config"])
        .arg(&cfg)
        .env("HOME", tmp.path())
        .current_dir(tmp.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(code(&o), 2, "{}", stderr(&o));
    assert!(stdout(&o).is_empty(), "{}", stdout(&o));
}

/// `policy check` and `test` as CI runs them: the accounts come from files.
#[test]
fn check_and_test_binary_with_user_files() {
    let tmp = common::tmp::short_tempdir();
    let p = tmp.path();
    fs::write(p.join("passwd"), "agent-shop:x:4001:4001::/h:/bin/sh\n").unwrap();
    fs::write(p.join("group"), "").unwrap();
    let cfg = p.join("config.toml");
    let text = |expect: &str| {
        format!(
            r#"version = 2
{daemon}
[[scope]]
name = "shop"
users = ["agent-shop"]
services = ["shopify"]
[services.shopify]
connector = "shopify"
secret = "s"
params = {{ shop = "acme" }}
allow = ["orders:read"]
[[example]]
user = "agent-shop"
request = "shopify orders.list"
expect = "{expect}"
"#,
            daemon = no_daemon(p),
        )
    };
    let run = |sub: &str| {
        Command::new(env!("CARGO_BIN_EXE_saiife"))
            .args(["policy", sub])
            .arg(&cfg)
            .arg("--passwd")
            .arg(p.join("passwd"))
            .arg("--group")
            .arg(p.join("group"))
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    fs::write(&cfg, text("allow")).unwrap();
    assert_eq!(code(&run("check")), 0);
    let o = run("test");
    assert_eq!(code(&o), 0, "{}", stdout(&o));
    assert!(stdout(&o).contains("ok   example 1"), "{}", stdout(&o));
    fs::write(&cfg, text("deny")).unwrap();
    assert_eq!(code(&run("check")), 0);
    assert_eq!(code(&run("test")), 1);
}
