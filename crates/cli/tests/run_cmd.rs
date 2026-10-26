//! `saiife run --secret` against a real daemon on temp dirs (plan 10,
//! Task 16). There is no root in tests, so the positive path runs a binary
//! that is root-owned on every Linux box (`printenv`, else `echo`), found
//! at test time; with none, the test prints why and skips.
#![cfg(target_os = "linux")]

mod common;

use common::daemon::{own_group, own_user, Opts, TestDaemon};
use serde_json::Value;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const VALUE: &str = "Zq9-run-secret-VALUE-1";

/// A root-owned regular file with a root-owned, non-writable chain, as the
/// daemon will judge it.
fn root_owned_bin() -> Option<PathBuf> {
    for c in ["/usr/bin/printenv", "/bin/echo"] {
        let Ok(p) = fs::canonicalize(c) else { continue };
        if fs::metadata(&p).map(|m| m.is_file()).unwrap_or(false)
            && saiife_system::fsops::root_owned_chain(&p).is_ok()
        {
            return Some(p);
        }
    }
    None
}

fn other_root_bin(not: &Path) -> Option<PathBuf> {
    for c in [
        "/usr/bin/true",
        "/bin/true",
        "/usr/bin/id",
        "/usr/bin/whoami",
    ] {
        let Ok(p) = fs::canonicalize(c) else { continue };
        if p != not && saiife_system::fsops::root_owned_chain(&p).is_ok() {
            return Some(p);
        }
    }
    None
}

macro_rules! need {
    ($e:expr) => {
        match $e {
            Some(b) => b,
            None => {
                eprintln!("skipped: no root-owned printenv or echo on this machine");
                return;
            }
        }
    };
}

fn config_extra(run_allow: &[&Path], scoped: bool) -> String {
    let list: Vec<String> = run_allow
        .iter()
        .map(|p| format!("{:?}", p.display().to_string()))
        .collect();
    let mut s = format!(
        "[admin]\ngroups = [{:?}]\n\n[secrets.tok]\nrun_allow = [{}]\n",
        own_group(),
        list.join(", ")
    );
    if scoped {
        s.push_str(&format!(
            "\n[[scope]]\nname = \"t\"\nusers = [{:?}]\n",
            own_user()
        ));
    }
    s
}

fn start(run_allow: &[&Path], scoped: bool) -> TestDaemon {
    let d = TestDaemon::start(Opts {
        extra: config_extra(run_allow, scoped),
        ..Opts::default()
    });
    let o = secret_add(&d);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    d
}

fn secret_add(d: &TestDaemon) -> Output {
    Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["secret", "--system-config"])
        .arg(d.config())
        .args(["add", "tok", "--kind", "token", "--service", "s"])
        .args(["--from-env", "SV"])
        .env("SV", VALUE)
        .env("HOME", d.path().join("home"))
        .env("PATH", "/usr/bin:/bin")
        .env("SAIIFE_DATA_DIR", d.path().join("data"))
        .env("SAIIFE_AUDIT_DIR", d.audit_dir())
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn run(d: &TestDaemon, path: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_saiife"))
        .arg("run")
        .arg("--system-config")
        .arg(d.config())
        .args(args)
        .env("HOME", d.path().join("home"))
        .env("PATH", path)
        .env("SAIIFE_DATA_DIR", d.path().join("data"))
        .env("SAIIFE_AUDIT_DIR", d.audit_dir())
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn uses(d: &TestDaemon) -> Vec<Value> {
    d.of_kind("secret")
        .into_iter()
        .filter(|r| r["event"] == "secret_use")
        .collect()
}

/// The value appears nowhere on disk or on a stream of this run.
fn assert_no_leak(d: &TestDaemon, outs: &[&Output]) {
    let mut hay = String::new();
    for o in outs {
        hay.push_str(&out(o));
        hay.push_str(&err(o));
    }
    for e in fs::read_dir(d.audit_dir()).unwrap() {
        hay.push_str(&String::from_utf8_lossy(
            &fs::read(e.unwrap().path()).unwrap(),
        ));
    }
    hay.push_str(&d.stderr_text());
    assert!(!hay.contains(VALUE), "the value leaked");
}

#[test]
fn run_masks_value_in_output() {
    let bin = need!(root_owned_bin());
    let dir = bin.parent().unwrap().display().to_string();
    let d = start(&[&bin], true);
    let name = bin.file_name().unwrap().to_str().unwrap();
    let args: Vec<&str> = if name == "printenv" {
        vec!["--secret", "tok:TOKEN", "--", name, "TOKEN"]
    } else {
        // echo has no env access: the value is passed as an argument by the
        // test through the shell-free `printenv`-less path, so only check
        // the lease and the exit code.
        vec!["--secret", "tok:TOKEN", "--", name, "hello"]
    };
    let o = run(&d, &dir, &args);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    if name == "printenv" {
        assert_eq!(out(&o), "[MASKED]\n");
    } else {
        assert_eq!(out(&o), "hello\n");
    }
    let u = uses(&d);
    assert_eq!(u.len(), 1, "{u:?}");
    assert_eq!(u[0]["decision"], "allow");
    assert_eq!(
        u[0]["input"].as_str().unwrap(),
        format!("run tok {}", bin.display())
    );
    assert_eq!(u[0]["name"], "tok");
    assert_no_leak(&d, &[&o]);
    assert_eq!(d.verify().status.code(), Some(0));
}

#[test]
fn default_env_name_is_upper_cased_with_underscores() {
    let bin = need!(root_owned_bin());
    if bin.file_name().unwrap() != "printenv" {
        eprintln!("skipped: printenv is not root-owned here");
        return;
    }
    let dir = bin.parent().unwrap().display().to_string();
    let d = start(&[&bin], true);
    // `tok` -> TOK
    let o = run(&d, &dir, &["--secret", "tok", "--", "printenv", "TOK"]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert_eq!(out(&o), "[MASKED]\n");
}

#[test]
fn exit_code_is_passed_through() {
    let bin = need!(root_owned_bin());
    if bin.file_name().unwrap() != "printenv" {
        eprintln!("skipped: printenv is not root-owned here");
        return;
    }
    let dir = bin.parent().unwrap().display().to_string();
    let d = start(&[&bin], true);
    // printenv exits 1 for an unset variable.
    let o = run(
        &d,
        &dir,
        &["--secret", "tok", "--", "printenv", "NOPE_UNSET"],
    );
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
}

#[test]
fn not_listed_refused_and_recorded() {
    let bin = need!(root_owned_bin());
    let other = need!(other_root_bin(&bin));
    let d = start(&[&bin], true);
    let dir = other.parent().unwrap().display().to_string();
    let name = other.file_name().unwrap().to_str().unwrap();
    let o = run(&d, &dir, &["--secret", "tok", "--", name]);
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
    assert!(err(&o).contains("run_not_allowed"), "{}", err(&o));
    let u = uses(&d);
    assert_eq!(u.len(), 1, "{u:?}");
    assert_eq!(u[0]["decision"], "deny");
    assert_eq!(u[0]["rule"], "run_not_allowed");
    assert_eq!(
        u[0]["input"].as_str().unwrap(),
        format!("run tok {}", other.display())
    );
    assert_no_leak(&d, &[&o]);
}

#[test]
fn interpreter_in_run_allow_is_config_error() {
    let d = TestDaemon::prepare(&Opts {
        extra: "[secrets.tok]\nrun_allow = [\"/usr/bin/bash\"]\n".into(),
        ..Opts::default()
    });
    let o = d.run_to_exit();
    assert!(!o.status.success());
    let e = String::from_utf8_lossy(&o.stderr).into_owned();
    assert!(e.contains("interpreter"), "{e}");
}

#[test]
fn canonical_interpreter_behind_a_symlink_is_refused() {
    // An innocent-looking name in the list that resolves to a shell.
    let Ok(sh) = fs::canonicalize("/bin/sh") else {
        eprintln!("skipped: no /bin/sh");
        return;
    };
    if saiife_system::fsops::root_owned_chain(&sh).is_err() {
        eprintln!("skipped: the shell is not root-owned here");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let link = tmp.path().join("purpose-built");
    std::os::unix::fs::symlink(&sh, &link).unwrap();
    let d = start(&[&link], true);
    let dir = sh.parent().unwrap().display().to_string();
    let name = sh.file_name().unwrap().to_str().unwrap();
    let o = run(&d, &dir, &["--secret", "tok", "--", name, "-c", "echo hi"]);
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
    assert_eq!(uses(&d)[0]["decision"], "deny");
    assert_no_leak(&d, &[&o]);
}

#[test]
fn user_owned_binary_refused() {
    let bin = need!(root_owned_bin());
    let tmp = tempfile::tempdir().unwrap();
    let copy = fs::canonicalize(tmp.path())
        .unwrap()
        .join(bin.file_name().unwrap());
    fs::copy(&bin, &copy).unwrap();
    assert_ne!(fs::metadata(&copy).unwrap().uid(), 0);
    let d = start(&[&copy], true);
    let dir = copy.parent().unwrap().display().to_string();
    let name = copy.file_name().unwrap().to_str().unwrap();
    let o = run(&d, &dir, &["--secret", "tok", "--", name, "TOK"]);
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
    let u = uses(&d);
    assert_eq!(u.len(), 1, "{u:?}");
    assert_eq!(u[0]["decision"], "deny");
    assert_eq!(u[0]["rule"], "run_not_allowed");
    assert_no_leak(&d, &[&o]);
}

#[test]
fn no_scope_refused() {
    let bin = need!(root_owned_bin());
    let dir = bin.parent().unwrap().display().to_string();
    let d = start(&[&bin], false);
    let name = bin.file_name().unwrap().to_str().unwrap();
    let o = run(&d, &dir, &["--secret", "tok", "--", name, "TOK"]);
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
    assert!(err(&o).contains("no_scope"), "{}", err(&o));
    let u = uses(&d);
    assert_eq!(u.len(), 1, "{u:?}");
    assert_eq!(u[0]["decision"], "deny");
    assert_eq!(u[0]["rule"], "no_scope");
    assert_no_leak(&d, &[&o]);
}
