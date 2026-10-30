//! `saiife system install|uninstall`, only ever against a temp root with the
//! fake host (`--root`). Nothing here touches the real machine. Locked mode
//! is Linux-only: on macOS install refuses every root, so the tests that
//! install run on Linux only.

use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;
use std::fs;
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn saiife() -> Command {
    let mut c = Command::cargo_bin("saiife").unwrap();
    // Nothing may leak into or out of the developer's environment.
    let home = tempfile::tempdir().unwrap().keep();
    c.env("HOME", &home)
        .env("SAIIFE_DATA_DIR", home.join("data"))
        .env("SAIIFE_AUDIT_DIR", home.join("audit"));
    c
}

fn fake_root() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    fs::create_dir_all(d.path().join("etc")).unwrap();
    fs::write(
        d.path().join("etc/os-release"),
        "NAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\nID=ubuntu\n",
    )
    .unwrap();
    fs::create_dir_all(d.path().join("run/systemd/system")).unwrap();
    // The fake host: systemd 249 (Ubuntu 22.04).
    fs::write(d.path().join(".fakehost.json"), r#"{"systemd": 249}"#).unwrap();
    d
}

fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

#[test]
fn install_without_root_refused() {
    // As root this would be a real install: never run it that way.
    if is_root() {
        eprintln!("skipped: running as root");
        return;
    }
    saiife()
        .args(["system", "install", "--non-interactive"])
        .assert()
        .code(2)
        .stderr(contains(
            "saiife: system install needs root (run it with sudo)",
        ));
    saiife()
        .args(["system", "uninstall"])
        .assert()
        .code(2)
        .stderr(contains("needs root"));
}

#[cfg(target_os = "linux")]
#[test]
fn install_and_uninstall_under_root_flag() {
    let root = fake_root();
    let r = root.path().to_str().unwrap();
    saiife()
        .args(["system", "install", "--root", r, "--agents", "claude,codex"])
        .args(["--approvers", "alice,group:ops", "--non-interactive"])
        .assert()
        // Installed; doctor fails the daemon checks under the fake host.
        .code(1);
    let p = |rel: &str| root.path().join(rel);
    assert!(p("opt/saiife/bin/saiife").is_file());
    assert!(p("etc/claude-code/managed-settings.d/50-saiife.json").is_file());
    assert!(p("etc/codex/requirements.toml").is_file());
    assert!(!p("etc/gemini-cli/settings.json").exists());
    let unit = fs::read_to_string(p("etc/systemd/system/saiifed.service")).unwrap();
    assert!(unit.contains("\nLoadCredential=vault-key:"));
    assert_eq!(
        fs::read(p("etc/saiife/credstore/vault-key")).unwrap().len(),
        32
    );
    let cfg = fs::read_to_string(p("etc/saiife/config.toml")).unwrap();
    assert!(
        cfg.contains("approvers = [\"alice\", \"group:ops\"]"),
        "{cfg}"
    );
    let installed = fs::read_to_string(p("etc/saiife/installed.toml")).unwrap();
    assert!(installed.contains("/opt/saiife/bin/saiife"), "{installed}");
    assert!(!installed.contains(r), "installed.toml holds logical paths");
    // The fake host saw the start, never a real systemctl.
    let fake = fs::read_to_string(p(".fakehost.json")).unwrap();
    assert!(fake.contains("systemctl enable --now saiifed.service"));

    // Again: idempotent.
    saiife()
        .args(["system", "install", "--root", r, "--agents", "claude,codex"])
        .assert()
        .code(1);

    saiife()
        .args(["system", "uninstall", "--root", r])
        .assert()
        .success()
        .stdout(contains("removed /opt/saiife/bin/saiife"));
    assert!(!p("opt").exists());
    assert!(!p("etc/codex").exists());
    assert!(p("etc/saiife/config.toml").is_file());
    assert!(!p("etc/saiife/installed.toml").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn install_under_root_runs_doctor() {
    let root = fake_root();
    let out = saiife()
        .args(["system", "install", "--root"])
        .arg(root.path())
        .args(["--agents", "claude", "--non-interactive"])
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    // No daemon answers under the fake host: daemon.health fails.
    assert_eq!(out.status.code(), Some(1), "{stdout}{stderr}");
    assert!(
        stdout.contains("saiife: locked mode is installed"),
        "{stdout}"
    );
    assert!(stdout.contains("FAIL  daemon.health  "), "{stdout}");
    assert!(stdout.contains("\ndoctor: "), "{stdout}");
    // The cargo-built binary is a test build: under --root install only
    // warns (on the real system it refuses), and doctor fails files.binary
    // when it is dynamically linked.
    let (warning, last) = stderr.trim_end().rsplit_once('\n').unwrap_or(("", &stderr));
    assert_eq!(
        last.trim_end(),
        "saiife: installed, but doctor found failures: fix them before relying on the lock"
    );
    assert!(
        warning.starts_with("saiife: warning: ") && warning.contains("test build"),
        "{stderr}"
    );
    assert!(stdout.contains("  files.binary  "), "{stdout}");
    assert!(!stdout.contains("install failed") && !stderr.contains("install failed"));
}

#[cfg(target_os = "linux")]
#[test]
fn unsupported_root_exits_2_with_the_refusal_line() {
    let root = fake_root();
    fs::write(
        root.path().join("etc/os-release"),
        "ID=alpine\nVERSION_ID=3.20.0\n",
    )
    .unwrap();
    saiife()
        .args(["system", "install", "--root"])
        .arg(root.path())
        .assert()
        .code(2)
        .stderr(contains("saiife: locked mode is not supported here: "))
        .stderr(contains(". Developer mode works as before."));
    assert!(!root.path().join("etc/saiife").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn step_failure_exits_2_with_the_step() {
    let root = fake_root();
    saiife()
        .args(["system", "install", "--root"])
        .arg(root.path())
        .args(["--config", "/nonexistent/saiife-config.toml"])
        .assert()
        .code(2)
        .stderr(contains("saiife: install failed at "));
}

#[cfg(target_os = "linux")]
#[test]
fn fleet_install_under_root_flag() {
    let root = fake_root();
    let p = |rel: &str| root.path().join(rel);
    let fleet = p("etc/saiife/fleet");
    fs::create_dir_all(&fleet).unwrap();
    for d in ["etc", "etc/saiife", "etc/saiife/fleet"] {
        fs::set_permissions(p(d), fs::Permissions::from_mode(0o755)).unwrap();
    }
    let config = "version = 2\nlocked = true\n\n[guard]\nbudget_ms = 40\n";
    fs::write(fleet.join("config.toml"), config).unwrap();
    fs::write(
        fleet.join("install.toml"),
        "agents = [\"claude\", \"codex\"]\n",
    )
    .unwrap();
    for f in ["config.toml", "install.toml"] {
        fs::set_permissions(fleet.join(f), fs::Permissions::from_mode(0o644)).unwrap();
    }
    saiife()
        .args(["system", "install", "--fleet", "--root"])
        .arg(root.path())
        .assert()
        // Installed; doctor fails the daemon checks under the fake host.
        .code(1);
    assert_eq!(
        fs::read(p("etc/saiife/config.toml")).unwrap(),
        config.as_bytes()
    );
    assert!(p("etc/claude-code/managed-settings.d/50-saiife.json").is_file());
    assert!(p("etc/codex/requirements.toml").is_file());
    assert!(!p("etc/gemini-cli/settings.json").exists());

    // A group-writable fleet dir: exit 2 naming it, nothing changed.
    fs::set_permissions(&fleet, fs::Permissions::from_mode(0o775)).unwrap();
    fs::write(fleet.join("install.toml"), "agents = [\"gemini\"]\n").unwrap();
    saiife()
        .args(["system", "install", "--fleet", "--root"])
        .arg(root.path())
        .assert()
        .code(2)
        .stderr(contains(
            "saiife: install failed at check: /etc/saiife/fleet: mode 0775",
        ));
    assert!(!p("etc/gemini-cli").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn fleet_with_no_agents_warns() {
    let root = fake_root();
    let p = |rel: &str| root.path().join(rel);
    let fleet = p("etc/saiife/fleet");
    fs::create_dir_all(&fleet).unwrap();
    for d in ["etc", "etc/saiife", "etc/saiife/fleet"] {
        fs::set_permissions(p(d), fs::Permissions::from_mode(0o755)).unwrap();
    }
    fs::write(fleet.join("install.toml"), "agents = []\n").unwrap();
    fs::set_permissions(
        fleet.join("install.toml"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    saiife()
        .args(["system", "install", "--fleet", "--root"])
        .arg(root.path())
        .assert()
        .code(1)
        .stderr(contains(
            "saiife: warning: no agents listed: no agent is guarded",
        ))
        .stdout(contains("WARN  agents  "));
    assert!(!p("etc/claude-code").exists());
    assert!(!p("etc/codex").exists());
    assert!(!p("etc/gemini-cli").exists());
}

/// With a fleet config, approvers in install.toml would be dropped without
/// a word: install refuses them before it changes anything.
#[cfg(target_os = "linux")]
#[test]
fn fleet_approvers_beside_a_fleet_config_refused() {
    let root = fake_root();
    let p = |rel: &str| root.path().join(rel);
    let fleet = p("etc/saiife/fleet");
    fs::create_dir_all(&fleet).unwrap();
    for d in ["etc", "etc/saiife", "etc/saiife/fleet"] {
        fs::set_permissions(p(d), fs::Permissions::from_mode(0o755)).unwrap();
    }
    fs::write(fleet.join("config.toml"), "version = 2\nlocked = true\n").unwrap();
    fs::write(
        fleet.join("install.toml"),
        "agents = [\"claude\"]\napprovers = [\"group:ops\"]\n",
    )
    .unwrap();
    for f in ["config.toml", "install.toml"] {
        fs::set_permissions(fleet.join(f), fs::Permissions::from_mode(0o644)).unwrap();
    }
    saiife()
        .args(["system", "install", "--fleet", "--root"])
        .arg(root.path())
        .assert()
        .code(2)
        .stderr(contains(
            "saiife: install failed at check: /etc/saiife/fleet/install.toml: approvers is not used",
        ))
        .stderr(contains(
            "[approval] approvers in /etc/saiife/fleet/config.toml",
        ));
    assert!(!p("opt").exists());
    assert!(!p("etc/saiife/config.toml").exists());
}

#[test]
fn fleet_conflicts_with_config() {
    let root = fake_root();
    for extra in [
        ["--config", "/nonexistent/c.toml"],
        ["--agents", "claude"],
        ["--approvers", "alice"],
    ] {
        saiife()
            .args(["system", "install", "--fleet", "--root"])
            .arg(root.path())
            .args(extra)
            .assert()
            .code(2)
            .stderr(contains("cannot be used with"));
    }
    assert!(!root.path().join("opt").exists());
    assert!(!root.path().join("etc/saiife").exists());
}

#[test]
fn unknown_agent_is_a_usage_error() {
    let root = fake_root();
    saiife()
        .args(["system", "install", "--root"])
        .arg(root.path())
        .args(["--agents", "cursor"])
        .assert()
        .code(2)
        .stderr(contains("cursor"));
    assert!(!Path::new(&root.path().join("opt")).exists());
}

#[test]
fn keep_audit_conflicts_with_purge() {
    let root = fake_root();
    saiife()
        .args(["system", "uninstall", "--keep-audit", "--purge", "--root"])
        .arg(root.path())
        .assert()
        .code(2)
        .stderr(contains("cannot be used with"));
}

#[test]
fn root_flag_is_hidden() {
    saiife()
        .args(["system", "install", "--help"])
        .assert()
        .success()
        .stdout(contains("--agents"))
        .stdout(predicates::str::contains("--root").not());
}
