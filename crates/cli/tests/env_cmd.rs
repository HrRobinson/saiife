//! `saiife env list|use`, and environments in the guard hook and the policy
//! tools. Every file lives in a temp dir; the root-only path runs through the
//! debug-build seam `SAIIFE_TEST_ASSUME_ROOT`.
#![cfg(target_os = "linux")]

mod common;

use common::daemon::{own_user, Opts, TestDaemon};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}
fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

const ENVS: &str = r#"
[environments.staging]
guard.packs = ["db.postgres"]

[environments.prod]
guard.packs = ["db.postgres", "container.k8s"]
"#;

/// `saiife env <args> --system-config <config>` run in `cwd`.
fn env_cmd(cwd: &Path, config: &Path, args: &[&str], assume_root: bool) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_saiife"));
    c.arg("env")
        .args(args)
        .arg("--system-config")
        .arg(config)
        .current_dir(cwd)
        .env("HOME", cwd.join("home"))
        .env("PATH", "/usr/bin:/bin")
        .env("SAIIFE_DATA_DIR", cwd.join("data"))
        .env("SAIIFE_AUDIT_DIR", cwd.join("audit"))
        .env_remove("SAIIFE_TEST_ASSUME_ROOT")
        .stdin(Stdio::null());
    if assume_root {
        c.env("SAIIFE_TEST_ASSUME_ROOT", "1");
    }
    c.output().unwrap()
}

/// A developer-mode world: a system config (not locked) that defines
/// environments, and a project whose config chooses `staging`.
fn dev_world() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let d = common::tmp::short_tempdir();
    let config = d.path().join("config.toml");
    fs::write(&config, format!("version = 2\n{ENVS}")).unwrap();
    let project = d.path().join("proj");
    fs::create_dir_all(project.join(".saiife")).unwrap();
    fs::write(
        project.join(".saiife/config.toml"),
        "# my project\nversion = 2\nenv = \"staging\" # chosen\n\n[services.x]\nallow = []\n",
    )
    .unwrap();
    (d, config, project)
}

#[test]
fn list_marks_applying_env_developer() {
    let (_d, config, project) = dev_world();
    let o = env_cmd(&project, &config, &["list"], false);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let text = out(&o);
    let staging = text.lines().find(|l| l.contains("staging")).unwrap();
    let prod = text.lines().find(|l| l.contains("prod")).unwrap();
    assert!(staging.starts_with('*'), "{text}");
    assert!(!prod.starts_with('*'), "{text}");
    assert!(prod.contains("packs+ 2"), "{text}");
}

#[test]
fn list_json_shape() {
    let (_d, config, project) = dev_world();
    let o = env_cmd(&project, &config, &["list", "--json"], false);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let v: Value = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(
        v,
        json!([
            {"name": "prod", "applies": false, "scopes": [], "packs": ["db.postgres", "container.k8s"], "services": []},
            {"name": "staging", "applies": true, "scopes": [], "packs": ["db.postgres"], "services": []},
        ])
    );
}

#[test]
fn use_developer_writes_project_key_keeps_comments() {
    let (_d, config, project) = dev_world();
    let o = env_cmd(&project, &config, &["use", "prod"], false);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let text = fs::read_to_string(project.join(".saiife/config.toml")).unwrap();
    assert!(text.contains("env = \"prod\""), "{text}");
    assert!(
        text.contains("# my project") && text.contains("[services.x]"),
        "{text}"
    );
    assert!(!text.contains("staging"), "{text}");
    let o = env_cmd(&project, &config, &["list", "--json"], false);
    let v: Value = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(v[0]["applies"], true, "{v}");
}

#[test]
fn use_undefined_env_refused() {
    let (_d, config, project) = dev_world();
    let before = fs::read_to_string(project.join(".saiife/config.toml")).unwrap();
    let o = env_cmd(&project, &config, &["use", "nope"], false);
    assert_eq!(code(&o), 2);
    assert!(err(&o).contains("not defined"), "{}", err(&o));
    assert_eq!(
        fs::read_to_string(project.join(".saiife/config.toml")).unwrap(),
        before
    );
    // Locked: refused too, as root.
    let (_l, lconfig) = locked_world();
    let o = env_cmd(
        _l.path(),
        &lconfig,
        &["use", "nope", "--scope", "shop"],
        true,
    );
    assert_eq!(code(&o), 2);
    assert!(err(&o).contains("not defined"), "{}", err(&o));
}

fn locked_world() -> (tempfile::TempDir, std::path::PathBuf) {
    let d = common::tmp::short_tempdir();
    let etc = d.path().join("etc");
    fs::create_dir_all(etc.join("policy.d")).unwrap();
    let config = etc.join("config.toml");
    fs::write(
        &config,
        format!(
            "version = 2\nlocked = true\n[daemon]\nuser = \"saiife-test-none\"\nsocket_dir = {:?}\n{ENVS}",
            d.path().join("run")
        ),
    )
    .unwrap();
    let drop_in = etc.join("policy.d/shop.toml");
    fs::write(
        &drop_in,
        format!(
            "# the shop scope\n[[scope]]\nname = \"shop\"\nusers = [{:?}]\nenv = \"staging\"\n",
            own_user()
        ),
    )
    .unwrap();
    fs::set_permissions(&drop_in, fs::Permissions::from_mode(0o640)).unwrap();
    (d, config)
}

fn running_as_root() -> bool {
    rustix::process::geteuid().is_root()
}

#[test]
fn use_locked_non_root_refused() {
    if running_as_root() {
        return;
    }
    let (d, config) = locked_world();
    let file = d.path().join("etc/policy.d/shop.toml");
    let before = fs::read_to_string(&file).unwrap();
    let o = env_cmd(
        d.path(),
        &config,
        &["use", "prod", "--scope", "shop"],
        false,
    );
    assert_eq!(code(&o), 2);
    let e = err(&o);
    assert!(e.contains("needs root") && e.contains("shop.toml"), "{e}");
    assert_eq!(fs::read_to_string(&file).unwrap(), before);
}

#[test]
fn use_locked_rewrites_scope_binding() {
    let (d, config) = locked_world();
    let file = d.path().join("etc/policy.d/shop.toml");
    let o = env_cmd(d.path(), &config, &["use", "prod", "--scope", "shop"], true);
    // No daemon answers in this fixture: the failed reload is reported
    // (non-zero), the file is already rewritten.
    assert_eq!(code(&o), 5, "{} / {}", out(&o), err(&o));
    assert!(
        err(&o).contains("file updated; reload failed"),
        "{}",
        err(&o)
    );
    let text = fs::read_to_string(&file).unwrap();
    assert!(
        text.contains("env = \"prod\"") && !text.contains("staging"),
        "{text}"
    );
    assert!(text.contains("# the shop scope"), "{text}");
    assert_eq!(
        fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o640
    );
    // config.toml itself is untouched.
    assert!(!fs::read_to_string(&config).unwrap().contains("[[scope]]"));
    // An unknown scope is refused.
    let o = env_cmd(d.path(), &config, &["use", "prod", "--scope", "nope"], true);
    assert_eq!(code(&o), 2);
    // Locked mode needs --scope.
    let o = env_cmd(d.path(), &config, &["use", "prod"], true);
    assert_eq!(code(&o), 2);
    assert!(err(&o).contains("--scope"), "{}", err(&o));
}

#[test]
fn use_locked_refuses_a_symlinked_target() {
    let (d, config) = locked_world();
    let file = d.path().join("etc/policy.d/shop.toml");
    let real = d.path().join("elsewhere.toml");
    fs::rename(&file, &real).unwrap();
    std::os::unix::fs::symlink(&real, &file).unwrap();
    let before = fs::read_to_string(&real).unwrap();
    let o = env_cmd(d.path(), &config, &["use", "prod", "--scope", "shop"], true);
    assert_eq!(code(&o), 2, "{}", err(&o));
    assert!(err(&o).contains("not a regular file"), "{}", err(&o));
    assert_eq!(fs::read_to_string(&real).unwrap(), before);
    assert!(fs::symlink_metadata(&file)
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn list_locked_marks_scope_env() {
    let (d, config) = locked_world();
    let o = env_cmd(d.path(), &config, &["list", "--json"], false);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let v: Value = serde_json::from_str(&out(&o)).unwrap();
    let staging = v
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "staging");
    assert_eq!(staging.unwrap()["applies"], true, "{v}");
    assert_eq!(staging.unwrap()["scopes"], json!(["shop"]));
}

// ---- the guard and the policy tools use the scope's environment

fn managed(config: &Path, project: &Path, command: &str) -> Output {
    let sb = common::tmp::short_tempdir();
    let payload = json!({
        "session_id": "s-env",
        "cwd": project,
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })
    .to_string();
    let mut child = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["check", "--managed", "--agent", "claude", "--system-config"])
        .arg(config)
        .env("HOME", sb.path().join("home"))
        .env("PATH", "/usr/bin:/bin")
        .env("SAIIFE_DATA_DIR", sb.path().join("data"))
        .env("SAIIFE_AUDIT_DIR", sb.path().join("audit"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        let mut sin = child.stdin.take().unwrap();
        let _ = sin.write_all(payload.as_bytes());
    }
    child.wait_with_output().unwrap()
}

fn shown_hash(d: &TestDaemon, env: &str) -> String {
    let o = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["policy", "show", "--system-config"])
        .arg(d.config())
        .env("HOME", d.path().join("home"))
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let text = out(&o);
    text.lines()
        .find_map(|l| l.strip_prefix(&format!("policy (env {env}): ")))
        .unwrap_or_else(|| panic!("no hash for {env}:\n{text}\n{}", err(&o)))
        .to_string()
}

#[test]
fn check_managed_hash_includes_env() {
    let extra = format!(
        "[[scope]]\nname = \"mine\"\nusers = [{:?}]\nenv = \"prod\"\n{}",
        own_user(),
        "[environments.prod]\nguard.packs = [\"db.postgres\"]\n"
    );
    let d = TestDaemon::start(Opts {
        extra,
        ..Opts::default()
    });
    let project = d.path().join("proj");
    fs::create_dir_all(&project).unwrap();
    // The env's pack is enforced: dropdb is denied by db.postgres, which
    // is off in the base config.
    let o = managed(&d.config(), &project, "dropdb customers");
    assert_eq!(code(&o), 2, "stderr: {}", err(&o));
    let r = d.of_kind("guard").pop().unwrap();
    assert_eq!(r["decision"], "deny", "{r}");
    // ... and its record carries the env's hash, as `policy show` prints.
    assert_eq!(r["policy"], shown_hash(&d, "prod"));
    assert_ne!(r["policy"], d.status()["policy"]);
}

#[test]
fn policy_test_example_uses_scope_env() {
    let d = common::tmp::short_tempdir();
    let p = d.path();
    fs::write(
        p.join("passwd"),
        "agent-a:x:4001:4001::/h:/bin/sh\nagent-b:x:4002:4002::/h:/bin/sh\n",
    )
    .unwrap();
    fs::write(p.join("group"), "").unwrap();
    let config = p.join("config.toml");
    fs::write(
        &config,
        r#"version = 2

[[scope]]
name = "prod-scope"
users = ["agent-a"]
env = "prod"

[[scope]]
name = "plain-scope"
users = ["agent-b"]

[environments.prod]
guard.packs = ["db.postgres"]

[[example]]
user = "agent-a"
command = "dropdb customers"
expect = "deny"

[[example]]
user = "agent-b"
command = "dropdb customers"
expect = "allow"
"#,
    )
    .unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["policy", "test"])
        .arg(&config)
        .arg("--passwd")
        .arg(p.join("passwd"))
        .arg("--group")
        .arg(p.join("group"))
        .env("HOME", p.join("home"))
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(code(&o), 0, "{} / {}", out(&o), err(&o));
    assert!(out(&o).contains("2 passed, 0 failed"), "{}", out(&o));
}

#[test]
fn hook_applies_a_group_bound_scope_env() {
    let extra = format!(
        "[[scope]]\nname = \"devs\"\nusers = [\"group:{}\"]\nenv = \"prod\"\n\n\
         [environments.prod]\nguard.packs = [\"db.postgres\"]\n",
        common::daemon::own_group()
    );
    let d = TestDaemon::start(Opts {
        extra,
        ..Opts::default()
    });
    let project = d.path().join("proj");
    fs::create_dir_all(&project).unwrap();
    let o = managed(&d.config(), &project, "dropdb customers");
    assert_eq!(code(&o), 2, "stderr: {}", err(&o));
    let r = d.of_kind("guard").pop().unwrap();
    assert_eq!(r["decision"], "deny", "{r}");
    assert_eq!(r["policy"], shown_hash(&d, "prod"));
}

#[test]
fn hook_ignores_a_locked_project_env() {
    let extra = format!(
        "[[scope]]\nname = \"mine\"\nusers = [{:?}]\nenv = \"prod\"\n\n\
         [environments.prod]\n\n[environments.other]\nguard.packs = [\"db.postgres\"]\n",
        own_user()
    );
    let d = TestDaemon::start(Opts {
        extra,
        ..Opts::default()
    });
    let project = d.path().join("proj");
    fs::create_dir_all(project.join(".saiife")).unwrap();
    fs::write(
        project.join(".saiife/config.toml"),
        "version = 2\nenv = \"other\"\n",
    )
    .unwrap();
    // The project's `other` would deny dropdb; the scope's `prod` does not.
    let o = managed(&d.config(), &project, "dropdb customers");
    assert_eq!(code(&o), 0, "stderr: {}", err(&o));
    let r = d.of_kind("guard").pop().unwrap();
    assert_eq!(r["decision"], "allow", "{r}");
    // (The record hash also covers the project overlay, so it is not the bare prod hash.)
}

/// Without `--system-config`, `env` finds its config through plan 16's
/// resolver: on a host with no locked config that is the personal broker's
/// own (`$XDG_CONFIG_HOME/saiife/broker/config.toml`). No broker needs to
/// run: listing and `env use` read and write files only.
#[test]
fn list_personal_config_via_broker_resolve() {
    let b = common::personal::TestBroker::prepare();
    b.write_config(&format!("version = 2\n{ENVS}"));
    let project = b.path().join("p");
    fs::create_dir_all(project.join(".saiife")).unwrap();
    fs::write(
        project.join(".saiife/config.toml"),
        "version = 2\nenv = \"staging\"\n",
    )
    .unwrap();
    let o = b.run_cli(&["env", "list", "--json"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let v: Value = serde_json::from_str(&out(&o)).unwrap();
    let names: Vec<(&str, bool)> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (e["name"].as_str().unwrap(), e["applies"] == true))
        .collect();
    assert_eq!(names, [("prod", false), ("staging", true)], "{v}");
    // `env use` checks the name against the broker's config too.
    let o = b.run_cli(&["env", "use", "prod"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let text = fs::read_to_string(project.join(".saiife/config.toml")).unwrap();
    assert!(text.contains("env = \"prod\""), "{text}");
    let o = b.run_cli(&["env", "use", "qa"]);
    assert_eq!(code(&o), 2);
    assert!(err(&o).contains("not defined"), "{}", err(&o));
    // No broker config: no environments (never the host's /etc config).
    fs::remove_file(b.config()).unwrap();
    let o = b.run_cli(&["env", "list", "--json"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert_eq!(out(&o).trim(), "[]");
}
