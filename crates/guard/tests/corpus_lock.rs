//! Golden corpus for the `core.lock` pack (spec §6.17): in locked mode an
//! agent may not change privileges, touch saiife's service, set up
//! persistence, turn off an agent's safety switches, or write saiife's
//! system paths and the managed agent settings. Everyday work and reading
//! saiife's setup stay allowed.

use std::fs;
use std::path::PathBuf;

use saiifeguard::builtins::builtin_packs;
use saiifeguard::canon::PathVars;
use saiifeguard::engine::{Decision, Engine};
use saiifeguard::pathrule::Access;

const TEST_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
}

impl Fixture {
    fn new() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let home = root.join("home");
        for d in ["app/src", ".local/share/saiife/audit", ".config"] {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        Fixture { _dir: dir, home }
    }

    /// The variables as `path_vars_locked` binds them for a host with the
    /// default system config.
    fn vars(&self) -> PathVars {
        PathVars::new()
            .with_cwd(self.home.join("app"))
            .with_var("HOME", &self.home)
            .with_var("PROJECT", self.home.join("app"))
            .with_var("SAIIFE_DATA_DIR", self.home.join(".local/share/saiife"))
            .with_var(
                "SAIIFE_AUDIT_DIR",
                self.home.join(".local/share/saiife/audit"),
            )
            .with_var("SAIIFE_AUDIT_DIR", "/var/log/saiife/audit")
            .with_var("SAIIFE_ETC", "/etc/saiife")
            .with_var("SAIIFE_STATE", "/var/lib/saiife")
            .with_var("SAIIFE_LOG", "/var/log/saiife")
            .with_var("SAIIFE_RUN", "/run/saiife")
            .with_var("SAIIFE_OPT", "/opt/saiife")
            .with_var("SAIIFE_UNIT", "/etc/systemd/system/saiifed.service")
    }

    /// `core.lock` alone.
    fn engine(&self) -> Engine {
        let (packs, warnings) = builtin_packs();
        assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
        let lock: Vec<_> = packs.into_iter().filter(|p| p.id == "core.lock").collect();
        assert_eq!(lock.len(), 1, "core.lock ships");
        assert!(!lock[0].default_on, "core.lock is off outside locked mode");
        Engine::new(lock)
            .with_budget(TEST_BUDGET)
            .with_paths(self.vars())
    }
}

fn assert_lock_denies(e: &Engine, cmd: &str) {
    match e.evaluate(cmd) {
        Decision::Deny { pack, reason, .. } => {
            assert_eq!(pack, "core.lock", "{cmd}");
            assert!(!reason.is_empty(), "{cmd}");
        }
        other => panic!("expected DENY for {cmd:?}, got {other:?}"),
    }
}

fn assert_lock_denies_path(e: &Engine, access: Access, path: &str) {
    match e.evaluate_path(access, path) {
        Decision::Deny { pack, .. } => assert_eq!(pack, "core.lock", "{path}"),
        other => panic!(
            "expected DENY for {} of {path:?}, got {other:?}",
            access.label()
        ),
    }
}

#[test]
fn privilege_changes_are_denied() {
    let f = Fixture::new();
    let e = f.engine();
    for cmd in [
        "sudo ls",
        "sudo -u root id",
        "su -",
        "doas sh",
        "pkexec bash",
        "run0 id",
        "osascript -e 'do shell script \"x\" with administrator privileges'",
        "/usr/bin/sudo ls",
        "env sudo ls",
        "FOO=1 sudo ls",
        "cd /tmp && sudo rm x",
        "bash -c 'sudo ls'",
        "echo x | sudo tee /etc/hosts",
    ] {
        assert_lock_denies(&e, cmd);
    }
}

#[test]
fn touching_the_service_is_denied() {
    let f = Fixture::new();
    let e = f.engine();
    for cmd in [
        "systemctl stop saiifed",
        "systemctl --now disable saiifed.service",
        "sudo systemctl mask saiifed",
        "pkill saiifed",
        "killall -9 saiifed",
        "kill -TERM saiifed",
        "launchctl bootout system/com.saiife.saiifed",
        "launchctl unload com.saiife.saiifed",
    ] {
        assert_lock_denies(&e, cmd);
    }
}

#[test]
fn persistence_is_denied() {
    let f = Fixture::new();
    let e = f.engine();
    for cmd in [
        "crontab -e",
        "crontab /tmp/cron",
        "echo x | at now",
        "at 10:00 -f job.sh",
        "systemd-run --user sh",
        "systemd-run --on-calendar=daily --user /tmp/x",
        "launchctl load ~/Library/LaunchAgents/x.plist",
        "launchctl bootstrap gui/501 ~/Library/LaunchAgents/x.plist",
        "echo x > ~/.config/systemd/user/x.service",
        "cp x.desktop ~/.config/autostart/",
        "cp x.plist ~/Library/LaunchAgents/x.plist",
    ] {
        assert_lock_denies(&e, cmd);
    }
}

#[test]
fn safety_switches_are_denied() {
    let f = Fixture::new();
    let e = f.engine();
    for cmd in [
        "codex --dangerously-bypass-hook-trust",
        "codex exec --dangerously-bypass-hook-trust fix",
        "GEMINI_CLI_SYSTEM_SETTINGS_PATH=/tmp/s gemini",
        "GEMINI_CLI_SYSTEM_DEFAULTS_PATH=/tmp/s gemini -p hi",
        "env GEMINI_CLI_SYSTEM_SETTINGS_PATH=/tmp/s gemini",
        "export GEMINI_CLI_SYSTEM_SETTINGS_PATH=/tmp/s",
    ] {
        assert_lock_denies(&e, cmd);
    }
}

#[test]
fn writes_to_saiifes_system_paths_are_denied() {
    let f = Fixture::new();
    let e = f.engine();
    let user_unit = f.home.join(".config/systemd/user/x.service");
    for path in [
        "/etc/saiife/config.toml",
        "/etc/saiife/policy.d/10-x.toml",
        "/etc/saiife",
        "/etc",
        "/",
        "/var/lib/saiife/keys/audit.ed25519",
        "/var/lib/saiife",
        "/var/lib",
        "/var/log/saiife/audit/2026-11.jsonl",
        "/var/log/saiife",
        "/run/saiife/saiife.sock",
        "/run/saiife",
        "/opt/saiife/bin/saiife",
        "/opt",
        "/etc/systemd/system/saiifed.service",
        "/etc/systemd/system",
        "/etc/claude-code/managed-settings.d/50-saiife.json",
        "/etc/claude-code/managed-settings.d",
        "/etc/claude-code/managed-settings.json",
        "/etc/codex/requirements.toml",
        "/etc/codex",
        "/etc/gemini-cli/settings.json",
        "/etc/gemini-cli",
        "~/.config/systemd/user/x.service",
        "~/Library/LaunchAgents/x.plist",
        "~/.config/autostart/x.desktop",
    ] {
        assert_lock_denies_path(&e, Access::Write, path);
    }
    assert_lock_denies_path(&e, Access::Write, &user_unit.display().to_string());
    // saiife's state (the signing key) may not even be read.
    assert_lock_denies_path(&e, Access::Read, "/var/lib/saiife/keys/audit.ed25519");
    for cmd in [
        "rm -rf /etc/saiife",
        "echo x >> /etc/saiife/config.toml",
        "sed -i s/locked/x/ /etc/saiife/config.toml",
        "mv /etc /tmp/x",
        "cat /var/lib/saiife/keys/audit.ed25519",
        "truncate -s0 /var/log/saiife/audit/2026-11.jsonl",
        "rm /run/saiife/saiife.sock",
        "cp /bin/true /opt/saiife/bin/saiife",
        "rm /etc/systemd/system/saiifed.service",
        "rm /etc/claude-code/managed-settings.d/50-saiife.json",
        "echo x > /etc/codex/requirements.toml",
        "rm -rf /etc/gemini-cli",
    ] {
        assert_lock_denies(&e, cmd);
    }
}

#[test]
fn everyday_work_and_reading_the_setup_are_allowed() {
    let f = Fixture::new();
    let e = f.engine();
    for cmd in [
        "systemctl status nginx",
        "systemctl --user restart pipewire",
        "ls /etc/saiife",
        "cat /etc/saiife/config.toml",
        "cat /etc/codex/requirements.toml",
        "journalctl -u nginx",
        "kill 1234",
        "kill -9 %1",
        "pkill node",
        "atop",
        "suspend-test",
        "sudoku",
        "echo sudo",
        "git commit -m 'run sudo later'",
        "cat",
        "make at",
        "cargo test",
        "ls ~/.config",
        "echo x > notes.txt",
        "codex exec fix",
        "gemini -p hi",
        "launchctl list",
    ] {
        let d = e.evaluate(cmd);
        assert!(!d.is_deny(), "expected ALLOW for {cmd:?}, got {d:?}");
    }
    for path in [
        "/etc/saiife/config.toml",
        "/etc/saiife",
        "/var/log/saiife/audit/2026-11.jsonl",
        "/etc/claude-code/managed-settings.d/50-saiife.json",
        "/etc/systemd/system/saiifed.service",
    ] {
        let d = e.evaluate_path(Access::Read, path);
        assert!(
            !d.is_deny(),
            "expected ALLOW for read of {path:?}, got {d:?}"
        );
    }
    for path in [
        "src/main.rs",
        "/tmp/x",
        "~/.config/other/x",
        "/etc/hosts.new",
    ] {
        let d = e.evaluate_path(Access::Write, path);
        assert!(
            !d.is_deny(),
            "expected ALLOW for write of {path:?}, got {d:?}"
        );
    }
}

/// The locked config dir and audit dir are guarded under every value they
/// are bound to, not only the defaults.
#[test]
fn extra_locked_values_are_guarded() {
    let f = Fixture::new();
    let (packs, _) = builtin_packs();
    let lock: Vec<_> = packs.into_iter().filter(|p| p.id == "core.lock").collect();
    let e = Engine::new(lock).with_budget(TEST_BUDGET).with_paths(
        f.vars()
            .with_var("SAIIFE_ETC", "/srv/saiife/etc")
            .with_var("SAIIFE_AUDIT_DIR", "/srv/saiife/audit")
            .with_var("SAIIFE_RUN", "/srv/saiife/run"),
    );
    for path in [
        "/srv/saiife/etc/config.toml",
        "/srv/saiife/audit/2026-11.jsonl",
        "/srv/saiife/run/saiife.sock",
        "/srv/saiife",
        "/srv",
    ] {
        assert_lock_denies_path(&e, Access::Write, path);
    }
}
