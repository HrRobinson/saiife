//! Golden corpus for the `core.lock` pack (spec §6.17): in locked mode an
//! agent may not change privileges, touch saiife's service, set up
//! persistence, turn off an agent's safety switches, or write saiife's
//! system paths and the managed agent settings. Everyday work and reading
//! saiife's setup stay allowed.

use std::fs;
use std::path::PathBuf;

use saiifeguard::builtins::builtin_packs;
use saiifeguard::canon::PathVars;
use saiifeguard::engine::{AllowTrace, Decision, Engine};
use saiifeguard::pathrule::Access;

const TEST_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

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

    /// A hand-written copy of what the CLI's `path_vars_locked` binds on a
    /// host with the default system config (this crate cannot call it):
    /// the §5.2 defaults, the per-user and the system audit dir, and
    /// `XDG_CONFIG_HOME` at its default (the locked worker's environment
    /// is cleared). `crates/cli/src/paths.rs` tests the real binding.
    fn vars(&self) -> PathVars {
        PathVars::new()
            .with_cwd(self.home.join("app"))
            .with_var("HOME", &self.home)
            .with_var("XDG_CONFIG_HOME", self.home.join(".config"))
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
        "sudo",
        "sudo -l",
        // Every wrapper the engine peels (fix round 1, I1).
        "timeout 5 sudo ls",
        "time sudo ls",
        "stdbuf -o0 sudo ls",
        "ionice -c3 sudo ls",
        "xargs sudo ls",
        "flock /tmp/l sudo ls",
        "chroot / sudo ls",
        "builtin exec sudo ls",
        "nice -n 5 sudo ls",
        "env -u FOO sudo ls",
        "env --unset FOO sudo ls",
        "nohup sudo ls",
        "command sudo ls",
        "timeout 5 doas sh",
        "xargs pkexec bash",
        "nice -n 5 su -",
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
        "timeout 5 systemctl stop saiifed",
        "timeout 1 pkill saiifed",
        "xargs kill saiifed",
        // Prefixes, globs, the user (M2).
        "pkill saiif",
        "pkill sai",
        "pkill -f saiife",
        "pkill -u saiife",
        "killall -u saiife",
        "systemctl stop saiif*",
        "systemctl stop 'saiife*'",
        "systemctl stop 'sai*'",
        "systemctl kill saiifed",
        "systemctl -s status kill saiifed",
        "sudo systemctl status saiifed",
        "timeout 5 systemctl status saiifed",
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
        // Behind wrappers (I1).
        "timeout 5 crontab -e",
        "xargs crontab < /tmp/c",
        "echo x | timeout 5 at now",
        "timeout 5 systemd-run --user sh",
        "sudo crontab -l",
        // More schedulers and unit managers (I2).
        "echo x | batch",
        "loginctl enable-linger",
        "loginctl enable-linger jonas",
        "systemctl --user link /tmp/x.service",
        "systemctl --user enable x",
        "systemctl --user enable --now x",
        "systemctl enable --user x",
        "systemctl --user edit x",
        "systemctl --user daemon-reload",
        "systemctl --user preset x",
        "systemctl --user revert x",
        "systemctl --user add-wants default.target x",
        "systemctl --user add-requires default.target x",
        // Unit dirs replaced from outside, or their parents moved (I2).
        "mkdir -p /tmp/s/user && mv /tmp/s ~/.config/systemd",
        "ln -s /tmp/u ~/.config/systemd",
        "mv ~/.config/systemd /tmp/x",
        "mv ~/.config ~/.config.bak",
        "echo x > ~/.local/share/systemd/user/x.service",
        "echo x > /run/user/1000/systemd/user/x.service",
        "echo x > ~/.config/systemd/user.control/x.service",
        "mv /tmp/la ~/Library/LaunchAgents",
        "ln -s /tmp/a ~/.config/autostart",
    ] {
        assert_lock_denies(&e, cmd);
    }
    for path in [
        "~/.config/systemd",
        "~/.config",
        "~/.config/systemd/user",
        "~/.config/systemd/user.control/x.service",
        "~/.local/share/systemd/user/x.service",
        "~/.local/share/systemd",
        "/run/user/1000/systemd/user/x.service",
        "/run/user/1000/systemd/user",
        "~/Library",
        "~/.config/autostart",
    ] {
        assert_lock_denies_path(&e, Access::Write, path);
    }
}

/// Fix round 2: `setsid` is peeled (R1); the value options of `nice`,
/// `ionice` and `stdbuf` are skipped with their value (R2); `env -S`'s
/// string is judged as a command line (R3).
#[test]
fn launchers_and_wrapper_values_do_not_hide_the_command() {
    let f = Fixture::new();
    let e = f.engine();
    for cmd in [
        // R1
        "setsid crontab /tmp/c",
        "setsid -f crontab /tmp/c",
        "setsid --fork --wait crontab /tmp/c",
        "nohup setsid crontab /tmp/c &",
        "setsid at now",
        "setsid systemd-run --user sh",
        "setsid systemctl stop saiifed",
        "setsid pkill saiifed",
        "setsid sudo ls",
        // R2
        "nice -n5 sudo ls",
        "nice --adjustment=5 sudo ls",
        "nice --adjustment 5 sudo ls",
        "nice -n 5 --adjustment=5 sudo ls",
        "nice -n5 crontab /tmp/c",
        "nice -5 crontab /tmp/c",
        "nice -n -5 crontab /tmp/c",
        "ionice -c 3 sudo ls",
        "ionice -n 7 sudo ls",
        "ionice -c3 -n7 crontab /tmp/c",
        "ionice --class 3 crontab /tmp/c",
        "ionice -t -c 3 crontab /tmp/c",
        "stdbuf -o L sudo ls",
        "stdbuf -i 0 -o L -e 0 crontab /tmp/c",
        "stdbuf -oL crontab /tmp/c",
        "stdbuf --output L crontab /tmp/c",
        "stdbuf --output=L crontab /tmp/c",
        // R3
        "env -S 'sudo ls'",
        "env --split-string='crontab /tmp/c'",
        "env --split-string 'crontab /tmp/c'",
        "env -S'pkill saiifed'",
        "env -iS 'sudo ls'",
        "env -S 'FOO=1 crontab' /tmp/c",
        "timeout 5 env -S 'sudo ls'",
        "env -S 'env -S \"sudo ls\"'",
    ] {
        assert_lock_denies(&e, cmd);
    }
    for cmd in [
        "env -S 'ls -la'",
        "nice -n 5 cargo build",
        "setsid -f code .",
        "ionice -c 3 make",
        "stdbuf -o L tail -f log",
    ] {
        let d = e.evaluate(cmd);
        assert!(!d.is_deny(), "expected ALLOW for {cmd:?}, got {d:?}");
    }
}

/// Fix round 2 (R4): a pattern operand that matches saiifed without
/// spelling it.
#[test]
fn pattern_operands_matching_saiifed_are_denied() {
    let f = Fixture::new();
    let e = f.engine();
    for cmd in [
        "pkill 'sa.*fed'",
        "pkill -f 's[a]iifed'",
        "pkill -f 'S.IIFED'",
        "pkill d",
        "pkill -9 -f 'i+fed'",
        "pkill -f 'foo('",
        "killall -r '^sai'",
        "killall --regexp 'i+f'",
        "killall 'sai*'",
        "killall '*fed'",
        "systemctl stop 's*d.service'",
        "systemctl stop '*fed'",
        "systemctl restart 'saiife?'",
        "systemctl disable '[s]aiifed'",
        "systemctl mask 's[!x]iifed.service'",
        "timeout 5 pkill 'sa.*fed'",
    ] {
        assert_lock_denies(&e, cmd);
    }
    for cmd in [
        "pkill -f sain",
        "pkill -u jonas node",
        "pkill -f 'python app.py'",
        "systemctl restart saint",
        "systemctl stop sa",
        "systemctl restart 'nginx*'",
        "systemctl status '*'",
        "killall node",
        "killall -r '^node'",
        "pgrep -f 'sa.*fed'",
    ] {
        let d = e.evaluate(cmd);
        assert!(!d.is_deny(), "expected ALLOW for {cmd:?}, got {d:?}");
    }
}

fn assert_denies(e: &Engine, cmd: &str) {
    let d = e.evaluate(cmd);
    assert!(d.is_deny(), "expected DENY for {cmd:?}, got {d:?}");
}

/// Fix round 3 (T1): env's own escapes, `${…}` and `#` in an `env -S`
/// string are not modelled: denied outright.
#[test]
fn env_split_string_escapes_fail_closed() {
    let f = Fixture::new();
    let e = f.engine();
    for cmd in [
        "env -S 'crontab\\_/tmp/c'",
        "env -S 'sudo\\_ls'",
        "env -S 'sudo\\_-u\\_root\\_id'",
        "env -S 'pkill\\_saiifed'",
        "env -S 'systemctl\\_stop\\_saiifed'",
        "env -S 'crontab\\c' /tmp/c",
        "X=sudo env -S '${X} ls'",
        "env -S 'ls #x'",
    ] {
        match e.evaluate(cmd) {
            Decision::Deny { reason, .. } => {
                assert_eq!(reason, "env -S escapes are not judged", "{cmd}")
            }
            d => panic!("expected DENY for {cmd:?}, got {d:?}"),
        }
    }
    for cmd in ["env -S 'node --inspect' app.js", "env -S 'ls -la'"] {
        let d = e.evaluate(cmd);
        assert!(!d.is_deny(), "expected ALLOW for {cmd:?}, got {d:?}");
    }
}

/// Fix round 3 (T2): long options by unambiguous prefix, as getopt reads
/// them; an unknown or ambiguous one leaves the segment not fully judged.
#[test]
fn wrapper_long_option_prefixes_are_resolved() {
    let f = Fixture::new();
    let e = f.engine();
    for cmd in [
        "nice --adj 5 crontab /tmp/c",
        "nice --adj 5 sudo ls",
        "nice --adj=5 sudo ls",
        "stdbuf --out L crontab /tmp/c",
        "stdbuf --err 0 sudo ls",
        "ionice --classd 7 crontab /tmp/c",
        "env --sp='crontab /tmp/c'",
        "env --sp='sudo ls'",
        "env --split-s 'crontab /tmp/c'",
        "timeout --sig KILL 5 crontab /tmp/c",
        "sudo --us root crontab -l",
    ] {
        assert_denies(&e, cmd);
    }
    for cmd in ["nice --frobnicate 5 crontab", "stdbuf --x L sudo-free-cmd"] {
        match e.evaluate(cmd) {
            Decision::Allow {
                trace: AllowTrace::Unjudgeable { reason },
            } => assert!(reason.contains("wrapper option"), "{cmd}: {reason}"),
            d => panic!("expected an unjudged allow for {cmd:?}, got {d:?}"),
        }
    }
    let d = e.evaluate("nice --adjustment=5 make");
    assert!(
        matches!(
            d,
            Decision::Allow {
                trace: AllowTrace::NoMatch
            }
        ),
        "{d:?}"
    );
}

/// Fix round 3 (T3): many operands stay within the budget, and what
/// follows is still judged.
#[test]
fn many_operands_stay_within_budget() {
    let f = Fixture::new();
    // The production budget is 50 ms; these take about 2–13 ms in a debug
    // build. A generous engine budget and a 250 ms wall-clock bound keep a
    // loaded test runner from turning the check into a flake, while one
    // regex compile per operand (~0.2 ms each, 2000 of them) would still
    // blow it.
    let e = f.engine();
    let plain: Vec<String> = (0..400).map(|i| format!("w{i}")).collect();
    let patterns: Vec<String> = (0..2000).map(|i| format!("x{i}.y")).collect();
    for cmd in [
        format!("pkill {}; rm -rf ~", plain.join(" ")),
        format!("pkill {}; sudo ls", plain.join(" ")),
        format!("systemctl restart {}; sudo ls", plain.join(" ")),
        format!("pkill {}", patterns.join(" ")),
        format!("killall -r {}", patterns.join(" ")),
    ] {
        let t = std::time::Instant::now();
        let d = e.evaluate(&cmd);
        let elapsed = t.elapsed();
        assert!(
            matches!(d, Decision::Deny { ref pack, .. } if pack == "core.lock"),
            "{d:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(250),
            "{elapsed:?}"
        );
    }
}

/// Fix round 3 (T5, T6): `pkill -f` patterns are matched against the
/// daemon's command line; read-only `systemctl` verbs take any pattern.
#[test]
fn pkill_full_and_read_only_globs() {
    let f = Fixture::new();
    let e = f.engine();
    for cmd in [
        "pkill -f 'bin/saiife daemon'",
        "pkill -f 'opt/s.*e'",
        "pkill -f daemon.--system",
        "pkill --full 'saiife d'",
        "pkill -9f 'saiife\\s'",
        "systemctl stop '[[:alpha:]]*'",
        "systemctl stop 'sai\\ifed'",
    ] {
        assert_lock_denies(&e, cmd);
    }
    for cmd in [
        "pkill -f 'python app.py'",
        "pkill -f node",
        "pkill 'daemon'",
        "systemctl list-units '*'",
        "systemctl list-unit-files 'sai*'",
        "systemctl status '*fed'",
        "systemctl is-active '*'",
    ] {
        let d = e.evaluate(cmd);
        assert!(!d.is_deny(), "expected ALLOW for {cmd:?}, got {d:?}");
    }
}

/// `$XDG_CONFIG_HOME` elsewhere than `~/.config` is guarded too.
#[test]
fn xdg_config_home_is_guarded() {
    let f = Fixture::new();
    let (packs, _) = builtin_packs();
    let lock: Vec<_> = packs.into_iter().filter(|p| p.id == "core.lock").collect();
    let xdg = f.home.join("xdg");
    let e = Engine::new(lock)
        .with_budget(TEST_BUDGET)
        .with_paths(f.vars().with_var("XDG_CONFIG_HOME", &xdg));
    for rel in [
        "systemd/user/x.service",
        "systemd/user",
        "systemd",
        "autostart/x.desktop",
        "",
    ] {
        let p = xdg.join(rel).display().to_string();
        assert_lock_denies_path(&e, Access::Write, p.trim_end_matches('/'));
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
        "/etc/claude-code",
        "/etc/codex/requirements.toml",
        "/etc/codex",
        "/etc/gemini-cli/settings.json",
        "/etc/gemini-cli",
        "/usr/share/polkit-1/actions/com.saiife.approve.policy",
        "/usr/share/polkit-1/actions",
        "/usr/share/polkit-1/rules.d/49-x.rules",
        "/usr/share/polkit-1",
        "/etc/polkit-1/rules.d/49-x.rules",
        "/etc/polkit-1/rules.d",
        "/etc/polkit-1",
        "/run/polkit-1/rules.d/49-x.rules",
        "/run/polkit-1/rules.d",
        "/run/polkit-1",
        "/usr/local/share/polkit-1/rules.d/49-x.rules",
        "/usr/local/share/polkit-1/actions/x.policy",
        "/usr/local/share/polkit-1",
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
        "mv /etc/claude-code /tmp/x",
        "sed -i s/auth_self/yes/ /usr/share/polkit-1/actions/com.saiife.approve.policy",
        "rm /usr/share/polkit-1/actions/com.saiife.approve.policy",
        "echo 'polkit.addRule(function(){return polkit.Result.YES;});' > /etc/polkit-1/rules.d/00-yes.rules",
        "cp yes.rules /usr/share/polkit-1/rules.d/00-yes.rules",
        "mv /etc/polkit-1 /tmp/x",
        "rm -rf /usr/share/polkit-1",
        "tee /etc/polkit-1/rules.d/10-x.rules",
        "cp yes.rules /run/polkit-1/rules.d/00-yes.rules",
        "echo x > /run/polkit-1/rules.d/00-yes.rules",
        "cp yes.rules /usr/local/share/polkit-1/rules.d/00-yes.rules",
        "rm -rf /usr/local/share/polkit-1",
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
        "cat /usr/share/polkit-1/actions/com.saiife.approve.policy",
        "ls /etc/polkit-1/rules.d",
        "ls /run/polkit-1/rules.d",
        "cat /usr/local/share/polkit-1/rules.d/x.rules",
        "cat /usr/share/polkit-1/rules.d/50-default.rules",
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
        // Read-only service and scheduler queries (M5).
        "systemctl status saiifed",
        "systemctl show saiifed",
        "systemctl is-active saiifed",
        "systemctl is-enabled saiifed.service",
        "systemctl --no-pager status saiifed",
        "crontab -l",
        "at -l",
        "atq",
        "systemctl --user status x",
        "loginctl list-sessions",
        "pkill -u jonas node",
        "systemctl restart nginx",
        "batchelor",
        "env -u FOO npm test",
        "timeout 5 cargo test",
        "xargs rm -f < list.txt",
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

/// Fix round 4 (F1): `pkill -f` and `killall -r` are read with getopt
/// from the tool's own option table, abbreviations and bundles included.
#[test]
fn full_and_regexp_options_are_read_with_getopt() {
    let f = Fixture::new();
    let e = f.engine();
    for cmd in [
        "pkill --f 'opt/s.*e'",
        "pkill --fu 'opt/s.*e'",
        "pkill --ful 'opt/s.*e'",
        "pkill --full 'opt/s.*e'",
        "pkill 'opt/s.*e' -f",
        "pkill -ef 'n/s.*e d'",
        "pkill --signal KILL -f 'opt/s.*e'",
        "pkill --e 'opt/s.*e'",
        "killall --reg '^sai'",
        "killall --r '^sai'",
        "killall -Ir '^sai'",
        "killall -w --regex '^sai'",
    ] {
        assert_lock_denies(&e, cmd);
    }
    for cmd in [
        "pkill -f node",
        "pkill --full 'python app.py'",
        "pkill -qf 'opt/s.*e'",
        "pkill 'opt/s.*e' -- -f",
        "killall -s r '^sai'",
        "killall -I '^node'",
    ] {
        let d = e.evaluate(cmd);
        assert!(!d.is_deny(), "expected ALLOW for {cmd:?}, got {d:?}");
    }
}

/// Fix round 5 (B1): pkill and killall take a `-SIGNAL` word before
/// getopt; it must not hide `-f`/`-r`. A value word starting with `-` is
/// read as options too, and killall's `-word` as a long option.
#[test]
fn signal_words_do_not_hide_options() {
    let f = Fixture::new();
    let e = f.engine();
    for cmd in [
        "pkill -IO -f 'opt/s.*e'",
        "pkill -TRAP -f 'opt/s.*e'",
        "pkill -TSTP -f 'opt/s.*e'",
        "pkill -SIGIO -f 'opt/s.*e'",
        "pkill -9 -f 'opt/s.*e'",
        "pkill -RTMIN+1 -f 'opt/s.*e'",
        "pkill -sigio -f 'opt/s.*e'",
        "pkill --signal -f 'opt/s.*e'",
        "killall -XFSZ -r '^sai'",
        "killall -TRAP -r '^sai'",
        "killall -9 -r '^sai'",
        "killall -regexp '^sai'",
        "killall -reg '^sai'",
        // Final review S14: a leading signal-name word is read as options
        // too (`-rtmin` may be `-r …`).
        "killall -rtmin '^sai'",
        "killall -RTMIN '^sai'",
        "killall -rtmin+1 '^sai'",
        "killall -rtmax '^sai'",
        // Final review S23: an expansion in a pattern counts as a match.
        "pkill \"sa${X}fed\"",
        "pkill \"$X\"",
        "killall \"saii${X}\"",
    ] {
        assert_lock_denies(&e, cmd);
    }
    for cmd in [
        "pkill -f node",
        "pkill -TERM node",
        "pkill -9 node",
        "pkill -HUP -f 'python app.py'",
        "killall -HUP node",
        "killall -9 -r '^node'",
    ] {
        let d = e.evaluate(cmd);
        assert!(!d.is_deny(), "expected ALLOW for {cmd:?}, got {d:?}");
    }
}

/// Fix round 4 (F2): the file `xargs` reads is found whatever the
/// spelling of `--arg-file`.
#[test]
fn xargs_arg_file_abbreviations_are_read() {
    let f = Fixture::new();
    let e = f.engine();
    for cmd in [
        "xargs --arg-f /var/lib/saiife/keys/audit.ed25519 echo",
        "xargs --arg /var/lib/saiife/keys/audit.ed25519 echo",
        "xargs --a /var/lib/saiife/keys/audit.ed25519 echo",
        "xargs --ar=/var/lib/saiife/keys/audit.ed25519 echo",
        "xargs -0ta /var/lib/saiife/keys/audit.ed25519 echo",
        "timeout 5 xargs --arg-file /var/lib/saiife/keys/audit.ed25519 echo",
    ] {
        assert_lock_denies(&e, cmd);
    }
    // `-I` takes `a` as its value: no file is read.
    let d = e.evaluate("xargs -I a echo a");
    assert!(!d.is_deny(), "{d:?}");
}

/// Fix round 4 (F3): the wrapper option tables follow the installed tools
/// (`--wait` takes a value, `--fcntl` and `--nonblocking` are flags,
/// `nohup --` ends options, xargs' `--max-lines` value is attached only).
/// `wrappers.rs` pins every table.
#[test]
fn wrapper_tables_follow_the_tools() {
    let f = Fixture::new();
    let e = f.engine();
    for cmd in [
        "flock --wait 5 /tmp/l sudo ls",
        "flock --wai 5 /tmp/l crontab /tmp/c",
        "flock --start 0 /tmp/l crontab /tmp/c",
        "flock --length 1 /tmp/l sudo ls",
        "flock --fcntl /tmp/l sudo ls",
        "flock --nonblocking /tmp/l crontab /tmp/c",
        "nohup -- sudo ls",
        "nohup -- crontab /tmp/c",
        "xargs --max-lines=1 sudo ls",
        "sudo --no-update crontab /tmp/c",
        "sudo --login-class x crontab /tmp/c",
        "env --block-signal crontab /tmp/c",
        "ionice --ignore crontab /tmp/c",
        "time --append -o /tmp/t crontab /tmp/c",
    ] {
        assert_lock_denies(&e, cmd);
    }
    for cmd in [
        "flock --fcntl /tmp/l make",
        "flock --nonblocking /tmp/l make",
        "flock --nb /tmp/l make",
        "flock --wait 5 /tmp/l make",
        "xargs --max-lines=1 echo",
        "env --block-signal=INT make",
    ] {
        let d = e.evaluate(cmd);
        assert!(
            matches!(
                d,
                Decision::Allow {
                    trace: AllowTrace::NoMatch
                }
            ),
            "expected a clean ALLOW for {cmd:?}, got {d:?}"
        );
    }
}

/// Fix round 4 (F4): hostile sub-cap patterns compile quickly, and what
/// follows them is judged in developer mode with core.lock opted in, at
/// the production budget.
#[test]
fn hostile_patterns_do_not_exhaust_the_budget() {
    let f = Fixture::new();
    let (packs, _) = builtin_packs();
    let active = saiifeguard::profile::select_active(packs, &["core.lock".to_string()]);
    let e = Engine::new(active)
        .with_budget(std::time::Duration::from_millis(50))
        .with_paths(f.vars());
    for width in [10, 20] {
        let pats: Vec<String> = (0..=30)
            .map(|i| format!("'\\w{{1,{width}}}\\d{i}'"))
            .collect();
        let cmd = format!("pkill {}; rm -rf ~", pats.join(" "));
        let t = std::time::Instant::now();
        let d = e.evaluate(&cmd);
        let elapsed = t.elapsed();
        assert!(d.is_deny(), "{width}: {d:?}");
        eprintln!("width {width}: {elapsed:?}");
        assert!(
            elapsed < std::time::Duration::from_millis(250),
            "{elapsed:?}"
        );
    }
    // Many pkill segments share one compile allowance per command line.
    let seg: Vec<String> = (0..32).map(|i| format!("'[a-z]{{1,9}}\\d{i}'")).collect();
    let cmd = format!(
        "{}rm -rf ~",
        format!("pkill {}; ", seg.join(" ")).repeat(20)
    );
    let d = e.evaluate(&cmd);
    assert!(d.is_deny(), "{d:?}");
}

/// macOS (plan 13): rewriting an authorization right (`com.saiife.approve`
/// or any other) and editing saiife's `_saiife*` accounts are denied, by
/// their own rule ids; reading the keychain, the rights and other accounts
/// stays allowed.
#[test]
fn macos_rights_and_saiife_accounts_are_denied() {
    let f = Fixture::new();
    let e = f.engine();
    let rule = |cmd: &str| match e.evaluate(cmd) {
        Decision::Deny { pack, pattern, .. } => {
            assert_eq!(pack, "core.lock", "{cmd}");
            e.rule_id(&pack, &pattern).map(str::to_string)
        }
        other => panic!("expected DENY for {cmd:?}, got {other:?}"),
    };
    for cmd in [
        "security authorizationdb write com.saiife.approve allow",
        "security authorizationdb remove com.saiife.approve",
        "security  authorizationdb merge /tmp/rights.plist",
        "SECURITY AuthorizationDB Write com.saiife.approve allow",
        "timeout 5 security authorizationdb write com.saiife.approve allow",
        // Global options before the command (review fix round 1).
        "security -q authorizationdb write com.saiife.approve allow",
        "security -v authorizationdb remove com.saiife.approve",
        "security -q -v authorizationdb merge rights.plist",
        // `--` before the verb (final review).
        "security authorizationdb -- write com.saiife.approve allow",
        "security -q authorizationdb --  remove com.saiife.approve",
    ] {
        assert_eq!(rule(cmd).as_deref(), Some("authorizationdb"), "{cmd}");
    }
    // Interactive security reads its commands from stdin.
    for cmd in [
        "echo 'authorizationdb write com.saiife.approve allow' | security -i",
        "security -i < cmds.txt",
        "security -qi",
        "security -q -i",
        "security -p 'sec> '",
    ] {
        assert_eq!(rule(cmd).as_deref(), Some("security-interactive"), "{cmd}");
    }
    for cmd in [
        "dseditgroup -o edit -a agent -t user _saiifeaudit",
        "dseditgroup -o delete _saiife",
        "dscl . -create /Users/_saiife UserShell /bin/zsh",
        "dscl . -delete /Groups/_saiifeaudit",
        "dscl . -append /Groups/_saiifeaudit GroupMembership agent",
        "DSCL . -passwd /Users/_saiife x",
        // A shorter prefix with a glob character.
        "dscl . -append /Groups/_saii* GroupMembership agent",
        "dscl . -create /Users/_sai?ifeaudit",
        "dseditgroup -o edit -a agent -t user _sa*",
    ] {
        assert_eq!(rule(cmd).as_deref(), Some("saiife-accounts"), "{cmd}");
    }
    // An operand whose value only the shell knows, or a glob that matches.
    for cmd in [
        "G=_saiifeaudit; dscl . -append /Groups/$G GroupMembership agent",
        "dscl . -append \"/Groups/${G}\" GroupMembership agent",
        "dseditgroup -o edit -a agent -t user $G",
        "dscl . -delete /Groups/?saiifeaudit",
        "dscl . -delete /Local/Default/Groups/*audit",
    ] {
        assert_eq!(
            rule(cmd).as_deref(),
            Some("saiife-accounts-pattern"),
            "{cmd}"
        );
    }
    // dscl with no command after the datasource is interactive.
    for cmd in [
        "printf 'append /Groups/_saiifeaudit GroupMembership agent\\n' | dscl .",
        "dscl . < cmds.txt",
        "dscl localhost",
        "dscl -u admin -P pw .",
        "dscl",
    ] {
        assert_eq!(rule(cmd).as_deref(), Some("dscl-interactive"), "{cmd}");
    }
    // Review fix round 2: attached option values, unknown words, no
    // command, xargs and command substitution.
    for cmd in [
        "security -ix",
        "security -ifoo",
        "security -qip",
        "security -p'x'",
        "security -pX",
    ] {
        assert_eq!(rule(cmd).as_deref(), Some("security-interactive"), "{cmd}");
    }
    for cmd in [
        "security",
        "security -v",
        "cat cmds | security",
        "security < f",
        "security -q < f",
        "echo x | security -q",
        "echo authorizationdb | xargs security",
        "xargs security < args.txt",
        "xargs -a f security",
    ] {
        assert_eq!(rule(cmd).as_deref(), Some("security-no-command"), "{cmd}");
    }
    for cmd in [
        "S=authorizationdb; security $S write com.saiife.approve allow",
        "A=write; security authorizationdb $A com.saiife.approve allow",
        "security authorizationdb \"$A\" com.saiife.approve allow",
        "security authorizationdb ${A} com.saiife.approve allow",
        "security authorizationdb -- $A com.saiife.approve allow",
        "security ${S} write com.saiife.approve allow",
        "security -q $S write com.saiife.approve allow",
        "security $(cat f) write com.saiife.approve allow",
        "security `cat f` write com.saiife.approve allow",
        "security auth* write com.saiife.approve allow",
    ] {
        assert_eq!(
            rule(cmd).as_deref(),
            Some("security-unknown-command"),
            "{cmd}"
        );
    }
    for cmd in [
        "xargs dseditgroup -o edit -a agent -t user",
        "xargs -n1 dscl . -append /Groups/staff GroupMembership",
        "find . -name x | xargs -I{} security {}",
    ] {
        assert_eq!(
            rule(cmd).as_deref(),
            Some("xargs-security-accounts"),
            "{cmd}"
        );
    }
    // A substitution's output is unknown: denied whichever rule sees it
    // first (the literal one when the text names the account).
    for cmd in [
        "dscl . -append /Groups/$(echo _saiifeaudit) GroupMembership agent",
        "dscl . -append /Groups/`echo _saiifeaudit` GroupMembership agent",
        "dscl . -delete /Groups/_saiife$((1))audit",
        "security $(echo authorizationdb) write x allow",
        "security authorizationdb `echo write` x allow",
    ] {
        assert!(e.evaluate(cmd).is_deny(), "{cmd}: {:?}", e.evaluate(cmd));
    }
    for cmd in [
        "dscl . -append \"/Groups/$(cat g)\" GroupMembership agent",
        "dseditgroup -o edit -a agent -t user \"$(cat g)\"",
        "dseditgroup -o edit -a agent -t user `cat g`",
        "dscl . -delete /Groups/$((1))",
        "dscl . -append /Groups/${G} GroupMembership agent",
    ] {
        assert_eq!(
            rule(cmd).as_deref(),
            Some("saiife-accounts-pattern"),
            "{cmd}"
        );
    }
    for cmd in [
        "security find-generic-password -s x",
        "security -q find-generic-password -s x",
        "security find-generic-password -w -s \"$SVC\"",
        "security find-identity -v -p codesigning",
        "security authorizationdb read \"$R\"",
        "security list-keychains",
        "security help",
        "xargs rm -f < list.txt",
        "xargs grep -l foo",
        "echo security",
        "security authorizationdb read com.saiife.approve",
        "security authorizationdb writer",
        "security authorizationdb -- read com.saiife.approve",
        "dscl . -read /Users/agent",
        "dscl . -list /Users",
        "dscl . -read /Groups/staff GroupMembership",
        "dscl localhost -read /Local/Default/Users/agent",
        "dscl . -read /Users/_salesteam",
        "dseditgroup -o checkmember -m agent staff",
        "echo security authorizationdb write x allow",
        "echo dscl .",
        "git commit -m 'security fix'",
    ] {
        let d = e.evaluate(cmd);
        assert!(!d.is_deny(), "expected ALLOW for {cmd:?}, got {d:?}");
    }
}
