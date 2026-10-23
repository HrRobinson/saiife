//! `saiife check` loads the opt-in packs of the project the agent works in:
//! the nearest `.saiife/config.toml` at or above the payload's `cwd`.

mod common;

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use saiife_audit::store::read_all;
use saiife_audit::DecisionKind;

const DROP: &str = "psql -c 'DROP DATABASE prod'";

fn check(audit: &Path, cwd: &Path, cmd: &str) -> (i32, String) {
    let payload = serde_json::json!({
        "session_id": "s",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": cmd }
    })
    .to_string();
    common::assert_no_host_config(&std::env::temp_dir());
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_saiife"));
    let _sandbox = common::hermetic(&mut cmd, audit);
    let mut child = cmd
        .args(["check", "--hook-exit", "--agent", "claude"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn project(packs: &str) -> tempfile::TempDir {
    let p = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(p.path().join(".saiife")).unwrap();
    std::fs::create_dir_all(p.path().join("src/deep")).unwrap();
    std::fs::write(
        p.path().join(".saiife/config.toml"),
        format!("version = 1\npacks = [{packs}]\n"),
    )
    .unwrap();
    p
}

#[test]
fn opt_in_pack_from_project_config_applies_in_subdirectories() {
    let audit = tempfile::tempdir().unwrap();
    let p = project("\"core.filesystem\", \"core.git\", \"db.postgres\"");
    let (code, stderr) = check(audit.path(), &p.path().join("src/deep"), DROP);
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("BLOCKED by db.postgres"), "{stderr}");
    let recs = read_all(audit.path()).records;
    let rec = recs.iter().find(|r| !r.is_bookkeeping()).unwrap();
    assert_eq!(rec.decision, DecisionKind::Deny);
    assert_eq!(rec.pack.as_deref(), Some("db.postgres"));
}

#[test]
fn outside_the_project_only_default_packs_apply() {
    let audit = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let (code, _) = check(audit.path(), elsewhere.path(), DROP);
    assert_eq!(code, 0);
}

#[test]
fn unknown_pack_ids_are_warned_about_and_ignored() {
    let audit = tempfile::tempdir().unwrap();
    let p = project("\"db.oracle\", \"db.postgres\"");
    let (code, stderr) = check(audit.path(), p.path(), DROP);
    assert_eq!(code, 2, "known packs still apply");
    assert!(stderr.contains("unknown pack \"db.oracle\""), "{stderr}");
    let (code, _) = check(audit.path(), p.path(), "rm -rf /");
    assert_eq!(code, 2, "default-on packs always apply");
}

#[test]
fn broken_project_config_fails_open_to_default_packs() {
    let audit = tempfile::tempdir().unwrap();
    let p = project("\"db.postgres\"");
    std::fs::write(p.path().join(".saiife/config.toml"), "packs = [\n").unwrap();
    let (code, stderr) = check(audit.path(), p.path(), "rm -rf /");
    assert_eq!(code, 2, "default-on packs still apply");
    assert!(stderr.contains("default packs only"), "{stderr}");
    let (code, _) = check(audit.path(), p.path(), DROP);
    assert_eq!(code, 0);
}

#[test]
fn oversized_project_config_fails_open_to_default_packs() {
    let audit = tempfile::tempdir().unwrap();
    let p = project("\"db.postgres\"");
    let big = format!(
        "# {}\nversion = 1\npacks = [\"db.postgres\"]\n",
        "x".repeat(70 * 1024)
    );
    std::fs::write(p.path().join(".saiife/config.toml"), big).unwrap();
    let (code, stderr) = check(audit.path(), p.path(), "rm -rf /");
    assert_eq!(code, 2, "default-on packs still apply");
    assert!(stderr.contains("default packs only"), "{stderr}");
    let (code, _) = check(audit.path(), p.path(), DROP);
    assert_eq!(code, 0, "opt-in pack from the oversized file is not loaded");
}

/// Run the hook in `cwd`, killing it after 30 s; returns its exit code, how
/// long it took, and the `policy` of the guard record it wrote.
fn timed_check(audit: &Path, cwd: &Path, cmd: &str) -> (i32, std::time::Duration, String) {
    let payload = serde_json::json!({
        "session_id": "s",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": cmd }
    })
    .to_string();
    let mut command = Command::new(env!("CARGO_BIN_EXE_saiife"));
    let _sandbox = common::hermetic(&mut command, audit);
    let start = std::time::Instant::now();
    let mut child = command
        .args(["check", "--hook-exit", "--agent", "claude"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if start.elapsed() > std::time::Duration::from_secs(30) {
            let _ = child.kill();
            break child.wait().unwrap();
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    let took = start.elapsed();
    let policy = read_all(audit)
        .records
        .iter()
        .rev()
        .find(|r| !r.is_bookkeeping())
        .and_then(|r| r.policy.clone())
        .unwrap_or_default();
    (status.code().unwrap_or(-1), took, policy)
}

/// An oversized config is refused by its size before a byte is read (so
/// any size costs the same): the hook answers well inside its budget and
/// still records a policy.
#[test]
fn oversized_config_does_not_delay_hook() {
    let audit = tempfile::tempdir().unwrap();
    let p = tempfile::tempdir().unwrap();
    std::fs::create_dir(p.path().join(".saiife")).unwrap();
    let f = std::fs::File::create(p.path().join(".saiife/config.toml")).unwrap();
    f.set_len(64 * 1024 + 1).unwrap();
    drop(f);
    let (code, took, policy) = timed_check(audit.path(), p.path(), "rm -rf /");
    assert_eq!(code, 2, "default-on packs still deny");
    assert!(
        took < std::time::Duration::from_secs(2),
        "hook took {took:?}"
    );
    assert!(policy.starts_with("sha256:"), "{policy:?}");
}

/// A symlinked config (staying inside the project) is followed, for the packs and the policy hash
/// alike: the policy is that of a plain file with the target's bytes. A
/// link to an oversized file is refused unread, without delay.
#[cfg(unix)]
#[test]
fn symlinked_config_is_followed_for_policy() {
    let audit = tempfile::tempdir().unwrap();
    let p = tempfile::tempdir().unwrap();
    // Targets inside the project (a link leading outside is refused).
    let inside = p.path().join("other");
    std::fs::create_dir(&inside).unwrap();
    let outside = tempfile::tempdir().unwrap();
    let _ = &outside;
    let a = "packs = [\"db.postgres\"]\n";
    std::fs::write(inside.join("a.toml"), a).unwrap();
    std::fs::write(inside.join("b.toml"), "packs = []\n").unwrap();
    std::fs::create_dir(p.path().join(".saiife")).unwrap();
    let link = p.path().join(".saiife/config.toml");
    std::os::unix::fs::symlink(inside.join("a.toml"), &link).unwrap();
    let (code, took, via_a) = timed_check(audit.path(), p.path(), DROP);
    assert_eq!(code, 2, "the linked config's opt-in pack is loaded");
    assert!(
        took < std::time::Duration::from_secs(2),
        "hook took {took:?}"
    );
    assert!(via_a.starts_with("sha256:"), "{via_a:?}");

    std::fs::remove_file(&link).unwrap();
    std::fs::write(&link, a).unwrap();
    let (_, _, plain_a) = timed_check(audit.path(), p.path(), DROP);
    assert_eq!(via_a, plain_a, "the target's bytes are hashed");

    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(inside.join("b.toml"), &link).unwrap();
    let (_, _, via_b) = timed_check(audit.path(), p.path(), DROP);
    assert_ne!(via_a, via_b, "another target, another policy");

    let big = inside.join("big.toml");
    std::fs::File::create(&big)
        .unwrap()
        .set_len(64 * 1024 + 1)
        .unwrap();
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&big, &link).unwrap();
    let (code, took, via_big) = timed_check(audit.path(), p.path(), DROP);
    assert_eq!(code, 0, "an oversized target is not loaded");
    assert!(
        took < std::time::Duration::from_secs(2),
        "hook took {took:?}"
    );
    std::fs::remove_file(&link).unwrap();
    std::fs::File::create(&link)
        .unwrap()
        .set_len(64 * 1024 + 1)
        .unwrap();
    let (_, _, plain_big) = timed_check(audit.path(), p.path(), DROP);
    assert_eq!(via_big, plain_big, "one marker for every unreadable config");
}

/// A config symlinked to a file outside the project is never opened: its
/// content (here a parse-failing canary) reaches neither stderr nor the
/// packs, and the hook still answers.
#[cfg(unix)]
#[test]
fn symlink_outside_project_is_refused_without_leaking() {
    let audit = tempfile::tempdir().unwrap();
    let p = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("id_rsa");
    std::fs::write(&secret, "SECRET-CANARY-not-toml = = =\n").unwrap();
    std::fs::create_dir(p.path().join(".saiife")).unwrap();
    std::os::unix::fs::symlink(&secret, p.path().join(".saiife/config.toml")).unwrap();
    let (code, stderr) = check(audit.path(), p.path(), "ls");
    assert_eq!(code, 0, "{stderr}");
    assert!(!stderr.contains("SECRET-CANARY"), "{stderr}");
    assert!(stderr.contains("outside the project"), "{stderr}");
}

// ---- Developer hook under a locked-mode `/etc` (spec §6.1.1, §11) ----

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// A stand-in for `/etc/saiife` in a temp dir.
struct Etc {
    dir: tempfile::TempDir,
}

impl Etc {
    fn new() -> Etc {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("etc/saiife")).unwrap();
        Etc { dir }
    }
    fn config(&self) -> std::path::PathBuf {
        self.dir.path().join("etc/saiife/config.toml")
    }
    fn write_config(&self, text: &str) {
        std::fs::write(self.config(), text).unwrap();
    }
    /// `installed.toml` listing a managed hook for each of `agents`.
    fn install(&self, agents: &[&str]) {
        let sha = "cc".repeat(32);
        let with: Vec<(&str, &str)> = agents.iter().map(|a| (*a, sha.as_str())).collect();
        self.install_with(&with);
    }
    /// `installed.toml` listing `(agent, sha256)` managed hooks.
    fn install_with(&self, agents: &[(&str, &str)]) {
        use saiife_policy::installed::*;
        let i = Installed {
            version: INSTALLED_VERSION,
            saiife: "0.1.1".into(),
            installed_at: "2026-10-22T10:00:00Z".into(),
            systemd: 255,
            vault_key: VaultKeyMode::Credential,
            users: vec![],
            groups: vec![],
            memberships: vec![],
            dirs: vec![],
            files: vec![],
            agents: agents
                .iter()
                .map(|(a, sha)| ManagedAgent {
                    agent: a.to_string(),
                    path: format!("/etc/{a}/managed").into(),
                    sha256: sha.to_string(),
                    whole_file: true,
                    created_file: true,
                })
                .collect(),
        };
        write_installed(&self.dir.path().join("etc/saiife/installed.toml"), &i).unwrap();
    }
}

/// `saiife check --agent <agent> --system-config <etc>` with `payload`;
/// `hook_exit` adds `--hook-exit`.
fn dev_check(
    etc: &Etc,
    audit: &Path,
    agent: &str,
    hook_exit: bool,
    payload: &str,
) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_saiife"));
    let _sandbox = common::hermetic(&mut cmd, audit);
    cmd.args(["check", "--agent", agent, "--system-config"])
        .arg(etc.config());
    if hook_exit {
        cmd.arg("--hook-exit");
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut sin = child.stdin.take().unwrap();
    let data = payload.as_bytes().to_vec();
    let w = std::thread::spawn(move || sin.write_all(&data));
    let out = child.wait_with_output().unwrap();
    // Every path reads the whole payload: an EPIPE here means the hook
    // stopped reading early.
    w.join()
        .unwrap()
        .unwrap_or_else(|e| panic!("writing the payload: {e}"));
    out
}

fn fixture(rel: &str) -> String {
    std::fs::read_to_string(Path::new(FIXTURES).join(rel)).unwrap()
}

fn guard_records(audit: &Path) -> Vec<saiife_audit::Record> {
    read_all(audit)
        .records
        .into_iter()
        .filter(|r| !r.is_bookkeeping())
        .collect()
}

#[test]
fn project_hook_quiet_when_agent_managed() {
    let etc = Etc::new();
    etc.install(&["claude", "codex"]);
    let audit = tempfile::tempdir().unwrap();
    let home = common::FixtureHome::new();
    let deny = home.real(&fixture("claude/bash-deny.json"));
    for hook_exit in [true, false] {
        let o = dev_check(&etc, audit.path(), "claude", hook_exit, &deny);
        assert_eq!(common::code(&o), 0, "{}", common::stderr(&o));
        assert!(o.stdout.is_empty(), "{}", common::stdout(&o));
        assert!(o.stderr.is_empty(), "{}", common::stderr(&o));
    }
    // Even a payload over the parse cap is drained completely (the writer
    // in `dev_check` would see EPIPE otherwise) and quietly.
    let big = "x".repeat(70 << 20);
    let o = dev_check(&etc, audit.path(), "claude", true, &big);
    assert_eq!(common::code(&o), 0, "{}", common::stderr(&o));
    assert!(o.stderr.is_empty(), "{}", common::stderr(&o));
    // An invalid /etc config does not make the quiet hook speak.
    etc.write_config("version = = 2\n");
    let o = dev_check(&etc, audit.path(), "claude", true, &deny);
    assert_eq!(common::code(&o), 0, "{}", common::stderr(&o));
    assert!(o.stderr.is_empty(), "{}", common::stderr(&o));
    assert!(
        std::fs::read_dir(audit.path()).unwrap().next().is_none(),
        "no record, no audit file"
    );
}

/// A managed hook replaces the project hook only when install wrote it (a
/// fingerprint on record) and the agent's lock holds (lock label lockable,
/// with gaps or with caveats). Otherwise the project hook still judges.
#[test]
fn project_hook_judges_when_managed_hook_does_not_hold() {
    let home = common::FixtureHome::new();
    for (installed, agent, payload) in [
        // The managed file write failed part-way: no fingerprint.
        (vec![("claude", "")], "claude", "claude/bash-deny.json"),
        // Codex and Gemini CLI are unverified.
        (vec![("codex", "cc")], "codex", "codex/bash-deny.json"),
        (vec![("gemini", "cc")], "gemini", "gemini/shell-deny.json"),
    ] {
        let etc = Etc::new();
        etc.install_with(&installed);
        let audit = tempfile::tempdir().unwrap();
        let o = dev_check(
            &etc,
            audit.path(),
            agent,
            true,
            &home.real(&fixture(payload)),
        );
        assert_eq!(common::code(&o), 2, "{agent}: {}", common::stderr(&o));
        assert!(
            common::stderr(&o).starts_with("saiife: BLOCKED by "),
            "{agent}: {}",
            common::stderr(&o)
        );
        let recs = guard_records(audit.path());
        assert_eq!(recs.len(), 1, "{agent}");
        assert_eq!(recs[0].decision, DecisionKind::Deny, "{agent}");
    }
}

#[test]
fn project_hook_works_for_unmanaged_agent() {
    let etc = Etc::new();
    etc.install(&["codex"]);
    let audit = tempfile::tempdir().unwrap();
    let home = common::FixtureHome::new();
    let o = dev_check(
        &etc,
        audit.path(),
        "claude",
        true,
        &home.real(&fixture("claude/bash-deny.json")),
    );
    assert_eq!(common::code(&o), 2, "{}", common::stderr(&o));
    assert!(
        common::stderr(&o).starts_with("saiife: BLOCKED by core.filesystem"),
        "{}",
        common::stderr(&o)
    );
    let recs = guard_records(audit.path());
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].decision, DecisionKind::Deny);
    assert_eq!(recs[0].mode.as_deref(), Some("developer"));
}

#[test]
fn developer_fail_closed_opt_in() {
    let etc = Etc::new();
    etc.write_config("version = 2\n[guard]\nfail = \"closed\"\n");
    let audit = tempfile::tempdir().unwrap();
    let bad = fixture("malformed/not-json.txt");
    let o = dev_check(&etc, audit.path(), "claude", true, &bad);
    assert_eq!(common::code(&o), 2, "{}", common::stderr(&o));
    let err = common::stderr(&o);
    assert!(
        err.starts_with("saiife: BLOCKED (fail closed): hook payload not usable"),
        "{err}"
    );
    assert!(o.stdout.is_empty());
    let recs = guard_records(audit.path());
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].decision, DecisionKind::ErrorDenied);

    // Without --hook-exit: the JSON deny.
    let o = dev_check(&etc, audit.path(), "claude", false, &bad);
    assert_eq!(common::code(&o), 0, "{}", common::stderr(&o));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(v["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap()
        .contains("fail closed"));
    assert_eq!(
        guard_records(audit.path())[1].decision,
        DecisionKind::ErrorDenied
    );

    // A judged call is unchanged.
    let home = common::FixtureHome::new();
    let o = dev_check(
        &etc,
        audit.path(),
        "claude",
        true,
        &home.real(&fixture("claude/bash-allow.json")),
    );
    assert_eq!(common::code(&o), 0, "{}", common::stderr(&o));

    // `locked = true` alone turns it on as well.
    etc.write_config("version = 2\nlocked = true\n");
    let o = dev_check(&etc, audit.path(), "claude", true, &bad);
    assert_eq!(common::code(&o), 2, "{}", common::stderr(&o));
}

#[test]
fn developer_bad_args_fail_closed_when_opted_in() {
    let etc = Etc::new();
    etc.write_config("version = 2\n[guard]\nfail = \"closed\"\n");
    let audit = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_saiife"));
    let _sandbox = common::hermetic(&mut cmd, audit.path());
    let o = cmd
        .args([
            "check",
            "--hook-exit",
            "--agent",
            "claude",
            "--bogus",
            "--system-config",
        ])
        .arg(etc.config())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(common::code(&o), 2, "{}", common::stderr(&o));
    assert!(
        common::stderr(&o).contains("fail closed"),
        "{}",
        common::stderr(&o)
    );
    let recs = guard_records(audit.path());
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].decision, DecisionKind::ErrorDenied);
}

#[test]
fn developer_default_still_fails_open() {
    // No file under the stand-in /etc at all.
    let etc = Etc::new();
    let audit = tempfile::tempdir().unwrap();
    let o = dev_check(
        &etc,
        audit.path(),
        "claude",
        true,
        &fixture("malformed/not-json.txt"),
    );
    assert_eq!(common::code(&o), 0, "{}", common::stderr(&o));
    assert!(
        common::stderr(&o).contains("failing open (allow)"),
        "{}",
        common::stderr(&o)
    );
    let recs = guard_records(audit.path());
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].decision, DecisionKind::ErrorAllowed);

    // An explicit `fail = "open"` (and a config without `fail`) too.
    for text in ["version = 2\n[guard]\nfail = \"open\"\n", "version = 2\n"] {
        etc.write_config(text);
        let o = dev_check(
            &etc,
            audit.path(),
            "claude",
            true,
            &fixture("malformed/not-json.txt"),
        );
        assert_eq!(common::code(&o), 0, "{text}: {}", common::stderr(&o));
    }
}

#[test]
fn invalid_system_config_fails_open_with_warning() {
    let etc = Etc::new();
    etc.write_config("version = = 2\n[guard]\nfail = \"closed\"\n");
    let audit = tempfile::tempdir().unwrap();
    let o = dev_check(
        &etc,
        audit.path(),
        "claude",
        true,
        &fixture("malformed/not-json.txt"),
    );
    assert_eq!(common::code(&o), 0, "{}", common::stderr(&o));
    let err = common::stderr(&o);
    let want = format!("saiife: warning: {} ignored: ", etc.config().display());
    assert_eq!(err.matches(&want).count(), 1, "{err}");
    let recs = guard_records(audit.path());
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].decision, DecisionKind::ErrorAllowed);
}
