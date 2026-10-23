//! `saiife init` / `saiife init --off` end to end (spec §5, §10 "Agents").

mod common;

use common::{code, stderr, stdout, Env};

const CLAUDE_USER: &str = "{\n  \"model\": \"opus\",\n  \"env\": {\n    \"FOO\": \"bar\"\n  }\n}\n";
const CODEX_USER: &str = "# mine\nmodel = \"gpt-5-codex\"\n\n[features]\nweb_search = true\n";
const GEMINI_USER: &str = "{\n  \"theme\": \"GitHub\"\n}\n";

#[test]
fn init_hooks_detected_agents_and_writes_the_config() {
    let env = Env::new(&["claude", "gemini"]);
    let out = env.saiife(&["init"]);
    assert_eq!(code(&out), 0, "{}{}", stdout(&out), stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("saiife is on for"), "{text}");
    assert!(text.contains("workspace trust"), "Claude next step: {text}");
    assert!(text.contains("trusted folder"), "Gemini next step: {text}");
    assert!(!text.contains("WARNING"), "{text}");
    assert!(env
        .read(".claude/settings.json")
        .contains("saiife check --hook-exit --agent claude"));
    assert!(env
        .read(".gemini/settings.json")
        .contains("\"name\": \"saiife\""));
    assert!(!env.root().join(".codex").exists(), "codex not on PATH");
    let cfg = env.read(".saiife/config.toml");
    assert!(
        cfg.contains(
            "packs = [\"core.filesystem\", \"core.git\", \"core.secrets\", \"core.self\", \"core.process\"]"
        ),
        "{cfg}"
    );
    assert!(cfg.contains("locked = false"), "{cfg}");
}

#[test]
fn explicit_agents_and_packs() {
    let env = Env::new(&[]);
    let out = env.saiife(&[
        "init",
        "--agent",
        "codex",
        "--pack",
        "db.postgres",
        "--pack",
        "db.nope",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(stderr(&out).contains("unknown pack \"db.nope\""));
    assert!(stdout(&out).contains("/hooks"), "Codex next step");
    assert!(env
        .read(".codex/config.toml")
        .contains("[[hooks.PreToolUse]]"));
    let cfg = env.read(".saiife/config.toml");
    assert!(cfg.contains("\"db.postgres\""), "{cfg}");
    assert!(!cfg.contains("db.nope"), "{cfg}");
}

#[test]
fn no_agent_on_path_exits_2() {
    let env = Env::new(&[]);
    let out = env.saiife(&["init"]);
    assert_eq!(code(&out), 2);
    assert!(stderr(&out).contains("no supported agent found"));
    assert!(!env.root().join(".saiife").exists());
}

#[test]
fn unknown_agent_exits_2() {
    let env = Env::new(&["claude"]);
    let out = env.saiife(&["init", "--agent", "cursor"]);
    assert_eq!(code(&out), 2);
    assert!(stderr(&out).contains("unknown agent"));
}

#[test]
fn second_init_changes_nothing() {
    let env = Env::new(&["claude", "codex", "gemini"]);
    env.write(".claude/settings.json", CLAUDE_USER);
    assert_eq!(code(&env.saiife(&["init"])), 0);
    let files = [
        ".claude/settings.json",
        ".codex/config.toml",
        ".gemini/settings.json",
        ".saiife/config.toml",
    ];
    let before: Vec<String> = files.iter().map(|f| env.read(f)).collect();
    let out = env.saiife(&["init"]);
    assert_eq!(code(&out), 0);
    assert!(stdout(&out).contains("already set up"));
    let after: Vec<String> = files.iter().map(|f| env.read(f)).collect();
    assert_eq!(before, after);
}

#[test]
fn off_restores_user_files_and_deletes_what_init_created() {
    let env = Env::new(&["claude", "codex", "gemini"]);
    env.write(".claude/settings.json", CLAUDE_USER);
    env.write(".codex/config.toml", CODEX_USER);
    assert_eq!(code(&env.saiife(&["init"])), 0);
    let out = env.saiife(&["init", "--off"]);
    assert_eq!(code(&out), 0, "{}{}", stdout(&out), stderr(&out));
    assert_eq!(env.read(".claude/settings.json"), CLAUDE_USER);
    assert_eq!(env.read(".codex/config.toml"), CODEX_USER);
    assert!(
        !env.root().join(".gemini").exists(),
        "created by init, now empty"
    );
    assert!(!env.root().join(".saiife").exists());
    // The integrity record is gone too.
    let records = std::fs::read_dir(env.data.path().join("projects"))
        .map(|d| d.count())
        .unwrap_or(0);
    assert_eq!(records, 0);
}

#[test]
fn off_keeps_files_with_user_content_added_after_init() {
    let env = Env::new(&["gemini"]);
    assert_eq!(code(&env.saiife(&["init"])), 0);
    // The user adds their own setting to the file saiife created.
    let with_theme =
        env.read(".gemini/settings.json")
            .replacen('{', "{\n  \"theme\": \"GitHub\",", 1);
    env.write(".gemini/settings.json", &with_theme);
    env.write(
        ".saiife/config.toml",
        "version = 1\npacks = [\"db.mysql\"]\n",
    );
    let out = env.saiife(&["init", "--off"]);
    assert_eq!(code(&out), 0);
    assert_eq!(env.read(".gemini/settings.json"), GEMINI_USER);
    assert!(
        stdout(&out).contains("config.toml kept"),
        "edited config is kept: {}",
        stdout(&out)
    );
    assert!(env.root().join(".saiife/config.toml").exists());
}

/// Review Focus 2: one broken settings file does not stop the others, and
/// is left exactly as it was.
#[test]
fn broken_settings_file_fails_that_agent_only() {
    let env = Env::new(&["claude", "gemini"]);
    let broken = "{\n  // comment\n  \"theme\": \"x\"\n}\n";
    env.write(".gemini/settings.json", broken);
    let out = env.saiife(&["init"]);
    assert_eq!(code(&out), 1);
    assert!(stdout(&out).contains("gemini  FAILED"), "{}", stdout(&out));
    assert!(
        stdout(&out).contains("did not change it"),
        "{}",
        stdout(&out)
    );
    assert_eq!(env.read(".gemini/settings.json"), broken);
    assert!(env.read(".claude/settings.json").contains("saiife check"));
}

/// Review Focus 3: init from a subdirectory of an initialized project uses
/// that project.
#[test]
fn init_from_a_subdirectory_reuses_the_project() {
    let env = Env::new(&["claude"]);
    assert_eq!(code(&env.saiife(&["init"])), 0);
    let sub = env.root().join("src/deep");
    std::fs::create_dir_all(&sub).unwrap();
    let out = env.saiife_in(&sub, &["init"]);
    assert_eq!(code(&out), 0);
    assert!(stdout(&out).contains("Using the saiife project at"));
    assert!(!sub.join(".claude").exists());
}

/// Review Focus 4: without saiife on PATH the hooks cannot fire; say so.
#[test]
fn init_warns_when_saiife_is_not_on_path() {
    let env = Env::bare(&["claude"]);
    let out = env.saiife(&["init"]);
    assert_eq!(code(&out), 0);
    assert!(
        stdout(&out).contains("WARNING: `saiife` is not on your PATH"),
        "{}",
        stdout(&out)
    );
}

/// A config the user edited between two inits is not saiife's to delete.
#[test]
fn off_keeps_config_edited_between_two_inits() {
    let env = Env::new(&["claude"]);
    assert_eq!(code(&env.saiife(&["init"])), 0);
    env.write(
        ".saiife/config.toml",
        "version = 1\npacks = [\"db.mysql\"]\n",
    );
    assert_eq!(code(&env.saiife(&["init"])), 0);
    let out = env.saiife(&["init", "--off"]);
    assert_eq!(code(&out), 0);
    assert!(
        stdout(&out).contains("config.toml kept"),
        "{}",
        stdout(&out)
    );
    assert!(env.read(".saiife/config.toml").contains("db.mysql"));
}

/// An unreadable integrity record is reported and kept by `--off`.
#[test]
fn off_keeps_an_unreadable_record_and_warns() {
    let env = Env::new(&["claude"]);
    assert_eq!(code(&env.saiife(&["init"])), 0);
    let projects = env.data.path().join("projects");
    let rec = std::fs::read_dir(&projects)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    std::fs::write(&rec, "not json").unwrap();
    let out = env.saiife(&["init", "--off"]);
    assert_eq!(code(&out), 1, "{}", stdout(&out));
    assert!(
        stderr(&out).contains("integrity record is unreadable"),
        "{}",
        stderr(&out)
    );
    assert!(rec.exists(), "record kept for inspection");
    let out = env.saiife(&["init"]);
    assert!(
        stderr(&out).contains("integrity record is unreadable"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn off_keeps_user_edits_when_init_pack_appends_to_an_edited_config() {
    let env = Env::new(&["claude"]);
    assert_eq!(code(&env.saiife(&["init"])), 0);
    env.write(
        ".saiife/config.toml",
        "# mine\nversion = 1\npacks = [\"db.mysql\"]\n",
    );
    assert_eq!(code(&env.saiife(&["init", "--pack", "db.postgres"])), 0);
    let out = env.saiife(&["init", "--off"]);
    assert_eq!(code(&out), 0);
    let cfg = env.read(".saiife/config.toml");
    assert!(
        cfg.contains("# mine") && cfg.contains("db.postgres"),
        "{cfg}"
    );
}

#[test]
fn off_deletes_config_after_a_saiife_only_pack_append() {
    let env = Env::new(&["claude"]);
    assert_eq!(code(&env.saiife(&["init"])), 0);
    assert_eq!(code(&env.saiife(&["init", "--pack", "db.postgres"])), 0);
    assert!(env.read(".saiife/config.toml").contains("db.postgres"));
    assert_eq!(code(&env.saiife(&["init", "--off"])), 0);
    assert!(!env.root().join(".saiife").exists());
}

/// M1: an agent config that is a symlink to a file outside the project is
/// refused; the outside file stays byte-identical, other agents still work.
#[cfg(unix)]
#[test]
fn symlinked_config_outside_the_project_is_refused() {
    let env = Env::new(&["claude", "codex", "gemini"]);
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("config.toml");
    let original = "# shared codex config\nmodel = \"gpt-5-codex\"\n";
    std::fs::write(&target, original).unwrap();
    std::fs::create_dir(env.root().join(".codex")).unwrap();
    std::os::unix::fs::symlink(&target, env.root().join(".codex/config.toml")).unwrap();
    let out = env.saiife(&["init"]);
    assert_eq!(code(&out), 1, "{}", stdout(&out));
    let text = stdout(&out);
    let codex = text
        .lines()
        .find(|l| l.contains("codex") && l.contains("FAILED"))
        .unwrap_or_else(|| panic!("{text}"));
    assert!(codex.contains("outside the project"), "{codex}");
    assert_eq!(std::fs::read_to_string(&target).unwrap(), original);
    assert!(env.read(".claude/settings.json").contains("saiife check"));
    assert!(env.read(".gemini/settings.json").contains("saiife check"));
}

/// A project config symlinked outside the project is refused by init, and
/// the target is left untouched.
#[cfg(unix)]
#[test]
fn symlinked_project_config_outside_the_project_is_refused() {
    let env = Env::new(&["claude"]);
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("creds");
    let original = "SECRET-CANARY-not-toml = = =\n";
    std::fs::write(&target, original).unwrap();
    std::fs::create_dir(env.root().join(".saiife")).unwrap();
    std::os::unix::fs::symlink(&target, env.root().join(".saiife/config.toml")).unwrap();
    let out = env.saiife(&["init"]);
    assert_ne!(code(&out), 0, "{}", stdout(&out));
    let all = format!("{}{}", stdout(&out), String::from_utf8_lossy(&out.stderr));
    assert!(all.contains("outside the project"), "{all}");
    assert!(!all.contains("SECRET-CANARY"), "{all}");
    assert_eq!(std::fs::read_to_string(&target).unwrap(), original);
}

/// A mode-0500 directory still writable (root) means permissions cannot
/// make a write fail here; tests that need that skip.
#[cfg(unix)]
fn dir_stays_writable(dir: &std::path::Path) -> bool {
    let probe = dir.join(".probe");
    let ok = std::fs::write(&probe, "x").is_ok();
    let _ = std::fs::remove_file(&probe);
    ok
}

/// Gives a directory back its mode 0755 when dropped, also on a failed assert.
#[cfg(unix)]
struct RestoreMode(std::path::PathBuf);

#[cfg(unix)]
impl Drop for RestoreMode {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
    }
}

/// `init --off` with one agent config unwritable keeps the record for that
/// agent only, so a later `status` warns about it alone.
#[cfg(unix)]
#[test]
fn partial_off_keeps_record_for_failed_agent() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new(&["claude", "gemini"]);
    assert_eq!(code(&env.saiife(&["init"])), 0);
    let claude_dir = env.root().join(".claude");
    std::fs::set_permissions(&claude_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let _restore = RestoreMode(claude_dir.clone());
    if dir_stays_writable(&claude_dir) {
        eprintln!("skipped: running as root, permissions do not stop writes");
        return;
    }
    let out = env.saiife(&["init", "--off"]);
    assert_eq!(code(&out), 1, "{}", stdout(&out));
    let rec = std::fs::read_dir(env.data.path().join("projects"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&rec).unwrap()).unwrap();
    let hooks = v["hooks"].as_object().unwrap();
    assert_eq!(hooks.keys().collect::<Vec<_>>(), ["claude"], "{v}");
    assert!(hooks["claude"]["error"].is_string(), "{v}");

    let st = env.saiife(&["status"]);
    let text = stdout(&st);
    assert_eq!(code(&st), 1, "{text}");
    assert!(
        text.contains("`saiife init --off` could not remove its hook from .claude/settings.json: "),
        "{text}"
    );
    assert!(
        text.contains(". Fix the file's permissions and run `saiife init --off` again."),
        "{text}"
    );
    assert!(!text.contains("run `saiife init` "), "{text}");
    // Exactly one warning: the failed agent. Nothing else.
    assert_eq!(text.matches("WARNING").count(), 1, "{text}");
    assert!(!text.contains("was removed"), "{text}");
    assert!(!text.contains("no agent is hooked"), "{text}");
    assert!(!text.contains("Gemini"), "{text}");
    assert!(env.root().join(".saiife/config.toml").is_file());
}

#[cfg(unix)]
#[test]
fn integrity_dir_is_tightened() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new(&["claude"]);
    let dir = env.data.path().join("projects");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(code(&env.saiife(&["init"])), 0);
    let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
}

#[cfg(unix)]
#[test]
fn dangling_agent_config_symlink_is_explained() {
    let env = Env::new(&["claude"]);
    std::fs::create_dir(env.root().join(".claude")).unwrap();
    let link = env.root().join(".claude/settings.json");
    std::os::unix::fs::symlink("gone/settings.json", &link).unwrap();
    let out = env.saiife(&["init"]);
    assert_eq!(code(&out), 1, "{}", stdout(&out));
    let text = stdout(&out);
    let line = text
        .lines()
        .find(|l| l.contains("FAILED") && l.contains("claude"))
        .unwrap_or_else(|| panic!("{text}"));
    assert!(line.contains(link.to_str().unwrap()), "{line}");
    assert!(line.contains("gone/settings.json"), "{line}");
    assert!(line.contains("does not exist"), "{line}");
    assert!(!line.contains("No such file"), "{line}");
}

#[cfg(unix)]
#[test]
fn dangling_symlink_chain_names_last_link() {
    let env = Env::new(&["claude"]);
    std::fs::create_dir(env.root().join(".claude")).unwrap();
    let dir = env.root().join(".claude");
    std::os::unix::fs::symlink("b.json", dir.join("a.json")).unwrap();
    std::os::unix::fs::symlink("missing.json", dir.join("b.json")).unwrap();
    std::os::unix::fs::symlink("a.json", dir.join("settings.json")).unwrap();
    let out = env.saiife(&["init"]);
    assert_eq!(code(&out), 1, "{}", stdout(&out));
    let text = stdout(&out);
    let line = text
        .lines()
        .find(|l| l.contains("FAILED") && l.contains("claude"))
        .unwrap_or_else(|| panic!("{text}"));
    assert!(line.contains("missing.json"), "{line}");
    assert!(line.contains("does not exist"), "{line}");
}

#[cfg(unix)]
#[test]
fn symlink_cycle_in_agent_config_keeps_loop_wording() {
    let env = Env::new(&["claude"]);
    let dir = env.root().join(".claude");
    std::fs::create_dir(&dir).unwrap();
    std::os::unix::fs::symlink("b.json", dir.join("a.json")).unwrap();
    std::os::unix::fs::symlink("a.json", dir.join("b.json")).unwrap();
    std::os::unix::fs::symlink("a.json", dir.join("settings.json")).unwrap();
    let out = env.saiife(&["init"]);
    assert_eq!(code(&out), 1, "{}", stdout(&out));
    let text = stdout(&out);
    let line = text
        .lines()
        .find(|l| l.contains("FAILED") && l.contains("claude"))
        .unwrap_or_else(|| panic!("{text}"));
    assert!(!line.contains("does not exist"), "{line}");
    assert!(line.contains("Too many levels of symbolic links"), "{line}");
}

/// Hook claude for real, then move its settings outside the project and
/// leave a symlink in its place.
#[cfg(unix)]
fn hooked_then_symlinked_outside(env: &Env, outside: &std::path::Path) -> std::path::PathBuf {
    assert_eq!(code(&env.saiife(&["init", "--agent", "claude"])), 0);
    let link = env.root().join(".claude/settings.json");
    let target = outside.join("settings.json");
    std::fs::rename(&link, &target).unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    std::fs::canonicalize(&target).unwrap()
}

#[cfg(unix)]
#[test]
fn outside_symlink_off_gives_cleanup_hint() {
    let env = Env::new(&["claude"]);
    let outside = tempfile::tempdir().unwrap();
    let target = hooked_then_symlinked_outside(&env, outside.path());
    let before = std::fs::read(&target).unwrap();
    assert!(String::from_utf8_lossy(&before).contains("saiife check"));
    let out = env.saiife(&["init", "--off"]);
    assert_eq!(code(&out), 1, "{}", stdout(&out));
    let text = stdout(&out);
    assert!(text.contains(target.to_str().unwrap()), "{text}");
    assert!(text.contains("by hand"), "{text}");
    assert!(text.contains("hook entry"), "{text}");
    assert_eq!(std::fs::read(&target).unwrap(), before);

    // `status` repeats the by-hand hint, never the permissions advice.
    let st = env.saiife(&["status"]);
    let text = stdout(&st);
    assert_eq!(code(&st), 1, "{text}");
    assert!(text.contains(target.to_str().unwrap()), "{text}");
    assert!(text.contains("by hand"), "{text}");
    assert!(!text.to_lowercase().contains("permissions"), "{text}");
    assert!(!text.contains("fix"), "{text}");
}

/// Plan 5b (status wording): the agent's earlier `init` failed (its config
/// already pointed outside the project), so after `--off` the hook "may
/// still be" in the outside file, not "is still"; status names the file
/// to check by hand. A second `--off` keeps that.
#[cfg(unix)]
#[test]
fn outside_symlink_off_after_failed_init_says_may_still_be_in_place() {
    let env = Env::new(&["claude", "codex"]);
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("config.toml");
    std::fs::write(&target, "model = \"x\"\n").unwrap();
    std::fs::create_dir(env.root().join(".codex")).unwrap();
    std::os::unix::fs::symlink(&target, env.root().join(".codex/config.toml")).unwrap();
    assert_eq!(code(&env.saiife(&["init"])), 1, "codex init fails");
    let target = std::fs::canonicalize(&target).unwrap();
    let target = target.to_str().unwrap();
    for _ in 0..2 {
        let out = env.saiife(&["init", "--off"]);
        let text = stdout(&out);
        assert_eq!(code(&out), 1, "{text}");
        assert!(text.contains("may still be there"), "{text}");
        let st = env.saiife(&["status"]);
        let text = stdout(&st);
        assert_eq!(code(&st), 1, "{text}");
        assert!(text.contains("may still be in place"), "{text}");
        assert!(!text.contains("is still in place"), "{text}");
        assert!(text.contains(target), "{text}");
        assert!(text.contains("by hand"), "{text}");
    }
}

#[cfg(unix)]
#[test]
fn outside_symlink_off_after_good_init_says_still_in_place() {
    let env = Env::new(&["claude"]);
    let outside = tempfile::tempdir().unwrap();
    hooked_then_symlinked_outside(&env, outside.path());
    assert_eq!(code(&env.saiife(&["init", "--off"])), 1);
    let text = stdout(&env.saiife(&["status"]));
    assert!(text.contains("is still in place"), "{text}");
    assert!(!text.contains("may still be"), "{text}");
}

/// Final review F1: an agent saiife never hooked is left alone, even when
/// its config is a symlink out of the project.
#[cfg(unix)]
#[test]
fn off_ignores_outside_symlink_of_an_agent_never_hooked() {
    let env = Env::new(&["claude", "codex"]);
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("settings.json");
    std::fs::write(&target, "{}\n").unwrap();
    std::fs::create_dir(env.root().join(".claude")).unwrap();
    std::os::unix::fs::symlink(&target, env.root().join(".claude/settings.json")).unwrap();
    assert_eq!(code(&env.saiife(&["init", "--agent", "codex"])), 0);
    let out = env.saiife(&["init", "--off"]);
    assert_eq!(code(&out), 0, "{}{}", stdout(&out), stderr(&out));
    let text = stdout(&out);
    assert!(!text.contains("FAILED"), "{text}");
    assert_eq!(std::fs::read(&target).unwrap(), b"{}\n");
    let st = env.saiife(&["status"]);
    let text = stdout(&st);
    // Fully off: the same clean "not set up" state as after any other off.
    assert!(text.contains("no integrity record"), "{text}");
    assert!(!text.contains("could not remove"), "{text}");
    assert!(!text.contains("settings.json"), "{text}");
}

#[cfg(unix)]
#[test]
fn off_ignores_dangling_symlink_of_an_agent_never_hooked() {
    let env = Env::new(&["claude", "codex"]);
    std::fs::create_dir(env.root().join(".claude")).unwrap();
    std::os::unix::fs::symlink(
        "gone/settings.json",
        env.root().join(".claude/settings.json"),
    )
    .unwrap();
    assert_eq!(code(&env.saiife(&["init", "--agent", "codex"])), 0);
    let out = env.saiife(&["init", "--off"]);
    assert_eq!(code(&out), 0, "{}{}", stdout(&out), stderr(&out));
    assert!(!stdout(&out).contains("FAILED"), "{}", stdout(&out));
}

/// Plan 7 (wording): when a step failed, the header must not claim saiife
/// is off.
#[cfg(unix)]
#[test]
fn off_partial_failure_header_says_not_completely_off() {
    let env = Env::new(&["claude"]);
    let outside = tempfile::tempdir().unwrap();
    hooked_then_symlinked_outside(&env, outside.path());
    let out = env.saiife(&["init", "--off"]);
    let text = stdout(&out);
    assert_eq!(code(&out), 1, "{text}");
    assert!(
        text.starts_with("saiife could not be turned off completely for"),
        "{text}"
    );
    assert!(text.contains("FAILED"), "{text}");
    assert!(!text.contains("saiife is off for"), "{text}");
}

#[test]
fn off_success_header_unchanged() {
    let env = Env::new(&["claude"]);
    assert_eq!(code(&env.saiife(&["init", "--agent", "claude"])), 0);
    let out = env.saiife(&["init", "--off"]);
    let text = stdout(&out);
    assert_eq!(code(&out), 0, "{text}");
    assert!(text.starts_with("saiife is off for"), "{text}");
}

#[test]
fn off_header_sanitizes_root() {
    let env = Env::new(&["claude"]);
    let dir = env.root().join("evil\x1b[31m");
    std::fs::create_dir_all(&dir).unwrap();
    let out = env.saiife_in(&dir, &["init", "--off"]);
    assert!(!out.stdout.contains(&0x1b), "{:?}", stdout(&out));
    assert!(stdout(&out).contains("evil\\x1b[31m"), "{}", stdout(&out));
}

/// Carry-over 2: a FIFO at the project config must not hang a re-run of
/// init (the "was it ours" hash read used to be a blocking `fs::read`).
#[cfg(unix)]
#[test]
fn init_with_fifo_config_does_not_hang() {
    let env = Env::new(&["claude"]);
    let out = env.saiife(&["init", "--agent", "claude"]);
    assert_eq!(code(&out), 0, "{}{}", stdout(&out), stderr(&out));
    let cfg = env.root().join(".saiife/config.toml");
    std::fs::remove_file(&cfg).unwrap();
    assert!(std::process::Command::new("mkfifo")
        .arg(&cfg)
        .status()
        .unwrap()
        .success());
    let out = env
        .saiife_within(
            &["init", "--agent", "claude"],
            std::time::Duration::from_secs(5),
        )
        .expect("saiife init hung on a FIFO config");
    assert_ne!(code(&out), 0, "{}{}", stdout(&out), stderr(&out));
}
