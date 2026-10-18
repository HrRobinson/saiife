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
            "packs = [\"core.filesystem\", \"core.git\", \"core.secrets\", \"core.self\"]"
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

/// A mode-0500 directory still writable (root) means permissions cannot
/// make a write fail here; tests that need that skip.
#[cfg(unix)]
fn dir_stays_writable(dir: &std::path::Path) -> bool {
    let probe = dir.join(".probe");
    let ok = std::fs::write(&probe, "x").is_ok();
    let _ = std::fs::remove_file(&probe);
    ok
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
    if dir_stays_writable(&claude_dir) {
        std::fs::set_permissions(&claude_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
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
    assert!(text.contains("could not set up Claude Code"), "{text}");
    assert!(!text.contains("Gemini"), "{text}");
    assert!(!text.contains("no agent is hooked"), "{text}");
    std::fs::set_permissions(&claude_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
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
fn outside_symlink_off_gives_cleanup_hint() {
    let env = Env::new(&["claude"]);
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("settings.json");
    std::fs::write(&target, "{}\n").unwrap();
    std::fs::create_dir(env.root().join(".claude")).unwrap();
    std::os::unix::fs::symlink(&target, env.root().join(".claude/settings.json")).unwrap();
    let out = env.saiife(&["init", "--off"]);
    assert_eq!(code(&out), 1, "{}", stdout(&out));
    let text = stdout(&out);
    let target_name = std::fs::canonicalize(&target).unwrap();
    assert!(text.contains(target_name.to_str().unwrap()), "{text}");
    assert!(text.contains("by hand"), "{text}");
    assert!(text.contains("hook entry"), "{text}");
}
