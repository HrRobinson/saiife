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
        cfg.contains("packs = [\"core.filesystem\", \"core.git\"]"),
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
