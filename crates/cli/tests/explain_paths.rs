//! `saiife explain --read/--write <path>` and `saiife packs <id>`: the path
//! rules a user hits through file tools, explained from the terminal.

mod common;

use common::{code, stderr, stdout, Env};

#[test]
fn explain_read_and_write_of_a_path() {
    let env = Env::new(&[]);
    let root = std::fs::canonicalize(env.root()).unwrap();

    let out = env.saiife(&["explain", "--read", ".env"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("path:     .env\n"), "{text}");
    // Windows: the guard's own spelling of the path (`d:/x`), not the verbatim
    // one `fs::canonicalize` gives.
    let resolved = if cfg!(windows) {
        let text = root.join(".env").display().to_string();
        let plain = text
            .strip_prefix(r"\\?\")
            .unwrap_or(&text)
            .replace('\\', "/");
        plain[..1].to_ascii_lowercase() + &plain[1..]
    } else {
        root.join(".env").display().to_string()
    };
    assert!(text.contains(&format!("resolved: {resolved}\n")), "{text}");
    assert!(text.contains("access:   read\n"), "{text}");
    assert!(text.contains("decision: DENY\n"), "{text}");
    assert!(text.contains("pack:     core.secrets\n"), "{text}");
    assert!(text.contains("rule:     **/.env\n"), "{text}");

    let out = env.saiife(&["explain", "--read", ".env.example"]);
    let text = stdout(&out);
    assert!(text.contains("decision: ALLOW\n"), "{text}");
    assert!(text.contains("allow rule:      **/.env.example"), "{text}");

    let out = env.saiife(&["explain", "--write", ".claude/settings.json"]);
    let text = stdout(&out);
    assert!(text.contains("decision: DENY\n"), "{text}");
    assert!(text.contains("pack:     core.self\n"), "{text}");

    let out = env.saiife(&["explain", "--read", ".claude/settings.json"]);
    assert!(
        stdout(&out).contains("decision: ALLOW\n"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn explain_needs_exactly_one_of_command_read_write() {
    let env = Env::new(&[]);
    assert_eq!(code(&env.saiife(&["explain"])), 2);
    assert_eq!(
        code(&env.saiife(&["explain", "--read", "a", "--write", "b"])),
        2
    );
    let out = env.saiife(&["explain", "cat .env"]);
    assert_eq!(code(&out), 0);
    assert!(
        stdout(&out).contains("pack:     core.secrets"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn test_resolves_relative_paths_against_the_current_directory() {
    let env = Env::new(&[]);
    assert_eq!(code(&env.saiife(&["test", "cat .env"])), 1);
    assert_eq!(code(&env.saiife(&["test", "cat README.md"])), 0);
}

#[test]
fn packs_with_an_id_shows_its_rules() {
    let env = Env::new(&[]);
    let out = env.saiife(&["packs", "core.self"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("core.self — Core: self-protection"), "{text}");
    assert!(text.contains("  deny   write  $SAIIFE_BIN\n"), "{text}");
    assert!(!text.contains("inactive here"), "{text}");
    let out = env.saiife(&["packs", "core.nope"]);
    assert_eq!(code(&out), 2);
    assert!(stderr(&out).contains("unknown pack"), "{}", stderr(&out));
}

/// With every variable bound, no command reports inactive rules. (The
/// unbound case is a unit test in `packs_cmd`: no environment can leave a
/// variable unbound any more.)
#[test]
fn nothing_is_reported_inactive_when_everything_is_bound() {
    let env = Env::new(&[]);
    let text = stdout(&env.saiife(&["explain", "--write", ".claude/settings.json"]));
    assert!(!text.contains("inactive here"), "{text}");
}

fn put_pack(env: &Env, text: &str) {
    let dir = env.home.path().join(".config/saiife/broker/policy.d/packs");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("user.t.toml"), text).unwrap();
}

fn user_pack_env(extra: &str) -> Env {
    let env = Env::new(&[]);
    put_pack(
        &env,
        &format!(
            "[pack]\nid = \"user.t\"\ntriggers = [\"deploy-prod\"]\n[[deny]]\nid = \"no-prod\"\npattern = '^deploy-prod\\b'\nreason = \"never deploy prod\"\n{extra}"
        ),
    );
    env
}

/// `saiife <args>` with the personal config dir under the test HOME.
fn user_run(env: &Env, args: &[&str]) -> std::process::Output {
    env.command_in(env.root(), args)
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .unwrap()
}

#[test]
fn explain_box_profile_skips_host_rules() {
    let env = user_pack_env("where = \"host\"\n");
    let out = user_run(&env, &["explain", "deploy-prod --now"]);
    let text = stdout(&out);
    assert!(text.contains("decision: DENY\n"), "{text}");
    assert!(text.contains("pack:     user.t\n"), "{text}");
    let out = user_run(&env, &["explain", "--profile", "box", "deploy-prod --now"]);
    let text = stdout(&out);
    assert!(text.contains("decision: ALLOW\n"), "{text}");
    assert!(!text.contains("user.t"), "{text}");
    // An `everywhere` rule stays in the box.
    let env = user_pack_env("");
    let out = user_run(&env, &["explain", "--profile", "box", "deploy-prod --now"]);
    assert!(
        stdout(&out).contains("pack:     user.t\n"),
        "{}",
        stdout(&out)
    );
}
