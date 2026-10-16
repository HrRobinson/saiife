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
    assert!(
        text.contains(&format!("resolved: {}\n", root.join(".env").display())),
        "{text}"
    );
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

/// A relative SAIIFE_AUDIT_DIR is dropped, so the audit-dir rules cannot
/// apply: both commands say so instead of hiding the rules.
#[test]
fn rules_with_an_unbound_variable_are_listed_as_inactive() {
    let env = Env::new(&[]);
    let run = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_saiife"))
            .args(args)
            .current_dir(env.root())
            .env("PATH", env.bin.path())
            .env("HOME", env.home.path())
            .env("SAIIFE_DATA_DIR", env.data.path())
            .env("SAIIFE_AUDIT_DIR", "relative/audit")
            .output()
            .unwrap()
    };
    let out = run(&["packs", "core.self"]);
    let text = stdout(&out);
    assert!(
        text.contains(
            "  deny   write  $SAIIFE_AUDIT_DIR/**  (inactive here: $SAIIFE_AUDIT_DIR is not set)\n"
        ),
        "{text}"
    );
    assert!(!text.contains("$SAIIFE_BIN  (inactive"), "{text}");

    let out = run(&["explain", "--write", ".claude/settings.json"]);
    let text = stdout(&out);
    assert!(text.contains("decision: DENY\n"), "{text}");
    assert!(
        text.contains("inactive here: $SAIIFE_AUDIT_DIR is not set: core.self"),
        "{text}"
    );

    // Everything bound: nothing is reported.
    let text = stdout(&env.saiife(&["explain", "--write", ".claude/settings.json"]));
    assert!(!text.contains("inactive here"), "{text}");
}
