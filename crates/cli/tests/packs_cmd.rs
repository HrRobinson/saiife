mod common;

use common::{code, stderr, stdout, Env};

#[test]
fn packs_shows_what_is_on_here() {
    let env = Env::new(&[]);
    let out = env.saiife(&["packs"]);
    assert_eq!(code(&out), 0);
    assert!(stdout(&out).contains("showing the defaults"));
    env.write(
        ".saiife/config.toml",
        "version = 1\npacks = [\"db.postgres\"]\n",
    );
    let out = env.saiife(&["packs"]);
    let text = stdout(&out);
    let pg = text
        .lines()
        .find(|l| l.starts_with("db.postgres "))
        .unwrap();
    assert!(pg.contains(" off     on "), "{pg}");
    assert!(text.lines().count() >= 12, "{text}");
}

/// A broken project config never breaks `saiife packs`: warn, show defaults.
#[test]
fn broken_config_warns_and_shows_the_defaults() {
    let env = Env::new(&[]);
    env.write(".saiife/config.toml", "packs = [\n");
    let out = env.saiife(&["packs"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("using the default packs only"),
        "{}",
        stderr(&out)
    );
    let text = stdout(&out);
    let git = text.lines().find(|l| l.starts_with("core.git ")).unwrap();
    assert!(git.contains(" on      on "), "{git}");
    let pg = text
        .lines()
        .find(|l| l.starts_with("db.postgres "))
        .unwrap();
    assert!(pg.contains(" off     off "), "{pg}");
}

/// With `SAIIFE_AUDIT_DIR` unset the audit dir defaults to one under the
/// user's data dir; a relative HOME (and no XDG_DATA_HOME) leaves that
/// default undeterminable too, so the audit-dir rules cannot apply and
/// `packs <id>` marks them inactive.
#[test]
fn explain_prints_inactive_note() {
    let env = Env::new(&[]);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["packs", "core.self"])
        .current_dir(env.root())
        .env("PATH", env.bin.path())
        .env("HOME", "relative-home")
        .env_remove("XDG_DATA_HOME")
        .env("SAIIFE_DATA_DIR", env.data.path())
        .env_remove("SAIIFE_AUDIT_DIR")
        .output()
        .unwrap();
    let text = stdout(&out);
    assert_eq!(code(&out), 0, "{text}");
    assert!(
        text.contains("(inactive here: $SAIIFE_AUDIT_DIR is not set)"),
        "{text}"
    );
}
