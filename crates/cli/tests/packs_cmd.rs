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
