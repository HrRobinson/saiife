mod common;

use common::{code, stdout, Env};

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
