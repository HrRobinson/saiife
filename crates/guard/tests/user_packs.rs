//! User packs through the engine: a user pack adds denies, never loosens a
//! built-in, and a broken one is an error.

use saiifeguard::builtins::Catalog;
use saiifeguard::canon::PathStyle;
use saiifeguard::profile::Profile;
use saiifeguard::userpack::{load_user_packs, UserSrc};
use saiifeguard::{Decision, Engine};

fn engine(user_toml: &str) -> Engine {
    let (mut packs, _) = Catalog::builtin().load_active(&[]);
    let srcs = [UserSrc {
        source: "t.toml",
        text: user_toml,
    }];
    packs.extend(load_user_packs(&srcs, PathStyle::Posix, Profile::Host).unwrap());
    Engine::new(packs)
}

fn load(text: &str) -> Result<usize, String> {
    let srcs = [UserSrc {
        source: "t.toml",
        text,
    }];
    load_user_packs(&srcs, PathStyle::Posix, Profile::Host)
        .map(|p| p.len())
        .map_err(|e| e.to_string())
}

const DENY: &str = r#"
[pack]
id = "user.t"
triggers = ["deploy-prod"]

[[deny]]
id = "l3-1"
pattern = '^deploy-prod(?:\s|$)'
reason = "CLAUDE.md:3 \"Never run deploy-prod\""
"#;

#[test]
fn user_deny_blocks_with_its_reason() {
    let e = engine(DENY);
    match e.evaluate("deploy-prod --now") {
        Decision::Deny { pack, reason, .. } => {
            assert_eq!(pack, "user.t");
            assert_eq!(reason, "CLAUDE.md:3 \"Never run deploy-prod\"");
        }
        other => panic!("expected deny, got {other:?}"),
    }
    assert!(matches!(
        e.evaluate("echo deploy-prod"),
        Decision::Allow { .. }
    ));
}

#[test]
fn user_allow_cannot_exempt_builtin() {
    let e = engine(
        r#"
[pack]
id = "user.loose"
triggers = ["git"]

[[allow]]
pattern = '^git\s+reset'

[[deny]]
id = "x"
pattern = '^never-matches-anything$'
reason = "r"
"#,
    );
    match e.evaluate("git reset --hard") {
        Decision::Deny { pack, .. } => assert_eq!(pack, "core.git"),
        other => panic!("expected core.git deny, got {other:?}"),
    }
}

#[test]
fn user_pack_id_must_be_user_prefixed() {
    for id in ["core.git", "user.", "user.-x", "user.UP"] {
        let err = load(&DENY.replace("user.t", id)).unwrap_err();
        assert!(err.contains(id), "{err}");
    }
    assert_eq!(load(&DENY.replace("user.t", "user.ok-1")), Ok(1));
}

#[test]
fn broken_regex_is_an_error_not_a_drop() {
    let err = load(&DENY.replace(r"'^deploy-prod(?:\s|$)'", "'('")).unwrap_err();
    assert!(err.contains("uncompilable"), "{err}");
}

#[test]
fn duplicate_ids_and_caps() {
    let srcs = [
        UserSrc {
            source: "a.toml",
            text: DENY,
        },
        UserSrc {
            source: "b.toml",
            text: DENY,
        },
    ];
    assert!(load_user_packs(&srcs, PathStyle::Posix, Profile::Host).is_err());

    let mut big = String::from("[pack]\nid = \"user.big\"\ntriggers = [\"x\"]\n");
    for i in 0..129 {
        big.push_str(&format!(
            "[[deny]]\nid = \"r{i}\"\npattern = '^x{i}$'\nreason = \"r\"\n"
        ));
    }
    assert!(load(&big).unwrap_err().contains("128"));

    let off = DENY.replace("triggers", "default_on = false\ntriggers");
    assert!(load(&off)
        .unwrap_err()
        .contains("a user pack is always on; remove default_on"));

    let noid = DENY.replace("id = \"l3-1\"\n", "");
    assert!(load(&noid)
        .unwrap_err()
        .contains("every [[deny]] in a user pack needs an id"));
}
