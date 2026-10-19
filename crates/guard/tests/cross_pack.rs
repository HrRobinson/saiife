//! Cross-pack profile behavior: the default profile activates the default-on
//! (`core.*`) packs only; opt-in packs stay INACTIVE until explicitly enabled.

use saiifeguard::builtins::builtin_packs;
use saiifeguard::engine::{AllowTrace, Decision, Engine};
use saiifeguard::pack::load_pack_str;
use saiifeguard::profile::select_active;

fn default_engine() -> Engine {
    let (packs, _) = builtin_packs();
    Engine::new(select_active(packs, &[])).with_budget(TEST_BUDGET)
}

fn engine_with(enabled: &[&str]) -> Engine {
    let (packs, _) = builtin_packs();
    let enabled: Vec<String> = enabled.iter().map(|s| s.to_string()).collect();
    Engine::new(select_active(packs, &enabled)).with_budget(TEST_BUDGET)
}

#[test]
fn default_profile_activates_core_packs() {
    let e = default_engine();
    assert!(e.evaluate("git reset --hard").is_deny(), "core.git active");
    assert!(e.evaluate("rm -rf /").is_deny(), "core.filesystem active");
}

#[test]
fn opt_in_packs_are_inactive_by_default() {
    let e = default_engine();
    // Commands the opt-in packs WOULD block are allowed under the default
    // profile, proving those packs are not loaded unless enabled.
    assert!(
        !e.evaluate("gcloud projects delete my-proj").is_deny(),
        "cloud.gcloud must be inactive by default"
    );
    assert!(
        !e.evaluate(r#"psql -c "DROP DATABASE prod""#).is_deny(),
        "db.postgres must be inactive by default"
    );
}

#[test]
fn enabling_an_opt_in_pack_activates_only_it() {
    let e = engine_with(&["cloud.gcloud"]);
    assert!(
        e.evaluate("gcloud projects delete p").is_deny(),
        "gcloud on"
    );
    // postgres was not enabled, so it stays inactive.
    assert!(
        !e.evaluate(r#"psql -c "DROP DATABASE prod""#).is_deny(),
        "db.postgres still inactive"
    );
}

fn pack(toml: &str) -> saiifeguard::pack::Pack {
    let mut w = Vec::new();
    let p = load_pack_str("<t>", toml, &mut w).unwrap();
    assert!(w.is_empty(), "{w:?}");
    p
}

const PACK_A_ALLOWS: &str = r#"
[pack]
id = "test.a"
triggers = ["foo"]

[[allow]]
pattern = '^foo\b'
reason = "a allows foo"
"#;

const PACK_B_DENIES: &str = r#"
[pack]
id = "test.b"
triggers = ["foo"]

[[deny]]
pattern = '^foo\s+--bad'
reason = "b denies --bad"
"#;

const PACK_B_ALLOWS: &str = r#"
[pack]
id = "test.b"
triggers = ["foo"]

[[allow]]
pattern = '^foo'
reason = "b allows foo"
"#;

#[test]
fn allow_in_one_pack_does_not_hide_deny_in_another() {
    let e = Engine::new(vec![pack(PACK_A_ALLOWS), pack(PACK_B_DENIES)]).with_budget(TEST_BUDGET);
    match e.evaluate("foo --bad") {
        Decision::Deny { pack, .. } => assert_eq!(pack, "test.b"),
        other => panic!("expected deny from test.b, got {other:?}"),
    }
    assert!(!e.evaluate("foo ok").is_deny());
}

#[test]
fn two_allowing_packs_return_first_trace() {
    let e = Engine::new(vec![pack(PACK_A_ALLOWS), pack(PACK_B_ALLOWS)]).with_budget(TEST_BUDGET);
    match e.evaluate("foo x") {
        Decision::Allow {
            trace: AllowTrace::AllowRule { pack, .. },
        } => assert_eq!(pack, "test.a", "load order decides the trace"),
        other => panic!("expected an allow-rule trace, got {other:?}"),
    }
}

/// Generous budget so a loaded runner cannot turn a deny into a latency
/// fail-open; the budget path itself is covered by dedicated tests.
const TEST_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);
