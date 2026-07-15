//! Cross-pack profile behavior: the default profile activates the default-on
//! (`core.*`) packs only; opt-in packs stay INACTIVE until explicitly enabled.

use lfguard::builtins::builtin_packs;
use lfguard::engine::Engine;
use lfguard::profile::select_active;

fn default_engine() -> Engine {
    let (packs, _) = builtin_packs();
    Engine::new(select_active(packs, &[]))
}

fn engine_with(enabled: &[&str]) -> Engine {
    let (packs, _) = builtin_packs();
    let enabled: Vec<String> = enabled.iter().map(|s| s.to_string()).collect();
    Engine::new(select_active(packs, &enabled))
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
