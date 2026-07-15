//! Golden corpus for the tokenizer hardening work: every adversarial shape
//! from both review rounds (escaped-quote-does-not-close-the-string,
//! adjacent-string concatenation, unquoted/no-whitespace operator splitting,
//! command substitution as an opaque non-splitting token, case-folded
//! argv[0], and command substitution in a guarded argument position denying
//! fail-safe) plus the corresponding must-allow spread, so none of it is a
//! false positive either.

use lfguard::builtins::builtin_packs;
use lfguard::engine::Engine;
use lfguard::profile::select_active;

/// core.filesystem + core.git are default-on; that's the context for every
/// corpus line below except the two gcloud/gsutil ones.
fn default_engine() -> Engine {
    let (packs, warnings) = builtin_packs();
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    Engine::new(select_active(packs, &[]))
}

/// cloud.gcloud is opt-in; the gcloud/gsutil corpus lines need it enabled.
fn gcloud_engine() -> Engine {
    let (packs, warnings) = builtin_packs();
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    Engine::new(select_active(packs, &["cloud.gcloud".to_string()]))
}

#[test]
fn denies_default_pack_corpus() {
    let e = default_engine();
    let deny = [
        // --- chaining: operator with and without surrounding whitespace ---
        "echo hi && rm -rf /",
        "true; rm -rf ~",
        "foo | rm -rf /",
        "a && b || rm -rf /",
        "a&&rm -rf /",
        "a ;rm -rf /",
        "a\nrm -rf /",
        // --- escaped-quote-does-not-close-the-string (round-2 Critical #1) ---
        "echo \"a\\\"\" ; rm -rf /",
        "echo \"a\\\"\" && git reset --hard",
        "true \"\\\"\" ; rm -rf /",
        // --- quoting / repeated-slash / flag-order variants of rm's target ---
        r#"rm -rf "/""#,
        "rm -rf //",
        "rm /etc -rf",
        "rm -r -f /",
        "rm --recursive --force /",
        "rm -fr /",
        "rm  -rf  ///",
        r#"rm -rf "/"//"#,
        "rm -rf /*",
        // --- adjacent-string concatenation (round-2 Critical #2) ---
        r#"rm -rf "/e"tc"#,
        r#"rm -rf /et"c""#,
        r#"rm -rf ""/"#,
        r#"rm -rf /""#,
        // --- case-folded argv[0] (round-2 Important) ---
        "RM -RF /",
        // --- command substitution in a guarded argument position ---
        "rm -rf $(some-cmd)",
    ];
    for cmd in deny {
        assert!(
            e.evaluate(cmd).is_deny(),
            "expected DENY for {cmd:?}, got {:?}",
            e.evaluate(cmd)
        );
    }
}

#[test]
fn denies_gcloud_corpus_when_pack_enabled() {
    let e = gcloud_engine();
    let deny = ["gcloud compute instances delete foo", "gsutil rb gs://x"];
    for cmd in deny {
        assert!(
            e.evaluate(cmd).is_deny(),
            "expected DENY for {cmd:?}, got {:?}",
            e.evaluate(cmd)
        );
    }
}

#[test]
fn allows_default_pack_corpus() {
    let e = default_engine();
    let allow = [
        "rm -rf ~/project/build",
        "cd foo && ls",
        r#"echo "a && b""#,
        r#"echo "a; b""#,
        r#"echo "$(date)""#,
        "ls -la",
    ];
    for cmd in allow {
        assert!(
            !e.evaluate(cmd).is_deny(),
            "expected ALLOW for {cmd:?}, got {:?}",
            e.evaluate(cmd)
        );
    }
}

#[test]
fn allows_gcloud_describe_of_a_delete_named_resource_when_pack_enabled() {
    let e = gcloud_engine();
    let cmd = "gcloud compute instances describe delete-me-vm";
    assert!(
        !e.evaluate(cmd).is_deny(),
        "expected ALLOW for {cmd:?}, got {:?}",
        e.evaluate(cmd)
    );
}

/// Independent sanity check for the fail-safe command-substitution policy:
/// it must be scoped to commands that are *already* guarded, adding no new
/// scrutiny to ordinary commands. `echo` has no deny rule anywhere, so a
/// substitution argument to it must not be treated specially.
#[test]
fn substitution_deny_is_scoped_to_already_guarded_commands() {
    let e = default_engine();
    assert!(!e.evaluate("echo $(date)").is_deny());
    assert!(!e.evaluate(r#"echo "$(date)""#).is_deny());
    assert!(!e.evaluate("echo `date`").is_deny());
}

/// A pathological, very long chain must still resolve well under the
/// engine's latency budget — segmentation and per-segment judging must stay
/// linear, not blow up on a long unmatched chain.
///
/// The threshold here is deliberately generous for an unoptimized `cargo
/// test` build (plain allocation/drop overhead per segment is much higher
/// in debug than in the `[profile.release]` build lfguard actually ships —
/// the same 3000-segment chain resolves in well under 1ms in `--release`).
/// What this test really guards against is a latent quadratic blowup: a
/// true O(n) implementation stays a small constant factor under the 50ms
/// engine budget even in debug; an accidental O(n^2) one blows past it by
/// orders of magnitude, not a few milliseconds.
#[test]
fn pathological_long_chain_stays_well_under_budget() {
    let e = default_engine();
    let mut cmd = String::new();
    for i in 0..3000 {
        if i > 0 {
            cmd.push_str(" && ");
        }
        cmd.push_str("true");
    }
    let start = std::time::Instant::now();
    let decision = e.evaluate(&cmd);
    let elapsed = start.elapsed();
    assert!(!decision.is_deny(), "expected ALLOW, got {decision:?}");
    assert!(
        elapsed < std::time::Duration::from_millis(45),
        "3000-segment chain took {elapsed:?}, expected comfortably under the 50ms budget"
    );
}

/// Same shape, but the last segment is destructive — proves the engine
/// still finds it (doesn't silently truncate/skip segments under load) and
/// still does so quickly, i.e. without ever needing to fail open on time.
#[test]
fn pathological_long_chain_still_catches_a_trailing_deny() {
    let e = default_engine();
    let mut cmd = String::new();
    for _ in 0..3000 {
        cmd.push_str("true && ");
    }
    cmd.push_str("rm -rf /");
    let start = std::time::Instant::now();
    let decision = e.evaluate(&cmd);
    let elapsed = start.elapsed();
    assert!(decision.is_deny(), "expected DENY, got {decision:?}");
    assert!(
        elapsed < std::time::Duration::from_millis(45),
        "3000-segment chain took {elapsed:?}, expected comfortably under the 50ms budget"
    );
}
