//! Golden corpus for two catastrophic bypasses closed in this slice:
//!
//! - **BLOCKER 1 — `sudo` with any flag bypassed every pack.** Every pack
//!   deny rule bakes in an `^(?:sudo\s+)?<cmd>` prefix, which only matches
//!   when `sudo` is immediately followed by the guarded command — any flag
//!   in between (`sudo -u root rm -rf /`, `sudo -n rm -rf /`, ...) slipped
//!   past every rule. Fixed by unwrapping `sudo` structurally, the same way
//!   as `command`/`env`/`nohup`/`nice`/`stdbuf`/`ionice` — see
//!   `wrappers::unwrap_transparent_prefix`.
//! - **BLOCKER 2 — command substitution in COMMAND position executed for
//!   real, unjudged.** The existing fail-safe only covers `$(...)`/`` `...`
//!   `` as an *argument* to a guarded command; when the substitution IS the
//!   command (`$(rm -rf /)`, `` `rm -rf /` ``, `FOO=$(rm -rf /)`), there's
//!   no argv[0] for any pack to match, and a real shell still runs it
//!   eagerly. Fixed by recursing into the substitution's inner text — see
//!   `subst::command_position_substitution`.

use lfguard::builtins::builtin_packs;
use lfguard::engine::{Decision, Engine};
use lfguard::profile::select_active;

/// core.filesystem + core.git are default-on; that's the context for every
/// corpus line below except the gcloud/gsutil ones.
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

// ---- BLOCKER 1: sudo with flags ------------------------------------------

#[test]
fn denies_sudo_with_any_flag_on_default_packs() {
    let e = default_engine();
    let deny = [
        "sudo -u root rm -rf /",
        "sudo -n rm -rf /",
        "sudo -E rm -rf /",
        "sudo -i rm -rf /",
        "sudo -H rm -rf /",
        "sudo --user root rm -rf /",
        "sudo --user=root rm -rf /",
        // bare sudo must still deny — this fix must not regress it
        "sudo rm -rf /",
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
fn denies_sudo_with_flags_across_gcloud_pack() {
    let e = gcloud_engine();
    let deny = [
        "sudo -u root gcloud projects delete p",
        "sudo -n gsutil rb gs://b",
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
fn allows_sudo_on_a_benign_command() {
    let e = default_engine();
    let allow = ["sudo ls", "sudo -u root ls"];
    for cmd in allow {
        assert!(
            !e.evaluate(cmd).is_deny(),
            "expected ALLOW for {cmd:?}, got {:?}",
            e.evaluate(cmd)
        );
    }
}

#[test]
fn lone_sudo_or_sudo_help_fails_open_without_panicking() {
    let e = default_engine();
    for cmd in ["sudo", "sudo --help"] {
        // Must not panic; a lone `sudo` with no resolvable command has
        // nothing for any pack to judge, so it fails open (allow).
        assert!(
            !e.evaluate(cmd).is_deny(),
            "expected ALLOW (fail-open) for {cmd:?}, got {:?}",
            e.evaluate(cmd)
        );
    }
}

// ---- BLOCKER 2: command substitution in command position -----------------

#[test]
fn denies_command_substitution_in_command_position() {
    let e = default_engine();
    let deny = [
        "$(rm -rf /)",
        "`rm -rf /`",
        "FOO=$(rm -rf /)",
        "x=$(rm -rf /)",
        "$(rm -rf /); echo done",
        "echo start; $(rm -rf /)",
        // nested substitution must recurse
        "$( $(rm -rf /) )",
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
fn denies_command_substitution_in_command_position_for_gcloud_pack() {
    let e = gcloud_engine();
    let cmd = "$(gcloud projects delete p)";
    assert!(
        e.evaluate(cmd).is_deny(),
        "expected DENY for {cmd:?}, got {:?}",
        e.evaluate(cmd)
    );
}

#[test]
fn does_not_regress_benign_quoted_substitutions() {
    let e = default_engine();
    let allow = [r#"echo "$(date)""#, r#"echo "$(git rev-parse HEAD)""#];
    for cmd in allow {
        assert!(
            !e.evaluate(cmd).is_deny(),
            "expected ALLOW for {cmd:?}, got {:?}",
            e.evaluate(cmd)
        );
    }
}

/// A long chain (5000 segments) mixing plain segments with a trailing
/// `sudo`-wrapped command must still resolve well under the latency budget —
/// the new unwrap/substitution-detection work runs per segment and must stay
/// linear, not introduce a quadratic blowup on a long chain.
#[test]
fn long_chain_with_trailing_sudo_denies_within_budget() {
    let e = default_engine();
    let mut cmd = String::new();
    for _ in 0..5000 {
        cmd.push_str("true && ");
    }
    cmd.push_str("sudo -u root rm -rf /");
    let start = std::time::Instant::now();
    let decision = e.evaluate(&cmd);
    let elapsed = start.elapsed();
    assert!(decision.is_deny(), "expected DENY, got {decision:?}");
    assert!(
        elapsed < std::time::Duration::from_millis(45),
        "5000-segment chain took {elapsed:?}, expected comfortably under the 50ms budget"
    );
}

#[test]
fn deep_nesting_of_command_position_substitution_fails_open_not_stack_overflow() {
    // Nest well past MAX_INLINE_DEPTH (8). Must not panic/overflow; must
    // resolve (fail open past the depth cap) well under the latency budget.
    let e = default_engine();
    let mut cmd = "rm -rf /".to_string();
    for _ in 0..20 {
        cmd = format!("$({cmd})");
    }
    let start = std::time::Instant::now();
    let decision = e.evaluate(&cmd);
    let elapsed = start.elapsed();
    // Not asserting deny/allow here deliberately — past the depth cap the
    // guard fails open by design, and the exact cutover point is an
    // implementation detail. What matters is it terminates quickly.
    let _ = decision;
    assert!(
        elapsed < std::time::Duration::from_millis(45),
        "20-deep nested substitution took {elapsed:?}, expected comfortably under the 50ms budget"
    );
}

#[test]
fn guarded_argument_fail_safe_still_denies_substitution_as_an_argument() {
    // `rm -rf $(x)` — substitution as an *argument*, not command position —
    // must still be caught by the pre-existing guarded-argument fail-safe.
    // This is a regression guard: the new command-position recursion must
    // not short-circuit or otherwise interfere with it.
    let e = default_engine();
    let cmd = "rm -rf $(x)";
    assert!(
        e.evaluate(cmd).is_deny(),
        "expected DENY for {cmd:?}, got {:?}",
        e.evaluate(cmd)
    );
}

// ---- combined: sudo + substitution (bonus coverage, not corpus-required) -

#[test]
fn sudo_wrapped_command_position_substitution_still_denies() {
    // Not explicitly required by the corpus, but falls out for free since
    // command-position detection runs on the *unwrapped* segment: sudo (with
    // or without flags) wrapping a command-position substitution must still
    // be judged, not silently allowed.
    let e = default_engine();
    for cmd in ["sudo $(rm -rf /)", "sudo -u root $(rm -rf /)"] {
        assert!(
            e.evaluate(cmd).is_deny(),
            "expected DENY for {cmd:?}, got {:?}",
            e.evaluate(cmd)
        );
    }
}

// ---- full prior corpus re-confirmed (no regressions) ----------------------

#[test]
fn full_prior_corpus_still_denies() {
    let e = default_engine();
    let deny = [
        // chaining
        "echo hi && rm -rf /",
        "true; rm -rf ~",
        // grouping / compound-keyword
        "( rm -rf / )",
        "{ rm -rf /; }",
        "if true; then rm -rf /; fi",
        // wrappers
        "command rm -rf /",
        "env rm -rf /",
        "nohup rm -rf /",
        "nice rm -rf /",
        // escaped-quote / adjacent-concat
        "echo \"a\\\"\" ; rm -rf /",
        r#"rm -rf "/e"tc"#,
        // case-fold
        "RM -RF /",
        // $'...' ANSI-C quoting
        "rm -rf $'/'",
        // false-positive-safe shapes that must still deny
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
fn full_prior_corpus_still_allows() {
    let e = default_engine();
    let allow = [
        "rm -rf ~/project/build",
        "cd foo && ls",
        r#"echo "a && b""#,
        r#"echo "$(date)""#,
        "ls -la",
        "rm -rf /tmp/{a,b}",
        r#"git commit -m "wip (fix)""#,
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
fn full_prior_corpus_gcloud_describe_still_allows() {
    let e = gcloud_engine();
    let cmd = "gcloud compute instances describe delete-me-vm";
    assert!(
        !e.evaluate(cmd).is_deny(),
        "expected ALLOW for {cmd:?}, got {:?}",
        e.evaluate(cmd)
    );
}

/// Deny-decision detail sanity: the propagated `pack`/`reason` for a
/// command-position substitution must come from whatever rule actually
/// matched the recursed inner command, not a generic substitution label —
/// proves the recursion reuses real pack judging, not a blanket deny.
#[test]
fn command_position_substitution_deny_carries_the_real_pack_and_reason() {
    let e = default_engine();
    match e.evaluate("$(rm -rf /)") {
        Decision::Deny {
            pack,
            reason,
            via_inline,
            ..
        } => {
            assert_eq!(pack, "core.filesystem");
            assert!(reason.contains("recursive"), "reason was: {reason:?}");
            assert_eq!(via_inline.as_deref(), Some("rm -rf /"));
        }
        other => panic!("expected DENY, got {other:?}"),
    }
}
