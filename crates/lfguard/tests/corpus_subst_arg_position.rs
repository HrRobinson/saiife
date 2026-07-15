//! Golden corpus for the catastrophic bypass closed in this slice:
//!
//! - **A command substitution as an argument to an UNGUARDED command was
//!   never judged, even though a real shell evaluates it eagerly.**
//!   `echo $(rm -rf /)` executes `rm -rf /` for real (its output, if any,
//!   is merely what `echo` prints afterward) — but the engine's only
//!   existing substitution handling was (a) recursion when the substitution
//!   filled the *whole command position* (`$(rm -rf /)`) and (b) a
//!   fail-safe deny when a substitution was an *argument to an
//!   already-guarded command* (`rm -rf $(x)`). Neither covers a
//!   substitution sitting as an argument to a command no pack has a deny
//!   rule for (`echo`, `cat`, `foo`, …) — that shape reached `build_argv`,
//!   matched no guarded-command fail-safe, and the substitution's raw text
//!   was never looked at again. Fixed by generalizing the recursion: every
//!   `$(...)`/`` `...` `` found ANYWHERE in a segment — command or argument
//!   position, guarded or unguarded command, quoted or bare, even glued to
//!   other text (`$(cmd)suffix`) — is now extracted and judged recursively
//!   through the whole pipeline. See `lexer::find_all_substitutions` and
//!   its use in `engine::Engine::evaluate_inner`.
//!
//! This generalization subsumes the two mechanisms above rather than
//! replacing them: command-position recursion (`subst::
//! command_position_substitution`) still runs first and is unaffected, and
//! the guarded-argument fail-safe still independently denies a dynamic
//! target for an already-guarded command even when the substitution's
//! inner is itself benign (`rm -rf $(echo /)`).

use lfguard::builtins::builtin_packs;
use lfguard::engine::Engine;
use lfguard::profile::select_active;

fn default_engine() -> Engine {
    let (packs, warnings) = builtin_packs();
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    Engine::new(select_active(packs, &[]))
}

fn gcloud_engine() -> Engine {
    let (packs, warnings) = builtin_packs();
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    Engine::new(select_active(packs, &["cloud.gcloud".to_string()]))
}

#[test]
fn denies_substitution_as_an_argument_to_an_unguarded_command() {
    let e = default_engine();
    let deny = [
        "echo $(rm -rf /)",
        r#"echo "$(rm -rf /)""#,
        "cat $(rm -rf /)",
        "foo $(rm -rf /) bar",
        "echo `rm -rf /`",
        // a substitution wrapping a grouped subshell is still just raw
        // text to the outer scan — the recursion re-lexes it and the
        // grouping boundary inside resolves normally.
        "echo $( ( rm -rf / ) )",
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
fn denies_substitution_argument_across_gcloud_pack() {
    let e = gcloud_engine();
    let cmd = "ls $(gcloud projects delete p)";
    assert!(
        e.evaluate(cmd).is_deny(),
        "expected DENY for {cmd:?}, got {:?}",
        e.evaluate(cmd)
    );
}

/// Command-position substitution recursion (the previous fix) must keep
/// working unchanged now that argument-position recursion has been added
/// alongside it.
#[test]
fn command_position_substitution_still_denies() {
    let e = default_engine();
    for cmd in ["$(rm -rf /)", "FOO=$(rm -rf /)"] {
        assert!(
            e.evaluate(cmd).is_deny(),
            "expected DENY for {cmd:?}, got {:?}",
            e.evaluate(cmd)
        );
    }
}

/// The guarded-argument fail-safe must keep denying a dynamic target for an
/// already-guarded command even when the substitution's own inner command
/// is benign — this is a different risk (an unknowable target) than "is the
/// inner itself destructive," and the new recursion must not weaken it.
#[test]
fn guarded_argument_fail_safe_still_denies_a_benign_inner() {
    let e = default_engine();
    let cmd = "rm -rf $(echo /)";
    assert!(
        e.evaluate(cmd).is_deny(),
        "expected DENY for {cmd:?}, got {:?}",
        e.evaluate(cmd)
    );
}

#[test]
fn does_not_regress_benign_substitution_arguments() {
    let e = default_engine();
    let allow = [
        r#"echo "$(date)""#,
        "echo $(git rev-parse HEAD)",
        r#"echo "$(uname -a)""#,
        "grep $(cat patterns) file",
        "x=$(date) && echo $x",
        "find / -name $(echo x)",
    ];
    for cmd in allow {
        assert!(
            !e.evaluate(cmd).is_deny(),
            "expected ALLOW for {cmd:?}, got {:?}",
            e.evaluate(cmd)
        );
    }
}

/// Two residuals the design doc previously documented as "not detected" —
/// a substitution consumed by `env`'s own leading-assignment skip, and a
/// substitution concatenated with trailing text in command position — are
/// closed as a side effect of scanning every word in the *original*
/// (pre-unwrap) segment for substitutions rather than only the "pure
/// command position" shape. Documented here as regression guards, not
/// because either was an explicit corpus requirement.
#[test]
fn closes_the_env_assignment_consumption_residual() {
    let e = default_engine();
    let cmd = "env FOO=$(rm -rf /) cmd";
    assert!(
        e.evaluate(cmd).is_deny(),
        "expected DENY for {cmd:?}, got {:?}",
        e.evaluate(cmd)
    );
}

#[test]
fn closes_the_concatenated_command_position_residual() {
    let e = default_engine();
    let cmd = "$(rm -rf /)suffix";
    assert!(
        e.evaluate(cmd).is_deny(),
        "expected DENY for {cmd:?}, got {:?}",
        e.evaluate(cmd)
    );
}

/// No quadratic blowup: many benign substitutions in one segment's
/// arguments must resolve well under the latency budget. Each substitution
/// triggers a bounded recursive re-lex of a short string, not a rescan of
/// the whole line, so this should stay comfortably linear.
#[test]
fn many_substitution_arguments_stay_within_budget() {
    let e = default_engine();
    let mut cmd = String::from("echo");
    for _ in 0..500 {
        cmd.push_str(" $(date)");
    }
    let start = std::time::Instant::now();
    let decision = e.evaluate(&cmd);
    let elapsed = start.elapsed();
    assert!(!decision.is_deny(), "expected ALLOW, got {decision:?}");
    assert!(
        elapsed < std::time::Duration::from_millis(45),
        "500 substitution arguments took {elapsed:?}, expected comfortably under the 50ms budget"
    );
}

/// A pathological chain combining many segments *and* many substitution
/// arguments must still fail safe (timeout => ALLOW) rather than stall,
/// and must never panic.
#[test]
fn many_segments_each_with_a_substitution_argument_stays_within_budget() {
    let e = default_engine();
    let mut cmd = String::new();
    for _ in 0..2000 {
        cmd.push_str("echo $(date) && ");
    }
    cmd.push_str("echo done");
    let start = std::time::Instant::now();
    let decision = e.evaluate(&cmd);
    let elapsed = start.elapsed();
    assert!(!decision.is_deny(), "expected ALLOW, got {decision:?}");
    assert!(
        elapsed < std::time::Duration::from_millis(45),
        "2000-segment substitution chain took {elapsed:?}, expected comfortably under the 50ms budget"
    );
}

// ---- full prior corpus re-confirmed (no regressions) ----------------------

#[test]
fn full_prior_corpus_still_denies() {
    let e = default_engine();
    let deny = [
        "sudo -u root rm -rf /",
        "( rm -rf / )",
        "{ rm -rf /; }",
        "if true; then rm -rf /; fi",
        "command rm -rf /",
        "env rm -rf /",
        "nohup rm -rf /",
        "nice rm -rf /",
        "echo \"a\\\"\" ; rm -rf /",
        r#"rm -rf "/e"tc"#,
        "RM -RF /",
        "rm -rf $'/'",
        "rm -rf $(some-cmd)",
        "rm -rf $(echo /)",
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
        r#"git commit -m "run rm later""#,
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
