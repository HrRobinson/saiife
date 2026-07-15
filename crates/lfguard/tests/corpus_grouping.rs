//! Golden corpus for the grouping/keyword, transparent-prefix, and `$'...'`
//! ANSI-C-quoting bypasses closed in this slice:
//!
//! 1. Shell grouping (`(`/`)`/`{`/`}`) and compound-keyword constructs
//!    (`if`/`then`, `for`/`do`, `while`/`do`) previously put the guarded
//!    command somewhere other than argv[0], so no deny rule ever fired.
//! 2. `command`/`env`/`nohup`/`nice`/`stdbuf`/`ionice` transparently wrap a
//!    command, so the wrapper — not the real command — landed at argv[0].
//! 3. `$'...'` ANSI-C quoting (`$'/'`, `$'\x2f'`) resolved to junk arguments
//!    instead of the real, decoded target (`/`).

use lfguard::builtins::builtin_packs;
use lfguard::engine::Engine;
use lfguard::profile::select_active;

fn default_engine() -> Engine {
    let (packs, warnings) = builtin_packs();
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    Engine::new(select_active(packs, &[]))
}

#[test]
fn denies_grouping_keyword_wrapper_and_ansi_c_quoting_bypasses() {
    let e = default_engine();
    let deny = [
        // --- shell grouping & compound-keyword constructs ---
        "( rm -rf / )",
        "(rm -rf /)",
        "{ rm -rf /; }",
        "if true; then rm -rf /; fi",
        "for i in 1; do rm -rf /; done",
        "while true; do rm -rf /; done",
        // --- transparent-prefix wrapping ---
        "command rm -rf /",
        "env rm -rf /",
        "nohup rm -rf /",
        "nice rm -rf /",
        // --- $'...' ANSI-C quoting ---
        "rm -rf $'/'",
        r"rm -rf $'\x2f'",
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
fn allows_the_corresponding_benign_shapes() {
    let e = default_engine();
    let allow = [
        // grouping chars as pure data (quoted) must not be mistaken for a
        // boundary or a trigger
        r#"echo "(a)""#,
        r#"echo "{x}""#,
        // benign commands inside a grouping/compound construct
        "( ls )",
        "{ ls; }",
        "for i in 1; do echo hi; done",
        // wrappers around a benign command
        "command ls",
        "env ls",
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
fn stdbuf_and_ionice_wrappers_are_also_unwrapped() {
    // Not in the adversarial-review corpus verbatim, but explicitly named as
    // "fold in while you're there" wrappers — cover them too.
    let e = default_engine();
    for cmd in ["stdbuf -oL rm -rf /", "ionice -c3 rm -rf /"] {
        assert!(
            e.evaluate(cmd).is_deny(),
            "expected DENY for {cmd:?}, got {:?}",
            e.evaluate(cmd)
        );
    }
}

#[test]
fn wrappers_compose_with_grouping_and_chaining() {
    let e = default_engine();
    // A wrapped command inside a group, and a wrapped command chained after
    // a benign one — both must still be caught at their own segment.
    assert!(e.evaluate("( command rm -rf / )").is_deny());
    assert!(e.evaluate("echo hi && env rm -rf /").is_deny());
}

#[test]
fn full_prior_corpus_spread_still_allows() {
    // Re-confirm none of this slice's changes regressed earlier hardening.
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
fn full_prior_corpus_spread_still_denies() {
    let e = default_engine();
    let deny = [
        "echo hi && rm -rf /",
        "true; rm -rf ~",
        r#"rm -rf "/e"tc"#,
        "RM -RF /",
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
