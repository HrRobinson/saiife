//! Golden corpus for the command-chaining bypass fix (C1): deny patterns are
//! `^`-anchored, so a destructive command wrapped in a benign chain
//! (`echo hi && rm -rf /`, `true; rm -rf ~`, `ls | rm -rf /`) must still be
//! caught — each top-level segment is judged independently.

use saiifeguard::builtins::builtin_packs;
use saiifeguard::engine::Engine;

fn engine() -> Engine {
    let (packs, warnings) = builtin_packs();
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    // core.filesystem + core.git are default-on; both are exercised below.
    Engine::new(packs).with_budget(TEST_BUDGET)
}

#[test]
fn denies_a_destructive_command_hidden_in_a_chain() {
    let e = engine();
    let deny = [
        "echo hi && rm -rf /",
        "true; rm -rf ~",
        "echo ok || rm -rf /",
        "ls -la | rm -rf /",
        "echo hi\nrm -rf /",
        "cd /tmp && git reset --hard",
        "echo start; git clean -fd",
        "npm test && git push origin main --force",
        // deny in the middle of a longer chain, not just the last segment
        "echo a && rm -rf / && echo b",
        // a `cd` earlier in the chain moves where a relative target lands
        "cd / && rm -rf *",
        "echo hi; cd /\nrm -rf *",
        "cd /tmp && cd / || true; rm -rf *",
    ];
    for cmd in deny {
        assert!(e.evaluate(cmd).is_deny(), "expected DENY for {cmd:?}");
    }
}

#[test]
fn allows_benign_chained_commands() {
    let e = engine();
    let allow = [
        "cd foo && ls",
        "echo hi && echo bye",
        "git status && git log",
        "cd foo; ls -la",
        "make || true",
        "cat a.txt | grep foo",
        "npm install && npm test",
        "cd /tmp && rm -rf ./build",
        "(cd / && ls) && rm -rf ./dist",
        "{ cd / ; } | rm -rf ./x",
    ];
    for cmd in allow {
        assert!(
            !e.evaluate(cmd).is_deny(),
            "expected ALLOW for {cmd:?}, got DENY"
        );
    }
}

#[test]
fn does_not_split_a_separator_inside_quotes() {
    let e = engine();
    // The `;` and `&&` here are inside quoted arguments, not real separators.
    let allow = [
        r#"git commit -m "a; rm -rf /""#,
        r#"echo "safe && rm -rf /""#,
    ];
    for cmd in allow {
        assert!(
            !e.evaluate(cmd).is_deny(),
            "expected ALLOW for {cmd:?} (separator is quoted), got DENY"
        );
    }
}

/// Generous budget so a loaded runner cannot turn a deny into a latency
/// fail-open; the budget path itself is covered by dedicated tests.
const TEST_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);
