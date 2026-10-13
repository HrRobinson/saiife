//! Golden corpus for the `core.git` pack: every deny rule must block, and a
//! spread of everyday-safe git commands must NOT (no false positives).

use saiifeguard::builtins::builtin_packs;
use saiifeguard::engine::Engine;

fn engine() -> Engine {
    let (packs, warnings) = builtin_packs();
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    Engine::new(packs)
}

#[test]
fn denies_destructive_git_commands() {
    let deny = [
        "git reset --hard",
        "git reset --hard origin/main",
        "git clean -f",
        "git clean -fd",
        "git clean -xfd",
        "git push origin main --force",
        "git push -f origin main",
        "git branch -D feature",
        "git checkout .",
        "git checkout -- .",
        "/usr/bin/git reset --hard",  // absolute path normalizes
        "bash -c 'git reset --hard'", // inline payload
    ];
    let e = engine();
    for cmd in deny {
        assert!(
            e.evaluate(cmd).is_deny(),
            "expected DENY for {cmd:?}, got ALLOW"
        );
    }
}

#[test]
fn allows_safe_git_commands() {
    let allow = [
        "git status",
        "git log --oneline",
        "git commit -m \"fix things\"",
        "git push",
        "git push --force-with-lease",
        "git push origin main --force-with-lease",
        "git reset --hard HEAD~1", // deliberate reflog-recoverable rewind (carve-out)
        "git reset --soft HEAD~1",
        "git clean -n",         // dry run, no -f
        "git branch -d merged", // lowercase -d is the safe delete
        "git checkout main",
        "git diff",
    ];
    let e = engine();
    for cmd in allow {
        assert!(
            !e.evaluate(cmd).is_deny(),
            "expected ALLOW for {cmd:?}, got DENY"
        );
    }
}
