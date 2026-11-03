//! Golden corpus for shell reserved words in command position: `!`, `if`,
//! `while`, `until`, `coproc`, `time`, `for NAME do` and the like head a
//! command without being one, so the command after them must be judged as
//! if they weren't there, by every rule of the shipped packs. `!` anywhere
//! else (`echo !`, `grep ! x`, `find . ! -name x`) is an argument.

use std::fs;
use std::path::PathBuf;

use saiifeguard::builtins::builtin_packs;
use saiifeguard::canon::PathVars;
use saiifeguard::engine::{Decision, Engine};
use saiifeguard::profile::select_active;

const TEST_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

/// A fake home and project with the files the cases name, and the default
/// profile as `saiife check` builds it.
struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        fs::create_dir_all(root.join("home/app/.saiife")).unwrap();
        fs::write(root.join("home/app/.env"), "x").unwrap();
        fs::write(root.join("home/app/.saiife/config.toml"), "version = 1\n").unwrap();
        Fixture { _dir: dir, root }
    }

    fn engine(&self) -> Engine {
        let (packs, warnings) = builtin_packs();
        assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
        Engine::new(select_active(packs, &[]))
            .with_budget(TEST_BUDGET)
            .with_paths(
                PathVars::new()
                    .with_cwd(self.root.join("home/app"))
                    .with_var("HOME", self.root.join("home"))
                    .with_var("PROJECT", self.root.join("home/app")),
            )
    }
}

fn deny_pack(e: &Engine, cmd: &str) -> Option<String> {
    match e.evaluate(cmd) {
        Decision::Deny { pack, .. } => Some(pack),
        _ => None,
    }
}

/// One command per way a segment gets judged: a shell reader of a secret
/// (path rule), a catastrophic delete (operands), a deny regex, a write
/// through a redirection, a relative path operand and a substitution.
const INNER: &[(&str, &str)] = &[
    ("cat .env", "core.secrets"),
    ("rm -rf /", "core.filesystem"),
    ("saiife init --off", "core.self"),
    ("echo x > .saiife/config.toml", "core.self"),
    ("cat ../app/.env", "core.secrets"),
    ("cat $(echo .env)", "core.secrets"),
];

/// Every `CMD` must be judged as `CMD` alone is.
fn assert_judged_as_inner(templates: &[&str]) {
    let f = Fixture::new();
    let e = f.engine();
    let mut misses = Vec::new();
    for t in templates {
        for (inner, pack) in INNER {
            assert_eq!(deny_pack(&e, inner).as_deref(), Some(*pack), "{inner}");
            let cmd = t.replace("CMD", inner);
            if deny_pack(&e, &cmd).as_deref() != Some(*pack) {
                misses.push(format!("{cmd:?}: {:?}", e.evaluate(&cmd)));
            }
        }
    }
    assert!(misses.is_empty(), "not judged:\n{}", misses.join("\n"));
}

#[test]
fn bang_alone() {
    assert_judged_as_inner(&["! CMD", "!  CMD", "!\tCMD", "! ! CMD", "! ! ! CMD"]);
}

#[test]
fn bang_with_time() {
    assert_judged_as_inner(&[
        "! time CMD",
        "time ! CMD",
        "time -p ! CMD",
        "time -- ! CMD",
        "time -p -- ! CMD",
        "time time ! CMD",
        "! time -p ! CMD",
    ]);
}

#[test]
fn bang_after_a_list_operator() {
    assert_judged_as_inner(&[
        "a && ! CMD",
        "a || ! CMD",
        "a ; ! CMD",
        "a & ! CMD",
        // A syntax error in bash 5.3, so never run there: over-denied.
        "a | ! CMD",
        "a\n! CMD",
    ]);
}

#[test]
fn bang_inside_groups_and_nested_shells() {
    assert_judged_as_inner(&[
        "(! CMD)",
        "( ! CMD )",
        "{ ! CMD; }",
        "! ( CMD )",
        "!(CMD)",
        "! { CMD; }",
        "sh -c '! CMD'",
        "bash -c '! CMD'",
        "! sh -c 'CMD'",
        "eval '! CMD'",
        "eval ! CMD",
        "! eval 'CMD'",
        "x=$(! CMD)",
        "echo `! CMD`",
        "! $(CMD)",
    ]);
}

#[test]
fn bang_before_assignments_and_wrappers() {
    assert_judged_as_inner(&[
        "! FOO=1 CMD",
        "! FOO=1 BAR=2 CMD",
        "! sudo CMD",
        "! env CMD",
        "! command CMD",
        "! nohup CMD",
    ]);
}

#[test]
fn bang_in_compound_commands() {
    assert_judged_as_inner(&[
        "if ! CMD; then x; fi",
        "if a; then ! CMD; fi",
        "if a; then x; elif ! CMD; then x; fi",
        "if a; then x; else ! CMD; fi",
        "while ! CMD; do x; done",
        "while a; do ! CMD; done",
        "until ! CMD; do x; done",
        "for i in 1; do ! CMD; done",
        "case x in x) ! CMD;; esac",
    ]);
}

#[test]
fn compound_heads_do_not_hide_their_condition() {
    assert_judged_as_inner(&[
        "if CMD; then x; fi",
        "if a; then x; elif CMD; then x; fi",
        "while CMD; do x; done",
        "until CMD; do x; done",
        "if if CMD; then a; fi; then x; fi",
        "! if CMD; then x; fi",
        "time if CMD; then x; fi",
        "time while CMD; do x; done",
        "time -p until CMD; do x; done",
        "then CMD",
        "do CMD",
        "else CMD",
        "elif CMD",
    ]);
}

#[test]
fn a_loop_without_a_separator_before_do() {
    assert_judged_as_inner(&[
        "for i do CMD; done",
        "for ((i=0;i<1;i++)) do CMD; done",
        "select i do CMD; done",
        "! for i do CMD; done",
        "time for i do CMD; done",
    ]);
}

#[test]
fn coproc_and_the_already_handled_heads() {
    assert_judged_as_inner(&[
        "coproc CMD",
        // In bash this `!` is a command name, not reserved: over-denied.
        "coproc ! CMD",
        "! coproc CMD",
        "coproc { CMD; }",
        "coproc n { CMD; }",
        "coproc ( CMD )",
        "{ CMD; }",
        "( CMD )",
        "exec CMD",
        "command CMD",
        "command -p CMD",
        "builtin CMD",
        "function f { CMD; }",
        "f() { CMD; }",
        "case x in x) CMD;; esac",
        "for i in 1; do CMD; done",
    ]);
}

#[test]
fn zsh_and_fish_prefixes() {
    // No zsh or fish in the differential test on every machine: these are
    // their documented forms (`noglob cmd`, `- cmd`, `repeat 3 cmd`;
    // `not cmd`, `a; and cmd`, `a; or cmd`, `begin cmd; end`). In bash they
    // are unknown commands, so judging what follows them only over-denies.
    assert_judged_as_inner(&[
        "noglob CMD",
        "nocorrect CMD",
        "- CMD",
        "repeat 3 CMD",
        "! noglob CMD",
        "not CMD",
        "a; and CMD",
        "a; or CMD",
        "begin CMD; end",
        "begin; CMD; end",
    ]);
}

#[test]
fn here_documents_read_by_a_shell_after_a_reserved_word() {
    let f = Fixture::new();
    let e = f.engine();
    for cmd in [
        "! bash <<EOF\nrm -rf /\nEOF",
        "time ! bash <<EOF\nrm -rf /\nEOF",
        "if bash <<EOF\nrm -rf /\nEOF\nthen x; fi",
        "while ! sh <<EOF\nrm -rf /\nEOF\ndo x; done",
        "if a; then bash <<EOF\nrm -rf /\nEOF\nfi",
        "for i in 1; do bash <<EOF\nrm -rf /\nEOF\ndone",
        "coproc bash <<EOF\nrm -rf /\nEOF",
    ] {
        assert_eq!(
            deny_pack(&e, cmd).as_deref(),
            Some("core.filesystem"),
            "{cmd:?}"
        );
    }
    // Still data for a command that does not run it.
    for cmd in [
        "! cat <<EOF\nrm -rf /\nEOF",
        "if cat <<EOF\nrm -rf /\nEOF\nthen x; fi",
    ] {
        assert_eq!(deny_pack(&e, cmd), None, "{cmd:?}");
    }
}

#[test]
fn cd_tracking_sees_through_reserved_words() {
    let f = Fixture::new();
    let e = f.engine();
    for cmd in [
        "! cd / && rm -rf *",
        "! cd /; ! rm -rf *",
        "time ! cd / ; rm -rf *",
        "if cd /; then ! rm -rf *; fi",
        "coproc cd /; rm -rf *",
    ] {
        assert_eq!(
            deny_pack(&e, cmd).as_deref(),
            Some("core.filesystem"),
            "{cmd:?}"
        );
    }
}

#[test]
fn redirections_after_a_bang_are_judged() {
    let f = Fixture::new();
    let e = f.engine();
    for cmd in [
        "! >.saiife/config.toml echo x",
        "! echo x >.saiife/config.toml",
        "! 2>.saiife/config.toml echo x",
    ] {
        assert_eq!(deny_pack(&e, cmd).as_deref(), Some("core.self"), "{cmd:?}");
    }
}

#[test]
fn whole_segment_rules_see_the_command_after_a_bang() {
    // `core.self` keys `PATH=… claude` on the whole segment, assignment
    // included: `!` in front must not move its anchor.
    let f = Fixture::new();
    let e = f.engine();
    let bare = deny_pack(&e, "HOME=/tmp/x claude");
    assert!(bare.is_some());
    for cmd in ["! HOME=/tmp/x claude", "time ! HOME=/tmp/x claude"] {
        assert_eq!(deny_pack(&e, cmd), bare, "{cmd:?}");
    }
}

#[test]
fn a_bang_that_is_not_in_command_position_is_an_argument() {
    let f = Fixture::new();
    let e = f.engine();
    for cmd in [
        "echo !",
        "echo ! rm -rf /",
        "grep ! x",
        "grep ! rm -rf",
        "find . ! -name x",
        "test ! -f x",
        "[ ! -f x ]",
        "[[ ! -f x ]]",
        "echo a ! b",
        "ls !",
    ] {
        assert_eq!(deny_pack(&e, cmd), None, "{cmd:?}");
    }
}

#[test]
fn a_word_that_only_looks_reserved_runs_something_else() {
    // In bash these run a command named `!cat`, `!` or `if`, or an argument
    // list; `rm` and `cat` never run. A non-interactive shell has no history
    // expansion, so `!cat` is a plain word.
    let f = Fixture::new();
    let e = f.engine();
    for cmd in [
        "!cat .env",
        "!rm -rf /",
        "\"!\" rm -rf /",
        "'!' cat .env",
        "\\! rm -rf /",
        "\"if\" rm -rf /",
        "'while' cat .env",
        "FOO=1 ! rm -rf /",
        "env ! rm -rf /",
        "/usr/bin/time ! rm -rf /",
        "echo if rm -rf /",
        "echo then rm -rf /",
        "for i in rm -rf /; do echo; done",
    ] {
        assert_eq!(deny_pack(&e, cmd), None, "{cmd:?}");
    }
}

#[test]
fn benign_commands_after_reserved_words_stay_allowed() {
    let f = Fixture::new();
    let e = f.engine();
    for cmd in [
        "!",
        "! !",
        "if",
        "time",
        "time !",
        "coproc",
        "! ls",
        "a | ! b",
        "! git status",
        "! true",
        "time ! ls",
        "if ! grep x y; then echo z; fi",
        "while read -r l; do echo \"$l\"; done < f",
        "until test -f x; do sleep 1; done",
        "for i do echo $i; done",
        "coproc cat",
        "coproc n { cat; }",
        "time -p make",
        "time -o out.txt make",
    ] {
        assert_eq!(deny_pack(&e, cmd), None, "{cmd:?}");
    }
}
