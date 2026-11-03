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
fn a_substitution_in_command_position_does_not_end_the_segment() {
    let f = Fixture::new();
    let e = f.engine();
    for (cmd, pack) in [
        ("if $(true) $(cat .env); then x; fi", "core.secrets"),
        ("$(true) $(cat .env)", "core.secrets"),
        ("! $(true) $(cat .env)", "core.secrets"),
        ("`true` `cat .env`", "core.secrets"),
        ("! `true` `cat .env`", "core.secrets"),
        ("$(true) $(rm -rf /)", "core.filesystem"),
        ("! $(true) $(rm -rf /)", "core.filesystem"),
        ("$(true) < .env", "core.secrets"),
        ("! $(true) < .env", "core.secrets"),
        ("$(true) > .saiife/config.toml", "core.self"),
        ("if $(true) > .saiife/config.toml; then x; fi", "core.self"),
        // A leading assignment holding the substitution.
        ("X=$(true) $(cat .env)", "core.secrets"),
        ("! X=$(true) $(cat .env)", "core.secrets"),
        ("X=$(true) Y=$(cat .env)", "core.secrets"),
        ("! X=`true` `cat .env`", "core.secrets"),
        ("X=$(true) < .env", "core.secrets"),
        ("X=$(true) > .saiife/config.toml", "core.self"),
        ("env X=$(true) $(cat .env)", "core.secrets"),
        // The substitution itself is still judged.
        ("$(cat .env) x", "core.secrets"),
        ("X=$(cat .env) y", "core.secrets"),
        ("$(rm -rf /)", "core.filesystem"),
        ("X=$(rm -rf /)", "core.filesystem"),
    ] {
        assert_eq!(deny_pack(&e, cmd).as_deref(), Some(pack), "{cmd:?}");
    }
}

#[test]
fn a_word_that_may_expand_to_nothing_does_not_hide_the_next_one() {
    // An unquoted expansion that comes out empty is removed before the
    // command is chosen, so `rm` runs in all of these when it does.
    let f = Fixture::new();
    let e = f.engine();
    for (cmd, pack) in [
        ("$(true) rm -rf /", "core.filesystem"),
        ("`true` rm -rf /", "core.filesystem"),
        ("$x rm -rf /", "core.filesystem"),
        ("${x} rm -rf /", "core.filesystem"),
        ("$x$y rm -rf /", "core.filesystem"),
        ("$(true)$x rm -rf /", "core.filesystem"),
        ("$1 rm -rf /", "core.filesystem"),
        ("$x $y $(true) rm -rf /", "core.filesystem"),
        ("! $x rm -rf /", "core.filesystem"),
        ("X=1 $x rm -rf /", "core.filesystem"),
        ("sudo $x rm -rf /", "core.filesystem"),
        ("$x sudo $y rm -rf /", "core.filesystem"),
        ("$x cat .env", "core.secrets"),
        ("$(true) saiife init --off", "core.self"),
    ] {
        assert_eq!(deny_pack(&e, cmd).as_deref(), Some(pack), "{cmd:?}");
    }
    // Quoted, most stay one empty word, so the command is an empty name; `$x`
    // with literal text beside it is never empty.
    for cmd in [
        "\"$x\" rm -rf /",
        "\"$*\" rm -rf /",
        "\"$(true)\" rm -rf /",
        "\"${x}\" rm -rf /",
        "\"${a[*]}\" rm -rf /",
        "\"\" rm -rf /",
        "a$x rm -rf /",
        "\"a$@\" rm -rf /",
        "$x/bin/tool rm -rf /",
    ] {
        assert_eq!(deny_pack(&e, cmd), None, "{cmd:?}");
    }
}

#[test]
fn other_forms_that_expand_to_nothing() {
    assert_judged_as_inner(&[
        "$! CMD",
        "${x:-${y}} CMD",
        "${x:-${y:-${z}}} CMD",
        "\"$@\" CMD",
        "\"${@}\" CMD",
        "\"${x[@]}\" CMD",
        "\"$@\"\"$@\" CMD",
        "{,} CMD",
        "{,,} CMD",
        "sudo \"$@\" CMD",
        "sudo {,} CMD",
        "$x {,} \"$@\" CMD",
        "! \"$@\" CMD",
    ]);
}

#[test]
fn empties_across_many_wrappers_are_judged_in_one_pass() {
    let f = Fixture::new();
    let e = f.engine();
    for n in [1, 8, 9, 40, 4000] {
        let cmd = format!("{}rm -rf /", "$v env ".repeat(n));
        assert_eq!(
            deny_pack(&e, &cmd).as_deref(),
            Some("core.filesystem"),
            "{n}"
        );
    }
    let cmd = format!("{}{{,}} sudo rm -rf /", "$v sudo ".repeat(9));
    assert_eq!(deny_pack(&e, &cmd).as_deref(), Some("core.filesystem"));
}

#[test]
fn nested_empties_do_not_exhaust_the_budget() {
    // Each level would judge its substitution once per run of empties.
    let mut inner = "true".to_string();
    for _ in 0..8 {
        inner = format!("{}$({inner}) z", "$v env ".repeat(40));
    }
    let cmd = format!("{inner}; rm -rf /");
    assert!(cmd.len() < 3000);
    let f = Fixture::new();
    // About 12 ms in a debug build. An optimized build gets the budget the
    // hook runs with; the exact work is pinned by a count in `engine.rs`.
    let budget = if cfg!(debug_assertions) {
        std::time::Duration::from_millis(200)
    } else {
        saiifeguard::engine::DEFAULT_BUDGET
    };
    let e = f.engine().with_budget(budget);
    for cmd in [
        cmd,
        // A scan of every later word per empty word was quadratic.
        format!("{}x; rm -rf /", "$(true) X=1 ".repeat(800)),
        format!("{}x; rm -rf /", "$v X=1 ".repeat(3000)),
    ] {
        let start = std::time::Instant::now();
        assert_eq!(
            deny_pack(&e, &cmd).as_deref(),
            Some("core.filesystem"),
            "{} bytes",
            cmd.len()
        );
        assert!(start.elapsed() < budget, "{} bytes", cmd.len());
    }
}

#[test]
fn a_function_body_without_braces_is_judged() {
    assert_judged_as_inner(&[
        "function f if CMD; then :; fi; f",
        "function f while CMD; do :; done",
        "function f CMD",
        "function f { CMD; }",
        "! function f if CMD; then :; fi",
    ]);
}

#[test]
fn zsh_short_forms_after_a_test_or_arithmetic() {
    assert_judged_as_inner(&[
        "if [[ x ]] CMD",
        "if (( 1 )) CMD",
        "while [[ x ]] CMD",
        "while (( 1 )) CMD",
        "[[ x ]] CMD",
        "(( 1 )) CMD",
    ]);
    let f = Fixture::new();
    let e = f.engine();
    for cmd in [
        "[[ a < b ]]",
        "if [[ -f x ]]; then echo y; fi",
        "[[ a == b ]] && echo y",
        "(( i++ ))",
        "for ((i=0;i<3;i++)); do echo $i; done",
        "for ((i=0;i<3;i++)) do echo $i; done",
        "echo ]] rm -rf /",
        "echo '[[' x ']]' rm -rf /",
    ] {
        assert_eq!(deny_pack(&e, cmd), None, "{cmd:?}");
    }
}

#[test]
fn ordinary_lines_with_a_leading_expansion_stay_allowed() {
    let f = Fixture::new();
    let e = f.engine();
    for cmd in [
        "$EDITOR notes.txt",
        "$PAGER README.md",
        "$CC -o out main.c",
        "$PYTHON -m pytest",
        "$GIT status",
        "$SHELL -c 'echo hi'",
        "$SUDO apt update",
        "$MAKE clean",
        "$DOCKER ps",
        "$NPM run build",
        "$(which python) script.py",
        "$(which node) --version",
        "$(brew --prefix)/bin/tool --help",
        "$(npm bin)/eslint .",
        "$HOME/bin/tool run",
        "${HOME}/bin/tool run",
        "$x",
        "\"$@\"",
        "\"${a[@]}\"",
        "exec \"$@\"",
        "cmd \"$@\"",
        "\"$@\" --verbose",
        "sudo \"$@\"",
        "command \"$@\"",
        "nohup \"$@\" &",
        "$CMD \"$@\"",
        // Nothing after the list: `env` wraps it, not a dump of the environment.
        "env \"$@\"",
        "env FOO=1 \"$@\"",
        "env \"$@\" > out.txt",
        "env $x",
        "env -i HOME=/home/agent \"${agent_env[@]}\" \"${cmd[@]}\"",
        "sudo -n -u \"$user\" env -C \"$home\" \"$@\" >\"$work/out\" 2>&1 || code=$?",
        "set -- \"$@\" extra",
        "echo {,}",
        "cp f{,.bak}",
        "{,} ls",
        "$! ls",
        "$(date)",
        "`date`",
        "X=$(date)",
        "X=$(date) Y=$(id -u)",
        "X=$(date) make",
        "$(true) > /dev/null",
        "$(true) 2>&1",
        "function greet { echo hi; }",
        "function greet() { echo hi; }; greet",
        "greet() { echo hi; }",
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
