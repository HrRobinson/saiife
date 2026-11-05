//! Where the reserved-word and budget work meets Windows developer mode. Neither
//! could test this alone: a word in command position that hides a Windows program
//! name, a budget that runs out in a reader, and a POSIX line on a Windows host.
//!
//! A zero budget takes the budget path without reading a clock, so these verdicts
//! do not depend on the machine's speed.

use std::time::Duration;

use saiifeguard::builtins::Catalog;
use saiifeguard::canon::{PathStyle, PathVars};
use saiifeguard::engine::{AllowTrace, Decision, Engine};
use saiifeguard::payload::Dialects;
use saiifeguard::wintable::Dialect::{Cmd, Posix, PowerShell};

const PS: Dialects = Dialects::One(PowerShell);
const CMD: Dialects = Dialects::One(Cmd);
const BASH: Dialects = Dialects::One(Posix);
const STRICTEST: Dialects = Dialects::Strictest(PowerShell, Posix);

const FULL: Duration = Duration::from_secs(60);

fn windows(budget: Duration) -> Engine {
    let (packs, warnings) = Catalog::builtin_for(PathStyle::Windows).load_active(&[]);
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    Engine::new(packs)
        .with_paths(
            PathVars::new()
                .with_style(PathStyle::Windows)
                .with_var("USERPROFILE", r"C:\Users\a")
                .with_var("LOCALAPPDATA", r"C:\Users\a\AppData\Local")
                .with_var("APPDATA", r"C:\Users\a\AppData\Roaming")
                .with_cwd(r"C:\p"),
        )
        .with_budget(budget)
}

fn posix(budget: Duration) -> Engine {
    let (packs, warnings) = Catalog::builtin_for(PathStyle::Posix).load_active(&[]);
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    Engine::new(packs)
        .with_paths(
            PathVars::new()
                .with_style(PathStyle::Posix)
                .with_var("HOME", "/home/a")
                .with_cwd("/home/a/p"),
        )
        .with_budget(budget)
}

fn timeout() -> Decision {
    Decision::Allow {
        trace: AllowTrace::FailedOpenTimeout,
    }
}

fn assert_denied(e: &Engine, dialects: Dialects, lines: &[String]) {
    let wrong: Vec<String> = lines
        .iter()
        .filter_map(|line| {
            let got = e.evaluate_call(line, dialects);
            (!got.is_deny()).then(|| {
                let shown: String = line.chars().take(80).collect();
                format!("{dialects:?} {shown:?}: {got:?}")
            })
        })
        .collect();
    assert!(wrong.is_empty(), "not denied:\n{}", wrong.join("\n"));
}

fn owned(lines: &[&str]) -> Vec<String> {
    lines.iter().map(ToString::to_string).collect()
}

/// A reserved word, and a word that may vanish, in front of a Windows program
/// name: the name is judged as the program, in every budget.
const HIDDEN_PROGRAM_NAMES: &[&str] = &[
    "! rm.exe -rf /c/Windows",
    "! ! rm.exe -rf /c/Windows",
    "! RM.EXE -rf /c/Windows",
    "! rm.exe::$DATA -rf /c/Windows",
    "! rm. -rf /c/Windows",
    "time ! rm.exe -rf /c/Windows",
    "if rm.exe -rf /c/Windows; then x; fi",
    "while rm.exe -rf /c/Windows; do x; done",
    "until rm.exe -rf /c/Windows; do x; done",
    "coproc rm.exe -rf /c/Windows",
    "for i do rm.exe -rf /c/Windows; done",
    "select i do rm.exe -rf /c/Windows; done",
    "a && ! rm.exe -rf /c/Windows",
    "(! rm.exe -rf /c/Windows)",
    "! sudo rm.exe -rf /c/Windows",
    "! env rm.exe -rf /c/Windows",
    "! FOO=1 rm.exe -rf /c/Windows",
    "if cat.exe .env; then x; fi",
    "! cat.exe .env",
    "while CAT.EXE .env; do x; done",
    "sh -c '! rm.exe -rf /c/Windows'",
    "bash.exe -c '! rm.exe -rf /c/Windows'",
    "$v rm.exe -rf /c/Windows",
    "$v RM.EXE -rf /c/Windows",
    "$v rm.exe::$DATA -rf /c/Windows",
    "$(true) rm.exe -rf /c/Windows",
    "`true` rm.exe -rf /c/Windows",
    "\"$@\" rm.exe -rf /c/Windows",
    "\"${a[@]}\" rm.exe -rf /c/Windows",
    "$! rm.exe -rf /c/Windows",
    "$v $w rm.exe -rf /c/Windows",
    "$v env rm.exe -rf /c/Windows",
    "$v env $w rm.exe -rf /c/Windows",
    "$v sudo.exe rm.exe -rf /c/Windows",
    "! $v rm.exe -rf /c/Windows",
    "if $v rm.exe -rf /c/Windows; then x; fi",
    "$v cat.exe .env",
    "! $v cat.exe .env",
    "$v \"rm.exe\" -rf /c/Windows",
    "$v 'C:\\tools\\rm.exe' -rf /c/Windows",
    "$v /usr/bin/rm.exe -rf /c/Windows",
    "$v > f rm.exe -rf /c/Windows",
    "$v FOO=1 rm.exe -rf /c/Windows",
    "$v env.exe -S 'rm -rf /c/Windows' $w",
    "$v eval.exe 'rm -rf /c/Windows'",
];

#[test]
fn a_word_in_front_does_not_hide_a_windows_program_name() {
    for budget in [FULL, Duration::ZERO] {
        assert_denied(&windows(budget), BASH, &owned(HIDDEN_PROGRAM_NAMES));
    }
}

/// With an unknown shell the POSIX reading is one of the readings.
#[test]
fn nor_when_the_shell_is_not_known() {
    for budget in [FULL, Duration::ZERO] {
        assert_denied(&windows(budget), STRICTEST, &owned(HIDDEN_PROGRAM_NAMES));
    }
}

/// A nested shell behind such a word is still read, in its own dialect.
#[test]
fn a_word_in_front_does_not_hide_a_nested_windows_shell() {
    let lines = owned(&[
        "! powershell -c \"gc .env\"",
        "! powershell.exe -c \"gc .env\"",
        "! POWERSHELL.EXE -c \"gc .env\"",
        "! pwsh -c \"gc .env\"",
        "if powershell -c \"gc .env\"; then x; fi",
        "time ! powershell -c \"gc .env\"",
        "$v powershell -c \"gc .env\"",
        "$v powershell.exe -c \"gc .env\"",
        "$(true) powershell.exe -c \"gc .env\"",
        "! cmd /c \"type .env\"",
        "! cmd.exe /c \"type .env\"",
        "$v cmd.exe /c \"type .env\"",
        "! powershell -c \"Remove-Item -Recurse -Force C:\\Windows\"",
        "! cmd /c \"rd /s /q C:\\Windows\"",
    ]);
    for budget in [FULL, Duration::ZERO] {
        assert_denied(&windows(budget), BASH, &lines);
    }
}

/// A here-document read by a shell is commands, whatever the shell's name ends in.
#[test]
fn a_word_in_front_does_not_hide_a_here_document_shell() {
    let lines = owned(&[
        "! bash.exe <<EOF\nrm -rf /c/Windows\nEOF",
        "if bash.exe <<EOF\nrm -rf /c/Windows\nEOF",
        "! sh.exe <<EOF\ncat .env\nEOF",
        "$v bash.exe <<EOF\nrm -rf /c/Windows\nEOF",
        "bash.exe <<EOF\nrm -rf /c/Windows\nEOF",
    ]);
    for budget in [FULL, Duration::ZERO] {
        assert_denied(&windows(budget), BASH, &lines);
    }
}

/// The lexer drops these words from a segment, and they are what says that text
/// written before a move of `HOME` runs after it.
#[test]
fn a_loop_keeps_running_text_out_of_order_when_its_word_is_stripped() {
    let e = windows(FULL);
    let lines = owned(&[
        "while cat ~/y; do HOME=/x; done",
        "until cat ~/y; do HOME=/x; done",
        "for i do cat ~/y; HOME=/x; done",
        "select i do cat ~/y; HOME=/x; done",
        "for i in a b; do cat ~/y; HOME=/x; done",
        "function f { cat ~/y; }; HOME=/x; f",
        "function f if cat ~/y; then :; fi; HOME=/x; f",
        "f() { cat ~/y; }; HOME=/x; f",
        "! while cat ~/y; do USERPROFILE=/x; done",
        "time while cat ~/y; do HOME=/x; done",
        "\twhile\tcat ~/y; do HOME=/x; done",
        "(while cat ~/y; do HOME=/x; done)",
        "a;while cat ~/y; do HOME=/x; done",
    ]);
    assert_denied(&e, BASH, &lines);
    // A move alone, or a read before it with nothing to run it again, is fine.
    for line in [
        "HOME=/tmp/x cargo test",
        "! HOME=/tmp/x cargo test",
        "if HOME=/tmp/x cargo test; then x; fi",
        "while HOME=/tmp/x cargo test; do x; done",
        "cat ~/y; HOME=/x",
        "echo \"a while\"; cat ~/y; HOME=/x",
        "echo 'for i'; cat ~/y; HOME=/x",
        "\"while\" cat ~/y; HOME=/x",
    ] {
        let got = e.evaluate_call(line, BASH);
        assert!(!got.is_deny(), "{line:?}: {got:?}");
    }
}

/// A read through a moved profile after a reserved word is still that read.
#[test]
fn a_reserved_word_does_not_hide_a_move_of_the_profile() {
    let lines = owned(&[
        "! HOME=/x; cat ~/y",
        "if HOME=/x; then cat ~/y; fi",
        "! export HOME=/x; ! cat ~/y",
        "! HOME=/x bash -c 'cat ~/y'",
    ]);
    assert_denied(&windows(FULL), BASH, &lines);
}

fn padded(part: &str, times: usize, tail: &str) -> String {
    format!("{}{tail}", part.repeat(times))
}

/// Padding and a rule at the end, as an agent's Bash tool would write them.
const POSIX_SHAPES: &[(&str, usize)] = &[
    ("! cd x; ", 240),
    ("if cd x; then ", 240),
    ("while cd x; do ", 240),
    ("$v cd x; ", 240),
    ("cd x; ", 240),
    ("$v > f ", 3000),
    ("$v eval ", 5000),
    ("$(true) ", 20_000),
    ("> f ", 3000),
    ("eval ", 8000),
    ("cat <<A ", 5000),
];

#[test]
fn padding_does_not_hide_a_windows_program_name_with_no_budget() {
    let e = windows(Duration::ZERO);
    let mut lines = vec![padded("! cd x; ", 240, "x; rm.exe -rf /c/Windows")];
    for (part, times) in POSIX_SHAPES {
        for tail in [
            "x; rm.exe -rf /c/Windows",
            "x; ! rm.exe -rf /c/Windows",
            "x; $v rm.exe -rf /c/Windows",
            "x; cat.exe .env",
            "x; ! powershell -c \"gc .env\"",
        ] {
            lines.push(padded(part, *times, tail));
        }
    }
    assert_denied(&e, BASH, &lines);
    assert_denied(&e, STRICTEST, &lines);
}

#[test]
fn the_same_padding_in_full_time_agrees() {
    let e = windows(FULL);
    let lines: Vec<String> = POSIX_SHAPES
        .iter()
        .map(|(part, times)| padded(part, *times, "x; rm.exe -rf /c/Windows"))
        .collect();
    assert_denied(&e, BASH, &lines);
}

/// `;` joins commands in PowerShell, `&` in cmd, where `;` does not.
const PS_SHAPES: &[(&str, usize)] = &[
    ("! cd x; ", 240),
    ("cd x; ", 240),
    ("if (cd x) { y }; ", 240),
    ("> f; ", 1000),
    ("$v; ", 2000),
    ("$(true); ", 2000),
    ("iex 'y'; ", 1000),
];

const CMD_SHAPES: &[(&str, usize)] = &[
    ("! cd x & ", 240),
    ("cd x & ", 240),
    ("if 1==1 cd x & ", 240),
    ("> f & ", 1000),
    ("y & ", 2000),
    ("call y & ", 1000),
];

#[test]
fn padding_does_not_hide_a_rule_from_the_powershell_reader_with_no_budget() {
    let e = windows(Duration::ZERO);
    let mut lines = Vec::new();
    for (part, times) in PS_SHAPES {
        for tail in [
            "x; rm.exe -rf /c/Windows",
            "x; Remove-Item -Recurse -Force C:\\Windows",
            "x; Get-Content .env",
            "x; gc.exe .env",
        ] {
            lines.push(padded(part, *times, tail));
        }
    }
    assert_denied(&e, PS, &lines);
    assert_denied(&e, STRICTEST, &lines);
}

#[test]
fn padding_does_not_hide_a_rule_from_the_cmd_reader_with_no_budget() {
    let e = windows(Duration::ZERO);
    let mut lines = Vec::new();
    for (part, times) in CMD_SHAPES {
        for tail in [
            "x & rm.exe -rf /c/Windows",
            "x & rd /s /q C:\\Windows",
            "x & type .env",
        ] {
            lines.push(padded(part, *times, tail));
        }
    }
    assert_denied(&e, CMD, &lines);
}

/// `cd` resolves through the filesystem, so with no budget it is followed on paper,
/// under the POSIX reading and the readers alike.
#[test]
fn a_cd_is_followed_lexically_on_windows_with_no_budget() {
    let e = windows(Duration::ZERO);
    assert_denied(
        &e,
        BASH,
        &owned(&["cd ~/.ssh; cat id_rsa", "! cd ~/.ssh; ! cat.exe id_rsa"]),
    );
    assert_denied(
        &e,
        PS,
        &owned(&[
            "cd $env:USERPROFILE\\.ssh; gc id_rsa",
            "Set-Location ~\\.ssh; Get-Content id_rsa",
        ]),
    );
    assert_denied(&e, CMD, &owned(&["cd %USERPROFILE%\\.ssh & type id_rsa"]));
}

/// What nothing denies stays the recorded timeout: the caller's fail policy
/// answers it. A false deny here would stop ordinary padding-free work on a slow
/// machine.
#[test]
fn nothing_denied_stays_a_recorded_timeout_in_every_reader() {
    let e = windows(Duration::ZERO);
    for (dialects, line) in [
        (BASH, "ls"),
        (BASH, "! ls"),
        (BASH, "if git status; then ls; fi"),
        (BASH, "$v ls.exe"),
        (PS, "Get-ChildItem"),
        (PS, "Get-Date; git status"),
        (CMD, "dir"),
        (CMD, "git status & dir"),
    ] {
        assert_eq!(e.evaluate_call(line, dialects), timeout(), "{line}");
    }
    for (part, times) in POSIX_SHAPES {
        assert_eq!(
            e.evaluate_call(&padded(part, *times, "x; ls"), BASH),
            timeout(),
            "{part}"
        );
    }
}

/// A bare shell with nothing to read stays allowed (owner ruling). A reserved word
/// the lexer dropped does not make a group or a compound command into that form.
#[test]
fn a_dropped_word_does_not_make_a_group_a_bare_shell() {
    let e = windows(FULL);
    assert_denied(
        &e,
        BASH,
        &owned(&[
            "! ( cmd )",
            "!(cmd)",
            "! { cmd; }",
            "coproc ( cmd )",
            "coproc { cmd; }",
            "function f { cmd; }",
            "if ( bash )",
            "while { powershell; }",
        ]),
    );
    for line in ["cmd", "bash", "powershell", "( cmd )"] {
        let got = e.evaluate_call(line, BASH);
        assert!(!got.is_deny(), "{line}: {got:?}");
    }
}

/// The POSIX lexer strips these words and the readers do not, so `cd` tracking still
/// has to see through them there. `!` is PowerShell's `-not`, which runs the `cd`.
#[test]
fn a_cd_behind_a_condition_word_moves_under_the_powershell_reader() {
    for line in [
        "! cd /; rm -rf *",
        "! time cd /; rm -rf *",
        "if cd /; then :; fi; rm -rf *",
        "until cd /; do :; done; rm -rf *",
    ] {
        let got = posix(FULL).evaluate_call(line, PS);
        assert!(got.is_deny(), "POSIX host {line:?}: {got:?}");
        let got = windows(FULL).evaluate_call(line, PS);
        assert!(got.is_deny(), "Windows host {line:?}: {got:?}");
    }
    for line in ["! cd /; rm -rf *", "! time cd /; rm -rf *"] {
        let got = windows(Duration::ZERO).evaluate_call(line, PS);
        assert!(got.is_deny(), "no budget {line:?}: {got:?}");
    }
}

/// A file a symlink could name is not looked up once the budget is gone: no system
/// call, and a share is the host the command chose.
#[test]
fn the_cheap_pass_asks_no_host_on_windows() {
    let e = windows(Duration::ZERO);
    assert_eq!(
        e.evaluate_call("cat //attacker/share/notes.txt", BASH),
        timeout()
    );
}

const BUDGETS: [Duration; 3] = [Duration::ZERO, saiifeguard::engine::DEFAULT_BUDGET, FULL];

/// `${v:-}` may vanish too. A program name's stream is cut at a `:`, and that must
/// not make the word look like anything else.
#[test]
fn a_parameter_with_an_operator_may_vanish_on_windows() {
    let lines = owned(&[
        "${v:-} rm -rf /",
        "${v:+x} rm -rf /",
        "${v:=} rm -rf /",
        "${v:0} rm -rf /",
        "${v:-} rm.exe -rf /c/Windows",
        "! ${v:-} cat.exe .env",
        "env ${v:-} rm -rf /",
        "${v:-} ${w:+x} rm -rf /",
        "${v:-} powershell -c \"gc .env\"",
    ]);
    for budget in [Duration::ZERO, FULL] {
        assert_denied(&windows(budget), BASH, &lines);
        assert_denied(&windows(budget), STRICTEST, &lines);
    }
    let e = windows(FULL);
    for line in ["${CC:-gcc} -c foo.c", "${EDITOR:-vi} notes.txt"] {
        let got = e.evaluate_call(line, BASH);
        assert!(!got.is_deny(), "{line}: {got:?}");
    }
}

#[test]
fn a_parameter_with_an_operator_may_vanish_on_posix() {
    for budget in [Duration::ZERO, FULL] {
        let e = posix(budget);
        for line in ["${v:-} rm -rf /", "${v:+x} rm -rf /", "env ${v:-} rm -rf /"] {
            let got = e.evaluate(line);
            assert!(got.is_deny(), "{line}: {got:?}");
        }
    }
}

const EMPTIES: &str = "{,,,,,,,,,}{,,,,,,,,,}{,,,,,,,,,}";
const NUMBERS: &str = "{0..9}{0..9}{0..9}";

/// Bash removes the empty words and runs the command, so no number of braces may
/// leave a segment unjudged, wherever the command stands among them.
#[test]
fn braces_on_a_line_do_not_hide_its_command() {
    let mut lines = Vec::new();
    for pad in [EMPTIES, NUMBERS] {
        let braces = format!("{pad} ").repeat(530);
        for head in [
            "rm -rf / ",
            "cat .env ",
            "git reset --hard ",
            "cmd /c x ",
            "powershell -enc x ",
        ] {
            lines.push(format!("{head}{braces}"));
        }
        for tail in ["; rm -rf /", "; cat .env", "; {rm,-rf,/}", "; $(rm -rf /)"] {
            lines.push(format!("{braces}{tail}"));
        }
    }
    for budget in BUDGETS {
        assert_denied(&windows(budget), BASH, &lines);
        assert_denied(&windows(budget), STRICTEST, &lines);
    }
    let posix_lines: Vec<String> = lines
        .into_iter()
        .filter(|l| !l.starts_with("cmd") && !l.starts_with("powershell"))
        .collect();
    for budget in BUDGETS {
        let e = posix(budget);
        for line in &posix_lines {
            let got = e.evaluate(line);
            let shown: String = line.chars().take(40).collect();
            assert!(got.is_deny(), "{budget:?} {shown}: {got:?}");
        }
    }
}

/// Past the line's brace limit the line is denied, naming why. Below it nothing
/// changes: one word too large to expand stays what it was, a note.
#[test]
fn past_the_brace_limit_a_line_is_denied_and_below_it_nothing_changes() {
    let over = format!("echo {}", format!("{NUMBERS} ").repeat(200));
    for got in [
        windows(FULL).evaluate_call(&over, BASH),
        posix(FULL).evaluate(&over),
    ] {
        match got {
            Decision::Deny { reason, .. } => assert!(reason.contains("split"), "{reason}"),
            other => panic!("{other:?}"),
        }
    }
    let one_word = format!("cat {}", "{a,b}".repeat(40));
    assert!(matches!(
        posix(FULL).evaluate(&one_word),
        Decision::Allow {
            trace: AllowTrace::Unjudgeable { .. }
        }
    ));
    let fine = format!("echo {}", "{a,b,c} ".repeat(100));
    assert!(!posix(FULL).evaluate(&fine).is_deny());
    assert!(!windows(FULL).evaluate_call(&fine, BASH).is_deny());
}

/// A `cd` behind a word must not take the slot of a plain `cd` after it, nor push
/// out one before it. Bash runs all of them, and any may fail.
#[test]
fn a_cd_behind_a_word_keeps_the_slots_of_plain_ones() {
    let mut lines = Vec::new();
    for part in [
        "! cd x; ",
        "if cd x; then ",
        "while cd x; do ",
        "until cd x; do ",
        "time ! cd x; ",
        "$v cd x; ",
        "${v:-} cd x; ",
        "$(true) cd x; ",
    ] {
        for times in [20, 240, 2000] {
            let pad = part.repeat(times);
            lines.push(format!("{pad}x; cd ~/.ssh; cat id_rsa"));
            lines.push(format!("{pad}x; cd ~; cd .ssh; cat id_rsa"));
            lines.push(format!("cd ~/.ssh; {pad}x; cat id_rsa"));
        }
    }
    assert_denied(&windows(FULL), BASH, &lines);
    let e = posix(FULL);
    for line in &lines {
        let got = e.evaluate(line);
        let shown: String = line.chars().rev().take(40).collect();
        assert!(got.is_deny(), "...{shown}: {got:?}");
    }
}

/// Each nested line has its own brace limit, so what they make together is charged
/// to the last look: 14,000 of `eval '{1..1000}'` took half a minute without that.
#[test]
fn braces_in_many_nested_lines_are_bounded() {
    for part in ["eval '{1..1000}'; ", "bash -c 'echo {1..1000}'; "] {
        let line = format!("{}x; ls", part.repeat(255 * 1024 / part.len()));
        for got in [
            windows(Duration::ZERO).evaluate_call(&line, BASH),
            posix(Duration::ZERO).evaluate(&line),
        ] {
            match got {
                Decision::Deny { reason, .. } => assert!(reason.contains("split"), "{reason}"),
                other => panic!("{part}: {other:?}"),
            }
        }
    }
}

fn long_cds(n: usize) -> String {
    (0..n)
        .map(|i| format!("cd {}{i}; ", "A".repeat(8000)))
        .collect()
}

/// Long `cd` targets make each nested line dearer. However dear, what a nested
/// line or a later path would be denied for stays denied. Each relative `cd` is
/// tried from every directory so far, so 4 fill the 16 slots, and a later `cd` has
/// none: main leaves that line unjudged too. So `~/.ssh` gets its slot here.
#[test]
fn long_cd_targets_do_not_spend_what_a_later_rule_needs() {
    let mut lines = Vec::new();
    for tail in [
        "$(cat .env)",
        "$(rm -rf /)",
        "bash -c \"rm -rf /\"",
        "eval 'rm -rf /'",
    ] {
        lines.push(format!("{}{}{tail}", long_cds(15), "$(x); ".repeat(1000)));
    }
    for pad in ["$(x); ", "cat a; "] {
        lines.push(format!(
            "{}{}cd ~/.ssh; cat id_rsa",
            long_cds(3),
            pad.repeat(1000)
        ));
        // A directory reached before the padding holds too, past any limit.
        lines.push(format!(
            "cd ~/.ssh; {}{}$(cat id_rsa)",
            long_cds(14),
            pad.repeat(500)
        ));
    }
    for budget in [Duration::ZERO, FULL] {
        assert_denied(&windows(budget), BASH, &lines);
        let e = posix(budget);
        for line in &lines {
            let got = e.evaluate(line);
            let shown: String = line.chars().rev().take(30).collect();
            assert!(got.is_deny(), "{budget:?} ...{shown}: {got:?}");
        }
    }
}

/// The padded shapes on a POSIX host, each ending in a command a rule denies, at no
/// budget, at the default budget and at full time.
#[test]
fn padded_shapes_end_in_a_deny_on_posix() {
    let shapes: &[(&str, usize)] = &[
        ("! cd x; ", 240),
        ("$v > f ", 3000),
        ("$v eval ", 5000),
        ("$(true) ", 20_000),
        ("cd x; ", 240),
        ("> f ", 3000),
        ("eval ", 8000),
        ("cat <<A ", 5000),
    ];
    for budget in [Duration::ZERO, saiifeguard::engine::DEFAULT_BUDGET, FULL] {
        let e = posix(budget);
        let mut wrong = Vec::new();
        for (part, times) in shapes {
            for tail in ["x; rm -rf /", "x; cat .env", "x; ! rm -rf /"] {
                let got = e.evaluate(&padded(part, *times, tail));
                if !got.is_deny() {
                    wrong.push(format!("{budget:?} {part:?} + {tail}: {got:?}"));
                }
            }
        }
        assert!(wrong.is_empty(), "not denied:\n{}", wrong.join("\n"));
    }
}
