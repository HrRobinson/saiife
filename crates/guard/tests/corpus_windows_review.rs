//! Plan 19a, last review: lines the readers and the rules let through, pinned end
//! to end on a forced Windows-style engine under the shipped packs.

use std::time::Duration;

use saiifeguard::builtins::Catalog;
use saiifeguard::canon::{PathStyle, PathVars};
use saiifeguard::engine::{Decision, Engine};
use saiifeguard::payload::Dialects;
use saiifeguard::pwsh::split_for_host;
use saiifeguard::wintable::Dialect::{Cmd, Posix, PowerShell};

const PS: Dialects = Dialects::One(PowerShell);
const CMD: Dialects = Dialects::One(Cmd);
const BASH: Dialects = Dialects::One(Posix);
const STRICTEST: Dialects = Dialects::Strictest(PowerShell, Posix);

fn engine_in(cwd: &str) -> Engine {
    let vars = PathVars::new()
        .with_style(PathStyle::Windows)
        .with_var("USERPROFILE", r"C:\Users\a")
        .with_var("LOCALAPPDATA", r"C:\Users\a\AppData\Local")
        .with_var("APPDATA", r"C:\Users\a\AppData\Roaming")
        .with_cwd(cwd);
    let (packs, warnings) = Catalog::builtin_for(PathStyle::Windows).load_active(&[]);
    assert!(warnings.is_empty(), "{warnings:?}");
    Engine::new(packs)
        .with_paths(vars)
        .with_budget(Duration::from_secs(5))
}

fn engine() -> Engine {
    engine_in(r"D:\work\app")
}

fn words(line: &str, windows: bool) -> Vec<Vec<String>> {
    split_for_host(line, windows)
        .0
        .iter()
        .map(|s| s.iter().map(|w| w.text.clone()).collect())
        .collect()
}

fn denied<S: AsRef<str>>(e: &Engine, how: Dialects, lines: &[S]) {
    let bad: Vec<String> = lines
        .iter()
        .filter_map(|l| {
            let got = e.evaluate_call(l.as_ref(), how);
            (!got.is_deny()).then(|| format!("{:?}: {got:?}", l.as_ref()))
        })
        .collect();
    assert!(bad.is_empty(), "not denied:\n{}", bad.join("\n"));
}

fn not_denied(e: &Engine, how: Dialects, lines: &[&str]) {
    let bad: Vec<String> = lines
        .iter()
        .filter_map(|l| {
            let got = e.evaluate_call(l, how);
            got.is_deny().then(|| format!("{l:?}: {got:?}"))
        })
        .collect();
    assert!(bad.is_empty(), "denied:\n{}", bad.join("\n"));
}

/// How the name is written does not matter to PowerShell: `& 'cd\'`, `. 'cd\'` and
/// `` c`d\ `` run the function `cd\`, as the bare word does.
#[test]
fn a_cd_function_called_by_a_quoted_or_escaped_name_moves_the_cwd() {
    let lines = [
        r"& 'cd\'; rm -r -fo *",
        r"& 'CD\'; rm -r -fo *",
        r#"& "cd\"; rm -r -fo *"#,
        r". 'cd\'; rm -r -fo *",
        r"c`d\; rm -r -fo *",
        r"& ('cd\'); rm -r -fo *",
        "& 'cd~'; rm -r -fo *",
        ". 'cd~'; rm -r -fo *",
        "& 'D:'; rm -r -fo *",
        ". 'C:'; rm -r -fo *",
    ];
    let e = engine();
    denied(&e, PS, &lines);
    denied(&e, STRICTEST, &lines);
    denied(
        &e,
        PS,
        &[
            r#"powershell -c "& 'cd\'; rm -r -fo *""#,
            r#"pwsh -c ". 'cd~'; rm -r -fo *""#,
            r#"powershell -c "c`d\; rm -r -fo *""#,
        ],
    );
    assert_eq!(words(r"& 'cd\'", true), [["cd", r"\"]]);
    assert_eq!(words(r". 'cd\'", true), [["cd", r"\"]]);
    assert_eq!(words(r"c`d\", true), [["cd", r"\"]]);
    assert_eq!(words("& 'D:'", true), [["cd", "D:"]]);
    assert_eq!(words("& 'cd..'", true), [["cd", ".."]]);
}

/// A string is not a call, an argument is not a name, and POSIX hosts have no such
/// functions.
#[test]
fn a_cd_function_name_as_text_stays_text() {
    assert_eq!(words(r"'cd\'", true), [[r"cd\"]]);
    assert_eq!(words("'C:'", true), [["C:"]]);
    assert_eq!(words(r"& 'cd\'", false), [[r"cd\"]]);
    not_denied(
        &engine(),
        PS,
        &[
            r"& 'cd\'",
            r". 'cd\'",
            r"c`d\",
            "& 'D:'",
            r"& 'cd\'; git status",
            r"'cd\'; rm -r -fo x",
            r"Write-Output cd\; rm -r -fo x",
        ],
    );
}

/// Functions are looked up through their scope and their drive: `global:cd\` is
/// `cd\`. `script:`, `local:` and `private:` read the same, and so does `function:`.
#[test]
fn a_cd_function_with_a_scope_prefix_moves_the_cwd() {
    let e = engine();
    for prefix in [
        "global:",
        "script:",
        "local:",
        "private:",
        "function:",
        "GLOBAL:",
        "Function:",
        "function:global:",
        "global:function:",
    ] {
        for (name, place) in [(r"cd\", r"\"), ("cd~", "~"), ("C:", "C:"), ("cd..", "..")] {
            let line = format!("{prefix}{name}");
            assert_eq!(words(&line, true), [["cd", place]], "{line}");
            let quoted = format!("& '{line}'");
            assert_eq!(words(&quoted, true), [["cd", place]], "{quoted}");
            // `cd..` from `D:\work\app` is no root.
            if name != "cd.." {
                denied(
                    &e,
                    PS,
                    &[
                        format!("{line}; rm -r -fo *"),
                        format!("{quoted}; rm -r -fo *"),
                    ],
                );
                denied(&e, STRICTEST, &[format!("{quoted}; rm -r -fo *")]);
            }
        }
    }
    assert_eq!(words(r"global:cd\", false), [[r"global:cd\"]]);
    assert_eq!(words(r"foo:cd\", true), [[r"foo:cd\"]]);
    assert_eq!(words("global:foo x", true)[0], ["global:foo", "x"]);
    not_denied(
        &e,
        PS,
        &[
            r"global:cd\",
            r"global:cd\; git status",
            "global:foo x",
            "script:prompt",
        ],
    );
}

/// Windows folds names, and a profile variable is its `HOME`: Bash sets one as cmd
/// and PowerShell do, so a path spelled with it is not what it says.
#[test]
fn a_profile_variable_set_from_bash_is_not_trusted() {
    let e = engine();
    let lines = [
        "USERPROFILE=/c/Users/a/.ssh; cat $USERPROFILE/id_rsa",
        "HOME=/c/Users/a/.ssh; cat ~/id_rsa",
        "HOME=/c/Users/a/.ssh; cat $HOME/id_rsa",
        "export USERPROFILE=/c/Users/a/.ssh; cat $USERPROFILE/id_rsa",
        "export HOME=/c/Users/a/.ssh; cat ~/id_rsa",
        "export HOME=/c/Users/a/.ssh; cat $HOME/id_rsa",
        "LOCALAPPDATA=/c/Users/a/.ssh; cat $LOCALAPPDATA/id_rsa",
        "export APPDATA=/c/Users/a/.ssh; cat $APPDATA/id_rsa",
        "declare -x HOME=/c/Users/a/.ssh; cat ~/id_rsa",
        "builtin export HOME=/c/Users/a/.ssh; cat ~/id_rsa",
        "(HOME=/c/Users/a/.ssh; cat ~/id_rsa)",
        "{ HOME=/c/Users/a/.ssh; cat ~/id_rsa; }",
        "if true; then HOME=/c/Users/a/.ssh; cat ~/id_rsa; fi",
        "HOME=/c/Users/a/.ssh bash -c 'cat ~/id_rsa'",
        "a=1 USERPROFILE=/c/Users/a/.ssh; cat $USERPROFILE/id_rsa",
        "bash -c 'USERPROFILE=/c/Users/a/.ssh; cat $USERPROFILE/id_rsa'",
        // What already held, and must keep holding: its case is its own.
        "x=/c/Users/a/.ssh; cat $x/id_rsa",
    ];
    denied(&e, BASH, &lines);
    denied(&e, STRICTEST, &lines);
    // Naming one assigns nothing, and other names are left alone.
    not_denied(
        &e,
        BASH,
        &[
            "x=1; echo $x",
            "X=1; path=2; echo $X $path",
            "export FOO=1; npm test",
            "git status",
            "echo $USERPROFILE",
            "cat $USERPROFILE/notes.txt",
            "echo HOME=/tmp",
            "docker run -e HOME=/root img",
            "git log --grep USERPROFILE=x",
        ],
    );
}

/// `cd c:` under Bash on Windows: that drive's own directory, read as the root. A
/// false deny there is the safe side.
#[test]
fn cd_to_a_bare_drive_under_bash_is_its_root() {
    let e = engine_in(r"C:\p");
    denied(
        &e,
        BASH,
        &[
            "cd c: && rm -rf *",
            "cd C:; rm -rf *",
            "cd d: && rm -rf *",
            "cd c: && rm -rf .",
            "pushd c: && rm -rf *",
        ],
    );
    denied(&e, PS, &["cd c:; rm -r -fo *", "C:; rm -r -fo *"]);
    denied(&e, CMD, &["cd /d c: & del /s /q *", "C: & del /s /q *"]);
    not_denied(
        &e,
        BASH,
        &["cd c:", "cd c: && git status", "cd c:x && rm -rf y"],
    );
}

/// saiife reads these for its home and data directories, so moving one moves them.
#[test]
fn moving_the_profile_variables_saiife_reads_is_denied() {
    let e = engine();
    for name in ["LOCALAPPDATA", "USERPROFILE", "localappdata", "UserProfile"] {
        denied(
            &e,
            CMD,
            &[
                format!(r"setx {name} C:\x"),
                format!(r"setx /M {name} C:\x"),
                format!(r"setx.exe {name} C:\x"),
                format!(r"reg add HKCU\Environment /v {name} /d C:\x /f"),
                format!(r"reg delete HKCU\Environment /v {name} /f"),
            ],
        );
        // By the rule, not only because a .NET call cannot be read.
        for line in [
            format!(r"setx {name} C:\x"),
            format!(r"[Environment]::SetEnvironmentVariable('{name}','C:\x','User')"),
            format!(r#"[System.Environment]::SetEnvironmentVariable("{name}", "C:\x")"#),
            format!(r"Set-Item Env:{name} C:\x"),
            format!(r"Set-Item Env:\{name} C:\x"),
            format!(r"si -Path Env:{name} -Value C:\x"),
            format!(r"Set-ItemProperty HKCU:\Environment -Name {name} -Value C:\x"),
            format!(r"New-ItemProperty -Path HKCU:\Environment -Name {name} -Value C:\x"),
        ] {
            let got = e.evaluate_call(&line, PS);
            assert!(
                matches!(&got, Decision::Deny { pack, .. } if pack == "core.self"),
                "{line}: {got:?}"
            );
        }
        denied(
            &e,
            BASH,
            &[
                format!(r"setx {name} 'C:\x'"),
                format!(r"reg.exe add 'HKCU\Environment' /v {name} /d x /f"),
            ],
        );
    }
    // Reading them, and setting anything else, stays allowed.
    not_denied(
        &e,
        CMD,
        &[
            "setx FOO bar",
            "echo %USERPROFILE%",
            "dir %LOCALAPPDATA%",
            r"reg add HKCU\Environment /v FOO /d x /f",
            r"reg query HKCU\Environment /v LOCALAPPDATA",
        ],
    );
    not_denied(
        &e,
        PS,
        &[
            "Set-Item Env:FOO x",
            r"Get-ChildItem $env:USERPROFILE\src",
            "Write-Output $env:LOCALAPPDATA",
        ],
    );
}

/// The WS-Management cmdlets act on a resource URI the reader cannot see.
#[test]
fn wsman_actions_are_opaque() {
    let note = |line: &str| split_for_host(line, true).1;
    for name in [
        "Invoke-WSManAction",
        "Set-WSManInstance",
        "New-WSManInstance",
        "Remove-WSManInstance",
        "invoke-wsmanaction",
    ] {
        assert!(note(&format!("{name} x")).is_some(), "{name}");
        denied(&engine(), PS, &[format!("{name} x")]);
    }
    // Reads are not.
    assert!(note("Get-WSManInstance x").is_none());
    assert!(note("Test-WSMan x").is_none());
}

/// The floors sit just under what CI compared, so a broken reader cannot slip
/// under them.
#[test]
fn the_differential_floors_are_close_to_what_ci_compared() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script = std::fs::read_to_string(root.join("scripts/differential-windows.ps1")).unwrap();
    let floor = |name: &str| -> u32 {
        let line = script
            .lines()
            .find(|l| l.starts_with(name))
            .unwrap_or_else(|| panic!("{name}"));
        line.rsplit('=').next().unwrap().trim().parse().unwrap()
    };
    assert_eq!(floor("$PowerShellFloor"), 80);
    assert_eq!(floor("$CmdFloor"), 58);
    let bench = std::fs::read_to_string(root.join("scripts/bench-check.sh")).unwrap();
    assert!(bench.contains("job uses 130 for the developer hook"));
}
