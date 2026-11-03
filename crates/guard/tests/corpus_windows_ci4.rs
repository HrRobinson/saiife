//! Plan 19a, fourth Windows CI run: what real PowerShell 5.1 and 7 and real cmd
//! showed about the readers (`scripts/differential-windows.ps1`), pinned on a
//! forced Windows-style engine, which any host runs.

use std::time::Duration;

use saiifeguard::builtins::Catalog;
use saiifeguard::canon::{PathStyle, PathVars};
use saiifeguard::engine::Engine;
use saiifeguard::payload::Dialects;
use saiifeguard::pwsh::{split_for_host, split_segments_noted};
use saiifeguard::wintable::Dialect::{Cmd, PowerShell};

const PS: Dialects = Dialects::One(PowerShell);

fn engine(active: &[String]) -> Engine {
    let vars = PathVars::new()
        .with_style(PathStyle::Windows)
        .with_var("USERPROFILE", r"C:\Users\a")
        .with_var("LOCALAPPDATA", r"C:\Users\a\AppData\Local")
        .with_var("APPDATA", r"C:\Users\a\AppData\Roaming")
        .with_cwd(r"D:\work\app");
    let (packs, warnings) = Catalog::builtin_for(PathStyle::Windows).load_active(active);
    assert!(warnings.is_empty(), "{warnings:?}");
    Engine::new(packs)
        .with_paths(vars)
        .with_budget(Duration::from_secs(5))
}

fn developer() -> Engine {
    engine(&[])
}

fn locked() -> Engine {
    engine(&["core.lock".to_string()])
}

fn words(line: &str, windows: bool) -> Vec<Vec<String>> {
    split_for_host(line, windows)
        .0
        .iter()
        .map(|s| s.iter().map(|w| w.text.clone()).collect())
        .collect()
}

fn denied(e: &Engine, cmds: &[&str]) {
    let bad: Vec<String> = cmds
        .iter()
        .filter(|c| !e.evaluate_call(c, PS).is_deny())
        .map(|c| format!("{c:?}"))
        .collect();
    assert!(bad.is_empty(), "not denied:\n{}", bad.join("\n"));
}

fn allowed(e: &Engine, cmds: &[&str]) {
    let bad: Vec<String> = cmds
        .iter()
        .filter_map(|c| {
            let got = e.evaluate_call(c, PS);
            got.is_deny().then(|| format!("{c:?}: {got:?}"))
        })
        .collect();
    assert!(bad.is_empty(), "denied:\n{}", bad.join("\n"));
}

/// The pairs the job printed, and the ones that change a verdict.
#[test]
fn an_alias_reads_as_the_command_it_resolves_to() {
    for (alias, command) in [
        ("sp", "Set-ItemProperty"),
        ("rp", "Remove-ItemProperty"),
        ("rnp", "Rename-ItemProperty"),
        ("cpp", "Copy-ItemProperty"),
        ("mp", "Move-ItemProperty"),
        ("clp", "Clear-ItemProperty"),
        ("si", "Set-Item"),
        ("cli", "Clear-Item"),
        ("gps", "Get-Process"),
        ("ps", "Get-Process"),
        ("iex", "Invoke-Expression"),
        ("tee", "Tee-Object"),
        ("spsv", "Stop-Service"),
        ("iwmi", "Invoke-WmiMethod"),
        ("icim", "Invoke-CimMethod"),
        ("SP", "Set-ItemProperty"),
    ] {
        assert_eq!(
            words(&format!("{alias} x y"), true),
            words(&format!("{command} x y"), true),
            "{alias}"
        );
        assert_eq!(
            split_for_host(&format!("{alias} x y"), true).1,
            split_for_host(&format!("{command} x y"), true).1,
            "{alias}'s note"
        );
    }
}

/// `tee` is `Tee-Object`, with one file; a second word is an error there, and
/// the real program keeps its reading.
#[test]
fn tee_writes_one_file_and_the_real_tee_all_of_them() {
    assert_eq!(words("tee x y", true), [[">", "x"]]);
    assert_eq!(words("tee.exe x y", true), [[">", "x", ">", "y"]]);
    assert_eq!(words(r"C:\bin\tee x y", true), [[">", "x", ">", "y"]]);
    let e = developer();
    denied(&e, &[r"git status | tee .claude\settings.json"]);
    allowed(&e, &["git status | tee log.txt"]);
}

/// Elsewhere these are real programs: `ps e` prints environments and `tee` writes
/// them all. Nothing a POSIX host reads changes.
#[test]
fn a_posix_host_reads_them_as_programs() {
    for (line, head) in [("ps e", "ps"), ("sort a", "sort"), ("sp x y", "sp")] {
        let (segs, _) = split_segments_noted(line);
        assert_eq!(segs[0][0].text, head, "{line}");
    }
    assert_eq!(words("tee x y", false), [[">", "x", ">", "y"]]);
    // A program by its path or extension, on Windows too.
    assert_eq!(words(r".\ps e", true)[0][0], "ps");
    assert_eq!(words("ps.exe e", true)[0][0], "ps");
}

/// Real bypasses: rules and lists named the full command and missed the alias.
#[test]
fn an_alias_is_judged_as_its_command() {
    denied(&locked(), &["spsv saiifed", "Stop-Service saiifed"]);
    denied(
        &developer(),
        &[
            "iwmi Win32_Process Create calc",
            "Invoke-WmiMethod Win32_Process Create calc",
            "icim Win32_Process Create",
            r"sp HKCU:\Environment -Name SAIIFE_DATA_DIR -Value x",
            r"rp HKCU:\Environment -Name SAIIFE_DATA_DIR",
            r"clp HKCU:\Environment -Name SAIIFE_DATA_DIR",
            r"rnp HKCU:\Environment -Name x -NewName SAIIFE_DATA_DIR",
            r"cpp HKCU:\x -Name SAIIFE_DATA_DIR -Destination HKCU:\Environment",
            r"mp HKCU:\x -Name SAIIFE_DATA_DIR -Destination HKCU:\Environment",
            r"si .claude\settings.json x",
            r"cli .claude\settings.json",
            r"sp .claude\settings.json -Name a -Value b",
            r"iex 'rm -r -fo C:\'",
            "ps | kill",
        ],
    );
    let locked = locked();
    denied(
        &locked,
        &[
            r"sp HKLM:\SOFTWARE\Policies\ClaudeCode -Name a -Value b",
            r"rp HKLM:\SOFTWARE\Policies\ClaudeCode -Name a",
            r"cpp HKLM:\x HKLM:\SOFTWARE\Policies\ClaudeCode",
            r"sp C:\ProgramData\saiife\x -Name a -Value b",
        ],
    );
}

/// What changes for the better: a line that was over-read as the POSIX program.
#[test]
fn everyday_aliases_stay_allowed() {
    allowed(
        &developer(),
        &[
            "ps",
            "ps e",
            "gps",
            "set",
            "echo hi",
            "echo .env",
            "pwd",
            "cls",
            "sleep 1",
            "git status | select -First 3",
            "git status | sort",
            "dir | where Name -eq x",
            "git log | measure",
        ],
    );
}

/// `` `<LF> `` in a word is its character, as the job showed. `` `<CR> `` is too,
/// and the LF after it then ends the statement: a command the reader joined to
/// the word it could not see.
#[test]
fn a_backtick_newline_in_a_word_does_not_hide_the_next_command() {
    assert_eq!(words("cat a`\nb", true), [["cat", "a\nb"]]);
    assert_eq!(words("cat a`\r\nb", true), [vec!["cat", "a\r"], vec!["b"]]);
    assert_eq!(words("cat `\nb", true), [["cat", "b"]]);
    assert_eq!(words("cat `\r\nb", true), [["cat", "b"]]);
    denied(
        &developer(),
        &[
            "echo a`\r\ngit reset --hard",
            "git status`\r\nrm -r -fo C:\\",
        ],
    );
}

#[test]
fn a_doubled_typographic_quote_is_its_second_character() {
    assert_eq!(
        words("cat 'a\u{2018}\u{2019}b'", true),
        [["cat", "a\u{2019}b"]]
    );
    assert_eq!(words("cat 'a''b'", true), [["cat", "a'b"]]);
    assert_eq!(
        words("cat \"a\u{201c}\u{201d}b\"", true),
        [["cat", "a\u{201d}b"]]
    );
    assert_eq!(words("cat \"a\"\"b\"", true), [["cat", "a\"b"]]);
}

/// After the first `--` nothing is a parameter. The table had this right, and it
/// is pinned here because the script's comparison had it wrong.
#[test]
fn after_a_double_dash_a_dashed_word_is_a_file() {
    assert_eq!(
        words("Get-Content -- -Path", true),
        [["cat", "--", "./-Path"]]
    );
    assert_eq!(words("rm -- -Recurse", true), [["rm", "--", "./-Recurse"]]);
    denied(&developer(), &["Get-Content -- .env"]);
}

/// 5.1's AST showed an empty command for the `&` around a block: the script's
/// fault. The body is what is judged.
#[test]
fn a_called_block_is_judged() {
    assert_eq!(
        words("& { Remove-Item -r -fo x }", true),
        [["rm", "-r", "-f", "x"]]
    );
    assert_eq!(words(". { Get-Content y }", true), [["cat", "y"]]);
    denied(
        &developer(),
        &[r"& { Remove-Item -r -fo C:\ }", ". { Get-Content .env }"],
    );
}

/// A word holding `>` is one word to the parser (`a2>f`); read as a redirection
/// it is an over-read, documented in the fixtures. What it must not do is lose a
/// write or a read that a real redirection would be.
#[test]
fn a_greater_than_in_a_word_is_over_read_as_a_redirection() {
    assert_eq!(words("a2>f", true), [["a2", ">", "f"]]);
    denied(
        &developer(),
        &[
            r"a2>.claude\settings.json",
            r"'x'>.claude\settings.json",
            "cat .env>x",
        ],
    );
}

/// `cd\`, `cd..`, `cd~` and `C:` are PowerShell's own functions, and change
/// where the next `rm` lands.
#[test]
fn powershells_cd_functions_move_the_cwd() {
    assert_eq!(words(r"cd\", true), [["cd", r"\"]]);
    assert_eq!(words("cd..", true), [["cd", ".."]]);
    assert_eq!(words("cd~", true), [["cd", "~"]]);
    assert_eq!(words("C:", true), [["cd", "C:"]]);
    // Not on a POSIX host, and not as text.
    assert_eq!(words(r"cd\", false), [[r"cd\"]]);
    assert_eq!(words("'C:'", true), [["C:"]]);
    denied(
        &developer(),
        &[
            r"cd\; rm -r -fo *",
            "cd~; rm -r -fo *",
            "C:; rm -r -fo *",
            r"c:; Remove-Item -Recurse -Force *",
        ],
    );
    allowed(
        &developer(),
        &["cd..", r"cd\", "cd~", "D:", "cd..; git status"],
    );
}

#[test]
fn a_bare_drive_moves_cmds_cwd_too() {
    let e = developer();
    for line in ["C: & del /s /q *", "c: && del /s /q *", "C:\ndel /s /q *"] {
        let got = e.evaluate_call(line, Dialects::One(Cmd));
        assert!(got.is_deny(), "{line:?}: {got:?}");
    }
    let got = e.evaluate_call("D:", Dialects::One(Cmd));
    assert!(!got.is_deny(), "{got:?}");
}
