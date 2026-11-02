//! The cmd reader, and the engine reading a line in a dialect. The packs' Windows
//! rules arrive with Task 7, so `core.filesystem` here is a stand-in holding the
//! W7 shape of its `rm` rule.

use super::*;
use crate::builtins::Catalog;
use crate::canon::{PathStyle, PathVars};
use crate::engine::{AllowTrace, Decision, Engine};
use crate::pack::load_pack_str;
use crate::payload::{classify_for, Dialects, ToolCall};
use crate::wintable::Dialect::{Cmd, Posix, PowerShell};

const STRICTEST: Dialects = Dialects::Strictest(PowerShell, Posix);
const PS: Dialects = Dialects::One(PowerShell);
const CMD: Dialects = Dialects::One(Cmd);
const POSIX: Dialects = Dialects::One(Posix);

fn read(cmd: &str) -> Vec<Vec<String>> {
    split_segments_noted(cmd)
        .0
        .iter()
        .map(|s| s.iter().map(|w| w.text.clone()).collect())
        .collect()
}

fn one(cmd: &str) -> Vec<String> {
    let mut all = read(cmd);
    assert_eq!(all.len(), 1, "{cmd}: {all:?}");
    all.remove(0)
}

fn noted(cmd: &str) -> bool {
    split_segments_noted(cmd).1.is_some()
}

/// Some segment removes `path` recursively.
fn has_rm_r(cmd: &str, path: &str) -> bool {
    read(cmd)
        .iter()
        .any(|s| s[0] == "rm" && s.iter().any(|w| w == "-r") && s.iter().any(|w| w == path))
}

const PACK: &str = r#"
[pack]
id = "core.filesystem"
triggers = ["rm"]

[[deny]]
pattern = '(?i)^rm\s+(?:\S+\s+)*-[a-z]*r[a-z]*\s+(?:\S+\s+)*[a-z]:[\\/]?\*?(?:\s|$)'
reason = "recursive rm of a drive root"

[[deny_path]]
glob = "**/.env"
access = "any"
reason = "secret"

[[deny_path]]
glob = "**/.ssh/id_*"
access = "any"
reason = "secret"
"#;

fn pack() -> crate::pack::Pack {
    let mut warnings = Vec::new();
    let p = load_pack_str("<t>", PACK, &mut warnings).unwrap();
    assert!(warnings.is_empty(), "{warnings:?}");
    p
}

fn windows_vars() -> PathVars {
    PathVars::new()
        .with_style(PathStyle::Windows)
        .with_var("USERPROFILE", r"C:\Users\a")
        .with_cwd(r"C:\p")
}

fn engine() -> Engine {
    Engine::new(vec![pack()]).with_paths(windows_vars())
}

fn default_engine() -> Engine {
    let (packs, _) = Catalog::builtin().load_active(&[]);
    Engine::new(packs).with_paths(windows_vars())
}

fn is_unjudged(d: &Decision) -> bool {
    matches!(
        d,
        Decision::Allow {
            trace: AllowTrace::Unjudgeable { .. }
        }
    )
}

fn is_clean(d: &Decision) -> bool {
    matches!(
        d,
        Decision::Allow {
            trace: AllowTrace::NoMatch | AllowTrace::AllowRule { .. }
        }
    )
}

/// UTF-16LE, base64: what `powershell -enc` takes.
fn encoded(text: &str) -> String {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        out.push(ABC[(n >> 18) as usize & 63] as char);
        out.push(ABC[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            ABC[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            ABC[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

// The brief's tests.

#[test]
fn cmd_rd_and_del_translate() {
    assert_eq!(one(r"rd /s /q C:\"), ["rm", "-r", "-f", r"C:\"]);
    assert_eq!(
        one(r"del /s /q /f C:\Users\a"),
        ["rm", "-r", "-f", "-f", r"C:\Users\a"]
    );
    for spelled in [
        r"RD /S /Q C:\",
        r"rmdir /s /q C:\",
        r"rd/s/q C:\",
        r"rd /s/q C:\",
        r"@rd /s /q C:\",
        r"r^d /s /q C:\",
        r#""rd" /s /q C:\"#,
        r"rd,/s,/q,C:\",
        r"rd;/s;/q;C:\",
        r",rd /s /q C:\",
        r"rd C:\ /s /q",
    ] {
        assert!(has_rm_r(spelled, r"C:\"), "{spelled}: {:?}", read(spelled));
        assert!(!noted(spelled), "{spelled}");
    }
    assert!(engine().evaluate_in(r"rd /s /q C:\", CMD).is_deny());
}

#[test]
fn cmd_caret_and_quotes() {
    assert_eq!(one("echo a^&b"), ["echo", "a&b"]);
    assert_eq!(one(r#"echo "a&b""#), ["echo", "a&b"]);
    assert_eq!(one(r#"echo ^"a b"#), ["echo", "\"a", "b"]);
    // `^` is an ordinary character inside quotes, `'` and `\` everywhere.
    assert_eq!(one(r#"echo "a^b""#), ["echo", "a^b"]);
    assert_eq!(read("echo 'a & rm x'").len(), 2);
    assert_eq!(one(r#"echo "C:\" x"#), ["echo", r"C:\", "x"]);
    // A caret continues the line.
    assert_eq!(one("rd /s ^\n/q C:\\x"), ["rm", "-r", "-f", r"C:\x"]);
    assert!(noted(r#"echo "open"#));
}

#[test]
fn cmd_percent_var_is_substitution() {
    for cmd in [
        "echo %X%",
        "echo a%X%b",
        r#"echo "%X%""#,
        "echo !X!",
        "echo %X:~0%",
        "echo %USERPROFILE:~0%",
        "echo !USERPROFILE!",
        "echo %%X%%",
        "echo %1",
        "echo %*",
        "echo %~dp0",
        "%X% /c y",
    ] {
        let (segs, note) = split_segments_noted(cmd);
        assert!(
            segs[0].iter().any(|w| w.has_substitution),
            "{cmd}: {segs:?}"
        );
        // Its value may hold `&`, so the whole line is not read.
        assert!(note.is_some(), "{cmd}");
    }
    // The variables `winpath` reads stay literal.
    let (segs, note) = split_segments_noted(r"type %USERPROFILE%\.ssh\id_rsa");
    assert_eq!(note, None);
    assert!(!segs[0].iter().any(|w| w.has_substitution));
    // A `%` that is text.
    assert!(!noted("echo 100%"));
    // A `%` that does not close stays read: what follows is still judged.
    assert!(has_rm_r(r"echo %a & rd /s /q C:\", r"C:\"));
    assert!(has_rm_r(r"echo %a b & rd /s /q C:\ %", r"C:\"));
}

#[test]
fn encoded_command_judged_inside() {
    let e = engine();
    let enc = encoded(r"Remove-Item -Recurse -Force C:\");
    for cmd in [
        format!("powershell -enc {enc}"),
        format!("pwsh -EncodedCommand {enc}"),
        format!("powershell.exe -NoProfile -e {enc}"),
    ] {
        for d in [PS, CMD, STRICTEST] {
            let got = e.evaluate_in(&cmd, d);
            let Decision::Deny { pack, .. } = &got else {
                panic!("{cmd}: {got:?}");
            };
            assert_eq!(pack, "core.filesystem");
        }
        // From Git Bash, on a Windows host.
        assert!(e.evaluate_in(&cmd, POSIX).is_deny(), "{cmd}");
    }
}

#[test]
fn bad_encoded_command_is_unresolved() {
    let e = engine();
    // Not the brief's `eval "$x"`: POSIX reads `$x` as text, so that one is a
    // silent `NoMatch`, which a bad `-enc` must never be (W5).
    assert_eq!(
        e.evaluate(r#"eval "$x""#),
        Decision::Allow {
            trace: AllowTrace::NoMatch
        }
    );
    let want = e.evaluate(r#"eval "$(x)""#);
    assert!(is_unjudged(&want), "{want:?}");
    for cmd in ["pwsh -e !!notbase64", "powershell -enc ???"] {
        assert_eq!(e.evaluate_in(cmd, PS), want, "{cmd}");
        assert!(e.evaluate_call(cmd, PS).is_deny(), "{cmd}");
    }
    assert_eq!(e.evaluate_in("powershell -enc ???", CMD), want);
}

#[test]
fn cmd_inside_powershell() {
    let e = engine();
    assert!(e.evaluate_in(r#"cmd /c "rd /s /q C:\""#, PS).is_deny());
    assert!(e.evaluate_in(r"cmd.exe /c rd /s /q C:\", PS).is_deny());
    assert!(e.evaluate_in(r#"cmd /k "del /s /q C:\""#, PS).is_deny());
    assert!(e.evaluate_in(r#"cmd /v:on /c "rd /s C:\""#, PS).is_deny());
}

#[test]
fn iex_literal_judged() {
    let e = engine();
    for cmd in [
        r"iex 'Remove-Item -r -fo C:\'",
        r#"Invoke-Expression "ri -Recurse C:\""#,
    ] {
        assert!(e.evaluate_in(cmd, PS).is_deny(), "{cmd}");
    }
    assert!(is_clean(&e.evaluate_in("iex 'git status'", PS)));
}

#[test]
fn iex_variable_unresolved() {
    let e = engine();
    let d = e.evaluate_in("iex $x", PS);
    assert!(is_unjudged(&d), "{d:?}");
    assert!(e.evaluate_call("iex $x", PS).is_deny());
}

#[test]
fn start_process_argument_list() {
    let e = engine();
    assert!(e
        .evaluate_in(r"Start-Process cmd -ArgumentList '/c rd /s /q C:\'", PS)
        .is_deny());
    assert!(e.evaluate_in(r"start cmd /c rd /s /q C:\", CMD).is_deny());
    assert!(e
        .evaluate_in(r#"start "" /b cmd /c rd /s /q C:\"#, CMD)
        .is_deny());
}

#[test]
fn script_block_judged() {
    let e = engine();
    assert!(e.evaluate_in(r"& { Remove-Item -r -fo C:\ }", PS).is_deny());
    assert!(e.evaluate_in(r". { ri -r C:\ }", PS).is_deny());
    assert!(e
        .evaluate_in(r"Invoke-Command -ScriptBlock { ri -r C:\ }", PS)
        .is_deny());
}

/// One command, read four ways: each dialect sees a different thing.
#[test]
fn strictest_of_both_dialects() {
    let e = engine();
    // PowerShell: a backtick escapes, so this is `Rm`. POSIX: unterminated.
    let ps_only = r"R`m -Recurse -Force C:\";
    assert!(e.evaluate_in(ps_only, PS).is_deny());
    assert!(!e.evaluate_in(ps_only, POSIX).is_deny());
    assert!(e.evaluate_in(ps_only, STRICTEST).is_deny());
    // POSIX: the backslash escapes, so this is `--hard`. PowerShell: it is an
    // ordinary character, and `\--hard` is some other word.
    let git = default_engine();
    let posix_only = r"git reset \--hard";
    assert!(git.evaluate_in(posix_only, POSIX).is_deny());
    assert!(!git.evaluate_in(posix_only, PS).is_deny());
    assert!(git.evaluate_in(posix_only, STRICTEST).is_deny());
    // cmd: the caret goes. Neither of the other two sees `rd`.
    let cmd_only = r"r^d /s /q C:\";
    assert!(e.evaluate_in(cmd_only, CMD).is_deny());
    assert!(!e.evaluate_in(cmd_only, PS).is_deny());
    assert!(!e.evaluate_in(cmd_only, POSIX).is_deny());
    assert!(e.evaluate_in(cmd_only, STRICTEST).is_deny());
    // PowerShell: a quote closes at its end, so this is one quoted word. cmd:
    // `'` is no quote, so `&` runs `rd`.
    let quoted = r"echo 'a & rd /s /q C:\ '";
    assert!(!e.evaluate_in(quoted, PS).is_deny());
    assert!(e.evaluate_in(quoted, CMD).is_deny());
    assert!(e.evaluate_in(quoted, STRICTEST).is_deny());
}

#[test]
fn strictest_ordering() {
    let e = engine();
    // An unread reading is not hidden by a clean one, whichever is first.
    let line = "iex $x";
    for d in [STRICTEST, Dialects::Strictest(Posix, PowerShell)] {
        assert!(is_unjudged(&e.evaluate_in(line, d)), "{d:?}");
    }
    // Equal decisions: the PowerShell one, whichever is first.
    let line = r"cat .env";
    let ps = e.evaluate_in(line, PS);
    assert!(ps.is_deny());
    assert_eq!(e.evaluate_in(line, STRICTEST), ps);
    assert_eq!(
        e.evaluate_in(line, Dialects::Strictest(Posix, PowerShell)),
        ps
    );
    // A rule trace beats no rule.
    const ALLOW: &str = r#"
[pack]
id = "t.allow"
triggers = ["thing"]

[[allow]]
pattern = '^thing a$'
reason = "fine"

[[deny]]
pattern = '^thing '
reason = "no"
"#;
    let mut w = Vec::new();
    let e = Engine::new(vec![load_pack_str("<t>", ALLOW, &mut w).unwrap()]);
    let d = e.evaluate_in("thing a", STRICTEST);
    assert!(
        matches!(
            d,
            Decision::Allow {
                trace: AllowTrace::AllowRule { .. }
            }
        ),
        "{d:?}"
    );
}

#[test]
fn benign_windows_commands_allowed_both_ways() {
    let e = default_engine();
    for cmd in [
        "git status; npm test",
        "Get-ChildItem -Recurse src",
        "dir /s src",
        r"Remove-Item -Recurse .\build",
    ] {
        let d = e.evaluate_in(cmd, STRICTEST);
        assert!(is_clean(&d), "{cmd}: {d:?}");
        assert!(is_clean(&e.evaluate_call(cmd, STRICTEST)), "{cmd}");
        assert!(is_clean(&e.evaluate_call(cmd, PS)), "{cmd}");
    }
}

#[test]
fn posix_engine_unchanged() {
    let e = engine();
    for cmd in [
        "git status",
        "rm -rf /",
        r#"eval "$(x)""#,
        "echo $(date)",
        "`x`",
    ] {
        assert_eq!(e.evaluate(cmd), e.evaluate_in(cmd, POSIX), "{cmd}");
        assert_eq!(e.evaluate(cmd), e.evaluate_call(cmd, POSIX), "{cmd}");
    }
    // POSIX style: `pwsh -c` stays as it was, a program with arguments.
    let posix = Engine::new(vec![pack()]);
    assert!(is_clean(&posix.evaluate(r"pwsh -c 'ri -r C:\'")));
}

// The coordinator's pin: a PowerShell payload never reaches POSIX.

/// `R`m` is `Rm` to PowerShell and an unterminated substitution to POSIX.
#[test]
fn a_powershell_payload_is_judged_as_powershell() {
    let e = Engine::new(vec![pack()]).with_paths(windows_vars());
    let cmd = r"R`m -Recurse -Force C:\";
    let input = serde_json::json!({"tool_name": "PowerShell", "tool_input": {"command": cmd}});
    for windows in [false, true] {
        let Ok(ToolCall::Shell { command, dialects }) =
            classify_for(&input.to_string(), 4096, Some("claude"), windows)
        else {
            panic!("not a shell call");
        };
        assert_eq!(dialects, PS);
        let d = e.evaluate_call(&command, dialects);
        let Decision::Deny { pack, .. } = &d else {
            panic!("{d:?}");
        };
        assert_eq!(pack, "core.filesystem");
    }
    // The POSIX reading of the same text is no deny: this test would not pass
    // on that route.
    assert!(!e.evaluate(cmd).is_deny());
}

/// What the PowerShell reader cannot read is never an allow.
#[test]
fn an_unreadable_powershell_command_is_no_allow() {
    let e = default_engine();
    for cmd in [
        "iex $x",
        "& $x",
        "$x",
        "pwsh -e !!notbase64",
        "pwsh -File x.ps1",
        "[IO.File]::Delete('C:/x')",
        "Set-Alias x Remove-Item",
        "function f { }",
        "'open",
        "{ open",
        "x --% y",
        "wsl rm -rf /x",
        "@p | x",
    ] {
        let d = e.evaluate_call(cmd, PS);
        assert!(d.is_deny(), "{cmd}: {d:?}");
    }
    // Over budget.
    let slow = Engine::new(vec![pack()])
        .with_paths(windows_vars())
        .with_budget(std::time::Duration::ZERO);
    assert!(matches!(
        slow.evaluate_in("a; b", PS),
        Decision::Allow {
            trace: AllowTrace::FailedOpenTimeout
        }
    ));
    assert!(slow.evaluate_call("a; b", PS).is_deny());
    // The PowerShell reading decides for a shell that may be PowerShell; a POSIX
    // reading's note does not block (a backtick is no POSIX mistake here).
    assert!(e.evaluate_call("iex $x", STRICTEST).is_deny());
    assert!(!e.evaluate_call("echo a`nb", STRICTEST).is_deny());
    // POSIX keeps its recorded fail-open.
    assert!(is_unjudged(&e.evaluate_call(r#"eval "$(x)""#, POSIX)));
}

/// Unquoted on a shell tool: POSIX reads `\` as an escape, so only the reader
/// sees a path here. Git Bash really does read it that way, so `One(Posix)` is
/// no misreading and stays as it is.
#[test]
fn unquoted_windows_paths_on_a_shell_tool_are_denied() {
    let e = engine();
    for cmd in [r"cat C:\Users\a\.ssh\id_rsa", r"cat .\$x\id_rsa"] {
        for agent in ["codex", "gemini"] {
            let input = serde_json::json!({
                "tool_name": if agent == "codex" { "Bash" } else { "run_shell_command" },
                "tool_input": { "command": cmd },
            });
            let Ok(ToolCall::Shell { command, dialects }) =
                classify_for(&input.to_string(), 4096, Some(agent), true)
            else {
                panic!("not a shell call");
            };
            assert_eq!(dialects, STRICTEST);
            assert!(e.evaluate_in(&command, dialects).is_deny(), "{cmd}");
            assert!(e.evaluate_call(&command, dialects).is_deny(), "{cmd}");
        }
        assert!(e.evaluate_in(cmd, PS).is_deny(), "{cmd}");
        assert!(!e.evaluate_in(cmd, POSIX).is_deny(), "{cmd}");
    }
}

/// `pwsh` on Linux or macOS: a variable that names a path is no allow either,
/// and one that names no path stays a value.
#[test]
fn a_powershell_variable_path_in_posix_style_is_no_allow() {
    let e = Engine::new(vec![pack()]).with_paths(PathVars::new().with_cwd("/p"));
    for cmd in [
        "Get-Content $x",
        "gc ./$x/id_rsa",
        "cat $x",
        "Copy-Item a $x",
    ] {
        let d = e.evaluate_in(cmd, PS);
        assert!(is_unjudged(&d) || d.is_deny(), "{cmd}: {d:?}");
        assert!(e.evaluate_call(cmd, PS).is_deny(), "{cmd}");
    }
    assert!(is_clean(&e.evaluate_call("echo $x", PS)));
    assert!(is_clean(&e.evaluate_call("Get-Content notes.txt", PS)));
    // POSIX reads the same line as it always did.
    assert!(is_clean(&e.evaluate("cat $x")));
}

/// `$` is an ordinary character to cmd; `%x%` and `!x!` are its live forms.
#[test]
fn cmd_dollars_are_literal() {
    let (segs, note) = split_segments_noted(r"type .\$x\notes.txt & echo $y");
    assert_eq!(note, None);
    for w in segs.iter().flatten() {
        assert!(w.literal_dollars, "{}", w.text);
    }
    let e = engine();
    assert!(is_clean(&e.evaluate_in(r"type .\$x\notes.txt", CMD)));
    assert!(e.evaluate_in(r"type .\$x\.env", CMD).is_deny());
    for live in [r"type .\%x%\id_rsa", r"type .\!x!\id_rsa"] {
        assert!(e.evaluate_call(live, CMD).is_deny(), "{live}");
    }
    // What the reader hands on is read in its own dialect.
    assert!(e
        .evaluate_in(r"powershell -c cat .\$x\id_rsa", CMD)
        .is_deny());
}

// What the Task 4 review named.

#[test]
fn cmd_links_and_drives() {
    for cmd in [
        r"mklink link C:\Users\a\.ssh",
        r"mklink /d link C:\Users\a\.ssh",
        r"mklink /D link C:\Users\a\.ssh",
        r"mklink /j link C:\Users\a\.ssh",
        r"mklink /h link C:\Users\a\.ssh",
        r"mklink/j link C:\Users\a\.ssh",
    ] {
        assert_eq!(one(cmd), ["ln", "-s", r"C:\Users\a\.ssh", "link"], "{cmd}");
        assert!(noted(cmd), "{cmd}");
    }
    assert_eq!(
        one(r"subst Z: C:\Users\a"),
        ["ln", "-s", r"C:\Users\a", "Z:"]
    );
    assert!(noted(r"subst Z: C:\Users\a"));
    assert!(noted("subst /d Z:"));
    assert!(noted(r"net use z: \\localhost\c$"));
}

#[test]
fn cmd_changes_directory() {
    assert_eq!(one(r"cd C:\x"), ["cd", r"C:\x"]);
    assert_eq!(one(r"chdir C:\x"), ["cd", r"C:\x"]);
    assert_eq!(one(r"cd /d C:\x"), ["cd", r"C:\x"]);
    assert_eq!(one(r"cd /D C:\x"), ["cd", r"C:\x"]);
    assert_eq!(one(r"cd/d C:\x"), ["cd", r"C:\x"]);
    assert_eq!(one(r"pushd C:\x"), ["pushd", r"C:\x"]);
    assert_eq!(one("popd"), ["popd"]);
    assert_eq!(one(r"cd\"), ["cd", r"\"]);
    assert_eq!(one(r"cd.."), ["cd", ".."]);
    // No quotes needed: cd takes the rest of the line.
    assert_eq!(one(r"cd /d C:\Program Files"), ["cd", r"C:\Program Files"]);
    let e = engine();
    for cmd in [
        r"cd /d C:\ & rd /s /q *",
        r"chdir C:\ && del /s *",
        r"pushd C:\ & rd /s /q *",
        r"cd /d C:\Windows\.. & rd /s /q .",
    ] {
        assert!(e.evaluate_in(cmd, CMD).is_deny(), "{cmd}");
    }
    // PowerShell tracks the same way, and Git Bash spells it its own way.
    assert!(e.evaluate_in(r"cd C:\; ri -r *", PS).is_deny());
    assert!(e.evaluate_in(r"Set-Location C:\; ri -r *", PS).is_deny());
    assert!(e.evaluate_in("cd /c && rm -rf *", POSIX).is_deny());
    assert!(e.evaluate_in("cd C:/ && rm -rf *", POSIX).is_deny());
    // A drive-relative or unknown target rewrites nothing.
    assert!(!e.evaluate_in(r"cd \x & rd /s /q *", CMD).is_deny());
    assert!(!e.evaluate_in(r"cd C:x & rd /s /q *", CMD).is_deny());
}

#[test]
fn cmd_operators() {
    for (cmd, n) in [
        ("a & b", 2),
        ("a && b", 2),
        ("a || b", 2),
        ("a | b", 2),
        ("a&b&&c||d|e", 5),
        ("a\nb", 2),
        ("(a & b) & c", 3),
        ("((a))", 1),
        ("(a\nb)", 2),
    ] {
        assert_eq!(read(cmd).len(), n, "{cmd}: {:?}", read(cmd));
        assert!(!noted(cmd), "{cmd}");
    }
    assert!(has_rm_r(r"echo x & rd /s /q C:\", r"C:\"));
    assert!(has_rm_r(r"(rd /s /q C:\)", r"C:\"));
    assert!(noted("(a"));
    // `)` is a word's end only inside a block.
    assert!(noted(&"(".repeat(100)));
}

#[test]
fn cmd_redirects() {
    // `nul` names no file, in any spelling.
    for cmd in ["dir 2>nul", "dir >NUL", "dir > nul 2>&1", "2>nul dir"] {
        let seg = one(cmd);
        assert_eq!(seg[0], "ls", "{cmd}");
        assert!(!seg.iter().any(|w| w.eq_ignore_ascii_case("nul")), "{cmd}");
    }
    assert_eq!(one("dir 2>&1"), ["ls", "2>&", "1"]);
    assert_eq!(one("echo x>f"), ["echo", "x", ">", "f"]);
    assert_eq!(one("echo x >> f"), ["echo", "x", ">>", "f"]);
    assert_eq!(one("echo 2>f"), ["echo", "2>", "f"]);
    assert_eq!(one("echo a2>f"), ["echo", "a2", ">", "f"]);
    assert_eq!(one(">f echo x"), ["echo", "x", ">", "f"]);
    assert_eq!(one("sort < f"), ["sort", "<", "f"]);
    assert!(noted("echo x > %X%"));
    assert!(noted("echo x >"));
    let e = engine();
    assert!(e.evaluate_in("echo x > .env", CMD).is_deny());
    assert!(e.evaluate_in("type .env 2>nul", CMD).is_deny());
    assert!(e.evaluate_in("2>nul type .env", CMD).is_deny());
    assert!(e.evaluate_in("sort < .env", CMD).is_deny());
    assert!(!e.evaluate_in("type notes.txt 2>nul", CMD).is_deny());
}

#[test]
fn cmd_if_runs_its_command() {
    for cmd in [
        r"if exist C:\x rd /s /q C:\",
        r"i^f exist C:\x rd /s /q C:\",
        r"if not exist x rd /s /q C:\",
        r"if /i a==a rd /s /q C:\",
        r"if a==a rd /s /q C:\",
        r"if a== a rd /s /q C:\",
        r"if a ==a rd /s /q C:\",
        r"if a == a rd /s /q C:\",
        r#"if "a b"=="a b" rd /s /q C:\"#,
        r#"if "a==b" == "c" rd /s /q C:\"#,
        r"if a equ a rd /s /q C:\",
        r"if /i not 1 lss 2 rd /s /q C:\",
        r"if defined X rd /s /q C:\",
        r"if errorlevel 1 rd /s /q C:\",
        r"if cmdextversion 2 rd /s /q C:\",
        r"if exist x (rd /s /q C:\)",
        r"if exist x (echo y) else rd /s /q C:\",
        r"if exist x (echo y) else (rd /s /q C:\)",
        r"if exist x echo y else rd /s /q C:\",
    ] {
        assert!(has_rm_r(cmd, r"C:\"), "{cmd}: {:?}", read(cmd));
    }
    assert!(!noted(r"if exist x rd /s /q y"));
    // A condition that cannot be read leaves the rest judged, and noted.
    assert!(noted(r"if rd /s /q C:\"));
    assert!(has_rm_r(r"if rd /s /q C:\", r"C:\"));
    assert!(noted("if"));
}

#[test]
fn cmd_for_runs_its_command() {
    for cmd in [
        r"for %i in (a b) do rd /s /q C:\",
        r"for /d %i in (a) do rd /s /q C:\",
        r"for /r C:\ %i in (a) do rd /s /q C:\",
        r"for /l %i in (1,1,2) do (rd /s /q C:\)",
        r#"for /f "delims=" %i in ('dir') do rd /s /q C:\"#,
        r#"for /f "usebackq" %i in (`rd /s /q C:\`) do echo %i"#,
        r"for /f %i in ('rd /s /q C:\') do echo %i",
    ] {
        assert!(has_rm_r(cmd, r"C:\"), "{cmd}: {:?}", read(cmd));
        assert!(noted(cmd), "{cmd}");
    }
    let e = engine();
    // A loop's variable as a guarded command's target.
    assert!(e
        .evaluate_in(r"for %i in (C:\) do rd /s /q %i", CMD)
        .is_deny());
    // `for /f` reads the file.
    assert!(e
        .evaluate_in("for /f %i in (.env) do echo %i", CMD)
        .is_deny());
    // Open or broken: the rest is still read.
    assert!(noted("for %i in (a"));
    assert!(has_rm_r(r"for rd & rd /s C:\", r"C:\"));
}

#[test]
fn cmd_call_and_set() {
    assert!(has_rm_r(r"call rd /s /q C:\", r"C:\"));
    assert!(has_rm_r(r"call call rd /s /q C:\", r"C:\"));
    assert!(noted("call :label"));
    assert!(noted("call %X%"));
    assert!(noted("call echo %%X%%"));
    let words = |cmd: &str| split_segments_noted(cmd).0.remove(0);
    let w = words("set X=a b");
    assert_eq!(w[0].text, "X=a b");
    assert!(w[0].assignment);
    assert_eq!(words(r#"set "X=a&b""#)[0].text, "X=a&b");
    assert!(words("set /a X=1")[0].has_substitution);
    assert!(words("set /p X=q")[0].has_substitution);
    assert_eq!(read(r"set X=a & rd /s C:\").len(), 2);
    // `set` alone only prints.
    assert_eq!(one("set"), ["set"]);
    assert!(!words("set X")[0].assignment);
}

#[test]
fn cmd_variables_change_what_is_protected() {
    const ENV: &str = r#"
[pack]
id = "t.env"
triggers = ["claude"]

[[deny]]
pattern = '^claude\b'
reason = "env"
after_env_change = true
"#;
    let mut w = Vec::new();
    let p = load_pack_str("<t>", ENV, &mut w).unwrap();
    let e = Engine::new(vec![p]).with_paths(windows_vars());
    // Names ignore case on Windows.
    assert!(!e.evaluate_in("claude", CMD).is_deny());
    assert!(e.evaluate_in(r"set path=C:\x & claude", CMD).is_deny());
    assert!(e.evaluate_in(r"set PATH=C:\x & claude", CMD).is_deny());
    assert!(e.evaluate_in(r"$env:path = 'C:\x'; claude", PS).is_deny());
    assert!(e.evaluate_in(r"$env:PATH = 'C:\x'; claude", PS).is_deny());
    assert!(e.evaluate_in(r"$env:PATH += ';C:\x'; claude", PS).is_deny());
    // The profile's variables move what `~` means: not fully judged.
    let d = default_engine().evaluate_in(r"set USERPROFILE=C:\x & echo y", CMD);
    assert!(is_unjudged(&d), "{d:?}");
    let d = default_engine().evaluate_in(r"$env:userprofile = 'C:\x'", PS);
    assert!(is_unjudged(&d), "{d:?}");
}

#[test]
fn cmd_nested_shells() {
    let e = engine();
    for cmd in [
        r#"cmd /c "rd /s /q C:\""#,
        r"cmd /c rd /s /q C:\",
        r"cmd/c rd /s /q C:\",
        r"cmd.exe /c rd /s /q C:\",
        r"cmd /k rd /s /q C:\",
        r"cmd /crd /s /q C:\",
        r"cmd /v:on /c rd /s /q C:\",
        r"cmd /s /c rd /s /q C:\",
        r#"powershell -c "Remove-Item -Recurse C:\""#,
        r"powershell -c ri -r C:\",
        r#"cmd /c "powershell -c ri -r C:\""#,
        r#"bash -c "rm -r C:/""#,
    ] {
        let d = e.evaluate_in(cmd, CMD);
        assert!(d.is_deny(), "{cmd}: {d:?}");
    }
    // Quote stripping inside quote stripping: not read, so never an allow.
    let line = r#"cmd /c "cmd /c "rd /s /q C:\"""#;
    assert!(is_unjudged(&e.evaluate_in(line, CMD)));
    assert!(e.evaluate_call(line, CMD).is_deny());
    assert!(noted("powershell -File x.ps1"));
    assert!(noted("echo rd | cmd"));
    assert!(noted("cmd < f"));
    assert!(noted("powershell -"));
    assert!(noted("cmd /c %X%"));
    assert!(noted("x.bat"));
    assert!(noted("call x.cmd"));
    assert!(noted(r#"forfiles /c "cmd /c rd""#));
    assert!(noted("wsl rm -rf /"));
    assert!(!noted("cmd /q"));
}

/// `cmd /c` reads the raw rest of its line, so a quoted path stays one word.
#[test]
fn cmd_nested_keeps_quoted_words() {
    const FILES: &str = r#"
[pack]
id = "t.files"
triggers = ["rm"]

[[deny]]
pattern = '^rm .*C:\\Program Files'
reason = "no"
"#;
    let mut w = Vec::new();
    let e = Engine::new(vec![load_pack_str("<t>", FILES, &mut w).unwrap()]);
    for (cmd, d) in [
        (r#"cmd /c rd /s /q "C:\Program Files""#, CMD),
        (r#"cmd /c rd /s /q "C:\Program Files""#, PS),
        (r#"cmd /c "rd /s /q "C:\Program Files"""#, PS),
    ] {
        let got = e.evaluate_in(cmd, d);
        assert!(got.is_deny() || is_unjudged(&got), "{cmd} {d:?}: {got:?}");
    }
    assert!(e
        .evaluate_in(r#"cmd /c rd /s /q "C:\Program Files""#, CMD)
        .is_deny());
    // Quote stripping leaves the line in pieces.
    assert!(is_unjudged(&e.evaluate_in(r#"cmd /c "a b" "c d""#, CMD)));
}

#[test]
fn nesting_stops_at_the_limit() {
    let e = engine();
    let mut cmd = "git status".to_string();
    for _ in 0..12 {
        cmd = format!("iex '{}'", cmd.replace('\'', "''"));
    }
    let d = e.evaluate_in(&cmd, PS);
    assert!(is_unjudged(&d), "{d:?}");
    assert!(e.evaluate_call(&cmd, PS).is_deny());
    // Under the limit it is read to the bottom.
    let mut cmd = r"ri -r C:\".to_string();
    for _ in 0..7 {
        cmd = format!("iex '{}'", cmd.replace('\'', "''"));
    }
    assert!(e.evaluate_in(&cmd, PS).is_deny());
}

#[test]
fn cmd_files_and_globs() {
    let e = engine();
    // Wildcards match dotfiles, quoted or not: cmd has no globbing of its own.
    let words = split_segments_noted(r#"type "*""#).0.remove(0);
    assert!(words[1].glob && words[1].glob_dots);
    let words = split_segments_noted("git add *").0.remove(0);
    assert!(words[2].glob && words[2].glob_dots);
    // `copy a+b c` has two sources.
    assert!(e.evaluate_in(r"copy x+.env out", CMD).is_deny());
    assert_eq!(one("copy a+b c"), ["cp", "a", "b", "c"]);
    // `del a,b` has two.
    assert!(e.evaluate_in("del x,.env", CMD).is_deny());
    assert!(e.evaluate_in("del x;.env", CMD).is_deny());
    // An external program keeps its words whole.
    assert_eq!(one("git config a=b,c"), ["git", "config", "a=b,c"]);
    assert_eq!(
        one(r"type %USERPROFILE%\.env"),
        ["cat", r"%USERPROFILE%\.env"]
    );
    assert!(e.evaluate_in(r"type %USERPROFILE%\.env", CMD).is_deny());
    assert!(noted(r#"type "C:\x\.en>""#));
    assert!(!noted(r#"echo "a>b""#));
}

/// Windows style lets `cd` and `rm` know a drive; POSIX style stays exact.
#[test]
fn cd_tracking_stays_posix_on_posix() {
    let e = Engine::new(vec![pack()]);
    assert!(!e.evaluate("cd C:/ && rm -rf *").is_deny());
}

#[test]
fn cmd_never_panics() {
    let alphabet: Vec<char> = "rd /s\\\"'^%!&|<>()=,;@:.*?\n\r\t é\u{a0}cmdforiexelsedo2-~"
        .chars()
        .collect();
    let mut seed = 0x2545_f491_4f6c_dd1d_u64;
    let e = engine();
    for round in 0..10_000 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let len = (seed % 40) as usize;
        let mut s = String::new();
        let mut x = seed;
        for _ in 0..len {
            x = x.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(1);
            s.push(alphabet[(x >> 32) as usize % alphabet.len()]);
        }
        let (segs, _) = split_segments_noted(&s);
        for seg in &segs {
            let _ = nested(seg);
        }
        if round % 50 == 0 {
            let _ = e.evaluate_in(&s, CMD);
            let _ = e.evaluate_call(&s, STRICTEST);
        }
    }
}

#[test]
fn long_lines_stay_linear() {
    let line = "echo a & ".repeat(20_000);
    let start = std::time::Instant::now();
    assert_eq!(read(&line).len(), 20_000);
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
    let line = "%".repeat(50_000);
    let start = std::time::Instant::now();
    let _ = read(&line);
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
}
