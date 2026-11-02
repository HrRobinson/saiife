//! Plan 19a Task 7, review round 1: what a reader or a rule got wrong, end to
//! end under the shipped packs. A bad rule here is either a bypass or a mass
//! false deny, so each deny has a benign neighbour, and the POSIX verdicts are
//! pinned against a table taken from `main`.

use std::time::Duration;

use saiifeguard::builtins::{builtin_packs, Catalog};
use saiifeguard::canon::{PathStyle, PathVars};
use saiifeguard::engine::{AllowTrace, Decision, Engine};
use saiifeguard::payload::{classify_for, Dialects, ToolCall};
use saiifeguard::wintable::Dialect::{Cmd, Posix, PowerShell};

const BUDGET: Duration = Duration::from_secs(5);

const PS: Dialects = Dialects::One(PowerShell);
const CMD: Dialects = Dialects::One(Cmd);
const POSIX: Dialects = Dialects::One(Posix);
const STRICTEST: Dialects = Dialects::Strictest(PowerShell, Posix);

fn profile_vars() -> PathVars {
    PathVars::new()
        .with_style(PathStyle::Windows)
        .with_var("USERPROFILE", r"C:\Users\a")
        .with_var("LOCALAPPDATA", r"C:\Users\a\AppData\Local")
        .with_var("APPDATA", r"C:\Users\a\AppData\Roaming")
}

fn windows_vars() -> PathVars {
    profile_vars().with_cwd(r"C:\p")
}

fn only(pack: &str) -> Engine {
    let (packs, warnings) = builtin_packs();
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    let p = packs.into_iter().find(|p| p.id == pack).unwrap();
    Engine::new(vec![p])
        .with_paths(windows_vars())
        .with_budget(BUDGET)
}

/// The packs a developer has: the default ones.
fn developer() -> Engine {
    let (packs, warnings) = Catalog::builtin().load_active(&[]);
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    Engine::new(packs)
        .with_paths(windows_vars())
        .with_budget(BUDGET)
}

/// The default packs plus `core.lock`.
fn locked() -> Engine {
    let (packs, warnings) = Catalog::builtin().load_active(&["core.lock".to_string()]);
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    Engine::new(packs)
        .with_paths(windows_vars())
        .with_budget(BUDGET)
}

/// Default packs (`lock`: plus `core.lock`) on a Linux or macOS host.
fn posix_host(lock: bool) -> Engine {
    let extra: &[String] = &["core.lock".to_string()];
    let (packs, warnings) = Catalog::builtin().load_active(if lock { extra } else { &[] });
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    Engine::new(packs).with_budget(BUDGET)
}

fn assert_all(e: &Engine, deny: bool, cases: &[(Dialects, &str)]) {
    let mut wrong = Vec::new();
    for (d, cmd) in cases {
        let got = e.evaluate_call(cmd, *d);
        if got.is_deny() != deny {
            wrong.push(format!("{d:?} {cmd:?}: {got:?}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "want {}:\n{}",
        if deny { "deny" } else { "allow" },
        wrong.join("\n")
    );
}

/// `pack`'s rule `id` denies every case.
fn assert_rule(e: &Engine, pack: &str, id: &str, cases: &[(Dialects, &str)]) {
    let mut wrong = Vec::new();
    for (d, cmd) in cases {
        match e.evaluate_in(cmd, *d) {
            Decision::Deny {
                pack: p, pattern, ..
            } if p == pack && e.rule_id(&p, &pattern) == Some(id) => {}
            got => wrong.push(format!("{d:?} {cmd:?}: {got:?}")),
        }
    }
    assert!(wrong.is_empty(), "want {pack}/{id}:\n{}", wrong.join("\n"));
}

// --- 1. Root spellings -----------------------------------------------------

#[test]
fn every_spelling_of_a_root_is_the_root() {
    let e = only("core.filesystem");
    let mut cases: Vec<(Dialects, &str)> = vec![
        (PS, r"Remove-Item -Recurse \Windows"),
        (PS, r"Remove-Item -Recurse C:\.\Windows"),
        (PS, r"Remove-Item -Recurse C:\Users\a\..\..\Windows"),
        (PS, r"Remove-Item -Recurse C:\Windows."),
        (PS, r"Remove-Item -Recurse -Force \\?\C:\Windows"),
        (PS, r"Remove-Item -Recurse C:\Win*"),
        (PS, r"Remove-Item -LiteralPath C:\PROGRA~2 -Recurse"),
        (PS, r"Remove-Item -Recurse -Force \"),
        (PS, r"Remove-Item -Recurse -Force .."),
        (CMD, r"rd /s /q \Windows"),
        (CMD, r"rd /s /q C:\PROGRA~1"),
        (CMD, r"rd /s /q C:\Users\a\..\..\Windows"),
        (CMD, r"rd /s /q \"),
        (CMD, r"rd /s /q .."),
        (CMD, r"rd /s /q \\localhost\c$\Windows"),
        (POSIX, "rm -rf /cygdrive/c/Windows"),
        (POSIX, "rm -rf /proc/cygdrive/c/Windows"),
        (POSIX, "rm -rf /mnt/c/Windows"),
        (POSIX, "rm -rf /c"),
        (POSIX, "rm -rf /c/"),
        (POSIX, "rm -rf /c/*"),
        (POSIX, "rm -rf /d/Users"),
        (POSIX, "rm -rf /c/PROGRA~1"),
        (POSIX, "rm -rf /c/Users/a/../../Windows"),
        (POSIX, r"rm -rf 'C:\Windows'"),
        (POSIX, "rm C:/Windows -rf"),
        (POSIX, "rm -rf //localhost/c$/Windows"),
        (POSIX, "rm -rf //?/C:/Windows"),
        (PS, "Remove-Item -Recurse //?/C:/Windows"),
        (PS, "Remove-Item -Recurse //127.0.0.1/c$/"),
        (STRICTEST, r"Remove-Item -Recurse \Windows"),
        (STRICTEST, r"rd /s /q \"),
        (STRICTEST, "rm -rf /mnt/c/Windows"),
    ];
    // The user's own profile, however it is spelled.
    cases.extend_from_slice(&[
        (PS, r"Remove-Item -Recurse C:\Users\a"),
        (PS, r"Remove-Item -Recurse c:\USERS\A\*"),
        (CMD, r"rd /s /q C:\Users\a"),
        (POSIX, "rm -rf /c/Users/a"),
    ]);
    assert_rule_any(&e, &cases);
}

/// Denied by `core.filesystem`, by any of its rules.
fn assert_rule_any(e: &Engine, cases: &[(Dialects, &str)]) {
    let mut wrong = Vec::new();
    for (d, cmd) in cases {
        match e.evaluate_in(cmd, *d) {
            Decision::Deny { pack, .. } if pack == "core.filesystem" => {}
            got => wrong.push(format!("{d:?} {cmd:?}: {got:?}")),
        }
    }
    assert!(wrong.is_empty(), "want deny:\n{}", wrong.join("\n"));
}

#[test]
fn a_root_with_no_working_directory_is_still_a_root() {
    let (packs, _) = builtin_packs();
    let p = packs
        .into_iter()
        .find(|p| p.id == "core.filesystem")
        .unwrap();
    let e = Engine::new(vec![p])
        .with_paths(profile_vars())
        .with_budget(BUDGET);
    assert_rule_any(
        &e,
        &[
            (CMD, r"rd /s /q \"),
            (CMD, r"rd /s /q \Windows"),
            (CMD, r"rd /s /q C:\Windows"),
            (CMD, "rd /s /q D:"),
            (PS, r"Remove-Item -Recurse \Windows"),
            (POSIX, "rm -rf /c/Windows"),
        ],
    );
    assert_all(
        &e,
        false,
        &[(CMD, r"rd /s /q build"), (PS, r"Remove-Item -Recurse .\x")],
    );
}

#[test]
fn a_cd_and_a_root_spelling_work_together() {
    let e = only("core.filesystem");
    assert_rule_any(
        &e,
        &[
            (CMD, r"cd /d D:\ & rd /s /q \"),
            (CMD, r"cd \ & rd /s /q Windows"),
            (PS, r"Set-Location C:\Windows; Remove-Item -Recurse ."),
        ],
    );
}

#[test]
fn a_windows_host_keeps_its_ordinary_deletes() {
    let e = developer();
    assert_all(
        &e,
        false,
        &[
            (CMD, "rd /s build"),
            (CMD, "rd /s /q build"),
            (CMD, r"rd /s /q C:\Users\a\proj\target"),
            (CMD, r"rd /s /q C:\p\Windows"),
            (CMD, "rd /s /q Windows"),
            (CMD, "del /s /q *.log"),
            (CMD, "del /s /a:h *.tmp"),
            (CMD, "del /s /p *.tmp"),
            (PS, "del /s /a:h *.tmp"),
            (PS, "del /s /p *.tmp"),
            (STRICTEST, "del /s /a:h *.tmp"),
            (PS, r"Remove-Item -Recurse .\users"),
            (PS, "Remove-Item -Recurse -Filter *.tmp build"),
            (PS, r"Remove-Item -Recurse -Force C:\Windows\Temp\x"),
            (PS, r"Remove-Item -Recurse C:\ProgramData\myapp"),
            (PS, r"Remove-Item C:\Windows"),
            (POSIX, "rm -rf build"),
            (POSIX, "rm -rf ./node_modules"),
            (POSIX, "rm -rf /tmp/x"),
            (POSIX, "rm -rf /c/Users/a/proj/target"),
            (POSIX, "rm -rf /x/build"),
        ],
    );
}

// --- 2. POSIX verdicts ------------------------------------------------------

/// `core.filesystem`'s Windows rules must not reach Linux and macOS. Taken from
/// `main` (the plan's base) with default packs and `core.lock`.
const MAIN_VERDICTS: &[(&str, bool)] = &[
    ("rm -rf /a/*", false),
    ("rm -rf /x/windows", false),
    ("rm -rf /u/users", false),
    ("rm -rf /n/users/*", false),
    ("rm -rf /cygdrive/x", false),
    ("rm -rf c:", false),
    (r"rm -r \", false),
    ("rm -rf /c/*", false),
    ("rm -rf /c/Windows", false),
    ("rm -rf /cygdrive/c", false),
    ("rm -rf /cygdrive/c/Windows", false),
    ("rm -rf /mnt/c/Windows", false),
    ("rm -rf /proc/cygdrive/c/Windows", false),
    ("rm -rf /a/b", false),
    ("rm -rf /a", false),
    ("rm -rf /", true),
    ("rm -rf /etc", true),
    ("rm -rf /tmp/c", false),
    ("rm -rf ./c", false),
    ("rm -rf /c", false),
    ("rm -rf /cache", false),
    ("rm -rf build", false),
    ("rm -rf target", false),
    ("rm -rf ./node_modules", false),
    ("rm -f a b", false),
    (r"rm -rf C:\", false),
    ("rm -rf ~/x", false),
    ("rm -rf ~", true),
    ("kill -9 %1", false),
    ("kill %?vim", false),
    ("kill 4242", false),
    ("pkill s*", true),
    ("pkill node", false),
    ("format --help", false),
    ("git status", false),
    ("cargo test foo::bar", false),
    ("npm run test:unit", false),
    ("docker pull nginx:latest", false),
    (r"reg add HKCU\Environment /v FOO /d x /f", false),
    ("icacls foo", false),
    ("setx FOO bar", false),
    ("wmic process list", false),
    (r#"taskkill /f /fi "imagename eq node.exe""#, false),
    ("bcdedit /enum", false),
    ("sc query", false),
    ("net stop foo", false),
    ("rm hklm", false),
    ("rm -r hkcu", false),
    ("rm -rf hklm/software", false),
    ("echo HKLM", false),
    ("cat hklm", false),
];

#[test]
fn posix_verdicts_match_main() {
    let mut wrong = Vec::new();
    for lock in [false, true] {
        let e = posix_host(lock);
        for (cmd, deny) in MAIN_VERDICTS {
            let got = e.evaluate(cmd);
            if got.is_deny() != *deny {
                wrong.push(format!("lock={lock} {cmd:?}: main {deny}, got {got:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The POSIX verdicts that differ from `main`, each on purpose: the word is not
/// an ordinary command on these systems, or stands for every process.
#[test]
fn posix_verdicts_that_differ_from_main_on_purpose() {
    let e = posix_host(false);
    for cmd in [
        // Canonical Windows spellings: a directory really called `c:`.
        "rm -rf c:/",
        "rm -rf c:/windows",
        "rm -rf c:/*",
        "rm -rf %systemroot%",
        // Parity with `pkill s*`: these name saiife or every process.
        "kill s*",
        "kill *",
        "kill saiife",
        // Windows programs, which do not exist here.
        "format a:",
        "taskkill /im saiife.exe",
        "wmic process where name='saiife.exe' call terminate",
        "bcdedit /set testsigning on",
        "bcdedit /delete {current}",
        r"reg delete HKLM /f",
        "setx SAIIFE_DATA_DIR x",
    ] {
        assert!(e.evaluate(cmd).is_deny(), "{cmd}");
    }
}

// --- 3. Triggers ------------------------------------------------------------

#[test]
fn a_program_named_with_its_extension_passes_the_trigger() {
    let (e, f, s, l) = (
        only("core.secrets"),
        only("core.filesystem"),
        only("core.self"),
        only("core.lock"),
    );
    let denies = |e: &Engine, cases: &[&str]| {
        for cmd in cases {
            for d in [PS, CMD] {
                let got = e.evaluate_in(cmd, d);
                assert!(got.is_deny(), "{d:?} {cmd:?}: {got:?}");
            }
            // Bash takes a backslash for an escape.
            let posix = cmd.replace('\\', r"\\");
            let got = e.evaluate_in(&posix, POSIX);
            assert!(got.is_deny(), "POSIX {posix:?}: {got:?}");
        }
    };
    denies(
        &e,
        &[
            r"reg.exe save HKLM\SAM x",
            r"REG.EXE export HKLM\SECURITY x",
            "cmdkey.exe /list",
            "vaultcmd.exe /list",
        ],
    );
    // Claude's Bash takes the quotes away, and there is no `reg ` in the line.
    let got = e.evaluate_in(r"reg.exe save 'HKLM\SAM' x", POSIX);
    assert!(got.is_deny(), "{got:?}");
    denies(
        &f,
        &[
            "format.com d:",
            "diskpart.exe",
            "cipher.exe /w:C",
            "vssadmin.exe delete shadows /all",
            "wbadmin.exe delete catalog",
            "wmic.exe shadowcopy delete",
            "bcdedit.exe /set x y",
            "reg.exe delete HKLM /f",
        ],
    );
    denies(&s, &["setx.exe SAIIFE_DATA_DIR x"]);
    denies(
        &l,
        &[
            "sc.exe stop saiifed",
            "net.exe stop saiifed",
            "net1.exe stop saiifed",
            r#"net.exe stop "saiife daemon""#,
            r"reg.exe import x.reg",
            r"reg.exe restore HKLM\x y",
            r"reg.exe delete HKLM\SOFTWARE\Policies /f",
            r"icacls.exe C:\ProgramData\saiife /grant Users:F",
            r"takeown.exe /f C:\ProgramData\saiife",
            r"net.exe localgroup saiife-audit bob /add",
        ],
    );
}

// --- 4 and 5. core.lock -----------------------------------------------------

#[test]
fn lock_reads_a_registry_drive_with_or_without_a_slash() {
    let e = only("core.lock");
    assert_rule(
        &e,
        "core.lock",
        "windows-claude-policy",
        &[
            (
                PS,
                r"Set-ItemProperty HKLM:SOFTWARE\Policies\ClaudeCode -Name Settings -Value x",
            ),
            (
                PS,
                r"Remove-Item -Recurse HKLM:SOFTWARE\Policies\ClaudeCode",
            ),
            (
                PS,
                r"Set-ItemProperty Registry::HKLM\SOFTWARE\Policies\ClaudeCode -Name a -Value b",
            ),
            (
                PS,
                r"Set-ItemProperty Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\ClaudeCode -Name a -Value b",
            ),
            (
                PS,
                r"Remove-Item -Recurse Microsoft.PowerShell.Core\Registry::HKLM\SOFTWARE\Policies\ClaudeCode",
            ),
            (
                PS,
                r"Set-ItemProperty hklm:/software/policies/claudecode -Name a -Value b",
            ),
        ],
    );
    assert_rule(
        &e,
        "core.lock",
        "windows-service",
        &[
            (
                PS,
                r"Set-ItemProperty HKLM:SYSTEM\CurrentControlSet\Services\saiifed -Name Start -Value 4",
            ),
            (
                PS,
                r"Set-ItemProperty Registry::HKLM\SYSTEM\CurrentControlSet\Services\saiifed -Name Start -Value 4",
            ),
        ],
    );
}

#[test]
fn lock_denies_a_registry_write_on_a_windows_host() {
    let e = locked();
    assert_all(
        &e,
        true,
        &[
            (
                PS,
                r"Set-ItemProperty Registry::HKLM\SOFTWARE\Foo -Name a -Value b",
            ),
            (PS, r"Set-ItemProperty HKLM:SOFTWARE\Foo -Name a -Value b"),
            (PS, r"Remove-Item HKLM:SOFTWARE\Foo"),
        ],
    );
    assert_all(
        &e,
        false,
        &[
            (PS, r"Get-ItemProperty Registry::HKLM\SOFTWARE\Foo"),
            (PS, r"Get-ItemProperty HKLM:SOFTWARE\Foo"),
        ],
    );
}

#[test]
fn lock_denies_the_parents_of_what_it_protects() {
    let e = only("core.lock");
    assert_rule(
        &e,
        "core.lock",
        "windows-claude-policy",
        &[
            (CMD, r"reg delete HKLM\SOFTWARE\Policies /f"),
            (CMD, r"reg delete HKLM\SOFTWARE /f"),
            (CMD, r"reg delete HKLM /f"),
            (PS, r"reg delete HKLM\SOFTWARE\Wow6432Node\Policies /f"),
            (POSIX, r"reg.exe delete 'HKLM\SOFTWARE\Policies' /f"),
            (PS, r"Remove-Item -Recurse HKLM:\SOFTWARE\Policies"),
            (PS, r"Remove-Item -Recurse HKLM:SOFTWARE"),
            (PS, r"Remove-Item -Recurse Registry::HKLM\SOFTWARE\Policies"),
            (PS, r"Move-Item HKLM:\SOFTWARE\Policies HKLM:\SOFTWARE\Old"),
            (
                CMD,
                r"reg copy HKLM\SOFTWARE\Evil HKLM\SOFTWARE\Policies /s /f",
            ),
        ],
    );
    assert_rule(
        &e,
        "core.lock",
        "windows-service",
        &[
            (CMD, r"reg delete HKLM\SYSTEM\CurrentControlSet\Services /f"),
            (CMD, r"reg delete HKLM\SYSTEM\ControlSet001\Services /f"),
            (CMD, r"reg delete HKLM\SYSTEM\CurrentControlSet /f"),
            (CMD, r"reg delete HKLM\SYSTEM /f"),
            (
                PS,
                r"Remove-Item -Recurse HKLM:\SYSTEM\CurrentControlSet\Services",
            ),
        ],
    );
    assert_rule(
        &e,
        "core.lock",
        "windows-files",
        &[
            (CMD, r"icacls C:\ProgramData /grant Users:F /t"),
            (PS, r"icacls C:\ProgramData /grant Users:F /t"),
            (POSIX, r"icacls 'C:\ProgramData' /grant Users:F /t"),
            (CMD, r"icacls D:\ProgramData\OpenAI /grant Users:F /T"),
            (CMD, r"icacls C:\ /grant Users:F /t"),
            (CMD, r"icacls %ProgramData% /grant Users:F /t"),
            (PS, r"icacls $env:ProgramData /grant Users:F /t"),
            (PS, r"icacls 'C:\Program Files' /reset /t"),
            (CMD, r"icacls C:\PROGRA~1 /grant Users:F /t"),
            (CMD, r"icacls C:\ProgramData /grant Users:(OI)(CI)F"),
            (CMD, r"takeown /f C:\ProgramData /r"),
            (CMD, r"takeown /r /f C:\ProgramData"),
            (CMD, r"takeown /f C:\ /r /d y"),
            (CMD, r"cacls C:\ProgramData /t /e /g Users:F"),
        ],
    );
    assert_all(
        &e,
        false,
        &[
            (CMD, r"reg delete HKLM\SOFTWARE\Foo /f"),
            (CMD, r"reg delete HKLM\SOFTWARE\Policies\Other /f"),
            (
                CMD,
                r"reg delete HKLM\SYSTEM\CurrentControlSet\Services\Other /f",
            ),
            (CMD, r"reg query HKLM\SOFTWARE\Policies"),
            (CMD, r"reg add HKCU\Software\X /v a /d 1"),
            (CMD, r"reg delete HKCU\Software\X /f"),
            (CMD, r"icacls C:\ProgramData\myapp /grant Users:F /t"),
            (CMD, r"icacls C:\Users\a\proj /grant Users:F /t"),
            (CMD, r"icacls C:\ProgramData /grant Users:F"),
            (CMD, r"takeown /f C:\Users\a\proj /r"),
        ],
    );
}

#[test]
fn listing_acls_is_no_change_of_acls() {
    let e = only("core.lock");
    assert_all(
        &e,
        false,
        &[
            (CMD, r"icacls C:\ProgramData\saiife"),
            (PS, r"icacls C:\ProgramData\saiife"),
            (POSIX, r"icacls 'C:\ProgramData\saiife'"),
            (CMD, r"icacls C:\ProgramData\saiife /t /c /q"),
            (CMD, r"icacls C:\ProgramData\saiife /l"),
            (CMD, r#"icacls "C:\Program Files\ClaudeCode" /t /c"#),
        ],
    );
    assert_all(
        &e,
        true,
        &[
            (CMD, r"icacls C:\ProgramData\saiife /grant Users:F"),
            (CMD, r"icacls C:\ProgramData\saiife /t /grant Users:F"),
            (CMD, r"icacls C:\ProgramData\saiife /reset"),
            (CMD, r"icacls C:\ProgramData\saiife /inheritance:r"),
            (CMD, r"icacls C:\ProgramData\saiife /setowner bob"),
            (CMD, r"icacls C:\ProgramData\saiife /restore x"),
            (CMD, r"icacls C:\ProgramData\saiife Users:F /t"),
            (
                CMD,
                r"icacls C:\ProgramData\saiife /t /c /q & del C:\ProgramData\saiife\x",
            ),
        ],
    );
}

// --- 6. Moving the data directory -------------------------------------------

#[test]
fn every_way_to_move_the_data_dir_for_later_programs() {
    let e = only("core.self");
    assert_rule(
        &e,
        "core.self",
        "windows-data-dir",
        &[
            (CMD, r"reg add HKCU\Environment /v SAIIFE_DATA_DIR /d x /f"),
            (PS, r"reg add HKCU\Environment /v SAIIFE_AUDIT_DIR /d x /f"),
            (
                POSIX,
                r"reg add 'HKCU\Environment' /v SAIIFE_DATA_DIR /d x /f",
            ),
            (
                POSIX,
                r"reg.exe add 'HKCU\Environment' /f /v Saiife_Data_Dir /d x",
            ),
            (
                CMD,
                r#"reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v SAIIFE_DATA_DIR /d x"#,
            ),
            (CMD, r"reg delete HKCU\Environment /v SAIIFE_DATA_DIR /f"),
            (
                PS,
                "[Environment]::SetEnvironmentVariable('SAIIFE_DATA_DIR','x','User')",
            ),
            (
                PS,
                r#"[System.Environment]::SetEnvironmentVariable("saiife_audit_dir", "x", "Machine")"#,
            ),
            (
                PS,
                r"Set-ItemProperty HKCU:\Environment -Name SAIIFE_DATA_DIR -Value x",
            ),
            (
                PS,
                r"New-ItemProperty -Path HKCU:\Environment -Name SAIIFE_DATA_DIR -Value x",
            ),
            (CMD, "setx SAIIFE_DATA_DIR x"),
        ],
    );
    // Read as what they are, `$env:x = y`: the assignment rule of the same pack.
    assert_all(
        &e,
        true,
        &[
            (PS, "Set-Item Env:SAIIFE_DATA_DIR x"),
            (PS, r"Set-Item Env:\SAIIFE_DATA_DIR x"),
            (PS, "si -Path Env:SAIIFE_AUDIT_DIR -Value x"),
        ],
    );
    assert_all(
        &e,
        false,
        &[
            (CMD, r"reg add HKCU\Environment /v FOO /d x /f"),
            (CMD, r"reg query HKCU\Environment /v SAIIFE_DATA_DIR"),
            (PS, "Set-Item Env:FOO x"),
            (CMD, "setx FOO bar"),
        ],
    );
    // A .NET call is opaque to a hook, but this rule is about the setter.
    let got = e.evaluate_in(
        "[Environment]::GetEnvironmentVariable('SAIIFE_DATA_DIR')",
        PS,
    );
    assert!(!got.is_deny(), "{got:?}");
}

// --- 7. Provider drives -----------------------------------------------------

#[test]
fn provider_drives_are_judged_by_what_is_done_to_them() {
    let e = developer();
    assert_all(
        &e,
        false,
        &[
            // Reads.
            (PS, r"Get-ItemProperty HKCU:\Software\Foo"),
            (PS, r"Test-Path HKCU:\Software\Foo"),
            (PS, r"Get-ChildItem HKCU:\"),
            (PS, r"Get-ItemProperty HKCU:Software\Foo"),
            (PS, r"Get-ItemProperty HKLM:\SOFTWARE\Foo"),
            (PS, r"Test-Path HKLM:\SOFTWARE\Foo"),
            (
                PS,
                r"Get-ItemProperty Registry::HKEY_CURRENT_USER\Software\Foo",
            ),
            (PS, r"Get-ChildItem Cert:\LocalMachine\My"),
            (PS, r"Get-ChildItem Env:"),
            (PS, r"Get-ChildItem Env:\"),
            (PS, "Get-Content Env:FOO"),
            (PS, "Test-Path Env:SAIIFE_DATA_DIR"),
            // HKCU writes.
            (PS, r"Set-ItemProperty HKCU:\Software\Foo -Name a -Value 1"),
            (
                PS,
                r"Set-ItemProperty -Path HKCU:\Software\Foo -Name a -Value 1",
            ),
            (PS, r"New-ItemProperty HKCU:\Software\Foo -Name a -Value 1"),
            (PS, r"Remove-ItemProperty HKCU:\Software\Foo -Name a"),
            (PS, r"New-Item HKCU:\Software\Foo"),
            (PS, r"Remove-Item -Recurse HKCU:\Software\Foo"),
            (PS, r"Set-Item HKCU:\Software\Foo x"),
            (PS, r"sp HKCU:\Software\Foo a 1"),
            // Env writes.
            (PS, "Set-Item Env:FOO x"),
            (PS, "Remove-Item Env:FOO"),
            (PS, "Clear-Item Env:FOO"),
        ],
    );
    assert_all(
        &e,
        true,
        &[
            // HKCU's Environment is what later programs start with.
            (PS, r"Set-ItemProperty HKCU:\Environment -Name FOO -Value 1"),
            (PS, r"Set-ItemProperty hkcu:environment -Name FOO -Value 1"),
            (PS, r"Remove-Item -Recurse HKCU:\Environment"),
            (
                PS,
                r"Set-ItemProperty Registry::HKEY_CURRENT_USER\Environment -Name a -Value 1",
            ),
            // HKLM writes, by a command the table knows or not.
            (PS, r"Set-ItemProperty HKLM:\SOFTWARE\Foo -Name a -Value 1"),
            (
                PS,
                r"Set-ItemProperty -Force HKLM:\SOFTWARE\Foo -Name a -Value 1",
            ),
            (
                PS,
                r"Set-ItemProperty -Name a -Value 1 -Path:HKLM:\SOFTWARE\Foo",
            ),
            (PS, r"New-ItemProperty HKLM:\SOFTWARE\Foo -Name a -Value 1"),
            (PS, r"Remove-ItemProperty HKLM:\SOFTWARE\Foo -Name a"),
            (PS, r"New-Item HKLM:\SOFTWARE\Foo"),
            (PS, r"Remove-Item -Recurse HKLM:\SOFTWARE\Foo"),
            (PS, r"Set-Item HKLM:\SOFTWARE\Foo x"),
            (PS, r"sp HKLM:\SOFTWARE\Foo a 1"),
            // The hives that hold secrets, read too.
            (PS, r"Get-ChildItem HKLM:\SAM"),
            (PS, r"Get-ItemProperty HKLM:\SECURITY\Policy"),
            (PS, r"Get-ItemProperty HKLM:SAM\x"),
            (PS, r"Get-ItemProperty Registry::HKLM\SAM\x"),
            (PS, r"Get-Content HKLM:\SAM\x"),
            // Certificate store writes.
            (PS, r"Remove-Item Cert:\LocalMachine\Root\ABC"),
            (PS, r"Set-Content Cert:\x y"),
            (
                PS,
                r"Import-Certificate -FilePath x.cer -CertStoreLocation Cert:\LocalMachine\Root",
            ),
            // SAIIFE_* of the environment, wildcards that can reach it.
            (PS, "Remove-Item Env:SAIIFE_DATA_DIR"),
            (PS, "Set-Item Env:SAIIFE_OTHER x"),
            (PS, "Remove-Item Env:*"),
            (PS, "Remove-Item Env:SAI*"),
            (PS, "Clear-Item Env:SAIIFE_AUDIT_DIR"),
            // A change of a protected variable still counts as one.
            (PS, r"Set-Item Env:PATH C:\x; claude"),
            // Drives nothing is known about stay denied.
            (PS, r"Get-Content Foo:\x"),
            (PS, r"Get-Content temp:\x"),
            (PS, r"Set-Item Function:foo x"),
            (PS, r"Set-Item Alias:ls rm"),
            (PS, r"Set-Item C:\x y"),
        ],
    );
}

/// `name:rest` and `a::b` are everywhere in ordinary commands. They become
/// provider paths only by a name PowerShell gives a provider.
#[test]
fn colons_in_ordinary_words_are_no_drives() {
    let e = developer();
    let cases = [
        "npm run test:unit",
        "npm run temp:clean",
        "npm run function:deploy",
        "npm run alias:x",
        "docker pull nginx:latest",
        "docker run -p 80:80 nginx:1.2",
        "cargo test foo::bar",
        "cargo test engine::tests::x",
        "cargo test registry::tests",
        "cargo test environment::tests",
        "cargo test certificate::tests::y",
        "cargo test function::x",
        "git push origin main:main",
        "git show HEAD:src/lib.rs",
        "ssh host:22",
    ];
    for d in [PS, CMD, STRICTEST] {
        for cmd in cases {
            let got = e.evaluate_call(cmd, d);
            assert!(!got.is_deny(), "{d:?} {cmd:?}: {got:?}");
        }
    }
    // A stream is still a stream, and the file under it still the file.
    assert_all(
        &e,
        true,
        &[
            (PS, r"Get-Content .env::$DATA"),
            (PS, r"Get-Content .env:s"),
            (CMD, r"type .env:s"),
        ],
    );
}

#[test]
fn a_file_tool_never_has_a_provider() {
    use saiifeguard::pathrule::Access;
    let e = developer();
    for raw in [r"HKCU:\Software\x", r"HKLM:\x", "Env:", r"Foo:\x"] {
        assert!(e.evaluate_path(Access::Read, raw).is_deny(), "{raw}");
    }
}

#[test]
fn true_false_and_null_are_values() {
    let e = developer();
    assert_all(
        &e,
        false,
        &[
            (PS, "Foo -Bar $true"),
            (PS, "Foo -Bar $false"),
            (PS, "Foo -Bar $null"),
            (PS, "Foo -Bar:$true"),
            (PS, "Foo -Bar:$FALSE"),
            (PS, "Foo $True"),
            (PS, "Get-Process > $null"),
            (STRICTEST, "Foo -Bar $true"),
            (STRICTEST, "Foo -Bar:$false"),
            (STRICTEST, "Get-Process > $null"),
            (STRICTEST, "npm test > $null"),
            (STRICTEST, "npm test 2> $null"),
        ],
    );
}

// --- Ruling: parity with Linux ---------------------------------------------

#[test]
fn stopping_saiife_or_everything() {
    let e = only("core.process");
    let id = "windows-kill-saiife";
    assert_rule(
        &e,
        "core.process",
        id,
        &[
            (CMD, r#"taskkill /f /fi "imagename eq saiife.exe""#),
            (PS, r#"taskkill /f /fi "imagename eq saiife.exe""#),
            (POSIX, r#"taskkill /f /fi "imagename eq saiife.exe""#),
            (POSIX, r#"TASKKILL.EXE //F //FI "IMAGENAME EQ SAIIFE.EXE""#),
            (CMD, r#"taskkill /fi "imagename eq sai*""#),
            (CMD, r#"taskkill /f /fi "imagename eq *""#),
            (CMD, r#"taskkill /fi "imagename ne foo.exe""#),
            (CMD, r#"taskkill /fi "pid gt 0""#),
            (CMD, r#"taskkill /fi "status eq running""#),
            (CMD, r#"taskkill /fi "username eq bob""#),
            (CMD, r#"taskkill /fi "services eq saiifed""#),
            (POSIX, r"taskkill /im saiife.exe /f"),
            (POSIX, r#"taskkill /fi "pid gt 0""#),
            (CMD, "wmic process where name='saiife.exe' call terminate"),
            (PS, "wmic process where name='saiife.exe' call terminate"),
            (POSIX, "wmic process where name='saiife.exe' call terminate"),
            (CMD, r#"wmic.exe process where "name like 'saiife'" delete"#),
            (CMD, "WMIC PROCESS WHERE PROCESSID=4242 CALL TERMINATE"),
            (PS, "Get-Process | Stop-Process"),
            (PS, "Get-Process | Stop-Process -Force"),
            (PS, "gps | kill"),
            (PS, "ps | spps"),
            (PS, "Get-Process * | Stop-Process"),
            (PS, "Get-Process -Name * | Stop-Process"),
        ],
    );
    assert_all(
        &e,
        false,
        &[
            (CMD, r#"taskkill /f /fi "imagename eq node.exe""#),
            (CMD, r#"taskkill /fi "pid eq 4242""#),
            (CMD, r#"taskkill /fi "windowtitle eq foo""#),
            (POSIX, r#"taskkill /f /fi "imagename eq node.exe""#),
            (POSIX, r#"taskkill /fi "pid eq 4242""#),
            (CMD, "taskkill /im node.exe"),
            (PS, "Stop-Process -Name node"),
            (PS, "Stop-Process -Id 4242"),
        ],
    );
    // `wmic` is opaque to a hook, but this rule is about stopping processes.
    for cmd in [
        "wmic process list brief",
        "wmic process where name='x' get processid",
    ] {
        let got = e.evaluate_in(cmd, CMD);
        assert!(!got.is_deny(), "{cmd}: {got:?}");
    }
    // Not the same: one process's pipeline stays what it is, a reader's note.
    for cmd in [
        "Get-Process node | Stop-Process",
        "Get-Process -Id 5 | Stop-Process",
    ] {
        let got = e.evaluate_in(cmd, PS);
        assert!(!got.is_deny(), "{cmd}: {got:?}");
    }
    // A pipeline stage or a statement between them breaks the link.
    for cmd in [
        "Get-Process; Stop-Process",
        "Get-Process | Where-Object Name -eq node | Stop-Process",
    ] {
        let got = e.evaluate_in(cmd, PS);
        assert!(!got.is_deny(), "{cmd}: {got:?}");
    }
}

#[test]
fn boot_configuration_and_registry_hives() {
    let e = only("core.filesystem");
    assert_rule(
        &e,
        "core.filesystem",
        "windows-boot-config",
        &[
            (CMD, "bcdedit /delete {current}"),
            (PS, "bcdedit /delete {current}"),
            (POSIX, "bcdedit /delete {current}"),
            (CMD, "bcdedit /set testsigning on"),
            (CMD, "BCDEDIT.EXE /SET {default} recoveryenabled no"),
            (CMD, "bcdedit /store x /set y z"),
            (CMD, "bcdedit /deletevalue x"),
        ],
    );
    assert_rule(
        &e,
        "core.filesystem",
        "windows-registry-root",
        &[
            (CMD, "reg delete HKLM /f"),
            (PS, "reg delete HKCU /f"),
            (POSIX, "reg delete HKCR /f"),
            (CMD, r"reg delete HKU\ /f"),
            (CMD, "reg.exe delete HKEY_LOCAL_MACHINE /f"),
            (PS, r"Remove-Item -Recurse HKCU:\"),
            (PS, "Remove-Item -Recurse HKLM:"),
            (PS, r"Remove-Item -Recurse Registry::HKEY_USERS"),
        ],
    );
    assert_all(
        &e,
        false,
        &[
            (CMD, "bcdedit /enum"),
            (CMD, "bcdedit"),
            (CMD, r"reg delete HKCU\Software\Foo /f"),
            (CMD, "reg query HKLM"),
            (PS, r"Remove-Item -Recurse HKCU:\Software\Foo"),
        ],
    );
}

// --- 10. The budget ---------------------------------------------------------

fn no_time(pack_vars: PathVars) -> Engine {
    let (packs, _) = Catalog::builtin().load_active(&[]);
    Engine::new(packs)
        .with_paths(pack_vars)
        .with_budget(Duration::ZERO)
}

fn timed_out(d: &Decision) -> bool {
    matches!(
        d,
        Decision::Allow {
            trace: AllowTrace::FailedOpenTimeout
        }
    )
}

/// No clock: a zero budget is what a line long enough for its reader to use
/// up the budget comes to.
#[test]
fn running_out_of_budget_skips_no_rule() {
    let e = no_time(windows_vars());
    let padding = "echo x & ".repeat(50);
    let tail = format!(r"{padding}rd /s /q C:\");
    let head = format!(r"rd /s /q C:\ & {padding}echo x");
    for (d, cmd) in [
        (CMD, tail.as_str()),
        (CMD, head.as_str()),
        (CMD, r"rd /s /q C:\ & echo x"),
        (CMD, r"echo x & rd /s /q C:\"),
        (CMD, r#"cmd /c "rd /s /q C:\""#),
        (CMD, r"type C:\p\.env"),
        (PS, r"Remove-Item -Recurse C:\; echo x"),
        (PS, r"echo x; Remove-Item -Recurse C:\"),
        (PS, r"Get-Content C:\p\.env"),
        (PS, r#"cmd /c "rd /s /q C:\""#),
        (STRICTEST, r"rd /s /q C:\ & echo x"),
        (POSIX, "rm -rf C:/"),
    ] {
        for got in [e.evaluate_in(cmd, d), e.evaluate_call(cmd, d)] {
            assert!(got.is_deny(), "{d:?} {cmd:?}: {got:?}");
        }
    }
    // Nothing to deny: still what the caller's fail policy decides.
    for d in [PS, CMD, STRICTEST, POSIX] {
        for cmd in ["a; b", "git status", "echo x"] {
            let got = e.evaluate_in(cmd, d);
            assert!(timed_out(&got), "{d:?} {cmd:?}: {got:?}");
        }
    }
}

/// What the budget's last look costs is linear in the line: a padded line of the
/// largest size a hook accepts is still judged, and quickly.
#[test]
fn the_last_look_at_a_long_line_is_linear() {
    let e = no_time(windows_vars());
    let padding = "echo x & ".repeat(256 * 1024 / 9);
    let cmd = format!(r"{padding}rd /s /q C:\");
    let started = std::time::Instant::now();
    assert!(e.evaluate_in(&cmd, CMD).is_deny());
    let cmd = format!(
        r"{}Remove-Item -Recurse C:\",
        "echo x; ".repeat(256 * 1024 / 7)
    );
    assert!(e.evaluate_in(&cmd, PS).is_deny());
    // Far above a release build's time; a quadratic pass would not make it.
    assert!(started.elapsed() < Duration::from_secs(120));
    eprintln!("p19a-t7 last look: {:?}", started.elapsed());
}

/// On Linux and macOS a POSIX line keeps its order: the budget is checked first,
/// and the record says so.
#[test]
fn a_posix_host_keeps_its_budget_order() {
    let (packs, _) = Catalog::builtin().load_active(&[]);
    let e = Engine::new(packs).with_budget(Duration::ZERO);
    for cmd in ["rm -rf /", "git status", "echo x & rm -rf /"] {
        assert!(timed_out(&e.evaluate(cmd)), "{cmd}");
    }
}

// --- 11. Tool names ---------------------------------------------------------

#[test]
fn a_shell_tool_of_any_casing_is_a_shell_tool() {
    let classify = |tool: &str, input: &str, windows: bool| {
        let json = format!(r#"{{"tool_name":"{tool}","tool_input":{input}}}"#);
        classify_for(&json, 1 << 20, Some("claude"), windows)
    };
    for tool in ["powershell", "POWERSHELL", "PowerSHELL"] {
        for windows in [false, true] {
            match classify(tool, r#"{"command":"ls"}"#, windows) {
                Ok(ToolCall::Shell { command, dialects }) => {
                    assert_eq!(command, "ls");
                    assert_eq!(dialects, PS, "{tool}");
                }
                other => panic!("{tool}: {other:?}"),
            }
            // A call with no usable command is what `PowerShell`'s is: never
            // a tool the guard does not judge.
            for input in ["{}", r#"{"command":""}"#, r#"{"command":7}"#] {
                let got = classify(tool, input, windows);
                let want = classify("PowerShell", input, windows);
                assert_eq!(format!("{got:?}"), format!("{want:?}"), "{tool} {input}");
                assert!(!matches!(got, Ok(ToolCall::Other { .. })), "{tool} {input}");
            }
        }
    }
    // The POSIX tools stay as they were: their names are exact.
    for tool in ["bash", "BASH", "Run_Shell_Command"] {
        assert!(
            matches!(classify(tool, "{}", false), Ok(ToolCall::Other { .. })),
            "{tool}"
        );
    }
    assert!(classify("Bash", "{}", false).is_err());
}
