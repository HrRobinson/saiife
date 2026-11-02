//! Golden corpus for the Windows rules (plan 19a, W7) in `core.filesystem`,
//! `core.secrets`, `core.self`, `core.process` and `core.lock`.
//!
//! Every rule is checked end to end: the command is read by the PowerShell or
//! cmd reader (translated to the POSIX form the packs judge), canonicalized as a
//! Windows host does, and judged by one built-in pack alone, so a deny is that
//! pack's doing. Each deny has a benign neighbour that must stay allowed.

use saiifeguard::builtins::{builtin_packs_for, Catalog};
use saiifeguard::canon::{PathStyle, PathVars};
use saiifeguard::engine::{Decision, Engine};
use saiifeguard::payload::Dialects;
use saiifeguard::wintable::Dialect::{Cmd, Posix, PowerShell};

const BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

const PS: Dialects = Dialects::One(PowerShell);
const CMD: Dialects = Dialects::One(Cmd);
const POSIX: Dialects = Dialects::One(Posix);
const STRICTEST: Dialects = Dialects::Strictest(PowerShell, Posix);

fn windows_vars() -> PathVars {
    PathVars::new()
        .with_style(PathStyle::Windows)
        .with_var("USERPROFILE", r"C:\Users\a")
        .with_var("LOCALAPPDATA", r"C:\Users\a\AppData\Local")
        .with_var("APPDATA", r"C:\Users\a\AppData\Roaming")
        .with_cwd(r"C:\p")
}

/// One built-in pack, alone, on a Windows host.
fn only(pack: &str) -> Engine {
    let (packs, warnings) = builtin_packs_for(PathStyle::Windows);
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    let p = packs.into_iter().find(|p| p.id == pack).unwrap();
    Engine::new(vec![p])
        .with_paths(windows_vars())
        .with_budget(BUDGET)
        .with_pattern_allowance(std::time::Duration::MAX)
}

/// Every default-on pack plus `core.lock`, on a Windows host (or a POSIX one).
fn everything(windows: bool) -> Engine {
    let style = if windows {
        PathStyle::Windows
    } else {
        PathStyle::Posix
    };
    let (packs, warnings) = Catalog::builtin_for(style).load_active(&["core.lock".to_string()]);
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    let e = Engine::new(packs).with_budget(BUDGET);
    if windows {
        e.with_paths(windows_vars())
    } else {
        e.with_paths(PathVars::new().with_style(PathStyle::Posix))
    }
}

/// `Some(rule id)` (`"path"` for a path rule, which has none) when `pack`
/// denies the command; a deny by another pack is a failure.
fn deny_id(e: &Engine, pack: &str, d: Dialects, cmd: &str) -> Option<String> {
    match e.evaluate_in(cmd, d) {
        Decision::Deny {
            pack: p, pattern, ..
        } => {
            assert_eq!(p, pack, "{cmd:?}: denied by {p}");
            Some(e.rule_id(&p, &pattern).unwrap_or("path").to_string())
        }
        _ => None,
    }
}

/// (dialects, command, rule id or "path").
type Case = (Dialects, &'static str, &'static str);

fn check(pack: &str, deny: &[Case], allow: &[(Dialects, &str)]) {
    let e = only(pack);
    let mut wrong = Vec::new();
    for (d, cmd, id) in deny {
        match deny_id(&e, pack, *d, cmd) {
            Some(got) if got == *id => {}
            got => wrong.push(format!("{cmd:?}: want deny {id}, got {got:?}")),
        }
    }
    for (d, cmd) in allow {
        if let Some(got) = deny_id(&e, pack, *d, cmd) {
            wrong.push(format!("{cmd:?}: want allow, denied by {got}"));
        }
    }
    assert!(wrong.is_empty(), "{pack}:\n{}", wrong.join("\n"));
}

#[test]
fn filesystem_windows_rules() {
    let deny: &[Case] = &[
        (PS, r"Remove-Item -Recurse -Force C:\", "windows-root-rm"),
        (PS, r"Remove-Item -Force -Recurse E:\", "windows-root-rm"),
        (PS, r"Remove-Item -Recurse -Force C:\*", "windows-root-rm"),
        (PS, r"Remove-Item -Recurse -Force C:", "windows-root-rm"),
        (
            PS,
            r"REMOVE-ITEM -RECURSE -FORCE c:\windows",
            "windows-root-rm",
        ),
        (PS, r"ri -r 'C:\Program Files'", "windows-root-rm"),
        (PS, r"ri -r 'C:\Program Files (x86)\'", "windows-root-rm"),
        (
            PS,
            r"Remove-Item -Recurse -Force \\?\C:\",
            "windows-root-rm",
        ),
        (
            PS,
            r"Remove-Item -Recurse -Force C:/Windows/",
            "windows-root-rm",
        ),
        (CMD, r"rd /s /q D:\Windows", "windows-root-rm"),
        (CMD, r"rd /s /q C:\", "windows-root-rm"),
        (CMD, r"rmdir /s /q c:\programdata", "windows-root-rm"),
        (CMD, r"del /s /q C:\Users\*", "windows-root-rm"),
        (CMD, r"rd /s /q \\localhost\c$\Windows", "windows-root-rm"),
        // Task 6 review forms.
        (CMD, r"del /s C:\*.*", "windows-root-rm"),
        (CMD, r"del /s /q C:\*.*", "windows-root-rm"),
        (PS, r"Remove-Item -Recurse C:\*.*", "windows-root-rm"),
        (CMD, r"rd /s /q \", "windows-root-rm"),
        (PS, r"Remove-Item -Recurse -Force \", "windows-root-rm"),
        (POSIX, r"rm -rf C:/", "windows-root-rm"),
        (POSIX, r"rm C:/ -rf", "windows-root-rm"),
        (POSIX, "rm -rf /c/Windows", "windows-root-rm"),
        (POSIX, "rm -rf '/c/Program Files'", "windows-root-rm"),
        (POSIX, "rm -rf /cygdrive/d/", "windows-root-rm"),
        (POSIX, "rm -rf /c/*", "windows-root-rm"),
        (
            STRICTEST,
            r"Remove-Item -Recurse -Force C:\",
            "windows-root-rm",
        ),
        (PS, r#"cmd /c "rd /s /q C:\""#, "windows-root-rm"),
        (PS, r"format C: /q", "windows-format"),
        (PS, r"FORMAT.COM d: /fs:ntfs", "windows-format"),
        (CMD, r"format D:", "windows-format"),
        (CMD, r"format /q /fs:ntfs E:", "windows-format"),
        (PS, "Format-Volume -DriveLetter C", "windows-format"),
        (PS, "Get-Volume D | Format-Volume", "windows-format"),
        (
            PS,
            "format-volume -DriveLetter d -FileSystem NTFS",
            "windows-format",
        ),
        (PS, "Clear-Disk -Number 0", "windows-format"),
        (PS, "CLEAR-DISK -Number 0 -RemoveData", "windows-format"),
        (PS, "Remove-Partition -DriveLetter D", "windows-format"),
        (PS, "Initialize-Disk 1", "windows-format"),
        (PS, r"diskpart /s wipe.txt", "windows-format"),
        (CMD, "diskpart", "windows-format"),
        (PS, r"cipher /w:C:\", "windows-cipher-wipe"),
        (CMD, "CIPHER /W:C", "windows-cipher-wipe"),
        (
            CMD,
            "vssadmin delete shadows /all /quiet",
            "windows-shadow-copies",
        ),
        (
            PS,
            "vssadmin.exe Delete Shadows /for=C:",
            "windows-shadow-copies",
        ),
        (
            CMD,
            "vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401MB",
            "windows-shadow-copies",
        ),
        (
            CMD,
            "wbadmin delete catalog -quiet",
            "windows-shadow-copies",
        ),
        (CMD, "wmic shadowcopy delete", "windows-shadow-copies"),
    ];
    let allow: &[(Dialects, &str)] = &[
        (PS, r"Remove-Item -Recurse .\build"),
        (CMD, r"rd /s /q C:\Users\a\proj\target"),
        (CMD, r"rd /s /q C:\Program Files\x"),
        (PS, r"Remove-Item -Recurse -Force C:\Windows\Temp\x"),
        (PS, r"Remove-Item C:\Windows"),
        (PS, r"Remove-Item -Recurse C:\Users\a\AppData\Local\Temp\x"),
        (PS, r"Remove-Item -Recurse C:\ProgramData\myapp\cache"),
        (POSIX, "rm -rf /tmp/c"),
        (POSIX, "rm -rf ./c"),
        (POSIX, "rm -rf /cache"),
        (POSIX, "rm -rf /c/Users/a/proj/target"),
        (PS, "Get-Process | Format-Table"),
        (PS, "Get-ChildItem | Format-List"),
        (PS, "format-table"),
        (PS, "Format-Hex file.bin"),
        (POSIX, "git log --format=%H"),
        (POSIX, "docker ps --format '{{.ID}}'"),
        (CMD, r"cipher /e C:\secret"),
        (CMD, "vssadmin list shadows"),
        (CMD, "wbadmin get versions"),
        (CMD, "echo diskpart"),
        (PS, "Get-Disk"),
        (PS, "Get-Partition"),
        (PS, "Get-Volume"),
    ];
    check("core.filesystem", deny, allow);
}

#[test]
fn secrets_windows_rules() {
    let deny: &[Case] = &[
        (PS, "cmdkey /list", "windows-credential-dump"),
        (CMD, "CMDKEY /LIST", "windows-credential-dump"),
        (CMD, "cmdkey /list:server", "windows-credential-dump"),
        (
            CMD,
            r#"vaultcmd /listcreds:"Windows Credentials""#,
            "windows-credential-dump",
        ),
        (CMD, "VaultCmd /list", "windows-credential-dump"),
        (PS, r"reg save HKLM\SAM sam.hiv", "windows-hive-save"),
        (PS, r"reg save HKLM\SYSTEM system.hiv", "windows-hive-save"),
        (
            CMD,
            r"reg.exe export HKEY_LOCAL_MACHINE\SECURITY x.reg",
            "windows-hive-save",
        ),
        (CMD, r"REG SAVE hklm\sam x", "windows-hive-save"),
        (CMD, r"reg save HKLM\SAM\SAM\Domains x", "windows-hive-save"),
        (PS, r"Get-Content C:\Users\a\.git-credentials", "path"),
        (PS, r"gc ~\.git-credentials", "path"),
        (CMD, r"type C:\Users\a\.git-credentials", "path"),
        (
            PS,
            r"Get-Content C:\Users\a\AppData\Roaming\Microsoft\Credentials\ABC123",
            "path",
        ),
        (
            PS,
            r"Get-Content $env:LOCALAPPDATA\Microsoft\Credentials\ABC123",
            "path",
        ),
        (
            PS,
            r"Get-Content $env:APPDATA\Microsoft\Protect\S-1-5-21\key",
            "path",
        ),
        (
            PS,
            r"Copy-Item C:\Users\a\AppData\Local\Microsoft\Vault\x .",
            "path",
        ),
        (PS, r"Copy-Item C:\Windows\System32\config\SAM .", "path"),
        (CMD, r"copy c:\windows\system32\config\system x", "path"),
        (
            PS,
            r"Get-Content 'C:\Users\a\AppData\Roaming\GitHub CLI\hosts.yml'",
            "path",
        ),
        (PS, r"Get-Content C:\Users\a\.ssh\id_ed25519", "path"),
        (PS, r"Get-Content C:\p\.env", "path"),
    ];
    let allow: &[(Dialects, &str)] = &[
        (PS, "cmdkey /help"),
        (CMD, "vaultcmd /?"),
        (PS, r"reg query HKLM\SOFTWARE\Microsoft"),
        (PS, r"reg export HKCU\Software\MyApp app.reg"),
        (
            PS,
            r"reg export HKLM\SYSTEM\CurrentControlSet\Services\Foo foo.reg",
        ),
        (PS, r"reg query HKLM\SAM"),
        (PS, r"Get-Content C:\Users\a\proj\README.md"),
        (CMD, r"type C:\Users\a\AppData\Roaming\Code\settings.json"),
        (PS, r"Get-Content C:\Windows\System32\drivers\etc\hosts"),
        (PS, r"Get-Content C:\Users\a\.ssh\id_ed25519.pub"),
    ];
    check("core.secrets", deny, allow);
}

#[test]
fn self_windows_rules() {
    let deny: &[Case] = &[
        (
            PS,
            r"Remove-Item -Recurse -Force $env:LOCALAPPDATA\saiife",
            "path",
        ),
        (CMD, r"rd /s /q C:\Users\a\AppData\Local\saiife", "path"),
        (
            PS,
            r"Remove-Item C:\Users\a\AppData\Local\saiife\audit\2026-10.jsonl",
            "path",
        ),
        (
            PS,
            r"Set-Content C:\Users\a\AppData\Local\saiife\x.json '{}'",
            "path",
        ),
        (
            PS,
            r"Set-Content C:\Users\a\AppData\Local\SAIIFE\x.json '{}'",
            "path",
        ),
        (CMD, r"setx SAIIFE_DATA_DIR D:\x", "windows-data-dir"),
        (CMD, r"setx /M SAIIFE_AUDIT_DIR D:\x", "windows-data-dir"),
        (CMD, r"SETX saiife_audit_dir x", "windows-data-dir"),
        (PS, r"Set-Content C:\p\.claude\settings.json '{}'", "path"),
        (PS, r"Remove-Item C:\p\.saiife\config.toml", "path"),
        (PS, r"taskkill /im saiife.exe /f", "path"),
    ];
    let allow: &[(Dialects, &str)] = &[
        (
            PS,
            r"Get-Content C:\Users\a\AppData\Local\saiife\config.toml",
        ),
        (PS, r"Get-ChildItem $env:LOCALAPPDATA\saiife"),
        (PS, r"Remove-Item C:\Users\a\AppData\Local\other\x"),
        (PS, r"Set-Content C:\Users\a\AppData\Local\saiife-tools\x 1"),
        (CMD, "setx FOO bar"),
        (CMD, "setx SAIIFE_OTHER x"),
        (PS, r"Get-Content C:\p\.claude\settings.json"),
    ];
    let e = only("core.self");
    // `taskkill` is the older self rule's, not one with an id.
    assert!(deny_id(&e, "core.self", PS, r"taskkill /im saiife.exe /f").is_some());
    let deny: Vec<Case> = deny
        .iter()
        .copied()
        .filter(|c| !c.1.starts_with("taskkill"))
        .collect();
    check("core.self", &deny, allow);
}

#[test]
fn process_windows_rules() {
    let deny: &[Case] = &[
        (CMD, "taskkill /im saiife.exe /f", "windows-kill-saiife"),
        (CMD, "taskkill /f /im saiifed.exe", "windows-kill-saiife"),
        (CMD, "TASKKILL /IM SAIIFE-BROKER.EXE", "windows-kill-saiife"),
        (PS, "taskkill /im saiife.exe /f", "windows-kill-saiife"),
        (
            PS,
            "Stop-Process -Name saiife -Force",
            "windows-kill-saiife",
        ),
        (PS, "Stop-Process -Name sai*", "windows-kill-saiife"),
        (PS, "Stop-Process -Name saiif?", "windows-kill-saiife"),
        (PS, "Stop-Process -Name s*", "windows-kill-saiife"),
        (PS, "Stop-Process -Name *", "windows-kill-saiife"),
        (PS, "spps -Name saiife", "windows-kill-saiife"),
        (
            PS,
            "Stop-Process -ProcessName saiife.exe",
            "windows-kill-saiife",
        ),
    ];
    let allow: &[(Dialects, &str)] = &[
        (CMD, "taskkill /im node.exe /f"),
        (PS, "Stop-Process -Name node"),
        (PS, "Stop-Process -Name *node*"),
        (PS, "Stop-Process -Name node*"),
        (PS, "Stop-Process -Name saturn*"),
        (PS, "Stop-Process -Name chrome -Force"),
        (PS, "Stop-Process -Id 4242"),
        (CMD, "taskkill /pid 4242 /f"),
        (PS, "Get-Process saiife"),
        (POSIX, "kill 4242"),
        (POSIX, "kill -9 4242"),
    ];
    check("core.process", deny, allow);
}

#[test]
fn lock_windows_rules() {
    let deny: &[Case] = &[
        // windows-files
        (
            PS,
            r"icacls C:\ProgramData\saiife /grant Users:F",
            "windows-files",
        ),
        (
            PS,
            r"ICACLS d:\programdata\saiife\bin /grant Users:F",
            "windows-files",
        ),
        (
            PS,
            r"icacls 'C:\Program Files\ClaudeCode' /inheritance:r",
            "windows-files",
        ),
        (
            CMD,
            r"takeown /f C:\ProgramData\gemini-cli /r",
            "windows-files",
        ),
        (
            PS,
            r"Set-Acl -Path C:\ProgramData\OpenAI\Codex $acl",
            "windows-files",
        ),
        (
            PS,
            r"icacls $env:ProgramData\saiife /grant Users:F",
            "windows-files",
        ),
        // windows-service
        (PS, "sc.exe stop saiifed", "windows-service"),
        (CMD, "sc stop saiifed", "windows-service"),
        (
            CMD,
            "SC.EXE CONFIG saiifed start= disabled",
            "windows-service",
        ),
        (CMD, "sc.exe delete saiifed", "windows-service"),
        (
            CMD,
            "sc.exe failure saiifed reset= 0 actions= \"\"",
            "windows-service",
        ),
        (
            CMD,
            "sc.exe sdset saiifed D:(A;;GA;;;WD)",
            "windows-service",
        ),
        (CMD, r"sc.exe \\localhost stop saiifed", "windows-service"),
        (CMD, "net stop saiifed", "windows-service"),
        (CMD, r#"net stop "saiife daemon""#, "windows-service"),
        (PS, "Stop-Service saiifed", "windows-service"),
        (PS, "Stop-Service -Name saiifed -Force", "windows-service"),
        (PS, "stop-service SAIIFED", "windows-service"),
        (
            PS,
            "Set-Service saiifed -StartupType Disabled",
            "windows-service",
        ),
        (PS, "Remove-Service saiifed", "windows-service"),
        (PS, "Restart-Service saiif*", "windows-service"),
        (PS, "Stop-Service sai*", "windows-service"),
        (PS, "Get-Service saiifed | Stop-Service", "windows-service"),
        (
            CMD,
            r"reg add HKLM\SYSTEM\CurrentControlSet\Services\saiifed /v Start /t REG_DWORD /d 4 /f",
            "windows-service",
        ),
        (
            PS,
            r"Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\saiifed -Name Start -Value 4",
            "windows-service",
        ),
        // windows-claude-policy
        (
            PS,
            r"reg add HKLM\SOFTWARE\Policies\ClaudeCode /v Settings /d {}",
            "windows-claude-policy",
        ),
        (
            CMD,
            r"reg delete HKLM\SOFTWARE\Policies\ClaudeCode /f",
            "windows-claude-policy",
        ),
        (
            CMD,
            r"REG DELETE hklm\software\policies\claudecode\x",
            "windows-claude-policy",
        ),
        (
            PS,
            r"Set-ItemProperty HKLM:\SOFTWARE\Policies\ClaudeCode -Name Settings -Value x",
            "windows-claude-policy",
        ),
        (
            PS,
            r"New-ItemProperty -Path HKLM:\SOFTWARE\Policies\ClaudeCode -Name x -Value 1",
            "windows-claude-policy",
        ),
        (
            PS,
            r"Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\ClaudeCode -Name Settings",
            "windows-claude-policy",
        ),
        (
            PS,
            r"Remove-Item -Recurse HKLM:\SOFTWARE\Policies\ClaudeCode",
            "windows-claude-policy",
        ),
        (
            PS,
            r"sp 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\ClaudeCode' Settings x",
            "windows-claude-policy",
        ),
        (CMD, "reg import evil.reg", "windows-claude-policy"),
        // windows-audit-group
        (
            CMD,
            "net localgroup saiife-audit alice /add",
            "windows-audit-group",
        ),
        (
            CMD,
            "net localgroup saiife-audit alice /delete",
            "windows-audit-group",
        ),
        (
            CMD,
            "net localgroup saiife-audit /delete",
            "windows-audit-group",
        ),
        (
            CMD,
            "NET1 LOCALGROUP saiife-audit alice /ADD",
            "windows-audit-group",
        ),
        (
            PS,
            "Add-LocalGroupMember -Group saiife-audit -Member alice",
            "windows-audit-group",
        ),
        (
            PS,
            "Remove-LocalGroupMember -Group saiife-audit -Member alice",
            "windows-audit-group",
        ),
        // path rules, any command, any drive
        (
            PS,
            r"Set-Content C:\ProgramData\gemini-cli\settings.json '{}'",
            "path",
        ),
        (PS, r"Remove-Item -Recurse C:\ProgramData\saiife", "path"),
        (PS, r"Remove-Item -Recurse D:\ProgramData\saiife", "path"),
        (
            PS,
            r"Set-Content C:\ProgramData\saiife\etc\config.toml 'x'",
            "path",
        ),
        (
            PS,
            r#"Remove-Item "C:\Program Files\ClaudeCode\managed-settings.d\50-saiife.json""#,
            "path",
        ),
        (
            PS,
            r"Copy-Item x C:\ProgramData\OpenAI\Codex\requirements.toml",
            "path",
        ),
        (
            PS,
            r"Get-Content C:\ProgramData\saiife\state\keys\audit.ed25519",
            "path",
        ),
        (
            PS,
            r"Set-Content C:\PROGRAMDATA\SAIIFE\bin\saiife.exe x",
            "path",
        ),
    ];
    let allow: &[(Dialects, &str)] = &[
        (PS, r"reg query HKLM\SOFTWARE\Policies\ClaudeCode"),
        (PS, "Get-Service saiifed"),
        (PS, "sc.exe query saiifed"),
        (CMD, "sc qc saiifed"),
        (CMD, "net start saiifed"),
        (CMD, "net stop spooler"),
        (PS, "Stop-Service spooler"),
        (PS, "Stop-Service -Name Spooler -Force"),
        (PS, "Restart-Service W32Time"),
        (PS, "Get-Service | Where-Object Status -eq Running"),
        (CMD, r"icacls C:\Users\a\proj /grant Users:F"),
        (CMD, r"takeown /f C:\Users\a\proj\x"),
        (PS, r"reg add HKLM\SOFTWARE\Policies\Other /v x /d 1"),
        (PS, r"reg add HKCU\Software\X /v a /d 1"),
        (CMD, r"reg export HKCU\Software\X y.reg"),
        (
            PS,
            r"reg add HKLM\SYSTEM\CurrentControlSet\Services\other /v Start /d 4",
        ),
        (CMD, "net localgroup Administrators"),
        (CMD, "net localgroup saiife-audit"),
        (CMD, "net localgroup devs alice /add"),
        (PS, "Get-LocalGroupMember saiife-audit"),
        (PS, r"Get-Content C:\ProgramData\saiife\etc\config.toml"),
        (PS, r"Get-Content C:\ProgramData\gemini-cli\settings.json"),
        (PS, r"Set-Content C:\ProgramData\other\x 1"),
        (PS, r"Remove-Item -Recurse C:\ProgramData\saiife-tools\x"),
        (PS, r"Remove-Item -Recurse 'C:\Program Files\Other\x'"),
    ];
    check("core.lock", deny, allow);
}

/// Windows commands that do everyday work, judged with every default-on pack
/// and `core.lock` on a Windows host (every reader) and on a POSIX host.
#[test]
fn benign_windows_commands_allowed_both_ways() {
    let benign: &[&str] = &[
        r"Remove-Item -Recurse .\build",
        r"rd /s /q C:\Users\a\proj\target",
        r"Remove-Item -Recurse -Force .\node_modules",
        "reg query HKLM\\SOFTWARE\\Policies\\ClaudeCode",
        "Get-Service saiifed",
        "sc.exe query saiifed",
        "Get-Process | Format-Table",
        "Get-ChildItem -Recurse | Format-List Name",
        "Stop-Process -Name node",
        "taskkill /im node.exe /f",
        "net stop spooler",
        "Stop-Service spooler",
        r"icacls C:\Users\a\proj /grant Users:F",
        r"Get-Content C:\Users\a\proj\README.md",
        "git status",
        "cargo build --release",
        "dir /s src",
        r"cipher /e C:\secret",
        "vssadmin list shadows",
        "setx FOO bar",
        r"reg export HKCU\Software\MyApp app.reg",
    ];
    let mut wrong = Vec::new();
    for (e, name, dialects) in [
        (everything(true), "windows ps", PS),
        (everything(true), "windows cmd", CMD),
        (everything(true), "windows strictest", STRICTEST),
        (everything(false), "posix", POSIX),
    ] {
        for cmd in benign {
            let d = e.evaluate_in(cmd, dialects);
            if d.is_deny() && !(name == "windows cmd" && cmd.contains("Get-")) {
                // PowerShell-only syntax read as cmd is another reading.
                wrong.push(format!("{name}: {cmd:?} -> {d:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// A Git Bash mount is a Windows host's reading (`rm -rf /c/Windows` above). On
/// Linux and macOS these are ordinary paths: `corpus_windows_round1` pins them
/// against `main`.
#[test]
fn a_posix_host_has_no_drive_mounts() {
    let e = everything(false);
    for cmd in [
        "rm -rf /c/*",
        "rm -rf /d/*",
        "rm -rf /x/windows",
        "rm -rf /cygdrive/c",
        "rm -rf /c/Windows",
        "rm -rf /tmp/c",
        "rm -rf ./c",
        "rm -rf c",
        "rm -rf /cc",
        "rm -rf /x",
        "rm -rf /c",
        "rm -rf /cache",
        "rm -rf /c/proj/target",
        "kill 4242",
        "format --help",
        "echo diskpart",
    ] {
        assert!(!e.evaluate(cmd).is_deny(), "{cmd}");
    }
}

/// `rd /s /q ..` from `C:\p` is the drive root: on a Windows host a relative
/// operand is joined onto the starting directory (`cdtrack.rs`). POSIX style
/// keeps the gap: there a line without `cd` is judged as written.
#[test]
fn relative_parent_of_a_one_level_cwd_is_the_drive_root() {
    let e = only("core.filesystem");
    assert!(e.evaluate_in(r"rd /s /q ..", CMD).is_deny());
    assert!(e
        .evaluate_in(r"Remove-Item -Recurse -Force ..", PS)
        .is_deny());
}
