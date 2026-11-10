//! `platform = "windows"` on the shipped packs (W7): the Windows rules compile on
//! a Windows-style host only. Three things can go wrong without any other test
//! seeing it: a rule loses its marker and costs every hook call on Linux, a marker
//! lands on a rule that protects Linux too, or a Windows test runs on a load
//! without the rule it means to test. So the marked rules are pinned one by one,
//! and each is shown to deny on the load the Windows corpus uses and not on a
//! POSIX one.

use saiifeguard::builtins::{builtin_packs_for, Catalog};
use saiifeguard::canon::{PathStyle, PathVars};
use saiifeguard::engine::{Decision, Engine};
use saiifeguard::payload::Dialects;
use saiifeguard::wintable::Dialect::{Cmd, PowerShell};
use saiifeguard::Pack;

const BUDGET: std::time::Duration = std::time::Duration::from_secs(5);
const PS: Dialects = Dialects::One(PowerShell);
const CMD: Dialects = Dialects::One(Cmd);

/// Each pack's marked rules: `[[deny]]` by id, `[[allow]]` and path rules by
/// pattern or glob.
const MARKED: &[(&str, &[&str])] = &[
    (
        "core.filesystem",
        &[
            "windows-boot-config",
            "windows-cipher-wipe",
            "windows-format",
            "windows-registry-root",
            "windows-root-chmod",
            "windows-root-chown",
            "windows-root-rm",
            "windows-shadow-copies",
        ],
    ),
    (
        "core.secrets",
        &[
            "**/AppData/*/Microsoft/Credentials/**",
            "**/AppData/*/Microsoft/Vault/**",
            "**/AppData/Roaming/GitHub CLI/hosts.yml",
            "**/AppData/Roaming/Microsoft/Protect/**",
            "**/AppData/Roaming/gcloud/**",
            "?:/programdata/microsoft/vault/**",
            "?:/windows/ntds/ntds.dit",
            "?:/windows/system32/config/sam",
            "?:/windows/system32/config/security",
            "?:/windows/system32/config/system",
            "windows-credential-dump",
            "windows-hive-save",
            "~/AppData/Local/Microsoft/Credentials",
            "~/AppData/Local/Microsoft/Vault",
            "~/AppData/Roaming/GitHub CLI/hosts.yml",
            "~/AppData/Roaming/Microsoft/Credentials",
            "~/AppData/Roaming/Microsoft/Protect",
            "~/AppData/Roaming/Microsoft/Vault",
            "~/AppData/Roaming/gcloud",
        ],
    ),
    (
        "core.self",
        &[
            "**/AppData/Local/saiife",
            "**/AppData/Local/saiife/**",
            "windows-data-dir",
        ],
    ),
    ("core.process", &["windows-kill-saiife"]),
    (
        "core.lock",
        &[
            "?:/program files/claudecode",
            "?:/program files/claudecode/**",
            "?:/programdata/gemini-cli",
            "?:/programdata/gemini-cli/**",
            "?:/programdata/openai/codex",
            "?:/programdata/openai/codex/**",
            "?:/programdata/saiife",
            "?:/programdata/saiife/**",
            "?:/programdata/saiife/state/**",
            "allow:icacls",
            "windows-audit-group",
            "windows-claude-policy",
            "windows-files",
            "windows-service",
        ],
    ),
];

/// The names of a pack's rules, one per rule; a repeated glob counts twice.
fn names(p: &Pack) -> Vec<String> {
    let mut out: Vec<String> = p
        .deny_rules()
        .iter()
        .map(|r| {
            r.id.clone()
                .unwrap_or_else(|| format!("deny:{}", r.pattern))
        })
        .chain(p.allow_rules().iter().map(|r| {
            if r.pattern.contains("icacls") {
                "allow:icacls".to_string()
            } else {
                format!("allow:{}", r.pattern)
            }
        }))
        .chain(p.allow_path.iter().map(|r| format!("allow:{}", r.glob)))
        .chain(
            p.deny_path
                .iter()
                .map(|r| format!("{}/{}", r.glob, r.access.label())),
        )
        .collect();
    out.sort();
    out
}

/// What a Windows load has that a POSIX load has not; the access of a path rule
/// is dropped, as the same glob may stand for a read and a write.
fn only_on_windows(pack: &str) -> Vec<String> {
    let load = |style| {
        let (packs, w) = builtin_packs_for(style);
        assert!(w.is_empty(), "{w:?}");
        names(packs.iter().find(|p| p.id == pack).unwrap())
    };
    let (win, mut posix) = (load(PathStyle::Windows), load(PathStyle::Posix));
    let mut out = Vec::new();
    for n in win {
        match posix.iter().position(|p| *p == n) {
            Some(at) => {
                posix.remove(at);
            }
            None => out.push(n),
        }
    }
    assert!(posix.is_empty(), "{pack}: POSIX-only rules: {posix:?}");
    let mut out: Vec<String> = out
        .into_iter()
        .map(|n| match n.rsplit_once('/') {
            Some((glob, access))
                if ["read", "write", "any", "replace", "content"].contains(&access) =>
            {
                glob.to_string()
            }
            _ => n,
        })
        .collect();
    out.sort();
    out
}

/// The set of rules marked is what this file says, in both directions: a mutation
/// that drops a marked rule or its marker, or marks another rule, fails here.
#[test]
fn the_marked_rules_are_exactly_these() {
    for (pack, want) in MARKED {
        let mut want: Vec<String> = want.iter().map(|s| s.to_string()).collect();
        want.sort();
        assert_eq!(only_on_windows(pack), want, "{pack}");
    }
    // No other pack has any.
    let (win, _) = builtin_packs_for(PathStyle::Windows);
    let (posix, _) = builtin_packs_for(PathStyle::Posix);
    assert_eq!(win.len(), posix.len());
    for (w, p) in win.iter().zip(&posix) {
        if !MARKED.iter().any(|(id, _)| *id == w.id) {
            assert_eq!(names(w), names(p), "{}", w.id);
            assert_eq!(w.triggers, p.triggers, "{}", w.id);
        }
    }
}

/// On POSIX the triggers are the ones `main` has: no case-insensitive one, whose
/// alternation is what costs, and none that would bring a pack's rules out for a
/// Windows program's name.
#[test]
fn a_posix_load_has_no_windows_trigger() {
    let (posix, _) = builtin_packs_for(PathStyle::Posix);
    for p in &posix {
        let bad: Vec<_> = p
            .triggers
            .iter()
            .filter(|t| t.starts_with("(?i)"))
            .collect();
        assert!(bad.is_empty(), "{}: {bad:?}", p.id);
    }
    let (win, _) = builtin_packs_for(PathStyle::Windows);
    for (id, _) in MARKED {
        let has = win
            .iter()
            .find(|p| p.id == *id)
            .unwrap()
            .triggers
            .iter()
            .any(|t| t.starts_with("(?i)"));
        assert!(has, "{id}");
    }
}

fn windows_vars() -> PathVars {
    PathVars::new()
        .with_style(PathStyle::Windows)
        .with_var("USERPROFILE", r"C:\Users\a")
        .with_var("LOCALAPPDATA", r"C:\Users\a\AppData\Local")
        .with_var("APPDATA", r"C:\Users\a\AppData\Roaming")
        .with_cwd(r"C:\p")
}

fn engine(style: PathStyle) -> Engine {
    let (packs, w) = Catalog::builtin_for(style).load_active(&["core.lock".to_string()]);
    assert!(w.is_empty(), "{w:?}");
    let vars = match style {
        PathStyle::Windows => windows_vars(),
        PathStyle::Posix => PathVars::new()
            .with_style(PathStyle::Posix)
            .with_var("HOME", "/home/a")
            .with_cwd("/home/a/p"),
    };
    Engine::new(packs).with_paths(vars).with_budget(BUDGET)
}

/// One command per marked rule that has an id, on a Windows-style host: it denies
/// under that rule, read in the dialect the corpus reads it in and in Git Bash's.
/// The same words on a POSIX host are allowed. `(pack, rule, windows dialect,
/// command)`.
const ONE_EACH: &[(&str, &str, Dialects, &str)] = &[
    (
        "core.filesystem",
        "windows-root-rm",
        PS,
        r"rm -rf c:/windows",
    ),
    (
        "core.filesystem",
        "windows-root-chmod",
        PS,
        r"chmod -R 777 c:/*",
    ),
    (
        "core.filesystem",
        "windows-root-chown",
        PS,
        r"chown -R root c:/*",
    ),
    ("core.filesystem", "windows-format", CMD, "format a:"),
    ("core.filesystem", "windows-cipher-wipe", CMD, "cipher /w:x"),
    (
        "core.filesystem",
        "windows-boot-config",
        CMD,
        "bcdedit /set testsigning on",
    ),
    (
        "core.filesystem",
        "windows-registry-root",
        CMD,
        "reg delete HKCR /f",
    ),
    (
        "core.filesystem",
        "windows-shadow-copies",
        CMD,
        "vssadmin delete shadows /all",
    ),
    (
        "core.secrets",
        "windows-credential-dump",
        CMD,
        "cmdkey /list",
    ),
    (
        "core.secrets",
        "windows-hive-save",
        CMD,
        "reg save HKLM/SAM x",
    ),
    (
        "core.self",
        "windows-data-dir",
        CMD,
        "setx SAIIFE_DATA_DIR x",
    ),
    ("core.lock", "windows-files", CMD, "takeown /f c:/ /r"),
    ("core.lock", "windows-service", CMD, "sc.exe stop saiifed"),
    (
        "core.lock",
        "windows-claude-policy",
        CMD,
        "reg import policy.reg",
    ),
    (
        "core.lock",
        "windows-audit-group",
        CMD,
        "net localgroup saiife-audit a /add",
    ),
];

fn denied_by(e: &Engine, d: Dialects, cmd: &str) -> Option<(String, String)> {
    match e.evaluate_in(cmd, d) {
        Decision::Deny { pack, pattern, .. } => {
            let id = e.rule_id(&pack, &pattern).unwrap_or("").to_string();
            Some((pack, id))
        }
        _ => None,
    }
}

#[test]
fn each_marked_rule_denies_on_a_windows_load_and_not_on_a_posix_one() {
    let (win, posix) = (engine(PathStyle::Windows), engine(PathStyle::Posix));
    let mut wrong = Vec::new();
    for (pack, rule, dialect, cmd) in ONE_EACH {
        let want = Some((pack.to_string(), rule.to_string()));
        let got = denied_by(&win, *dialect, cmd);
        if got != want {
            wrong.push(format!("windows {cmd:?}: want {want:?}, got {got:?}"));
        }
        // Git Bash on Windows counts: same rules, in the POSIX dialect.
        let bash = win.evaluate(cmd);
        if !bash.is_deny() {
            wrong.push(format!("git bash {cmd:?}: {bash:?}"));
        }
        let linux = posix.evaluate(cmd);
        if linux.is_deny() {
            wrong.push(format!("posix {cmd:?}: {linux:?}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    // Every marked rule with an id is in the table, `core.process` below.
    for (pack, marked) in MARKED {
        for m in marked.iter().filter(|m| m.starts_with("windows-")) {
            assert!(
                ONE_EACH.iter().any(|(p, r, ..)| p == pack && r == m)
                    || *m == "windows-kill-saiife",
                "{pack}/{m} has no row"
            );
        }
    }
}

/// `core.process` is the lazy one, and `kill s*` has a second rule on purpose.
#[test]
fn the_kill_rules_split_as_they_should() {
    let (win, posix) = (engine(PathStyle::Windows), engine(PathStyle::Posix));
    // `core.process` alone: `core.self` comes first and has its own say on names.
    let dev = |style| {
        let (packs, _) = Catalog::builtin_for(style).load_active(&[]);
        let packs: Vec<_> = packs
            .into_iter()
            .filter(|p| p.id == "core.process")
            .collect();
        Engine::new(packs).with_paths(match style {
            PathStyle::Windows => windows_vars(),
            PathStyle::Posix => PathVars::new().with_style(PathStyle::Posix),
        })
    };
    let (win_dev, posix_dev) = (dev(PathStyle::Windows), dev(PathStyle::Posix));
    for e in [&win, &posix] {
        assert!(e.evaluate_in("Stop-Process -Name *", PS).is_deny());
    }
    // A Windows host names the rule it always named.
    assert_eq!(
        denied_by(&win_dev, PS, "Stop-Process -Name sai*"),
        Some(("core.process".into(), "windows-kill-saiife".into()))
    );
    assert_eq!(
        denied_by(&win_dev, CMD, "taskkill /im saiife.exe"),
        Some(("core.process".into(), "windows-kill-saiife".into()))
    );
    assert_eq!(
        denied_by(&posix_dev, PS, "Stop-Process -Name sai*"),
        Some(("core.process".into(), "kill-saiife-name".into()))
    );
    assert!(!posix_dev.evaluate("taskkill /im saiife.exe").is_deny());
}

/// The path rules, by the path a Windows host reads and the same text on POSIX.
#[test]
fn marked_path_rules_apply_on_a_windows_load_only() {
    let (win, posix) = (engine(PathStyle::Windows), engine(PathStyle::Posix));
    for cmd in [
        r"type C:\Users\a\AppData\Roaming\gcloud\x",
        r"type C:\Users\a\AppData\Roaming\Microsoft\Protect\x",
        r"type C:\Windows\System32\config\SAM",
        r"del C:\Users\a\AppData\Local\saiife\audit.jsonl",
        r"del C:\ProgramData\saiife\saiife.exe",
    ] {
        assert!(win.evaluate_in(cmd, CMD).is_deny(), "{cmd}");
    }
    for cmd in [
        "cat /home/a/AppData/Roaming/gcloud/x",
        "cat /home/a/AppData/Roaming/Microsoft/Protect/x",
        "echo x > /home/a/AppData/Local/saiife/x",
    ] {
        assert!(!posix.evaluate(cmd).is_deny(), "{cmd}");
    }
}

/// The production path: a hook loads for the host it runs on. So on this host's
/// CI cell the Windows rules are there or not as the host says.
#[test]
fn the_hooks_own_load_follows_the_host() {
    let (packs, _) = Catalog::builtin().load_active(&["core.lock".to_string()]);
    let has = packs
        .iter()
        .flat_map(|p| p.deny_rules())
        .any(|r| r.id.as_deref() == Some("windows-root-rm"));
    assert_eq!(has, cfg!(windows));
    assert_eq!(PathStyle::host() == PathStyle::Windows, cfg!(windows));
    assert!(packs.iter().all(|p| p.fits(PathStyle::host())));
}

/// A test that forces Windows paths on a pack loaded for POSIX would judge without
/// the rules it means to test, so the engine refuses in every test build.
#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "another host style")]
fn windows_paths_over_a_posix_load_panic() {
    let (packs, _) = builtin_packs_for(PathStyle::Posix);
    let _ = Engine::new(packs).with_paths(windows_vars());
}

#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "another host style")]
fn posix_paths_over_a_windows_load_panic() {
    let (packs, _) = builtin_packs_for(PathStyle::Windows);
    let _ = Engine::new(packs).with_paths(PathVars::new().with_style(PathStyle::Posix));
}
