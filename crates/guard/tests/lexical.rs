//! The lexical file system view (plan 21, Task 1): under `FsView::Lexical`
//! the guard judges a call with no file system access at all, as the saiife
//! service does when it re-judges a co-signed call.
//!
//! A POSIX engine is checked against a POSIX tree on disk, so those tests are
//! Unix only (on Windows the tree is `\\?\D:\…`, no POSIX path); the Windows
//! engine's checks run on every host.

#[path = "support/corpus.rs"]
mod corpus;

use saiifeguard::canon::{fs_calls_made, with_fs_view, FsView, PathStyle, PathVars};
use saiifeguard::engine::Engine;
use saiifeguard::pathrule::Access;
use saiifeguard::payload::Dialects;
use saiifeguard::profile::select_active;
use saiifeguard::wintable::Dialect;

#[cfg(unix)]
use corpus::{claude_fixtures, rehome};
use corpus::{configs, corpus_cases, fixtures_in, judge_payload, Tree};

const BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// The real file system calls made while judging every corpus case and
/// every Claude fixture under `view`, engines included.
fn calls_judging_everything(view: FsView) -> u64 {
    let tree = Tree::new();
    let cases = corpus_cases();
    assert!(cases.len() > 1000, "only {} corpus cases", cases.len());
    let fixtures = fixtures_in(&tree);
    with_fs_view(view, || {
        let before = fs_calls_made();
        for c in configs(&tree) {
            for cmd in &cases {
                for d in &c.dialects {
                    let _ = c.engine.evaluate_call(cmd, *d);
                }
                let _ = c.engine.evaluate_path(Access::Read, cmd);
                let _ = c.engine.evaluate_path(Access::Write, cmd);
            }
            for (_, payload) in &fixtures {
                let _ = judge_payload(&c.engine, payload);
            }
        }
        fs_calls_made() - before
    })
}

#[test]
fn lexical_makes_no_fs_call() {
    assert_eq!(calls_judging_everything(FsView::Lexical), 0);
    // The meter sees the host's calls, so the zero above means something.
    assert!(calls_judging_everything(FsView::Host) > 0);
}

#[test]
fn the_view_is_scoped_and_host_is_the_default() {
    assert_eq!(saiifeguard::canon::fs_view(), FsView::Host);
    with_fs_view(FsView::Lexical, || {
        assert_eq!(saiifeguard::canon::fs_view(), FsView::Lexical);
        with_fs_view(FsView::Host, || {
            assert_eq!(saiifeguard::canon::fs_view(), FsView::Host)
        });
        assert_eq!(saiifeguard::canon::fs_view(), FsView::Lexical);
        // Another thread keeps its own view.
        std::thread::spawn(|| assert_eq!(saiifeguard::canon::fs_view(), FsView::Host))
            .join()
            .unwrap();
    });
    assert_eq!(saiifeguard::canon::fs_view(), FsView::Host);
    // A panic inside the scope does not leave the thread lexical.
    let _ = std::panic::catch_unwind(|| with_fs_view(FsView::Lexical, || panic!("in scope")));
    assert_eq!(saiifeguard::canon::fs_view(), FsView::Host);
}

fn default_engine(vars: PathVars) -> Engine {
    let (packs, warnings) = saiifeguard::builtins::builtin_packs_for(vars.style());
    assert!(warnings.is_empty(), "{warnings:?}");
    Engine::new(select_active(packs, &[]))
        .with_budget(BUDGET)
        .with_pattern_allowance(std::time::Duration::MAX)
        .with_paths(vars)
}

#[cfg(unix)]
#[test]
fn lexical_symlink_is_literal() {
    let tree = Tree::new();
    let host = default_engine(tree.vars());
    assert!(host.evaluate("cat notes.txt").is_deny());
    with_fs_view(FsView::Lexical, || {
        let vars = tree.vars();
        assert_eq!(
            saiifeguard::canon::canonicalize("notes.txt", None, &vars),
            Some(tree.app().join("notes.txt"))
        );
        let lexical = default_engine(vars);
        let d = lexical.evaluate("cat notes.txt");
        assert!(!d.is_deny(), "{d:?}");
        // Its name is still judged: a link spelled `.env` is a secret.
        assert!(lexical.evaluate("cat .env").is_deny());
        assert!(lexical.evaluate("cat cfg/../.env").is_deny());
    });
}

#[cfg(unix)]
#[test]
fn lexical_home_rules_still_deny() {
    let tree = Tree::new();
    with_fs_view(FsView::Lexical, || {
        let posix = default_engine(tree.vars());
        assert!(posix.evaluate("cat ~/.ssh/id_rsa").is_deny());
        assert!(posix.evaluate("cat $HOME/.ssh/id_rsa").is_deny());
        assert!(posix
            .evaluate_path(Access::Read, "$HOME/.aws/credentials")
            .is_deny());
        let read = format!(
            r#"{{"cwd":"{app}","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{{"file_path":"{home}/.aws/credentials"}}}}"#,
            app = tree.app().display(),
            home = tree.home().display(),
        );
        assert!(judge_payload(&posix, &read).is_deny());
    });
}

/// The Windows half of `lexical_home_rules_still_deny`, on every host: the
/// Windows engine binds a Windows profile and needs no tree on disk.
#[test]
fn lexical_windows_home_rules_still_deny() {
    with_fs_view(FsView::Lexical, || {
        let windows = default_engine(corpus::windows_vars());
        let d = windows.evaluate_in(
            r"type %USERPROFILE%\.ssh\id_rsa",
            Dialects::One(Dialect::Cmd),
        );
        assert!(d.is_deny(), "{d:?}");
        let d = windows.evaluate_in(
            r"Get-Content $env:USERPROFILE\.ssh\id_rsa",
            Dialects::One(Dialect::PowerShell),
        );
        assert!(d.is_deny(), "{d:?}");
        assert!(windows
            .evaluate_path(Access::Read, r"C:\Users\a\.aws\credentials")
            .is_deny());
    });
}

/// A glob the lexical view cannot expand is denied when a path it may expand
/// to is one a rule denies, as the host denies it where such a file exists
/// (`cat .e*` finds `.env`). Otherwise it is judged as spelled: as the host
/// judges it in a project where it matches nothing.
#[cfg(unix)]
#[test]
fn lexical_globs_are_judged_as_spelled() {
    let tree = Tree::new();
    let empty = tempfile::tempdir().unwrap();
    let empty = std::fs::canonicalize(empty.path()).unwrap();
    let host_empty = default_engine(
        PathVars::new()
            .with_style(PathStyle::Posix)
            .with_cwd(&empty)
            .with_var("HOME", &empty),
    );
    let cmds = ["cat *.txt", "ls src/**/*.rs", "cat ~/.ssh/id_*.pub"];
    let host: Vec<bool> = cmds
        .iter()
        .map(|c| host_empty.evaluate(c).is_deny())
        .collect();
    with_fs_view(FsView::Lexical, || {
        let e = default_engine(tree.vars());
        let before = fs_calls_made();
        let lexical: Vec<bool> = cmds.iter().map(|c| e.evaluate(c).is_deny()).collect();
        assert_eq!(lexical, host, "{cmds:?}");
        assert!(e.evaluate("cat .env").is_deny());
        assert!(e.evaluate("cat .env*").is_deny());
        assert!(e.evaluate("cat ~/.ssh/id_*").is_deny());
        assert_eq!(fs_calls_made(), before);
    });
}

/// The lexical gap (owner ruling 2026-11-09, "close it"): a glob whose
/// spelling names no rule but which may expand to a secret. The host expands
/// it on disk and denies; the lexical view now denies it too, with no file
/// system call. A forged hook allow of these met the service's lexical allow.
#[cfg(unix)]
#[test]
fn lexical_globs_that_may_match_a_secret_deny() {
    let tree = Tree::new();
    let gap = [
        "cat .e*",
        "cat ~/.aws/cred*",
        "cat ~/.ssh/id_*",
        "cat .[e]nv",
        "cat ~/.s?h/id_rsa",
        "head -n 3 ./.e?v",
        "grep KEY .en*",
        "cat ~/.*/credentials",
        "cat src/../.e*",
        "cp ~/.ssh/id_* /tmp/",
        "cat .{e,x}*",
    ];
    let host = default_engine(tree.vars());
    for cmd in gap {
        assert!(host.evaluate(cmd).is_deny(), "host: {cmd}");
    }
    with_fs_view(FsView::Lexical, || {
        let e = default_engine(tree.vars());
        let before = fs_calls_made();
        for cmd in gap {
            let d = e.evaluate(cmd);
            assert!(d.is_deny(), "lexical: {cmd}: {d:?}");
        }
        // Not on disk, so only the lexical view denies these.
        for cmd in [
            "cat src/**/.env*",
            "cat ~/.n*rc",
            "cat ~/.config/gcl*/x.json",
        ] {
            let d = e.evaluate(cmd);
            assert!(d.is_deny(), "lexical: {cmd}: {d:?}");
        }
        let d = e.evaluate("cat .e*");
        let saiifeguard::Decision::Deny { pack, reason, .. } = d else {
            panic!("{d:?}")
        };
        assert_eq!(pack, "core.secrets");
        assert!(
            reason.contains("the glob") && reason.contains(".e*"),
            "{reason}"
        );
        assert_eq!(fs_calls_made(), before);
    });
}

/// What a glob cannot reach stays allowed: a wildcard skips a leading `.`
/// as the shell's does, and an `allow_path` carve-out still applies (every
/// match of `id_*.pub` is a public key). These are the honest calls the
/// check must not block (a lexical deny blocks the call in locked mode).
/// `head ./*.pem`: no built-in rule names `*.pem`, so the host allows it too.
#[cfg(unix)]
#[test]
fn lexical_globs_that_cannot_match_a_secret_allow() {
    let tree = Tree::new();
    let fine = [
        "ls *.rs",
        "cat src/*.md",
        "rm target/*.o",
        "cat docs/*",
        "cat *",
        "wc -l src/**/*.rs",
        "cat ~/.ssh/id_*.pub",
        "cat ~/.ssh/*.pub",
        "cat ~/*.txt",
        "head ./*.pem",
        "cat [.]env",
        "cat .e[!n]v",
        "cat build/*/out.log",
        "rm -rf build/*",
    ];
    // The host agrees, except on `cat *`: it finds `notes.txt`, a symlink to
    // a secret, which the lexical view cannot see (A21).
    let host = default_engine(tree.vars());
    for cmd in fine.iter().filter(|c| **c != "cat *") {
        assert!(!host.evaluate(cmd).is_deny(), "host: {cmd}");
    }
    with_fs_view(FsView::Lexical, || {
        let e = default_engine(tree.vars());
        for cmd in fine {
            let d = e.evaluate(cmd);
            assert!(!d.is_deny(), "lexical: {cmd}: {d:?}");
        }
    });
}

/// The check compares a glob with the rules in force, not with a fixed list:
/// with a rule for `*.pem`, `head ./*.pem` may read one, and is denied.
#[cfg(unix)]
#[test]
fn lexical_globs_meet_any_rule_in_force() {
    let tree = Tree::new();
    let mut warnings = Vec::new();
    let pack = saiifeguard::pack::load_pack_str(
        "<t>",
        r#"
[pack]
id = "test.pem"

[[deny_path]]
glob = "**/*.pem"
access = "read"
reason = "keys"
"#,
        &mut warnings,
    )
    .unwrap();
    assert!(warnings.is_empty(), "{warnings:?}");
    with_fs_view(FsView::Lexical, || {
        let e = Engine::new(vec![pack])
            .with_budget(BUDGET)
            .with_pattern_allowance(std::time::Duration::MAX)
            .with_paths(tree.vars());
        assert!(e.evaluate("head ./*.pem").is_deny());
        assert!(e.evaluate("cat certs/s?rver.p*").is_deny());
        assert!(!e.evaluate("head ./*.pem.txt").is_deny());
        assert!(!e.evaluate("rm ./*.pem").is_deny(), "a read rule");
    });
}

/// The Windows engine, on every host: names compare case-folded, and
/// PowerShell's and cmd's `?` and `[…]` match a leading `.`. Their `*` does
/// too, but here it does not stand for one, or every `*.md` could be a
/// `.env.md`: `Get-Content *env` stays the hook's to deny (`globlap`).
#[test]
fn lexical_windows_globs_that_may_match_a_secret_deny() {
    with_fs_view(FsView::Lexical, || {
        let e = default_engine(corpus::windows_vars());
        let before = fs_calls_made();
        for (cmd, dialect) in [
            (r"type %USERPROFILE%\.ssh\id_*", Dialect::Cmd),
            (r"type .E*", Dialect::Cmd),
            (
                r"Get-Content $env:USERPROFILE\.aws\cred*",
                Dialect::PowerShell,
            ),
            (r"Get-Content ?env", Dialect::PowerShell),
        ] {
            let d = e.evaluate_in(cmd, Dialects::One(dialect));
            assert!(d.is_deny(), "{cmd}: {d:?}");
        }
        for (cmd, dialect) in [
            (r"type src\*.md", Dialect::Cmd),
            (r"Get-Content *.rs", Dialect::PowerShell),
            (r"Get-Content *", Dialect::PowerShell),
            (r"Get-Content *env", Dialect::PowerShell),
        ] {
            let d = e.evaluate_in(cmd, Dialects::One(dialect));
            assert!(!d.is_deny(), "{cmd}: {d:?}");
        }
        assert_eq!(fs_calls_made(), before);
    });
}

/// A move or copy target the view cannot see may be a file or a directory,
/// so it is judged as both: `mv evil ~/.aws/credentials` reads and replaces
/// the credentials when they are a file, as the host sees they are.
#[cfg(unix)]
#[test]
fn lexical_target_is_judged_as_the_file_and_the_directory() {
    let tree = Tree::new();
    // A protected name with no extension that is a file here: `**/.codex`
    // may not be written, `.codex/<name>` may.
    std::fs::write(tree.home().join(".codex"), "x").unwrap();
    let host = default_engine(tree.vars());
    let cmds = [
        "mv evil ~/.aws/credentials",
        "mv -f evil ~/.aws/credentials",
        "mv evil/ ~/.aws/credentials",
        "mv a b ~/.aws/credentials",
        "mv evil $HOME/.aws/credentials",
        "mv evil ~/.ssh/id_rsa",
        "mv -T evil ~/.aws/credentials",
        "cp evil ~/.codex",
        "cp -r evil/ ~/.codex",
        "cp -T evil ~/.codex",
        "install evil ~/.codex",
        "ln -sf evil ~/.codex",
        "mv evil ~/.codex",
        "cp evil.json .claude/settings.json",
        "cp settings.json .claude",
    ];
    for cmd in cmds {
        assert!(host.evaluate(cmd).is_deny(), "host: {cmd}");
    }
    with_fs_view(FsView::Lexical, || {
        let e = default_engine(tree.vars());
        let before = fs_calls_made();
        for cmd in cmds {
            let d = e.evaluate(cmd);
            assert!(d.is_deny(), "lexical: {cmd}: {d:?}");
        }
        assert_eq!(fs_calls_made(), before);
    });
}

/// `-t DIR` and `--target-directory[=]DIR` always name a directory, in both
/// views: what lands is `DIR/<name>`, never `DIR` itself.
#[cfg(unix)]
#[test]
fn target_directory_is_a_directory_in_both_views() {
    let tree = Tree::new();
    std::fs::write(tree.home().join(".codex"), "x").unwrap();
    let allowed = [
        "cp -t .claude review.md",
        "cp --target-directory=.claude review.md",
        "cp --target-directory .claude review.md",
        "mv -t .claude x",
        "mv --target-directory=.claude x",
        "install -t .claude x",
        "ln -s -t .claude x",
        // Not `.codex` itself: `cp` refuses a `-t` file.
        "cp -t ~/.codex x",
        "mv -t ~/.aws x",
    ];
    let denied = [
        "cp -t .claude settings.json",
        "mv --target-directory=.claude settings.json",
        "install -t ~/.ssh/x .codex",
        "mv -t ~/.aws x/credentials",
        "ln -t ~/proj/.claude settings.local.json",
        "cp -t ~/.newdir .codex",
    ];
    for view in [FsView::Host, FsView::Lexical] {
        with_fs_view(view, || {
            let e = default_engine(tree.vars());
            for cmd in allowed {
                let d = e.evaluate(cmd);
                assert!(!d.is_deny(), "{view:?}: {cmd}: {d:?}");
            }
            for cmd in denied {
                assert!(e.evaluate(cmd).is_deny(), "{view:?}: {cmd}");
            }
        });
    }
}

/// What the lexical view may deny that the host allows: a copy into a
/// protected directory spelled with no trailing `/` and no `-t`, which the
/// view cannot tell from a copy onto that name (`KNOWN_STRICTER`).
#[cfg(unix)]
#[test]
fn lexical_copy_into_a_bare_protected_directory_is_stricter() {
    let tree = Tree::new();
    let host = default_engine(tree.vars());
    let stricter = ["cp review.md .claude", "mv x .claude"];
    for cmd in stricter {
        assert!(!host.evaluate(cmd).is_deny(), "host: {cmd}");
    }
    with_fs_view(FsView::Lexical, || {
        let e = default_engine(tree.vars());
        for cmd in stricter {
            assert!(e.evaluate(cmd).is_deny(), "lexical: {cmd}");
        }
        for cmd in [
            "cp review.md .claude/",
            "cp -t .claude review.md",
            "cp review.md src",
            "mv x build",
        ] {
            assert!(!e.evaluate(cmd).is_deny(), "lexical: {cmd}");
        }
    });
}

#[test]
fn windows_style_values_are_not_resolved() {
    with_fs_view(FsView::Lexical, || {
        let before = fs_calls_made();
        let vars = corpus::windows_vars();
        assert_eq!(vars.style(), PathStyle::Windows);
        assert!(vars.home().is_some());
        assert_eq!(fs_calls_made(), before);
    });
}

#[cfg(unix)]
#[test]
fn every_fixture_judges_alike_in_both_views_here() {
    // The fixtures name nothing a symlink changes, so both views agree.
    let tree = Tree::new();
    let verdict = |view| {
        with_fs_view(view, || {
            let e = default_engine(tree.vars());
            claude_fixtures()
                .into_iter()
                .map(|(name, p)| (name, judge_payload(&e, &rehome(&p, &tree.home())).is_deny()))
                .collect::<Vec<_>>()
        })
    };
    assert_eq!(verdict(FsView::Host), verdict(FsView::Lexical));
}
