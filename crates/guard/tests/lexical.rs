//! The lexical file system view (plan 21, Task 1): under `FsView::Lexical`
//! the guard judges a call with no file system access at all, as the saiife
//! service does when it re-judges a co-signed call.
//!
//! A POSIX engine is checked against a POSIX tree on disk, so those tests are
//! Unix only (on Windows the tree is `\\?\D:\…`, no POSIX path); the Windows
//! engine's checks run on every host.

#[path = "support/corpus.rs"]
mod corpus;

#[cfg(unix)]
use saiifeguard::canon::PathStyle;
use saiifeguard::canon::{fs_calls_made, with_fs_view, FsView, PathVars};
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

/// A glob matches nothing, so it is judged as spelled: as the host judges it
/// in a project where it matches nothing. (`cat .env*` with a `.env` on disk
/// is the hook's to deny; the lexical view is never stricter, not as strict.)
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
    let cmds = [
        "cat .env*",
        "cat *.txt",
        "ls src/**/*.rs",
        "cat ~/.ssh/id_*",
    ];
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
