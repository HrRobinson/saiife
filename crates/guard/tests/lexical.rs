//! The lexical file system view (plan 21, Task 1): under `FsView::Lexical`
//! the guard judges a call with no file system access at all, as the saiife
//! service does when it re-judges a co-signed call.

#[path = "support/corpus.rs"]
mod corpus;

use saiifeguard::canon::{fs_calls_made, with_fs_view, FsView, PathStyle, PathVars};
use saiifeguard::engine::Engine;
use saiifeguard::pathrule::Access;
use saiifeguard::payload::Dialects;
use saiifeguard::profile::select_active;
use saiifeguard::wintable::Dialect;

use corpus::{claude_fixtures, configs, corpus_cases, judge_payload, rehome, Tree};

const BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// The real file system calls made while judging every corpus case and
/// every Claude fixture under `view`, engines included.
fn calls_judging_everything(view: FsView) -> u64 {
    let tree = Tree::new();
    let cases = corpus_cases();
    assert!(cases.len() > 1000, "only {} corpus cases", cases.len());
    let fixtures = claude_fixtures();
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
                let _ = judge_payload(&c.engine, &rehome(payload, &tree.home()));
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

/// A copy target the view cannot see lands as `target/<name>`, as in a
/// directory: never stricter than the host, and the landing is still judged.
#[test]
fn lexical_copy_lands_inside_the_target() {
    let tree = Tree::new();
    let host = default_engine(tree.vars());
    with_fs_view(FsView::Lexical, || {
        let e = default_engine(tree.vars());
        let before = fs_calls_made();
        for cmd in [
            "cp review.md .claude",
            "cp -t .claude review.md",
            "mv -t .claude x",
        ] {
            assert!(!host.evaluate(cmd).is_deny(), "host: {cmd}");
            assert!(!e.evaluate(cmd).is_deny(), "lexical: {cmd}");
        }
        assert!(e.evaluate("cp evil.json .claude/settings.json").is_deny());
        assert!(e.evaluate("cp settings.json .claude").is_deny());
        assert_eq!(fs_calls_made(), before);
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
