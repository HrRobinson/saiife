//! Running out of the latency budget is not a way past the rules. The segments
//! left when it runs out still get the pack rules and the path rules, symlinks and
//! globs included, for a fixed count of system calls. A deny found there is a deny;
//! only when nothing denies does the line stay `FailedOpenTimeout`.
//!
//! A zero budget takes that path without reading a clock: the first check
//! fails, whatever the machine's speed.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use saiifeguard::builtins::builtin_packs;
use saiifeguard::canon::PathVars;
use saiifeguard::engine::{AllowTrace, Decision, Engine};
use saiifeguard::profile::select_active;

const KB: usize = 1024;

/// The part repeated and the size of the padding. The first group failed open
/// on the branch that first judged them, the second came close to it, and the
/// third is slow on main too.
const SHAPES: &[(&str, usize)] = &[
    // Blocking: 240 repeats of each.
    ("! cd x; ", 240 * 8),
    ("if cd x; then ", 240 * 14),
    ("while cd x; do ", 240 * 15),
    ("$v cd x; ", 240 * 9),
    // Near the budget.
    ("$v > f ", 20 * KB),
    ("$v eval ", 40 * KB),
    ("$(true) ", 160 * KB),
    // On main too.
    ("cd x; ", 240 * 6),
    ("> f ", 10 * KB),
    ("eval ", 40 * KB),
    ("cat <<A ", 40 * KB),
];

/// A fake home and project, and the default profile as `saiife check` builds it.
struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        fs::create_dir_all(root.join("home/app")).unwrap();
        fs::create_dir_all(root.join("home/.ssh")).unwrap();
        fs::write(root.join("home/app/.env"), "x").unwrap();
        fs::write(root.join("home/.ssh/id_rsa"), "x").unwrap();
        Fixture { _dir: dir, root }
    }

    fn engine(&self, budget: Duration) -> Engine {
        let (packs, warnings) = builtin_packs();
        assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
        Engine::new(select_active(packs, &[]))
            .with_budget(budget)
            .with_paths(
                PathVars::new()
                    .with_cwd(self.root.join("home/app"))
                    .with_var("HOME", self.root.join("home"))
                    .with_var("PROJECT", self.root.join("home/app")),
            )
    }
}

fn padded(part: &str, size: usize, tail: &str) -> String {
    format!("{}x; {tail}", part.repeat(size / part.len()))
}

fn timeout() -> Decision {
    Decision::Allow {
        trace: AllowTrace::FailedOpenTimeout,
    }
}

/// The pack of the deny, or a description of what came instead.
fn denied_by(e: &Engine, cmd: &str) -> Result<String, String> {
    match e.evaluate(cmd) {
        Decision::Deny { pack, pattern, .. } => {
            assert!(!pattern.is_empty(), "a deny names its rule");
            Ok(pack)
        }
        other => Err(format!("{other:?}")),
    }
}

#[test]
fn a_rule_at_the_end_of_a_padded_line_denies_with_no_budget() {
    let f = Fixture::new();
    let e = f.engine(Duration::ZERO);
    let mut misses = Vec::new();
    for (part, size) in SHAPES {
        for (tail, pack) in [
            ("rm -rf /", "core.filesystem"),
            ("cat .env", "core.secrets"),
        ] {
            let line = padded(part, *size, tail);
            match denied_by(&e, &line) {
                Ok(p) if p == pack => {}
                got => misses.push(format!("{part:?} + {tail}: {got:?}")),
            }
        }
    }
    assert!(misses.is_empty(), "not denied:\n{}", misses.join("\n"));
}

#[test]
fn a_rule_alone_denies_with_no_budget() {
    let f = Fixture::new();
    let e = f.engine(Duration::ZERO);
    for (cmd, pack) in [
        ("rm -rf /", "core.filesystem"),
        ("cat .env", "core.secrets"),
        ("cat ../app/.env", "core.secrets"),
        ("echo x; rm -rf /", "core.filesystem"),
        ("! rm -rf /", "core.filesystem"),
        ("$v rm -rf /", "core.filesystem"),
        // Nested lines are judged the same way.
        ("$(rm -rf /)", "core.filesystem"),
        ("echo $(cat .env)", "core.secrets"),
        ("bash -c 'rm -rf /'", "core.filesystem"),
        ("eval 'cat .env'", "core.secrets"),
        ("eval eval 'rm -rf /'", "core.filesystem"),
    ] {
        assert_eq!(denied_by(&e, cmd).as_deref(), Ok(pack), "{cmd}");
    }
}

#[test]
fn nothing_denied_stays_a_recorded_timeout() {
    let f = Fixture::new();
    let e = f.engine(Duration::ZERO);
    for cmd in [
        "ls",
        "git status && ls -la",
        "echo $(date)",
        "cat README.md",
    ] {
        assert_eq!(e.evaluate(cmd), timeout(), "{cmd}");
    }
    for (part, size) in SHAPES {
        let line = padded(part, *size, "ls");
        assert_eq!(e.evaluate(&line), timeout(), "{part:?}");
    }
}

/// With time to spare the same lines are denied by the same rules, and the
/// padding is allowed: the zero-budget verdict adds nothing of its own.
#[test]
fn the_verdict_with_no_budget_agrees_with_the_full_one() {
    let f = Fixture::new();
    let e = f.engine(Duration::from_secs(60));
    for (part, size) in SHAPES {
        for (tail, pack) in [
            ("rm -rf /", "core.filesystem"),
            ("cat .env", "core.secrets"),
        ] {
            let line = padded(part, *size, tail);
            assert_eq!(denied_by(&e, &line).as_deref(), Ok(pack), "{part:?} {tail}");
        }
        assert!(
            !e.evaluate(&padded(part, *size, "ls")).is_deny(),
            "{part:?}"
        );
    }
}

/// `cd` is followed with no budget.
#[test]
fn a_cd_is_followed_with_no_budget() {
    let f = Fixture::new();
    let e = f.engine(Duration::ZERO);
    for cmd in ["cd ~/.ssh; cat id_rsa", "cd ../.ssh && cat id_rsa"] {
        assert_eq!(denied_by(&e, cmd).as_deref(), Ok("core.secrets"), "{cmd}");
    }
}

/// Whether a copy's target is a directory takes the filesystem, so the cheap
/// pass judges it both ways.
#[test]
fn a_copy_target_is_judged_both_ways_with_no_budget() {
    let f = Fixture::new();
    let cheap = f.engine(Duration::ZERO);
    let full = f.engine(Duration::from_secs(60));
    for cmd in [
        "cp /tmp/empty.json ~/.claude/settings.json",
        "cp /tmp/x .saiife/config.toml",
        "cp review.md .claude",
        "ln -s /tmp/u ~/.config/systemd",
        "mv /tmp/s ~/.config/systemd",
    ] {
        assert!(full.evaluate(cmd).is_deny(), "{cmd}");
        assert_eq!(
            denied_by(&cheap, cmd).as_deref(),
            denied_by(&full, cmd).as_deref(),
            "{cmd}"
        );
        let line = padded("$(true) ", 8 * KB, cmd);
        assert!(cheap.evaluate(&line).is_deny(), "padded {cmd}");
    }
    // A copy to nowhere special stays what it was, and a trailing slash or a
    // `-t` says the target is a directory, so only what lands in it is judged.
    for cmd in [
        "cp a b",
        "mv a b/",
        "cp review.md .claude/",
        "mv notes.md .claude/",
        "cp -r docs .claude/",
        "cp -t .claude review.md",
        "mv -t .claude x",
    ] {
        assert!(!full.evaluate(cmd).is_deny(), "{cmd}");
        assert_eq!(cheap.evaluate(cmd), timeout(), "{cmd}");
    }
}

/// A project holding a link to `.env` and a link to the directory of the keys.
#[cfg(unix)]
fn with_links() -> Fixture {
    let f = Fixture::new();
    let app = f.root.join("home/app");
    std::os::unix::fs::symlink(".env", app.join("link")).unwrap();
    std::os::unix::fs::symlink("../.ssh", app.join("keys")).unwrap();
    std::os::unix::fs::symlink("notes.md", app.join("plain")).unwrap();
    fs::write(app.join("notes.md"), "x").unwrap();
    fs::create_dir_all(app.join(".claude")).unwrap();
    std::os::unix::fs::symlink(".claude", app.join("conf")).unwrap();
    f
}

/// What only the filesystem can name, each denied on main: padding that main
/// skips must not spend the budget and leave these to a look that cannot see it.
#[cfg(unix)]
const NAMED_BY_THE_FILESYSTEM: &[&str] = &[
    "cat link",
    "cat .en*",
    "cat .en?",
    "cat .e[n]v",
    "cat keys/id_rsa",
    "cat kez*/id_rsa ke?s/id_rsa",
    "cd keys; cat id_rsa",
    "cd keys && cat id*",
    "! cd keys; cat id_rsa",
    "cat < link",
    "cp link /tmp/out",
    "echo x > conf/settings.json",
    "cp /tmp/settings.json conf",
];

/// The padding of the finding: main skips the rest of the segment after `$(true)`.
#[cfg(unix)]
fn behind_the_padding(tail: &str) -> String {
    format!("<{}>x; {tail}", "$(true) X=1 ".repeat(20_000))
}

/// The last look follows symlinks and expands globs, with no budget at all.
#[cfg(unix)]
#[test]
fn the_last_look_follows_symlinks_and_globs() {
    let f = with_links();
    let mut wrong = Vec::new();
    for budget in [Duration::ZERO, Duration::from_secs(60)] {
        let e = f.engine(budget);
        for tail in NAMED_BY_THE_FILESYSTEM {
            for line in [tail.to_string(), behind_the_padding(tail)] {
                let got = e.evaluate(&line);
                if !got.is_deny() {
                    let shown: String = line.chars().rev().take(40).collect();
                    wrong.push(format!("{budget:?} {tail:?} …{shown:?}: {got:?}"));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "not denied:\n{}", wrong.join("\n"));
}

/// Every padding of `SHAPES` in front of them, with no budget.
#[cfg(unix)]
#[test]
fn every_padding_leaves_the_filesystem_to_the_last_look() {
    let f = with_links();
    let e = f.engine(Duration::ZERO);
    let mut wrong = Vec::new();
    for (part, size) in SHAPES {
        for tail in ["cat link", "cat .en*", "cat keys/id_rsa"] {
            let got = e.evaluate(&padded(part, *size, tail));
            if !got.is_deny() {
                wrong.push(format!("{part:?} + {tail}: {got:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "not denied:\n{}", wrong.join("\n"));
}

/// A link or a glob to nothing a rule guards stays the timeout it was, and a
/// directory link is judged by where it goes.
#[cfg(unix)]
#[test]
fn what_resolves_to_nothing_guarded_stays_a_recorded_timeout() {
    let f = with_links();
    let e = f.engine(Duration::ZERO);
    for cmd in [
        "cat plain",
        "cat not*",
        "cat missing*",
        "cat keys/nothing",
        "ls keys",
    ] {
        let want = f.engine(Duration::from_secs(60)).evaluate(cmd);
        assert!(!want.is_deny(), "{cmd}: {want:?}");
        assert_eq!(e.evaluate(cmd), timeout(), "{cmd}");
        assert_eq!(
            e.evaluate(&behind_the_padding(cmd)),
            timeout(),
            "padded {cmd}"
        );
    }
}

/// `pwsh` on a POSIX host reads the line itself, and the same look follows it.
#[cfg(unix)]
#[test]
fn the_last_look_follows_them_under_a_reader() {
    use saiifeguard::payload::Dialects;
    use saiifeguard::wintable::Dialect::PowerShell;
    let f = with_links();
    let e = f.engine(Duration::ZERO);
    for cmd in ["Get-Content link", "Get-Content .en*", "gc keys/id_rsa"] {
        let got = e.evaluate_call(cmd, Dialects::One(PowerShell));
        assert!(got.is_deny(), "{cmd}: {got:?}");
    }
}
