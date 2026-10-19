//! Pins the engine's decisions across the `evaluate_inner` split (plan 5a,
//! task 1): every nested path the engine re-enters — `$(…)` as the command
//! and nested, backticks, `bash -c`/`sh -c`, `eval`, here-documents inside
//! `$(…)`, `cd` before path rules, `cd $(…)`, `IFS` on the line, an
//! environment change before a nested agent, and the depth cap.
//!
//! The expected values were recorded with `saiife explain` from the code
//! before the refactor, run in a tempdir laid out like the fixture below.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use saiifeguard::builtins::builtin_packs;
use saiifeguard::canon::PathVars;
use saiifeguard::engine::{AllowTrace, Decision, Engine};
use saiifeguard::profile::select_active;

const TEST_BUDGET: Duration = Duration::from_secs(5);

/// The decision kind a line must keep.
#[derive(Debug)]
enum Want {
    /// Allowed, no rule involved.
    Allow,
    /// Allowed by an allow rule of this pack.
    AllowRule(&'static str),
    /// Denied by this pack, at the top level.
    Deny(&'static str),
    /// Denied by this pack, inside a nested evaluation.
    DenyInline(&'static str),
    /// Allowed as not judged, the reason containing this text.
    Unjudged(&'static str),
}
use Want::*;

const CORPUS: &[(&str, Want)] = &[
    // $(...) as the command, and nested
    ("$(rm -rf /)", DenyInline("core.filesystem")),
    ("$( $(rm -rf /) )", DenyInline("core.filesystem")),
    ("$(git reset --hard)", DenyInline("core.git")),
    ("$(echo hi)", Allow),
    ("FOO=$(rm -rf /)", DenyInline("core.filesystem")),
    ("$(cat .env)", DenyInline("core.secrets")),
    ("$($(cat .env))", DenyInline("core.secrets")),
    ("echo hi && $(rm -rf /)", DenyInline("core.filesystem")),
    ("HOME=$(mktemp -d) && claude -p hi", Deny("core.self")),
    // embedded substitutions
    ("echo $(rm -rf /)", DenyInline("core.filesystem")),
    ("echo \"$(git reset --hard)\"", DenyInline("core.git")),
    ("echo $(date)", Allow),
    ("echo \"$(date)\"", Allow),
    ("echo $(echo $(rm -rf /))", DenyInline("core.filesystem")),
    ("ls $(cat .env)suffix", DenyInline("core.secrets")),
    ("env FOO=$(rm -rf /) ls", DenyInline("core.filesystem")),
    ("FOO=$(date) git reset --hard", Deny("core.git")),
    ("rm -rf $(echo /)", Deny("core.filesystem")),
    ("git status $(echo x)", Allow),
    // backticks
    ("`rm -rf /`", DenyInline("core.filesystem")),
    ("echo `rm -rf /`", DenyInline("core.filesystem")),
    ("echo `date`", Allow),
    ("echo \"`cat .env`\"", DenyInline("core.secrets")),
    // bash -c / sh -c
    ("bash -c 'rm -rf /'", DenyInline("core.filesystem")),
    ("sh -c 'git reset --hard'", DenyInline("core.git")),
    ("sh -c 'echo hi'", Allow),
    ("bash -c \"cat .env\"", DenyInline("core.secrets")),
    ("su -c 'su -c \"rm -rf /\"'", DenyInline("core.filesystem")),
    ("bash -lc 'rm -rf /'", DenyInline("core.filesystem")),
    ("bash -c 'echo hi'; git reset --hard", Deny("core.git")),
    ("watch rm -rf /", DenyInline("core.filesystem")),
    ("sh -c 'cd src && cat .env'", DenyInline("core.secrets")),
    // eval
    ("eval rm -rf /", DenyInline("core.filesystem")),
    ("eval 'git reset --hard'", DenyInline("core.git")),
    ("eval -- cat .env", DenyInline("core.secrets")),
    ("eval echo hi", Allow),
    ("eval \"$(echo hi)\"", Allow),
    ("eval $(date)", Unjudged("eval of a command substitution cannot be judged")),
    // here-documents inside $(...)
    ("git commit -m \"$(cat <<'EOF'\nfix(guard): keep commits working\n\nBody line with .env and rm -rf mentioned.\n\nCo-Authored-By: Claude <noreply@anthropic.com>\nEOF\n)\"", Allow),
    ("git tag -a v1 -m \"$(cat <<'EOF'\nrelease\nEOF\n)\"", Allow),
    ("cat \"$(cat <<'EOF'\n.env\nEOF\n)\"", Deny("core.secrets")),
    ("rm -rf \"$(cat <<'EOF'\n/\nEOF\n)\"", Deny("core.filesystem")),
    ("echo \"$(cat <<'EOF'\nit's\nEOF\n)\"; cat .env", Deny("core.secrets")),
    ("x=$(cat <<'EOF'\n(\nEOF\n)\ncat .env", Deny("core.secrets")),
    ("cat <<EOF\n$(rm -rf /)\nEOF", DenyInline("core.filesystem")),
    ("cat <<'EOF'\n$(rm -rf /)\nEOF", Allow),
    ("echo x > \"$(cat <<'EOF'\n.claude/settings.json\nEOF\n)\"", Deny("core.self")),
    // cd then path rules
    ("cd .. && cat app/.env", Deny("core.secrets")),
    ("cd src && cat .env", Deny("core.secrets")),
    ("cd src && cat ../.env.example", Allow),
    ("cd /nonexistent; cat .env", Deny("core.secrets")),
    ("(cd src); cat .env", Deny("core.secrets")),
    ("cd src; cd /tmp; cat .env", Deny("core.secrets")),
    ("cd ~ && cat .ssh/id_rsa", Deny("core.secrets")),
    ("pushd /tmp; cat .env", Deny("core.secrets")),
    ("cd /tmp && cat notes.txt", Allow),
    // cd $(...) unknown cwd
    ("cd $(x) && cat notes.txt", Unjudged("working directory unknown after cd")),
    ("cd $(x) && cat .env", Deny("core.secrets")),
    ("cd - && cat notes.txt", Unjudged("working directory unknown after cd")),
    ("cd $(git rev-parse --show-toplevel) && cargo test", Allow),
    ("cd $(x) && cat /etc/hosts", Allow),
    ("cd `pwd` && cat notes.txt", Unjudged("working directory unknown after cd")),
    // IFS
    ("IFS=:; rm -f $(echo .saiife:x)", Deny("saiifeguard.core")),
    ("cat $(echo .env) # IFS", Deny("core.secrets")),
    ("IFS=x; cat $(echo .env)", Deny("core.secrets")),
    ("IFS=x; cat $(echo .envx)", Unjudged("IFS is set on this line: substitution values may split differently")),
    ("IFS=x; echo hi > $(echo .claude/settings.jsonx)", Unjudged("IFS is set on this line: substitution values may split differently")),
    ("git commit -m \"$(echo fix IFS)\"", Allow),
    ("IFS=x; echo $(date)", Allow),
    // env change then nested agent
    ("export HOME=/tmp/x; claude -p hi", Deny("core.self")),
    ("export PATH=/tmp/fake; bash -c 'claude -p hi'", DenyInline("core.self")),
    ("HOME=/tmp/x; $(claude -p hi)", DenyInline("core.self")),
    ("export HOME=/tmp/x; eval codex exec fix", DenyInline("core.self")),
    ("export PATH=/tmp/fake; echo $(codex exec fix)", DenyInline("core.self")),
    ("PATH=/tmp/fake:$PATH claude", Deny("core.self")),
    ("HOME=/tmp/x claude -p hi", Deny("core.self")),
    ("export FOO=1; claude -p hi", Allow),
    ("bash -c 'export HOME=/tmp/x; claude -p hi'", DenyInline("core.self")),
    // depth cap
    ("echo $( $( $( $( $( cat .env ) ) ) ) )", DenyInline("core.secrets")),
    ("echo $( $( $( $( $( $( $( $( $( cat .env ) ) ) ) ) ) ) ) )", Unjudged("command substitution nested too deeply to judge")),
    ("echo $( $( $( $( $( $( $( $( $( $( $( $( $( $( $( $( $( $( $( $( echo hi ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) ) )", Unjudged("command substitution nested too deeply to judge")),
    ("$($($($($($($($($(cat .env)))))))))", Unjudged("command substitution nested too deeply to judge")),
    ("$($($($($($($($($($(echo hi))))))))))", Unjudged("command substitution nested too deeply to judge")),
    ("watch watch watch watch watch watch watch watch watch watch cat .env", Unjudged("inline command nested too deeply to judge")),
    ("watch watch watch watch watch watch watch watch watch watch echo hi", Unjudged("inline command nested too deeply to judge")),
    ("eval eval eval eval eval eval eval eval eval eval echo hi", Unjudged("eval nested too deeply to judge")),
    ("bash -c 'bash -c \"rm -rf /\"'", DenyInline("core.filesystem")),
    ("echo \"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(\"$(x)\")\")\")\")\")\")\")\")\")\")\")\")\")\")\")\")\")\")\")\")\")\")\")\")\")\")\")\")\")\")\")\")\")\")\")\")\")\")\")\"", Unjudged("command substitution nested too deeply to judge")),
    // plain
    ("git status", Allow),
    ("rm -rf /", Deny("core.filesystem")),
    ("cat .env", Deny("core.secrets")),
    ("cat .env.example", Allow),
    ("ls -la", Allow),
    ("git reset --hard HEAD~1", AllowRule("core.git")),
    ("bash -c 'git push --force-with-lease'", AllowRule("core.git")),
    ("echo $(git reset --hard HEAD~2)", AllowRule("core.git")),
    ("eval git push origin main --force-with-lease", AllowRule("core.git")),
    ("$(git push --force-with-lease)", AllowRule("core.git")),
];

/// `<tmp>/home` (HOME), `<tmp>/home/app` (working directory and project),
/// `<tmp>/data` (data dir) and `<tmp>/data/audit` (audit dir).
fn engine(root: &std::path::Path) -> Engine {
    let home = root.join("home");
    let app = home.join("app");
    let data = root.join("data");
    for d in [app.join("src"), app.join(".claude"), data.join("audit")] {
        fs::create_dir_all(d).unwrap();
    }
    let vars = PathVars::new()
        .with_cwd(&app)
        .with_var("HOME", &home)
        .with_var("PROJECT", &app)
        .with_var("SAIIFE_DATA_DIR", &data)
        .with_var("SAIIFE_AUDIT_DIR", data.join("audit"));
    let (packs, warnings) = builtin_packs();
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    Engine::new(select_active(packs, &[]))
        .with_paths(vars)
        .with_budget(TEST_BUDGET)
}

fn matches(want: &Want, got: &Decision) -> bool {
    match (want, got) {
        (
            Allow,
            Decision::Allow {
                trace: AllowTrace::NoMatch,
            },
        ) => true,
        (
            AllowRule(p),
            Decision::Allow {
                trace: AllowTrace::AllowRule { pack, .. },
            },
        ) => pack == p,
        (
            Deny(p),
            Decision::Deny {
                pack,
                via_inline: None,
                ..
            },
        ) => pack == p,
        (
            DenyInline(p),
            Decision::Deny {
                pack,
                via_inline: Some(_),
                ..
            },
        ) => pack == p,
        (
            Unjudged(r),
            Decision::Allow {
                trace: AllowTrace::Unjudgeable { reason },
            },
        ) => reason.contains(r),
        _ => false,
    }
}

#[test]
fn refactor_equivalence_corpus() {
    assert!(CORPUS.len() >= 60);
    let dir = tempfile::tempdir().unwrap();
    let root: PathBuf = fs::canonicalize(dir.path()).unwrap();
    let e = engine(&root);
    let wrong: Vec<String> = CORPUS
        .iter()
        .filter_map(|(cmd, want)| {
            let got = e.evaluate(cmd);
            (!matches(want, &got)).then(|| format!("{cmd:?}: want {want:?}, got {got:?}"))
        })
        .collect();
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
