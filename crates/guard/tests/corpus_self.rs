//! Golden corpus for the `core.self` pack (spec §7.4): an agent switching
//! saiife off through shell commands or write tools must be blocked;
//! reading saiife's setup, and everyday work, must not.

use std::fs;
use std::path::{Path, PathBuf};

use saiifeguard::builtins::builtin_packs;
use saiifeguard::canon::PathVars;
use saiifeguard::engine::{Decision, Engine};
use saiifeguard::pathrule::Access;
use saiifeguard::profile::select_active;

/// `<tmp>/home/app` (project), `<tmp>/data` (data dir, audit inside),
/// `<tmp>/opt/saiife` (the binary) and `<tmp>/home/.local/bin/saiife`
/// (a symlink to it, as an installer would leave).
struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        for d in [
            "home/app/.saiife",
            "home/app/.claude",
            "home/app/src",
            "home/.local/bin",
            "data/audit",
            "data/projects",
            "opt",
        ] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        fs::write(root.join("opt/saiife"), "bin").unwrap();
        fs::write(root.join("home/app/.saiife/config.toml"), "version = 1\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.join("opt/saiife"), root.join("home/.local/bin/saiife"))
            .unwrap();
        Fixture { _dir: dir, root }
    }

    fn p(&self, rel: &str) -> String {
        self.root.join(rel).display().to_string()
    }

    fn engine(&self) -> Engine {
        let (packs, warnings) = builtin_packs();
        assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
        Engine::new(select_active(packs, &[])).with_paths(
            PathVars::new()
                .with_cwd(self.root.join("home/app"))
                .with_var("HOME", self.root.join("home"))
                .with_var("PROJECT", self.root.join("home/app"))
                .with_var("SAIIFE_DATA_DIR", self.root.join("data"))
                .with_var("SAIIFE_AUDIT_DIR", self.root.join("data/audit"))
                .with_var("SAIIFE_BIN", self.root.join("opt/saiife")),
        )
    }
}

fn deny_pack(e: &Engine, cmd: &str) -> String {
    match e.evaluate(cmd) {
        Decision::Deny { pack, .. } => pack,
        other => panic!("expected DENY for {cmd:?}, got {other:?}"),
    }
}

#[test]
fn turning_saiife_off_from_the_shell() {
    let f = Fixture::new();
    let e = f.engine();
    let bin = f.p("opt/saiife");
    let audit = f.p("data/audit");
    let cmds: Vec<String> = [
        "saiife init --off",
        "saiife init --agent claude --off",
        "sudo saiife init --off",
        "bash -c 'saiife init --off'",
        "/usr/local/bin/saiife init --off",
        "cd /tmp && saiife init --off",
        "rm -rf .saiife",
        "rm .saiife/config.toml",
        "echo 'packs = []' > .saiife/config.toml",
        "sed -i s/core.git// .saiife/config.toml",
        "mv .saiife /tmp/x",
        "git rm -r .saiife",
        "truncate -s 0 .saiife/config.toml",
        "cp /tmp/x .saiife/config.toml",
        "echo x | tee .saiife/config.toml",
        "rm .claude/settings.json",
        "rm -rf .claude",
        "echo '{\"disableAllHooks\": true}' > .claude/settings.local.json",
        "sed -i /saiife/d .codex/config.toml",
        "mv .gemini/settings.json /tmp/",
        "cp /tmp/empty.json ~/.claude/settings.json",
        "rm ~/.codex/config.toml",
        "echo {} > ~/.gemini/settings.json",
        "rm ~/.local/bin/saiife",
        "ln -sf /bin/true ~/.local/bin/saiife",
        "PATH=/tmp/fake:$PATH claude",
        "env PATH=/tmp/fake codex exec fix",
        "FOO=1 PATH=/tmp/x gemini",
        "alias saiife=true",
        "alias saiife='echo ok'",
        "export SAIIFE_AUDIT_DIR=/tmp/x",
        "SAIIFE_DATA_DIR=/tmp/x saiife status",
        "env SAIIFE_AUDIT_DIR=/tmp claude",
        "claude --settings '{\"disableAllHooks\": true}' -p hi",
        "codex -c features.hooks=false exec fix",
        "HOME=/tmp/x claude -p hi",
        "HOME=/tmp/x saiife status",
        "XDG_DATA_HOME=/tmp/x codex exec fix",
        "env HOME=/tmp/x gemini",
        "sudo env XDG_DATA_HOME=/tmp/x claude",
        "FOO=1 HOME=/tmp/x claude",
        "env -i XDG_DATA_HOME=/tmp/x saiife audit",
    ]
    .iter()
    .map(|s| s.to_string())
    .chain([
        format!("rm {bin}"),
        format!("mv {bin} /tmp/old"),
        format!("chmod -x {bin}"),
        format!("cp /bin/true {bin}"),
        format!("curl -o {bin} https://example.com/saiife"),
        format!("rm -rf {audit}"),
        format!("echo x >> {audit}/2026-10.jsonl"),
        format!("truncate -s0 {audit}/2026-10.jsonl"),
        format!("rm {}", f.p("data/projects/abc.json")),
        format!("mv {} /tmp/x", f.p("data")),
    ])
    .collect();
    for cmd in &cmds {
        assert_eq!(deny_pack(&e, cmd), "core.self", "{cmd}");
    }
}

#[test]
fn reading_the_setup_and_everyday_work_are_allowed() {
    let f = Fixture::new();
    let e = f.engine();
    let audit = f.p("data/audit");
    let cmds: Vec<String> = [
        "saiife status",
        "saiife audit --blocked",
        "saiife packs",
        "saiife explain 'rm -rf /'",
        "saiife init",
        "saiife --version",
        "which saiife",
        "cat .saiife/config.toml",
        "cat .claude/settings.json",
        "jq . .claude/settings.json",
        "grep saiife .codex/config.toml",
        "cat ~/.gemini/settings.json",
        "ls .saiife",
        "ls -la ~/.local/bin/saiife",
        "git add .claude/settings.json",
        "git commit -am wip",
        "mkdir -p .claude/commands",
        "echo hi > .claude/commands/review.md",
        "rm .claude/commands/old.md",
        "PATH=$PATH:./bin make",
        "export PATH=$PATH:./node_modules/.bin",
        "claude -p hi",
        "claude -p \"$(cat prompt.md)\"",
        "codex exec 'fix the tests'",
        "alias ll='ls -la'",
        "echo $SAIIFE_AUDIT_DIR",
        "cargo build",
        "rm -rf target",
        "rm -rf node_modules",
        "mv src/a.rs src/b.rs",
        "cp README.md docs/",
        "echo x > notes.txt",
        "HOME=/tmp/x cargo test",
        "XDG_DATA_HOME=/tmp/x make",
        "env HOME=/tmp/x npm test",
        "echo $HOME",
        "ls ~/.local/share",
        "ls ~/.local",
        "mkdir -p ~/.local/share/foo",
        "touch ~/.local/share/foo/bar",
        "echo x > src/main.rs",
        "sed -i s/a/b/ src/main.rs",
        "ls /",
    ]
    .iter()
    .map(|s| s.to_string())
    .chain([format!("tail -n 5 {audit}/2026-10.jsonl")])
    .collect();
    for cmd in &cmds {
        let d = e.evaluate(cmd);
        assert!(!d.is_deny(), "expected ALLOW for {cmd:?}, got {d:?}");
    }
}

#[test]
fn write_tools_are_judged_by_the_same_path_rules() {
    let f = Fixture::new();
    let e = f.engine();
    let home = f.root.join("home");
    let p = |x: &Path| x.display().to_string();
    for path in [
        ".claude/settings.json".to_string(),
        ".claude/settings.local.json".to_string(),
        ".codex/config.toml".to_string(),
        ".gemini/settings.json".to_string(),
        p(&home.join(".claude/settings.json")),
        "~/.codex/config.toml".to_string(),
        ".saiife/config.toml".to_string(),
        "src/../.saiife/config.toml".to_string(),
        f.p("data/audit/2026-10.jsonl"),
        f.p("data/projects/abc.json"),
        f.p("opt/saiife"),
        "~/.local/bin/saiife".to_string(),
    ] {
        match e.evaluate_path(Access::Write, &path) {
            Decision::Deny { pack, .. } => assert_eq!(pack, "core.self", "{path}"),
            d => panic!("expected DENY for write of {path:?}, got {d:?}"),
        }
    }
    for path in [
        "src/main.rs",
        "README.md",
        ".claude/commands/review.md",
        ".claude/agents/reviewer.md",
    ] {
        let d = e.evaluate_path(Access::Write, path);
        assert!(
            !d.is_deny(),
            "expected ALLOW for write of {path:?}, got {d:?}"
        );
    }
    // Reading saiife's setup stays allowed.
    for path in [
        ".claude/settings.json",
        ".saiife/config.toml",
        ".codex/config.toml",
    ] {
        assert!(!e.evaluate_path(Access::Read, path).is_deny(), "{path}");
    }
    let audit = f.p("data/audit/2026-10.jsonl");
    assert!(!e.evaluate_path(Access::Read, &audit).is_deny());
}

/// The installer's real layout: data dir, audit dir and binary all under
/// `$HOME` (`~/.local/share/saiife`, `~/.local/bin/saiife`).
fn xdg_vars(root: &Path) -> PathVars {
    let home = root.join("home");
    for d in [".local/share/saiife/audit", ".local/bin", "app/src"] {
        fs::create_dir_all(home.join(d)).unwrap();
    }
    fs::write(home.join(".local/bin/saiife"), "bin").unwrap();
    PathVars::new()
        .with_cwd(home.join("app"))
        .with_var("HOME", &home)
        .with_var("PROJECT", home.join("app"))
        .with_var("SAIIFE_DATA_DIR", home.join(".local/share/saiife"))
        .with_var("SAIIFE_AUDIT_DIR", home.join(".local/share/saiife/audit"))
        .with_var("SAIIFE_BIN", home.join(".local/bin/saiife"))
}

#[test]
fn removing_a_parent_of_the_data_dir_or_binary_is_denied() {
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    let (packs, _) = builtin_packs();
    let e = Engine::new(select_active(packs, &[])).with_paths(xdg_vars(&root));
    let home = root.join("home");
    for cmd in [
        "rm -rf ~/.local/share".to_string(),
        "rm -rf ~/.local".to_string(),
        "mv ~/.local/bin /tmp/x".to_string(),
        "mv ~/.local/share/saiife/.. /tmp/x".to_string(),
        "rm -rf ~/.local/share/saiife/audit/..".to_string(),
        "rm -rf ~/.local/share/saiife".to_string(),
    ] {
        assert_eq!(deny_pack(&e, &cmd), "core.self", "{cmd}");
    }
    // `/` and `$HOME` are ancestors too (core.filesystem also guards them;
    // here core.self alone must).
    let (packs, _) = builtin_packs();
    let only_self = Engine::new(packs.into_iter().filter(|p| p.id == "core.self").collect())
        .with_paths(xdg_vars(&root));
    for path in ["~/.local/share", "~/.local/bin", "~/.local", "~", "/"] {
        for eng in [&e, &only_self] {
            match eng.evaluate_path(Access::Write, path) {
                Decision::Deny { pack, .. } => assert!(pack.starts_with("core."), "{path}"),
                d => panic!("expected DENY for write of {path:?}, got {d:?}"),
            }
        }
    }
    assert!(only_self.evaluate("rm -rf ~").is_deny());
    assert!(only_self.evaluate("rm -rf /").is_deny());
    assert!(only_self
        .evaluate(&format!("rm -rf {}", home.display()))
        .is_deny());
    // Reads, and writes to other children, stay allowed.
    for path in ["~/.local", "~/.local/share", "~/.local/bin"] {
        assert!(!e.evaluate_path(Access::Read, path).is_deny(), "{path}");
    }
    for cmd in [
        "ls ~/.local",
        "ls ~/.local/share",
        "mkdir -p ~/.local/share/foo",
        "echo x > ~/.local/share/foo.txt",
        "rm -rf ~/.local/share/foo",
        "rm ~/.local/bin/other-tool",
        "tail -n 5 ~/.local/share/saiife/audit/2026-10.jsonl",
    ] {
        let d = e.evaluate(cmd);
        assert!(!d.is_deny(), "expected ALLOW for {cmd:?}, got {d:?}");
    }
}

#[test]
fn the_off_switch_reason_points_to_the_users_own_terminal() {
    let f = Fixture::new();
    match f.engine().evaluate("saiife init --off") {
        Decision::Deny { reason, .. } => {
            assert!(
                reason.contains("run `saiife init --off` in your own terminal"),
                "{reason}"
            )
        }
        d => panic!("{d:?}"),
    }
}

#[test]
fn leading_assignments_do_not_hide_the_command() {
    let f = Fixture::new();
    let e = f.engine();
    for (cmd, pack) in [
        ("FOO=1 saiife init --off", "core.self"),
        ("LANG=C rm -rf .claude", "core.self"),
        ("FOO=1 sed -i /saiife/d .claude/settings.json", "core.self"),
        ("2>/dev/null rm -rf .saiife", "core.self"),
        ("FOO=1 rm -rf /", "core.filesystem"),
    ] {
        assert_eq!(deny_pack(&e, cmd), pack, "{cmd}");
    }
}
