//! The guard corpora as data: every string literal of
//! `crates/guard/tests/corpus_*.rs`, and every Claude Code hook fixture of
//! `crates/cli/tests/fixtures/claude`. Shared by `crates/guard/tests/lexical.rs`
//! and `crates/cli/tests/lexical_corpus.rs` (plan 21, Task 1).
//!
//! The corpora are code, not tables: each pins its cases with its own engine.
//! Taking every literal is a superset of their commands. A literal that is no
//! command (a pack id, a panic message) is judged too, which costs nothing.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use saiifeguard::builtins::builtin_packs_for;
use saiifeguard::canon::{PathStyle, PathVars};
use saiifeguard::engine::{AllowTrace, Decision, Engine};
use saiifeguard::pathrule::Access;
use saiifeguard::payload::{classify_for, Dialects, ToolCall, MAX_PAYLOAD_BYTES};
#[cfg(unix)]
use saiifeguard::profile::select_active;
use saiifeguard::wintable::Dialect;

/// `crates/guard`, from either crate's tests.
fn guard_dir() -> PathBuf {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let guard = here.join("../guard");
    if guard.join("tests").is_dir() {
        guard
    } else {
        here.to_path_buf()
    }
}

/// Every distinct string literal of the guard corpora, in file order.
pub fn corpus_cases() -> Vec<String> {
    let dir = guard_dir().join("tests");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("guard tests dir")
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("corpus_") && n.ends_with(".rs"))
        })
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no corpus files under {}", dir.display());
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for f in files {
        let src = std::fs::read_to_string(&f).expect("corpus file");
        for lit in string_literals(&src) {
            if !lit.trim().is_empty() && lit.len() <= 16 * 1024 && seen.insert(lit.clone()) {
                out.push(lit);
            }
        }
    }
    out
}

/// The Claude Code hook fixtures: `(file name, payload)`, sorted by name.
pub fn claude_fixtures() -> Vec<(String, String)> {
    let dir = guard_dir().join("../cli/tests/fixtures/claude");
    let mut out: Vec<(String, String)> = std::fs::read_dir(&dir)
        .expect("claude fixtures dir")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .map(|p| {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            (name, std::fs::read_to_string(&p).expect("fixture"))
        })
        .collect();
    out.sort();
    assert!(!out.is_empty(), "no fixtures under {}", dir.display());
    out
}

/// A home and a project on disk (`<tmp>/home`, `<tmp>/home/app`) with the
/// files the corpora name, so the host view has something to find: secrets,
/// a symlink to one, and plain files a glob expands to.
pub struct Tree {
    _dir: tempfile::TempDir,
    pub root: PathBuf,
}

impl Tree {
    pub fn new() -> Tree {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let home = root.join("home");
        let app = home.join("app");
        for d in [
            app.join("src"),
            app.join("build"),
            app.join(".claude"),
            app.join(".saiife"),
            home.join(".ssh"),
            home.join(".aws"),
            home.join(".config/gcloud"),
            root.join("secrets"),
        ] {
            std::fs::create_dir_all(d).unwrap();
        }
        for f in [
            app.join(".env"),
            app.join(".env.example"),
            app.join("README.md"),
            app.join("a.txt"),
            app.join("b.txt"),
            app.join("src/main.rs"),
            app.join(".claude/settings.json"),
            home.join(".ssh/id_rsa"),
            home.join(".ssh/id_rsa.pub"),
            home.join(".ssh/config"),
            home.join(".aws/credentials"),
            root.join("secrets/.env"),
        ] {
            std::fs::write(f, "x").unwrap();
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.join("secrets/.env"), app.join("notes.txt")).unwrap();
            std::os::unix::fs::symlink(root.join("secrets"), app.join("cfg")).unwrap();
        }
        Tree { _dir: dir, root }
    }

    pub fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    pub fn app(&self) -> PathBuf {
        self.home().join("app")
    }

    /// The tree's path variables, as the hook binds them.
    pub fn vars(&self) -> PathVars {
        PathVars::new()
            .with_style(PathStyle::Posix)
            .with_cwd(self.app())
            .with_var("HOME", self.home())
            .with_var("PROJECT", self.app())
    }
}

impl Default for Tree {
    fn default() -> Self {
        Tree::new()
    }
}

const BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// One engine the corpora are judged with, and the readings it is asked.
pub struct Config {
    pub name: &'static str,
    pub engine: Engine,
    pub dialects: Vec<Dialects>,
}

/// The engines the corpora are compared under. Build them inside the view
/// they judge in: `PathVars` resolves its values when they are bound.
/// - `posix-default`: the default-on packs, POSIX, bound to `tree`;
/// - `posix-all`: every POSIX built-in pack, bound to `tree`;
/// - `windows-all`: every Windows built-in pack, a Windows profile, read by
///   PowerShell, cmd and the strictest of PowerShell and POSIX.
///
/// The POSIX engines are Unix only: their tree must be a POSIX path, and on
/// Windows the tree is `\\?\D:\…` (a POSIX engine judges POSIX paths, which a
/// Windows host's file system does not hold). `windows-all` runs everywhere.
pub fn configs(tree: &Tree) -> Vec<Config> {
    let mut out = Vec::new();
    #[cfg(unix)]
    {
        let posix = |enabled: bool| {
            let (packs, warnings) = builtin_packs_for(PathStyle::Posix);
            assert!(warnings.is_empty(), "{warnings:?}");
            let packs = if enabled {
                packs
            } else {
                select_active(packs, &[])
            };
            Engine::new(packs)
                .with_budget(BUDGET)
                .with_pattern_allowance(std::time::Duration::MAX)
                .with_paths(tree.vars())
        };
        out.push(Config {
            name: "posix-default",
            engine: posix(false),
            dialects: vec![Dialects::One(Dialect::Posix)],
        });
        out.push(Config {
            name: "posix-all",
            engine: posix(true),
            dialects: vec![Dialects::One(Dialect::Posix)],
        });
    }
    #[cfg(not(unix))]
    let _ = tree;
    let (wpacks, warnings) = builtin_packs_for(PathStyle::Windows);
    assert!(warnings.is_empty(), "{warnings:?}");
    let windows = Engine::new(wpacks)
        .with_budget(BUDGET)
        .with_pattern_allowance(std::time::Duration::MAX)
        .with_paths(windows_vars());
    out.push(Config {
        name: "windows-all",
        engine: windows,
        dialects: vec![
            Dialects::One(Dialect::PowerShell),
            Dialects::One(Dialect::Cmd),
            Dialects::Strictest(Dialect::PowerShell, Dialect::Posix),
        ],
    });
    out
}

/// A Windows profile, as the Windows corpora bind it.
pub fn windows_vars() -> PathVars {
    PathVars::new()
        .with_style(PathStyle::Windows)
        .with_var("USERPROFILE", r"C:\Users\a")
        .with_var("LOCALAPPDATA", r"C:\Users\a\AppData\Local")
        .with_var("APPDATA", r"C:\Users\a\AppData\Roaming")
        .with_cwd(r"C:\Users\a\app")
}

/// A Claude Code fixture with its `/home/u` replaced by `home`, so its paths
/// land in a test's own tree. `home` is a plain POSIX path (no quote or
/// backslash to escape in JSON).
pub fn rehome(payload: &str, home: &Path) -> String {
    let home = home.to_string_lossy();
    assert!(!home.contains(['"', '\\']), "{home}");
    payload.replace("/home/u", &home)
}

/// The Claude Code fixtures moved into `tree` ([`rehome`]), as `(file name,
/// payload)`. None on Windows: the fixtures are POSIX hook payloads, and a
/// Windows tree's home (`\\?\D:\…`) is no POSIX path to move them to.
pub fn fixtures_in(tree: &Tree) -> Vec<(String, String)> {
    if cfg!(unix) {
        claude_fixtures()
            .into_iter()
            .map(|(name, p)| (name, rehome(&p, &tree.home())))
            .collect()
    } else {
        Vec::new()
    }
}

/// Judge one hook payload as the hook does on a POSIX host: a shell command
/// by `evaluate_call`, each path of a file tool by `evaluate_path`. A tool the
/// guard does not judge, or a payload it cannot read, allows here.
pub fn judge_payload(engine: &Engine, payload: &str) -> Decision {
    let allow = Decision::Allow {
        trace: AllowTrace::NoMatch,
    };
    match classify_for(payload, MAX_PAYLOAD_BYTES, Some("claude"), false) {
        Ok(ToolCall::Shell { command, dialects }) => engine.evaluate_call(&command, dialects),
        Ok(ToolCall::File { paths, write, .. }) => {
            let access = if write { Access::Write } else { Access::Read };
            for p in &paths {
                let d = engine.evaluate_path(access, p);
                if d.is_deny() {
                    return d;
                }
            }
            allow
        }
        _ => allow,
    }
}

/// The string literals of Rust source `src`, unescaped: `"…"`, `b"…"` and
/// raw `r#"…"#`. Comments and char literals are skipped.
pub fn string_literals(src: &str) -> Vec<String> {
    let s: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    while i < s.len() {
        let c = s[i];
        let prev = if i > 0 { Some(s[i - 1]) } else { None };
        if c == '/' && s.get(i + 1) == Some(&'/') {
            while i < s.len() && s[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && s.get(i + 1) == Some(&'*') {
            i += 2;
            while i + 1 < s.len() && !(s[i] == '*' && s[i + 1] == '/') {
                i += 1;
            }
            i += 2;
        } else if c == 'r'
            && !prev.is_some_and(|p| ident(p) && p != 'b')
            && matches!(s.get(i + 1), Some('"' | '#'))
        {
            let mut j = i + 1;
            let mut hashes = 0;
            while s.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if s.get(j) != Some(&'"') {
                i += 1;
                continue;
            }
            j += 1;
            let start = j;
            loop {
                if j >= s.len() {
                    break;
                }
                if s[j] == '"' && (0..hashes).all(|k| s.get(j + 1 + k) == Some(&'#')) {
                    break;
                }
                j += 1;
            }
            out.push(s[start..j.min(s.len())].iter().collect());
            i = j + 1 + hashes;
        } else if c == '"' {
            let (lit, next) = cooked(&s, i + 1);
            out.push(lit);
            i = next;
        } else if c == '\'' {
            // A char literal (`'"'`, `'\''`, `'\u{1F600}'`) or a lifetime.
            if s.get(i + 1) == Some(&'\\') {
                let mut j = i + 2;
                while j < s.len() && s[j] != '\'' {
                    j += 1;
                }
                i = j + 1;
            } else if s.get(i + 2) == Some(&'\'') {
                i += 3;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    out
}

/// A cooked string body from `start` (after its quote): the text and the
/// index after the closing quote.
fn cooked(s: &[char], start: usize) -> (String, usize) {
    let mut out = String::new();
    let mut j = start;
    while j < s.len() {
        match s[j] {
            '"' => return (out, j + 1),
            '\\' => {
                j += 1;
                match s.get(j) {
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some('r') => out.push('\r'),
                    Some('0') => out.push('\0'),
                    Some('\\') => out.push('\\'),
                    Some('"') => out.push('"'),
                    Some('\'') => out.push('\''),
                    Some('x') => {
                        let hex: String = s[j + 1..(j + 3).min(s.len())].iter().collect();
                        if let Some(ch) =
                            u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32)
                        {
                            out.push(ch);
                        }
                        j += 2;
                    }
                    Some('u') => {
                        let mut k = j + 2;
                        let mut hex = String::new();
                        while k < s.len() && s[k] != '}' {
                            hex.push(s[k]);
                            k += 1;
                        }
                        if let Some(ch) =
                            u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32)
                        {
                            out.push(ch);
                        }
                        j = k;
                    }
                    Some('\n') => {
                        // A line continuation drops the newline and the indent.
                        while s.get(j + 1).is_some_and(|c| c.is_whitespace()) {
                            j += 1;
                        }
                    }
                    Some(other) => out.push(*other),
                    None => {}
                }
                j += 1;
            }
            c => {
                out.push(c);
                j += 1;
            }
        }
    }
    (out, j)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_are_unescaped_and_comments_skipped() {
        let src = concat!(
            "// \"not this\"\n",
            "let a = [\"cat .env\", r\"C:\\x\", r#\"say \"hi\"\"#];\n",
            "let q = '\"'; let l: &'static str = \"a\\tb\\\n    c\";\n",
            "/* \"nor this\" */ let b = b\"bytes\";\n",
        );
        assert_eq!(
            string_literals(src),
            vec!["cat .env", r"C:\x", r#"say "hi""#, "a\tbc", "bytes"]
        );
    }
}
