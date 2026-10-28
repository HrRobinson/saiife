//! The wording rule of spec section 10: the docs and the README never say
//! "the agent never holds a credential" on its own. The plans and specs under
//! `docs/superpowers/` quote the phrase and are not checked.

use std::fs;
use std::path::{Path, PathBuf};

const REQUIRED: &str = "the agent never holds a credential for a brokered service; it holds its own model-provider login unless you run a local model";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "superpowers") {
                continue;
            }
            collect(&p, out);
        } else if p.extension().is_some_and(|x| x == "md") {
            out.push(p);
        }
    }
}

/// Whitespace (including line breaks and quote markers) collapsed.
fn flat(text: &str) -> String {
    text.split(|c: char| c.is_whitespace() || c == '>')
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// Each use of "never hold(s) (a) credential(s)" that is not followed by
/// "for a brokered service" (any subject: "the agent", "agents", ...).
fn offenders(text: &str) -> Vec<String> {
    let t = flat(text);
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = t[from..].find("never hold") {
        let start = from + i;
        let mut rest = &t[start + "never hold".len()..];
        from = start + 1;
        rest = rest.strip_prefix('s').unwrap_or(rest);
        rest = rest
            .strip_prefix(" a")
            .or(rest.strip_prefix(" any"))
            .unwrap_or(rest);
        let Some(rest) = rest.strip_prefix(" credential") else {
            continue;
        };
        let rest = rest.strip_prefix('s').unwrap_or(rest);
        if !rest.starts_with(" for a brokered service") {
            out.push(t[start..(start + 70).min(t.len())].to_string());
        }
    }
    out
}

#[test]
fn checker_flags_a_bare_claim() {
    assert_eq!(offenders("So the agent never holds a credential.").len(), 1);
    assert_eq!(
        offenders("so the agent never\nholds a credential at all").len(),
        1
    );
    assert!(
        offenders("The agent never holds a credential for a brokered\nservice; it holds")
            .is_empty()
    );
    assert_eq!(offenders("Agents never hold credentials.").len(), 1);
    assert!(offenders("> the agent never holds a credential for a brokered service").is_empty());
}

#[test]
fn docs_and_readme_never_make_the_bare_claim() {
    let root = root();
    let mut files = vec![root.join("README.md")];
    collect(&root.join("docs"), &mut files);
    assert!(files.len() > 10, "found only {} pages", files.len());
    let mut bad = Vec::new();
    for f in &files {
        let text = fs::read_to_string(f).unwrap();
        for o in offenders(&text) {
            bad.push(format!("{}: ...{o}", f.display()));
        }
    }
    assert!(bad.is_empty(), "bare claim:\n{}", bad.join("\n"));
}

#[test]
fn readme_and_threats_carry_the_full_sentence() {
    let root = root();
    for f in ["README.md", "docs/threats.md"] {
        let text = flat(&fs::read_to_string(root.join(f)).unwrap());
        assert!(text.contains(REQUIRED), "{f} lacks the wording rule");
    }
}

#[test]
fn new_pages_exist_and_are_linked_from_the_readme() {
    let root = root();
    let readme = fs::read_to_string(root.join("README.md")).unwrap();
    for page in [
        "docs/forwarding.md",
        "docs/auditors.md",
        "docs/egress.md",
        "docs/threats.md",
    ] {
        assert!(root.join(page).is_file(), "{page} missing");
        assert!(readme.contains(page), "README does not link {page}");
    }
}
