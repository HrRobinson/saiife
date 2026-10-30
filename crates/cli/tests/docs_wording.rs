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
        "docs/environments.md",
        "docs/collections.md",
    ] {
        assert!(root.join(page).is_file(), "{page} missing");
        assert!(readme.contains(page), "README does not link {page}");
    }
}

#[test]
fn new_pages_linked() {
    let root = root();
    let index = fs::read_to_string(root.join("docs/connectors/README.md")).unwrap();
    for page in ["environments.md", "collections.md"] {
        assert!(root.join("docs").join(page).is_file(), "{page} missing");
        assert!(
            index.contains(&format!("(../{page})")),
            "the connector index does not link {page}"
        );
    }
    // Every connector page is listed in the index.
    for e in fs::read_dir(root.join("docs/connectors")).unwrap() {
        let name = e.unwrap().file_name().into_string().unwrap();
        if name != "README.md" && name.ends_with(".md") {
            assert!(
                index.contains(&format!("({name})")),
                "the connector index does not list {name}"
            );
        }
    }
}

// ---- docs/mcp.md (plan 17) ----

fn mcp_page() -> String {
    fs::read_to_string(root().join("docs/mcp.md")).expect("docs/mcp.md")
}

#[test]
fn mcp_page_is_linked() {
    let root = root();
    let readme = fs::read_to_string(root.join("README.md")).unwrap();
    assert!(
        readme.contains("docs/mcp.md"),
        "README does not link docs/mcp.md"
    );
    let index = fs::read_to_string(root.join("docs/connectors/README.md")).unwrap();
    assert!(
        index.contains("(../mcp.md)"),
        "the connector index does not link mcp.md"
    );
}

#[test]
fn mcp_page_holds_the_warning_text() {
    let t = flat(&mcp_page());
    assert!(
        t.contains(&flat(
            "MCP server linear bypasses saiife: its requests are not brokered or limited"
        )),
        "docs/mcp.md lacks the exact unbrokered-server warning"
    );
}

#[test]
fn network_is_never_called_sandboxed() {
    let root = root();
    for f in [
        "docs/mcp.md",
        "docs/threats.md",
        "docs/superpowers/specs/2026-10-19-saiife-v2-design.md",
    ] {
        let t = flat(&fs::read_to_string(root.join(f)).unwrap());
        assert!(
            t.contains("network is **not** sandboxed") || t.contains("network is not sandboxed"),
            "{f} does not say the gateway child's network is not sandboxed"
        );
    }
}

#[test]
fn mcp_page_does_not_claim_codex_or_gemini_restrictions() {
    let t = flat(&mcp_page());
    assert!(
        t.contains("saiife does not restrict their mcp servers yet"),
        "docs/mcp.md must say saiife does not restrict Codex or Gemini MCP servers yet"
    );
    assert!(t.contains("restricted by the hook only"));
    for claim in [
        "restricts codex",
        "restricts gemini",
        "writes a codex",
        "writes a gemini",
        "managed keys for codex",
        "managed keys for gemini",
        "codex and gemini are restricted by policy",
        "codex and gemini get a managed",
    ] {
        assert!(!t.contains(claim), "docs/mcp.md claims: {claim}");
    }
    // A sentence that names Codex or Gemini and "restrict" must carry a
    // negation or the hook-only wording.
    for s in t.split(['.', '\n']) {
        let names = s.contains("codex") || s.contains("gemini");
        if names && s.contains("restrict") {
            assert!(
                s.contains(" not ")
                    || s.contains("hook only")
                    || s.contains("no managed")
                    || s.contains("none is written"),
                "docs/mcp.md may claim a Codex/Gemini restriction: {s}"
            );
        }
    }
}

#[test]
fn mcp_page_example_loads() {
    let text = mcp_page();
    let mut blocks = Vec::new();
    let mut cur: Option<String> = None;
    for line in text.lines() {
        match &mut cur {
            Some(b) if line.trim_start().starts_with("```") => {
                blocks.push(std::mem::take(b));
                cur = None;
            }
            Some(b) => {
                b.push_str(line);
                b.push('\n');
            }
            None if line.trim() == "```toml" => cur = Some(String::new()),
            None => {}
        }
    }
    let ex: Vec<_> = blocks
        .iter()
        .filter(|b| b.contains("[mcp.linear]"))
        .collect();
    assert_eq!(ex.len(), 1, "expected one [mcp.linear] example");
    #[derive(serde::Deserialize)]
    struct Drop {
        mcp: std::collections::BTreeMap<String, saiife_policy::McpServerCfg>,
    }
    let d: Drop = toml::from_str(ex[0]).expect("the mcp-linear.toml example parses");
    // `read_paths` must exist on a real host; check the other keys.
    let mut c = d.mcp["linear"].clone();
    c.read_paths.clear();
    c.validate("linear").expect("the example validates");
}
