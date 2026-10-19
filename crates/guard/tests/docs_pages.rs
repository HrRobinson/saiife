//! The pack pages in `docs/packs/` stay true: every built-in pack has a page
//! with the agreed headings, the index lists every pack, and every example on
//! a page gets the decision the page claims, judged with only that pack on.

use std::path::PathBuf;

use saiifeguard::builtins::builtin_packs;
use saiifeguard::engine::Engine;
use saiifeguard::pack::Pack;

/// The `##` headings every page has, in this order.
const HEADINGS: [&str; 5] = [
    "## On by default",
    "## Blocked",
    "## Allowed on purpose",
    "## Not covered",
    "## Examples",
];

/// Generous budget so a loaded runner cannot turn a deny into a latency
/// fail-open; the budget path itself is covered by dedicated tests.
const TEST_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

fn docs_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/packs")
}

fn packs() -> Vec<Pack> {
    let (packs, warnings) = builtin_packs();
    assert!(warnings.is_empty(), "built-in load warnings: {warnings:?}");
    assert_eq!(packs.len(), 13, "expected the 13 built-in packs");
    packs
}

fn page(id: &str) -> String {
    let path = docs_dir().join(format!("{id}.md"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The lines of every fenced block whose info string is `saiife-examples`.
fn example_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if !inside && trimmed == "```saiife-examples" {
            inside = true;
        } else if inside && trimmed == "```" {
            inside = false;
        } else if inside && !trimmed.is_empty() {
            out.push(trimmed.to_string());
        }
    }
    assert!(!inside, "unclosed saiife-examples block");
    out
}

#[test]
fn every_builtin_pack_has_a_page() {
    for pack in packs() {
        let text = page(&pack.id);
        let title = format!("# {} ({})", pack.name, pack.id);
        assert_eq!(
            text.lines().next(),
            Some(title.as_str()),
            "{}: the first line must be {title:?}",
            pack.id
        );
        let mut from = 0;
        for heading in HEADINGS {
            let at = text
                .lines()
                .enumerate()
                .skip(from)
                .find(|(_, l)| l.trim_end() == heading)
                .map(|(i, _)| i)
                .unwrap_or_else(|| panic!("{}: missing {heading:?} (or out of order)", pack.id));
            from = at + 1;
        }
    }
}

#[test]
fn examples_match_the_engine() {
    let mut wrong = Vec::new();
    for pack in packs() {
        let id = pack.id.clone();
        let lines = example_lines(&page(&id));
        let engine = Engine::new(vec![pack]).with_budget(TEST_BUDGET);
        let (mut denies, mut allows) = (0, 0);
        for line in lines {
            let (want_deny, cmd) = if let Some(cmd) = line.strip_prefix("deny ") {
                denies += 1;
                (true, cmd)
            } else if let Some(cmd) = line.strip_prefix("allow ") {
                allows += 1;
                (false, cmd)
            } else {
                panic!("{id}: example line must start with `deny ` or `allow `: {line:?}");
            };
            let got = engine.evaluate(cmd);
            // Only this pack is on, so any deny is its doing, including the
            // engine's own check for a hidden `$(...)` target of its commands.
            if got.is_deny() != want_deny {
                wrong.push(format!(
                    "{id}: page says {} for {cmd:?}, engine says {got:?}",
                    if want_deny { "deny" } else { "allow" }
                ));
            }
        }
        assert!(
            denies >= 3,
            "{id}: needs at least 3 deny examples, has {denies}"
        );
        assert!(
            allows >= 1,
            "{id}: needs at least 1 allow example, has {allows}"
        );
    }
    assert!(
        wrong.is_empty(),
        "examples that do not match:\n{}",
        wrong.join("\n")
    );
}

#[test]
fn index_lists_every_pack() {
    let path = docs_dir().join("README.md");
    let index =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    for pack in packs() {
        assert!(
            index.contains(&format!("({}.md)", pack.id)),
            "docs/packs/README.md does not link {}",
            pack.id
        );
    }
}

/// Every `.md` file under `dir`, skipping `docs/superpowers/` (plans, specs
/// and research are working notes, not user docs).
fn markdown_files(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) != Some("superpowers") {
                markdown_files(&path, out);
            }
        } else if path.extension().and_then(|e| e.to_str()) == Some("md") {
            out.push(path);
        }
    }
}

/// The targets of every inline Markdown link `[text](target)` outside fenced
/// code blocks.
fn link_targets(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut fenced = false;
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            continue;
        }
        let mut rest = line;
        while let Some(at) = rest.find("](") {
            let after = &rest[at + 2..];
            let Some(end) = after.find(')') else { break };
            // Drop an optional title: `(file.md "Title")`.
            let target = after[..end].split_whitespace().next().unwrap_or("");
            out.push(target.to_string());
            rest = &after[end + 1..];
        }
    }
    out
}

#[test]
fn docs_links_resolve() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = vec![root.join("README.md")];
    markdown_files(&root.join("docs"), &mut files);
    let mut broken = Vec::new();
    for file in &files {
        let text =
            std::fs::read_to_string(file).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        let base = file.parent().expect("file has a parent");
        for target in link_targets(&text) {
            if target.is_empty()
                || target.starts_with('#')
                || target.starts_with("http://")
                || target.starts_with("https://")
                || target.starts_with("mailto:")
            {
                continue;
            }
            // Check the file part only; `#anchor` suffixes are not checked.
            let file_part = target.split('#').next().unwrap_or("");
            if !base.join(file_part).exists() {
                broken.push(format!("{}: {target}", file.display()));
            }
        }
    }
    assert!(broken.is_empty(), "broken links:\n{}", broken.join("\n"));
}
