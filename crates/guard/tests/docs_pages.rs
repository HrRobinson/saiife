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
