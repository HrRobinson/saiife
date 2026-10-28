//! Every built-in connector has a docs page whose suggested policies load
//! cleanly and put every write under `ask` (plan 14). New connectors are
//! checked by these tests without any change here.

use saiife_broker::manifest::OpKind;
use saiife_broker::{builtin, catalog, Catalog, Manifest};
use saiife_policy::capability::Capability;
use saiife_policy::decide::{decide, Request, Verdict};
use saiife_policy::{Mode, SystemConfig};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn page_path(id: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/connectors")
        .join(format!("{id}.md"))
}

fn page(id: &str) -> String {
    let p = page_path(id);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// `(the heading above it, the block text)` of every ```` ```toml ```` block.
fn toml_blocks(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut heading = String::new();
    let mut block: Option<String> = None;
    for line in text.lines() {
        match &mut block {
            Some(b) => {
                if line.trim_start().starts_with("```") {
                    out.push((heading.clone(), std::mem::take(b)));
                    block = None;
                } else {
                    b.push_str(line);
                    b.push('\n');
                }
            }
            None => {
                if line.starts_with('#') {
                    heading = line.trim_start_matches('#').trim().to_string();
                } else if line.trim() == "```toml" {
                    block = Some(String::new());
                }
            }
        }
    }
    out
}

/// The blocks that are policy fragments (they start with `[services.`).
fn policy_blocks(text: &str) -> Vec<(String, String)> {
    toml_blocks(text)
        .into_iter()
        .filter(|(_, b)| b.trim_start().starts_with("[services."))
        .collect()
}

/// Deep merge of `over` into `base`: tables merge, everything else replaces.
fn merge(base: &mut toml::Table, over: &toml::Table) {
    for (k, v) in over {
        match (base.get_mut(k), v) {
            (Some(toml::Value::Table(b)), toml::Value::Table(o)) => merge(b, o),
            _ => {
                base.insert(k.clone(), v.clone());
            }
        }
    }
}

fn has_connector(frag: &toml::Table) -> bool {
    frag.get("services")
        .and_then(|s| s.as_table())
        .is_some_and(|s| {
            s.values()
                .all(|v| v.as_table().is_some_and(|t| t.contains_key("connector")))
        })
}

/// Each fragment as a whole config: a fragment without `connector` (a
/// `[services.x.limits]` block) extends the last full one on the page.
fn configs(id: &str, text: &str) -> Vec<(String, SystemConfig)> {
    let mut last_full: Option<toml::Table> = None;
    let mut out = Vec::new();
    for (heading, block) in policy_blocks(text) {
        let frag: toml::Table = block
            .parse()
            .unwrap_or_else(|e| panic!("{id}: block under {heading:?} is not TOML: {e}"));
        let mut cfg: toml::Table = "version = 2\n".parse().unwrap();
        if has_connector(&frag) {
            last_full = Some(frag.clone());
        } else {
            let base = last_full.as_ref().unwrap_or_else(|| {
                panic!("{id}: block under {heading:?} has no connector and no block before it")
            });
            merge(&mut cfg, base);
        }
        merge(&mut cfg, &frag);
        let parsed: SystemConfig = toml::Value::Table(cfg)
            .try_into()
            .unwrap_or_else(|e| panic!("{id}: block under {heading:?}: {e}"));
        out.push((heading, parsed));
    }
    out
}

#[test]
fn every_connector_has_a_docs_page() {
    assert!(!builtin().is_empty());
    for m in builtin() {
        let p = page_path(&m.id);
        assert!(p.is_file(), "{}: no docs page {}", m.id, p.display());
        let text = page(&m.id);
        for h in ["## Locked mode", "## Suggested policy"] {
            assert!(text.contains(h), "{}: the page has no {h:?}", m.id);
        }
    }
}

#[test]
fn docs_policies_validate() {
    let cat = Catalog::new(builtin(), Vec::new());
    for m in builtin() {
        let text = page(&m.id);
        let cfgs = configs(&m.id, &text);
        assert!(!cfgs.is_empty(), "{}: no policy block", m.id);
        for (heading, cfg) in cfgs {
            let warnings = catalog::validate(&cfg, &cat)
                .unwrap_or_else(|e| panic!("{}: block under {heading:?}: {e}", m.id));
            assert!(
                warnings.is_empty(),
                "{}: block under {heading:?}: {warnings:?}",
                m.id
            );
        }
    }
}

fn writes(m: &Manifest) -> impl Iterator<Item = &saiife_broker::Operation> {
    m.operation
        .iter()
        .filter(|o| matches!(o.kind, OpKind::Write | OpKind::Delete | OpKind::Bulk))
}

#[test]
fn docs_writes_under_ask() {
    for m in builtin() {
        let text = page(&m.id);
        let ask: Vec<(String, SystemConfig)> = configs(&m.id, &text)
            .into_iter()
            .filter(|(h, _)| h.to_ascii_lowercase().contains("every write under `ask`"))
            .collect();
        assert!(
            !ask.is_empty(),
            "{}: no policy block headed \"every write under `ask`\"",
            m.id
        );
        for (heading, cfg) in ask {
            let svc = cfg
                .services
                .values()
                .find(|s| s.connector == m.id)
                .unwrap_or_else(|| panic!("{}: {heading:?} names no {} service", m.id, m.id));
            for op in writes(m) {
                // No qualifier and no params: an ask with a qualifier still
                // matches (ask matches broadly), an allow does not.
                let cap = Capability::parse(&op.capability).unwrap();
                let v = decide(
                    svc,
                    None,
                    Mode::Locked,
                    &Request {
                        capability: &cap,
                        params: &BTreeMap::new(),
                    },
                );
                assert_eq!(v, Verdict::Ask, "{}: {} under {heading:?}", m.id, op.id);
            }
        }
    }
}
