//! Prebuilt packs (plan 21, speed option C): a hook loads the built-in packs
//! from Rust data and compiles each rule regex when a command first reaches
//! it. Every corpus case and Claude Code fixture is judged exactly as with
//! every regex compiled at load, under every engine the corpora use.

#[path = "support/corpus.rs"]
mod corpus;

use saiifeguard::builtins::Catalog;
use saiifeguard::canon::PathStyle;
use saiifeguard::engine::Engine;
use saiifeguard::pathrule::Access;

use corpus::{claude_fixtures, configs, corpus_cases, judge_payload, rehome, windows_vars, Tree};

const BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// The hook's engine for `config` (see `corpus::configs`): the packs from
/// `Catalog::load_active`, so their regexes are compiled on first use.
fn hook_engine(config: &str, tree: &Tree) -> Engine {
    let (style, vars) = match config {
        "windows-all" => (PathStyle::Windows, windows_vars()),
        _ => (PathStyle::Posix, tree.vars()),
    };
    let catalog = Catalog::builtin_for(style);
    let enabled: Vec<String> = if config == "posix-default" {
        Vec::new()
    } else {
        catalog.headers().into_iter().map(|(id, _, _)| id).collect()
    };
    let (packs, warnings) = catalog.load_active(&enabled);
    assert!(warnings.is_empty(), "{warnings:?}");
    Engine::new(packs)
        .with_budget(BUDGET)
        .with_pattern_allowance(std::time::Duration::MAX)
        .with_paths(vars)
}

#[test]
fn first_use_regexes_judge_every_corpus_case_alike() {
    let tree = Tree::new();
    let cases = corpus_cases();
    assert!(cases.len() > 1000, "only {} corpus cases", cases.len());
    let fixtures = claude_fixtures();
    let mut judged = 0usize;
    for c in configs(&tree) {
        let hook = hook_engine(c.name, &tree);
        assert_eq!(hook.pack_count(), c.engine.pack_count(), "{}", c.name);
        let mut differ = Vec::new();
        for cmd in &cases {
            for d in &c.dialects {
                let (a, b) = (c.engine.evaluate_call(cmd, *d), hook.evaluate_call(cmd, *d));
                if format!("{a:?}") != format!("{b:?}") {
                    differ.push(format!("{d:?} {cmd:?}: eager {a:?}, first use {b:?}"));
                }
                judged += 1;
            }
            for access in [Access::Read, Access::Write] {
                let (a, b) = (
                    c.engine.evaluate_path(access, cmd),
                    hook.evaluate_path(access, cmd),
                );
                if format!("{a:?}") != format!("{b:?}") {
                    differ.push(format!("{access:?} {cmd:?}: eager {a:?}, first use {b:?}"));
                }
            }
        }
        for (name, payload) in &fixtures {
            let payload = rehome(payload, &tree.home());
            let (a, b) = (
                judge_payload(&c.engine, &payload),
                judge_payload(&hook, &payload),
            );
            if format!("{a:?}") != format!("{b:?}") {
                differ.push(format!("{name}: eager {a:?}, first use {b:?}"));
            }
        }
        assert!(differ.is_empty(), "{}: {}", c.name, differ.join("\n"));
    }
    assert!(judged > 3000, "{judged}");
}
