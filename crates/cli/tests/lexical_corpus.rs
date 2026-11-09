//! The lexical view is never stricter than the host's (plan 21, Task 1;
//! Review Focus 1): every case of the guard corpora and every Claude Code
//! fixture, judged under `FsView::Host` against a project on disk and under
//! `FsView::Lexical`. A case the host allows and the lexical view denies would
//! be a false deny of the service's re-judgment, on a call the hook allowed.

#[path = "../../guard/tests/support/corpus.rs"]
mod corpus;

use saiifeguard::canon::{with_fs_view, FsView};
use saiifeguard::pathrule::Access;

use corpus::{claude_fixtures, configs, corpus_cases, judge_payload, rehome, Tree};

/// Cases the lexical view may deny although the host allows them, each
/// approved by the owner by name. Starts empty.
const KNOWN_STRICTER: &[&str] = &[];

/// What is judged, as `(case label, denied)`, in a fixed order.
fn verdicts(view: FsView, tree: &Tree, cases: &[String]) -> Vec<(String, bool)> {
    let fixtures = claude_fixtures();
    with_fs_view(view, || {
        let mut out = Vec::new();
        for c in configs(tree) {
            for cmd in cases {
                for d in &c.dialects {
                    out.push((
                        format!("{} {d:?}: {cmd}", c.name),
                        c.engine.evaluate_call(cmd, *d).is_deny(),
                    ));
                }
                for access in [Access::Read, Access::Write] {
                    out.push((
                        format!("{} path {access:?}: {cmd}", c.name),
                        c.engine.evaluate_path(access, cmd).is_deny(),
                    ));
                }
            }
            for (name, payload) in &fixtures {
                out.push((
                    format!("{} fixture: {name}", c.name),
                    judge_payload(&c.engine, &rehome(payload, &tree.home())).is_deny(),
                ));
            }
        }
        out
    })
}

#[test]
fn lexical_never_stricter_on_the_corpora() {
    let tree = Tree::new();
    let cases = corpus_cases();
    assert!(cases.len() > 1000, "only {} corpus cases", cases.len());
    let host = verdicts(FsView::Host, &tree, &cases);
    let lexical = verdicts(FsView::Lexical, &tree, &cases);
    assert_eq!(host.len(), lexical.len());
    let stricter: Vec<&str> = host
        .iter()
        .zip(&lexical)
        .filter(|((_, h), (_, l))| !*h && *l)
        .map(|((label, _), _)| label.as_str())
        .filter(|label| !KNOWN_STRICTER.iter().any(|k| label.ends_with(k)))
        .collect();
    assert!(
        stricter.is_empty(),
        "{} case(s) the host allows and the lexical view denies:\n{}",
        stricter.len(),
        stricter.join("\n")
    );
    // The comparison is not empty: both views deny much of the corpora.
    assert!(lexical.iter().filter(|(_, d)| *d).count() > 1000);
}
