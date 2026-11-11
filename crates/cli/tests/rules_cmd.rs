//! `saiife rules` end to end (plan 33).

mod common;

use common::{code, stdout, Env};

#[test]
fn rules_help_lists_the_actions() {
    let env = Env::new(&[]);
    let out = env.saiife(&["rules", "--help"]);
    assert_eq!(code(&out), 0);
    let text = stdout(&out);
    for word in ["import", "sync", "list"] {
        assert!(text.contains(word), "{word} missing: {text}");
    }
}
