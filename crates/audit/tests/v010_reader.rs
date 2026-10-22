//! The v2 log must stay readable by saiife 0.1.0, whose reader skips lines
//! it cannot parse. These are frozen copies of `Record` and `DecisionKind`
//! from the `v0.1.0` tag (`git show v0.1.0:crates/audit/src/record.rs`).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    Allow,
    Deny,
    ErrorAllowed,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub v: u32,
    pub ts: String,
    pub agent: String,
    pub project: String,
    #[serde(default)]
    pub session: Option<String>,
    pub tool: String,
    pub input: String,
    pub decision: DecisionKind,
    #[serde(default)]
    pub pack: Option<String>,
    #[serde(default)]
    pub rule: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    pub saiife: String,
}

#[test]
fn v010_reader_parses_every_v2_line() {
    let body = include_str!("fixtures/v2/2026-11.jsonl");
    let mut n = 0;
    for (i, line) in body.lines().enumerate() {
        let r: Record = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("line {} not readable by 0.1.0: {e}", i + 1));
        assert_eq!(r.v, 2);
        n += 1;
    }
    assert_eq!(n, 6);
}

#[test]
fn v010_reader_parses_locked_fixture() {
    let body = include_str!("fixtures/v2-locked/2026-11.jsonl");
    let mut kinds = Vec::new();
    for (i, line) in body.lines().enumerate() {
        let r: Record = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("line {} not readable by 0.1.0: {e}", i + 1));
        assert_eq!(r.v, 2);
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        kinds.push(v["kind"].as_str().unwrap().to_string());
    }
    assert_eq!(
        kinds,
        [
            "genesis",
            "guard",
            "guard",
            "guard",
            "checkpoint",
            "key_rotate",
            "checkpoint",
            "daemon"
        ]
    );
}
