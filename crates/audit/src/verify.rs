//! Verifier for the hash-chained log (spec §6.4.3): re-reads every month
//! file, re-hashes it line by line and reports where the chain does not hold.
//!
//! The rules mirror `chain::append_chained`: `prev` is the SHA-256 of the
//! previous physical line (any line, even a bad one), `seq` runs on across
//! unchained lines and month files, and a genesis opens each chain. At most
//! one break is reported per line, the first that applies.

use std::path::Path;

use serde_json::Value;

use crate::chain::{sha256_hex, ZERO_PREV};
use crate::store;

/// What went wrong with a line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakKind {
    Unparseable,
    Unchained,
    SeqGap { expected: u64, found: u64 },
    PrevMismatch,
    BadGenesis,
    MissingGenesis,
    ChainRestarted,
    V1InsideChain,
}

impl BreakKind {
    /// Plain-language text for the user.
    pub fn describe(&self) -> String {
        match self {
            Self::Unparseable => "not a valid record (edited, or a write was cut off)".into(),
            Self::Unchained => {
                "record written without the chain (the chain lock was unavailable)".into()
            }
            Self::SeqGap { expected, found } => format!(
                "expected seq {expected}, found {found} (records were deleted, inserted or moved)"
            ),
            Self::PrevMismatch => {
                "does not follow the line before (a line was edited, deleted, inserted or moved)"
                    .into()
            }
            Self::BadGenesis => "chain start record is malformed".into(),
            Self::MissingGenesis => {
                "the start of the chain is missing (the oldest records were deleted)".into()
            }
            Self::ChainRestarted => {
                "a new chain starts here (older saiife version, or the log was rewritten)".into()
            }
            Self::V1InsideChain => {
                "v1 record inside the chain (written by saiife 0.1.x after an upgrade)".into()
            }
        }
    }
}

/// One place where the log does not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Break {
    /// File name only.
    pub file: String,
    /// 1-based line number in that file.
    pub line: usize,
    pub seq: Option<u64>,
    pub kind: BreakKind,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifyReport {
    /// Chained records seen, genesis included.
    pub chained: u64,
    pub v1_records: u64,
    /// Files made up only of v1 lines.
    pub v1_files: Vec<String>,
    /// `chain` id of the latest genesis.
    pub chain: Option<String>,
    /// `seq` and line hash of the newest chained record.
    pub head: Option<(u64, String)>,
    pub checkpoints: u64,
    pub breaks: Vec<Break>,
    /// Files or directories that could not be read; the log is unverified.
    pub read_errors: Vec<String>,
}

impl VerifyReport {
    /// 2 if something could not be read, else 1 if the chain is broken, else 0.
    pub fn exit_code(&self) -> u8 {
        if !self.read_errors.is_empty() {
            2
        } else if !self.breaks.is_empty() {
            1
        } else {
            0
        }
    }

    pub fn first_break(&self) -> Option<&Break> {
        self.breaks.first()
    }
}

/// Verify every month file in `dir`. A missing directory is an empty, intact log.
pub fn verify(dir: &Path) -> VerifyReport {
    let mut report = VerifyReport::default();
    let files = match store::month_files(dir) {
        Ok(files) => files,
        Err(e) => {
            report
                .read_errors
                .push(format!("cannot list {}: {e}", dir.display()));
            return report;
        }
    };
    let mut state = State::default();
    for path in files {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        let Some(body) = store::read_regular(&path) else {
            report
                .read_errors
                .push(format!("cannot read {}", path.display()));
            continue;
        };
        let mut lines: Vec<&[u8]> = body.split(|&b| b == b'\n').collect();
        if lines.last().is_some_and(|l| l.is_empty()) {
            lines.pop();
        }
        let v1_before = report.v1_records;
        for (i, line) in lines.iter().enumerate() {
            state.check(line, &name, i + 1, &mut report);
        }
        if !lines.is_empty() && report.v1_records - v1_before == lines.len() as u64 {
            report.v1_files.push(name);
        }
    }
    report
}

#[derive(Default)]
struct State {
    /// Hash of the previous physical line, across files.
    prev_hash: Option<String>,
    /// The next `seq` to expect; `None` until the chain has started.
    expected: Option<u64>,
    seen_genesis: bool,
}

impl State {
    fn check(&mut self, line: &[u8], file: &str, n: usize, report: &mut VerifyReport) {
        let hash = sha256_hex(line);
        let prev_hash = self.prev_hash.replace(hash.clone());
        let (seq, kind) = self.judge(line, prev_hash.as_deref(), &hash, report);
        if let Some(kind) = kind {
            report.breaks.push(Break {
                file: file.to_string(),
                line: n,
                seq,
                kind,
            });
        }
    }

    /// Judge one line and advance the state; returns its `seq` (if any) and
    /// the first break that applies.
    fn judge(
        &mut self,
        line: &[u8],
        prev_hash: Option<&str>,
        hash: &str,
        report: &mut VerifyReport,
    ) -> (Option<u64>, Option<BreakKind>) {
        let Ok(Value::Object(obj)) = serde_json::from_slice::<Value>(line) else {
            return (None, Some(BreakKind::Unparseable));
        };
        let v = obj.get("v").and_then(Value::as_u64).unwrap_or(1);
        if v < 2 {
            if self.expected.is_some() {
                return (None, Some(BreakKind::V1InsideChain));
            }
            report.v1_records += 1;
            return (None, None);
        }
        let Some(seq) = obj.get("seq").and_then(Value::as_u64) else {
            return (None, Some(BreakKind::Unchained));
        };
        let kind_field = obj.get("kind").and_then(Value::as_str);
        let mut brk = None;
        if kind_field == Some("genesis") {
            let prev = obj.get("prev").and_then(Value::as_str);
            if seq != 0 || prev != Some(ZERO_PREV) {
                brk = Some(BreakKind::BadGenesis);
            } else if self.seen_genesis {
                brk = Some(BreakKind::ChainRestarted);
            }
            self.seen_genesis = true;
            report.chain = obj.get("chain").and_then(Value::as_str).map(String::from);
            self.expected = Some(1);
        } else {
            match self.expected {
                None => brk = Some(BreakKind::MissingGenesis),
                Some(expected) if seq != expected => {
                    brk = Some(BreakKind::SeqGap {
                        expected,
                        found: seq,
                    });
                }
                Some(_) => {
                    if obj.get("prev").and_then(Value::as_str) != prev_hash {
                        brk = Some(BreakKind::PrevMismatch);
                    }
                }
            }
            if kind_field == Some("checkpoint") {
                report.checkpoints += 1;
            }
            self.expected = Some(seq + 1);
        }
        report.chained += 1;
        report.head = Some((seq, hash.to_string()));
        (Some(seq), brk)
    }
}
