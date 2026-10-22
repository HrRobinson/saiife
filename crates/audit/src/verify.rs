//! Verifier for the hash-chained log (spec §6.4.3): re-reads every month
//! file, re-hashes it line by line and reports where the chain does not hold.
//!
//! The rules mirror `chain::append_chained`: `prev` is the SHA-256 of the
//! previous physical line (any line, even a bad one), `seq` runs on across
//! unchained lines and month files, and a genesis opens each chain. At most
//! one break is reported per line, the first that applies.
//!
//! Locked-mode chains also carry a signing key (spec §6.4.2): the genesis
//! `key` sets the key in force, a `key_rotate` signed by it switches to its
//! `new_key`, and every checkpoint must be signed by the key in force over
//! the record before it.

use std::path::Path;

use serde_json::Value;

use crate::chain::{sha256_hex, ZERO_PREV};
use crate::sign::{checkpoint_message, fingerprint_of, key_rotate_message, verify_b64};
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
    BadCheckpoint,
    CheckpointWithoutKey,
    BadKeyRotate,
    UnsignedKeyRotate,
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
            Self::BadCheckpoint => "checkpoint does not match its signature or the records before it (records were changed, or the checkpoint is forged)".into(),
            Self::CheckpointWithoutKey => "checkpoint in a chain that has no signing key".into(),
            Self::BadKeyRotate => "signing key change not signed by the previous key".into(),
            Self::UnsignedKeyRotate => "signing key replaced without the previous key (the daemon's key file was lost or removed)".into(),
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
    /// `(seq, ts)` of the newest checkpoint that verified.
    pub last_checkpoint: Option<(u64, String)>,
    /// Fingerprint of the signing key in force at the end of the log.
    pub key: Option<String>,
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
pub(crate) struct State {
    /// Hash of the previous physical line, across files.
    prev_hash: Option<String>,
    /// The next `seq` to expect; `None` until the chain has started.
    expected: Option<u64>,
    seen_genesis: bool,
    /// `chain` id of the current genesis, for the signed messages.
    chain: Option<String>,
    /// `ed25519:<spki b64>` of the signing key in force.
    key: Option<String>,
}

impl State {
    /// A state that continues a chain in the middle (the startup check of
    /// the recent lines): `prev_hash` hashes the line before the first one
    /// fed, `expected` is that line's `seq`, and `key` is the key in force
    /// there.
    pub(crate) fn resume(
        prev_hash: Option<String>,
        expected: u64,
        chain: Option<String>,
        key: Option<String>,
    ) -> State {
        State {
            prev_hash,
            expected: Some(expected),
            seen_genesis: true,
            chain,
            key,
        }
    }

    pub(crate) fn check(&mut self, line: &[u8], file: &str, n: usize, report: &mut VerifyReport) {
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
            self.chain = obj.get("chain").and_then(Value::as_str).map(String::from);
            report.chain.clone_from(&self.chain);
            let key = obj.get("key").and_then(Value::as_str).map(String::from);
            self.set_key(key, report);
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
            let signed = match kind_field {
                Some("checkpoint") => {
                    report.checkpoints += 1;
                    self.check_checkpoint(&obj, seq, prev_hash)
                }
                Some("key_rotate") => self.key_rotate(&obj, seq, prev_hash, report),
                _ => None,
            };
            brk = brk.or(signed);
            if kind_field == Some("checkpoint") && brk.is_none() {
                let ts = obj.get("ts").and_then(Value::as_str).unwrap_or_default();
                report.last_checkpoint = Some((seq, ts.to_string()));
            }
            self.expected = seq.checked_add(1);
        }
        report.chained += 1;
        report.head = Some((seq, hash.to_string()));
        (Some(seq), brk)
    }

    fn set_key(&mut self, key: Option<String>, report: &mut VerifyReport) {
        report.key = key.as_deref().and_then(fingerprint_of);
        self.key = key;
    }

    /// The break of a checkpoint, if any: it needs a key in force, must name
    /// the record right before it (`head_seq`, `head`) and that key's
    /// fingerprint, and carry its valid signature.
    fn check_checkpoint(
        &self,
        obj: &serde_json::Map<String, Value>,
        seq: u64,
        prev_hash: Option<&str>,
    ) -> Option<BreakKind> {
        let Some(spki) = self.key.as_deref() else {
            return Some(BreakKind::CheckpointWithoutKey);
        };
        let ok = (|| {
            let head_seq = obj.get("head_seq")?.as_u64()?;
            let head = obj.get("head")?.as_str()?;
            let ts = obj.get("ts")?.as_str()?;
            let msg = checkpoint_message(self.chain.as_deref()?, head_seq, head, ts);
            Some(
                Some(head_seq) == seq.checked_sub(1)
                    && Some(head) == prev_hash
                    && fingerprint_of(spki).as_deref() == obj.get("key")?.as_str()
                    && verify_b64(spki, msg.as_bytes(), obj.get("sig")?.as_str()?),
            )
        })();
        (ok != Some(true)).then_some(BreakKind::BadCheckpoint)
    }

    /// Judge a `key_rotate` and switch the key in force: a valid signature
    /// by the old key switches it; a missing one (`sig` null) switches it
    /// too but is a break when there was a key to sign with; an invalid one
    /// is a break and the key stays.
    fn key_rotate(
        &mut self,
        obj: &serde_json::Map<String, Value>,
        seq: u64,
        prev_hash: Option<&str>,
        report: &mut VerifyReport,
    ) -> Option<BreakKind> {
        let new_key = obj.get("new_key").and_then(Value::as_str).map(String::from);
        let sig = obj.get("sig").unwrap_or(&Value::Null);
        if sig.is_null() {
            // A chain without a key (developer mode) that gets one is not a
            // loss: there was nothing to sign the change with.
            let brk = self.key.is_some().then_some(BreakKind::UnsignedKeyRotate);
            self.set_key(new_key, report);
            return brk;
        }
        let ok = (|| {
            let old = self.key.as_deref()?;
            let head_seq = obj.get("head_seq")?.as_u64()?;
            let head = obj.get("head")?.as_str()?;
            let ts = obj.get("ts")?.as_str()?;
            let new_key = new_key.as_deref()?;
            fingerprint_of(new_key)?;
            let msg = key_rotate_message(self.chain.as_deref()?, head_seq, head, new_key, ts);
            Some(
                Some(head_seq) == seq.checked_sub(1)
                    && Some(head) == prev_hash
                    && fingerprint_of(old).as_deref() == obj.get("key")?.as_str()
                    && verify_b64(old, msg.as_bytes(), sig.as_str()?),
            )
        })();
        if ok == Some(true) {
            self.set_key(new_key, report);
            None
        } else {
            Some(BreakKind::BadKeyRotate)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seq_max_does_not_panic() {
        let dir = tempfile::tempdir().unwrap();
        let body = format!(
            "{{\"v\":2,\"seq\":0,\"kind\":\"genesis\",\"prev\":\"{ZERO_PREV}\"}}\n\
             {{\"v\":2,\"seq\":{},\"prev\":\"x\"}}\n\
             {{\"v\":2,\"seq\":3,\"prev\":\"x\"}}\n",
            u64::MAX
        );
        std::fs::write(dir.path().join("2026-10.jsonl"), body).unwrap();
        let r = verify(dir.path());
        assert!(!r.breaks.is_empty());
        assert_eq!(r.exit_code(), 1);
    }
}
