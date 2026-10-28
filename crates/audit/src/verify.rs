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

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

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
    /// `mode` of the latest genesis (`developer`, `locked`, `personal`).
    pub mode: Option<String>,
    /// `seq` and line hash of the newest chained record.
    pub head: Option<(u64, String)>,
    pub checkpoints: u64,
    /// `(seq, ts)` of the newest checkpoint that verified.
    pub last_checkpoint: Option<(u64, String)>,
    /// Fingerprint of the signing key in force at the end of the log.
    pub key: Option<String>,
    pub breaks: Vec<Break>,
    /// A forwarded copy only: chained lines that repeat an earlier line
    /// byte for byte and were skipped (delivery is at least once, so a
    /// forwarder restart sends the lines after its cursor again).
    pub duplicates: u64,
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
    check_files(&files, &mut State::default(), &mut report);
    report
}

/// Feed every line of `files`, in order, to `state`. Files are read as a
/// stream, so a forwarded copy spanning months is never held in memory.
fn check_files(files: &[PathBuf], state: &mut State, report: &mut VerifyReport) {
    for path in files {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        let Some(file) = store::open_regular(path) else {
            report
                .read_errors
                .push(format!("cannot read {}", path.display()));
            continue;
        };
        let mut reader = BufReader::new(file);
        let (v1_before, mut n) = (report.v1_records, 0usize);
        let mut line = Vec::new();
        loop {
            line.clear();
            match reader.read_until(b'\n', &mut line) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) => {
                    report
                        .read_errors
                        .push(format!("cannot read {}: {e}", path.display()));
                    break;
                }
            }
            if line.last() == Some(&b'\n') {
                line.pop();
            }
            n += 1;
            state.check(&line, &name, n, report);
        }
        if n > 0 && report.v1_records - v1_before == n as u64 {
            report.v1_files.push(name);
        }
    }
}

/// The local log checked against a forwarded copy (spec §6.4.3 item 3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExternalReport {
    /// The local log on its own.
    pub local: VerifyReport,
    /// The forwarded copy on its own; its breaks mean the copy is damaged,
    /// not the local log.
    pub external: VerifyReport,
    /// `head_seq` of each checkpoint of the copy that the local log lacks,
    /// where the copy is intact around it: the local history was rewritten
    /// or cut.
    pub missing_checkpoints: Vec<u64>,
    /// `head_seq` of each checkpoint of the copy that the local log lacks,
    /// where the copy is damaged next to it (its own line, or a `prev` or
    /// `seq` break on the line after it): either side may have changed.
    pub missing_near_damage: Vec<u64>,
    /// Lines of the copy whose `seq` the local log has, but with other
    /// bytes. Since both chains are verified, a matching line vouches for
    /// everything before it; a differing one means a rewritten history.
    pub rewritten: Vec<HeadMismatch>,
    /// `(local max seq, external max seq)` when the copy goes further than
    /// the local log: its tail was cut off.
    pub cut_tail: Option<(u64, u64)>,
    /// Checkpoints of the copy compared with the local log (all of them).
    pub compared: u64,
    /// The host id prefix of the copy's month files, when it is not this
    /// machine's: the copy may be another host's log.
    pub external_host: Option<String>,
}

/// A line of the copy whose bytes the local log does not have at its `seq`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadMismatch {
    pub seq: u64,
    /// `seq` of the newest checkpoint before it that both sides share.
    pub after_checkpoint: Option<u64>,
    /// The copy vouches for the line: the next line's `prev` hashes it. The
    /// copy's last line is not vouched for (nothing follows it), so a
    /// mismatch there may be either side's change.
    pub vouched: bool,
}

impl ExternalReport {
    /// 2 if either side could not be read, else 1 on any break (local,
    /// external, missing checkpoint, rewritten line, cut tail), else 0.
    pub fn exit_code(&self) -> u8 {
        if !self.local.read_errors.is_empty() || !self.external.read_errors.is_empty() {
            2
        } else if !self.local.breaks.is_empty()
            || !self.external.breaks.is_empty()
            || !self.missing_checkpoints.is_empty()
            || !self.missing_near_damage.is_empty()
            || !self.rewritten.is_empty()
            || self.cut_tail.is_some()
        {
            1
        } else {
            0
        }
    }
}

/// Verify the local log in `local` against a forwarded copy at `external`:
/// one JSONL file with the lines as forwarded, or a directory of month
/// files (`YYYY-MM.jsonl`, or the file target's `<host id>-YYYY-MM.jsonl`).
///
/// Both are chain-verified on their own. Then:
/// - every checkpoint of the copy must be in the local log with the same
///   `head_seq`, `head` and `sig`;
/// - the last line of every intact stretch of the copy (and the copy's
///   last line) must be in the local log byte for byte at its `seq`, which
///   catches a tail rewritten after the last checkpoint;
/// - the local log must reach the copy's highest `seq`.
///
/// The copy is read first, collecting the few `seq`s to compare, then the
/// local log in one pass; neither is held in memory.
pub fn verify_external(local: &Path, external: &Path) -> ExternalReport {
    let mut out = ExternalReport::default();
    let mut ext_state = State {
        partial: true,
        ..State::default()
    };
    match external_files(external) {
        Ok((files, host)) => {
            out.external_host = host;
            check_files(&files, &mut ext_state, &mut out.external);
            ext_state.seen.end_run();
        }
        Err(e) => out.external.read_errors.push(e),
    }
    if out.external.read_errors.is_empty() && out.external.chained == 0 {
        out.external
            .read_errors
            .push(format!("{} holds no chained records", external.display()));
    }
    let mut local_state = State::default();
    local_state.seen.watch = ext_state.seen.heads.iter().map(|h| h.seq).collect();
    match store::month_files(local) {
        Ok(files) => check_files(&files, &mut local_state, &mut out.local),
        Err(e) => out
            .local
            .read_errors
            .push(format!("cannot list {}: {e}", local.display())),
    }
    if out.exit_code() == 2 {
        return out;
    }

    // Checkpoints.
    let have: BTreeSet<&CheckpointId> = local_state
        .seen
        .checkpoints
        .iter()
        .map(|(_, c)| c)
        .collect();
    let broken = &ext_state.seen.broken;
    let mut shared = Vec::new();
    for (line, cp) in &ext_state.seen.checkpoints {
        out.compared += 1;
        if have.contains(cp) {
            shared.push(cp.head_seq.saturating_add(1));
            continue;
        }
        // A changed checkpoint line breaks itself (a bad signature) or the
        // line after it (`prev`, or `seq` when that line was dropped).
        let damaged = broken.contains_key(line)
            || matches!(
                broken.get(&(line + 1)),
                Some(BreakKind::PrevMismatch | BreakKind::SeqGap { .. })
            );
        if damaged {
            out.missing_near_damage.push(cp.head_seq);
        } else {
            out.missing_checkpoints.push(cp.head_seq);
        }
    }

    // Heads.
    let local_max = local_state.seen.max_seq;
    for h in &ext_state.seen.heads {
        if local_max.is_none_or(|m| m < h.seq) {
            continue; // past the local end: `cut_tail`
        }
        let same = local_state
            .seen
            .found
            .get(&h.seq)
            .is_some_and(|v| v.contains(&h.hash));
        if !same {
            out.rewritten.push(HeadMismatch {
                seq: h.seq,
                after_checkpoint: shared.iter().copied().filter(|&c| c < h.seq).max(),
                vouched: h.vouched,
            });
        }
    }

    if let Some(ext_max) = ext_state.seen.max_seq {
        match local_max {
            Some(local_max) if local_max >= ext_max => {}
            local_max => out.cut_tail = Some((local_max.unwrap_or(0), ext_max)),
        }
    }
    out
}

/// The files of a forwarded copy, in order. A directory holds the month
/// files of one host: plain `YYYY-MM.jsonl`, or `<prefix>-YYYY-MM.jsonl`
/// with one prefix (this host's id when there are several). Also returns
/// that prefix when it is not this host's id.
fn external_files(p: &Path) -> Result<(Vec<PathBuf>, Option<String>), String> {
    let cannot = |e: &dyn std::fmt::Display| format!("cannot read {}: {e}", p.display());
    let p = std::fs::canonicalize(p).map_err(|e| cannot(&e))?;
    let meta = std::fs::metadata(&p).map_err(|e| cannot(&e))?;
    if meta.is_file() {
        return Ok((vec![p], None));
    }
    if !meta.is_dir() {
        return Err(cannot(&"not a file or directory"));
    }
    let mut hosts: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
    for entry in std::fs::read_dir(&p).map_err(|e| cannot(&e))? {
        let path = entry.map_err(|e| cannot(&e))?.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(split) = name.len().checked_sub(13) else {
            continue;
        };
        let (Some(prefix), Some(month)) = (name.get(..split), name.get(split..)) else {
            continue;
        };
        if !store::is_month_file(month) {
            continue;
        }
        let prefix = match prefix.strip_suffix('-') {
            Some(host) if !host.is_empty() => host,
            _ if prefix.is_empty() => "",
            _ => continue,
        };
        hosts.entry(prefix.to_string()).or_default().push(path);
    }
    let this = crate::chain::host_id().unwrap_or_default();
    let mut other_host = None;
    let mut files = match hosts.len() {
        0 => return Err(cannot(&"no month files (YYYY-MM.jsonl) in it")),
        1 => {
            let (host, files) = hosts.into_iter().next().unwrap_or_default();
            if !host.is_empty() && host != this {
                other_host = Some(host);
            }
            files
        }
        _ => match hosts.remove(&this) {
            Some(files) => files,
            None => {
                let names: Vec<&str> = hosts.keys().map(|h| h.as_str()).collect();
                return Err(cannot(&format!(
                    "it holds the month files of several hosts ({}); pass one host's files",
                    names.join(", ")
                )));
            }
        },
    };
    files.sort();
    Ok((files, other_host))
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
    /// A forwarded copy that may start mid-chain: until a genesis shows up
    /// the missing start is no break, and signatures are not judged (the
    /// chain id and key are unknown); the comparison with the local log
    /// vouches for its checkpoints instead.
    partial: bool,
    seen: Seen,
}

/// What a checkpoint's signature covers: the record it seals and the
/// signature itself. Equal ids in two copies mean the same signed head.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CheckpointId {
    head_seq: u64,
    head: String,
    sig: String,
}

/// What `verify_external` needs beyond the report.
#[derive(Default)]
struct Seen {
    /// Physical lines fed so far, across files.
    lines: usize,
    /// Every checkpoint, with the 0-based physical line it is on.
    checkpoints: Vec<(usize, CheckpointId)>,
    /// Physical lines that have a break, with the break.
    broken: BTreeMap<usize, BreakKind>,
    max_seq: Option<u64>,
    /// A partial copy only: hashes of the last `RESEND_WINDOW` chained
    /// lines. A chained line whose exact bytes are among them
    /// is a resend (delivery is at least once) and is skipped before it is
    /// judged: it neither advances the chain state (`prev_hash`,
    /// `expected`) nor counts as a break, so the line after a resent run
    /// is checked against the original it repeats. Only byte-identical
    /// lines qualify, so an edited repeat is still judged (and breaks);
    /// a repeat older than the window is judged too, and breaks as a
    /// `seq` gap. The local log never skips anything.
    recent: HashSet<String>,
    recent_order: VecDeque<String>,
    /// A partial copy only: the newest chained, unbroken line of the
    /// current intact stretch, and the one before it.
    run_last: Option<(u64, String)>,
    run_prev: Option<(u64, String)>,
    /// A partial copy only: the lines to look up in the local log.
    heads: Vec<Head>,
    /// The local log only: the `seq`s to note the line hashes of (from the
    /// copy's `heads`), and those hashes (several when a chain restarts).
    watch: BTreeSet<u64>,
    found: BTreeMap<u64, Vec<String>>,
}

/// A line of the copy to look up in the local log by `seq`.
struct Head {
    seq: u64,
    hash: String,
    /// The next line's `prev` confirmed this line's bytes.
    vouched: bool,
}

/// How far back a resent line is recognised. A forwarder resends at most
/// what it sent after its last cursor write: one batch (at most 500).
const RESEND_WINDOW: usize = 10_000;

impl Seen {
    /// Track the intact stretches of a copy. A line inside a stretch is
    /// vouched for by the next line's `prev`, so the second-to-last line of
    /// each stretch is a vouched head; at the end of the copy its last line
    /// is a head too, though nothing vouches for it.
    fn track_run(&mut self, seq: Option<u64>, hash: &str, broken: bool) {
        match seq {
            _ if broken => {
                if let Some((seq, hash)) = self.run_prev.take() {
                    self.heads.push(Head {
                        seq,
                        hash,
                        vouched: true,
                    });
                }
                self.run_last = None;
            }
            Some(seq) => self.run_prev = self.run_last.replace((seq, hash.to_string())),
            None => {} // a v1 line before the chain
        }
    }

    /// The end of the copy.
    fn end_run(&mut self) {
        let last = self.run_last.take();
        self.track_run(None, "", true);
        if let Some((seq, hash)) = last {
            self.heads.push(Head {
                seq,
                hash,
                vouched: false,
            });
        }
    }

    fn remember(&mut self, hash: String) {
        if self.recent.insert(hash.clone()) {
            self.recent_order.push_back(hash);
        }
        if self.recent_order.len() > RESEND_WINDOW {
            if let Some(old) = self.recent_order.pop_front() {
                self.recent.remove(&old);
            }
        }
    }
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
            partial: false,
            seen: Seen::default(),
        }
    }

    pub(crate) fn check(&mut self, line: &[u8], file: &str, n: usize, report: &mut VerifyReport) {
        let hash = sha256_hex(line);
        self.seen.lines += 1;
        if self.partial && self.seen.recent.contains(&hash) {
            report.duplicates += 1;
            return;
        }
        let prev_hash = self.prev_hash.replace(hash.clone());
        let (seq, kind) = self.judge(line, prev_hash.as_deref(), &hash, report);
        if let Some(seq) = seq {
            self.seen.max_seq = self.seen.max_seq.max(Some(seq));
            if self.seen.watch.contains(&seq) {
                self.seen.found.entry(seq).or_default().push(hash.clone());
            }
        }
        if self.partial {
            self.seen.track_run(seq, &hash, kind.is_some());
            if seq.is_some() {
                self.seen.remember(hash);
            }
        }
        if let Some(kind) = kind {
            self.seen.broken.insert(self.seen.lines - 1, kind.clone());
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
            report.mode = obj.get("mode").and_then(Value::as_str).map(String::from);
            let key = obj.get("key").and_then(Value::as_str).map(String::from);
            self.set_key(key, report);
            self.expected = Some(1);
        } else {
            match self.expected {
                None if self.partial => {}
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
            // Before its first genesis a partial copy knows no chain id or
            // key to judge a signature with.
            let unknown_key = self.partial && !self.seen_genesis;
            let signed = match kind_field {
                Some("checkpoint") => {
                    report.checkpoints += 1;
                    self.note_checkpoint(&obj);
                    if unknown_key {
                        None
                    } else {
                        self.check_checkpoint(&obj, seq, prev_hash)
                    }
                }
                Some("key_rotate") if unknown_key => None,
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

    /// Remember a checkpoint's signed head for `verify_external`.
    fn note_checkpoint(&mut self, obj: &serde_json::Map<String, Value>) {
        let id = (|| {
            Some(CheckpointId {
                head_seq: obj.get("head_seq")?.as_u64()?,
                head: obj.get("head")?.as_str()?.to_string(),
                sig: obj.get("sig")?.as_str()?.to_string(),
            })
        })();
        if let Some(id) = id {
            self.seen.checkpoints.push((self.seen.lines - 1, id));
        }
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
    /// too but is a break when there was a key to sign with; an invalid one,
    /// or an unsigned one without a valid SPKI `new_key`, is a break and the
    /// key stays.
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
            // An unsigned change must at least name a real key: a null or
            // non-SPKI `new_key` would drop the key in force and let a later
            // unsigned rotate pass as a keyless chain adopting one.
            if new_key.as_deref().and_then(fingerprint_of).is_none() {
                return Some(BreakKind::BadKeyRotate);
            }
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
