//! The tree delta a box exports (plan 39, spec §7.5 Out, §12): frames of
//! [`crate::frame`], written by the guest and validated by the host as
//! hostile input before anything is reviewed or landed.
//!
//! Wire format (L1):
//! - `{"t":"delta","n":<export n>,"entries":<count>}`
//! - per entry, sorted by path bytes, each path once:
//!   `{"t":"entry","path","op","kind","mode","size","sha256","old_kind","old_size","old_sha256"}`
//!   then Bytes frames: `old_size` bytes of the old content (modify only),
//!   then `size` bytes of the new content (add, modify). A symlink's content
//!   is its target.
//! - `{"t":"end","entries":<count>}`
//!
//! Field rules:
//! - add: `old_*` are null.
//! - modify: `old_kind`, `old_size`, `old_sha256` describe the base entry;
//!   `kind`, `mode`, `size`, `sha256` the new one (the kind may change).
//! - delete: the one rule (controller ruling R-T1a) is `mode` 0, `size` 0
//!   and `sha256` `""` (nothing new is described); `kind` equals
//!   `old_kind`, and `old_*` describe the base entry being removed. No
//!   bytes follow.
//!
//! Path rules beyond [`check_path`]: at most [`MAX_DEPTH`] components, no
//! unsafe char (control, bidi, invisible), and no `.git` alias: a component
//! whose [`normalize_component`] is `.git` or `git~<digits>` (R-T1e, R-T3i).
//! No component a Windows or macOS host would read as another name (R-T3h):
//! none ends in a dot or a space, none contains any of `<>:"|?*` (so no
//! NTFS stream such as `a::$DATA`), and none is shaped like an 8.3 short
//! name (the part before the first `.` is 1 to 6 chars, `~`, then digits,
//! as in `CLAUDE~1.MD`), and every component is already in Unicode NFC
//! form (R-T3l). The same rules apply to every named component of a
//! symlink target. Case-only collisions are not refused here (Task 3 flags
//! them).
//!
//! No path may go through a symlink, in the base or in the delta, compared
//! in their [`fold_path`] spelling (R-T1e, R-T3i, R-T3l: canonical
//! decomposition, full case fold, combining marks dropped). So a directory
//! and a symlink never swap in one delta, either way: deleting the symlink `ln` and adding `ln/x` is
//! refused, and so is adding the symlink `docs` while deleting `docs/a`.
//!
//! Every reason is free of unsafe chars: guest text in it (paths, targets,
//! serde's echo of unknown field or variant names) is escaped as `\u{..}`.
//! [`DeltaError::path`] is the raw guest path; render it escaped (the
//! `Display` impl does).
//!
//! The [`Reader`] is fed one frame at a time. Everything a header declares
//! (entry count, sizes, running totals, path length and depth, modes) is
//! checked before a single content byte is read; content is hashed as it
//! streams and only new content reaches the [`BlobSink`], whose `finish` is
//! called once the hash has been verified. [`Reader::finish`] then checks
//! the resulting tree (L3).

use crate::frame::{write_frame, Frame, MAX_FRAME};
use crate::manifest::{check_path, hex, is_hex, BaseManifest, Entry, EntryKind, LINK_MAX};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::ops::Bound;
use unicode_normalization::{is_nfc, UnicodeNormalization};

/// L2: the most entries one delta may carry.
pub const MAX_ENTRIES: usize = 20_000;
/// L2: the largest content one entry may carry, on each side.
pub const MAX_FILE_BYTES: u64 = 64 << 20;
/// L2: the most new content one delta may carry (old content is bounded by
/// the same number separately).
pub const MAX_TOTAL_BYTES: u64 = 512 << 20;
/// R-P1: the most `/`-separated components a delta path may have.
pub const MAX_DEPTH: usize = 64;
/// R-P1: the largest JSON frame (an entry header, the delta header or the
/// end frame) the reader accepts, serialized.
pub const MAX_HEAD_BYTES: usize = 64 << 10;
/// The reason given when the old side of a modify or delete does not match
/// the base manifest.
pub const BASE_MISMATCH: &str = "the box's base no longer matches";

/// What an entry does to its path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Add,
    Modify,
    Delete,
}

/// One entry header (the `"t":"entry"` frame without its tag).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryHead {
    pub path: String,
    pub op: Op,
    pub kind: EntryKind,
    pub mode: u32,
    pub size: u64,
    pub sha256: String,
    pub old_kind: Option<EntryKind>,
    pub old_size: Option<u64>,
    pub old_sha256: Option<String>,
}

/// The caps (L2); `Default` gives the plan's values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub entries: usize,
    pub file_bytes: u64,
    pub total_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            entries: MAX_ENTRIES,
            file_bytes: MAX_FILE_BYTES,
            total_bytes: MAX_TOTAL_BYTES,
        }
    }
}

/// Where new content goes (the host spills it to `blobs/<sha256>`).
/// `begin`, then `write`s, then `finish(sha256)` once the content's hash
/// has been verified. On an error from the reader the caller discards
/// whatever was begun and not finished.
pub trait BlobSink {
    fn begin(&mut self) -> io::Result<()>;
    fn write(&mut self, b: &[u8]) -> io::Result<()>;
    fn finish(&mut self, sha256: &str) -> io::Result<()>;
}

/// A delta that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Valid {
    pub n: u32,
    pub entries: Vec<EntryHead>,
}

/// Why a delta was refused: the offending path, if any, and a human reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaError {
    pub path: Option<String>,
    pub reason: String,
}

impl std::fmt::Display for DeltaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.path {
            // Debug quoting: the path came from the guest.
            Some(p) => write!(f, "delta refused: {}: {}", esc(p), clean(&self.reason)),
            None => write!(f, "delta refused: {}", clean(&self.reason)),
        }
    }
}

impl std::error::Error for DeltaError {}

/// Replaces every unsafe char (control, bidi, invisible) with `\u{..}`.
fn clean(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if saiife_wire::text::is_unsafe_char(c) {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// Guest text for a reason: Debug-quoted, then cleaned.
fn esc(s: &str) -> String {
    clean(&format!("{s:?}"))
}

/// Every refusal goes through here, so no reason carries an unsafe char
/// whatever guest text was formatted into it (serde echoes unknown field
/// and variant names raw).
fn bad(path: Option<&str>, reason: impl Into<String>) -> DeltaError {
    DeltaError {
        path: path.map(str::to_string),
        reason: clean(&reason.into()),
    }
}

fn io_bad(path: &str, e: io::Error) -> DeltaError {
    bad(Some(path), format!("the blob store failed: {e}"))
}

/// The tag-less bodies of the delta header and the end frame.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeltaHead {
    n: u32,
    entries: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EndHead {
    entries: u64,
}

/// One side of an entry's content still being received.
struct Side {
    left: u64,
    hash: Sha256,
    /// The hash the side must have; `None` (only the old side in
    /// `paths_only`) is consumed and bounded but not checked.
    want: Option<String>,
}

impl Side {
    fn new(left: u64, want: Option<String>) -> Side {
        Side {
            left,
            hash: Sha256::new(),
            want,
        }
    }
}

/// The entry whose content is being received.
struct Pending {
    path: String,
    old: Option<Side>,
    new: Option<Side>,
    begun: bool,
    /// A symlink's target, collected to check it (at most `LINK_MAX` bytes).
    link: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Start,
    Entries,
    Done,
}

/// The validating state machine; see the module docs.
pub struct Reader<'a> {
    base: Option<&'a BaseManifest>,
    limits: Limits,
    sink: &'a mut dyn BlobSink,
    state: State,
    n: u32,
    declared: u64,
    entries: Vec<EntryHead>,
    pending: Option<Pending>,
    total_new: u64,
    total_old: u64,
    failed: Option<DeltaError>,
}

/// An `io::Write` that only counts, failing past a bound (sizes a JSON frame
/// without building it).
struct Counter {
    n: usize,
    max: usize,
}

impl Write for Counter {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.n += b.len();
        if self.n > self.max {
            return Err(io::Error::other("too large"));
        }
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Splits a JSON frame into its `t` tag and the remaining object, after
/// bounding its size.
fn split(v: serde_json::Value) -> Result<(String, serde_json::Value), DeltaError> {
    let mut c = Counter {
        n: 0,
        max: MAX_HEAD_BYTES,
    };
    if serde_json::to_writer(&mut c, &v).is_err() {
        return Err(bad(
            None,
            format!("a JSON frame is larger than {MAX_HEAD_BYTES} bytes"),
        ));
    }
    let serde_json::Value::Object(mut m) = v else {
        return Err(bad(None, "a JSON frame is not an object"));
    };
    let t = match m.remove("t") {
        Some(serde_json::Value::String(t)) => t,
        _ => return Err(bad(None, "a JSON frame has no \"t\" tag")),
    };
    Ok((t, serde_json::Value::Object(m)))
}

/// The proper ancestors of a path, nearest last (`a/b/c` → `a`, `a/b`).
fn ancestors(p: &str) -> impl Iterator<Item = &str> {
    p.match_indices('/').map(move |(i, _)| &p[..i])
}

fn has_unsafe(s: &str) -> Option<char> {
    s.chars().find(|&c| saiife_wire::text::is_unsafe_char(c))
}

/// R-T3i: combining marks a normalising file system may drop.
fn is_combining(c: char) -> bool {
    matches!(c as u32,
        0x0300..=0x036F | 0x1AB0..=0x1AFF | 0x1DC0..=0x1DFF | 0x20D0..=0x20FF | 0xFE20..=0xFE2F)
}

/// R-T3i, R-T3l: the one comparison key of a path component, the spelling
/// case-insensitive, normalising hosts (NTFS, HFS+, APFS) may treat as the
/// same name. Every comparison of names goes through it: [`fold_path`] (the
/// symlink write-through checks), [`is_git_alias`] (here and in the guest's
/// export) and the host's protected-path list and case-collision flag.
///
/// In order:
/// 1. trailing dots and spaces stripped (refused anyway, R-T3h);
/// 2. canonical decomposition (NFD), so a precomposed and a decomposed
///    spelling meet (delta paths are NFC, but base paths are not checked
///    and may be NFD, as a macOS checkout commits them);
/// 3. full case fold: Unicode lowercase, then `ß` → `ss` (`ẞ` lowercases to
///    `ß`), `ς` → `σ`, the Kelvin sign → `k`, long s → `s`, dotted and
///    dotless i → `i`, the Angstrom sign → `å`;
/// 4. decomposed again, then the combining marks dropped (over-folding
///    only refuses or flags more);
/// 5. trailing dots and spaces stripped again, in case a mark hid one.
pub fn normalize_component(c: &str) -> String {
    let mut cased = String::with_capacity(c.len());
    for ch in c.trim_end_matches(['.', ' ']).nfd() {
        for l in ch.to_lowercase() {
            match l {
                '\u{DF}' => cased.push_str("ss"),
                '\u{3C2}' => cased.push('\u{3C3}'),
                '\u{212A}' => cased.push('k'),
                '\u{017F}' => cased.push('s'),
                '\u{0130}' | '\u{0131}' => cased.push('i'),
                '\u{212B}' => cased.push('\u{E5}'),
                l => cased.push(l),
            }
        }
    }
    let mut out: String = cased.nfd().filter(|&ch| !is_combining(ch)).collect();
    // A mark after a trailing dot hid the dot from the first trim.
    let t = out.trim_end_matches(['.', ' ']).len();
    out.truncate(t);
    out
}

/// R-T3i: a path in the spelling a case-insensitive, normalising host
/// resolves it to: [`normalize_component`] of each component, rejoined.
pub fn fold_path(p: &str) -> String {
    p.split('/')
        .map(normalize_component)
        .collect::<Vec<_>>()
        .join("/")
}

/// R-T1e, R-T3i: a component a Windows or macOS host could resolve to
/// `.git`: [`normalize_component`] gives `.git` or the 8.3 short name
/// `git~<digits>`.
pub fn is_git_alias(c: &str) -> bool {
    let n = normalize_component(c);
    if n == ".git" {
        return true;
    }
    n.strip_prefix("git~")
        .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
}

/// R-T3h: an 8.3 short name: the part before the first `.` (or the whole
/// name) is 1 to 6 chars, `~`, then one or more digits.
fn is_short_name(c: &str) -> bool {
    let stem = c.split('.').next().unwrap_or(c);
    let Some((head, digits)) = stem.rsplit_once('~') else {
        return false;
    };
    (1..=6).contains(&head.chars().count())
        && !head.contains('~')
        && !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
}

/// R-T3h, R-T3l: a component no host may read as a different name; it
/// must also already be NFC, so precomposed and decomposed spellings of one
/// name never both reach a checkout.
fn check_spelling(c: &str) -> Result<(), String> {
    if !is_nfc(c) {
        return Err(format!("component {c:?} is not in Unicode NFC form"));
    }
    if c.ends_with(['.', ' ']) {
        return Err(format!("component {c:?} ends with a dot or a space"));
    }
    if let Some(x) = c.chars().find(|x| "<>:\"|?*".contains(*x)) {
        return Err(format!(
            "component {c:?} contains {x:?}, which Windows does not allow in a name"
        ));
    }
    if is_short_name(c) {
        return Err(format!("component {c:?} is shaped like an 8.3 short name"));
    }
    Ok(())
}

/// Path rules beyond [`check_path`]: depth, unsafe chars, `.git` aliases.
fn check_delta_path(p: &str) -> Result<(), String> {
    check_path(p).map_err(|e| clean(&e))?;
    if p.split('/').any(is_git_alias) {
        return Err("has a .git component (or an NTFS alias of one)".into());
    }
    for c in p.split('/') {
        check_spelling(c)?;
    }
    if p.split('/').count() > MAX_DEPTH {
        return Err(format!("deeper than MAX_DEPTH ({MAX_DEPTH} components)"));
    }
    if let Some(c) = has_unsafe(p) {
        return Err(format!(
            "contains the unsafe character U+{:04X} (control, bidi or invisible)",
            c as u32
        ));
    }
    Ok(())
}

/// R-P1: mode bits first, naming every forbidden bit present.
fn check_mode_bits(mode: u32) -> Result<(), String> {
    let mut named = Vec::new();
    if mode & 0o170000 != 0 {
        named.push("file-type bits (0o170000)");
    }
    if mode & 0o4000 != 0 {
        named.push("setuid (0o4000)");
    }
    if mode & 0o2000 != 0 {
        named.push("setgid (0o2000)");
    }
    if mode & 0o1000 != 0 {
        named.push("sticky (0o1000)");
    }
    if named.is_empty() {
        Ok(())
    } else {
        Err(format!("mode {mode:#o} sets {}", named.join(", ")))
    }
}

/// A symlink target: UTF-8, non-empty, relative, at most [`LINK_MAX`]
/// bytes, no NUL, `\` or unsafe char, no `.git` component (or alias), and
/// `..` only as a leading run, not climbing above the repo. With every
/// link's directory a real directory, this keeps the link inside the repo
/// lexically and through any chain of links the delta creates; a base
/// symlink's target is not checked (the manifest holds only its hash), so a
/// delta link resolving through an escaping base link escapes with it.
fn check_link(path: &str, target: &[u8]) -> Result<(), DeltaError> {
    let refuse = |why: String| Err(bad(Some(path), format!("symlink target {why}")));
    let Ok(t) = std::str::from_utf8(target) else {
        return refuse("is not UTF-8".into());
    };
    if t.is_empty() {
        return refuse("is empty".into());
    }
    if target.len() as u64 > LINK_MAX {
        return refuse(format!("is longer than {LINK_MAX} bytes"));
    }
    if t.starts_with('/') {
        return refuse(format!("{t:?} is absolute"));
    }
    if t.contains('\0') {
        return refuse("contains NUL".into());
    }
    if t.contains('\\') {
        return refuse(format!("{t:?} contains a backslash"));
    }
    if let Some(c) = has_unsafe(t) {
        return refuse(format!(
            "contains the unsafe character U+{:04X} (control, bidi or invisible)",
            c as u32
        ));
    }
    // The link's directory depth: components of `path` minus the link name.
    let mut depth = path.split('/').count() - 1;
    let mut named = false;
    for c in t.split('/') {
        match c {
            "" | "." => {}
            ".." if named => {
                return refuse(format!("{t:?} has a .. after a name"));
            }
            ".." => {
                if depth == 0 {
                    return refuse(format!("{t:?} leaves the repo"));
                }
                depth -= 1;
            }
            c if is_git_alias(c) => {
                return refuse(format!("{t:?} has a .git component"));
            }
            c => {
                if let Err(e) = check_spelling(c) {
                    return refuse(format!("{t:?}: {e}"));
                }
                named = true;
            }
        }
    }
    Ok(())
}

impl<'a> Reader<'a> {
    /// Validates against the base manifest (the host's receive).
    pub fn new(base: &'a BaseManifest, limits: Limits, sink: &'a mut dyn BlobSink) -> Reader<'a> {
        Reader::make(Some(base), limits, sink)
    }

    /// The CLI's re-check of `delta.bin`: path, symlink, size, mode and hash
    /// rules, no manifest (`old_*` ignored; a modify's old bytes are
    /// consumed and bounded but not checked).
    pub fn paths_only(limits: Limits, sink: &'a mut dyn BlobSink) -> Reader<'a> {
        Reader::make(None, limits, sink)
    }

    fn make(
        base: Option<&'a BaseManifest>,
        limits: Limits,
        sink: &'a mut dyn BlobSink,
    ) -> Reader<'a> {
        Reader {
            base,
            limits,
            sink,
            state: State::Start,
            n: 0,
            declared: 0,
            entries: Vec::new(),
            pending: None,
            total_new: 0,
            total_old: 0,
            failed: None,
        }
    }

    /// Feeds one frame. `Ok(true)` once the end frame has been accepted.
    /// After an error every later call returns the same error.
    pub fn push(&mut self, f: Frame) -> Result<bool, DeltaError> {
        if let Some(e) = &self.failed {
            return Err(e.clone());
        }
        let r = self.step(f);
        if let Err(e) = &r {
            self.failed = Some(e.clone());
        }
        r
    }

    fn step(&mut self, f: Frame) -> Result<bool, DeltaError> {
        match (self.state, f) {
            (State::Done, _) => Err(bad(None, "a frame after the end frame")),
            (State::Start, Frame::Bytes(_)) => {
                Err(bad(None, "content bytes before the delta header"))
            }
            (State::Start, Frame::Json(v)) => {
                let (t, body) = split(v)?;
                if t != "delta" {
                    return Err(bad(None, format!("expected the delta header, got {t:?}")));
                }
                let h: DeltaHead = serde_json::from_value(body)
                    .map_err(|e| bad(None, format!("bad delta header: {e}")))?;
                if h.entries > self.limits.entries as u64 {
                    return Err(bad(
                        None,
                        format!(
                            "{} entries is over MAX_ENTRIES ({})",
                            h.entries, self.limits.entries
                        ),
                    ));
                }
                self.n = h.n;
                self.declared = h.entries;
                self.state = State::Entries;
                Ok(false)
            }
            (State::Entries, Frame::Bytes(b)) => {
                self.advance(&b)?;
                Ok(false)
            }
            (State::Entries, Frame::Json(v)) => {
                if let Some(p) = &self.pending {
                    return Err(bad(
                        Some(&p.path),
                        "fewer content bytes than the entry declared",
                    ));
                }
                let (t, body) = split(v)?;
                match t.as_str() {
                    "entry" => {
                        self.entry(body)?;
                        Ok(false)
                    }
                    "end" => {
                        let e: EndHead = serde_json::from_value(body)
                            .map_err(|e| bad(None, format!("bad end frame: {e}")))?;
                        let got = self.entries.len() as u64;
                        if e.entries != self.declared || got != self.declared {
                            return Err(bad(
                                None,
                                format!(
                                    "entry count mismatch: the header declared {}, the end frame says {}, {got} were sent",
                                    self.declared, e.entries
                                ),
                            ));
                        }
                        self.state = State::Done;
                        Ok(true)
                    }
                    other => Err(bad(None, format!("unexpected frame {other:?}"))),
                }
            }
        }
    }

    /// Checks one entry header: everything is bounded here, before any of
    /// its content is read.
    fn entry(&mut self, body: serde_json::Value) -> Result<(), DeltaError> {
        if self.entries.len() as u64 >= self.declared {
            return Err(bad(
                None,
                format!("more entries than the {} declared", self.declared),
            ));
        }
        let h: EntryHead = serde_json::from_value(body)
            .map_err(|e| bad(None, format!("bad entry header: {e}")))?;
        let p = h.path.as_str();
        let refuse = |why: String| Err(bad(Some(p), why));

        check_delta_path(p).map_err(|e| bad(Some(p), e))?;
        if let Some(prev) = self.entries.last() {
            if prev.path == h.path {
                return refuse("duplicate path".into());
            }
            if prev.path.as_bytes() > p.as_bytes() {
                return refuse(format!(
                    "entries not sorted by path (after {:?})",
                    prev.path
                ));
            }
        }

        check_mode_bits(h.mode).map_err(|e| bad(Some(p), e))?;
        match (h.op, &h.kind) {
            (Op::Delete, _) => {
                if h.mode != 0 || h.size != 0 || !h.sha256.is_empty() {
                    return refuse("a delete must have mode 0, size 0 and sha256 \"\"".into());
                }
            }
            (_, EntryKind::File) => {
                if h.mode != 0o644 && h.mode != 0o755 {
                    return refuse(format!("file mode {:#o} is not 0o644 or 0o755", h.mode));
                }
            }
            (_, EntryKind::Symlink) => {
                if h.mode != 0 {
                    return refuse(format!("symlink mode {:#o} is not 0", h.mode));
                }
            }
        }
        if h.op != Op::Delete && !is_hex(&h.sha256, &[64]) {
            return refuse("sha256 is not 64 lowercase hex digits".into());
        }

        // Caps (L2), before any byte.
        if h.size > self.limits.file_bytes {
            return refuse(format!(
                "size {} is over MAX_FILE_BYTES ({})",
                h.size, self.limits.file_bytes
            ));
        }
        if h.kind == EntryKind::Symlink && h.size > LINK_MAX {
            return refuse(format!(
                "symlink target of {} bytes is over {LINK_MAX}",
                h.size
            ));
        }
        // A modify's old bytes follow even in `paths_only`; they are bounded
        // like new ones (with a manifest, old_size must also match the base).
        let old_size = if h.op == Op::Modify {
            h.old_size.unwrap_or(0)
        } else {
            0
        };
        if old_size > self.limits.file_bytes {
            return refuse(format!(
                "old size {old_size} is over MAX_FILE_BYTES ({})",
                self.limits.file_bytes
            ));
        }
        let total_new = self.total_new.saturating_add(h.size);
        if total_new > self.limits.total_bytes {
            return refuse(format!(
                "new content reaches {total_new} bytes, over MAX_TOTAL_BYTES ({})",
                self.limits.total_bytes
            ));
        }
        let total_old = self.total_old.saturating_add(old_size);
        if total_old > self.limits.total_bytes {
            return refuse(format!(
                "old content reaches {total_old} bytes, over MAX_TOTAL_BYTES ({})",
                self.limits.total_bytes
            ));
        }

        // The old side against the base (L3).
        let mut old_want = None;
        if let Some(base) = self.base {
            let have = base.entries.get(p);
            match h.op {
                Op::Add => {
                    if h.old_kind.is_some() || h.old_size.is_some() || h.old_sha256.is_some() {
                        return refuse("an add carries old_kind/old_size/old_sha256".into());
                    }
                    if have.is_some() {
                        return refuse("an add of a path the base already has".into());
                    }
                }
                Op::Modify | Op::Delete => {
                    let Some(e) = have else {
                        return refuse(format!(
                            "a {} of a path the base does not have",
                            if h.op == Op::Modify {
                                "modify"
                            } else {
                                "delete"
                            }
                        ));
                    };
                    if h.old_kind.as_ref() != Some(&e.kind)
                        || h.old_size != Some(e.size)
                        || h.old_sha256.as_deref() != Some(e.sha256.as_str())
                    {
                        return refuse(BASE_MISMATCH.into());
                    }
                    if h.op == Op::Delete && h.kind != e.kind {
                        return refuse("a delete's kind is not its old_kind".into());
                    }
                    old_want = Some(e.sha256.clone());
                }
            }
        }

        self.total_new = total_new;
        self.total_old = total_old;
        let pending = Pending {
            path: h.path.clone(),
            old: (h.op == Op::Modify).then(|| Side::new(old_size, old_want)),
            new: (h.op != Op::Delete).then(|| Side::new(h.size, Some(h.sha256.clone()))),
            begun: false,
            link: (h.op != Op::Delete && h.kind == EntryKind::Symlink).then(Vec::new),
        };
        self.entries.push(h);
        self.pending = Some(pending);
        self.advance(&[])
    }

    /// Feeds content bytes to the pending entry, finishing sides (and the
    /// entry) as their counts reach zero. Bytes beyond the entry are refused.
    fn advance(&mut self, mut data: &[u8]) -> Result<(), DeltaError> {
        loop {
            let Some(p) = self.pending.as_mut() else {
                if data.is_empty() {
                    return Ok(());
                }
                let last = self.entries.last().map(|h| h.path.as_str());
                return Err(bad(last, "more content bytes than the entry declared"));
            };
            if let Some(o) = p.old.as_mut() {
                let take = o.left.min(data.len() as u64) as usize;
                o.hash.update(&data[..take]);
                o.left -= take as u64;
                data = &data[take..];
                if o.left > 0 {
                    return Ok(());
                }
                let o = p.old.take().expect("old side present");
                if let Some(want) = o.want {
                    if hex(&o.hash.finalize()) != want {
                        return Err(bad(Some(&p.path), BASE_MISMATCH));
                    }
                }
                continue;
            }
            if let Some(nw) = p.new.as_mut() {
                if !p.begun {
                    self.sink.begin().map_err(|e| io_bad(&p.path, e))?;
                    p.begun = true;
                }
                let take = nw.left.min(data.len() as u64) as usize;
                let chunk = &data[..take];
                nw.hash.update(chunk);
                nw.left -= take as u64;
                data = &data[take..];
                if !chunk.is_empty() {
                    self.sink.write(chunk).map_err(|e| io_bad(&p.path, e))?;
                }
                if let Some(link) = p.link.as_mut() {
                    link.extend_from_slice(chunk);
                }
                if nw.left > 0 {
                    return Ok(());
                }
                let nw = p.new.take().expect("new side present");
                let want = nw.want.expect("the new side always has a hash");
                if hex(&nw.hash.finalize()) != want {
                    return Err(bad(
                        Some(&p.path),
                        "content does not match its declared sha256",
                    ));
                }
                if let Some(link) = &p.link {
                    check_link(&p.path, link)?;
                }
                self.sink.finish(&want).map_err(|e| io_bad(&p.path, e))?;
                continue;
            }
            self.pending = None;
        }
    }

    /// The resulting-tree checks (L3) once the end frame was accepted.
    pub fn finish(self) -> Result<Valid, DeltaError> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        if self.state != State::Done {
            return Err(bad(
                self.pending.as_ref().map(|p| p.path.as_str()),
                "truncated: the delta ended before its end frame",
            ));
        }
        let delta: BTreeMap<&str, &EntryHead> =
            self.entries.iter().map(|h| (h.path.as_str(), h)).collect();
        let base = self.base.map(|b| &b.entries);
        let deleted = |k: &str| matches!(delta.get(k), Some(d) if d.op == Op::Delete);
        let in_result = |k: &str| match delta.get(k) {
            Some(d) => d.op != Op::Delete,
            None => base.is_some_and(|b| b.contains_key(k)),
        };

        // No writing through a symlink, in the base or in the delta, folded
        // as a case-insensitive, normalising host would (R-T1e, R-T3i:
        // `LN/x` or `doc\u{17F}/x` goes through `ln` or `docs` there).
        let fold = fold_path;
        let base_links: BTreeSet<String> = base
            .into_iter()
            .flatten()
            .filter(|(_, e)| e.kind == EntryKind::Symlink)
            .map(|(k, _)| fold(k))
            .collect();
        let delta_links: BTreeSet<String> = self
            .entries
            .iter()
            .filter(|h| h.kind == EntryKind::Symlink)
            .map(|h| fold(&h.path))
            .collect();
        for h in &self.entries {
            let folded = fold(&h.path);
            for a in ancestors(&folded) {
                if base_links.contains(a) {
                    return Err(bad(
                        Some(&h.path),
                        format!("goes through {a:?}, a symlink in the base"),
                    ));
                }
                if delta_links.contains(a) {
                    return Err(bad(
                        Some(&h.path),
                        format!("goes through {a:?}, a symlink in the delta"),
                    ));
                }
            }
        }

        // No path both an entry and a directory of another.
        for h in self.entries.iter().filter(|h| h.op != Op::Delete) {
            for a in ancestors(&h.path) {
                if in_result(a) {
                    return Err(bad(
                        Some(&h.path),
                        format!("{a:?} would be both a file and a directory"),
                    ));
                }
            }
            let prefix = format!("{}/", h.path);
            let in_delta = delta
                .range::<&str, _>((Bound::Included(prefix.as_str()), Bound::Unbounded))
                .map(|(k, _)| *k)
                .take_while(|k| k.starts_with(prefix.as_str()))
                .any(|k| !deleted(k));
            let in_base = base.is_some_and(|b| {
                b.range::<str, _>((Bound::Included(prefix.as_str()), Bound::Unbounded))
                    .map(|(k, _)| k.as_str())
                    .take_while(|k| k.starts_with(prefix.as_str()))
                    .any(|k| !deleted(k))
            });
            if in_delta || in_base {
                return Err(bad(
                    Some(&h.path),
                    "would be both a file and a directory".to_string(),
                ));
            }
        }

        Ok(Valid {
            n: self.n,
            entries: self.entries,
        })
    }
}

/// One entry for [`write_delta`]: its header, the old bytes (modify) and
/// the new bytes (add, modify).
pub type DeltaItem<'b> = (EntryHead, Option<&'b [u8]>, Option<&'b [u8]>);

/// Writes a delta. Each entry's `old` bytes (modify) and `new` bytes (add,
/// modify) are sent as given, in frames of at most [`MAX_FRAME`] bytes; the
/// writer does not check them (the reader does).
pub fn write_delta(w: &mut impl Write, n: u32, entries: &[DeltaItem<'_>]) -> io::Result<()> {
    let json = |v: serde_json::Value| Frame::Json(v);
    write_frame(
        w,
        &json(serde_json::json!({"t": "delta", "n": n, "entries": entries.len()})),
    )?;
    for (head, old, new) in entries {
        let mut v = serde_json::to_value(head)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        v["t"] = "entry".into();
        write_frame(w, &json(v))?;
        for side in [old, new].into_iter().flatten() {
            for chunk in side.chunks(MAX_FRAME) {
                write_frame(w, &Frame::Bytes(chunk.to_vec()))?;
            }
        }
    }
    write_frame(
        w,
        &json(serde_json::json!({"t": "end", "entries": entries.len()})),
    )
}

/// The base after a land of `v`: every entry, or only the paths in `only`
/// (a partial land; the caller picks a set that keeps the tree valid).
/// `files` and `bytes` are recomputed; the other fields are kept.
pub fn apply_manifest(
    base: &BaseManifest,
    v: &Valid,
    only: Option<&BTreeSet<String>>,
) -> BaseManifest {
    let mut m = base.clone();
    for h in &v.entries {
        if only.is_some_and(|o| !o.contains(&h.path)) {
            continue;
        }
        match h.op {
            Op::Delete => {
                m.entries.remove(&h.path);
            }
            Op::Add | Op::Modify => {
                m.entries.insert(
                    h.path.clone(),
                    Entry {
                        kind: h.kind.clone(),
                        mode: h.mode,
                        size: h.size,
                        sha256: h.sha256.clone(),
                    },
                );
            }
        }
    }
    m.files = m.entries.len() as u64;
    m.bytes = m.entries.values().map(|e| e.size).sum();
    m
}
