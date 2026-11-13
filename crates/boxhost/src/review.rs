//! The host side of a land review (plan 39 Task 3, spec §7.5, §10.5, §12).
//!
//! [`receive`] asks the guest for export `n` and feeds the frames to the
//! hostile-input [`Reader`] against the trusted base manifest. New content
//! goes to `lands/<n>/blobs/<sha256>` once its hash is verified; the old
//! content of a `modify` small enough to render as text is kept the same
//! way once it matches the manifest. On any error `lands/<n>` is removed:
//! nothing of a refused delta is stored.
//!
//! [`render`] writes the unified diff itself from trusted old content and
//! validated new content, never from guest-made diff text. Every guest char
//! for which `saiife_wire::text::is_unsafe_char` holds (TAB aside) is shown
//! as `\u{XXXX}`; `'\n'` ends lines, a lone `'\r'` does not (ruling R-P2).
//! Escaping is not injective, so each file's header carries
//! `index <old sha256>..<new sha256> <mode>` (64 zeros for a side that does
//! not exist): `diff_sha256` = SHA-256 of the full rendering binds every
//! byte that lands. Format (plan 39 fixed values):
//!
//! ```text
//! diff --saiife a/<p> b/<p>
//! index <old>..<new> <mode>
//! new file mode <mode> | deleted file mode <mode> | old mode <m>\nnew mode <m>
//! --- a/<p> | --- /dev/null
//! +++ b/<p> | +++ /dev/null
//! @@ hunks, 3 lines of context, `\ No newline at end of file` @@
//! | Binary file b/<p>: <size> bytes, sha256 <hex>
//! | File a/<p> deleted: <size> bytes, sha256 <hex>
//! ```
//!
//! Modes are `100644`, `100755`, and `120000` for a symlink, which renders
//! as a one-line text file holding its target. A side is text when both
//! sides are UTF-8 without NUL and at most [`TEXT_MAX`] bytes; else the
//! file is binary. A delete carries no content in the delta (ruling R-T1a),
//! so it renders as its `File … deleted` line (the index line binds the
//! old hash). Lines are diffed with `similar`'s Myers over `'\n'`-split
//! lines with no deadline, so the output is deterministic; a file whose
//! changed middle is too large for the work budget renders as one hunk
//! replacing that middle.
//!
//! Land files (`delta.bin`, `review.json`) are written by
//! [`write_land_files`] after [`check_subset`] (ruling R-T1d).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::ops::Bound;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use saiife_boxes::guest::GuestError;
use saiife_boxproto::delta::{
    apply_manifest, fold_path, normalize_component, BlobSink, DeltaError, EntryHead, Limits, Op,
    Reader, Valid,
};
use saiife_boxproto::frame::{write_frame, Frame, MAX_FRAME};
use saiife_boxproto::manifest::{BaseManifest, EntryKind};
use saiife_boxproto::msg::Request;
use saiife_wire::source::{BoxId, DiffSummary, FileChange, FileStatus, MAX_DIFF_BYTES};
use serde::{Deserialize, Serialize};
use similar::udiff::UnifiedHunkHeader;
use similar::{capture_diff_slices, group_diff_ops, Algorithm, ChangeTag, DiffOp};

use crate::guest::{VsockGuest, STREAM_DEADLINE};
use crate::paths::BoxPaths;

/// L2: the whole export, first frame to end frame (plan 38 R13).
pub const EXPORT_TIMEOUT: Duration = Duration::from_secs(120);
/// Each frame after the first must arrive within this (the first may take
/// the whole [`EXPORT_TIMEOUT`]: the guest snapshots `/work` first).
pub const EXPORT_FRAME_TIMEOUT: Duration = Duration::from_secs(30);
/// The text rule: each side at most this many bytes.
pub const TEXT_MAX: u64 = 1 << 20;
/// Guest `why` text kept in a refusal, in bytes.
const MAX_WHY: usize = 512;
/// Line-diff work allowed for one file, in `(changed lines)^2`.
const FILE_COST: u128 = 1 << 28;
/// Line-diff work allowed for one rendering, all files together.
const TOTAL_COST: u128 = 1 << 32;
/// The in-progress blob names inside `blobs/` (never a 64-hex name).
const PART: &str = ".part";
const OLD_PART: &str = ".old";

/// One flagged path (L6). `why` is one of "protected path",
/// "rule <pack>: <reason>", "becomes executable", "new symlink", "binary",
/// "differs only in case or accents from <other>".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flag {
    pub path: String,
    pub why: String,
}

/// The review of export `n` (or of the subset of it a partial land takes).
/// `entries` are the reviewed (selected) entries; `base_head` is the
/// user's `HEAD` at spawn (L5), shown beside `summary.base_commit`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Review {
    pub n: u32,
    pub summary: DiffSummary,
    pub flags: Vec<Flag>,
    pub entries: Vec<EntryHead>,
    pub base_head: Option<String>,
}

/// Plan 32's `diff_hits`, mapped to flags by the daemon.
pub type Hits<'a> = &'a dyn Fn(&[&str]) -> Vec<Flag>;

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn sha256(b: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, b).as_ref())
}

fn zero_sha() -> String {
    "0".repeat(64)
}

fn is_sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Guest text in the rendering: every unsafe char except TAB as
/// `\u{XXXX}` (R-P2).
pub fn escape(s: &str) -> String {
    escape_with(s, true)
}

fn escape_with(s: &str, keep_tab: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if (c != '\t' || !keep_tab) && saiife_wire::text::is_unsafe_char(c) {
            let _ = write!(out, "\\u{{{:04X}}}", c as u32);
        } else {
            out.push(c);
        }
    }
    out
}

/// Guest text in an error: Debug-quoted, then every unsafe char escaped.
fn quote(s: &str) -> String {
    escape_with(&format!("{s:?}"), false)
}

fn refused(reason: impl Into<String>) -> DeltaError {
    DeltaError {
        path: None,
        reason: escape_with(&reason.into(), false),
    }
}

fn nofollow() -> i32 {
    rustix::fs::OFlags::NOFOLLOW.bits() as i32
}

/// A new file, 0600, `O_CREAT|O_EXCL|O_NOFOLLOW`.
fn create_new(p: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nofollow())
        .open(p)
}

/// A daemon-written file, `O_NOFOLLOW`, regular, exactly `size` bytes.
fn open_blob(blobs: &Path, sha: &str, size: u64) -> io::Result<File> {
    if !is_sha(sha) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a sha256"));
    }
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(nofollow())
        .open(blobs.join(sha))?;
    let md = f.metadata()?;
    if !md.is_file() || md.len() != size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the blob is not a regular file of the declared size",
        ));
    }
    Ok(f)
}

/// A blob's bytes (`size` 0 needs no file).
fn read_blob(blobs: &Path, sha: &str, size: u64) -> io::Result<Vec<u8>> {
    if size == 0 {
        return Ok(Vec::new());
    }
    let f = open_blob(blobs, sha, size)?;
    let mut b = Vec::with_capacity(size as usize);
    f.take(size).read_to_end(&mut b)?;
    if b.len() as u64 != size {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short blob"));
    }
    Ok(b)
}

/// Writes `bytes` as `blobs/<sha>` (through a temp name) unless present.
fn put_blob(blobs: &Path, sha: &str, bytes: &[u8]) -> io::Result<()> {
    if !is_sha(sha) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a sha256"));
    }
    let dest = blobs.join(sha);
    if fs::symlink_metadata(&dest).is_ok() {
        return Ok(());
    }
    let tmp = blobs.join(OLD_PART);
    let mut f = create_new(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, &dest)
}

/// The blob store of one land: content is written to `blobs/.part` and
/// renamed to `blobs/<sha256>` only after the reader verified the hash.
struct Store {
    dir: PathBuf,
    part: Option<File>,
}

impl BlobSink for Store {
    fn begin(&mut self) -> io::Result<()> {
        self.part = Some(create_new(&self.dir.join(PART))?);
        Ok(())
    }
    fn write(&mut self, b: &[u8]) -> io::Result<()> {
        self.part
            .as_mut()
            .ok_or_else(|| io::Error::other("no blob begun"))?
            .write_all(b)
    }
    fn finish(&mut self, sha256: &str) -> io::Result<()> {
        let f = self
            .part
            .take()
            .ok_or_else(|| io::Error::other("no blob begun"))?;
        f.sync_all()?;
        drop(f);
        if !is_sha(sha256) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a sha256"));
        }
        fs::rename(self.dir.join(PART), self.dir.join(sha256))
    }
}

/// The old side of the current modify, kept when the review may render it
/// as text.
#[derive(Default)]
struct Tee {
    left: u64,
    buf: Option<Vec<u8>>,
    want: Option<String>,
}

/// `lands/` (0700, created if missing, never a symlink) and a new
/// `lands/<n>/blobs/`. An existing `lands/<n>` is refused and left alone.
fn make_land_dir(paths: &BoxPaths, n: u32) -> Result<(), DeltaError> {
    let lands = paths.lands_dir();
    let mut b = DirBuilder::new();
    b.mode(0o700);
    match b.create(&lands) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(refused(format!("cannot create the lands dir: {e}"))),
    }
    match fs::symlink_metadata(&lands) {
        Ok(m) if m.is_dir() => {}
        _ => return Err(refused("the lands dir is not a directory")),
    }
    match b.create(paths.land_dir(n)) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            return Err(refused(format!("land {n} already exists")))
        }
        Err(e) => return Err(refused(format!("cannot create land {n}: {e}"))),
    }
    if let Err(e) = b.create(paths.land_blobs(n)) {
        let _ = fs::remove_dir_all(paths.land_dir(n));
        return Err(refused(format!("cannot create the blob store: {e}")));
    }
    Ok(())
}

/// Receives export `n` into `lands/<n>/blobs` within [`EXPORT_TIMEOUT`].
pub fn receive(
    guest: &VsockGuest,
    id: &BoxId,
    paths: &BoxPaths,
    base: &BaseManifest,
    n: u32,
) -> Result<Valid, DeltaError> {
    receive_within(
        guest,
        id,
        paths,
        base,
        n,
        EXPORT_TIMEOUT,
        EXPORT_FRAME_TIMEOUT,
    )
}

/// [`receive`] with its own time caps (tests). `total` bounds the whole
/// export; each frame after the first must come within `per_frame`. On any
/// error `lands/<n>` is removed.
pub fn receive_within(
    guest: &VsockGuest,
    id: &BoxId,
    paths: &BoxPaths,
    base: &BaseManifest,
    n: u32,
    total: Duration,
    per_frame: Duration,
) -> Result<Valid, DeltaError> {
    make_land_dir(paths, n)?;
    let r = receive_into(guest, id, paths, base, n, total, per_frame);
    if r.is_err() {
        let _ = fs::remove_dir_all(paths.land_dir(n));
    }
    r
}

/// The guest's `{"t":"err","why"}` instead of a delta.
fn guest_refusal(v: &serde_json::Value) -> DeltaError {
    let mut why = v
        .get("why")
        .and_then(|w| w.as_str())
        .unwrap_or("")
        .to_string();
    if why.len() > MAX_WHY {
        let mut k = MAX_WHY;
        while !why.is_char_boundary(k) {
            k -= 1;
        }
        why.truncate(k);
    }
    refused(format!("the guest could not export: {}", quote(&why)))
}

fn tag(v: &serde_json::Value) -> Option<&str> {
    v.get("t").and_then(|t| t.as_str())
}

fn receive_into(
    guest: &VsockGuest,
    id: &BoxId,
    paths: &BoxPaths,
    base: &BaseManifest,
    n: u32,
    total: Duration,
    per_frame: Duration,
) -> Result<Valid, DeltaError> {
    let blobs = paths.land_blobs(n);
    let mut store = Store {
        dir: blobs.clone(),
        part: None,
    };
    let mut reader = Reader::new(base, Limits::default(), &mut store);
    let mut tee = Tee::default();
    let mut failed: Option<DeltaError> = None;
    let deadline = Instant::now() + total;
    let streamed = {
        let mut on_frame = |f: Frame| -> Result<bool, String> {
            let mut fail = |e: DeltaError| {
                let m = e.to_string();
                failed = Some(e);
                Err(m)
            };
            let mut head = None;
            match &f {
                Frame::Json(v) if tag(v) == Some("err") => return fail(guest_refusal(v)),
                Frame::Json(v) if tag(v) == Some("entry") => head = Some(v.clone()),
                Frame::Json(_) => {}
                Frame::Bytes(b) if tee.left > 0 => {
                    let take = tee.left.min(b.len() as u64) as usize;
                    if let Some(buf) = tee.buf.as_mut() {
                        buf.extend_from_slice(&b[..take]);
                    }
                    tee.left -= take as u64;
                }
                Frame::Bytes(_) => {}
            }
            let done = match reader.push(f) {
                Ok(d) => d,
                Err(e) => return fail(e),
            };
            // The old side is complete and the reader checked it against
            // the manifest; keep it if it may render as text.
            if tee.left == 0 {
                if let (Some(buf), Some(want)) = (tee.buf.take(), tee.want.take()) {
                    if sha256(&buf) != want {
                        return fail(refused(saiife_boxproto::delta::BASE_MISMATCH));
                    }
                    if let Err(e) = put_blob(&blobs, &want, &buf) {
                        return fail(refused(format!("the blob store failed: {e}")));
                    }
                }
            }
            if let Some(mut v) = head {
                if let Some(m) = v.as_object_mut() {
                    m.remove("t");
                }
                // The reader accepted this header, so it parses.
                if let Ok(h) = serde_json::from_value::<EntryHead>(v) {
                    if h.op == Op::Modify {
                        let old_size = h.old_size.unwrap_or(0);
                        let keep = old_size > 0 && old_size <= TEXT_MAX && h.size <= TEXT_MAX;
                        tee = Tee {
                            left: old_size,
                            buf: keep.then(Vec::new),
                            want: keep.then(|| h.old_sha256.clone().unwrap_or_default()),
                        };
                    }
                }
            }
            Ok(!done)
        };
        guest.request_stream_until(
            id,
            &Request::Export { n },
            per_frame,
            deadline,
            &mut on_frame,
        )
    };
    if let Some(e) = failed {
        return Err(e);
    }
    match streamed {
        Ok(()) => {}
        Err(GuestError::Unavailable(m)) if m == STREAM_DEADLINE => {
            return Err(refused(format!(
                "the export did not finish within {total:?} (the export timeout)"
            )))
        }
        Err(GuestError::Unavailable(m)) => {
            return Err(refused(format!("the guest export failed: {}", quote(&m))))
        }
        Err(GuestError::NotConnected) => return Err(refused("the guest is not connected")),
    }
    let v = reader.finish()?;
    if v.n != n {
        return Err(refused(format!(
            "the guest sent export {} for export {n}",
            v.n
        )));
    }
    Ok(v)
}

fn selected<'v>(
    v: &'v Valid,
    only: Option<&'v BTreeSet<String>>,
) -> impl Iterator<Item = &'v EntryHead> + 'v {
    v.entries
        .iter()
        .filter(move |h| only.is_none_or(|o| o.contains(&h.path)))
}

fn mode_str(kind: &EntryKind, mode: u32) -> &'static str {
    match kind {
        EntryKind::Symlink => "120000",
        EntryKind::File if mode == 0o755 => "100755",
        EntryKind::File => "100644",
    }
}

fn as_text(b: &[u8]) -> Option<&str> {
    std::str::from_utf8(b).ok().filter(|s| !s.contains('\0'))
}

/// Line ops, Myers when the changed middle fits the budget, else one
/// replacement of the middle. Deterministic either way.
fn diff_ops(a: &[&str], b: &[&str], budget: &mut u128) -> Vec<DiffOp> {
    let pre = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    let suf = a[pre..]
        .iter()
        .rev()
        .zip(b[pre..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let (ma, mb) = (a.len() - pre - suf, b.len() - pre - suf);
    let cost = ((ma + mb) as u128).pow(2);
    if cost <= FILE_COST && cost <= *budget {
        *budget -= cost;
        return capture_diff_slices(Algorithm::Myers, a, b);
    }
    let mut ops = Vec::new();
    if pre > 0 {
        ops.push(DiffOp::Equal {
            old_index: 0,
            new_index: 0,
            len: pre,
        });
    }
    if ma > 0 {
        ops.push(DiffOp::Delete {
            old_index: pre,
            old_len: ma,
            new_index: pre,
        });
    }
    if mb > 0 {
        ops.push(DiffOp::Insert {
            old_index: pre + ma,
            new_index: pre,
            new_len: mb,
        });
    }
    if suf > 0 {
        ops.push(DiffOp::Equal {
            old_index: pre + ma,
            new_index: pre + mb,
            len: suf,
        });
    }
    ops
}

/// Unified hunks of two texts; returns (added, removed) lines.
fn hunks(old: &str, new: &str, budget: &mut u128, emit: &mut dyn FnMut(&str)) -> (u64, u64) {
    let a: Vec<&str> = old.split_inclusive('\n').collect();
    let b: Vec<&str> = new.split_inclusive('\n').collect();
    let ops = diff_ops(&a, &b, budget);
    let (mut added, mut removed) = (0u64, 0u64);
    for group in group_diff_ops(ops, 3) {
        if group.iter().all(|op| matches!(op, DiffOp::Equal { .. })) {
            continue;
        }
        emit(&format!("{}\n", UnifiedHunkHeader::new(&group)));
        for op in &group {
            for ch in op.iter_changes(&a[..], &b[..]) {
                let sign = match ch.tag() {
                    ChangeTag::Equal => ' ',
                    ChangeTag::Delete => {
                        removed += 1;
                        '-'
                    }
                    ChangeTag::Insert => {
                        added += 1;
                        '+'
                    }
                };
                let line: &str = ch.value();
                let (body, nl) = match line.strip_suffix('\n') {
                    Some(x) => (x, true),
                    None => (line, false),
                };
                emit(&format!("{sign}{}\n", escape(body)));
                if !nl {
                    emit("\\ No newline at end of file\n");
                }
            }
        }
    }
    (added, removed)
}

/// Renders every selected entry, line by line (each `emit` is one line
/// ending in `'\n'`), and returns the file list.
fn render_into(
    base: &BaseManifest,
    v: &Valid,
    blobs: &Path,
    only: Option<&BTreeSet<String>>,
    emit: &mut dyn FnMut(&str),
) -> Vec<FileChange> {
    let mut budget = TOTAL_COST;
    let mut files = Vec::new();
    for h in selected(v, only) {
        let p = escape(&h.path);
        let old_kind = h.old_kind.clone().unwrap_or(EntryKind::File);
        let old_mode = match base.entries.get(&h.path) {
            Some(e) if h.op != Op::Add => mode_str(&e.kind, e.mode),
            _ => mode_str(&old_kind, 0o644),
        };
        let new_mode = mode_str(&h.kind, h.mode);
        let old_sha = match h.op {
            Op::Add => zero_sha(),
            _ => h.old_sha256.clone().unwrap_or_else(zero_sha),
        };
        let (new_sha, idx_mode) = match h.op {
            Op::Delete => (zero_sha(), old_mode),
            _ => (h.sha256.clone(), new_mode),
        };
        emit(&format!("diff --saiife a/{p} b/{p}\n"));
        emit(&format!(
            "index {}..{} {idx_mode}\n",
            escape(&old_sha),
            escape(&new_sha)
        ));
        match h.op {
            Op::Add => emit(&format!("new file mode {new_mode}\n")),
            Op::Delete => emit(&format!("deleted file mode {old_mode}\n")),
            Op::Modify if old_mode != new_mode => {
                emit(&format!("old mode {old_mode}\n"));
                emit(&format!("new mode {new_mode}\n"));
            }
            Op::Modify => {}
        }
        match h.op {
            Op::Add => emit("--- /dev/null\n"),
            _ => emit(&format!("--- a/{p}\n")),
        }
        match h.op {
            Op::Delete => emit("+++ /dev/null\n"),
            _ => emit(&format!("+++ b/{p}\n")),
        }
        let status = match h.op {
            Op::Add => FileStatus::Added,
            Op::Modify => FileStatus::Modified,
            Op::Delete => FileStatus::Deleted,
        };
        let (mut added, mut removed, mut binary) = (0u64, 0u64, false);
        if h.op == Op::Delete {
            emit(&format!(
                "File a/{p} deleted: {} bytes, sha256 {}\n",
                h.old_size.unwrap_or(0),
                escape(&old_sha)
            ));
        } else {
            let old_size = if h.op == Op::Modify {
                h.old_size.unwrap_or(0)
            } else {
                0
            };
            let mut text = None;
            if h.size <= TEXT_MAX && old_size <= TEXT_MAX {
                let new_b = read_blob(blobs, &h.sha256, h.size);
                let old_b = match h.op {
                    Op::Modify => read_blob(blobs, &old_sha, old_size),
                    _ => Ok(Vec::new()),
                };
                if let (Ok(o), Ok(n)) = (old_b, new_b) {
                    if as_text(&o).is_some() && as_text(&n).is_some() {
                        text = Some((o, n));
                    }
                }
            }
            match text {
                Some((o, n)) => {
                    let (o, n) = (as_text(&o).unwrap_or(""), as_text(&n).unwrap_or(""));
                    (added, removed) = hunks(o, n, &mut budget, emit);
                }
                None => {
                    binary = true;
                    emit(&format!(
                        "Binary file b/{p}: {} bytes, sha256 {}\n",
                        h.size,
                        escape(&h.sha256)
                    ));
                }
            }
        }
        let clamp = |x: u64| u32::try_from(x).unwrap_or(u32::MAX);
        files.push(FileChange {
            path: h.path.clone(),
            status,
            added: clamp(added),
            removed: clamp(removed),
            binary,
        });
    }
    files
}

/// The full unified diff of the selected entries (all when `only` is
/// `None`) and their file list. Old content of a modify is read from
/// `blobs` (stored by [`receive`] only after it matched the manifest).
pub fn render(
    base: &BaseManifest,
    v: &Valid,
    blobs: &Path,
    only: Option<&BTreeSet<String>>,
) -> (String, Vec<FileChange>) {
    let mut full = String::new();
    let files = render_into(base, v, blobs, only, &mut |l| full.push_str(l));
    (full, files)
}

/// L6: the built-in protected paths. Each component is compared by
/// [`normalize_component`], the one comparison key shared with the delta
/// validator's symlink checks and `.git` alias check (R-T3i, R-T3l:
/// decomposition, full case fold, combining marks dropped, as a
/// case-insensitive or normalising checkout would resolve them).
/// - rooted: `.claude/**`, `.saiife/**`, `.vscode/**`, `.devcontainer/**`,
///   `.husky/**`, `.cursor/**`, `.gemini/**`, `.codex/**`, `.gitlab/**`,
///   `.circleci/**`, `.github/workflows/**`, `.mcp.json`,
///   `.gitlab-ci.yml`, `.pre-commit-config.yaml`, `.cursorrules`;
/// - at any depth (agents and direnv read nested ones): `CLAUDE.md`,
///   `AGENTS.md`, `GEMINI.md`, `.envrc`;
/// - any component starting with `.git` (`.gitattributes`, `.gitmodules`,
///   `.gitconfig`, `.github/…`) except a final `.gitignore`.
pub fn protected(path: &str) -> bool {
    let comps: Vec<String> = path.split('/').map(normalize_component).collect();
    let last = comps.len() - 1;
    let first = comps[0].as_str();
    if last > 0
        && matches!(
            first,
            ".claude"
                | ".saiife"
                | ".vscode"
                | ".devcontainer"
                | ".husky"
                | ".cursor"
                | ".gemini"
                | ".codex"
                | ".gitlab"
                | ".circleci"
        )
    {
        return true;
    }
    if last == 0
        && matches!(
            first,
            ".claude"
                | ".saiife"
                | ".mcp.json"
                | ".gitlab-ci.yml"
                | ".pre-commit-config.yaml"
                | ".cursorrules"
        )
    {
        return true;
    }
    if last >= 2 && first == ".github" && comps[1] == "workflows" {
        return true;
    }
    if matches!(
        comps[last].as_str(),
        "claude.md" | "agents.md" | "gemini.md" | ".envrc"
    ) {
        return true;
    }
    comps
        .iter()
        .enumerate()
        .any(|(i, c)| c.starts_with(".git") && !(i == last && c == ".gitignore"))
}

/// A path in the spelling case collisions and symlink prefixes are
/// compared in: [`fold_path`], the shared key (R-T3i, R-T3l).
fn fold(p: &str) -> String {
    fold_path(p)
}

fn flags(
    base: &BaseManifest,
    v: &Valid,
    only: Option<&BTreeSet<String>>,
    files: &[FileChange],
    hits: Hits<'_>,
) -> Vec<Flag> {
    let result = apply_manifest(base, v, only);
    let mut folded: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for k in result.entries.keys() {
        folded.entry(fold(k)).or_default().push(k);
    }
    let binary: BTreeSet<&str> = files
        .iter()
        .filter(|f| f.binary)
        .map(|f| f.path.as_str())
        .collect();
    let mut out = Vec::new();
    let mut flag = |path: &str, why: String| {
        out.push(Flag {
            path: path.to_string(),
            why,
        })
    };
    for h in selected(v, only) {
        let p = h.path.as_str();
        if protected(p) {
            flag(p, "protected path".into());
        }
        if h.op == Op::Delete {
            continue;
        }
        let old = base.entries.get(p).filter(|_| h.op == Op::Modify);
        let was_exec = old.is_some_and(|e| e.kind == EntryKind::File && e.mode == 0o755);
        if h.kind == EntryKind::File && h.mode == 0o755 && !was_exec {
            flag(p, "becomes executable".into());
        }
        if h.kind == EntryKind::Symlink && old.is_none_or(|e| e.kind != EntryKind::Symlink) {
            flag(p, "new symlink".into());
        }
        if binary.contains(p) {
            flag(p, "binary".into());
        }
        let same = folded.get(&fold(p));
        if let Some(other) = same.and_then(|s| s.iter().find(|o| **o != p)) {
            flag(
                p,
                format!("differs only in case or accents from {}", escape(other)),
            );
        }
    }
    let paths: Vec<&str> = selected(v, only).map(|h| h.path.as_str()).collect();
    out.extend(hits(&paths));
    out
}

/// The review: the rendering, its hash over the full text
/// (`diff_sha256`), the unified text cut at a line end at most
/// `MAX_DIFF_BYTES`, and the L6 flags plus `hits`. With `only`, the subset
/// alone is rendered and hashed; [`check_subset`] says whether it may land.
pub fn review(
    id: &BoxId,
    base: &BaseManifest,
    v: &Valid,
    blobs: &Path,
    only: Option<&BTreeSet<String>>,
    hits: Hits<'_>,
) -> Review {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut unified = String::new();
    let mut truncated = false;
    let files = render_into(base, v, blobs, only, &mut |line| {
        ctx.update(line.as_bytes());
        if !truncated {
            if unified.len() + line.len() <= MAX_DIFF_BYTES {
                unified.push_str(line);
            } else {
                truncated = true;
            }
        }
    });
    let diff_sha256 = hex(ctx.finish().as_ref());
    let flags = flags(base, v, only, &files, hits);
    Review {
        n: v.n,
        summary: DiffSummary {
            id: id.clone(),
            base_commit: base.snapshot_commit.clone(),
            diff_sha256,
            files,
            unified,
            truncated,
            tests: None,
        },
        flags,
        entries: selected(v, only).cloned().collect(),
        base_head: base.base_commit.clone(),
    }
}

/// The proper ancestors of a path (`a/b/c` → `a`, `a/b`).
fn ancestors(p: &str) -> impl Iterator<Item = &str> {
    p.match_indices('/').map(move |(i, _)| &p[..i])
}

/// R-T1d: a partial land's `only` must name paths of the delta and leave a
/// valid tree (base + the selected entries): no path both a file and a
/// directory, none through a symlink. The error names the change that
/// must be selected too.
pub fn check_subset(
    base: &BaseManifest,
    v: &Valid,
    only: Option<&BTreeSet<String>>,
) -> Result<(), String> {
    let Some(only) = only else {
        return Ok(());
    };
    let in_delta: BTreeSet<&str> = v.entries.iter().map(|h| h.path.as_str()).collect();
    if only.is_empty() {
        return Err("the selection names no file".into());
    }
    for p in only {
        if !in_delta.contains(p.as_str()) {
            return Err(format!("{} is not in the diff", quote(p)));
        }
    }
    let result = apply_manifest(base, v, Some(only));
    let links: BTreeSet<String> = result
        .entries
        .iter()
        .filter(|(_, e)| e.kind == EntryKind::Symlink)
        .map(|(k, _)| fold(k))
        .collect();
    // The path of the pair whose change was left out.
    let missing = |a: &str, b: &str| -> String {
        let left_out = |x: &str| in_delta.contains(x) && !only.contains(x);
        quote(if left_out(b) { b } else { a })
    };
    let conflict = |a: &str, b: &str, what: &str| {
        Err(format!(
            "the selection is not a valid tree: {} and {} {what}; select the change of {} too",
            quote(a),
            quote(b),
            missing(a, b)
        ))
    };
    for h in selected(v, Some(only)).filter(|h| h.op != Op::Delete) {
        let p = h.path.as_str();
        for a in ancestors(p) {
            if result.entries.contains_key(a) {
                return conflict(p, a, "would be a file and a directory");
            }
            if links.contains(&fold(a)) {
                return conflict(p, a, "would put a path through a symlink");
            }
        }
        let prefix = format!("{p}/");
        let under = result
            .entries
            .range::<str, _>((Bound::Included(prefix.as_str()), Bound::Unbounded))
            .map(|(k, _)| k.as_str())
            .take_while(|k| k.starts_with(prefix.as_str()))
            .next();
        if let Some(k) = under {
            return conflict(p, k, "would be a file and a directory");
        }
    }
    Ok(())
}

/// Writes `lands/<n>/<name>` through a temp name and a rename (0600,
/// `O_EXCL|O_NOFOLLOW`), so a second review of the same export replaces it.
fn write_atomic(
    dest: &Path,
    body: &mut dyn FnMut(&mut BufWriter<File>) -> io::Result<()>,
) -> io::Result<()> {
    let name = dest
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| io::Error::other("bad land file name"))?;
    let tmp = dest.with_file_name(format!(".{name}.part"));
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut w = BufWriter::new(create_new(&tmp)?);
    let r = body(&mut w).and_then(|()| w.flush());
    let f = w.into_inner().map_err(|e| e.into_error());
    let r = r.and_then(|()| f.and_then(|f| f.sync_all()));
    if let Err(e) = r {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    fs::rename(&tmp, dest)
}

/// The `delta.bin` head of an entry: as reviewed, except that a modify's
/// `old_size` is null, since no old bytes follow (a reader reads
/// `old_size` old bytes before a modify's new ones).
fn land_head(h: &EntryHead) -> EntryHead {
    let mut h = h.clone();
    if h.op == Op::Modify {
        h.old_size = None;
    }
    h
}

/// Writes `delta.bin` frame by frame as `write_delta` would for the
/// selected entries with no old bytes: the same frames, without holding
/// all content in memory. Each blob is checked against its hash.
fn write_delta_bin(
    w: &mut dyn Write,
    blobs: &Path,
    n: u32,
    entries: &[&EntryHead],
) -> io::Result<()> {
    let mut w = w;
    write_frame(
        &mut w,
        &Frame::Json(serde_json::json!({"t": "delta", "n": n, "entries": entries.len()})),
    )?;
    let mut buf = vec![0u8; MAX_FRAME];
    for h in entries {
        let head = land_head(h);
        let mut v = serde_json::to_value(&head)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        v["t"] = "entry".into();
        write_frame(&mut w, &Frame::Json(v))?;
        if h.op == Op::Delete || h.size == 0 {
            continue;
        }
        let mut f = open_blob(blobs, &h.sha256, h.size)?;
        let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
        let mut left = h.size;
        while left > 0 {
            let k = left.min(MAX_FRAME as u64) as usize;
            f.read_exact(&mut buf[..k])?;
            ctx.update(&buf[..k]);
            write_frame(&mut w, &Frame::Bytes(buf[..k].to_vec()))?;
            left -= k as u64;
        }
        if hex(ctx.finish().as_ref()) != h.sha256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "a stored blob does not match its sha256",
            ));
        }
    }
    write_frame(
        &mut w,
        &Frame::Json(serde_json::json!({"t": "end", "entries": entries.len()})),
    )
}

/// Writes `lands/<n>/delta.bin` (the new content of the entries `only`
/// selects, for the CLI; `Reader::paths_only` reads it back) and
/// `lands/<n>/review.json`, both 0600, after [`check_subset`] (R-T1d)
/// against `base`, the manifest the review was made against.
pub fn write_land_files(
    paths: &BoxPaths,
    base: &BaseManifest,
    r: &Review,
    only: Option<&BTreeSet<String>>,
) -> Result<(), String> {
    let v = Valid {
        n: r.n,
        entries: r.entries.clone(),
    };
    check_subset(base, &v, only)?;
    let dir = paths.land_dir(r.n);
    match fs::symlink_metadata(&dir) {
        Ok(m) if m.is_dir() => {}
        _ => return Err(format!("land {} has no directory", r.n)),
    }
    let sel: Vec<&EntryHead> = selected(&v, only).collect();
    let blobs = paths.land_blobs(r.n);
    write_atomic(&paths.land_delta(r.n), &mut |w| {
        write_delta_bin(w, &blobs, r.n, &sel)
    })
    .map_err(|e| format!("cannot write delta.bin of land {}: {e}", r.n))?;
    let json = serde_json::to_vec_pretty(r).map_err(|e| format!("review.json: {e}"))?;
    write_atomic(&paths.land_review(r.n), &mut |w| w.write_all(&json))
        .map_err(|e| format!("cannot write review.json of land {}: {e}", r.n))?;
    Ok(())
}
