//! The headless terminal and the recorder (spec §9.4, plan 38 G4/G5).
//!
//! The guest PTY bytes are untrusted. `Screen` applies them to a vt100
//! emulator (no scrollback), and cuts frames of *cleaned text rows*: no
//! control characters, no bidi/format characters, and no OSC payloads
//! (vt100 never renders OSC output). `Recorder` writes an asciicast v2 file
//! with a hard size cap.
//!
//! Time is injected everywhere; nothing here reads the wall clock.

use std::collections::VecDeque;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use saiife_wire::source::{TermBatch, TermFrame};

/// A frame is cut at most this often (G4).
const CUT_INTERVAL_MS: u64 = 200;
/// Frames kept for readers (G4).
const RING: usize = 2000;
/// A Snapshot follows this many Deltas (G4).
const SNAPSHOT_EVERY: u32 = 200;
/// Byte budget of the whole ring; the oldest frames go first, but the newest
/// Snapshot always stays so a reader can always be brought up to date.
const RING_BYTES: usize = 4 << 20;
/// Byte cap of one frame. A screen whose rows add up to more is cut to a
/// truncated snapshot: every row is truncated to the same per-row byte limit
/// (at a character boundary), and that truncated text is the screen state
/// deltas are computed against, so readers stay consistent.
const FRAME_BYTES: usize = 256 << 10;
/// Per-frame overhead counted for each line, on top of its text.
const LINE_OVERHEAD: usize = 8;
/// Combining marks kept per cell (extra ones are dropped).
const MAX_MARKS: usize = 4;
/// Bounds on the emulated screen (memory stays small whatever the guest asks).
const MAX_ROWS: u16 = 200;
const MAX_COLS: u16 = 400;
/// One `batch` call returns at most this many frames and bytes; `next` is the
/// highest seq returned, so the reader pages.
const BATCH_FRAMES: usize = 256;
const BATCH_BYTES: usize = 1 << 20;
/// Recording cap (G5).
const CAST_CAP: u64 = 64 << 20;
const CAST_STOP_NOTE: &str = "recording stopped: 64 MiB cap";

fn seq_of(f: &TermFrame) -> u64 {
    match f {
        TermFrame::Snapshot { seq, .. } | TermFrame::Delta { seq, .. } => *seq,
    }
}

/// Bytes a frame counts against the budgets.
fn frame_bytes(f: &TermFrame) -> usize {
    match f {
        TermFrame::Snapshot { lines, .. } => lines.iter().map(|l| l.len() + LINE_OVERHEAD).sum(),
        TermFrame::Delta { lines, .. } => lines.iter().map(|(_, l)| l.len() + LINE_OVERHEAD).sum(),
    }
}

/// The host's view of the agent's terminal. Memory is bounded by the screen
/// size and the ring byte budget; `feed` keeps no per-call state beyond the
/// emulator.
pub struct Screen {
    parser: vt100::Parser,
    ring: VecDeque<TermFrame>,
    ring_bytes: usize,
    snapshots: usize,
    bytes_since_snapshot: usize,
    seq: u64,
    rows: u16,
    cols: u16,
    last_rows: Vec<String>,
    last_cursor: (u16, u16),
    last_cut_ms: Option<u64>,
    deltas_since_snapshot: u32,
    dirty: bool,
}

fn clamp_dims(rows: u16, cols: u16) -> (u16, u16) {
    (rows.clamp(1, MAX_ROWS), cols.clamp(1, MAX_COLS))
}

fn truncate_at_boundary(s: &mut String, max: usize) {
    if s.len() > max {
        let mut n = max;
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        s.truncate(n);
    }
}

impl Screen {
    pub fn new(rows: u16, cols: u16) -> Screen {
        Self::new_after(rows, cols, 0)
    }

    /// A fresh screen whose first frame has seq `seq + 1`: a box's next run
    /// goes on from its earlier run's last seq, so readers' `after` stays
    /// monotonic (and an `after` from the earlier run gets the new screen).
    pub fn new_after(rows: u16, cols: u16, seq: u64) -> Screen {
        let (rows, cols) = clamp_dims(rows, cols);
        Screen {
            // Scrollback 0: nothing outside the visible screen is kept.
            parser: vt100::Parser::new(rows, cols, 0),
            ring: VecDeque::new(),
            ring_bytes: 0,
            snapshots: 0,
            bytes_since_snapshot: 0,
            seq,
            rows,
            cols,
            last_rows: Vec::new(),
            last_cursor: (0, 0),
            last_cut_ms: None,
            deltas_since_snapshot: 0,
            dirty: false,
        }
    }

    /// The seq of the newest frame (0: none yet).
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Parses all bytes; cuts a frame only if at least 200 ms passed since the
    /// last cut (otherwise the change waits for `flush`).
    pub fn feed(&mut self, bytes: &[u8], now_ms: u64) {
        if bytes.is_empty() {
            return;
        }
        self.parser.process(bytes);
        self.dirty = true;
        let due = match self.last_cut_ms {
            None => true,
            Some(t) => now_ms.saturating_sub(t) >= CUT_INTERVAL_MS,
        };
        if due {
            self.cut(now_ms, false);
        }
    }

    /// Cuts a pending change now (200 ms timer, and at exit).
    pub fn flush(&mut self, now_ms: u64) {
        if self.dirty {
            self.cut(now_ms, false);
        }
    }

    /// Always a Snapshot.
    pub fn resize(&mut self, rows: u16, cols: u16, now_ms: u64) {
        let (rows, cols) = clamp_dims(rows, cols);
        self.parser.set_size(rows, cols);
        self.rows = rows;
        self.cols = cols;
        self.cut(now_ms, true);
    }

    /// The screen as cleaned text rows: at most 1 + MAX_MARKS characters per
    /// cell, no unsafe characters, and within FRAME_BYTES in total.
    fn current_rows(&self) -> Vec<String> {
        let screen = self.parser.screen();
        let mut rows: Vec<String> = (0..self.rows)
            .map(|r| {
                let mut line = String::new();
                for c in 0..self.cols {
                    match screen.cell(r, c) {
                        Some(cell) if cell.is_wide_continuation() => {}
                        Some(cell) => {
                            let t = cell.contents();
                            if t.is_empty() {
                                line.push(' ');
                            } else {
                                line.extend(t.chars().take(1 + MAX_MARKS));
                            }
                        }
                        None => {}
                    }
                }
                let mut line = clean_line(&line);
                line.truncate(line.trim_end_matches(' ').len());
                line
            })
            .collect();
        let total: usize = rows.iter().map(|l| l.len() + LINE_OVERHEAD).sum();
        if total > FRAME_BYTES {
            let per_row = (FRAME_BYTES / rows.len().max(1)).saturating_sub(LINE_OVERHEAD);
            for l in &mut rows {
                truncate_at_boundary(l, per_row);
            }
        }
        rows
    }

    fn cut(&mut self, now_ms: u64, force_snapshot: bool) {
        self.dirty = false;
        self.last_cut_ms = Some(now_ms);
        let rows = self.current_rows();
        let cursor = self.parser.screen().cursor_position();
        let mut snapshot = force_snapshot
            || self.ring.is_empty()
            || self.deltas_since_snapshot >= SNAPSHOT_EVERY
            || rows.len() != self.last_rows.len();
        let mut changed: Vec<(u16, String)> = Vec::new();
        if !snapshot {
            changed = rows
                .iter()
                .enumerate()
                .filter(|(i, l)| self.last_rows.get(*i) != Some(*l))
                .map(|(i, l)| (i as u16, l.clone()))
                .collect();
            if changed.is_empty() && cursor == self.last_cursor {
                return;
            }
            // Keep a Snapshot within reach of the byte budget.
            let size: usize = changed.iter().map(|(_, l)| l.len() + LINE_OVERHEAD).sum();
            if self.bytes_since_snapshot + size > RING_BYTES / 4 {
                snapshot = true;
            }
        }
        self.seq += 1;
        let frame = if snapshot {
            self.deltas_since_snapshot = 0;
            TermFrame::Snapshot {
                seq: self.seq,
                rows: self.rows,
                cols: self.cols,
                lines: rows.clone(),
                cursor,
            }
        } else {
            self.deltas_since_snapshot += 1;
            TermFrame::Delta {
                seq: self.seq,
                lines: changed,
                cursor,
            }
        };
        self.last_rows = rows;
        self.last_cursor = cursor;
        self.push(frame);
    }

    fn push(&mut self, frame: TermFrame) {
        let size = frame_bytes(&frame);
        if matches!(frame, TermFrame::Snapshot { .. }) {
            self.snapshots += 1;
            self.bytes_since_snapshot = 0;
        } else {
            self.bytes_since_snapshot += size;
        }
        self.ring_bytes += size;
        self.ring.push_back(frame);
        while self.ring.len() > 1 && (self.ring.len() > RING || self.ring_bytes > RING_BYTES) {
            let front_is_snapshot = matches!(self.ring.front(), Some(TermFrame::Snapshot { .. }));
            if front_is_snapshot && self.snapshots == 1 {
                break;
            }
            if let Some(old) = self.ring.pop_front() {
                self.ring_bytes -= frame_bytes(&old);
                if matches!(old, TermFrame::Snapshot { .. }) {
                    self.snapshots -= 1;
                }
            }
        }
    }

    /// Bytes the ring currently holds (for tests and diagnostics).
    #[cfg(test)]
    fn ring_bytes_measured(&self) -> usize {
        self.ring.iter().map(frame_bytes).sum()
    }

    /// Plan 28 semantics: frames with `seq > after`; `next` is the highest seq
    /// returned, or `after.unwrap_or(0)`. At most BATCH_FRAMES frames and
    /// BATCH_BYTES bytes per call (oldest first; the reader pages with
    /// `next`). `None`, and an `after` older than the ring, start at the
    /// newest Snapshot.
    pub fn batch(&self, after: Option<u64>, ended: bool) -> TermBatch {
        let newest_snapshot = || {
            self.ring
                .iter()
                .rposition(|f| matches!(f, TermFrame::Snapshot { .. }))
                .unwrap_or(0)
        };
        let start = match after {
            None => newest_snapshot(),
            Some(a) => {
                let behind = self
                    .ring
                    .front()
                    .is_some_and(|f| seq_of(f) > a.saturating_add(1));
                if behind {
                    newest_snapshot()
                } else {
                    self.ring.partition_point(|f| seq_of(f) <= a)
                }
            }
        };
        let mut frames: Vec<TermFrame> = Vec::new();
        let mut bytes = 0usize;
        for f in self.ring.range(start..) {
            let size = frame_bytes(f);
            if !frames.is_empty() && (frames.len() >= BATCH_FRAMES || bytes + size > BATCH_BYTES) {
                break;
            }
            bytes += size;
            frames.push(f.clone());
        }
        let next = frames
            .last()
            .map(seq_of)
            .unwrap_or_else(|| after.unwrap_or(0));
        TermBatch {
            frames,
            next,
            ended,
        }
    }
}

/// Plain text only: drops every `saiife_wire::text::is_unsafe_char` character
/// (C0, DEL, C1, format and default-ignorable characters, private use,
/// separators) and tab. Printable and wide characters stay.
pub fn clean_line(s: &str) -> String {
    s.chars().filter(|c| !is_unwanted(*c)).collect()
}

fn is_unwanted(c: char) -> bool {
    // Tab is dropped too: a row is plain printable text.
    c == '\t' || saiife_wire::text::is_unsafe_char(c)
}

/// asciicast v2 writer for `<box>/term.cast`. Raw escapes live in the file:
/// it is evidence, never `cat` it. Output bytes that are not UTF-8 are
/// converted lossily (U+FFFD), as asciicast recorders do; a multi-byte
/// sequence split across two `output` calls is held until it completes.
pub struct Recorder {
    out: BufWriter<std::fs::File>,
    bytes: u64,
    cap: u64,
    capped: bool,
    pending: Vec<u8>,
}

impl Recorder {
    /// Creates `path` fresh: the parent directory is opened as a dirfd
    /// (O_DIRECTORY|O_NOFOLLOW), any existing entry of that name is unlinked
    /// without following it (a directory is refused), and the file is created
    /// O_CREAT|O_EXCL|O_NOFOLLOW (mode 0600). The new file must be a regular
    /// file with one link, owned by us. Nothing planted in the box dir (a
    /// symlink, a hard link, a FIFO) is ever opened or truncated.
    pub fn create(path: &Path, rows: u16, cols: u16, unix_now: u64) -> io::Result<Recorder> {
        Self::create_with_cap(path, rows, cols, unix_now, CAST_CAP)
    }

    #[cfg(test)]
    fn create_capped(
        path: &Path,
        rows: u16,
        cols: u16,
        unix_now: u64,
        cap: u64,
    ) -> io::Result<Recorder> {
        Self::create_with_cap(path, rows, cols, unix_now, cap)
    }

    fn create_with_cap(
        path: &Path,
        rows: u16,
        cols: u16,
        unix_now: u64,
        cap: u64,
    ) -> io::Result<Recorder> {
        use rustix::fs::{fstat, openat, unlinkat, AtFlags, FileType, Mode, OFlags, CWD};
        let bad = |m: &'static str| io::Error::new(io::ErrorKind::InvalidInput, m);
        let name = path
            .file_name()
            .ok_or_else(|| bad("term.cast has no file name"))?;
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        let dir = openat(
            CWD,
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        match unlinkat(&dir, name, AtFlags::empty()) {
            Ok(()) => {}
            Err(e) if e == rustix::io::Errno::NOENT => {}
            // A directory (EISDIR/EPERM) or anything else: refuse.
            Err(e) => return Err(e.into()),
        }
        let fd = openat(
            &dir,
            name,
            OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::NOCTTY
                | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?;
        let st = fstat(&fd)?;
        if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
            || st.st_nlink != 1
            || st.st_uid != rustix::process::geteuid().as_raw()
        {
            return Err(bad("term.cast is not a fresh regular file of ours"));
        }
        let file = std::fs::File::from(fd);
        let header = serde_json::json!({
            "version": 2,
            "width": cols,
            "height": rows,
            "timestamp": unix_now,
            "env": { "TERM": "xterm-256color" },
        });
        let mut line = header.to_string();
        line.push('\n');
        let mut out = BufWriter::new(file);
        out.write_all(line.as_bytes())?;
        Ok(Recorder {
            out,
            bytes: line.len() as u64,
            cap,
            capped: false,
            pending: Vec::new(),
        })
    }

    /// Appends one `[t, "o", data]` event. After the cap (counted in bytes
    /// actually written, header included) one final `"m"` line is written and
    /// nothing more; that line may exceed the cap by its own length only.
    pub fn output(&mut self, t_secs: f64, bytes: &[u8]) {
        if self.capped {
            return;
        }
        let mut buf = std::mem::take(&mut self.pending);
        buf.extend_from_slice(bytes);
        let keep = incomplete_tail(&buf);
        let split = buf.len() - keep;
        self.pending = buf[split..].to_vec();
        if split == 0 {
            return;
        }
        let data = String::from_utf8_lossy(&buf[..split]);
        self.event(t_secs, "o", &data);
    }

    fn event(&mut self, t_secs: f64, kind: &str, data: &str) {
        let t = if t_secs.is_finite() && t_secs > 0.0 {
            (t_secs * 1e6).round() / 1e6
        } else {
            0.0
        };
        let mut line = serde_json::to_string(&(t, kind, data)).unwrap_or_default();
        line.push('\n');
        if self.bytes + line.len() as u64 > self.cap {
            self.capped = true;
            let mut stop = serde_json::to_string(&(t, "m", CAST_STOP_NOTE)).unwrap_or_default();
            stop.push('\n');
            self.write(stop.as_bytes());
            let _ = self.out.flush();
            return;
        }
        self.write(line.as_bytes());
    }

    fn write(&mut self, b: &[u8]) {
        match self.out.write_all(b) {
            Ok(()) => self.bytes += b.len() as u64,
            // A failing disk ends the recording rather than looping on errors.
            Err(_) => self.capped = true,
        }
    }

    pub fn flush(&mut self) {
        let _ = self.out.flush();
    }
}

/// Length of a trailing, possibly valid but incomplete, UTF-8 sequence.
fn incomplete_tail(buf: &[u8]) -> usize {
    match std::str::from_utf8(buf) {
        Ok(_) => 0,
        Err(e) if e.error_len().is_none() => buf.len() - e.valid_up_to(),
        Err(_) => {
            // An invalid byte somewhere: only the very end can still be
            // incomplete, so look at the last (up to 3) bytes.
            let n = buf.len().min(3);
            for k in (1..=n).rev() {
                let tail = &buf[buf.len() - k..];
                if let Err(e) = std::str::from_utf8(tail) {
                    if e.valid_up_to() == 0 && e.error_len().is_none() {
                        return k;
                    }
                }
            }
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_lines(b: &TermBatch) -> Vec<String> {
        let mut out = Vec::new();
        for f in &b.frames {
            match f {
                TermFrame::Snapshot { lines, .. } => out.extend(lines.iter().cloned()),
                TermFrame::Delta { lines, .. } => out.extend(lines.iter().map(|(_, l)| l.clone())),
            }
        }
        out
    }

    #[test]
    fn first_frame_is_snapshot() {
        let mut s = Screen::new(5, 20);
        s.feed(b"hello", 1000);
        let b = s.batch(None, false);
        assert_eq!(b.frames.len(), 1);
        match &b.frames[0] {
            TermFrame::Snapshot {
                seq,
                rows,
                cols,
                lines,
                ..
            } => {
                assert_eq!((*seq, *rows, *cols), (1, 5, 20));
                assert_eq!(lines.len(), 5);
                assert_eq!(lines[0], "hello");
            }
            other => panic!("not a snapshot: {other:?}"),
        }
        assert_eq!(b.next, 1);
        assert!(!b.ended);
    }

    /// m3: a later run's screen goes on from the earlier run's seq; a
    /// reader at the old seq gets the new screen's snapshot.
    #[test]
    fn new_after_goes_on_from_the_earlier_seq() {
        let mut old = Screen::new(5, 20);
        old.feed(b"one", 1000);
        old.feed(b"\r\ntwo", 1300);
        let last = old.seq();
        assert_eq!(last, 2);
        let mut s = Screen::new_after(5, 20, last);
        assert_eq!(s.seq(), last);
        assert!(s.batch(Some(last), false).frames.is_empty());
        s.feed(b"again", 10);
        let b = s.batch(Some(last), false);
        assert_eq!(b.frames.len(), 1);
        assert!(
            matches!(&b.frames[0], TermFrame::Snapshot { seq, .. } if *seq == last + 1),
            "{b:?}"
        );
        assert_eq!(b.next, last + 1);
    }

    #[test]
    fn delta_lists_changed_rows_only() {
        let mut s = Screen::new(5, 20);
        s.feed(b"one\r\ntwo", 1000);
        s.feed(b"\x1b[2;1Hbwo", 1300);
        let b = s.batch(Some(1), false);
        assert_eq!(b.frames.len(), 1);
        match &b.frames[0] {
            TermFrame::Delta { seq, lines, .. } => {
                assert_eq!(*seq, 2);
                assert_eq!(lines, &vec![(1u16, "bwo".to_string())]);
            }
            other => panic!("not a delta: {other:?}"),
        }
    }

    #[test]
    fn cursor_is_reported() {
        let mut s = Screen::new(5, 20);
        s.feed(b"ab\r\ncde", 1000);
        match &s.batch(None, false).frames[0] {
            TermFrame::Snapshot { cursor, .. } => assert_eq!(*cursor, (1, 3)),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn osc_sequences_never_reach_frames() {
        let mut s = Screen::new(5, 40);
        s.feed(b"\x1b]52;c;aGk=\x07", 1000);
        s.feed(b"\x1b]0;EVIL TITLE\x07\x1b]2;EVIL TWO\x1b\\", 1300);
        s.feed(b"\x1b]8;;https://x\x07link\x1b]8;;\x07", 1600);
        let b = s.batch(None, false);
        let lines = all_lines(&b);
        assert!(lines.iter().any(|l| l.contains("link")));
        for l in &lines {
            for bad in ["]52", "]8", "https://x", "\x1b", "EVIL", "aGk="] {
                assert!(!l.contains(bad), "{l:?} contains {bad:?}");
            }
        }
    }

    #[test]
    fn bidi_controls_are_stripped() {
        let s =
            "a\u{200B}b\u{200E}c\u{202E}d\u{2066}e\u{2069}f\u{FEFF}g\u{061C}h\u{200F}i\u{202A}j";
        assert_eq!(clean_line(s), "abcdefghij");
        let mut sc = Screen::new(3, 30);
        sc.feed("x\u{202E}evil\u{200B}y".as_bytes(), 1000);
        for l in all_lines(&sc.batch(None, false)) {
            assert_eq!(clean_line(&l), l);
            assert!(!l.contains('\u{202E}') && !l.contains('\u{200B}'));
        }
    }

    #[test]
    fn clean_line_keeps_printable_and_wide() {
        assert_eq!(clean_line("a\x01b\x7fc\u{85}d\u{9b}e\tf"), "abcdef");
        assert_eq!(clean_line("日本語 ok ✓"), "日本語 ok ✓");
    }

    #[test]
    fn frames_have_no_control_chars() {
        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut s = Screen::new(10, 40);
        let mut now = 0u64;
        for _ in 0..1000 {
            let n = (next() % 200) as usize + 1;
            let bytes: Vec<u8> = (0..n).map(|_| (next() >> 24) as u8).collect();
            now += 250;
            s.feed(&bytes, now);
        }
        s.flush(now + 1000);
        let b = s.batch(None, false);
        assert!(!b.frames.is_empty());
        for l in all_lines(&b) {
            assert_eq!(clean_line(&l), l);
        }
    }

    #[test]
    fn burst_is_rate_limited() {
        let mut s = Screen::new(40, 120);
        let chunk = vec![b'x'; 1 << 20];
        for i in 0..10u64 {
            // 10 MB over one simulated second.
            s.feed(&chunk, i * 100);
        }
        s.flush(1000);
        let b = s.batch(None, false);
        assert!(b.frames.len() <= 6, "got {} frames", b.frames.len());
    }

    #[test]
    fn old_after_gets_a_snapshot() {
        let mut s = Screen::new(3, 20);
        for i in 0..2600u64 {
            s.feed(format!("\x1b[1;1H{i}").as_bytes(), i * 200);
        }
        let b = s.batch(Some(1), false);
        assert!(matches!(b.frames[0], TermFrame::Snapshot { .. }));
        assert!(b.frames.len() <= 2000);
        assert_eq!(b.next, seq_of(b.frames.last().unwrap()));
        let all = s.batch(None, false);
        assert!(matches!(all.frames[0], TermFrame::Snapshot { .. }));
    }

    #[test]
    fn snapshot_every_200_deltas() {
        let mut s = Screen::new(3, 20);
        for i in 0..450u64 {
            s.feed(format!("\x1b[1;1H{i}").as_bytes(), i * 200);
        }
        let mut snaps = Vec::new();
        let mut after = Some(0);
        loop {
            let b = s.batch(after, false);
            if b.frames.is_empty() {
                break;
            }
            snaps.extend(
                b.frames
                    .iter()
                    .filter(|f| matches!(f, TermFrame::Snapshot { .. }))
                    .map(seq_of),
            );
            after = Some(b.next);
        }
        assert_eq!(snaps, vec![1, 202, 403]);
    }

    #[test]
    fn batch_none_starts_at_the_newest_snapshot() {
        let mut s = Screen::new(3, 20);
        for i in 0..450u64 {
            s.feed(format!("\x1b[1;1H{i}").as_bytes(), i * 200);
        }
        let b = s.batch(None, false);
        assert!(matches!(&b.frames[0], TermFrame::Snapshot { seq: 403, .. }));
        assert_eq!(b.frames.len(), 48);
        assert_eq!(b.next, 450);
    }

    #[test]
    fn batch_is_capped_in_frames_and_bytes() {
        let mut s = Screen::new(3, 20);
        for i in 0..1500u64 {
            s.feed(format!("\x1b[1;1H{i}").as_bytes(), i * 200);
        }
        let b = s.batch(Some(0), false);
        assert_eq!(b.frames.len(), BATCH_FRAMES);
        assert_eq!(b.next, BATCH_FRAMES as u64);
        // Byte cap: big frames page by bytes.
        let mut big = Screen::new(200, 400);
        for i in 0..30u64 {
            let ch = char::from(b'a' + (i % 26) as u8);
            let mut buf = String::new();
            for r in 1..=200 {
                buf.push_str(&format!("\x1b[{r};1H"));
                buf.extend(std::iter::repeat_n(ch, 400));
            }
            big.feed(buf.as_bytes(), i * 200);
        }
        let mut after = Some(0);
        let mut seen = 0;
        loop {
            let b = big.batch(after, false);
            if b.frames.is_empty() {
                break;
            }
            let bytes: usize = b.frames.iter().map(frame_bytes).sum();
            assert!(b.frames.len() <= BATCH_FRAMES);
            assert!(bytes <= BATCH_BYTES || b.frames.len() == 1, "{bytes}");
            seen += b.frames.len();
            after = Some(b.next);
        }
        assert!(seen > 0);
    }

    #[test]
    fn combining_mark_flood_stays_in_budget() {
        let mut s = Screen::new(200, 400);
        for i in 0..40u64 {
            let ch = char::from(b'a' + (i % 26) as u8);
            let cell = format!("{ch}{}", "\u{301}".repeat(8));
            let mut buf = String::new();
            for r in 1..=200 {
                buf.push_str(&format!("\x1b[{r};1H"));
                buf.push_str(&cell.repeat(400));
            }
            s.feed(buf.as_bytes(), i * 200);
            assert!(s.ring_bytes_measured() <= RING_BYTES);
            assert_eq!(s.ring_bytes, s.ring_bytes_measured());
        }
        let b = s.batch(None, false);
        assert!(matches!(b.frames[0], TermFrame::Snapshot { .. }));
        for f in &b.frames {
            assert!(frame_bytes(f) <= FRAME_BYTES);
            if let TermFrame::Snapshot { lines, .. } = f {
                assert!(lines
                    .iter()
                    .all(|l| l.chars().count() <= 400 * (1 + MAX_MARKS)));
            }
        }
        assert!(s.ring.len() > 1);
    }

    #[test]
    fn batch_pages_by_seq() {
        let mut s = Screen::new(3, 20);
        for i in 0..3u64 {
            s.feed(format!("\x1b[1;1H{i}").as_bytes(), i * 300);
        }
        let all = s.batch(None, false);
        assert_eq!(all.frames.len(), 3);
        assert_eq!(all.next, 3);
        let rest = s.batch(Some(1), true);
        assert_eq!(
            rest.frames.iter().map(seq_of).collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert_eq!(rest.next, 3);
        assert!(rest.ended);
        let none = s.batch(Some(3), false);
        assert!(none.frames.is_empty());
        assert_eq!(none.next, 3);
        let empty = Screen::new(3, 20).batch(None, false);
        assert!(empty.frames.is_empty());
        assert_eq!(empty.next, 0);
    }

    #[test]
    fn flush_cuts_a_pending_change() {
        let mut s = Screen::new(3, 20);
        s.feed(b"a", 1000);
        s.feed(b"b", 1050);
        assert_eq!(s.batch(None, false).frames.len(), 1);
        s.flush(1100);
        assert_eq!(s.batch(None, false).frames.len(), 2);
        s.flush(1500);
        assert_eq!(s.batch(None, false).frames.len(), 2);
    }

    #[test]
    fn resize_is_snapshot() {
        let mut s = Screen::new(3, 20);
        s.feed(b"hi", 1000);
        s.resize(6, 30, 1050);
        let b = s.batch(Some(1), false);
        match &b.frames[0] {
            TermFrame::Snapshot {
                seq,
                rows,
                cols,
                lines,
                ..
            } => {
                assert_eq!((*seq, *rows, *cols), (2, 6, 30));
                assert_eq!(lines.len(), 6);
            }
            other => panic!("{other:?}"),
        }
    }

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn cast_header_and_events() {
        let d = tmp();
        let p = d.path().join("term.cast");
        let mut r = Recorder::create(&p, 40, 120, 1_700_000_000).unwrap();
        r.output(0.5, b"hi \x1b[31m\"q\"\r\n");
        r.output(1.25, &[0xff, b'z']);
        r.flush();
        let text = std::fs::read_to_string(&p).unwrap();
        let mut it = text.lines();
        let h: serde_json::Value = serde_json::from_str(it.next().unwrap()).unwrap();
        assert_eq!(h["version"], 2);
        assert_eq!(h["width"], 120);
        assert_eq!(h["height"], 40);
        assert_eq!(h["timestamp"], 1_700_000_000u64);
        assert_eq!(h["env"]["TERM"], "xterm-256color");
        let e1: serde_json::Value = serde_json::from_str(it.next().unwrap()).unwrap();
        assert_eq!(e1[0], 0.5);
        assert_eq!(e1[1], "o");
        assert_eq!(e1[2], "hi \x1b[31m\"q\"\r\n");
        let e2: serde_json::Value = serde_json::from_str(it.next().unwrap()).unwrap();
        assert_eq!(e2[2], "\u{fffd}z");
        assert!(it.next().is_none());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn cast_stops_at_cap() {
        let d = tmp();
        let p = d.path().join("term.cast");
        let mut r = Recorder::create_capped(&p, 40, 120, 1, 400).unwrap();
        for i in 0..100 {
            r.output(i as f64, b"0123456789");
        }
        r.output(200.0, b"after");
        r.flush();
        let text = std::fs::read_to_string(&p).unwrap();
        let last = text.lines().last().unwrap();
        let v: serde_json::Value = serde_json::from_str(last).unwrap();
        assert_eq!(v[1], "m");
        assert_eq!(v[2], "recording stopped: 64 MiB cap");
        assert_eq!(text.matches("recording stopped").count(), 1);
        assert!(!text.contains("after"));
        assert!(text.len() as u64 <= 400 + last.len() as u64 + 1);
    }

    #[test]
    fn cast_replaces_a_symlink_and_leaves_its_target() {
        let d = tmp();
        let target = d.path().join("target");
        std::fs::write(&target, b"keep").unwrap();
        let p = d.path().join("term.cast");
        std::os::unix::fs::symlink(&target, &p).unwrap();
        let mut r = Recorder::create(&p, 40, 120, 1).unwrap();
        r.output(0.1, b"x");
        r.flush();
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
        assert!(!std::fs::symlink_metadata(&p)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(std::fs::read_to_string(&p).unwrap().contains("\"o\""));
    }

    #[test]
    fn cast_refuses_a_symlinked_box_dir() {
        let d = tmp();
        let real = d.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(Recorder::create(&link.join("term.cast"), 4, 8, 1).is_err());
        assert!(!real.join("term.cast").exists());
    }

    #[test]
    fn cast_leaves_a_hard_linked_file_alone() {
        let d = tmp();
        let outside = d.path().join("outside");
        std::fs::write(&outside, b"precious data").unwrap();
        let p = d.path().join("term.cast");
        std::fs::hard_link(&outside, &p).unwrap();
        let mut r = Recorder::create(&p, 40, 120, 1).unwrap();
        r.flush();
        assert_eq!(std::fs::read(&outside).unwrap(), b"precious data");
        assert_eq!(std::fs::metadata(&outside).unwrap().len(), 13);
        let cast = std::fs::read_to_string(&p).unwrap();
        assert!(cast.starts_with("{\"") && cast.contains("\"version\":2"));
        use std::os::unix::fs::MetadataExt;
        assert_eq!(std::fs::metadata(&p).unwrap().nlink(), 1);
    }

    #[test]
    fn cast_refuses_a_directory_at_the_name() {
        let d = tmp();
        let p = d.path().join("term.cast");
        std::fs::create_dir(&p).unwrap();
        assert!(Recorder::create(&p, 4, 8, 1).is_err());
        assert!(p.is_dir());
    }

    #[test]
    fn cast_replaces_a_fifo_without_blocking() {
        use rustix::fs::{mknodat, FileType, Mode, CWD};
        let d = tmp();
        let p = d.path().join("term.cast");
        mknodat(CWD, &p, FileType::Fifo, Mode::from_raw_mode(0o600), 0).unwrap();
        // A reader on the FIFO must not matter: the entry is unlinked, not opened.
        use std::os::unix::fs::OpenOptionsExt;
        let _reader = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
            .open(&p)
            .unwrap();
        let _r = Recorder::create(&p, 40, 120, 1).unwrap();
        assert!(std::fs::metadata(&p).unwrap().is_file());
    }

    #[test]
    fn cast_truncates_an_old_regular_file() {
        let d = tmp();
        let p = d.path().join("term.cast");
        std::fs::write(&p, vec![b'x'; 1000]).unwrap();
        let mut r = Recorder::create(&p, 4, 8, 1).unwrap();
        r.flush();
        let text = std::fs::read_to_string(&p).unwrap();
        assert_eq!(text.lines().count(), 1);
    }
}
