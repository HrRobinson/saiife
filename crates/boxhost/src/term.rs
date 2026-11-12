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
use std::fs::OpenOptions;
use std::io::{self, BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use saiife_wire::source::{TermBatch, TermFrame};

/// A frame is cut at most this often (G4).
const CUT_INTERVAL_MS: u64 = 200;
/// Frames kept for readers (G4).
const RING: usize = 2000;
/// A Snapshot follows this many Deltas (G4).
const SNAPSHOT_EVERY: u32 = 200;
/// Bounds on the emulated screen (memory stays small whatever the guest asks).
const MAX_ROWS: u16 = 500;
const MAX_COLS: u16 = 1000;
/// Recording cap (G5).
const CAST_CAP: u64 = 64 << 20;
const CAST_STOP_NOTE: &str = "recording stopped: 64 MiB cap";

/// The host's view of the agent's terminal. Memory is bounded by the screen
/// size and the ring; `feed` keeps no per-call state beyond the emulator.
pub struct Screen {
    parser: vt100::Parser,
    ring: VecDeque<TermFrame>,
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

impl Screen {
    pub fn new(rows: u16, cols: u16) -> Screen {
        let (rows, cols) = clamp_dims(rows, cols);
        Screen {
            // Scrollback 0: nothing outside the visible screen is kept.
            parser: vt100::Parser::new(rows, cols, 0),
            ring: VecDeque::new(),
            seq: 0,
            rows,
            cols,
            last_rows: Vec::new(),
            last_cursor: (0, 0),
            last_cut_ms: None,
            deltas_since_snapshot: 0,
            dirty: false,
        }
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

    fn current_rows(&self) -> Vec<String> {
        self.parser
            .screen()
            .rows(0, self.cols)
            .map(|r| clean_line(&r))
            .collect()
    }

    fn cut(&mut self, now_ms: u64, force_snapshot: bool) {
        self.dirty = false;
        self.last_cut_ms = Some(now_ms);
        let rows = self.current_rows();
        let cursor = self.parser.screen().cursor_position();
        let snapshot = force_snapshot
            || self.ring.is_empty()
            || self.deltas_since_snapshot >= SNAPSHOT_EVERY
            || rows.len() != self.last_rows.len();
        let frame = if snapshot {
            self.seq += 1;
            self.deltas_since_snapshot = 0;
            TermFrame::Snapshot {
                seq: self.seq,
                rows: self.rows,
                cols: self.cols,
                lines: rows.clone(),
                cursor,
            }
        } else {
            let changed: Vec<(u16, String)> = rows
                .iter()
                .enumerate()
                .filter(|(i, l)| self.last_rows.get(*i) != Some(*l))
                .map(|(i, l)| (i as u16, l.clone()))
                .collect();
            if changed.is_empty() && cursor == self.last_cursor {
                return;
            }
            self.seq += 1;
            self.deltas_since_snapshot += 1;
            TermFrame::Delta {
                seq: self.seq,
                lines: changed,
                cursor,
            }
        };
        self.last_rows = rows;
        self.last_cursor = cursor;
        self.ring.push_back(frame);
        while self.ring.len() > RING {
            self.ring.pop_front();
        }
    }

    /// Plan 28 semantics: frames with `seq > after`; `next` is the highest seq
    /// returned, or `after.unwrap_or(0)`. A reader whose `after` is older than
    /// the ring (or who starts at a Delta whose Snapshot was evicted) gets the
    /// newest Snapshot first.
    pub fn batch(&self, after: Option<u64>, ended: bool) -> TermBatch {
        let seq_of = |f: &TermFrame| match f {
            TermFrame::Snapshot { seq, .. } | TermFrame::Delta { seq, .. } => *seq,
        };
        let mut frames: Vec<TermFrame> = self
            .ring
            .iter()
            .filter(|f| after.is_none_or(|a| seq_of(f) > a))
            .cloned()
            .collect();
        let behind = match (self.ring.front(), after) {
            (Some(first), Some(a)) => seq_of(first) > a.saturating_add(1),
            _ => false,
        };
        let starts_mid =
            matches!(frames.first(), Some(TermFrame::Delta { .. })) && (after.is_none() || behind);
        if starts_mid || behind {
            if let Some(i) = frames
                .iter()
                .rposition(|f| matches!(f, TermFrame::Snapshot { .. }))
            {
                frames.drain(..i);
            }
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

/// Plain text only: drops C0, DEL, C1 and the format characters that can
/// spoof text (bidi controls, zero-width, BOM, line/paragraph separators,
/// tag characters). Printable and wide characters stay.
pub fn clean_line(s: &str) -> String {
    s.chars().filter(|c| !is_unwanted(*c)).collect()
}

fn is_unwanted(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
                | '\u{061C}'
                | '\u{E0000}'..='\u{E007F}'
        )
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
    /// Opens the file O_NOFOLLOW|O_NONBLOCK (mode 0600), refuses anything that
    /// is not a regular file, then truncates and writes the header.
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
        let flags = (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32;
        // No O_TRUNC here: truncating before the type check could clobber
        // what a planted file points at.
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(flags)
            .open(path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "term.cast is not a regular file",
            ));
        }
        file.set_len(0)?;
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

    fn seq_of(f: &TermFrame) -> u64 {
        match f {
            TermFrame::Snapshot { seq, .. } | TermFrame::Delta { seq, .. } => *seq,
        }
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
        let b = s.batch(None, false);
        let snaps: Vec<u64> = b
            .frames
            .iter()
            .filter(|f| matches!(f, TermFrame::Snapshot { .. }))
            .map(seq_of)
            .collect();
        assert_eq!(snaps, vec![1, 202, 403]);
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
    fn cast_refuses_symlink() {
        let d = tmp();
        let target = d.path().join("target");
        std::fs::write(&target, b"keep").unwrap();
        let p = d.path().join("term.cast");
        std::os::unix::fs::symlink(&target, &p).unwrap();
        assert!(Recorder::create(&p, 40, 120, 1).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    }

    #[test]
    fn cast_refuses_fifo() {
        use rustix::fs::{mknodat, FileType, Mode, CWD};
        let d = tmp();
        let p = d.path().join("term.cast");
        mknodat(CWD, &p, FileType::Fifo, Mode::from_raw_mode(0o600), 0).unwrap();
        // With no reader the open fails (ENXIO); with a reader it opens and
        // the type check refuses. Both must return at once.
        assert!(Recorder::create(&p, 40, 120, 1).is_err());
        let _reader = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags_nonblock()
            .open(&p)
            .unwrap();
        assert!(Recorder::create(&p, 40, 120, 1).is_err());
    }

    trait NonBlock {
        fn custom_flags_nonblock(&mut self) -> &mut Self;
    }
    impl NonBlock for std::fs::OpenOptions {
        fn custom_flags_nonblock(&mut self) -> &mut Self {
            use std::os::unix::fs::OpenOptionsExt;
            self.custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
        }
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
