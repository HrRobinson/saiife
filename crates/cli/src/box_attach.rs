//! `saiife box attach <id>` (plan 38): a read-only terminal viewer for a box.
//!
//! The frames come from an untrusted guest. The host strips control
//! characters before it sends them; this end still shows every character the
//! shared table flags (`saiife_wire::text::is_unsafe_char`) and every control
//! character as a visible escape, so nothing the guest sends can act on the
//! user's terminal. The only escape sequences written are our own clear and
//! cursor-home. Input is read only for `q` and Ctrl-C; nothing is sent to
//! the box (use `saiife box say`).

use std::io::Write;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use saiife_ipc::client::{Client, ClientError};
use saiife_wire::source::{BoxId, TermFrame};
use serde_json::{json, Map, Value};

use crate::text::sanitize;

/// The most rows the client keeps; frames beyond are ignored.
pub const MAX_ROWS: usize = 500;
/// The most characters kept per row; the rest is cut.
pub const MAX_COLS: usize = 1000;
/// The most frames taken from one answer.
const MAX_FRAMES: usize = 4000;
const POLL: Duration = Duration::from_millis(250);
const CALL_TIMEOUT: Duration = Duration::from_secs(10);
const ENDED: &str = "the box's terminal has ended";

type Args = Map<String, Value>;

/// Why the viewer stopped before the box's terminal ended.
#[derive(Debug, PartialEq)]
pub enum Fail {
    /// Exit 2: not found, wrong state, invalid.
    Refused(String),
    /// Exit 5: the daemon cannot be reached or has no boxes.
    Unavailable(String),
}

/// One request to the daemon: op and arguments, the answer's fields.
pub type Call<'a> = dyn FnMut(&str, Args) -> Result<Args, Fail> + 'a;

/// Where `q` and Ctrl-C come from.
pub trait Keys {
    /// Waits up to `d` for input; true when the user asked to quit.
    fn quit_within(&mut self, d: Duration) -> bool;
}

fn clip(s: &str) -> String {
    s.chars().take(MAX_COLS).collect()
}

/// A snapshot replaces the screen; a delta patches the rows it names. The
/// screen stays within [`MAX_ROWS`] x [`MAX_COLS`]; a row index beyond the
/// bound is ignored.
pub fn apply(screen: &mut Vec<String>, f: &TermFrame) {
    match f {
        TermFrame::Snapshot { lines, .. } => {
            *screen = lines.iter().take(MAX_ROWS).map(|l| clip(l)).collect();
        }
        TermFrame::Delta { lines, .. } => {
            for (row, text) in lines {
                let row = usize::from(*row);
                if row >= MAX_ROWS {
                    continue;
                }
                if screen.len() <= row {
                    screen.resize(row + 1, String::new());
                }
                screen[row] = clip(text);
            }
        }
    }
}

/// Text made safe to print: control characters through the shared
/// `sanitize`, every other character the wire table flags (bidi marks, line
/// and paragraph separators, private use, ...) as `\u{XXXX}`.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut buf = [0u8; 4];
    for c in s.chars() {
        let one: &str = c.encode_utf8(&mut buf);
        let safe = sanitize(one);
        if safe != one {
            out.push_str(&safe);
        } else if saiife_wire::text::is_unsafe_char(c) {
            out.push_str(&format!("\\u{{{:04X}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

fn header(id: &BoxId, state: &str) -> String {
    let id = id.as_str();
    format!(
        "box {id} ({}): read-only, q quits; type into it with saiife box say {id} \"…\"",
        esc(state)
    )
}

fn draw(out: &mut dyn Write, head: &str, screen: &[String], clear: bool) {
    let mut s = String::new();
    if clear {
        // Our own sequences: clear the screen, cursor home.
        s.push_str("\x1b[2J\x1b[H");
    }
    s.push_str(head);
    s.push('\n');
    let end = screen
        .iter()
        .rposition(|l| !l.trim().is_empty())
        .map_or(0, |i| i + 1);
    for l in &screen[..end] {
        s.push_str(&esc(l));
        s.push('\n');
    }
    let _ = out.write_all(s.as_bytes());
    let _ = out.flush();
}

/// The viewer loop over an injected daemon call, keyboard and output.
pub fn drive(
    call: &mut Call<'_>,
    id: &BoxId,
    tty: bool,
    keys: &mut dyn Keys,
    out: &mut dyn Write,
) -> Result<(), Fail> {
    let listed = call("box.list", {
        let mut a = Args::new();
        a.insert("all".into(), json!(false));
        a
    })?;
    let state = listed
        .get("boxes")
        .and_then(Value::as_array)
        .and_then(|bs| {
            bs.iter()
                .find(|b| b.get("id").and_then(Value::as_str) == Some(id.as_str()))
        })
        .and_then(|b| b.get("state").and_then(Value::as_str))
        .ok_or_else(|| Fail::Refused(format!("no box {}", id.as_str())))?
        .to_string();
    let head = header(id, &state);
    let mut screen: Vec<String> = Vec::new();
    let mut after: Option<u64> = None;
    let mut first = true;
    loop {
        // `box`, not `id`: the frame's own `id` is the request's.
        let mut a = Args::new();
        a.insert("box".into(), json!(id.as_str()));
        a.insert("after".into(), json!(after));
        let ans = call("box.term.read", a)?;
        let frames: Vec<TermFrame> = match ans.get("frames") {
            Some(v) => serde_json::from_value(v.clone())
                .map_err(|_| Fail::Unavailable("the terminal answer is not readable".into()))?,
            None => Vec::new(),
        };
        for f in frames.iter().take(MAX_FRAMES) {
            apply(&mut screen, f);
        }
        if let Some(n) = ans.get("next").and_then(Value::as_u64) {
            after = Some(n);
        }
        if first || !frames.is_empty() {
            draw(out, &head, &screen, tty);
            first = false;
        }
        if ans.get("ended").and_then(Value::as_bool) == Some(true) {
            let _ = writeln!(out, "{ENDED}");
            return Ok(());
        }
        if !tty || keys.quit_within(POLL) {
            return Ok(());
        }
    }
}

/// Puts the terminal back as it was on every way out, a panic unwinding
/// included (this crate does not abort on panic).
struct RawGuard {
    orig: rustix::termios::Termios,
}

impl Drop for RawGuard {
    fn drop(&mut self) {
        use std::os::fd::AsFd;
        let _ = rustix::termios::tcsetattr(
            std::io::stdin().as_fd(),
            rustix::termios::OptionalActions::Flush,
            &self.orig,
        );
    }
}

fn raw_mode() -> Result<RawGuard, String> {
    use rustix::termios::{InputModes, LocalModes, OptionalActions, SpecialCodeIndex};
    use std::os::fd::AsFd;
    let stdin = std::io::stdin();
    let fd = stdin.as_fd();
    let e = |e: rustix::io::Errno| format!("cannot read the terminal: {e}");
    let orig = rustix::termios::tcgetattr(fd).map_err(e)?;
    let mut raw = orig.clone();
    raw.local_modes &= !(LocalModes::ECHO | LocalModes::ICANON | LocalModes::ISIG);
    raw.input_modes &= !InputModes::IXON;
    raw.special_codes[SpecialCodeIndex::VMIN] = 1;
    raw.special_codes[SpecialCodeIndex::VTIME] = 0;
    let guard = RawGuard { orig };
    rustix::termios::tcsetattr(fd, OptionalActions::Flush, &raw).map_err(e)?;
    Ok(guard)
}

/// Stdin in raw mode: `q`, `Q`, Ctrl-C or end of input quit.
struct StdinKeys;

impl Keys for StdinKeys {
    fn quit_within(&mut self, d: Duration) -> bool {
        use rustix::event::{poll, PollFd, PollFlags, Timespec};
        use std::os::fd::AsFd;
        let stdin = std::io::stdin();
        let fd = stdin.as_fd();
        let mut fds = [PollFd::new(&fd, PollFlags::IN)];
        let t = Timespec {
            tv_sec: d.as_secs() as _,
            tv_nsec: d.subsec_nanos() as _,
        };
        match poll(&mut fds, Some(&t)) {
            Ok(0) => false,
            Ok(_) => {
                let mut b = [0u8; 64];
                match rustix::io::read(stdin.as_fd(), &mut b) {
                    Ok(0) => true,
                    Ok(n) => b[..n].iter().any(|c| matches!(c, b'q' | b'Q' | 0x03)),
                    Err(rustix::io::Errno::INTR) => false,
                    Err(_) => true,
                }
            }
            Err(rustix::io::Errno::INTR) => false,
            Err(_) => true,
        }
    }
}

/// No keyboard (no TTY): never asked to quit.
struct NoKeys;

impl Keys for NoKeys {
    fn quit_within(&mut self, _: Duration) -> bool {
        false
    }
}

fn client_call(client: &mut Client, op: &str, a: Args) -> Result<Args, Fail> {
    client
        .call(op, a, Instant::now() + CALL_TIMEOUT)
        .map_err(|e| match e {
            ClientError::Refused { code, message } if code == "unavailable" => {
                Fail::Unavailable(message)
            }
            ClientError::Refused { message, .. } => Fail::Refused(message),
            other => Fail::Unavailable(format!("the daemon call failed: {other}")),
        })
}

/// Runs the viewer: exit 0 on `q`, Ctrl-C or the end of the box's terminal
/// (and for the one-shot print without a TTY), 2 refused, 5 unavailable.
pub fn run(client: &mut Client, id: &BoxId, tty: bool) -> ExitCode {
    let mut call = |op: &str, a: Args| client_call(client, op, a);
    let mut out = std::io::stdout();
    let r = if tty {
        match raw_mode() {
            Ok(_guard) => drive(&mut call, id, true, &mut StdinKeys, &mut out),
            Err(m) => Err(Fail::Unavailable(m)),
        }
    } else {
        drive(&mut call, id, false, &mut NoKeys, &mut out)
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(Fail::Refused(m)) => {
            eprintln!("saiife: {}", esc(&m));
            ExitCode::from(2)
        }
        Err(Fail::Unavailable(m)) => {
            eprintln!("saiife: {}", esc(&m));
            ExitCode::from(5)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(lines: &[&str]) -> TermFrame {
        TermFrame::Snapshot {
            seq: 1,
            rows: 40,
            cols: 120,
            lines: lines.iter().map(|s| s.to_string()).collect(),
            cursor: (0, 0),
        }
    }
    fn delta(lines: &[(u16, &str)]) -> TermFrame {
        TermFrame::Delta {
            seq: 2,
            lines: lines.iter().map(|(r, s)| (*r, s.to_string())).collect(),
            cursor: (0, 0),
        }
    }

    #[test]
    fn apply_snapshot_and_delta() {
        let mut s = vec!["old".to_string()];
        apply(&mut s, &snap(&["a", "b", "c"]));
        assert_eq!(s, ["a", "b", "c"]);
        apply(&mut s, &delta(&[(1, "B"), (4, "E")]));
        assert_eq!(s, ["a", "B", "c", "", "E"]);
        apply(&mut s, &snap(&["z"]));
        assert_eq!(s, ["z"]);
    }

    #[test]
    fn apply_is_bounded() {
        let mut s = Vec::new();
        let many: Vec<String> = (0..MAX_ROWS + 50).map(|_| "x".repeat(2000)).collect();
        apply(
            &mut s,
            &TermFrame::Snapshot {
                seq: 1,
                rows: 40,
                cols: 120,
                lines: many,
                cursor: (0, 0),
            },
        );
        assert_eq!(s.len(), MAX_ROWS);
        assert!(s.iter().all(|l| l.chars().count() == MAX_COLS));
        apply(&mut s, &delta(&[(MAX_ROWS as u16, "no"), (60000, "no")]));
        assert_eq!(s.len(), MAX_ROWS);
        apply(&mut s, &delta(&[(499, "yes")]));
        assert_eq!(s[499], "yes");
    }

    #[test]
    fn esc_shows_every_unsafe_char() {
        let t = esc("a\u{1b}[31m\u{202e}b\u{85}c\u{2028}d\u{e000}\u{200b}e");
        for bad in [
            '\u{1b}', '\u{202e}', '\u{85}', '\u{2028}', '\u{e000}', '\u{200b}',
        ] {
            assert!(!t.contains(bad), "{t:?}");
        }
        assert!(t.contains("\\x1b"), "{t}");
        assert!(t.contains("\\u{202E}"), "{t}");
        assert!(t.contains("\\x85"), "{t}");
        assert!(t.contains("\\u{2028}"), "{t}");
        assert_eq!(esc("plain ünï"), "plain ünï");
    }

    struct Quit(usize);
    impl Keys for Quit {
        fn quit_within(&mut self, _: Duration) -> bool {
            self.0 = self.0.saturating_sub(1);
            self.0 == 0
        }
    }

    fn id() -> BoxId {
        BoxId::parse("b1").unwrap()
    }

    fn answer(frames: Value, next: u64, ended: bool) -> Args {
        let v = json!({"frames": frames, "next": next, "ended": ended});
        v.as_object().unwrap().clone()
    }

    fn listed() -> Args {
        json!({"boxes": [{"id": "b1", "state": "run\u{1b}ning"}]})
            .as_object()
            .unwrap()
            .clone()
    }

    #[test]
    fn attach_sends_box_not_id() {
        let mut seen: Vec<(String, Args)> = Vec::new();
        let mut n = 0;
        let mut call = |op: &str, a: Args| -> Result<Args, Fail> {
            seen.push((op.to_string(), a));
            n += 1;
            Ok(match op {
                "box.list" => listed(),
                _ if n < 4 => answer(
                    json!([serde_json::to_value(snap(&["hi"])).unwrap()]),
                    7,
                    false,
                ),
                _ => answer(json!([]), 7, true),
            })
        };
        let mut out = Vec::new();
        drive(&mut call, &id(), true, &mut Quit(10), &mut out).unwrap();
        let reads: Vec<&Args> = seen
            .iter()
            .filter(|(o, _)| o == "box.term.read")
            .map(|(_, a)| a)
            .collect();
        assert_eq!(reads.len(), 3);
        assert_eq!(
            Value::Object(reads[0].clone()),
            json!({"box": "b1", "after": null})
        );
        assert_eq!(
            Value::Object(reads[1].clone()),
            json!({"box": "b1", "after": 7})
        );
        assert!(reads.iter().all(|a| !a.contains_key("id")));
        let o = String::from_utf8(out).unwrap();
        assert!(o.ends_with("the box's terminal has ended\n"), "{o}");
    }

    #[test]
    fn attach_without_tty_prints_once() {
        let mut reads = 0;
        let mut call = |op: &str, _a: Args| -> Result<Args, Fail> {
            Ok(if op == "box.list" {
                listed()
            } else {
                reads += 1;
                answer(
                    json!([serde_json::to_value(snap(&["one", "t\u{1b}wo\u{202e}"])).unwrap()]),
                    1,
                    false,
                )
            })
        };
        let mut out = Vec::new();
        drive(&mut call, &id(), false, &mut NoKeys, &mut out).unwrap();
        assert_eq!(reads, 1);
        let o = String::from_utf8(out).unwrap();
        assert!(!o.contains('\u{1b}') && !o.contains('\u{202e}'), "{o:?}");
        assert!(
            o.contains("box b1 (run\\x1bning): read-only, q quits;"),
            "{o}"
        );
        assert!(o.contains("one\n"), "{o}");
        assert!(o.contains("t\\x1bwo\\u{202E}"), "{o}");
    }

    #[test]
    fn unknown_box_is_refused() {
        let mut call = |_: &str, _: Args| -> Result<Args, Fail> {
            Ok(json!({"boxes": []}).as_object().unwrap().clone())
        };
        let r = drive(&mut call, &id(), false, &mut NoKeys, &mut Vec::new());
        assert_eq!(r, Err(Fail::Refused("no box b1".into())));
    }
}
