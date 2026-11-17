//! Terminal prompts without echo: secret values (`secret add`, `connect`) and
//! the PIN of a FIDO2 key (`saiife touch`).

use zeroize::Zeroizing;

/// The longest line a hidden prompt reads.
pub(crate) const MAX_LINE_BYTES: usize = 64 * 1024;
/// The error of a line longer than [`MAX_LINE_BYTES`].
pub(crate) const TOO_LONG: &str = "the value is too long";

/// Puts the terminal back as it was, on every path out (return, error,
/// panic). Ctrl-C does not need a signal handler: `ISIG` is off while
/// the prompt is up, so it arrives as a byte and ends the prompt here.
#[cfg(unix)]
struct Restore {
    orig: rustix::termios::Termios,
}

#[cfg(unix)]
impl Drop for Restore {
    fn drop(&mut self) {
        use std::os::fd::AsFd;
        let _ = rustix::termios::tcsetattr(
            std::io::stdin().as_fd(),
            rustix::termios::OptionalActions::Flush,
            &self.orig,
        );
    }
}

/// One line from the terminal without echo. `Err` is `cannot read the
/// terminal: …`, `no value read`, `interrupted`, [`TOO_LONG`] or
/// `the value is not UTF-8 text`.
#[cfg(unix)]
pub(crate) fn read_hidden(label: &str) -> Result<Zeroizing<String>, String> {
    use rustix::termios::{InputModes, LocalModes, OptionalActions, SpecialCodeIndex};
    use std::os::fd::AsFd;
    let stdin = std::io::stdin();
    let fd = stdin.as_fd();
    let tty = |e: rustix::io::Errno| format!("cannot read the terminal: {e}");
    let orig = rustix::termios::tcgetattr(fd).map_err(tty)?;
    let mut raw = orig.clone();
    raw.local_modes &= !(LocalModes::ECHO | LocalModes::ICANON | LocalModes::ISIG);
    raw.input_modes &= !InputModes::IXON;
    raw.special_codes[SpecialCodeIndex::VMIN] = 1;
    raw.special_codes[SpecialCodeIndex::VTIME] = 0;
    let _restore = Restore { orig };
    rustix::termios::tcsetattr(fd, OptionalActions::Flush, &raw).map_err(tty)?;
    eprint!("{label}");
    let r = read_line(fd);
    eprintln!();
    r
}

#[cfg(unix)]
fn read_line(fd: std::os::fd::BorrowedFd<'_>) -> Result<Zeroizing<String>, String> {
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let mut b = [0u8; 1];
    loop {
        match rustix::io::read(fd, &mut b) {
            Ok(0) => break,
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(format!("cannot read the terminal: {e}")),
        }
        match b[0] {
            // Ctrl-C: stop here; `Restore` puts the terminal back.
            0x03 => return Err("interrupted".into()),
            b'\n' | b'\r' => break,
            // Ctrl-D ends the value, or aborts when nothing was typed.
            0x04 => {
                if buf.is_empty() {
                    return Err("no value read".into());
                }
                break;
            }
            0x7f | 0x08 => {
                // Drop the last character, whole (UTF-8).
                while buf.last().is_some_and(|c| c & 0xC0 == 0x80) {
                    buf.pop();
                }
                buf.pop();
            }
            c if c < 0x20 => {}
            c => {
                if buf.len() >= MAX_LINE_BYTES {
                    return Err(TOO_LONG.into());
                }
                buf.push(c);
            }
        }
    }
    if buf.is_empty() {
        return Err("no value read".into());
    }
    std::str::from_utf8(&buf)
        .map(|s| Zeroizing::new(s.to_string()))
        .map_err(|_| "the value is not UTF-8 text".into())
}

/// One line from the console without echo: `rpassword` reads `CONIN$`, never a
/// piped stdin. `Err` is `cannot read the console (…)`, `no value read` or
/// [`TOO_LONG`].
#[cfg(windows)]
pub(crate) fn read_hidden(label: &str) -> Result<Zeroizing<String>, String> {
    let line = rpassword::prompt_password(label)
        .map(Zeroizing::new)
        .map_err(|e| format!("cannot read the console ({e})"))?;
    if line.is_empty() {
        return Err("no value read".into());
    }
    if line.len() > MAX_LINE_BYTES {
        return Err(TOO_LONG.into());
    }
    Ok(line)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    /// The bytes are written from a thread: macOS's socket buffer (8 KiB)
    /// is smaller than the longest line, so a write first never returns.
    fn line(bytes: &[u8]) -> Result<Zeroizing<String>, String> {
        let (mut w, r) = UnixStream::pair().unwrap();
        let bytes = bytes.to_vec();
        let writer = std::thread::spawn(move || {
            // The reader stops at a newline or the length limit and may
            // close its end first: a broken pipe here is expected.
            let _ = w.write_all(&bytes);
        });
        let got = read_line(r.as_fd());
        drop(r);
        writer.join().unwrap();
        got
    }

    #[test]
    fn read_line_edits_and_stops() {
        assert_eq!(line(b"ab\x7fc\n").unwrap().as_str(), "ac");
        assert_eq!(line("é\x7fx\r".as_bytes()).unwrap().as_str(), "x");
        assert_eq!(line(b"pin\x04rest").unwrap().as_str(), "pin");
        assert_eq!(line(b"p\x01in").unwrap().as_str(), "pin");
        assert_eq!(line(b"\x03").unwrap_err(), "interrupted");
        assert_eq!(line(b"ab\x03cd\n").unwrap_err(), "interrupted");
        assert_eq!(line(b"\n").unwrap_err(), "no value read");
        assert_eq!(line(b"\x04").unwrap_err(), "no value read");
        assert_eq!(line(b"").unwrap_err(), "no value read");
        assert_eq!(
            line(b"\xff\xfe\n").unwrap_err(),
            "the value is not UTF-8 text"
        );
        let long = vec![b'a'; MAX_LINE_BYTES + 1];
        assert_eq!(line(&long).unwrap_err(), TOO_LONG);
        let full = vec![b'a'; MAX_LINE_BYTES];
        assert_eq!(line(&full).unwrap().len(), MAX_LINE_BYTES);
    }
}
