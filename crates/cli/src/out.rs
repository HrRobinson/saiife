//! Stdout writes that ignore a closed pipe.
//!
//! Rust ignores SIGPIPE, so `println!` panics when the reader has gone away
//! (`saiife status | head -1`). A reader that left early is not an error: the
//! command must still finish its work and return its real exit code. These
//! macros drop any write error.

macro_rules! out {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = write!(std::io::stdout().lock(), $($arg)*);
    }};
}

macro_rules! outln {
    () => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stdout().lock());
    }};
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stdout().lock(), $($arg)*);
    }};
}
