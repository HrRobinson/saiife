//! The embedded UI assets (plan 29, Task 7). Plan 30 fills `ASSETS` with the
//! real UI; the server serves whatever the table holds.

use ring::digest::{digest, SHA256};

/// One embedded file. `path` starts with `/`; `/` itself serves `/index.html`.
pub struct Asset {
    pub path: &'static str,
    pub mime: &'static str,
    pub bytes: &'static [u8],
}

/// Media type from the file extension (the `assets` test checks every entry).
const fn mime_of(path: &str) -> &'static str {
    let b = path.as_bytes();
    let n = b.len();
    if n >= 5
        && b[n - 5] == b'.'
        && b[n - 4] == b'h'
        && b[n - 3] == b't'
        && b[n - 2] == b'm'
        && b[n - 1] == b'l'
    {
        "text/html; charset=utf-8"
    } else if n >= 4 && b[n - 4] == b'.' && b[n - 3] == b'c' && b[n - 2] == b's' && b[n - 1] == b's'
    {
        "text/css; charset=utf-8"
    } else if n >= 3 && b[n - 3] == b'.' && b[n - 2] == b'j' && b[n - 1] == b's' {
        "text/javascript; charset=utf-8"
    } else if n >= 4 && b[n - 4] == b'.' && b[n - 3] == b's' && b[n - 2] == b'v' && b[n - 1] == b'g'
    {
        "image/svg+xml"
    } else {
        "application/json"
    }
}

macro_rules! asset {
    ($path:literal) => {
        Asset {
            path: concat!("/", $path),
            mime: mime_of($path),
            bytes: include_bytes!(concat!("../assets/", $path)),
        }
    };
}

/// The Workspace UI: every file under `crates/link/assets/` except `tests/`.
pub static ASSETS: &[Asset] = &[
    asset!("index.html"),
    asset!("app.css"),
    asset!("js/app.js"),
    asset!("js/dom.js"),
    asset!("js/format.js"),
    asset!("js/views/placeholder.js"),
    asset!("js/actions.js"),
    asset!("js/keystore.js"),
    asset!("js/wire.js"),
    asset!("js/pairing.js"),
    asset!("js/views/pair.js"),
];

/// The strong ETag: `"` + the first 16 hex digits of SHA-256(bytes) + `"`.
pub fn etag(a: &Asset) -> String {
    let d = digest(&SHA256, a.bytes);
    let mut s = String::with_capacity(18);
    s.push('"');
    for b in &d.as_ref()[..8] {
        s.push_str(&format!("{b:02x}"));
    }
    s.push('"');
    s
}
