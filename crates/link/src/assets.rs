//! The embedded UI assets (plan 29, Task 7). Plan 30 replaces `ASSETS` with
//! the real UI; the server serves whatever the table holds.

use ring::digest::{digest, SHA256};

/// One embedded file. `path` starts with `/`; `/` itself serves `/index.html`.
pub struct Asset {
    pub path: &'static str,
    pub mime: &'static str,
    pub bytes: &'static [u8],
}

/// The placeholder UI: a page and a stylesheet, no script.
pub static ASSETS: &[Asset] = &[
    Asset {
        path: "/index.html",
        mime: "text/html; charset=utf-8",
        bytes: b"<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>saiife Workspace</title>\n<link rel=\"stylesheet\" href=\"/app.css\">\n</head>\n<body>\n<main>\n<h1>saiife Workspace</h1>\n</main>\n</body>\n</html>\n",
    },
    Asset {
        path: "/app.css",
        mime: "text/css; charset=utf-8",
        bytes: b"body { font-family: system-ui, sans-serif; margin: 2rem; }\n",
    },
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
