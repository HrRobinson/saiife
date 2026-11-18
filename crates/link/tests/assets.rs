//! The asset table matches the files, and the assets stay free of HTML sinks.
#![cfg(unix)]

mod common;

use bytes::Bytes;
use common::{me, world};
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use saiife_link::assets::ASSETS;
use saiife_link::local::serve;
use saiife_link::Daemon;
use std::path::{Path, PathBuf};

fn assets_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("assets")
}

/// Every file under `assets/` except `assets/tests/`, as (served path, file).
fn files() -> Vec<(String, PathBuf)> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, PathBuf)>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                if p.strip_prefix(root).unwrap() == Path::new("tests") {
                    continue;
                }
                walk(&p, root, out);
            } else {
                let rel = p.strip_prefix(root).unwrap().to_str().unwrap().to_string();
                out.push((format!("/{rel}"), p));
            }
        }
    }
    let root = assets_dir();
    let mut out = Vec::new();
    walk(&root, &root, &mut out);
    out.sort();
    out
}

fn ext(path: &str) -> &str {
    path.rsplit('.').next().unwrap()
}

fn text(path: &PathBuf) -> String {
    String::from_utf8(std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn every_asset_file_is_served() {
    let files = files();
    assert!(!files.is_empty());
    for (url, f) in &files {
        assert!(
            ["html", "css", "js", "svg", "json"].contains(&ext(url)),
            "{} has an extension that is not allowed",
            f.display()
        );
        assert!(
            ASSETS.iter().any(|a| a.path == url),
            "{} is not in ASSETS",
            f.display()
        );
    }
    for a in ASSETS {
        assert!(
            files.iter().any(|(u, _)| u == a.path),
            "ASSETS entry {} has no file",
            a.path
        );
    }
    assert_eq!(files.len(), ASSETS.len());
}

#[test]
fn asset_mime_matches_extension() {
    for a in ASSETS {
        let want = match ext(a.path) {
            "html" => "text/html; charset=utf-8",
            "css" => "text/css; charset=utf-8",
            "js" => "text/javascript; charset=utf-8",
            "svg" => "image/svg+xml",
            "json" => "application/json",
            other => panic!("{}: unexpected extension {other}", a.path),
        };
        assert_eq!(a.mime, want, "{}", a.path);
    }
}

/// `import(` followed by anything but a quote.
fn dynamic_import_with_non_literal(line: &str) -> bool {
    let mut rest = line;
    while let Some(i) = rest.find("import(") {
        let after = rest[i + 7..].trim_start();
        if !(after.starts_with('"') || after.starts_with('\'')) {
            return true;
        }
        rest = &rest[i + 7..];
    }
    false
}

/// `on` + letters + `=` as an attribute name: preceded by whitespace or a quote.
fn has_event_attribute(line: &str) -> bool {
    let b = line.as_bytes();
    for i in 0..b.len().saturating_sub(2) {
        let prev = if i == 0 { b' ' } else { b[i - 1] };
        let boundary = !(prev.is_ascii_alphanumeric() || prev == b'_' || prev == b'-');
        if boundary && b[i] == b'o' && b[i + 1] == b'n' {
            let mut j = i + 2;
            while j < b.len() && b[j].is_ascii_lowercase() {
                j += 1;
            }
            if j > i + 2 && j < b.len() && b[j] == b'=' {
                return true;
            }
        }
    }
    false
}

/// Every forbidden thing found in one file, as "name:line: what".
fn violations(url: &str, src: &str) -> Vec<String> {
    let mut v = Vec::new();
    let is_svg = ext(url) == "svg";
    let markup = ext(url) == "html" || is_svg;
    for (n, line) in src.lines().enumerate() {
        let at = n + 1;
        let mut hit = |what: &str| v.push(format!("{url}:{at}: {what}"));
        for tok in [
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "document.write",
            "eval(",
            "new Function",
            "setTimeout(\"",
            "setTimeout('",
            "//cdn",
            "javascript:",
            "localStorage",
        ] {
            if line.contains(tok) {
                hit(tok);
            }
        }
        let scrubbed = if is_svg {
            line.replace("xmlns=\"http://www.w3.org/2000/svg\"", "")
        } else {
            line.to_string()
        };
        for tok in ["http://", "https://"] {
            if scrubbed.contains(tok) {
                hit(tok);
            }
        }
        if dynamic_import_with_non_literal(line) {
            hit("import( with a non-literal");
        }
        if markup {
            if line.contains("<script") && !line.contains("src=") {
                hit("<script without src");
            }
            if line.contains("style=") {
                hit("style= attribute");
            }
            if has_event_attribute(line) {
                hit("on...= attribute");
            }
        }
    }
    v
}

#[test]
fn assets_never_use_html_sinks() {
    let mut all = Vec::new();
    for (url, f) in files() {
        all.extend(violations(&url, &text(&f)));
    }
    assert!(all.is_empty(), "forbidden tokens:\n{}", all.join("\n"));
}

#[test]
fn scan_names_file_and_line() {
    let v = violations("/js/x.js", "ok\nel.innerHTML = x;\n");
    assert_eq!(v, vec!["/js/x.js:2: innerHTML".to_string()]);
    assert!(violations("/a.svg", "<svg xmlns=\"http://www.w3.org/2000/svg\"/>").is_empty());
    assert!(!violations(
        "/a.svg",
        "<svg xmlns=\"http://www.w3.org/2000/svg\"><image href=\"http://x/a\"/>"
    )
    .is_empty());
    assert!(!violations("/a.svg", "<svg onload=\"x\"/>").is_empty());
    assert!(!violations("/a.html", "<a/onclick=\"x\">").is_empty());
    assert!(!violations("/a.html", "<a href='x'onclick='y'>").is_empty());
    assert!(!violations("/a.html", "<a data-x='1' onclick=y>").is_empty());
    assert!(violations("/a.html", "<a data-onclick=\"y\">").is_empty());
    assert!(!violations("/a.html", "<a onclick=\"x\">").is_empty());
    assert!(!violations("/a.html", "<script>x</script>").is_empty());
    assert!(!violations("/a.js", "import(name)").is_empty());
    assert!(violations("/a.js", "import('./x.js')").is_empty());
}

#[test]
fn index_has_no_inline_script_or_style() {
    let src = text(&assets_dir().join("index.html"));
    assert!(src.starts_with("<!doctype html>"));
    assert!(src.contains("lang=\"en\""));
    assert!(src.contains("<script type=\"module\" src=\"/js/app.js\"></script>"));
    assert!(src.contains("<link rel=\"stylesheet\" href=\"/app.css\">"));
    assert!(src.contains("<main id=\"view\">"));
    assert!(src.contains("id=\"toast\" role=\"status\" aria-live=\"polite\""));
    assert_eq!(src.matches("<script").count(), 1);
    assert!(!src.contains("<style"));
    assert!(!src.contains("style="));
    assert!(!has_event_attribute(&src));
}

#[tokio::test]
async fn served_bytes_equal_files() {
    let w = world().await;
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(serve(l, Daemon::new(w.run.clone(), me()), addr.port()));
    for (url, f) in files() {
        let s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(s))
            .await
            .unwrap();
        tokio::spawn(conn);
        let req = Request::builder()
            .uri(&url)
            .header("host", format!("localhost:{}", addr.port()))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = tx.send_request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{url}");
        let mime = resp.headers()["content-type"].to_str().unwrap().to_string();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            body.as_ref(),
            std::fs::read(&f).unwrap().as_slice(),
            "{url}"
        );
        let a = ASSETS.iter().find(|a| a.path == url).unwrap();
        assert_eq!(mime, a.mime);
    }
}

/// Plan 31: the touch prompt, the terminal pane and the shared unsafe-char
/// table are embedded and served as JavaScript.
#[test]
fn assets_list_touch_and_term() {
    for p in ["/js/touch.js", "/js/term.js", "/js/unsafe.js"] {
        let a = ASSETS
            .iter()
            .find(|a| a.path == p)
            .unwrap_or_else(|| panic!("{p} is not in ASSETS"));
        assert_eq!(a.mime, "text/javascript; charset=utf-8", "{p}");
        assert!(!a.bytes.is_empty(), "{p}");
    }
}

/// `js/unsafe.js` (what `format.js visible()` escapes) equals the shared
/// sanitizer `saiife_wire::text::is_unsafe_char` for every char, and also
/// covers the surrogates (a lone one can sit in a JS string).
#[test]
fn js_unsafe_table_equals_wire() {
    let src = text(&assets_dir().join("js/unsafe.js"));
    let start = src.find("export const UNSAFE").expect("UNSAFE table");
    let body = &src[start..src[start..].find("]);").map(|i| start + i).unwrap()];
    let mut ranges: Vec<(u32, u32)> = Vec::new();
    for line in body.lines().skip(1) {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        let inner = l
            .strip_prefix('[')
            .and_then(|x| x.strip_suffix("],"))
            .unwrap_or_else(|| panic!("table line {l:?}"));
        let (lo, hi) = inner.split_once(", ").unwrap();
        let num = |s: &str| u32::from_str_radix(s.strip_prefix("0x").unwrap(), 16).unwrap();
        ranges.push((num(lo), num(hi)));
    }
    assert!(ranges.len() > 10, "{ranges:?}");
    assert!(
        ranges.windows(2).all(|w| w[0].1 < w[1].0),
        "sorted, disjoint"
    );
    let in_js = |u: u32| ranges.iter().any(|&(lo, hi)| lo <= u && u <= hi);
    for u in 0..=0x10FFFFu32 {
        match char::from_u32(u) {
            Some(c) => assert_eq!(in_js(u), saiife_wire::text::is_unsafe_char(c), "U+{u:04X}"),
            None => assert!(in_js(u), "surrogate U+{u:04X}"),
        }
    }
}

/// FU1 (M3): the Review badge's text is the daemon's and the CLI's.
#[test]
fn review_guard_text_mirrors_the_wire_constant() {
    let src = text(&assets_dir().join("js/views/review.js"));
    assert!(
        src.contains(&format!("\"{}\"", saiife_wire::source::GUARD_SKIPPED_WHY)),
        "review.js must carry GUARD_SKIPPED_WHY verbatim"
    );
}
