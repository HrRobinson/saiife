//! Response masking (spec §6.7.1 step 10): every vault value in use, in
//! every encoding an upstream is likely to echo it in, plus the v1 masking
//! patterns (§6.3), becomes `[MASKED]`. Then field redaction (§6.7.3), then
//! the cut to `max_response_bytes`.
//!
//! Forms built for each value (values shorter than 4 bytes are skipped):
//! - raw;
//! - standard and URL-safe base64, padded and unpadded;
//! - the base64 "cores" for the three byte alignments: inside a larger
//!   base64 blob the value's encoding depends on its offset mod 3, so for
//!   each offset we keep the characters whose 6 bits come from the value
//!   alone. At most one character on each side of a masked core carries up
//!   to 4 bits of the value; that is not enough to recover anything;
//! - percent-encoded: exact forms (every byte outside the RFC 3986
//!   unreserved set, upper- and lower-case hex), plus a per-value byte regex
//!   where each byte may be raw or `%XX` in any case and a space may be `+`
//!   or `%20` (partial encoders such as Python `quote` or JS
//!   `encodeURIComponent`, mixed case, form encoding);
//! - hex, lower and upper case;
//! - each of the above as it appears inside a JSON string (`\"`, `\\`,
//!   control characters, and `/` either as-is or as `\/`), when that differs.
//!
//! Matching is Aho-Corasick with overlapping matches plus the percent
//! regexes, over the bytes and over a JSON-unescaped view of them; the union
//! of all hits is masked, so overlapping values are hidden whole.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use bytes::Bytes;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use percent_encoding::{percent_encode, AsciiSet, NON_ALPHANUMERIC};
use regex::bytes::{Regex, RegexBuilder};
use zeroize::Zeroizing;

use crate::BrokerError;

pub const MASK: &str = "[MASKED]";

/// Values shorter than this would mask noise (and the vault refuses them).
const MIN_VALUE_LEN: usize = 4;

/// RFC 3986 unreserved: ALPHA / DIGIT / "-" / "." / "_" / "~".
const NOT_UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Replaces vault values in every masked form. `Debug` never prints them.
pub struct Masker {
    ac: Option<AhoCorasick>,
    /// One per value: every byte raw or `%XX` (any hex case), a space also
    /// as `+` or `%20`. Covers partial encoders (Python `quote`, JS
    /// `encodeURIComponent`) and mixed-case escapes.
    pct: Vec<Regex>,
    forms: usize,
}

impl std::fmt::Debug for Masker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Masker")
            .field("forms", &self.forms)
            .field("percent_patterns", &self.pct.len())
            .finish()
    }
}

impl Masker {
    pub fn new(values: &[&str]) -> Masker {
        let mut forms: Vec<Zeroizing<Vec<u8>>> = Vec::new();
        let mut pct = Vec::new();
        for v in values {
            let v = v.as_bytes();
            if v.len() < MIN_VALUE_LEN {
                continue;
            }
            // The pattern is generated and always valid; a size-limit error
            // (a huge value) leaves the exact percent forms in `ac` below.
            // regex errors for size never quote the pattern.
            if let Ok(re) = RegexBuilder::new(&percent_pattern(v))
                .size_limit(64 << 20)
                .build()
            {
                pct.push(re);
            }
            for form in encodings(v) {
                for escaped in json_escapes(&form) {
                    forms.push(escaped);
                }
                forms.push(form);
            }
        }
        forms.sort_unstable_by(|a, b| a.as_slice().cmp(b.as_slice()));
        forms.dedup_by(|a, b| a.as_slice() == b.as_slice());
        forms.retain(|f| !f.is_empty());
        let ac = if forms.is_empty() {
            None
        } else {
            Some(
                // Standard semantics: overlapping matches are all reported
                // and masked as a union, so two values sharing a suffix and
                // a prefix are both hidden whole.
                AhoCorasickBuilder::new()
                    .match_kind(MatchKind::Standard)
                    .build(forms.iter().map(|f| f.as_slice()))
                    .expect("masking automaton builds"),
            )
        };
        Masker {
            ac,
            pct,
            forms: forms.len(),
        }
    }

    /// Replace every vault form in `b` with `[MASKED]`. Matches are looked
    /// for in `b` and, when `b` holds a backslash, in a JSON-unescaped view
    /// of it (`\uXXXX`, `\/`, ...) mapped back to `b`'s offsets, so a value
    /// hidden by escapes is caught even in JSON that does not parse (a body
    /// cut by the reader). Overlapping hits are merged into one mask.
    pub fn mask_bytes(&self, b: &[u8]) -> Vec<u8> {
        let mut spans = Vec::new();
        self.collect_spans(b, &mut spans);
        if b.contains(&b'\\') {
            if u32::try_from(b.len()).is_err() {
                // Far above any read limit; fail closed rather than map it.
                return MASK.as_bytes().to_vec();
            }
            let (decoded, map) = json_unescape(b);
            let mut inner = Vec::new();
            self.collect_spans(&decoded, &mut inner);
            spans.extend(
                inner
                    .into_iter()
                    .map(|(s, e)| (map[s] as usize, orig_span(&map, b.len(), e - 1).1)),
            );
        }
        apply_spans(b, spans)
    }

    fn collect_spans(&self, b: &[u8], spans: &mut Vec<(usize, usize)>) {
        if let Some(ac) = &self.ac {
            spans.extend(ac.find_overlapping_iter(b).map(|m| (m.start(), m.end())));
        }
        for re in &self.pct {
            spans.extend(
                re.find_iter(b)
                    .filter(|m| !m.is_empty())
                    .map(|m| (m.start(), m.end())),
            );
        }
    }

    /// Vault forms, then the v1 masking patterns.
    pub fn mask_text(&self, s: &str) -> String {
        let masked = self.mask_bytes(s.as_bytes());
        // Every form is ASCII or a whole valid UTF-8 string, and a valid
        // UTF-8 needle only matches on char boundaries, so this is lossless.
        let masked = String::from_utf8(masked)
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
        saiife_audit::mask::mask(&masked)
    }
}

/// Byte regex for `v` with each byte raw or percent-encoded in any hex case
/// (unreserved bytes too: some encoders escape them), and a space also as
/// `+`. Unicode is off, so `\xNN` is one byte.
fn percent_pattern(v: &[u8]) -> Zeroizing<String> {
    fn nibble(p: &mut String, n: u8) {
        match n {
            0..=9 => p.push((b'0' + n) as char),
            _ => {
                let up = (b'A' + n - 10) as char;
                p.push('[');
                p.push(up);
                p.push(up.to_ascii_lowercase());
                p.push(']');
            }
        }
    }
    let mut p = Zeroizing::new(String::from("(?-u)"));
    for &b in v {
        p.push_str(&format!("(?:\\x{b:02X}|%"));
        nibble(&mut p, b >> 4);
        nibble(&mut p, b & 0xf);
        if b == b' ' {
            p.push_str("|\\+");
        }
        p.push(')');
    }
    p
}

/// Decode JSON string escapes anywhere in `b`. Returns the decoded bytes and,
/// for each decoded byte, the offset in `b` where its source starts (see
/// [`orig_span`] for the end). Malformed escapes and lone surrogates are kept
/// as literal bytes.
///
/// Memory bound: the decoded output is never longer than `b`, and the map is
/// one `u32` per decoded byte, so it takes at most 4x `b.len()` (test
/// `unescape_map_is_compact`). The caller keeps `b.len() <= u32::MAX`.
fn json_unescape(b: &[u8]) -> (Vec<u8>, Vec<u32>) {
    fn hex4(b: &[u8], at: usize) -> Option<u32> {
        let s = b.get(at..at + 4)?;
        let s = std::str::from_utf8(s).ok()?;
        if !s.bytes().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        u32::from_str_radix(s, 16).ok()
    }
    let mut out = Vec::with_capacity(b.len());
    let mut map = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            let simple = match b[i + 1] {
                b'"' => Some(b'"'),
                b'\\' => Some(b'\\'),
                b'/' => Some(b'/'),
                b'n' => Some(b'\n'),
                b'r' => Some(b'\r'),
                b't' => Some(b'\t'),
                b'b' => Some(0x08),
                b'f' => Some(0x0c),
                _ => None,
            };
            if let Some(c) = simple {
                out.push(c);
                map.push(i as u32);
                i += 2;
                continue;
            }
            if b[i + 1] == b'u' {
                if let Some(hi) = hex4(b, i + 2) {
                    let (cp, len) = if (0xD800..0xDC00).contains(&hi)
                        && b.get(i + 6) == Some(&b'\\')
                        && b.get(i + 7) == Some(&b'u')
                    {
                        match hex4(b, i + 8) {
                            Some(lo) if (0xDC00..0xE000).contains(&lo) => {
                                (0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00), 12)
                            }
                            _ => (hi, 6),
                        }
                    } else {
                        (hi, 6)
                    };
                    if let Some(ch) = char::from_u32(cp) {
                        let mut buf = [0u8; 4];
                        for &c in ch.encode_utf8(&mut buf).as_bytes() {
                            out.push(c);
                            map.push(i as u32);
                        }
                        i += len;
                        continue;
                    }
                }
            }
        }
        out.push(b[i]);
        map.push(i as u32);
        i += 1;
    }
    (out, map)
}

/// `[start, end)` in the original bytes (of length `len`) of decoded byte
/// `i`. Sources are contiguous, so a byte's source ends where the next
/// different start begins; the bytes of one `\uXXXX` share a start, so this
/// looks at most 3 entries ahead.
fn orig_span(map: &[u32], len: usize, i: usize) -> (usize, usize) {
    let start = map[i];
    let end = map[i + 1..]
        .iter()
        .find(|&&s| s != start)
        .map_or(len, |&s| s as usize);
    (start as usize, end)
}

/// Replace the union of `spans` in `b` with one `[MASKED]` per merged run.
fn apply_spans(b: &[u8], mut spans: Vec<(usize, usize)>) -> Vec<u8> {
    if spans.is_empty() {
        return b.to_vec();
    }
    spans.sort_unstable();
    let mut out = Vec::with_capacity(b.len());
    let mut last = 0;
    let mut cur: Option<(usize, usize)> = None;
    for (s, e) in spans {
        match cur {
            Some((cs, ce)) if s <= ce => cur = Some((cs, ce.max(e))),
            Some((cs, ce)) => {
                out.extend_from_slice(&b[last..cs]);
                out.extend_from_slice(MASK.as_bytes());
                last = ce;
                cur = Some((s, e));
            }
            None => cur = Some((s, e)),
        }
    }
    if let Some((cs, ce)) = cur {
        out.extend_from_slice(&b[last..cs]);
        out.extend_from_slice(MASK.as_bytes());
        last = ce;
    }
    out.extend_from_slice(&b[last..]);
    out
}

/// Raw, base64 (both alphabets, padded, unpadded, three alignments),
/// percent-encoded and hex forms of `v`.
fn encodings(v: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
    let mut out: Vec<Zeroizing<Vec<u8>>> = vec![Zeroizing::new(v.to_vec())];
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        out.push(Zeroizing::new(engine.encode(v).into_bytes()));
    }
    for engine in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
        for shift in 0..3usize {
            let mut shifted = Zeroizing::new(vec![0u8; shift]);
            shifted.extend_from_slice(v);
            let enc = Zeroizing::new(engine.encode(shifted.as_slice()).into_bytes());
            // Characters are 6 bits; the value's bits are [8*shift, 8*(shift+n)).
            let start = (8 * shift).div_ceil(6);
            let end = (8 * (shift + v.len())) / 6;
            if end > start {
                out.push(Zeroizing::new(enc[start..end].to_vec()));
            }
        }
    }
    // `%2F` and `%2f`: only escapes and hex digits are touched by the
    // lowercasing, since unreserved letters are left raw and unchanged.
    let pct = Zeroizing::new(percent_encode(v, NOT_UNRESERVED).to_string().into_bytes());
    out.push(Zeroizing::new(lower_percent_hex(&pct)));
    out.push(pct);
    out.push(Zeroizing::new(hex(v, b"0123456789abcdef")));
    out.push(Zeroizing::new(hex(v, b"0123456789ABCDEF")));
    out
}

/// `%2F` → `%2f`, leaving every other byte alone.
fn lower_percent_hex(b: &[u8]) -> Vec<u8> {
    let mut out = b.to_vec();
    let mut i = 0;
    while i < out.len() {
        if out[i] == b'%' && i + 2 < out.len() {
            out[i + 1] = out[i + 1].to_ascii_lowercase();
            out[i + 2] = out[i + 2].to_ascii_lowercase();
            i += 3;
        } else {
            i += 1;
        }
    }
    out
}

fn hex(v: &[u8], digits: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 2);
    for b in v {
        out.push(digits[(b >> 4) as usize]);
        out.push(digits[(b & 0xf) as usize]);
    }
    out
}

/// `form` as it appears inside a JSON string: once with `/` unescaped (what
/// serde_json writes) and once as `\/`. Only the variants that differ from
/// `form` are returned.
fn json_escapes(form: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
    let mut out = Vec::new();
    for escape_slash in [false, true] {
        let mut e = Zeroizing::new(Vec::with_capacity(form.len() + 8));
        for &c in form {
            match c {
                b'"' => e.extend_from_slice(b"\\\""),
                b'\\' => e.extend_from_slice(b"\\\\"),
                b'/' if escape_slash => e.extend_from_slice(b"\\/"),
                b'\n' => e.extend_from_slice(b"\\n"),
                b'\r' => e.extend_from_slice(b"\\r"),
                b'\t' => e.extend_from_slice(b"\\t"),
                0x08 => e.extend_from_slice(b"\\b"),
                0x0c => e.extend_from_slice(b"\\f"),
                c if c < 0x20 => e.extend_from_slice(format!("\\u{c:04x}").as_bytes()),
                c => e.push(c),
            }
        }
        if e.as_slice() != form {
            out.push(e);
        }
    }
    out
}

/// A response after masking, redaction and the cut.
#[derive(Debug)]
pub struct Finished {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub truncated: bool,
    pub redacted: usize,
}

/// Response headers that reach the agent (masked). All others are dropped.
fn header_allowed(name: &HeaderName) -> bool {
    // HeaderName is always lower case.
    let n = name.as_str();
    matches!(
        n,
        "content-type" | "link" | "retry-after" | "etag" | "x-shopify-shop-api-call-limit"
    ) || n.starts_with("x-ratelimit-")
        || n.starts_with("ratelimit-")
}

fn mask_headers(headers: &HeaderMap, masker: &Masker) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in headers {
        if !header_allowed(name) {
            continue;
        }
        let masked = match value.to_str() {
            Ok(s) => masker.mask_text(s).into_bytes(),
            Err(_) => masker.mask_bytes(value.as_bytes()),
        };
        // Masking only inserts ASCII, so this succeeds; if not, drop it.
        if let Ok(v) = HeaderValue::from_bytes(&masked) {
            out.append(name.clone(), v);
        }
    }
    out
}

/// Mask strings (keys and values) of a JSON tree in place, with the vault
/// forms and the v1 patterns.
fn mask_json_strings(v: &mut serde_json::Value, masker: &Masker) {
    use serde_json::Value;
    match v {
        Value::String(s) => *s = masker.mask_text(s),
        Value::Array(items) => items.iter_mut().for_each(|i| mask_json_strings(i, masker)),
        Value::Object(map) => {
            let old = std::mem::take(map);
            for (k, mut child) in old {
                mask_json_strings(&mut child, masker);
                map.insert(masker.mask_text(&k), child);
            }
        }
        _ => {}
    }
}

/// `application/json`, `text/json` or any `+json` media type.
fn is_json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| {
            let mt = ct
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            mt.ends_with("/json") || mt.ends_with("+json")
        })
        .unwrap_or(false)
}

/// The v1 patterns over a body that is not JSON. A body that is not UTF-8
/// is scanned through a lossy view; it is only replaced by that (masked)
/// view when a pattern hit, so clean binary passes through byte for byte.
fn v1_mask_body(masked: Vec<u8>) -> Vec<u8> {
    match String::from_utf8(masked) {
        Ok(s) => saiife_audit::mask::mask(&s).into_bytes(),
        Err(e) => {
            let bytes = e.into_bytes();
            let lossy = String::from_utf8_lossy(&bytes);
            let m = saiife_audit::mask::mask(&lossy);
            if m == lossy {
                bytes
            } else {
                m.into_bytes()
            }
        }
    }
}

/// Step 10 of the pipeline. `body` was read up to `max + 64 KiB` (Task 9)
/// and `truncated` says whether more was available. Order:
/// 0. a JSON content type over a body that is not UTF-8 is refused
///    (`BadResponseEncoding`), except a char cut by the reader,
/// 1. mask the bytes with the vault forms (every body),
/// 2. if it parses as JSON: redact (when `redact` is set), mask every key
///    and string with the vault forms and the v1 patterns, always
///    re-serialize, then the v1 patterns over the whole text. Not JSON: `RedactNonJson` when `redact` is set,
///    else the v1 patterns over the (lossy, if need be) text,
/// 3. cut to `max` and set `truncated`.
///
/// Masking before the cut means a value straddling `max` is replaced whole.
pub fn finish(
    status: u16,
    headers: HeaderMap,
    body: Bytes,
    truncated: bool,
    masker: &Masker,
    redact: &[String],
    max: usize,
) -> Result<Finished, BrokerError> {
    if is_json_content_type(&headers) {
        if let Err(e) = std::str::from_utf8(&body) {
            // Only a multi-byte char cut by the reader is tolerated.
            if !(truncated && e.error_len().is_none()) {
                return Err(BrokerError::BadResponseEncoding);
            }
        }
    }
    let headers = mask_headers(&headers, masker);
    let mut redacted = 0;
    // Pass 1, every body: the vault forms over the bytes.
    let masked = masker.mask_bytes(&body);
    // Pass 2: JSON gets the tree pass (redact, then every key and string,
    // which sees values hidden by escapes), is always re-serialized, and gets
    // the v1 patterns once more over the whole text. Anything else gets the
    // v1 patterns over the text.
    let mut out: Vec<u8> = match serde_json::from_slice::<serde_json::Value>(&masked) {
        Ok(mut v) => {
            if !redact.is_empty() {
                redacted = crate::redact::redact(&mut v, redact);
            }
            mask_json_strings(&mut v, masker);
            // Always the re-serialized tree: with duplicate keys serde keeps
            // the last value, and a client could read the first, so only the
            // checked tree may leave.
            let text = serde_json::to_string(&v).map_err(|_| BrokerError::RedactNonJson)?;
            // The vault forms once more over exactly the bytes that leave: a
            // value can form across a key/value boundary or by re-escaping.
            let text = match String::from_utf8(masker.mask_bytes(text.as_bytes())) {
                Ok(t) => t,
                Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
            };
            // Last pass over the whole text, for v1 patterns that span JSON
            // tokens. It may break the JSON; over-masking is accepted.
            saiife_audit::mask::mask(&text).into_bytes()
        }
        Err(_) if !redact.is_empty() => return Err(BrokerError::RedactNonJson),
        Err(_) => v1_mask_body(masked),
    };
    let mut truncated = truncated;
    if out.len() > max {
        out.truncate(max);
        truncated = true;
    }
    Ok(Finished {
        status,
        headers,
        body: Bytes::from(out),
        truncated,
        redacted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "shpat_0123456789abcdef/+x?Y";

    fn masked(m: &Masker, s: &str) -> String {
        String::from_utf8(m.mask_bytes(s.as_bytes())).unwrap()
    }

    #[test]
    fn masks_raw_base64_url_hex_forms() {
        let m = Masker::new(&[SECRET]);
        let v = SECRET.as_bytes();
        let pct = percent_encode(v, NOT_UNRESERVED).to_string();
        assert!(pct.contains("%2F"), "{pct}");
        let forms = [
            SECRET.to_string(),
            STANDARD.encode(v),
            STANDARD_NO_PAD.encode(v),
            URL_SAFE.encode(v),
            URL_SAFE_NO_PAD.encode(v),
            pct.clone(),
            String::from_utf8(lower_percent_hex(pct.as_bytes())).unwrap(),
            String::from_utf8(hex(v, b"0123456789abcdef")).unwrap(),
            String::from_utf8(hex(v, b"0123456789ABCDEF")).unwrap(),
        ];
        for form in forms {
            let out = masked(&m, &format!("a {form} b"));
            assert_eq!(out, "a [MASKED] b", "form {form} not masked");
        }
    }

    #[test]
    fn basic_auth_pair_with_colon_masked() {
        // Task 7 passes `username:password` as one value for `basic` auth.
        let pair = "shop-admin:s3cr3t-Pass";
        let m = Masker::new(&[pair]);
        let hdr = format!("Basic {}", STANDARD.encode(pair));
        assert_eq!(masked(&m, &hdr), "Basic [MASKED]");
        assert_eq!(masked(&m, &format!("u={pair};")), "u=[MASKED];");
        assert_eq!(masked(&m, "shop-admin%3As3cr3t-Pass"), "[MASKED]");
        assert_eq!(masked(&m, "shop-admin%3as3cr3t-Pass"), "[MASKED]");
    }

    #[test]
    fn masks_base64url_unpadded() {
        // A GitHub-style error body echoing the token as base64url, no padding.
        let tok = "ghx_tokenvalue12345";
        let m = Masker::new(&[tok]);
        let enc = URL_SAFE_NO_PAD.encode(tok);
        assert_ne!(enc.len() % 4, 0, "test needs a value that would be padded");
        let body = format!(r#"{{"message":"bad credentials {enc}"}}"#);
        assert_eq!(
            masked(&m, &body),
            r#"{"message":"bad credentials [MASKED]"}"#
        );
    }

    #[test]
    fn masks_base64_at_every_alignment_inside_a_blob() {
        let m = Masker::new(&[SECRET]);
        for prefix in ["", "u", "us", "use", "user:"] {
            for suffix in ["", "!", ":tail", "xyzw"] {
                let blob = format!("{prefix}{SECRET}{suffix}");
                for engine in [&STANDARD, &URL_SAFE_NO_PAD] {
                    let enc = engine.encode(blob.as_bytes());
                    let out = masked(&m, &enc);
                    assert!(out.contains(MASK), "{prefix:?}/{suffix:?}: {out}");
                    // At most one stray char on each side of the core.
                    let rest = out.replace(MASK, "");
                    let core_len = enc.len() - rest.len();
                    assert!(core_len >= (SECRET.len() * 8 / 6) - 2, "{out}");
                }
            }
        }
    }

    #[test]
    fn masks_json_escaped_forms() {
        let secret = r#"pa"ss\w/rd"#;
        let m = Masker::new(&[secret]);
        assert_eq!(masked(&m, r#"{"p":"pa\"ss\\w/rd"}"#), r#"{"p":"[MASKED]"}"#);
        assert_eq!(
            masked(&m, r#"{"p":"pa\"ss\\w\/rd"}"#),
            r#"{"p":"[MASKED]"}"#
        );
        let slashy = "key???value"; // standard base64 has a `/`
        let b64 = Masker::new(&[slashy]);
        let esc = STANDARD.encode(slashy).replace('/', "\\/");
        assert!(esc.contains("\\/"), "{esc}");
        assert_eq!(masked(&b64, &format!("\"{esc}\"")), "\"[MASKED]\"");
    }

    #[test]
    fn short_values_skipped_and_debug_hides_values() {
        let m = Masker::new(&["abc", SECRET]);
        assert_eq!(masked(&m, "abc"), "abc");
        let dbg = format!("{m:?}");
        assert!(!dbg.contains(SECRET) && !dbg.contains("abc"), "{dbg}");
        let empty = Masker::new(&[]);
        assert_eq!(masked(&empty, "x"), "x");
    }

    #[test]
    fn masks_secret_straddling_cut() {
        let max = 1000;
        let m = Masker::new(&[SECRET]);
        let mut body = "a".repeat(max - 3);
        body.push_str(SECRET);
        body.push_str(&"b".repeat(100));
        let f = finish(
            200,
            HeaderMap::new(),
            Bytes::from(body),
            false,
            &m,
            &[],
            max,
        )
        .unwrap();
        assert!(f.truncated);
        assert_eq!(f.body.len(), max);
        let text = std::str::from_utf8(&f.body).unwrap();
        assert!(text.ends_with("[MA"), "{}", &text[text.len() - 10..]);
        // No prefix of the secret survives.
        assert!(!text.contains(&SECRET[..3]));
    }

    #[test]
    fn not_cut_when_under_max_keeps_reader_flag() {
        let m = Masker::new(&[]);
        let f = finish(
            200,
            HeaderMap::new(),
            Bytes::from_static(b"ok"),
            false,
            &m,
            &[],
            10,
        )
        .unwrap();
        assert!(!f.truncated);
        assert_eq!(&f.body[..], b"ok");
        let f = finish(
            200,
            HeaderMap::new(),
            Bytes::from_static(b"ok"),
            true,
            &m,
            &[],
            10,
        )
        .unwrap();
        assert!(f.truncated);
    }

    #[test]
    fn v1_patterns_masked_in_text() {
        let m = Masker::new(&[SECRET]);
        let gh = format!("ghp_{}", "Z".repeat(36));
        let out = m.mask_text(&format!("vault {SECRET} other {gh} end"));
        assert_eq!(out, "vault [MASKED] other [MASKED] end");
        // And through finish, with and without redaction.
        let body = format!(r#"{{"note":"token {gh}","customer":{{"email":"a@b.dk"}}}}"#);
        let f = finish(
            200,
            HeaderMap::new(),
            Bytes::from(body.clone()),
            false,
            &m,
            &[],
            1 << 20,
        )
        .unwrap();
        assert!(!std::str::from_utf8(&f.body).unwrap().contains(&gh));
        let f = finish(
            200,
            HeaderMap::new(),
            Bytes::from(body),
            false,
            &m,
            &["customer.email".to_string()],
            1 << 20,
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&f.body).unwrap();
        assert_eq!(v["note"], "token [MASKED]");
        assert_eq!(v["customer"]["email"], "[REDACTED]");
        assert_eq!(f.redacted, 1);
    }

    #[test]
    fn redact_set_masks_values_hidden_by_json_escapes() {
        // `s` is `s`: only visible to the masker after parsing.
        let m = Masker::new(&[SECRET]);
        let hidden = SECRET.replacen('s', "\\u0073", 1);
        let body = format!(r#"{{"k":"{hidden}"}}"#);
        let f = finish(
            200,
            HeaderMap::new(),
            Bytes::from(body),
            false,
            &m,
            &["x".into()],
            1 << 20,
        )
        .unwrap();
        assert_eq!(&f.body[..], br#"{"k":"[MASKED]"}"#);
    }

    #[test]
    fn redact_non_json_withheld() {
        let m = Masker::new(&[]);
        let err = finish(
            200,
            HeaderMap::new(),
            Bytes::from_static(b"<html>not json</html>"),
            false,
            &m,
            &["customer.email".to_string()],
            1 << 20,
        )
        .unwrap_err();
        assert!(matches!(err, BrokerError::RedactNonJson));
        // A body cut by the reader is not valid JSON either.
        let err = finish(
            200,
            HeaderMap::new(),
            Bytes::from_static(b"{\"a\":"),
            true,
            &m,
            &["a".to_string()],
            1 << 20,
        )
        .unwrap_err();
        assert!(matches!(err, BrokerError::RedactNonJson));
    }

    #[test]
    fn headers_outside_allowlist_dropped() {
        let m = Masker::new(&[SECRET]);
        let mut h = HeaderMap::new();
        h.insert("content-type", HeaderValue::from_static("application/json"));
        h.insert(
            "link",
            HeaderValue::from_str(&format!("<https://x/?page=2&t={SECRET}>; rel=\"next\""))
                .unwrap(),
        );
        h.insert("retry-after", HeaderValue::from_static("5"));
        h.insert("etag", HeaderValue::from_static("\"abc\""));
        h.insert("x-ratelimit-remaining", HeaderValue::from_static("59"));
        h.insert("ratelimit-reset", HeaderValue::from_static("10"));
        h.insert(
            "x-shopify-shop-api-call-limit",
            HeaderValue::from_static("1/40"),
        );
        h.insert("set-cookie", HeaderValue::from_static("sid=1"));
        h.insert("x-request-id", HeaderValue::from_static("r1"));
        h.insert("content-length", HeaderValue::from_static("123"));
        h.insert("server", HeaderValue::from_static("nginx"));
        h.insert("ratelimit", HeaderValue::from_static("x"));
        let f = finish(200, h, Bytes::new(), false, &m, &[], 10).unwrap();
        let mut names: Vec<&str> = f.headers.keys().map(|k| k.as_str()).collect();
        names.sort();
        assert_eq!(
            names,
            [
                "content-type",
                "etag",
                "link",
                "ratelimit-reset",
                "retry-after",
                "x-ratelimit-remaining",
                "x-shopify-shop-api-call-limit"
            ]
        );
        assert_eq!(
            f.headers["link"],
            "<https://x/?page=2&t=[MASKED]>; rel=\"next\""
        );
    }

    fn fin(
        m: &Masker,
        ct: Option<&str>,
        body: Vec<u8>,
        truncated: bool,
    ) -> Result<Finished, BrokerError> {
        let mut h = HeaderMap::new();
        if let Some(ct) = ct {
            h.insert("content-type", HeaderValue::from_str(ct).unwrap());
        }
        finish(200, h, Bytes::from(body), truncated, m, &[], 1 << 20)
    }

    #[test]
    fn redact_masks_values_hidden_by_json_escapes() {
        // redact = []: the tree pass still runs on every JSON body.
        let m = Masker::new(&[SECRET]);
        let hidden = SECRET.replacen('s', "\\u0073", 1);
        let body = format!(r#"{{"k":"{hidden}","n":1}}"#);
        let f = fin(&m, Some("application/json"), body.into_bytes(), false).unwrap();
        assert_eq!(&f.body[..], br#"{"k":"[MASKED]","n":1}"#);

        // Every byte escaped, in a key.
        let all: String = SECRET.bytes().map(|b| format!("\\u{b:04x}")).collect();
        let body = format!(r#"{{"{all}":"v"}}"#);
        let f = fin(&m, None, body.into_bytes(), false).unwrap();
        assert_eq!(&f.body[..], br#"{"[MASKED]":"v"}"#);

        // Python json.dumps (ensure_ascii): non-ASCII as `\u00XX`.
        let py = "t\u{f8}ken-\u{e9}1234";
        let m = Masker::new(&[py]);
        let body = br#"{"a": "t\u00f8ken-\u00e91234", "b": [1, 2]}"#.to_vec();
        let f = fin(&m, Some("application/json"), body, false).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&f.body).unwrap();
        assert_eq!(v["a"], "[MASKED]");
    }

    #[test]
    fn json_always_reserialized() {
        // The bytes sent are exactly the tree that was checked.
        let m = Masker::new(&[SECRET]);
        let body = b"{ \"a\" : 1,\n  \"b\": \"\\u0041\" }".to_vec();
        let f = fin(&m, Some("application/json"), body, false).unwrap();
        assert_eq!(&f.body[..], br#"{"a":1,"b":"A"}"#);
    }

    #[test]
    fn duplicate_keys_resolved_to_checked_value() {
        // serde keeps the last value; a client reading the first must not
        // see a different, unchecked one.
        let m = Masker::new(&[SECRET]);
        let body = format!(r#"{{"a":"{SECRET}","a":"fine"}}"#);
        let f = fin(&m, Some("application/json"), body.into_bytes(), false).unwrap();
        assert_eq!(&f.body[..], br#"{"a":"fine"}"#);
        let body = br#"{"a":"first","a":"second"}"#.to_vec();
        let f = fin(&m, None, body, false).unwrap();
        assert_eq!(&f.body[..], br#"{"a":"second"}"#);
    }

    #[test]
    fn vault_value_formed_only_by_reserialization_masked() {
        // Neither the raw bytes (space before `:`), the key nor the value
        // holds the secret; the compact serialization `abcd":"wxyz` does.
        let secret = r#"abcd":"wxyz"#;
        let m = Masker::new(&[secret]);
        let body = br#"{"abcd" : "wxyz"}"#.to_vec();
        let f = fin(&m, Some("application/json"), body, false).unwrap();
        assert_eq!(&f.body[..], br#"{"[MASKED]"}"#);
    }

    #[test]
    fn v1_pass_over_whole_serialized_text() {
        // The key `MY_TOKEN=` alone is no hit for the tree pass; over the
        // whole text the v1 `..TOKEN=` rule eats what follows. That breaks
        // the JSON, which is the accepted over-masking.
        let m = Masker::new(&[]);
        let body = br#"{"MY_TOKEN=":918273645}"#.to_vec();
        let f = fin(&m, Some("application/json"), body, false).unwrap();
        assert_eq!(&f.body[..], br#"{"MY_TOKEN=[MASKED]"#);
    }

    #[test]
    fn truncated_json_inside_unicode_escape_does_not_panic() {
        let m = Masker::new(&[SECRET]);
        for tail in ["\\u00", "\\u0", "\\u", "\\", "\\ud83d\\u", "\\ud83d\\ude0"] {
            let body = format!(r#"{{"k":"abc{tail}"#);
            let f = fin(
                &m,
                Some("application/json"),
                body.clone().into_bytes(),
                true,
            )
            .unwrap();
            assert_eq!(&f.body[..], body.as_bytes());
        }
    }

    #[test]
    fn unescape_map_is_compact() {
        // 1 MiB of mixed raw bytes and escapes: the offset map stays at
        // 4 bytes per decoded byte, so at most 4x the body.
        let unit = "ab\\u0041\\/c\\n";
        let mut body = String::new();
        while body.len() < (1 << 20) {
            body.push_str(unit);
        }
        let (decoded, map) = json_unescape(body.as_bytes());
        assert_eq!(map.len(), decoded.len());
        let map_bytes = map.capacity() * std::mem::size_of_val(&map[0]);
        assert!(
            map_bytes <= 4 * body.len(),
            "{map_bytes} > 4 x {}",
            body.len()
        );
        // And the spans still map back exactly.
        assert_eq!(orig_span(&map, body.len(), 2), (2, 8));
        assert_eq!(orig_span(&map, body.len(), 0), (0, 1));
    }

    #[test]
    fn escaped_value_masked_in_truncated_json() {
        // Cut by the reader, so not parseable: the escape-decoded view still
        // finds the value.
        let m = Masker::new(&[SECRET]);
        let hidden = SECRET.replace('/', "\\/").replacen('a', "\\u0061", 1);
        let body = format!(r#"{{"k":"{hidden}","rest":"aaaa"#);
        let f = fin(&m, Some("application/json"), body.into_bytes(), true).unwrap();
        let text = std::str::from_utf8(&f.body).unwrap();
        assert_eq!(text, r#"{"k":"[MASKED]","rest":"aaaa"#);
    }

    #[test]
    fn partial_and_mixed_percent_encoding_masked() {
        let m = Masker::new(&[SECRET]); // shpat_0123456789abcdef/+x?Y
                                        // Python urllib.parse.quote: `/` stays raw.
        assert_eq!(
            masked(&m, "t=shpat_0123456789abcdef/%2Bx%3FY&"),
            "t=[MASKED]&"
        );
        // Mixed-case escapes.
        assert_eq!(masked(&m, "shpat_0123456789abcdef%2f%2bx%3FY"), "[MASKED]");
        // JS encodeURIComponent leaves !'()* raw.
        let js = "a!b'c(d)e*f/g";
        let m = Masker::new(&[js]);
        assert_eq!(masked(&m, "q=a!b'c(d)e*f%2Fg"), "q=[MASKED]");
        // Form encoding: `+` (or %20) for space.
        let sp = "my secret pass";
        let m = Masker::new(&[sp]);
        assert_eq!(masked(&m, "p=my+secret+pass&"), "p=[MASKED]&");
        assert_eq!(masked(&m, "p=my%20secret+pass&"), "p=[MASKED]&");
    }

    #[test]
    fn surrogate_pair_escape_decoded() {
        let v = "key\u{1F600}value";
        let m = Masker::new(&[v]);
        assert_eq!(masked(&m, r#""key\ud83d\ude00value""#), "\"[MASKED]\"");
        // A lone surrogate is left alone, nothing panics.
        assert_eq!(masked(&m, r#""\ud83d x""#), r#""\ud83d x""#);
    }

    #[test]
    fn overlapping_secrets_masked_as_union() {
        let a = "abcdefXYZW";
        let b = "XYZW12345678";
        let m = Masker::new(&[a, b]);
        assert_eq!(masked(&m, "<abcdefXYZW12345678>"), "<[MASKED]>");
        assert_eq!(
            masked(&m, "<XYZW12345678 abcdefXYZW>"),
            "<[MASKED] [MASKED]>"
        );
    }

    #[test]
    fn v1_patterns_run_on_non_utf8_bodies() {
        let m = Masker::new(&[]);
        let gh = format!("ghp_{}", "Q".repeat(36));
        let mut body = vec![0xff, 0xfe, b' '];
        body.extend_from_slice(gh.as_bytes());
        let f = fin(&m, Some("application/octet-stream"), body, false).unwrap();
        let lossy = String::from_utf8_lossy(&f.body);
        assert!(!lossy.contains(&gh), "{lossy}");
        assert!(lossy.contains(MASK));
        // Binary without hits passes through unchanged.
        let bin = vec![0u8, 0xff, 0x80, 7, 9];
        let f = fin(&m, None, bin.clone(), false).unwrap();
        assert_eq!(&f.body[..], &bin[..]);
    }

    #[test]
    fn json_content_type_with_bad_utf8_refused() {
        let m = Masker::new(&[]);
        let bad = b"{\"a\":\"\xff\"}".to_vec();
        let err = fin(&m, Some("application/json; charset=utf-8"), bad, false).unwrap_err();
        assert!(matches!(err, BrokerError::BadResponseEncoding));
        let err = fin(
            &m,
            Some("application/problem+json"),
            vec![0xc3, 0x28],
            false,
        )
        .unwrap_err();
        assert!(matches!(err, BrokerError::BadResponseEncoding));
        // A body the reader cut inside a multi-byte char is not an error.
        let f = fin(
            &m,
            Some("application/json"),
            b"{\"a\":\"\xc3".to_vec(),
            true,
        )
        .unwrap();
        assert!(f.truncated);
    }
}
