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
//! - percent-encoded (every byte outside the RFC 3986 unreserved set), with
//!   upper- and lower-case hex digits;
//! - hex, lower and upper case;
//! - each of the above as it appears inside a JSON string (`\"`, `\\`,
//!   control characters, and `/` either as-is or as `\/`), when that differs.
//!
//! Matching is Aho-Corasick, leftmost-longest, so a full form wins over a
//! core or a shorter form that is a prefix of it.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use bytes::Bytes;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use percent_encoding::{percent_encode, AsciiSet, NON_ALPHANUMERIC};
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
    forms: usize,
}

impl std::fmt::Debug for Masker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Masker")
            .field("forms", &self.forms)
            .finish()
    }
}

impl Masker {
    pub fn new(values: &[&str]) -> Masker {
        let mut forms: Vec<Zeroizing<Vec<u8>>> = Vec::new();
        for v in values {
            let v = v.as_bytes();
            if v.len() < MIN_VALUE_LEN {
                continue;
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
                AhoCorasickBuilder::new()
                    .match_kind(MatchKind::LeftmostLongest)
                    .build(forms.iter().map(|f| f.as_slice()))
                    .expect("masking automaton builds"),
            )
        };
        Masker {
            ac,
            forms: forms.len(),
        }
    }

    /// Replace every vault form in `b` with `[MASKED]`.
    pub fn mask_bytes(&self, b: &[u8]) -> Vec<u8> {
        let Some(ac) = &self.ac else {
            return b.to_vec();
        };
        let mut out = Vec::with_capacity(b.len());
        let mut last = 0;
        for m in ac.find_iter(b) {
            out.extend_from_slice(&b[last..m.start()]);
            out.extend_from_slice(MASK.as_bytes());
            last = m.end();
        }
        out.extend_from_slice(&b[last..]);
        out
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

/// Mask strings (keys and values) of a JSON tree in place.
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

/// Step 10 of the pipeline. `body` was read up to `max + 64 KiB` (Task 9)
/// and `truncated` says whether more was available. Order:
/// 1. mask the bytes (vault forms; v1 patterns too when the body is UTF-8),
/// 2. with `redact` set: parse JSON (not JSON → `RedactNonJson`), redact,
///    mask every string, re-serialize,
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
    let headers = mask_headers(&headers, masker);
    let mut redacted = 0;
    let mut out: Vec<u8> = if redact.is_empty() {
        let masked = masker.mask_bytes(&body);
        match String::from_utf8(masked) {
            Ok(s) => saiife_audit::mask::mask(&s).into_bytes(),
            Err(e) => e.into_bytes(),
        }
    } else {
        let masked = masker.mask_bytes(&body);
        let mut v: serde_json::Value =
            serde_json::from_slice(&masked).map_err(|_| BrokerError::RedactNonJson)?;
        redacted = crate::redact::redact(&mut v, redact);
        mask_json_strings(&mut v, masker);
        serde_json::to_vec(&v).map_err(|_| BrokerError::RedactNonJson)?
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
    fn redact_masks_values_hidden_by_json_escapes() {
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
}
