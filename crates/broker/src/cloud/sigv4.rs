//! AWS Signature Version 4, header signing: pure and sync.
//!
//! The rules are those of the AWS SigV4 docs, pinned by the AWS signing test
//! suite in `tests/fixtures/sigv4/` (decision 14). Per decision 4, the
//! service name picks the variant: `s3` has no double encoding, no path
//! normalization and an `x-amz-content-sha256` header; every other service
//! double-encodes and normalizes, with no content header.
//!
//! [`sign`] rewrites the request URI into its AWS `UriEncode` form first, so
//! what is signed is what is sent, and it signs every header present.

use http::header::{HeaderName, HeaderValue, AUTHORIZATION, HOST};
use http::Uri;
use ring::hmac;
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, UtcOffset};
use zeroize::Zeroizing;

use super::CloudError;
use crate::request::Built;
use crate::BrokerError;

const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const X_AMZ_DATE: &str = "x-amz-date";
const X_AMZ_TOKEN: &str = "x-amz-security-token";
const X_AMZ_SHA256: &str = "x-amz-content-sha256";

/// AWS keys from the vault, or session credentials from STS.
#[derive(Clone)]
pub struct AwsCreds {
    pub access_key_id: Zeroizing<String>,
    pub secret_access_key: Zeroizing<String>,
    pub session_token: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for AwsCreds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AwsCreds{..}")
    }
}

/// How to sign for one region and service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignOpts {
    pub region: String,
    pub service: String,
    /// URI-encode the (already encoded) path once more in the canonical
    /// request.
    pub double_encode: bool,
    /// Remove `.`, `..` and empty segments from the path.
    pub normalize_path: bool,
    /// Send and sign `x-amz-content-sha256`.
    pub content_sha256_header: bool,
    /// Add `x-amz-security-token` after signing instead of signing it.
    pub omit_session_token: bool,
}

/// The rules of decision 4, chosen by the service name.
pub fn for_service(region: &str, service: &str) -> SignOpts {
    let s3 = service == "s3";
    SignOpts {
        region: region.to_string(),
        service: service.to_string(),
        double_encode: !s3,
        normalize_path: !s3,
        content_sha256_header: s3,
        omit_session_token: false,
    }
}

fn hex(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(D[usize::from(x >> 4)] as char);
        s.push(D[usize::from(x & 15)] as char);
    }
    s
}

fn sha256_hex(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

/// AWS `UriEncode`: every byte but `A-Za-z0-9-._~` (and `/` when
/// `keep_slash`) becomes `%XX`, upper-case.
fn uri_encode(s: &[u8], keep_slash: bool) -> String {
    const H: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &c in s {
        if c.is_ascii_alphanumeric()
            || matches!(c, b'-' | b'.' | b'_' | b'~')
            || (keep_slash && c == b'/')
        {
            out.push(c as char);
        } else {
            out.push('%');
            out.push(H[usize::from(c >> 4)] as char);
            out.push(H[usize::from(c & 15)] as char);
        }
    }
    out
}

/// Percent-decoding; `+` stays a `+`.
fn decode(s: &str) -> Vec<u8> {
    percent_encoding::percent_decode_str(s).collect()
}

/// RFC 3986 dot-segment removal, with empty segments dropped as well (the
/// suite's `get-slashes-normalized`). A trailing `/` is kept.
fn normalize(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    let mut p = format!("/{}", out.join("/"));
    if p.len() > 1 && path.ends_with('/') {
        p.push('/');
    }
    p
}

/// The canonical query string: each pair decoded then `UriEncode`d, a
/// missing `=` read as an empty value, sorted by key then value.
fn canonical_query(query: &str) -> String {
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (uri_encode(&decode(k), false), uri_encode(&decode(v), false))
        })
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// A header value as signed: trimmed, runs of spaces and tabs collapsed.
fn canonical_value(v: &str) -> String {
    v.split([' ', '\t'])
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The canonical request and its signed-header list.
///
/// `path` and `query` are the request target as sent: with `double_encode`
/// the path is `UriEncode`d once more, without it the path is taken as is
/// (and [`sign`] has already encoded it). Every header given is signed;
/// repeated names are joined with `,` in order.
pub fn canonical_request(
    method: &str,
    path: &str,
    query: &str,
    headers: &[(String, String)],
    payload_sha256_hex: &str,
    o: &SignOpts,
) -> (String, String) {
    let path = if path.is_empty() { "/" } else { path };
    let path = if o.normalize_path {
        normalize(path)
    } else {
        path.to_string()
    };
    let path = if o.double_encode {
        uri_encode(path.as_bytes(), true)
    } else {
        path
    };

    let mut hs: Vec<(String, String)> = Vec::new();
    let mut sorted: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), canonical_value(v)))
        .collect();
    // A stable sort keeps the order of repeated names.
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for (k, v) in sorted {
        match hs.last_mut() {
            Some((lk, lv)) if *lk == k => {
                lv.push(',');
                lv.push_str(&v);
            }
            _ => hs.push((k, v)),
        }
    }
    let signed = hs
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let mut creq = format!("{method}\n{path}\n{}\n", canonical_query(query));
    for (k, v) in &hs {
        creq.push_str(k);
        creq.push(':');
        creq.push_str(v);
        creq.push('\n');
    }
    creq.push('\n');
    creq.push_str(&signed);
    creq.push('\n');
    creq.push_str(payload_sha256_hex);
    (creq, signed)
}

/// `YYYYMMDD'T'HHMMSS'Z'` and `YYYYMMDD`, both from the same instant.
fn stamps(at: OffsetDateTime) -> (String, String) {
    let t = at.to_offset(UtcOffset::UTC);
    let date = format!("{:04}{:02}{:02}", t.year(), u8::from(t.month()), t.day());
    let full = format!("{date}T{:02}{:02}{:02}Z", t.hour(), t.minute(), t.second());
    (full, date)
}

/// `date/region/service/aws4_request`.
pub fn scope(at: OffsetDateTime, region: &str, service: &str) -> String {
    format!("{}/{region}/{service}/aws4_request", stamps(at).1)
}

pub fn string_to_sign(at: OffsetDateTime, scope: &str, creq: &str) -> String {
    format!(
        "{ALGORITHM}\n{}\n{scope}\n{}",
        stamps(at).0,
        sha256_hex(creq.as_bytes())
    )
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// The derived key: `HMAC(HMAC(HMAC(HMAC("AWS4" + secret, date), region),
/// service), "aws4_request")`.
pub fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> [u8; 32] {
    let k0 = Zeroizing::new(format!("AWS4{secret}"));
    let k = hmac_sha256(k0.as_bytes(), date.as_bytes());
    let k = hmac_sha256(&k, region.as_bytes());
    let k = hmac_sha256(&k, service.as_bytes());
    hmac_sha256(&k, b"aws4_request")
}

fn bad(what: &str) -> CloudError {
    CloudError::Transport(BrokerError::Upstream(format!("cannot sign: {what}")))
}

fn header(v: &str) -> Result<HeaderValue, CloudError> {
    HeaderValue::from_str(v).map_err(|_| bad("a signing header is not visible ASCII"))
}

/// The path as sent: each segment decoded and `UriEncode`d (so `%2F` inside
/// a segment stays one segment), then normalized when the service wants it.
fn wire_path(path: &str, o: &SignOpts) -> String {
    let p = path
        .split('/')
        .map(|seg| uri_encode(&decode(seg), false))
        .collect::<Vec<_>>()
        .join("/");
    let p = if p.is_empty() { "/".to_string() } else { p };
    if o.normalize_path {
        normalize(&p)
    } else {
        p
    }
}

/// Signs `b` in place at `at`.
///
/// The URI is rewritten into the canonical encoding (path segments and a
/// sorted query, `+` sent as `%2B`). `host` (the authority the upstream
/// client sends), `x-amz-date`, `x-amz-security-token`,
/// `x-amz-content-sha256` (when the service wants it) and `authorization`
/// are set or replaced. Every other header present is signed as well.
pub fn sign(
    b: &mut Built,
    c: &AwsCreds,
    o: &SignOpts,
    at: OffsetDateTime,
) -> Result<(), CloudError> {
    let scheme = b
        .uri
        .scheme_str()
        .ok_or_else(|| bad("the URL has no scheme"))?;
    let authority = b
        .uri
        .authority()
        .ok_or_else(|| bad("the URL has no host"))?
        .as_str()
        .to_string();
    let path = wire_path(b.uri.path(), o);
    let query = canonical_query(b.uri.query().unwrap_or(""));
    let target = if query.is_empty() {
        format!("{scheme}://{authority}{path}")
    } else {
        format!("{scheme}://{authority}{path}?{query}")
    };
    b.uri = target
        .parse::<Uri>()
        .map_err(|_| bad("the canonical URI does not parse"))?;

    let (amz_date, date) = stamps(at);
    let payload = sha256_hex(b.body.as_deref().unwrap_or_default());
    for n in [
        AUTHORIZATION.as_str(),
        HOST.as_str(),
        X_AMZ_DATE,
        X_AMZ_TOKEN,
        X_AMZ_SHA256,
    ] {
        b.headers.remove(n);
    }
    b.headers.insert(HOST, header(&authority)?);
    b.headers
        .insert(HeaderName::from_static(X_AMZ_DATE), header(&amz_date)?);
    if o.content_sha256_header {
        b.headers
            .insert(HeaderName::from_static(X_AMZ_SHA256), header(&payload)?);
    }
    let token = match &c.session_token {
        Some(t) => {
            let mut v = HeaderValue::from_str(t)
                .map_err(|_| bad("the session token is not visible ASCII"))?;
            v.set_sensitive(true);
            Some(v)
        }
        None => None,
    };
    if let (Some(t), false) = (&token, o.omit_session_token) {
        b.headers
            .insert(HeaderName::from_static(X_AMZ_TOKEN), t.clone());
    }

    let mut hs = Vec::with_capacity(b.headers.len());
    for (k, v) in &b.headers {
        let v = v
            .to_str()
            .map_err(|_| bad("a header value is not visible ASCII"))?;
        hs.push((k.as_str().to_string(), v.to_string()));
    }
    let (creq, signed) = canonical_request(
        b.method.as_str(),
        b.uri.path(),
        b.uri.query().unwrap_or(""),
        &hs,
        &payload,
        o,
    );
    let sc = format!("{date}/{}/{}/aws4_request", o.region, o.service);
    let sts = string_to_sign(at, &sc, &creq);
    let key = Zeroizing::new(signing_key(
        &c.secret_access_key,
        &date,
        &o.region,
        &o.service,
    ));
    let sig = hex(&hmac_sha256(&key[..], sts.as_bytes()));
    let auth = Zeroizing::new(format!(
        "{ALGORITHM} Credential={}/{sc}, SignedHeaders={signed}, Signature={sig}",
        c.access_key_id.as_str()
    ));
    let mut auth = header(&auth)?;
    auth.set_sensitive(true);
    b.headers.insert(AUTHORIZATION, auth);
    if let (Some(t), true) = (token, o.omit_session_token) {
        b.headers.insert(HeaderName::from_static(X_AMZ_TOKEN), t);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_cases() {
        assert_eq!(normalize("/"), "/");
        assert_eq!(normalize("//"), "/");
        assert_eq!(normalize("//example//"), "/example/");
        assert_eq!(normalize("/example1/example2/../.."), "/");
        assert_eq!(normalize("/./example"), "/example");
        assert_eq!(normalize("/a/../b"), "/b");
    }

    #[test]
    fn query_plus_is_literal() {
        assert_eq!(canonical_query("b=2&a=x+y&c"), "a=x%2By&b=2&c=");
    }
}
