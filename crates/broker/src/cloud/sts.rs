//! AWS STS `AssumeRole` (decisions 8, 11 and 13): the Query API request, a
//! strict reader for its XML answer, and the signed call.
//!
//! The answer is read with a minimal tag extractor, not an XML library: it
//! takes the four `Credentials` fields and `Error/Code`, each at most once,
//! unescapes the five predefined XML entities and refuses everything else
//! XML could carry (a DTD, entity declarations, comments, CDATA, processing
//! instructions, numeric character references, mixed content, unbalanced
//! tags). The answer is at most [`MAX_RESPONSE`] bytes.
//!
//! Errors keep only the sanitized AWS error code (decision 18): a `Message`
//! is never read, and no error names a credential value.

use bytes::Bytes;
use http::header::{ACCEPT_ENCODING, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue, Method, Uri};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use ring::rand::{SecureRandom, SystemRandom};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};
use zeroize::{Zeroize, Zeroizing};

use super::sigv4::{for_service, sign, AwsCreds};
use super::CloudError;
use crate::request::Built;
use crate::upstream::Upstream;

/// The STS Query API version.
pub const VERSION: &str = "2011-06-15";
/// The most of an STS answer read (decision 7).
pub const MAX_RESPONSE: usize = 64 * 1024;
/// A `run --cloud` lease: the AWS minimum and the spec's maximum
/// (decision 11).
pub const LEASE_SECONDS: u32 = 900;
/// The deepest element nesting accepted in an answer.
const MAX_DEPTH: usize = 16;
/// The longest session token accepted.
const MAX_TOKEN: usize = 16 * 1024;

/// One `AssumeRole` call. `policy` is an inline session policy
/// ([`super::session_policy`]); without one the session has the role's
/// permissions (sign mode, decision 8).
#[derive(Debug, Clone)]
pub struct AssumeRole<'a> {
    pub role_arn: &'a str,
    pub session_name: String,
    pub duration_s: u32,
    pub policy: Option<&'a str>,
    pub external_id: Option<&'a str>,
}

/// `saiife-<uid>-<8 hex>`, the hex from the system CSPRNG.
pub fn session_name(uid: u32) -> String {
    let mut r = [0u8; 4];
    // The system RNG does not fail on Linux; a zero suffix only makes the
    // name less unique, never less safe.
    let _ = SystemRandom::new().fill(&mut r);
    format!("saiife-{uid}-{:08x}", u32::from_be_bytes(r))
}

/// RFC 3986 unreserved characters stay; everything else is encoded.
const FORM: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

fn bad(why: &str) -> CloudError {
    CloudError::Key(format!("AssumeRole: {why}"))
}

fn resp(why: &str) -> CloudError {
    CloudError::Response(format!("STS: {why}"))
}

/// `[a-z0-9]+(-[a-z0-9]+)*`, at most 32 bytes.
fn valid_region(r: &str) -> bool {
    (1..=32).contains(&r.len())
        && !r.starts_with('-')
        && !r.ends_with('-')
        && !r.contains("--")
        && r.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `[\w+=,.@-]{2,64}`.
fn valid_session_name(s: &str) -> bool {
    (2..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_+=,.@-".contains(&b))
}

/// The STS Query API `AssumeRole` call: a form POST to
/// `https://sts.{region}.amazonaws.com/`, not yet signed.
pub fn assume_role_request(region: &str, p: &AssumeRole<'_>) -> Result<Built, CloudError> {
    if !valid_region(region) {
        return Err(bad("the region must be [a-z0-9-]{1,32}"));
    }
    if !saiife_policy::valid_role_arn(p.role_arn) {
        return Err(bad("role_arn is not an IAM role ARN"));
    }
    if !valid_session_name(&p.session_name) {
        return Err(bad("the session name must be [A-Za-z0-9_+=,.@-]{2,64}"));
    }
    if !(900..=43_200).contains(&p.duration_s) {
        return Err(bad("DurationSeconds must be 900 to 43200"));
    }
    if let Some(pol) = p.policy {
        let ok = (1..=super::session_policy::MAX_POLICY).contains(&pol.len())
            && pol.bytes().all(|b| (0x20..0x7f).contains(&b));
        if !ok {
            return Err(bad(
                "the session policy must be 1 to 2048 printable ASCII bytes",
            ));
        }
    }
    if let Some(e) = p.external_id {
        if !saiife_policy::valid_external_id(e) {
            return Err(bad("external_id must be [A-Za-z0-9+=,.@:/_-]{2,1224}"));
        }
    }
    let uri: Uri = format!("https://sts.{region}.amazonaws.com/")
        .parse()
        .map_err(|_| bad("the endpoint URL does not parse"))?;
    let duration = p.duration_s.to_string();
    let mut fields: Vec<(&str, &str)> = vec![
        ("Action", "AssumeRole"),
        ("DurationSeconds", &duration),
        ("RoleArn", p.role_arn),
        ("RoleSessionName", &p.session_name),
        ("Version", VERSION),
    ];
    if let Some(e) = p.external_id {
        fields.push(("ExternalId", e));
    }
    if let Some(pol) = p.policy {
        fields.push(("Policy", pol));
    }
    fields.sort_by(|a, b| a.0.cmp(b.0));
    let mut body = String::new();
    for (k, v) in fields {
        if !body.is_empty() {
            body.push('&');
        }
        body.push_str(k);
        body.push('=');
        body.extend(utf8_percent_encode(v, FORM));
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded; charset=utf-8"),
    );
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
    Ok(Built {
        method: Method::POST,
        uri,
        headers,
        body: Some(Bytes::from(body)),
    })
}

// ------------------------------------------------------------- the answer

const CRED_PATH: [&str; 3] = ["AssumeRoleResponse", "AssumeRoleResult", "Credentials"];
const ERROR_PATH: [&str; 2] = ["ErrorResponse", "Error"];
const FIELDS: [&str; 4] = [
    "AccessKeyId",
    "SecretAccessKey",
    "SessionToken",
    "Expiration",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Want {
    Field(usize),
    Code,
}

struct Frame<'s> {
    name: &'s str,
    want: Option<Want>,
    text: Zeroizing<String>,
    has_child: bool,
    has_text: bool,
}

#[derive(Default)]
struct Extract {
    fields: [Option<Zeroizing<String>>; 4],
    code: Option<Zeroizing<String>>,
}

fn name_byte(b: u8, first: bool) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || (!first && (b.is_ascii_digit() || b"-.:".contains(&b)))
}

/// An element name at `i`; returns it and the index after it.
fn name_at(s: &str, i: usize) -> Result<(&str, usize), CloudError> {
    let b = s.as_bytes();
    let mut j = i;
    while j < b.len() && name_byte(b[j], j == i) {
        j += 1;
    }
    if j == i {
        return Err(resp("a malformed tag"));
    }
    Ok((&s[i..j], j))
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    i
}

/// Checks `raw` for entities, unescaping the five predefined ones into
/// `out` when given. Any other `&` is refused.
fn unescape(raw: &str, mut out: Option<&mut String>) -> Result<(), CloudError> {
    let mut rest = raw;
    while let Some(k) = rest.find('&') {
        if let Some(o) = out.as_deref_mut() {
            o.push_str(&rest[..k]);
        }
        let after = &rest[k + 1..];
        let end = after
            .find(';')
            .filter(|&e| e <= 4)
            .ok_or_else(|| resp("an XML entity other than the five predefined ones"))?;
        let c = match &after[..end] {
            "lt" => '<',
            "gt" => '>',
            "amp" => '&',
            "quot" => '"',
            "apos" => '\'',
            _ => return Err(resp("an XML entity other than the five predefined ones")),
        };
        if let Some(o) = out.as_deref_mut() {
            o.push(c);
        }
        rest = &after[end + 1..];
    }
    if let Some(o) = out {
        o.push_str(rest);
    }
    Ok(())
}

fn want_for(stack: &[Frame<'_>], name: &str) -> Option<Want> {
    let path: Vec<&str> = stack.iter().map(|f| f.name).collect();
    if path == CRED_PATH {
        FIELDS.iter().position(|f| *f == name).map(Want::Field)
    } else if path == ERROR_PATH && name == "Code" {
        Some(Want::Code)
    } else {
        None
    }
}

fn close(f: Frame<'_>, x: &mut Extract) -> Result<(), CloudError> {
    let Some(w) = f.want else {
        return Ok(());
    };
    if f.has_child {
        return Err(resp("a credential field holds elements"));
    }
    let v = Zeroizing::new(f.text.trim_matches([' ', '\t', '\r', '\n']).to_string());
    let slot = match w {
        Want::Field(i) => &mut x.fields[i],
        Want::Code => &mut x.code,
    };
    if slot.is_some() {
        return Err(resp("a credential field or the error code appears twice"));
    }
    *slot = Some(v);
    Ok(())
}

/// The strict tag extractor of decision 13.
fn extract(body: &[u8]) -> Result<Extract, CloudError> {
    if body.len() > MAX_RESPONSE {
        return Err(CloudError::TooLarge);
    }
    let s = std::str::from_utf8(body).map_err(|_| resp("the answer is not UTF-8"))?;
    let b = s.as_bytes();
    let mut i = 0;
    if s.starts_with("<?xml") && s.as_bytes().get(5).is_some_and(|c| c.is_ascii_whitespace()) {
        let end = s
            .find("?>")
            .ok_or_else(|| resp("an unterminated XML declaration"))?;
        if s[1..end].contains('<') {
            return Err(resp("a malformed XML declaration"));
        }
        i = end + 2;
    }
    let mut x = Extract::default();
    let mut stack: Vec<Frame<'_>> = Vec::new();
    let mut root_done = false;
    let mut credentials = 0;
    while i < b.len() {
        if b[i] != b'<' {
            let end = s[i..].find('<').map_or(b.len(), |k| i + k);
            let raw = &s[i..end];
            let blank = raw
                .bytes()
                .all(|c| matches!(c, b' ' | b'\t' | b'\r' | b'\n'));
            match stack.last_mut() {
                None if blank => {}
                None => return Err(resp("text outside the root element")),
                Some(f) => {
                    if !blank {
                        if f.has_child {
                            return Err(resp("mixed content"));
                        }
                        f.has_text = true;
                    }
                    if f.want.is_some() && f.text.capacity() - f.text.len() < raw.len() {
                        // Unescaping never lengthens text, so with room for
                        // `raw` the buffer never reallocates; the old one is
                        // wiped when its `Zeroizing` drops.
                        let mut n = Zeroizing::new(String::with_capacity(f.text.len() + raw.len()));
                        n.push_str(&f.text);
                        f.text = n;
                    }
                    let out: Option<&mut String> = f.want.is_some().then_some(&mut *f.text);
                    unescape(raw, out)?;
                }
            }
            i = end;
            continue;
        }
        match b.get(i + 1) {
            Some(b'?') | Some(b'!') => {
                return Err(resp(
                    "a DTD, entity declaration, comment, CDATA section or processing instruction",
                ))
            }
            Some(b'/') => {
                let (name, j) = name_at(s, i + 2)?;
                let j = skip_ws(b, j);
                if b.get(j) != Some(&b'>') {
                    return Err(resp("a malformed end tag"));
                }
                let f = stack.pop().ok_or_else(|| resp("an unbalanced end tag"))?;
                if f.name != name {
                    return Err(resp("an unbalanced end tag"));
                }
                close(f, &mut x)?;
                if stack.is_empty() {
                    root_done = true;
                }
                i = j + 1;
            }
            _ => {
                if root_done {
                    return Err(resp("more than one root element"));
                }
                let (name, mut j) = name_at(s, i + 1)?;
                // Attributes: ws name ws? = ws? quoted value.
                let self_closing = loop {
                    let k = skip_ws(b, j);
                    match b.get(k) {
                        Some(b'>') => {
                            j = k + 1;
                            break false;
                        }
                        Some(b'/') if b.get(k + 1) == Some(&b'>') => {
                            j = k + 2;
                            break true;
                        }
                        Some(_) if k > j => {
                            let (_, a) = name_at(s, k)?;
                            let a = skip_ws(b, a);
                            if b.get(a) != Some(&b'=') {
                                return Err(resp("a malformed attribute"));
                            }
                            let q = skip_ws(b, a + 1);
                            let quote = match b.get(q) {
                                Some(c @ (b'"' | b'\'')) => *c,
                                _ => return Err(resp("a malformed attribute")),
                            };
                            let len = s[q + 1..]
                                .find(quote as char)
                                .ok_or_else(|| resp("a malformed attribute"))?;
                            let v = &s[q + 1..q + 1 + len];
                            if v.contains('<') {
                                return Err(resp("a malformed attribute"));
                            }
                            unescape(v, None)?;
                            j = q + 1 + len + 1;
                        }
                        _ => return Err(resp("a malformed tag")),
                    }
                };
                if let Some(p) = stack.last_mut() {
                    if p.has_text {
                        return Err(resp("mixed content"));
                    }
                    p.has_child = true;
                }
                if stack.len() >= MAX_DEPTH {
                    return Err(resp("elements nested too deeply"));
                }
                let want = want_for(&stack, name);
                if name == "Credentials"
                    && stack
                        .iter()
                        .map(|f| f.name)
                        .eq(CRED_PATH[..2].iter().copied())
                {
                    credentials += 1;
                    if credentials > 1 {
                        return Err(resp("Credentials appears twice"));
                    }
                }
                let f = Frame {
                    name,
                    want,
                    text: Zeroizing::new(String::new()),
                    has_child: false,
                    has_text: false,
                };
                if self_closing {
                    close(f, &mut x)?;
                    if stack.is_empty() {
                        root_done = true;
                    }
                } else {
                    stack.push(f);
                }
                i = j;
            }
        }
    }
    if !root_done || !stack.is_empty() {
        return Err(resp("the answer ends inside an element"));
    }
    Ok(x)
}

/// The error code as recorded: `[A-Za-z0-9_.]{1,64}`, else `unknown`.
fn sanitize_code(c: &str) -> String {
    let ok = (1..=64).contains(&c.len())
        && c.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.');
    if ok {
        c.to_string()
    } else {
        "unknown".to_string()
    }
}

fn digits(s: &str, n: usize) -> Option<u32> {
    (s.len() == n && s.bytes().all(|b| b.is_ascii_digit()))
        .then(|| s.parse().ok())
        .flatten()
}

/// `YYYY-MM-DDTHH:MM:SS[.fraction]Z`, as STS writes `Expiration`.
fn parse_expiration(s: &str) -> Option<OffsetDateTime> {
    let s = s.strip_suffix('Z')?;
    let (date, clock) = s.split_once('T')?;
    let mut d = date.split('-');
    let (y, mo, da) = (d.next()?, d.next()?, d.next()?);
    if d.next().is_some() {
        return None;
    }
    let clock = match clock.split_once('.') {
        Some((c, frac)) => {
            if frac.is_empty() || frac.len() > 9 || !frac.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            c
        }
        None => clock,
    };
    let mut c = clock.split(':');
    let (h, mi, se) = (c.next()?, c.next()?, c.next()?);
    if c.next().is_some() {
        return None;
    }
    let date = Date::from_calendar_date(
        digits(y, 4)? as i32,
        Month::try_from(digits(mo, 2)? as u8).ok()?,
        digits(da, 2)? as u8,
    )
    .ok()?;
    let t = Time::from_hms(
        digits(h, 2)? as u8,
        digits(mi, 2)? as u8,
        digits(se, 2)? as u8,
    )
    .ok()?;
    Some(PrimitiveDateTime::new(date, t).assume_utc())
}

/// Reads an `AssumeRole` answer (decision 13). A non-200 answer is
/// [`CloudError::Endpoint`] with its sanitized `Error/Code`; a 200 answer
/// must hold each `Credentials` field exactly once.
pub fn parse_assume_role(
    status: u16,
    body: &[u8],
) -> Result<(AwsCreds, OffsetDateTime), CloudError> {
    if body.len() > MAX_RESPONSE {
        return Err(CloudError::TooLarge);
    }
    if status != 200 {
        let code = extract(body).ok().and_then(|x| x.code);
        return match code {
            Some(c) => Err(CloudError::Endpoint {
                code: sanitize_code(&c),
            }),
            None => Err(resp(&format!("HTTP {status} without an error code"))),
        };
    }
    let x = extract(body)?;
    let [ak, sk, tok, exp] = x.fields;
    let missing = |i: usize| resp(&format!("the answer has no Credentials/{}", FIELDS[i]));
    let ak = ak.ok_or_else(|| missing(0))?;
    let sk = sk.ok_or_else(|| missing(1))?;
    let tok = tok.ok_or_else(|| missing(2))?;
    let exp = exp.ok_or_else(|| missing(3))?;
    if !(16..=128).contains(&ak.len())
        || !ak
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        return Err(resp("AccessKeyId is not an access key id"));
    }
    if !(1..=256).contains(&sk.len()) || !sk.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(resp("SecretAccessKey is not usable"));
    }
    if !(1..=MAX_TOKEN).contains(&tok.len()) || !tok.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(resp("SessionToken is not usable"));
    }
    let exp = parse_expiration(&exp).ok_or_else(|| resp("Expiration is not a UTC timestamp"))?;
    Ok((
        AwsCreds {
            access_key_id: ak,
            secret_access_key: sk,
            session_token: Some(tok),
        },
        exp,
    ))
}

/// Wipes a body that held credentials, when nothing else shares it.
fn wipe(b: Bytes) {
    if let Ok(mut m) = b.try_into_mut() {
        m.as_mut().zeroize();
    }
}

/// Calls `AssumeRole` with `base`, signed for `sts` in `region`. The
/// expiry is the earlier of the answer's `Expiration` and
/// `now + duration_s`; an answer already expired is refused.
pub async fn assume(
    up: &Upstream,
    base: &AwsCreds,
    region: &str,
    p: &AssumeRole<'_>,
    now: OffsetDateTime,
) -> Result<(AwsCreds, OffsetDateTime), CloudError> {
    let mut b = assume_role_request(region, p)?;
    sign(&mut b, base, &for_service(region, "sts"), now)?;
    let r = up.send(b, MAX_RESPONSE).await?;
    if r.truncated {
        wipe(r.body);
        return Err(CloudError::TooLarge);
    }
    let parsed = parse_assume_role(r.status, &r.body);
    wipe(r.body);
    let (creds, exp) = parsed?;
    let cap = now + time::Duration::seconds(i64::from(p.duration_s));
    let exp = exp.min(cap);
    if exp <= now {
        return Err(resp("the credentials are already expired"));
    }
    Ok((creds, exp))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiration_forms() {
        assert!(parse_expiration("2019-11-09T13:34:41Z").is_some());
        assert!(parse_expiration("2011-07-15T23:28:33.359Z").is_some());
        for bad in [
            "2019-11-09T13:34:41",
            "2019-11-09 13:34:41Z",
            "2019-13-09T13:34:41Z",
            "19-11-09T13:34:41Z",
            "2019-11-09T13:34:41.Z",
            "2019-11-09T13:34:41+00:00",
        ] {
            assert!(parse_expiration(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn session_names() {
        let a = session_name(1000);
        assert!(a.starts_with("saiife-1000-"), "{a}");
        assert_eq!(a.len(), "saiife-1000-".len() + 8);
        assert!(valid_session_name(&a));
        assert!(valid_session_name(&session_name(u32::MAX)));
    }

    #[test]
    fn codes_sanitized() {
        assert_eq!(sanitize_code("AccessDenied"), "AccessDenied");
        assert_eq!(sanitize_code("a b"), "unknown");
        assert_eq!(sanitize_code(""), "unknown");
        assert_eq!(sanitize_code(&"x".repeat(65)), "unknown");
    }

    #[test]
    fn regions() {
        assert!(valid_region("us-east-1"));
        for bad in ["", "US-east-1", "us_east", "-us", "us-", "a.b", "x/y"] {
            assert!(!valid_region(bad), "{bad}");
        }
    }
}
