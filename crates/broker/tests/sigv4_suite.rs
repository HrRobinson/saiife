//! The SigV4 signer against the AWS signing test suite (vendored from
//! `awslabs/aws-c-auth`, see `fixtures/sigv4/README.md`) and the worked
//! examples of the AWS docs. Offline.

use std::fs;
use std::path::{Path, PathBuf};

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};
use saiife_broker::cloud::sigv4::{
    self, canonical_request, for_service, scope, signing_key, string_to_sign, AwsCreds, SignOpts,
};
use saiife_broker::request::Built;
use sha2::{Digest, Sha256};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};
use zeroize::Zeroizing;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sigv4")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `2015-08-30T12:36:00Z` (the suite's only timestamp form).
fn parse_ts(s: &str) -> OffsetDateTime {
    let n = |r: std::ops::Range<usize>| s[r].parse::<u32>().unwrap();
    let date = Date::from_calendar_date(
        n(0..4) as i32,
        Month::try_from(n(5..7) as u8).unwrap(),
        n(8..10) as u8,
    )
    .unwrap();
    let t = Time::from_hms(n(11..13) as u8, n(14..16) as u8, n(17..19) as u8).unwrap();
    PrimitiveDateTime::new(date, t).assume_utc()
}

struct Case {
    name: String,
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    creds: AwsCreds,
    opts: SignOpts,
    sign_body: bool,
    at: OffsetDateTime,
    dir: PathBuf,
}

impl Case {
    fn file(&self, f: &str) -> String {
        fs::read_to_string(self.dir.join(f)).unwrap()
    }
}

fn load(dir: &Path) -> Case {
    let ctx: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(dir.join("context.json")).unwrap()).unwrap();
    let raw = fs::read(dir.join("request.txt")).unwrap();
    let raw = String::from_utf8(raw).unwrap();
    let (head, body) = match raw.split_once("\n\n") {
        Some((h, b)) => (h.to_string(), b.as_bytes().to_vec()),
        None => (raw.trim_end_matches('\n').to_string(), Vec::new()),
    };
    let mut lines = head.lines();
    let first = lines.next().unwrap();
    let (method, rest) = first.split_once(' ').unwrap();
    let target = rest.strip_suffix(" HTTP/1.1").unwrap();
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let headers = lines
        .map(|l| {
            let (k, v) = l.split_once(':').unwrap();
            (k.to_string(), v.to_string())
        })
        .collect();
    let c = &ctx["credentials"];
    let creds = AwsCreds {
        access_key_id: Zeroizing::new(c["access_key_id"].as_str().unwrap().to_string()),
        secret_access_key: Zeroizing::new(c["secret_access_key"].as_str().unwrap().to_string()),
        session_token: c["token"].as_str().map(|t| Zeroizing::new(t.to_string())),
    };
    let sign_body = ctx["sign_body"].as_bool().unwrap_or(false);
    let normalize = ctx["normalize"].as_bool().unwrap_or(true);
    let opts = SignOpts {
        region: ctx["region"].as_str().unwrap().to_string(),
        service: ctx["service"].as_str().unwrap().to_string(),
        double_encode: true,
        normalize_path: normalize,
        content_sha256_header: sign_body,
        omit_session_token: ctx["omit_session_token"].as_bool().unwrap_or(false),
    };
    Case {
        name: dir.file_name().unwrap().to_string_lossy().into_owned(),
        method: method.to_string(),
        path: path.to_string(),
        query: query.to_string(),
        headers,
        body,
        creds,
        opts,
        sign_body,
        at: parse_ts(ctx["timestamp"].as_str().unwrap()),
        dir: dir.to_path_buf(),
    }
}

fn cases() -> Vec<Case> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(fixtures())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    dirs.iter().map(|d| load(d)).collect()
}

fn amz_date(at: OffsetDateTime) -> String {
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        at.year(),
        at.month() as u8,
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    )
}

/// The `Authorization` line of a signed request file.
fn auth_line(signed: &str) -> String {
    signed
        .lines()
        .find_map(|l| l.strip_prefix("Authorization:"))
        .unwrap()
        .to_string()
}

#[test]
fn aws_suite_vectors() {
    let all = cases();
    assert!(all.len() >= 20, "only {} cases", all.len());
    let mut signed_via_sign = 0;
    for c in &all {
        // The signing headers the signer adds, as the suite expects them.
        let mut headers = c.headers.clone();
        headers.push(("X-Amz-Date".into(), amz_date(c.at)));
        let payload = hex(&Sha256::digest(&c.body));
        if c.sign_body {
            headers.push(("X-Amz-Content-Sha256".into(), payload.clone()));
        }
        if let Some(t) = &c.creds.session_token {
            if !c.opts.omit_session_token {
                headers.push(("X-Amz-Security-Token".into(), t.to_string()));
            }
        }
        let (creq, signed_headers) =
            canonical_request(&c.method, &c.path, &c.query, &headers, &payload, &c.opts);
        assert_eq!(
            creq,
            c.file("header-canonical-request.txt"),
            "{}: canonical request",
            c.name
        );
        assert_eq!(
            signed_headers,
            creq.lines().rev().nth(1).unwrap(),
            "{}: signed headers",
            c.name
        );
        let sc = scope(c.at, &c.opts.region, &c.opts.service);
        let sts = string_to_sign(c.at, &sc, &creq);
        assert_eq!(
            sts,
            c.file("header-string-to-sign.txt"),
            "{}: string to sign",
            c.name
        );
        let key = signing_key(
            &c.creds.secret_access_key,
            &sc[..8],
            &c.opts.region,
            &c.opts.service,
        );
        let sig = hex(ring::hmac::sign(
            &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key),
            sts.as_bytes(),
        )
        .as_ref());
        assert_eq!(sig, c.file("header-signature.txt"), "{}: signature", c.name);

        // The whole signer, where the target is a valid URI as written. A
        // raw non-ASCII path is sent percent-encoded, which AWS then signs
        // double-encoded, so `get-utf8`'s raw form is not what `sign` sends.
        if !c.path.is_ascii() {
            continue;
        }
        let Ok(uri) = format!(
            "https://example.amazonaws.com{}{}{}",
            c.path,
            if c.query.is_empty() { "" } else { "?" },
            c.query
        )
        .parse::<Uri>() else {
            continue;
        };
        let mut hm = HeaderMap::new();
        for (k, v) in &c.headers {
            hm.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v.trim()).unwrap(),
            );
        }
        let mut b = Built {
            method: Method::from_bytes(c.method.as_bytes()).unwrap(),
            uri,
            headers: hm,
            body: (!c.body.is_empty()).then(|| Bytes::from(c.body.clone())),
        };
        sigv4::sign(&mut b, &c.creds, &c.opts, c.at).unwrap();
        assert_eq!(
            b.headers["authorization"].to_str().unwrap(),
            auth_line(&c.file("header-signed-request.txt")),
            "{}: sign()",
            c.name
        );
        signed_via_sign += 1;
    }
    assert!(
        signed_via_sign >= 20,
        "sign() ran on {signed_via_sign} cases"
    );
}

fn docs_secret() -> String {
    concat!("wJalrXUtnFEMI/K7MDENG", "/bPxRfiCYEXAMPLEKEY").to_string()
}

/// The derived-key examples of the AWS docs, both for `us-east-1`/`iam`: the
/// current page ("Create a signed AWS API request", 20150830) and the older
/// one ("Examples of how to derive a signing key", 20120215).
#[test]
fn signing_key_matches_aws_docs_example() {
    let secret = concat!("wJalrXUtnFEMI/K7MDENG", "+bPxRfiCYEXAMPLEKEY");
    assert_eq!(
        hex(&signing_key(secret, "20150830", "us-east-1", "iam")),
        "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
    );
    assert_eq!(
        hex(&signing_key(secret, "20120215", "us-east-1", "iam")),
        "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
    );
}

fn creds(token: Option<&str>) -> AwsCreds {
    AwsCreds {
        access_key_id: Zeroizing::new(concat!("AKIA", "IOSFODNN7EXAMPLE").to_string()),
        secret_access_key: Zeroizing::new(docs_secret()),
        session_token: token.map(|t| Zeroizing::new(t.to_string())),
    }
}

fn built(method: Method, uri: &str) -> Built {
    Built {
        method,
        uri: uri.parse().unwrap(),
        headers: HeaderMap::new(),
        body: None,
    }
}

fn may_24_2013() -> OffsetDateTime {
    PrimitiveDateTime::new(
        Date::from_calendar_date(2013, Month::May, 24).unwrap(),
        Time::MIDNIGHT,
    )
    .assume_utc()
}

/// "Example: GET Object" of the S3 docs page "Signature Calculations for
/// the Authorization Header: Transferring Payload in a Single Chunk".
#[test]
fn s3_get_object_docs_example() {
    let mut b = built(
        Method::GET,
        "https://examplebucket.s3.amazonaws.com/test.txt",
    );
    b.headers
        .insert("range", HeaderValue::from_static("bytes=0-9"));
    let o = for_service("us-east-1", "s3");
    sigv4::sign(&mut b, &creds(None), &o, may_24_2013()).unwrap();
    let want = concat!(
        "AWS4-HMAC-SHA256 Credential=",
        "AKIA",
        "IOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, ",
        "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, ",
        "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    );
    assert_eq!(b.headers["authorization"], want);
    assert_eq!(
        b.headers["x-amz-content-sha256"],
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(b.headers["x-amz-date"], "20130524T000000Z");
    assert_eq!(b.headers["host"], "examplebucket.s3.amazonaws.com");
}

#[test]
fn for_service_rules() {
    let s3 = for_service("eu-west-1", "s3");
    assert!(!s3.double_encode && !s3.normalize_path && s3.content_sha256_header);
    let sts = for_service("eu-west-1", "sts");
    assert!(sts.double_encode && sts.normalize_path && !sts.content_sha256_header);
    assert!(!s3.omit_session_token && !sts.omit_session_token);
    assert_eq!(
        (sts.region.as_str(), sts.service.as_str()),
        ("eu-west-1", "sts")
    );
}

#[test]
fn scope_date_and_amz_date_same_instant() {
    let at = PrimitiveDateTime::new(
        Date::from_calendar_date(2026, Month::October, 28).unwrap(),
        Time::from_hms_milli(23, 59, 59, 900).unwrap(),
    )
    .assume_utc();
    assert_eq!(
        scope(at, "us-east-1", "s3"),
        "20261028/us-east-1/s3/aws4_request"
    );
    let sts = string_to_sign(at, &scope(at, "us-east-1", "s3"), "x");
    assert_eq!(sts.lines().nth(1).unwrap(), "20261028T235959Z");
    let mut b = built(Method::GET, "https://s3.us-east-1.amazonaws.com/b/k");
    sigv4::sign(&mut b, &creds(None), &for_service("us-east-1", "s3"), at).unwrap();
    assert_eq!(b.headers["x-amz-date"], "20261028T235959Z");
    let auth = b.headers["authorization"].to_str().unwrap();
    assert!(
        auth.contains("/20261028/us-east-1/s3/aws4_request,"),
        "{auth}"
    );
}

/// Recomputes the canonical request of a signed request from what will be
/// sent: the URI and the headers named in `SignedHeaders`.
fn resigned(b: &Built, o: &SignOpts) -> (String, String) {
    let auth = b.headers["authorization"].to_str().unwrap().to_string();
    let signed = auth
        .split("SignedHeaders=")
        .nth(1)
        .unwrap()
        .split(',')
        .next()
        .unwrap()
        .to_string();
    let headers: Vec<(String, String)> = signed
        .split(';')
        .flat_map(|n| {
            b.headers
                .get_all(n)
                .iter()
                .map(move |v| (n.to_string(), v.to_str().unwrap().to_string()))
        })
        .collect();
    let payload = hex(&Sha256::digest(b.body.as_deref().unwrap_or_default()));
    let (creq, _) = canonical_request(
        b.method.as_str(),
        b.uri.path(),
        b.uri.query().unwrap_or(""),
        &headers,
        &payload,
        o,
    );
    (creq, auth)
}

#[test]
fn sent_uri_equals_canonical_for_awkward_keys() {
    // The key `a b+c/ü~%=&!*'()`, as the request builder percent-encodes it
    // (and once more with the reserved characters left raw).
    let want = "/bucket/a%20b%2Bc/%C3%BC~%25%3D%26%21%2A%27%28%29";
    for path in [
        "/bucket/a%20b%2Bc/%C3%BC~%25%3D%26%21%2A%27%28%29",
        "/bucket/a%20b+c/%C3%BC%7E%25=&!*'()",
    ] {
        let mut b = built(
            Method::GET,
            &format!("https://s3.us-east-1.amazonaws.com{path}?x-id=GetObject&a=b+c"),
        );
        let o = for_service("us-east-1", "s3");
        sigv4::sign(&mut b, &creds(None), &o, may_24_2013()).unwrap();
        assert_eq!(b.uri.path(), want, "from {path}");
        assert_eq!(b.uri.query(), Some("a=b%2Bc&x-id=GetObject"));
        let (creq, auth) = resigned(&b, &o);
        let mut l = creq.lines();
        assert_eq!(l.next(), Some("GET"));
        assert_eq!(l.next(), Some(want), "the signed URI is the sent URI");
        assert_eq!(l.next(), Some("a=b%2Bc&x-id=GetObject"));
        // And the signature is over exactly that canonical request.
        let sc = scope(may_24_2013(), "us-east-1", "s3");
        let key = signing_key(&docs_secret(), "20130524", "us-east-1", "s3");
        let sig = hex(ring::hmac::sign(
            &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key),
            string_to_sign(may_24_2013(), &sc, &creq).as_bytes(),
        )
        .as_ref());
        assert!(auth.ends_with(&format!("Signature={sig}")), "{auth}");
    }
}

#[test]
fn non_s3_path_is_double_encoded_but_sent_once() {
    let mut b = built(Method::GET, "https://iam.amazonaws.com/a%20b/./c");
    let o = for_service("us-east-1", "iam");
    sigv4::sign(&mut b, &creds(None), &o, may_24_2013()).unwrap();
    assert_eq!(b.uri.path(), "/a%20b/c");
    let (creq, _) = resigned(&b, &o);
    assert_eq!(creq.lines().nth(1), Some("/a%2520b/c"));
}

#[test]
fn existing_signing_headers_replaced() {
    let mut b = built(Method::PUT, "https://s3.us-east-1.amazonaws.com/b/k");
    for (k, v) in [
        ("authorization", "AWS4-HMAC-SHA256 stale"),
        ("x-amz-date", "19990101T000000Z"),
        ("x-amz-security-token", "stale-token"),
        ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
        ("host", "evil.example"),
    ] {
        b.headers.append(k, HeaderValue::from_static(v));
        b.headers.append(k, HeaderValue::from_static(v));
    }
    b.body = Some(Bytes::from_static(b"hello"));
    let o = for_service("us-east-1", "s3");
    sigv4::sign(&mut b, &creds(Some("fresh-token")), &o, may_24_2013()).unwrap();
    for n in [
        "authorization",
        "x-amz-date",
        "x-amz-security-token",
        "x-amz-content-sha256",
        "host",
    ] {
        assert_eq!(b.headers.get_all(n).iter().count(), 1, "{n}");
    }
    assert_eq!(b.headers["host"], "s3.us-east-1.amazonaws.com");
    assert_eq!(b.headers["x-amz-date"], "20130524T000000Z");
    assert_eq!(b.headers["x-amz-security-token"], "fresh-token");
    assert_eq!(
        b.headers["x-amz-content-sha256"],
        hex(&Sha256::digest(b"hello"))
    );
    let auth = b.headers["authorization"].to_str().unwrap();
    assert!(!auth.contains("stale"));
    let (creq, auth) = resigned(&b, &o);
    assert!(!creq.contains("evil") && !creq.contains("stale"));
    assert!(
        auth.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token,"),
        "{auth}"
    );
}

#[test]
fn session_token_signed_unless_omitted() {
    let token = concat!("FQoGZXIvYXdzE", "fake-session-token");
    let mut o = for_service("us-east-1", "sts");
    let mut b = built(Method::POST, "https://sts.us-east-1.amazonaws.com/");
    sigv4::sign(&mut b, &creds(Some(token)), &o, may_24_2013()).unwrap();
    assert_eq!(b.headers["x-amz-security-token"], token);
    let auth = b.headers["authorization"].to_str().unwrap();
    assert!(
        auth.contains("SignedHeaders=host;x-amz-date;x-amz-security-token,"),
        "{auth}"
    );

    o.omit_session_token = true;
    let mut b = built(Method::POST, "https://sts.us-east-1.amazonaws.com/");
    sigv4::sign(&mut b, &creds(Some(token)), &o, may_24_2013()).unwrap();
    assert_eq!(b.headers["x-amz-security-token"], token);
    let auth = b.headers["authorization"].to_str().unwrap();
    assert!(auth.contains("SignedHeaders=host;x-amz-date,"), "{auth}");

    let mut b = built(Method::POST, "https://sts.us-east-1.amazonaws.com/");
    sigv4::sign(&mut b, &creds(None), &o, may_24_2013()).unwrap();
    assert!(b.headers.get("x-amz-security-token").is_none());
}

#[test]
fn debug_hides_creds() {
    let c = creds(Some("the-session-token"));
    let d = format!("{c:?} {:#?}", c);
    assert_eq!(format!("{c:?}"), "AwsCreds{..}");
    assert!(!d.contains("IOSFODNN7EXAMPLE"));
    assert!(!d.contains("EXAMPLEKEY"));
    assert!(!d.contains("the-session-token"));
}

#[test]
fn errors_hold_no_values() {
    use saiife_broker::cloud::CloudError;
    let e = CloudError::Endpoint {
        code: "invalid_grant".into(),
    };
    assert!(e.to_string().contains("invalid_grant"));
    let e = CloudError::Unrepresentable {
        pattern: "s3:read:*".into(),
        why: "a single `*` crosses `/` in IAM",
    };
    assert!(e.to_string().contains("s3:read:*"));
    assert!(!CloudError::TooLarge.to_string().is_empty());
}
