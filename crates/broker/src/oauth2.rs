//! OAuth2 refresh (decision 8), the pure half: the token request and the
//! token response. The daemon sends the request and keeps the access token
//! in memory (`saiife_daemon::oauth`); nothing here touches the network.
//!
//! The token endpoint is `https://<base URL host><token_path>`, so it is
//! pinned to the admin's host like every other request (`checked_uri`). A
//! response naming another instance is refused.

use crate::manifest::{AuthSpec, Manifest};
use crate::request::{checked_uri, fill_base, Built};
use crate::BrokerError;
use bytes::Bytes;
use http::header::{ACCEPT, ACCEPT_ENCODING, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue, Method, Uri};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use std::collections::BTreeMap;
use std::time::Duration;
use zeroize::Zeroizing;

/// The vault fields of an `oauth2` secret.
pub const FIELDS: [&str; 3] = ["client_id", "client_secret", "refresh_token"];
/// How long an access token is used when the response has no `expires_in`.
pub const DEFAULT_TTL: Duration = Duration::from_secs(15 * 60);
/// A token is refreshed this long before it expires.
pub const EARLY: Duration = Duration::from_secs(60);
/// The longest `expires_in` believed.
const MAX_TTL: Duration = Duration::from_secs(24 * 3600);
/// The most of a token response read.
pub const MAX_RESPONSE: usize = 64 * 1024;
/// The longest token accepted.
const MAX_TOKEN: usize = 8 * 1024;

/// A token response. `Debug` shows neither token.
pub struct Token {
    pub access: Zeroizing<String>,
    /// A rotated refresh token, when the response carries one.
    pub refresh: Option<Zeroizing<String>>,
    pub ttl: Duration,
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Token")
            .field("access_len", &self.access.len())
            .field("refresh", &self.refresh.is_some())
            .field("ttl", &self.ttl)
            .finish()
    }
}

/// Why a refresh failed; [`RefreshError::reason`] is the record's `reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshError {
    /// The token endpoint answered with this status.
    Http(u16),
    /// No answer (connect, TLS, timeout).
    Network,
    /// An answer that is not a usable token.
    BadResponse,
    /// `instance_url` names another host.
    InstanceMismatch,
    /// The rotated refresh token could not be written to the vault.
    Persist,
}

impl RefreshError {
    pub fn reason(&self) -> String {
        match self {
            RefreshError::Http(s) => format!("http_{s}"),
            RefreshError::Network => "network".into(),
            RefreshError::BadResponse => "bad_response".into(),
            RefreshError::InstanceMismatch => "instance_mismatch".into(),
            RefreshError::Persist => "persist".into(),
        }
    }
}

/// RFC 3986 unreserved characters stay; everything else is encoded.
const FORM: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// The refresh request: `POST https://<host><token_path>` with the form
/// `grant_type=refresh_token&client_id&client_secret&refresh_token`. The
/// host is the base URL's, checked against the manifest's `hosts`. `Debug`
/// of the result never shows the body ([`Built`]).
pub fn token_request(
    spec: &AuthSpec,
    m: &Manifest,
    svc_params: &BTreeMap<String, String>,
    fields: &BTreeMap<String, Zeroizing<String>>,
) -> Result<Built, BrokerError> {
    if spec.kind != "oauth2" {
        return Err(BrokerError::Manifest(format!(
            "{}: not an oauth2 auth",
            m.id
        )));
    }
    let path = spec
        .token_path
        .as_deref()
        .ok_or_else(|| BrokerError::Manifest(format!("{}: oauth2 needs a token_path", m.id)))?;
    let base: Uri = fill_base(m, svc_params)?
        .parse()
        .map_err(|_| BrokerError::HostNotAllowed)?;
    let authority = base.authority().ok_or(BrokerError::HostNotAllowed)?;
    let uri = checked_uri(m, svc_params, &format!("https://{authority}{path}"))?;
    let mut body = Zeroizing::new(String::from("grant_type=refresh_token"));
    for name in FIELDS {
        let v = fields.get(name).ok_or_else(|| {
            BrokerError::Manifest(format!("auth oauth2: the secret has no field {name:?}"))
        })?;
        body.push('&');
        body.push_str(name);
        body.push('=');
        body.extend(utf8_percent_encode(v, FORM));
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
    Ok(Built {
        method: Method::POST,
        uri,
        headers,
        body: Some(Bytes::copy_from_slice(body.as_bytes())),
    })
}

/// A token as it can go into a header and the vault: printable ASCII, no
/// space, at least 4 and at most 8 KiB bytes.
fn usable(t: &str) -> bool {
    (4..=MAX_TOKEN).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_graphic())
}

/// Parses a token response. `instance_url`, when present, must be an
/// `https` URL whose host is `expect_host` (the configured instance), or
/// the response is refused: an access token for another instance is never
/// used, and a refresh token from such a response is never stored.
pub fn parse_token(body: &[u8], expect_host: &str) -> Result<Token, RefreshError> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| RefreshError::BadResponse)?;
    let o = v.as_object().ok_or(RefreshError::BadResponse)?;
    if let Some(inst) = o.get("instance_url") {
        let inst = inst.as_str().ok_or(RefreshError::BadResponse)?;
        let uri: Uri = inst.parse().map_err(|_| RefreshError::InstanceMismatch)?;
        let ok = uri.scheme_str() == Some("https")
            && uri.authority().is_some_and(|a| {
                !a.as_str().contains('@') && a.host().eq_ignore_ascii_case(expect_host)
            });
        if !ok {
            return Err(RefreshError::InstanceMismatch);
        }
    }
    if let Some(t) = o.get("token_type").and_then(|t| t.as_str()) {
        if !t.eq_ignore_ascii_case("bearer") {
            return Err(RefreshError::BadResponse);
        }
    }
    let access = o
        .get("access_token")
        .and_then(|t| t.as_str())
        .filter(|t| usable(t))
        .ok_or(RefreshError::BadResponse)?;
    let refresh = match o.get("refresh_token") {
        None | Some(serde_json::Value::Null) => None,
        Some(r) => Some(
            r.as_str()
                .filter(|t| usable(t))
                .ok_or(RefreshError::BadResponse)?,
        ),
    };
    let ttl = match o.get("expires_in") {
        None | Some(serde_json::Value::Null) => DEFAULT_TTL,
        Some(e) => {
            let secs = e
                .as_u64()
                .or_else(|| e.as_str().and_then(|s| s.parse().ok()))
                .ok_or(RefreshError::BadResponse)?;
            Duration::from_secs(secs).min(MAX_TTL)
        }
    };
    Ok(Token {
        access: Zeroizing::new(access.to_string()),
        refresh: refresh.map(|r| Zeroizing::new(r.to_string())),
        ttl,
    })
}

/// The token is due for a refresh: it is `age` old and lived `ttl`.
pub fn due(age: Duration, ttl: Duration) -> bool {
    age >= ttl.saturating_sub(EARLY)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Manifest {
        Manifest::parse(
            r#"
id = "sfx"
version = 1
title = "SF"
base_url = "https://{instance_host}/services/data/v60.0"
hosts = ["{instance_host}"]
auth = [{ kind = "oauth2", token_path = "/services/oauth2/token" }]
[params.instance_host]
type = "string"
pattern = "^[a-z0-9-]+\\.sf\\.test$"
required = true
[[operation]]
id = "limits"
capability = "limits:read"
kind = "read"
method = "GET"
path = "/limits"
"#,
        )
        .unwrap()
    }

    fn fields() -> BTreeMap<String, Zeroizing<String>> {
        [
            ("client_id", "cid-1"),
            ("client_secret", "c s&=+"),
            ("refresh_token", "rt-abc/def"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), Zeroizing::new(v.to_string())))
        .collect()
    }

    fn params(h: &str) -> BTreeMap<String, String> {
        [("instance_host".to_string(), h.to_string())].into()
    }

    #[test]
    fn request_is_a_form_post_to_the_admin_host() {
        let m = manifest();
        let b = token_request(&m.auth[0], &m, &params("acme.sf.test"), &fields()).unwrap();
        assert_eq!(b.method, Method::POST);
        assert_eq!(
            b.uri.to_string(),
            "https://acme.sf.test/services/oauth2/token"
        );
        assert_eq!(
            std::str::from_utf8(b.body.as_ref().unwrap()).unwrap(),
            "grant_type=refresh_token&client_id=cid-1&client_secret=c%20s%26%3D%2B&refresh_token=rt-abc%2Fdef"
        );
        assert_eq!(b.headers[CONTENT_TYPE], "application/x-www-form-urlencoded");
        let d = format!("{b:?}");
        assert!(!d.contains("rt-abc") && !d.contains("c%20s"), "{d}");
    }

    #[test]
    fn request_refuses_a_host_param_that_escapes() {
        let m = manifest();
        for h in ["evil.test", "acme.sf.test@evil.test", "ACME.sf.test"] {
            assert!(
                token_request(&m.auth[0], &m, &params(h), &fields()).is_err(),
                "{h}"
            );
        }
    }

    #[test]
    fn parse_takes_tokens_ttl_and_checks_the_instance() {
        let t = parse_token(
            br#"{"access_token":"at-1234","refresh_token":"rt-5678","instance_url":"https://acme.sf.test","token_type":"Bearer","expires_in":3600}"#,
            "acme.sf.test",
        )
        .unwrap();
        assert_eq!(t.access.as_str(), "at-1234");
        assert_eq!(t.refresh.as_deref().map(String::as_str), Some("rt-5678"));
        assert_eq!(t.ttl, Duration::from_secs(3600));
        let d = format!("{t:?}");
        assert!(!d.contains("at-1234") && !d.contains("rt-5678"), "{d}");

        let t = parse_token(br#"{"access_token":"at-1234"}"#, "acme.sf.test").unwrap();
        assert_eq!(t.ttl, DEFAULT_TTL);
        assert!(t.refresh.is_none());

        for bad in [
            &br#"{"access_token":"at-1234","instance_url":"https://evil.sf.test"}"#[..],
            br#"{"access_token":"at-1234","instance_url":"http://acme.sf.test"}"#,
            br#"{"access_token":"at-1234","instance_url":"https://acme.sf.test@evil.test"}"#,
            br#"{"access_token":"at-1234","instance_url":"https://acme.sf.test.evil.test"}"#,
        ] {
            assert_eq!(
                parse_token(bad, "acme.sf.test").unwrap_err(),
                RefreshError::InstanceMismatch
            );
        }
        for bad in [
            &b"not json"[..],
            br#"{"access_token":""}"#,
            br#"{"access_token":"a b c d"}"#,
            br#"{"access_token":"at-1234","refresh_token":5}"#,
            br#"{"access_token":"at-1234","token_type":"mac"}"#,
            br#"{"access_token":"at-1234","expires_in":"soon"}"#,
            br#"{"refresh_token":"rt-5678"}"#,
        ] {
            assert_eq!(
                parse_token(bad, "acme.sf.test").unwrap_err(),
                RefreshError::BadResponse
            );
        }
    }

    #[test]
    fn due_sixty_seconds_early() {
        let ttl = Duration::from_secs(900);
        assert!(!due(Duration::from_secs(839), ttl));
        assert!(due(Duration::from_secs(840), ttl));
        assert!(due(Duration::ZERO, Duration::from_secs(30)));
    }

    #[test]
    fn reasons() {
        assert_eq!(RefreshError::Http(400).reason(), "http_400");
        assert_eq!(RefreshError::Persist.reason(), "persist");
        assert_eq!(RefreshError::InstanceMismatch.reason(), "instance_mismatch");
    }
}
