//! The GCP and Azure OAuth2 token exchanges (decision 6): the request, the
//! response and one bounded exchange. There is no cache here; the daemon
//! keeps minted tokens (plan 15, Task 9).
//!
//! The endpoints are pinned in code. GCP is always [`GCP_TOKEN_URL`] (a key
//! file's `token_uri` is ignored); Azure is
//! `https://{authority}/{tenant}/oauth2/v2.0/token` with an authority from
//! [`AZURE_AUTHORITIES`]. [`mint`] sends nothing anywhere else, reads at
//! most [`MAX_RESPONSE`] bytes, follows no redirect, and on an error answer
//! keeps only the sanitized `error` code (decision 18).

use bytes::Bytes;
use http::header::{ACCEPT, ACCEPT_ENCODING, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue, Method, Uri};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use std::collections::BTreeMap;
use std::time::Duration;
use time::OffsetDateTime;
use zeroize::Zeroizing;

use super::jwt::{assertion, GcpKey};
use super::CloudError;
use crate::oauth2::Token;
use crate::request::Built;
use crate::upstream::Upstream;
use crate::BrokerError;

/// Google's token endpoint, the JWT `aud`.
pub const GCP_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
/// The Azure authorities a token may come from; the first is the default.
pub const AZURE_AUTHORITIES: [&str; 3] = [
    "login.microsoftonline.com",
    "login.microsoftonline.us",
    "login.chinacloudapi.cn",
];
/// The vault fields of an `azure_sp` secret.
pub const AZURE_FIELDS: [&str; 3] = ["tenant_id", "client_id", "client_secret"];
/// The most of a token response read; more is [`CloudError::TooLarge`].
pub const MAX_RESPONSE: usize = 64 * 1024;
/// The longest a token exchange may take.
pub const MINT_TIMEOUT: Duration = Duration::from_secs(15);
/// The longest access token accepted.
const MAX_TOKEN: usize = 8 * 1024;
/// The `expires_in` range believed, in seconds.
const MAX_EXPIRES_IN: u64 = 86_400;
const JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// RFC 3986 unreserved characters stay; everything else is encoded.
const FORM: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

fn form_post(uri: Uri, body: &Zeroizing<String>) -> Built {
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
    Built {
        method: Method::POST,
        uri,
        headers,
        body: Some(Bytes::copy_from_slice(body.as_bytes())),
    }
}

fn push_pair(body: &mut Zeroizing<String>, name: &str, value: &str) {
    if !body.is_empty() {
        body.push('&');
    }
    body.push_str(name);
    body.push('=');
    body.extend(utf8_percent_encode(value, FORM));
}

/// The GCP exchange: `POST https://oauth2.googleapis.com/token` with
/// `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=<JWT>`.
/// `Debug` of the result never shows the body.
pub fn gcp_request(k: &GcpKey, scope: &str, now: OffsetDateTime) -> Result<Built, CloudError> {
    let jwt = assertion(k, scope, now)?;
    let mut body = Zeroizing::new(String::with_capacity(jwt.len() + 128));
    push_pair(&mut body, "grant_type", JWT_BEARER);
    push_pair(&mut body, "assertion", &jwt);
    let uri = Uri::from_static(GCP_TOKEN_URL);
    Ok(form_post(uri, &body))
}

/// `8-4-4-4-12` hex digits.
fn is_guid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && [8usize, 4, 4, 4, 12]
            .iter()
            .zip(&parts)
            .all(|(n, p)| p.len() == *n && p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// A DNS name with at least one dot (a tenant's verified domain).
fn is_domain(s: &str) -> bool {
    s.len() <= 253
        && s.contains('.')
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// The Azure exchange: `POST https://{authority}/{tenant}/oauth2/v2.0/token`
/// with the `client_credentials` grant (`client_id`, `client_secret`,
/// `scope`). `authority` defaults to `login.microsoftonline.com` and must
/// be one of [`AZURE_AUTHORITIES`]; the tenant must be a GUID or a domain.
/// `Debug` of the result never shows the body.
pub fn azure_request(
    fields: &BTreeMap<String, Zeroizing<String>>,
    authority: Option<&str>,
    scope: &str,
) -> Result<Built, CloudError> {
    let authority = authority.unwrap_or(AZURE_AUTHORITIES[0]);
    if !AZURE_AUTHORITIES.contains(&authority) {
        return Err(CloudError::Key(
            "azure_sp: the authority is not a known Azure login host".into(),
        ));
    }
    let get = |name: &str| {
        fields
            .get(name)
            .map(|v| v.as_str())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| CloudError::Key(format!("azure_sp: the secret has no field {name:?}")))
    };
    let tenant = get("tenant_id")?;
    let client_id = get("client_id")?;
    let client_secret = get("client_secret")?;
    if !(is_guid(tenant) || is_domain(tenant)) {
        return Err(CloudError::Key(
            "azure_sp: tenant_id is not a GUID or a domain".into(),
        ));
    }
    if scope.is_empty() || !scope.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
        return Err(CloudError::Key(
            "azure_sp: the scope is not printable".into(),
        ));
    }
    let uri: Uri = format!("https://{authority}/{tenant}/oauth2/v2.0/token")
        .parse()
        .map_err(|_| CloudError::Key("azure_sp: tenant_id is not a GUID or a domain".into()))?;
    let mut body = Zeroizing::new(String::with_capacity(256));
    push_pair(&mut body, "grant_type", "client_credentials");
    push_pair(&mut body, "client_id", client_id);
    push_pair(&mut body, "client_secret", client_secret);
    push_pair(&mut body, "scope", scope);
    Ok(form_post(uri, &body))
}

/// The URI is one of the pinned token endpoints.
fn pinned(uri: &Uri) -> bool {
    if uri.scheme_str() != Some("https") || uri.query().is_some() {
        return false;
    }
    let Some(a) = uri.authority() else {
        return false;
    };
    if a.port().is_some() || a.as_str().contains('@') {
        return false;
    }
    let host = a.host();
    let path = uri.path();
    if host == "oauth2.googleapis.com" {
        return path == "/token";
    }
    AZURE_AUTHORITIES.contains(&host)
        && path
            .strip_prefix('/')
            .and_then(|p| p.strip_suffix("/oauth2/v2.0/token"))
            .is_some_and(|t| is_guid(t) || is_domain(t))
}

/// An OAuth `error` code as it may be recorded: `[A-Za-z0-9_.]{1,64}`, or
/// `unrecognized`. Nothing else of an error answer is kept.
fn sanitize_code(code: &str) -> String {
    if (1..=64).contains(&code.len())
        && code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
    {
        code.to_string()
    } else {
        "unrecognized".into()
    }
}

fn bad(why: &str) -> CloudError {
    CloudError::Response(why.to_string())
}

/// Reads a token endpoint's answer. A non-2xx status, or an `error` field,
/// is [`CloudError::Endpoint`] with the sanitized `error` code (`http_<n>`
/// when there is none); `error_description` is never kept. A success needs
/// `token_type` `Bearer`, an `access_token` of printable ASCII up to 8 KiB
/// and an `expires_in` (a number or a numeric string) in `1..=86400`.
pub fn parse_token_response(status: u16, body: &[u8]) -> Result<Token, CloudError> {
    let v: Option<serde_json::Value> = serde_json::from_slice(body).ok();
    let o = v.as_ref().and_then(|v| v.as_object());
    let error = o.and_then(|o| o.get("error")).filter(|e| !e.is_null());
    if !(200..300).contains(&status) || error.is_some() {
        let code = match error {
            Some(e) => sanitize_code(e.as_str().unwrap_or("")),
            None => format!("http_{status}"),
        };
        return Err(CloudError::Endpoint { code });
    }
    let o = o.ok_or_else(|| bad("not a JSON object"))?;
    let token_type = o.get("token_type").and_then(|t| t.as_str());
    if !token_type.is_some_and(|t| t.eq_ignore_ascii_case("bearer")) {
        return Err(bad("token_type is not Bearer"));
    }
    let access = o
        .get("access_token")
        .and_then(|t| t.as_str())
        .filter(|t| (1..=MAX_TOKEN).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_graphic()))
        .ok_or_else(|| bad("no usable access_token"))?;
    let secs = o
        .get("expires_in")
        .and_then(|e| {
            e.as_u64()
                .or_else(|| e.as_str().and_then(|s| s.parse::<u64>().ok()))
        })
        .filter(|s| (1..=MAX_EXPIRES_IN).contains(s))
        .ok_or_else(|| bad("expires_in is missing or out of range"))?;
    Ok(Token {
        access: Zeroizing::new(access.to_string()),
        refresh: None,
        ttl: Duration::from_secs(secs),
    })
}

/// Sends a token request built by [`gcp_request`] or [`azure_request`] and
/// reads the token. Only the pinned endpoints are contacted; the exchange
/// takes at most [`MINT_TIMEOUT`] (or the client's timeout, if shorter),
/// reads at most [`MAX_RESPONSE`] bytes, and a 3xx answer is
/// [`BrokerError::RedirectRefused`].
pub async fn mint(up: &Upstream, req: Built) -> Result<Token, CloudError> {
    if req.method != Method::POST || !pinned(&req.uri) {
        return Err(CloudError::Key("not a pinned cloud token endpoint".into()));
    }
    let up = up.with_timeout(up.timeout().min(MINT_TIMEOUT));
    let r = up.send(req, MAX_RESPONSE).await?;
    if (300..400).contains(&r.status) {
        return Err(BrokerError::RedirectRefused.into());
    }
    if r.truncated {
        return Err(CloudError::TooLarge);
    }
    parse_token_response(r.status, &r.body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_pinned_endpoints() {
        for ok in [
            GCP_TOKEN_URL,
            "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token",
            "https://login.chinacloudapi.cn/00000000-0000-0000-0000-000000000000/oauth2/v2.0/token",
        ] {
            assert!(pinned(&ok.parse().unwrap()), "{ok}");
        }
        for bad in [
            "http://oauth2.googleapis.com/token",
            "https://oauth2.googleapis.com:8443/token",
            "https://oauth2.googleapis.com/token?x=1",
            "https://oauth2.googleapis.com/other",
            "https://evil.test/token",
            "https://login.microsoftonline.com/a/b/oauth2/v2.0/token",
            "https://login.microsoftonline.com/oauth2/v2.0/token",
            "https://login.evil.test/contoso.com/oauth2/v2.0/token",
        ] {
            assert!(!pinned(&bad.parse().unwrap()), "{bad}");
        }
    }

    #[test]
    fn codes_are_sanitized() {
        assert_eq!(sanitize_code("invalid_grant"), "invalid_grant");
        assert_eq!(sanitize_code("a.b_9"), "a.b_9");
        for bad in ["", "has space", "x/y", &"a".repeat(65), "é"] {
            assert_eq!(sanitize_code(bad), "unrecognized", "{bad}");
        }
    }
}
