//! Upstream request building (spec §6.7.1 step 9): the base URL from the
//! manifest and the service parameters, the operation's path and query, the
//! headers the manifest allows, and the credential in exactly one place.

use crate::manifest::{template_segments, AuthSpec, Manifest, Operation, Seg};
use crate::BrokerError;
use base64::Engine as _;
use bytes::Bytes;
use http::header::AUTHORIZATION;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// A request ready for [`crate::upstream::Upstream::send`].
#[derive(Debug, Clone)]
pub struct Built {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: Option<Bytes>,
}

/// The credential for one call: the manifest's auth kind and header name,
/// and the fields of the vault entry. `Debug` never shows the values.
pub struct AuthMaterial {
    pub kind: String,
    pub name: Option<String>,
    pub fields: BTreeMap<String, Zeroizing<String>>,
}

impl std::fmt::Debug for AuthMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthMaterial")
            .field("kind", &self.kind)
            .field("name", &self.name)
            .field("fields", &self.fields.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl AuthMaterial {
    /// The material for `spec` from a vault entry's fields.
    pub fn from_spec(spec: &AuthSpec, fields: BTreeMap<String, Zeroizing<String>>) -> Self {
        AuthMaterial {
            kind: spec.kind.clone(),
            name: spec.name.clone(),
            fields,
        }
    }

    /// No credential, for a manifest without `auth`.
    pub fn none() -> Self {
        AuthMaterial {
            kind: NO_AUTH.to_string(),
            name: None,
            fields: BTreeMap::new(),
        }
    }

    /// Every non-empty field value, for the response masker (Task 8). For
    /// `basic` it also holds `username:password`, whose base64 is what goes
    /// on the wire.
    pub fn values(&self) -> Vec<Zeroizing<String>> {
        let mut out: Vec<Zeroizing<String>> = self
            .fields
            .values()
            .filter(|v| !v.is_empty())
            .cloned()
            .collect();
        if self.kind == "basic" {
            if let (Some(u), Some(p)) = (self.fields.get("username"), self.fields.get("password")) {
                out.push(basic_pair(u, p));
            }
        }
        out
    }

    fn field(&self, name: &str) -> Result<&str, BrokerError> {
        self.fields.get(name).map(|v| v.as_str()).ok_or_else(|| {
            BrokerError::Manifest(format!(
                "auth {}: the secret has no field {name:?}",
                self.kind
            ))
        })
    }
}

fn basic_pair(username: &str, password: &str) -> Zeroizing<String> {
    Zeroizing::new(format!("{username}:{password}"))
}

/// [`AuthMaterial::kind`] of [`AuthMaterial::none`].
pub const NO_AUTH: &str = "none";

/// Agent headers that never reach the upstream, whatever the manifest says:
/// credentials and the host, plus hop-by-hop and framing headers, which
/// hyper sets itself (letting an agent set them invites request smuggling).
const ALWAYS_DROPPED: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "te",
    "upgrade",
    "expect",
    "keep-alive",
    "trailer",
    "proxy-connection",
];

/// Everything but RFC 3986 unreserved characters is percent-encoded, in
/// path segments and query components alike.
const COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

fn bad_value(name: &str, reason: &str) -> BrokerError {
    BrokerError::BadValue {
        name: name.to_string(),
        reason: reason.to_string(),
    }
}

fn has_crlf_nul(v: &str) -> bool {
    v.contains(['\r', '\n', '\0'])
}

/// Fills `{x}` in `base_url`. A value must be URL-unreserved characters
/// only, so it cannot change the scheme, authority or query, and it must
/// pass the manifest's parameter type.
fn fill_base(m: &Manifest, svc_params: &BTreeMap<String, String>) -> Result<String, BrokerError> {
    let mut out = String::with_capacity(m.base_url.len());
    let mut rest = m.base_url.as_str();
    while let Some(i) = rest.find('{') {
        out.push_str(&rest[..i]);
        let end = rest[i..]
            .find('}')
            .ok_or_else(|| BrokerError::Manifest(format!("{}: unbalanced {{ in base_url", m.id)))?
            + i;
        let name = &rest[i + 1..end];
        let value = svc_params
            .get(name)
            .ok_or_else(|| BrokerError::MissingParam(name.to_string()))?;
        if let Some(spec) = m.params.get(name) {
            spec.param_type()?
                .check(value)
                .map_err(|why| bad_value(name, &why))?;
        }
        if value.is_empty()
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
        {
            return Err(bad_value(name, "must be letters, digits, - . _ or ~"));
        }
        out.push_str(value);
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// `pattern` is a host or `*.suffix`, where `*` is exactly one non-empty
/// label. Both compare case-insensitively.
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    match pattern.strip_prefix("*.") {
        Some(suffix) => host
            .strip_suffix(suffix)
            .and_then(|h| h.strip_suffix('.'))
            .is_some_and(|label| !label.is_empty() && !label.contains('.')),
        None => host == pattern,
    }
}

/// The `https` URI with an allowed host and no userinfo, or an error.
fn checked_uri(m: &Manifest, text: &str) -> Result<Uri, BrokerError> {
    let uri: Uri = text.parse().map_err(|_| BrokerError::HostNotAllowed)?;
    if uri.scheme_str() != Some("https") {
        return Err(BrokerError::HostNotAllowed);
    }
    let authority = uri.authority().ok_or(BrokerError::HostNotAllowed)?;
    if authority.as_str().contains('@') {
        return Err(BrokerError::HostNotAllowed);
    }
    let host = authority.host();
    if !m.hosts.iter().any(|p| host_matches(p, host)) {
        return Err(BrokerError::HostNotAllowed);
    }
    Ok(uri)
}

fn auth_header(
    m: &Manifest,
    auth: &AuthMaterial,
) -> Result<Option<(HeaderName, HeaderValue)>, BrokerError> {
    let refuse = |why: &str| BrokerError::Manifest(format!("{}: {why}", m.id));
    if auth.kind == NO_AUTH {
        return if m.auth.is_empty() {
            Ok(None)
        } else {
            Err(refuse("the connector needs a credential"))
        };
    }
    let spec = m
        .auth
        .iter()
        .find(|a| {
            a.kind == auth.kind
                && (a.kind != "header"
                    || a.name.as_deref().map(str::to_ascii_lowercase)
                        == auth.name.as_deref().map(str::to_ascii_lowercase))
        })
        .ok_or_else(|| refuse("the credential does not match the connector's auth"))?;
    let (name, value) = match spec.kind.as_str() {
        "header" => {
            let name = spec.name.as_deref().unwrap_or("");
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| refuse("auth header name is invalid"))?;
            (name, auth.field(&spec.secret_field)?.to_string())
        }
        "bearer" => (
            AUTHORIZATION,
            format!("Bearer {}", auth.field(&spec.secret_field)?),
        ),
        "basic" => {
            // Ruling: basic uses the fields `username` and `password`;
            // `secret_field` is not used.
            let pair = basic_pair(auth.field("username")?, auth.field("password")?);
            (
                AUTHORIZATION,
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(&*pair)
                ),
            )
        }
        other => return Err(refuse(&format!("auth kind {other:?} is not supported"))),
    };
    let value = Zeroizing::new(value);
    let secret_err = || bad_value("auth", "the secret is not a valid header value");
    if has_crlf_nul(&value) {
        return Err(secret_err());
    }
    let mut value = HeaderValue::from_str(&value).map_err(|_| secret_err())?;
    value.set_sensitive(true);
    Ok(Some((name, value)))
}

/// Builds the upstream request. `params` are the validated call parameters
/// (`params::validate`); `svc_params` fill the `{x}` of `base_url`.
pub fn build(
    m: &Manifest,
    op: &Operation,
    svc_params: &BTreeMap<String, String>,
    params: &BTreeMap<String, String>,
    agent_headers: &[(String, String)],
    body: Option<Bytes>,
    auth: &AuthMaterial,
) -> Result<Built, BrokerError> {
    let method = Method::from_bytes(op.method.as_bytes())
        .map_err(|_| BrokerError::Manifest(format!("{}: bad method", m.id)))?;

    let mut url = fill_base(m, svc_params)?;
    while url.ends_with('/') {
        url.pop();
    }
    for seg in template_segments(&op.path).map_err(|e| BrokerError::Manifest(e.to_string()))? {
        url.push('/');
        match seg {
            Seg::Lit(s) => url.push_str(s),
            Seg::Var {
                prefix,
                name,
                suffix,
            } => {
                let v = params
                    .get(name)
                    .ok_or_else(|| BrokerError::MissingParam(name.to_string()))?;
                if v.is_empty() || v == "." || v == ".." || v.contains(['/', '\\']) {
                    return Err(bad_value(name, "not a single path segment"));
                }
                url.push_str(prefix);
                url.extend(utf8_percent_encode(v, COMPONENT));
                url.push_str(suffix);
            }
        }
    }
    let mut sep = '?';
    for name in op.query.keys() {
        if let Some(v) = params.get(name) {
            url.push(sep);
            sep = '&';
            url.extend(utf8_percent_encode(name, COMPONENT));
            url.push('=');
            url.extend(utf8_percent_encode(v, COMPONENT));
        }
    }
    let uri = checked_uri(m, &url)?;

    let auth = auth_header(m, auth)?;
    let mut headers = HeaderMap::new();
    for (name, value) in agent_headers {
        if has_crlf_nul(value) {
            return Err(bad_value(name, "header value contains CR, LF or NUL"));
        }
        let hname = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| bad_value(name, "not a valid header name"))?;
        let hvalue = HeaderValue::from_str(value)
            .map_err(|_| bad_value(name, "not a valid header value"))?;
        let lower = hname.as_str();
        let listed = m
            .request_headers
            .iter()
            .any(|h| h.eq_ignore_ascii_case(lower));
        let is_auth = auth.as_ref().is_some_and(|(n, _)| n == hname);
        if listed && !is_auth && !ALWAYS_DROPPED.contains(&lower) {
            // A repeated header: the last one wins.
            headers.insert(hname, hvalue);
        }
    }
    if let Some((name, value)) = auth {
        headers.insert(name, value);
    }
    Ok(Built {
        method,
        uri,
        headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::named;

    /// The Shopify manifest of spec §8.4.
    const SHOPIFY_LIKE: &str = r#"
id = "shopify-like"
version = 1
title = "Shopify-like"
base_url = "https://{shop}.myshopify.com/admin/api/2026-07"
hosts = ["*.myshopify.com"]
auth = [{ kind = "header", name = "X-Shopify-Access-Token", secret_field = "token" }]
request_headers = ["Content-Type", "Accept", "Idempotency-Key"]

[params.shop]
type = "string"
pattern = "^[a-z0-9-]+$"
required = true

[[operation]]
id = "orders.list"
capability = "orders:read"
kind = "read"
method = "GET"
path = "/orders.json"
query = { status = "enum:open,closed,cancelled,any", limit = "int:1..250", since_id = "int", created_at_min = "datetime" }
pagination = "link-header"

[[operation]]
id = "refunds.create"
capability = "refunds:write"
kind = "write"
method = "POST"
path = "/orders/{order_id}/refunds.json"
path_params = { order_id = "int" }
body = "json"
amount = { field = "refund.transactions[].amount", currency_field = "refund.currency", unit = "major" }
"#;

    fn plain_api(kind: &str, secret_field: &str) -> Manifest {
        Manifest::parse(&format!(
            r#"
id = "plain"
version = 1
title = "Plain"
base_url = "https://api.example.test/v1"
hosts = ["api.example.test"]
auth = [{{ kind = "{kind}", secret_field = "{secret_field}" }}]
request_headers = ["Content-Type", "Accept"]

[[operation]]
id = "items.get"
capability = "items:read"
kind = "read"
method = "GET"
path = "/items/{{id}}"
path_params = {{ id = "int" }}

[[operation]]
id = "items.create"
capability = "items:write"
kind = "write"
method = "POST"
path = "/items"
body = "json"
"#
        ))
        .unwrap()
    }

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn hdrs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn auth(spec: &AuthSpec, fields: &[(&str, &str)]) -> AuthMaterial {
        AuthMaterial {
            kind: spec.kind.clone(),
            name: spec.name.clone(),
            fields: fields
                .iter()
                .map(|(k, v)| (k.to_string(), Zeroizing::new(v.to_string())))
                .collect(),
        }
    }

    fn shopify() -> Manifest {
        Manifest::parse(SHOPIFY_LIKE).unwrap()
    }

    fn shop_auth(m: &Manifest) -> AuthMaterial {
        auth(&m.auth[0], &[("token", "shpat_SECRET123")])
    }

    /// `METHOD URI`, then `name: value` per header, sorted.
    fn render(b: &Built) -> String {
        let mut lines: Vec<String> = b
            .headers
            .iter()
            .map(|(k, v)| format!("{}: {}", k.as_str(), v.to_str().unwrap()))
            .collect();
        lines.sort();
        let mut out = format!("{} {}\n", b.method, b.uri);
        for l in lines {
            out.push_str(&l);
            out.push('\n');
        }
        out
    }

    fn golden(name: &str, auth_value: &str) -> String {
        let path = format!("{}/tests/golden/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{path}: {e}"))
            .replace("<AUTH>", auth_value)
    }

    #[test]
    fn build_shopify_like_orders_list() {
        let m = shopify();
        let op = named(&m, "orders.list").unwrap();
        let b = build(
            &m,
            op,
            &map(&[("shop", "acme")]),
            &map(&[("status", "open"), ("limit", "50")]),
            &hdrs(&[
                ("Accept", "application/json"),
                ("X-Not-Listed", "1"),
                ("X-Shopify-Access-Token", "agent-guess"),
            ]),
            None,
            &shop_auth(&m),
        )
        .unwrap();
        assert_eq!(
            render(&b),
            golden("build_shopify_like_orders_list.http", "shpat_SECRET123")
        );
        assert!(b.body.is_none());
    }

    #[test]
    fn build_bearer() {
        let m = plain_api("bearer", "token");
        let op = named(&m, "items.get").unwrap();
        let b = build(
            &m,
            op,
            &BTreeMap::new(),
            &map(&[("id", "42")]),
            &hdrs(&[("accept", "application/json")]),
            None,
            &auth(&m.auth[0], &[("token", "tok-XYZ")]),
        )
        .unwrap();
        assert_eq!(render(&b), golden("build_bearer.http", "tok-XYZ"));
    }

    #[test]
    fn build_basic() {
        // The ruling: basic uses the fields `username` and `password`;
        // `secret_field` is not used.
        let m = plain_api("basic", "");
        let op = named(&m, "items.create").unwrap();
        let body = Bytes::from_static(br#"{"name":"x"}"#);
        let b = build(
            &m,
            op,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &hdrs(&[("Content-Type", "application/json")]),
            Some(body.clone()),
            &auth(&m.auth[0], &[("username", "ann"), ("password", "pa:ss")]),
        )
        .unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode("ann:pa:ss");
        assert_eq!(render(&b), golden("build_basic.http", &encoded));
        assert_eq!(b.body, Some(body));
    }

    #[test]
    fn basic_needs_username_and_password() {
        let m = plain_api("basic", "");
        let op = named(&m, "items.create").unwrap();
        for fields in [&[("username", "ann")][..], &[("password", "pw")][..]] {
            let err = build(
                &m,
                op,
                &BTreeMap::new(),
                &BTreeMap::new(),
                &[],
                None,
                &auth(&m.auth[0], fields),
            )
            .unwrap_err();
            assert!(matches!(err, BrokerError::Manifest(_)), "{err:?}");
            assert!(!err.to_string().contains("pw") && !err.to_string().contains("ann"));
        }
    }

    #[test]
    fn build_path_param_encoded() {
        let m = shopify();
        let op = named(&m, "refunds.create").unwrap();
        let b = build(
            &m,
            op,
            &map(&[("shop", "acme")]),
            &map(&[("order_id", "12 34")]),
            &hdrs(&[
                ("Content-Type", "application/json"),
                ("Idempotency-Key", "k-1"),
            ]),
            Some(Bytes::from_static(b"{}")),
            &shop_auth(&m),
        )
        .unwrap();
        assert_eq!(
            render(&b),
            golden("build_path_param_encoded.http", "shpat_SECRET123")
        );
    }

    #[test]
    fn path_segment_with_prefix_and_suffix() {
        let mut m = shopify();
        m.operation[1].path = "/orders/v{order_id}.json".into();
        let op = &m.operation[1];
        let b = build(
            &m,
            op,
            &map(&[("shop", "acme")]),
            &map(&[("order_id", "12 34")]),
            &[],
            None,
            &shop_auth(&m),
        )
        .unwrap();
        assert_eq!(b.uri.path(), "/admin/api/2026-07/orders/v12%2034.json");
    }

    #[test]
    fn path_param_with_slash_refused() {
        let m = shopify();
        let op = named(&m, "refunds.create").unwrap();
        for v in ["1/2", "..", "a\\b"] {
            let err = build(
                &m,
                op,
                &map(&[("shop", "acme")]),
                &map(&[("order_id", v)]),
                &[],
                None,
                &shop_auth(&m),
            )
            .unwrap_err();
            assert!(matches!(err, BrokerError::BadValue { .. }), "{v}: {err:?}");
        }
    }

    #[test]
    fn lowercase_authorization_dropped() {
        let m = shopify();
        let op = named(&m, "orders.list").unwrap();
        // Even a manifest that lists Authorization never lets the agent's
        // through.
        let mut m2 = m.clone();
        m2.request_headers.push("authorization".into());
        for mm in [&m, &m2] {
            let b = build(
                mm,
                op,
                &map(&[("shop", "acme")]),
                &BTreeMap::new(),
                &hdrs(&[("authorization", "Bearer agent"), ("AUTHORIZATION", "x")]),
                None,
                &shop_auth(mm),
            )
            .unwrap();
            assert!(b.headers.get("authorization").is_none());
        }
        // With bearer auth, the only Authorization is the vault's.
        let m = plain_api("bearer", "token");
        let mut m3 = m.clone();
        m3.request_headers.push("Authorization".into());
        let op = named(&m3, "items.get").unwrap();
        let b = build(
            &m3,
            op,
            &BTreeMap::new(),
            &map(&[("id", "1")]),
            &hdrs(&[("authorization", "Bearer agent")]),
            None,
            &auth(&m3.auth[0], &[("token", "vault")]),
        )
        .unwrap();
        let all: Vec<_> = b.headers.get_all("authorization").iter().collect();
        assert_eq!(all, ["Bearer vault"]);
    }

    #[test]
    fn host_and_cookie_dropped() {
        let mut m = shopify();
        m.request_headers
            .extend(["Host".to_string(), "Cookie".to_string()]);
        let op = named(&m, "orders.list").unwrap();
        let b = build(
            &m,
            op,
            &map(&[("shop", "acme")]),
            &BTreeMap::new(),
            &hdrs(&[
                ("Host", "evil.example"),
                ("cookie", "session=1"),
                ("Accept", "*/*"),
            ]),
            None,
            &shop_auth(&m),
        )
        .unwrap();
        assert!(b.headers.get("host").is_none());
        assert!(b.headers.get("cookie").is_none());
        assert_eq!(b.headers.get("accept").unwrap(), "*/*");
    }

    #[test]
    fn crlf_in_header_value_rejected() {
        let m = shopify();
        let op = named(&m, "orders.list").unwrap();
        for v in ["a\r\nX-Evil: 1", "a\nb", "a\rb", "a\0b"] {
            // Listed or not, a smuggling attempt fails the call.
            for name in ["Accept", "X-Not-Listed"] {
                let err = build(
                    &m,
                    op,
                    &map(&[("shop", "acme")]),
                    &BTreeMap::new(),
                    &hdrs(&[(name, v)]),
                    None,
                    &shop_auth(&m),
                )
                .unwrap_err();
                match err {
                    BrokerError::BadValue { name: n, .. } => assert_eq!(n, name),
                    other => panic!("{v:?}: {other:?}"),
                }
            }
        }
    }

    #[test]
    fn crlf_in_secret_rejected_without_the_value() {
        let m = shopify();
        let op = named(&m, "orders.list").unwrap();
        let err = build(
            &m,
            op,
            &map(&[("shop", "acme")]),
            &BTreeMap::new(),
            &[],
            None,
            &auth(&m.auth[0], &[("token", "tok\r\nX-Evil: 1")]),
        )
        .unwrap_err();
        assert!(matches!(err, BrokerError::BadValue { .. }), "{err:?}");
        assert!(!err.to_string().contains("tok"), "{err}");
        assert!(!format!("{err:?}").contains("Evil"));
    }

    #[test]
    fn base_url_host_must_match_hosts() {
        let m = shopify();
        let op = named(&m, "orders.list").unwrap();
        let call = |m: &Manifest, shop: &str| {
            build(
                m,
                op,
                &map(&[("shop", shop)]),
                &BTreeMap::new(),
                &[],
                None,
                &shop_auth(m),
            )
        };
        // The manifest pattern refuses it before any URL is formed.
        assert!(matches!(
            call(&m, "evil.com#").unwrap_err(),
            BrokerError::BadValue { .. }
        ));
        // Without the pattern, the host check still refuses what escapes
        // the one-label glob.
        let mut loose = m.clone();
        loose.params.get_mut("shop").unwrap().pattern = None;
        for shop in ["a.b", "evil.com#", "evil.com/x?", "x@evil.com", ""] {
            let err = call(&loose, shop).unwrap_err();
            assert!(
                matches!(
                    err,
                    BrokerError::HostNotAllowed | BrokerError::BadValue { .. }
                ),
                "{shop:?}: {err:?}"
            );
        }
        assert!(matches!(
            call(&loose, "a.b").unwrap_err(),
            BrokerError::HostNotAllowed
        ));
        assert!(call(&loose, "acme").is_ok());
        // A base URL outside the hosts list.
        let mut off = m.clone();
        off.base_url = "https://{shop}.evil.example/admin".into();
        assert!(matches!(
            call(&off, "acme").unwrap_err(),
            BrokerError::HostNotAllowed
        ));
        // A missing service parameter.
        let err = build(
            &m,
            op,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &[],
            None,
            &shop_auth(&m),
        )
        .unwrap_err();
        assert!(matches!(err, BrokerError::MissingParam(ref p) if p == "shop"));
    }

    #[test]
    fn host_glob_is_one_label() {
        assert!(host_matches("*.myshopify.com", "a.myshopify.com"));
        assert!(host_matches("*.myshopify.com", "A.MyShopify.com"));
        assert!(!host_matches("*.myshopify.com", "myshopify.com"));
        assert!(!host_matches("*.myshopify.com", ".myshopify.com"));
        assert!(!host_matches("*.myshopify.com", "a.b.myshopify.com"));
        assert!(!host_matches("*.myshopify.com", "amyshopify.com"));
        assert!(host_matches("api.example.test", "API.example.test"));
        assert!(!host_matches("api.example.test", "x.api.example.test"));
    }

    #[test]
    fn query_values_are_encoded() {
        let mut m = shopify();
        m.operation[0].query.insert("q".into(), "string".into());
        let op = &m.operation[0];
        let b = build(
            &m,
            op,
            &map(&[("shop", "acme")]),
            &map(&[("q", "a&b=c d#"), ("unlisted", "x")]),
            &[],
            None,
            &shop_auth(&m),
        )
        .unwrap();
        assert_eq!(b.uri.query(), Some("q=a%26b%3Dc%20d%23"));
    }

    #[test]
    fn auth_material_values_and_debug() {
        let m = plain_api("basic", "");
        let a = auth(&m.auth[0], &[("username", "ann"), ("password", "s3cret")]);
        let mut v: Vec<String> = a.values().iter().map(|s| s.to_string()).collect();
        v.sort();
        // Basic also yields the combined pair, whose base64 is the wire form.
        assert_eq!(v, ["ann", "ann:s3cret", "s3cret"]);
        let d = format!("{a:?}");
        assert!(!d.contains("s3cret") && d.contains("password"), "{d}");
        // Other kinds yield only their fields.
        let b = AuthMaterial {
            kind: "bearer".into(),
            name: None,
            fields: [("token".to_string(), Zeroizing::new("t0k".to_string()))].into(),
        };
        let v: Vec<String> = b.values().iter().map(|s| s.to_string()).collect();
        assert_eq!(v, ["t0k"]);
    }

    #[test]
    fn hop_by_hop_and_framing_headers_dropped() {
        let mut m = shopify();
        let hop = [
            "Content-Length",
            "Transfer-Encoding",
            "Connection",
            "TE",
            "Upgrade",
            "Expect",
            "Keep-Alive",
            "Trailer",
            "Proxy-Connection",
        ];
        m.request_headers.extend(hop.iter().map(|h| h.to_string()));
        let op = named(&m, "orders.list").unwrap();
        let agent: Vec<(String, String)> = hop
            .iter()
            .map(|h| (h.to_string(), "1".to_string()))
            .chain([("Accept".to_string(), "*/*".to_string())])
            .collect();
        let b = build(
            &m,
            op,
            &map(&[("shop", "acme")]),
            &BTreeMap::new(),
            &agent,
            None,
            &shop_auth(&m),
        )
        .unwrap();
        for h in hop {
            assert!(b.headers.get(h).is_none(), "{h} survived");
        }
        assert_eq!(b.headers.get("accept").unwrap(), "*/*");
    }

    #[test]
    fn duplicate_agent_header_last_wins() {
        let m = shopify();
        let op = named(&m, "orders.list").unwrap();
        let b = build(
            &m,
            op,
            &map(&[("shop", "acme")]),
            &BTreeMap::new(),
            &hdrs(&[("Accept", "text/plain"), ("accept", "application/json")]),
            None,
            &shop_auth(&m),
        )
        .unwrap();
        let all: Vec<_> = b.headers.get_all("accept").iter().collect();
        assert_eq!(all, ["application/json"]);
    }

    #[test]
    fn auth_header_is_sensitive() {
        let m = shopify();
        let op = named(&m, "orders.list").unwrap();
        let b = build(
            &m,
            op,
            &map(&[("shop", "acme")]),
            &BTreeMap::new(),
            &[],
            None,
            &shop_auth(&m),
        )
        .unwrap();
        assert!(!format!("{b:?}").contains("shpat_SECRET123"));
    }

    #[test]
    fn auth_kind_must_match_manifest() {
        let m = shopify();
        let op = named(&m, "orders.list").unwrap();
        let wrong = AuthMaterial {
            kind: "bearer".into(),
            name: None,
            fields: [("token".to_string(), Zeroizing::new("t".to_string()))].into(),
        };
        assert!(build(
            &m,
            op,
            &map(&[("shop", "acme")]),
            &BTreeMap::new(),
            &[],
            None,
            &wrong
        )
        .is_err());
    }
}
