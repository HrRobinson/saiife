//! The manifest schema additions for connector waves 2 and 3 (plan 14,
//! decisions 1–7): host placeholders, auth prefixes and `basic_token`,
//! fixed headers, built bodies (JSON, form, GraphQL), `currency_param`
//! amounts, cursor `more`, offset pagination, Link `results="false"` and the
//! generated built-in list. Inline manifests only; the one network test
//! talks to a loopback server.

use base64::Engine as _;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Request, Response};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;
use saiife_broker::manifest::{AmountSpec, Manifest, Pagination, Unit};
use saiife_broker::pipeline::prepare_body;
use saiife_broker::request::{
    build, build_body, form_encode, next_cursor, next_from_link, AuthMaterial,
};
use saiife_broker::resolve::{named, proxy};
use saiife_broker::upstream::{Resolver, Upstream};
use saiife_broker::{amount, catalog, BrokerError, Catalog};
use saiife_policy::SystemConfig;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use zeroize::Zeroizing;

const HOSTNAME_RE: &str = r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$";

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

fn material(m: &Manifest, fields: &[(&str, &str)]) -> AuthMaterial {
    AuthMaterial::from_spec(
        &m.auth[0],
        fields
            .iter()
            .map(|(k, v)| (k.to_string(), Zeroizing::new(v.to_string())))
            .collect(),
    )
}

/// A whole-host placeholder manifest (GitLab-like), with `params.host`
/// declared as `extra` says.
fn host_manifest(param_extra: &str) -> String {
    format!(
        r#"
id = "selfhosted"
version = 1
title = "Self-hosted"
base_url = "https://{{host}}/api/v4"
hosts = ["{{host}}"]
auth = [{{ kind = "bearer", secret_field = "token" }}]
request_headers = ["Accept"]

[params.host]
type = "string"
{param_extra}

[[operation]]
id = "projects.list"
capability = "projects:read"
kind = "read"
method = "GET"
path = "/projects"
"#
    )
}

fn pinned() -> Manifest {
    Manifest::parse(&host_manifest(&format!(
        "pattern = '{HOSTNAME_RE}'\nrequired = true"
    )))
    .unwrap()
}

// ---------------------------------------------------------------- hosts

struct AnyPort(u16);

impl Resolver for AnyPort {
    fn resolve(&self, host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
        if host == "gitlab.acme.test" || host == "other.test" {
            Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, self.0))])
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "unknown test host"))
        }
    }
}

/// A loopback TLS server for `gitlab.acme.test` that redirects every
/// request to `other.test`.
async fn redirecting_server() -> (Upstream, Arc<AtomicUsize>) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![
        "gitlab.acme.test".to_string(),
        "other.test".to_string(),
    ])
    .unwrap()
    .signed_by(&leaf_key, &ca)
    .unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    )
    .unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let hits = Arc::new(AtomicUsize::new(0));
    let hits2 = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let hits = hits2.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let svc = service_fn(move |_req: Request<Incoming>| {
                    hits.fetch_add(1, Ordering::SeqCst);
                    async {
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(302)
                                .header("location", "https://other.test/api/v4/projects")
                                .body(Full::new(Bytes::from_static(b"moved")))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let up = Upstream::with_roots(roots, Arc::new(AnyPort(port)), Duration::from_secs(5));
    (up, hits)
}

#[tokio::test]
async fn host_placeholder_pins_admin_host() {
    let m = pinned();
    let op = named(&m, "projects.list").unwrap();
    let tok = concat!("glpat", "-", "pinned0000");
    let b = build(
        &m,
        op,
        &map(&[("host", "gitlab.acme.test")]),
        &BTreeMap::new(),
        &[],
        None,
        &material(&m, &[("token", tok)]),
    )
    .unwrap();
    assert_eq!(b.uri.host(), Some("gitlab.acme.test"));
    assert_eq!(b.uri.path(), "/api/v4/projects");
    // A value the pattern refuses never forms a URL.
    let err = build(
        &m,
        op,
        &map(&[("host", "gitlab.acme.test@evil.test")]),
        &BTreeMap::new(),
        &[],
        None,
        &material(&m, &[("token", tok)]),
    )
    .unwrap_err();
    assert!(matches!(err, BrokerError::BadValue { .. }), "{err:?}");
    // The upstream redirects to another host: refused before it connects.
    let (up, hits) = redirecting_server().await;
    let err = up.send(b, 4096).await.unwrap_err();
    assert!(matches!(err, BrokerError::RedirectRefused), "{err:?}");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

fn cfg_with_host(value: &str) -> SystemConfig {
    let text = format!(
        "version = 2\n[services.gl]\nconnector = \"selfhosted\"\nparams = {{ host = {} }}\n",
        toml::Value::String(value.to_string())
    );
    toml::from_str(&text).unwrap()
}

#[test]
fn host_param_must_be_bare_hostname() {
    // A loose (but anchored) pattern: the bare-hostname check still holds.
    let loose = Manifest::parse(&host_manifest("pattern = '^.*$'\nrequired = true")).unwrap();
    for m in [pinned(), loose] {
        let cat = Catalog::new(&[], vec![m]);
        catalog::validate(&cfg_with_host("gitlab.acme.com"), &cat).unwrap();
        for bad in [
            "gitlab.acme.com@evil.test",
            "evil.test/x",
            "evil.test:8443",
            "EVIL.test.",
            "evil.test.",
            "Evil.test",
            "",
            "-x.test",
            "a..b",
        ] {
            let err = catalog::validate(&cfg_with_host(bad), &cat).unwrap_err();
            assert!(
                matches!(err, BrokerError::BadValue { .. }),
                "{bad:?}: {err:?}"
            );
        }
    }
}

#[test]
fn host_placeholder_needs_required_pattern() {
    for extra in [
        format!("pattern = '{HOSTNAME_RE}'"),
        "required = true".to_string(),
        // Not anchored.
        "pattern = '[a-z.]+'\nrequired = true".to_string(),
    ] {
        let err = Manifest::parse(&host_manifest(&extra)).unwrap_err();
        assert!(matches!(err, BrokerError::Manifest(_)), "{extra}: {err:?}");
    }
    // The base_url host must be exactly the placeholder.
    let text = host_manifest(&format!("pattern = '{HOSTNAME_RE}'\nrequired = true"))
        .replace("https://{host}/api/v4", "https://{host}.evil.test/api/v4");
    assert!(Manifest::parse(&text).is_err());
    // An undeclared host placeholder.
    let text = host_manifest(&format!("pattern = '{HOSTNAME_RE}'\nrequired = true"))
        .replace("hosts = [\"{host}\"]", "hosts = [\"{nohost}\"]");
    assert!(Manifest::parse(&text).is_err());
}

#[test]
fn whole_host_param_checked_against_fixed_list() {
    // Intercom-like: the admin picks one of the listed regional hosts.
    let m = Manifest::parse(
        r#"
id = "regional"
version = 1
title = "Regional"
base_url = "https://{region_host}"
hosts = ["api.one.test", "api.eu.one.test"]
auth = [{ kind = "bearer", secret_field = "token" }]

[params.region_host]
type = "string"
required = true

[[operation]]
id = "me"
capability = "me:read"
kind = "read"
method = "GET"
path = "/me"
"#,
    )
    .unwrap();
    let op = named(&m, "me").unwrap();
    let tok = concat!("tok", "-", "regional");
    let call = |h: &str| {
        build(
            &m,
            op,
            &map(&[("region_host", h)]),
            &BTreeMap::new(),
            &[],
            None,
            &material(&m, &[("token", tok)]),
        )
    };
    assert_eq!(
        call("api.eu.one.test").unwrap().uri.host(),
        Some("api.eu.one.test")
    );
    assert!(matches!(
        call("api.evil.test").unwrap_err(),
        BrokerError::HostNotAllowed
    ));
}

// ---------------------------------------------------------------- auth

fn auth_manifest(auth: &str, extra: &str) -> Result<Manifest, BrokerError> {
    Manifest::parse(&format!(
        r#"
id = "authy"
version = 1
title = "Authy"
base_url = "https://api.authy.test"
hosts = ["api.authy.test"]
auth = [{auth}]
request_headers = ["Accept", "From", "Content-Type"]
{extra}

[[operation]]
id = "things.list"
capability = "things:read"
kind = "read"
method = "GET"
path = "/things"
"#
    ))
}

fn build_list(m: &Manifest, svc: &[(&str, &str)], agent: &[(&str, &str)], tok: &str) -> HeaderMap {
    let op = named(m, "things.list").unwrap();
    build(
        m,
        op,
        &map(svc),
        &BTreeMap::new(),
        &hdrs(agent),
        None,
        &material(m, &[("token", tok)]),
    )
    .unwrap()
    .headers
}

#[test]
fn header_prefix_applied() {
    let m = auth_manifest(
        r#"{ kind = "header", name = "Authorization", prefix = "Token token=", secret_field = "token" }"#,
        "",
    )
    .unwrap();
    let tok = concat!("pd", "-", "prefix-77");
    let h = build_list(&m, &[], &[], tok);
    assert_eq!(
        h.get("authorization").unwrap(),
        &format!("Token token={tok}")
    );
    assert!(h.get("authorization").unwrap().is_sensitive());
    // Bot prefix, and a header without a prefix stays raw.
    let m = auth_manifest(
        r#"{ kind = "header", name = "Authorization", secret_field = "token" }"#,
        "",
    )
    .unwrap();
    assert_eq!(
        build_list(&m, &[], &[], tok).get("authorization").unwrap(),
        tok
    );
    // A prefix must be printable ASCII.
    for p in ["T\\n", "T\\u00e9"] {
        let a = format!(
            r#"{{ kind = "header", name = "Authorization", prefix = "{p}", secret_field = "token" }}"#
        );
        assert!(auth_manifest(&a, "").is_err(), "{p}");
    }
}

#[test]
fn prefix_refused_on_bearer() {
    for kind in ["bearer", "basic", "basic_token"] {
        let a = format!(r#"{{ kind = "{kind}", prefix = "X ", secret_field = "token" }}"#);
        let err = auth_manifest(&a, "").unwrap_err();
        assert!(matches!(err, BrokerError::Manifest(_)), "{kind}: {err:?}");
    }
    // token_path belongs to oauth2 only, and oauth2 needs one.
    assert!(auth_manifest(
        r#"{ kind = "bearer", token_path = "/t", secret_field = "token" }"#,
        ""
    )
    .is_err());
    assert!(auth_manifest(r#"{ kind = "oauth2" }"#, "").is_err());
    assert!(auth_manifest(
        r#"{ kind = "oauth2", token_path = "/services/oauth2/token" }"#,
        ""
    )
    .is_ok());
}

#[test]
fn basic_token_encodes_token_colon() {
    let m = auth_manifest(r#"{ kind = "basic_token", secret_field = "token" }"#, "").unwrap();
    let key = concat!("wk", "_", "segment123");
    let h = build_list(&m, &[], &[], key);
    let want = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{key}:"))
    );
    assert_eq!(h.get("authorization").unwrap(), &want);
    // The masker gets the wire pair too.
    let vals: Vec<String> = material(&m, &[("token", key)])
        .values()
        .iter()
        .map(|v| v.to_string())
        .collect();
    assert!(vals.contains(&format!("{key}:")), "{vals:?}");
}

#[test]
fn fixed_headers_override_agent() {
    let m = auth_manifest(
        r#"{ kind = "bearer", secret_field = "token" }"#,
        r#"headers = { Accept = "application/vnd.pagerduty+json;version=2", From = "{from}" }

[params.from]
type = "string"
required = true
"#,
    )
    .unwrap();
    let tok = concat!("tok", "-", "fixed");
    let h = build_list(
        &m,
        &[("from", "ops@acme.test")],
        &[("From", "x"), ("Accept", "text/plain")],
        tok,
    );
    let from: Vec<_> = h.get_all("from").iter().collect();
    assert_eq!(from, ["ops@acme.test"]);
    assert_eq!(
        h.get("accept").unwrap(),
        "application/vnd.pagerduty+json;version=2"
    );
    // A fixed header may not set credentials or framing, nor use an
    // undeclared param.
    for bad in [
        r#"headers = { Authorization = "x" }"#,
        r#"headers = { Host = "x" }"#,
        r#"headers = { Content-Length = "1" }"#,
        r#"headers = { X-A = "{nope}" }"#,
        r#"headers = { "Bad Name" = "x" }"#,
    ] {
        assert!(
            auth_manifest(r#"{ kind = "bearer", secret_field = "token" }"#, bad).is_err(),
            "{bad}"
        );
    }
}

// ---------------------------------------------------------------- bodies

fn body_manifest(ops: &str) -> Manifest {
    Manifest::parse(&format!(
        r#"
id = "bodies"
version = 1
title = "Bodies"
base_url = "https://api.bodies.test"
hosts = ["api.bodies.test"]
auth = [{{ kind = "bearer", secret_field = "token" }}]

[params.currency]
type = "string"
pattern = "^[A-Z]{{3}}$"

{ops}
"#
    ))
    .unwrap()
}

const INCIDENT_OP: &str = r#"
[[operation]]
id = "incidents.create"
capability = "incidents:write"
kind = "write"
method = "POST"
path = "/incidents"
body = "json"
body_params = { "incident.title" = "string", "incident.urgency" = "enum:high,low", "incident.priority" = "int" }
body_const = { "incident.type" = "incident" }
"#;

#[test]
fn body_params_build_nested_json() {
    let m = body_manifest(INCIDENT_OP);
    let op = named(&m, "incidents.create").unwrap();
    let v = build_body(
        op,
        &map(&[("incident.title", "Down"), ("incident.priority", "2")]),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        v,
        json!({"incident": {"title": "Down", "type": "incident", "priority": 2}})
    );
    // Body params are validated like query params.
    let err =
        saiife_broker::params::validate(op, &map(&[("incident.urgency", "meh")]), &BTreeMap::new())
            .unwrap_err();
    assert!(matches!(err, BrokerError::BadValue { .. }), "{err:?}");
    assert!(saiife_broker::params::validate(
        op,
        &map(&[("incident.urgency", "high")]),
        &BTreeMap::new()
    )
    .is_ok());
    // A body param colliding with a constant, or nesting under a scalar.
    for bad in [
        r#"body_params = { "a.b" = "string" }
body_const = { "a.b" = 1 }"#,
        r#"body_params = { "a.b" = "string" }
body_const = { "a" = 1 }"#,
        r#"body_params = { "a" = "string", "a.b" = "string" }"#,
        r#"body_params = { "a..b" = "string" }"#,
        r#"body_params = { "a" = "nope" }"#,
    ] {
        let text = format!(
            "id = \"b\"\nversion = 1\ntitle = \"B\"\nbase_url = \"https://b.test\"\nhosts = [\"b.test\"]\n\
             [[operation]]\nid = \"x\"\ncapability = \"x:write\"\nkind = \"write\"\nmethod = \"POST\"\n\
             path = \"/x\"\nbody = \"json\"\n{bad}\n"
        );
        assert!(Manifest::parse(&text).is_err(), "{bad}");
    }
}

#[test]
fn raw_body_refused_when_body_params() {
    let m = body_manifest(INCIDENT_OP);
    let op = named(&m, "incidents.create").unwrap();
    let raw = Bytes::from_static(br#"{"incident":{"title":"agent"}}"#);
    assert_eq!(
        prepare_body(op, &map(&[("incident.title", "x")]), Some(&raw)).unwrap_err(),
        "bad_param"
    );
    // Without a raw body the built one is sent, as canonical JSON.
    let p = prepare_body(op, &map(&[("incident.title", "x")]), None).unwrap();
    assert_eq!(
        p.bytes.as_deref(),
        Some(&br#"{"incident":{"title":"x","type":"incident"}}"#[..])
    );
    assert_eq!(p.content_type, Some("application/json"));
}

const GRAPHQL_OPS: &str = r#"
[[operation]]
id = "issues.list"
capability = "issues:read"
kind = "read"
method = "POST"
path = "/graphql"
body = "json"
graphql = "query($first: Int, $after: String) { issues(first: $first, after: $after) { nodes { id } } }"
body_params = { first = "int:1..250", after = "string" }

[[operation]]
id = "issues.create"
capability = "issues:write"
kind = "write"
method = "POST"
path = "/graphql"
body = "json"
graphql = "mutation($title: String!) { issueCreate(input: { title: $title }) { success } }"
body_params = { title = "string" }
"#;

#[test]
fn graphql_envelope() {
    let m = body_manifest(GRAPHQL_OPS);
    let op = named(&m, "issues.list").unwrap();
    let v = build_body(op, &map(&[("first", "10"), ("after", "x")]))
        .unwrap()
        .unwrap();
    assert_eq!(
        v,
        json!({
            "query": "query($first: Int, $after: String) { issues(first: $first, after: $after) { nodes { id } } }",
            "variables": {"first": 10, "after": "x"}
        })
    );
    // The agent can never send its own GraphQL.
    let raw = Bytes::from_static(br#"{"query":"mutation { evil }"}"#);
    assert_eq!(
        prepare_body(op, &BTreeMap::new(), Some(&raw)).unwrap_err(),
        "bad_param"
    );
    // No variables given: an empty object.
    let v = build_body(op, &BTreeMap::new()).unwrap().unwrap();
    assert_eq!(v["variables"], json!({}));
}

#[test]
fn graphql_op_not_reachable_by_proxy() {
    let m = body_manifest(GRAPHQL_OPS);
    let err = proxy(&m, "POST", "/graphql").unwrap_err();
    assert!(matches!(err, BrokerError::UnknownOperation(_)), "{err:?}");
}

#[test]
fn two_graphql_ops_same_path_allowed() {
    let m = body_manifest(GRAPHQL_OPS);
    assert_eq!(m.operation.len(), 2);
    // Two plain operations with the same shape are still refused.
    let dup = GRAPHQL_OPS.replace("graphql = ", "# graphql = ");
    let text = format!(
        "id = \"g\"\nversion = 1\ntitle = \"G\"\nbase_url = \"https://g.test\"\nhosts = [\"g.test\"]\n{dup}"
    );
    assert!(Manifest::parse(&text).is_err());
    // graphql needs a JSON body.
    let form = GRAPHQL_OPS.replace("body = \"json\"", "body = \"form\"");
    let text = format!(
        "id = \"g\"\nversion = 1\ntitle = \"G\"\nbase_url = \"https://g.test\"\nhosts = [\"g.test\"]\n{form}"
    );
    assert!(Manifest::parse(&text).is_err());
}

#[test]
fn qualifier_from_body_param() {
    let m = body_manifest(
        r#"
[[operation]]
id = "chat.postMessage"
capability = "messages:write"
qualifier = "channel={channel}"
kind = "write"
method = "POST"
path = "/chat.postMessage"
body = "json"
body_params = { channel = "string:[A-Z0-9]{1,32}", text = "string" }
"#,
    );
    let op = named(&m, "chat.postMessage").unwrap();
    let params = saiife_broker::params::validate(
        op,
        &map(&[("channel", "C1"), ("text", "hi")]),
        &BTreeMap::new(),
    )
    .unwrap();
    let q = saiife_broker::manifest::qualifier_for(op, &params).unwrap();
    assert_eq!(
        format!("{}:{q}", op.capability),
        "messages:write:channel=C1"
    );
}

#[test]
fn form_encode_stripe_nesting() {
    let v = json!({"metadata": {"a": "1"}, "amount": 500});
    assert_eq!(form_encode(&v).unwrap(), "amount=500&metadata%5Ba%5D=1");
    let v = json!({"items": [{"price": "p_1"}, {"price": "p 2"}], "ok": true});
    assert_eq!(
        form_encode(&v).unwrap(),
        "items%5B0%5D%5Bprice%5D=p_1&items%5B1%5D%5Bprice%5D=p%202&ok=true"
    );
    assert!(form_encode(&json!([1])).is_err());
    assert!(form_encode(&json!({"a": null})).is_err());
}

const REFUND_OP: &str = r#"
[[operation]]
id = "refunds.create"
capability = "refunds:write"
kind = "write"
method = "POST"
path = "/v1/refunds"
body = "form"
body_params = { charge = "string", amount = "int:1.." }
body_const = { "metadata.source" = "saiife" }
amount = { field = "amount", currency_param = "currency", unit = "minor" }
"#;

#[test]
fn form_body_amount_checked_and_hash_of_sent_bytes() {
    let m = body_manifest(REFUND_OP);
    let op = named(&m, "refunds.create").unwrap();
    let svc = map(&[("currency", "EUR")]);
    let p = prepare_body(op, &map(&[("charge", "ch_1"), ("amount", "1250")]), None).unwrap();
    let sent = p.bytes.clone().unwrap();
    assert_eq!(
        &sent[..],
        b"amount=1250&charge=ch_1&metadata%5Bsource%5D=saiife"
    );
    assert_eq!(p.content_type, Some("application/x-www-form-urlencoded"));
    // The recorded hash is of the bytes sent, not of the JSON.
    let want: String = Sha256::digest(&sent)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(p.sha256().unwrap(), want);
    // The amount comes from the JSON before encoding.
    let spec = op.amount.as_ref().unwrap();
    assert_eq!(
        amount::extract(spec, p.json.as_ref().unwrap(), &svc).unwrap(),
        (1250, "EUR".to_string())
    );
    // A refund without an amount fails closed.
    let p = prepare_body(op, &map(&[("charge", "ch_1")]), None).unwrap();
    assert!(matches!(
        amount::extract(spec, p.json.as_ref().unwrap(), &svc),
        Err(BrokerError::BadAmount(_))
    ));
    // A raw agent body on a form op without body_params: strict JSON,
    // form-encoded, and kept as canonical JSON for a later approval.
    let m = body_manifest(
        r#"
[[operation]]
id = "charges.create"
capability = "charges:write"
kind = "write"
method = "POST"
path = "/v1/charges"
body = "form"
"#,
    );
    let op = named(&m, "charges.create").unwrap();
    let raw = Bytes::from_static(br#"{ "b": 2, "a": {"x": "y"} }"#);
    let p = prepare_body(op, &BTreeMap::new(), Some(&raw)).unwrap();
    assert_eq!(p.bytes.as_deref(), Some(&b"a%5Bx%5D=y&b=2"[..]));
    let again = prepare_body(op, &BTreeMap::new(), p.input.as_ref()).unwrap();
    assert_eq!(again.bytes, p.bytes);
    let dup = Bytes::from_static(br#"{"a":1,"a":2}"#);
    assert_eq!(
        prepare_body(op, &BTreeMap::new(), Some(&dup)).unwrap_err(),
        "bad_body"
    );
}

#[test]
fn currency_param_amount() {
    let spec = AmountSpec {
        field: "amount".into(),
        currency_field: None,
        currency_param: Some("currency".into()),
        unit: Unit::Minor,
    };
    let svc = map(&[("currency", "EUR")]);
    assert_eq!(
        amount::extract(&spec, &json!({"amount": 1250}), &svc).unwrap(),
        (1250, "EUR".to_string())
    );
    // Lower case is upper-cased; a missing or unknown currency is refused.
    assert_eq!(
        amount::extract(&spec, &json!({"amount": 5}), &map(&[("currency", "eur")]))
            .unwrap()
            .1,
        "EUR"
    );
    assert!(amount::extract(&spec, &json!({"amount": 5}), &BTreeMap::new()).is_err());
    assert!(amount::extract(&spec, &json!({"amount": 5}), &map(&[("currency", "XAU")])).is_err());
    // currency_param must be a declared manifest param.
    let text = REFUND_OP.replace("currency_param = \"currency\"", "currency_param = \"nope\"");
    let full = format!(
        "id = \"b\"\nversion = 1\ntitle = \"B\"\nbase_url = \"https://b.test\"\nhosts = [\"b.test\"]\n{text}"
    );
    assert!(Manifest::parse(&full).is_err());
}

#[test]
fn both_currency_keys_refused() {
    for amount in [
        r#"amount = { field = "amount", currency_param = "currency", currency_field = "cur", unit = "minor" }"#,
        r#"amount = { field = "amount", unit = "minor" }"#,
    ] {
        let ops = format!(
            "[[operation]]\nid = \"r\"\ncapability = \"r:write\"\nkind = \"write\"\nmethod = \"POST\"\n\
             path = \"/r\"\nbody = \"json\"\n{amount}\n"
        );
        let text = format!(
            "id = \"b\"\nversion = 1\ntitle = \"B\"\nbase_url = \"https://b.test\"\nhosts = [\"b.test\"]\n\
             [params.currency]\ntype = \"string\"\n{ops}"
        );
        let err = Manifest::parse(&text).unwrap_err();
        assert!(matches!(err, BrokerError::Manifest(_)), "{amount}: {err:?}");
    }
}

// ---------------------------------------------------------------- pagination

fn cursor(next: &str, more: Option<&str>) -> Pagination {
    Pagination::Cursor {
        param: "starting_after".into(),
        next: next.into(),
        more: more.map(str::to_string),
    }
}

#[test]
fn cursor_more_false_stops() {
    let p = cursor("next_id", Some("has_more"));
    let body = json!({"next_id": "abc", "has_more": false});
    assert_eq!(next_cursor(&p, &body), None);
    let body = json!({"next_id": "abc", "has_more": true});
    assert_eq!(
        next_cursor(&p, &body),
        Some(("starting_after".into(), "abc".into()))
    );
    // `more` declared but missing or not a bool: the last page.
    assert_eq!(next_cursor(&p, &json!({"next_id": "abc"})), None);
    assert_eq!(
        next_cursor(&p, &json!({"next_id": "abc", "has_more": "yes"})),
        None
    );
}

#[test]
fn cursor_last_element_path() {
    let p = cursor("data[-1].id", Some("has_more"));
    let body = json!({"data": [{"id": "ch_1"}, {"id": "ch_2"}], "has_more": true});
    assert_eq!(
        next_cursor(&p, &body),
        Some(("starting_after".into(), "ch_2".into()))
    );
    assert_eq!(
        next_cursor(&p, &json!({"data": [], "has_more": true})),
        None
    );
    // Manifest check: only `[-1]` is allowed as an index.
    for next in ["data[0].id", "data[].id", "data[-1"] {
        let text = format!(
            "id = \"p\"\nversion = 1\ntitle = \"P\"\nbase_url = \"https://p.test\"\nhosts = [\"p.test\"]\n\
             [[operation]]\nid = \"l\"\ncapability = \"l:read\"\nkind = \"read\"\nmethod = \"GET\"\n\
             path = \"/l\"\nquery = {{ starting_after = \"string\" }}\n\
             pagination = {{ cursor = {{ param = \"starting_after\", next = \"{next}\" }} }}\n"
        );
        assert!(Manifest::parse(&text).is_err(), "{next}");
    }
}

#[test]
fn empty_cursor_is_last_page() {
    let p = Pagination::Cursor {
        param: "cursor".into(),
        next: "response_metadata.next_cursor".into(),
        more: None,
    };
    assert_eq!(
        next_cursor(&p, &json!({"response_metadata": {"next_cursor": ""}})),
        None
    );
    assert_eq!(
        next_cursor(
            &p,
            &json!({"response_metadata": {"next_cursor": "dXNlcjpVMDYx="}})
        ),
        Some(("cursor".into(), "dXNlcjpVMDYx=".into()))
    );
}

#[test]
fn offset_next() {
    let p = Pagination::Offset {
        param: "offset".into(),
        limit_field: "limit".into(),
        more: "more".into(),
    };
    assert_eq!(
        next_cursor(&p, &json!({"offset": 25, "limit": 25, "more": true})),
        Some(("offset".into(), "50".into()))
    );
    assert_eq!(
        next_cursor(&p, &json!({"offset": 25, "limit": 25, "more": false})),
        None
    );
    assert_eq!(next_cursor(&p, &json!({"offset": 25, "more": true})), None);
    assert_eq!(
        next_cursor(&p, &json!({"offset": -5, "limit": 25, "more": true})),
        None
    );
    // The manifest form.
    let m = Manifest::parse(
        r#"
id = "pd"
version = 1
title = "PD"
base_url = "https://api.pd.test"
hosts = ["api.pd.test"]

[[operation]]
id = "incidents.list"
capability = "incidents:read"
kind = "read"
method = "GET"
path = "/incidents"
query = { offset = "int:0..", limit = "int:1..100" }
pagination = { offset = { param = "offset", limit_field = "limit", more = "more" } }
"#,
    )
    .unwrap();
    assert_eq!(m.operation[0].pagination, Some(p));
}

fn link_op() -> Manifest {
    Manifest::parse(
        r#"
id = "sentryish"
version = 1
title = "Sentry-ish"
base_url = "https://sentry.test/api/0"
hosts = ["sentry.test"]

[[operation]]
id = "issues.list"
capability = "issues:read"
kind = "read"
method = "GET"
path = "/projects/{org}/issues/"
path_params = { org = "string" }
query = { cursor = "string" }
pagination = "link-header"
"#,
    )
    .unwrap()
}

#[test]
fn link_results_false_is_last_page() {
    let m = link_op();
    let op = named(&m, "issues.list").unwrap();
    let given = map(&[("org", "acme")]);
    let mut h = HeaderMap::new();
    h.insert(
        "link",
        HeaderValue::from_static(
            "<https://sentry.test/api/0/projects/acme/issues/?cursor=0:0:1>; rel=\"previous\"; results=\"false\"; cursor=\"0:0:1\", \
             <https://sentry.test/api/0/projects/acme/issues/?cursor=0:100:0>; rel=\"next\"; results=\"false\"; cursor=\"0:100:0\"",
        ),
    );
    assert_eq!(next_from_link(op, &given, &h), None);
    let mut h = HeaderMap::new();
    h.insert(
        "link",
        HeaderValue::from_static(
            "<https://sentry.test/api/0/projects/acme/issues/?cursor=0:100:0>; rel=\"next\"; results=\"true\"; cursor=\"0:100:0\"",
        ),
    );
    assert_eq!(
        next_from_link(op, &given, &h),
        Some(map(&[("org", "acme"), ("cursor", "0:100:0")]))
    );
}

// ---------------------------------------------------------------- built-in list

#[test]
fn build_rs_lists_every_connector_file() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/connectors");
    let mut stems: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter_map(|n| n.strip_suffix(".toml").map(str::to_string))
        .filter(|s| s != "test-echo")
        .collect();
    stems.sort();
    let ids: Vec<String> = saiife_broker::builtin()
        .iter()
        .map(|m| m.id.clone())
        .collect();
    assert_eq!(ids, stems);
}

// ---------------------------------------------------------------- fix round 1

#[test]
fn form_keys_from_the_agent_cannot_nest() {
    // `refund[amount]` would decode upstream as the nested amount the
    // broker never checked.
    let smuggle = json!({"refund": {"amount": 100}, "refund[amount]": 99999});
    assert!(form_encode(&smuggle).is_err());
    for bad in [
        json!({"a": {"b.c": 1}}),
        json!({"a]": 1}),
        json!({"": 1}),
        json!({"a": [{"x[y]": 1}]}),
    ] {
        assert!(form_encode(&bad).is_err(), "{bad}");
    }
    let m = body_manifest(
        r#"
[[operation]]
id = "charges.create"
capability = "charges:write"
kind = "write"
method = "POST"
path = "/v1/charges"
body = "form"
"#,
    );
    let op = named(&m, "charges.create").unwrap();
    for raw in [
        &br#"{"refund":{"amount":100},"refund[amount]":99999}"#[..],
        // A duplicated name.
        &br#"{"refund":{"amount":100},"refund":{"amount":99999}}"#[..],
    ] {
        assert_eq!(
            prepare_body(op, &BTreeMap::new(), Some(&Bytes::copy_from_slice(raw))).unwrap_err(),
            "bad_body"
        );
    }
    // An amount-capped form operation must build its body.
    let text = "id = \"b\"\nversion = 1\ntitle = \"B\"\nbase_url = \"https://b.test\"\nhosts = [\"b.test\"]\n\
                [params.currency]\ntype = \"string\"\n\
                [[operation]]\nid = \"r\"\ncapability = \"r:write\"\nkind = \"write\"\nmethod = \"POST\"\n\
                path = \"/r\"\nbody = \"form\"\n\
                amount = { field = \"amount\", currency_param = \"currency\", unit = \"minor\" }\n";
    let err = Manifest::parse(text).unwrap_err();
    assert!(matches!(err, BrokerError::Manifest(_)), "{err:?}");
}

#[test]
fn multiline_body_param_allowed() {
    let m = body_manifest(
        r#"
[[operation]]
id = "messages.create"
capability = "messages:write"
kind = "write"
method = "POST"
path = "/channels/{channel_id}/messages"
path_params = { channel_id = "string:[0-9]{1,20}" }
query = { q = "string" }
body = "json"
body_params = { content = "string" }
"#,
    );
    let op = named(&m, "messages.create").unwrap();
    let content = "Deploy done:\n\t- web\n\t- api";
    let p = saiife_broker::params::validate(
        op,
        &map(&[("channel_id", "123"), ("content", content)]),
        &BTreeMap::new(),
    )
    .unwrap();
    let v = build_body(op, &p).unwrap().unwrap();
    assert_eq!(v["content"], content);
    // Other control characters stay refused, and so does a line break in a
    // path or query param.
    for (k, v) in [
        ("content", "a\rb"),
        ("content", "a\u{0}b"),
        ("content", "a\u{7f}"),
        ("q", "a\nb"),
        ("channel_id", "1\n2"),
    ] {
        let err = saiife_broker::params::validate(
            op,
            &map(&[("channel_id", "123"), (k, v)]),
            &BTreeMap::new(),
        )
        .unwrap_err();
        assert!(
            matches!(err, BrokerError::BadValue { .. }),
            "{k}={v:?}: {err:?}"
        );
    }
}

#[test]
fn qualifier_params_refuse_control_characters() {
    let m = body_manifest(
        r#"
[[operation]]
id = "chat.postMessage"
capability = "messages:write"
qualifier = "channel={channel}"
kind = "write"
method = "POST"
path = "/chat.postMessage"
body = "json"
body_params = { channel = "string", text = "string" }
"#,
    );
    let op = named(&m, "chat.postMessage").unwrap();
    for ch in ["general\nrandom", "general\trandom", "general\r"] {
        let err = saiife_broker::params::validate(
            op,
            &map(&[("channel", ch), ("text", "hi")]),
            &BTreeMap::new(),
        )
        .unwrap_err();
        assert!(
            matches!(err, BrokerError::BadValue { ref name, .. } if name == "channel"),
            "{ch:?}: {err:?}"
        );
    }
    // The message text in the same op may still span lines.
    let p = saiife_broker::params::validate(
        op,
        &map(&[("channel", "general"), ("text", "line 1\nline 2\tend")]),
        &BTreeMap::new(),
    )
    .unwrap();
    assert_eq!(
        saiife_broker::manifest::qualifier_for(op, &p).as_deref(),
        Some("channel=general")
    );
}

#[test]
fn host_param_refuses_ip_literals() {
    for ip in ["169.254.169.254", "127.0.0.1", "10.0.0.1", "::1", "fe80::1"] {
        assert!(!saiife_broker::request::bare_hostname(ip), "{ip}");
    }
    assert!(saiife_broker::request::bare_hostname("gitlab.acme.com"));
    assert!(saiife_broker::request::bare_hostname(
        "1password.example.com"
    ));
    // The manifest pattern would let the digits through; the check does not.
    let cat = Catalog::new(&[], vec![pinned()]);
    for ip in ["169.254.169.254", "127.0.0.1"] {
        let err = catalog::validate(&cfg_with_host(ip), &cat).unwrap_err();
        assert!(matches!(err, BrokerError::BadValue { .. }), "{ip}: {err:?}");
    }
}

#[test]
fn pagination_param_must_be_an_op_param() {
    let manifest = |query: &str, pagination: &str| {
        Manifest::parse(&format!(
            "id = \"p\"\nversion = 1\ntitle = \"P\"\nbase_url = \"https://p.test\"\nhosts = [\"p.test\"]\n\
             [[operation]]\nid = \"l\"\ncapability = \"l:read\"\nkind = \"read\"\nmethod = \"GET\"\n\
             path = \"/l\"\nquery = {{ {query} }}\npagination = {pagination}\n"
        ))
    };
    let cursor = "{ cursor = { param = \"after\", next = \"next\" } }";
    let offset = "{ offset = { param = \"offset\", limit_field = \"limit\", more = \"more\" } }";
    assert!(manifest("after = \"string\"", cursor).is_ok());
    assert!(manifest("before = \"string\"", cursor).is_err());
    assert!(manifest("offset = \"int:0..\"", offset).is_ok());
    assert!(manifest("limit = \"int\"", offset).is_err());
}

#[test]
fn transport_mail_refused_until_task_6() {
    let text = "id = \"m\"\nversion = 1\ntitle = \"M\"\nbase_url = \"https://m.test\"\nhosts = [\"m.test\"]\ntransport = \"mail\"\n";
    assert!(Manifest::parse(text).is_err());
    let text = text.replace("\"mail\"", "\"https\"");
    assert!(Manifest::parse(&text).is_ok());
    // `body = "text"` is mail only.
    let text = "id = \"m\"\nversion = 1\ntitle = \"M\"\nbase_url = \"https://m.test\"\nhosts = [\"m.test\"]\n\
                [[operation]]\nid = \"s\"\ncapability = \"s:write\"\nkind = \"write\"\nmethod = \"POST\"\npath = \"/s\"\nbody = \"text\"\n";
    assert!(Manifest::parse(text).is_err());
}
