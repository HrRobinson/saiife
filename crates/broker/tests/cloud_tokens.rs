//! The GCP and Azure token exchanges (plan 15, Task 6) against a loopback
//! hyper server with `rcgen` certificates for the real token hosts. The
//! test resolver maps those names to 127.0.0.1; nothing leaves the host.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use ring::signature::{RsaKeyPair, UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;
use saiife_broker::cloud::jwt::{assertion, parse_gcp_key};
use saiife_broker::cloud::token::{
    azure_request, gcp_request, mint, parse_token_response, GCP_TOKEN_URL,
};
use saiife_broker::cloud::CloudError;
use saiife_broker::upstream::{Resolver, Upstream};
use saiife_broker::BrokerError;
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use time::OffsetDateTime;
use tokio::net::TcpListener;
use zeroize::Zeroizing;

const GCP_HOST: &str = "oauth2.googleapis.com";
const AZURE_HOSTS: [&str; 3] = [
    "login.microsoftonline.com",
    "login.microsoftonline.us",
    "login.chinacloudapi.cn",
];
const SCOPE_GCS: &str = "https://www.googleapis.com/auth/devstorage.read_write";
const SCOPE_ARM: &str = "https://management.azure.com/.default";
const EMAIL: &str = "robot@proj-1.iam.gserviceaccount.com";
const KEY_ID: &str = "0123456789abcdef0123456789abcdef01234567";
const TENANT: &str = "11111111-2222-3333-4444-555555555555";
const CLIENT_ID: &str = "66666666-7777-8888-9999-000000000000";
/// Built at runtime: no token-shaped literal in the source.
const ACCESS: &str = concat!("mock", "-access-", "token-0042");
const CLIENT_SECRET: &str = concat!("az", "-client-secret~", "Qz9.x");

// ---------------------------------------------------------------- fixtures

/// A throwaway 2048-bit RSA test key (decision 15), made once with
/// `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048` and
/// `openssl pkcs8 -topk8 -nocrypt`, committed as hex DER.
fn key_der() -> Vec<u8> {
    let hex: String = include_str!("fixtures/gcp/test-rsa-2048.pk8.hex")
        .split_whitespace()
        .collect();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// The PKCS#8 PEM, built at runtime.
fn key_pem() -> String {
    let b64 = STANDARD.encode(key_der());
    let mut pem = String::from(concat!("-----BEGIN ", "PRIVATE KEY-----\n"));
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str(concat!("-----END ", "PRIVATE KEY-----\n"));
    pem
}

fn fields(pairs: &[(&str, &str)]) -> BTreeMap<String, Zeroizing<String>> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), Zeroizing::new(v.to_string())))
        .collect()
}

fn gcp_fields() -> BTreeMap<String, Zeroizing<String>> {
    let pem = key_pem();
    fields(&[
        ("client_email", EMAIL),
        ("private_key_id", KEY_ID),
        ("private_key", &pem),
        ("project_id", "proj-1"),
    ])
}

fn azure_fields() -> BTreeMap<String, Zeroizing<String>> {
    fields(&[
        ("tenant_id", TENANT),
        ("client_id", CLIENT_ID),
        ("client_secret", CLIENT_SECRET),
    ])
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
}

/// Every secret-bearing string of a run: the PEM (and its base64 lines),
/// the client secret, the minted token.
fn secrets(extra: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = key_pem()
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .map(str::to_string)
        .collect();
    v.push(STANDARD.encode(key_der()));
    v.push(CLIENT_SECRET.to_string());
    v.push(ACCESS.to_string());
    v.extend(extra.iter().map(|s| s.to_string()));
    v
}

fn assert_clean(what: &str, text: &str, secrets: &[String]) {
    for s in secrets {
        assert!(!text.contains(s.as_str()), "{what} holds a secret: {text}");
    }
}

// ---------------------------------------------------------------- the mock

struct Pki {
    ca: CertificateDer<'static>,
    leaf: CertificateDer<'static>,
    leaf_key: PrivatePkcs8KeyDer<'static>,
}

fn pki() -> Pki {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let mut names = vec![GCP_HOST.to_string(), "evil.example.test".to_string()];
    names.extend(AZURE_HOSTS.iter().map(|h| h.to_string()));
    let leaf = CertificateParams::new(names)
        .unwrap()
        .signed_by(&leaf_key, &ca)
        .unwrap();
    Pki {
        ca: ca.der().clone(),
        leaf: leaf.der().clone(),
        leaf_key: PrivatePkcs8KeyDer::from(leaf_key.serialize_der()),
    }
}

/// Maps the token hosts to the mock (any port, as the pinned URLs have
/// none); everything else fails.
struct Loopback {
    port: u16,
}

impl Resolver for Loopback {
    fn resolve(&self, host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
        if host == GCP_HOST || AZURE_HOSTS.contains(&host) || host == "evil.example.test" {
            Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, self.port))])
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "unknown test host"))
        }
    }
}

#[derive(Clone, Debug)]
struct Seen {
    host: String,
    path: String,
    content_type: String,
    body: String,
}

/// What the mock answers: status, extra headers, body.
type Answer = (u16, Vec<(&'static str, String)>, Vec<u8>);

struct Mock {
    seen: Arc<Mutex<Vec<Seen>>>,
    answer: Arc<Mutex<Answer>>,
    up: Upstream,
}

fn ok_body() -> Vec<u8> {
    format!(r#"{{"access_token":"{ACCESS}","expires_in":3599,"token_type":"Bearer"}}"#).into_bytes()
}

async fn mock() -> Mock {
    let pki = pki();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![pki.leaf.clone()],
        PrivateKeyDer::Pkcs8(pki.leaf_key.clone_key()),
    )
    .unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let answer = Arc::new(Mutex::new((200, Vec::new(), ok_body())));
    let (seen2, answer2) = (seen.clone(), answer.clone());
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let (seen, answer) = (seen2.clone(), answer2.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let svc = service_fn(move |req: Request<Incoming>| {
                    let (seen, answer) = (seen.clone(), answer.clone());
                    async move {
                        let (parts, body) = req.into_parts();
                        let body = body.collect().await.unwrap().to_bytes();
                        let hv = |n: &str| {
                            parts
                                .headers
                                .get(n)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string()
                        };
                        seen.lock().unwrap().push(Seen {
                            host: hv("host"),
                            path: parts.uri.path().to_string(),
                            content_type: hv("content-type"),
                            body: String::from_utf8_lossy(&body).into_owned(),
                        });
                        let (status, headers, b) = answer.lock().unwrap().clone();
                        let mut r = Response::builder().status(status);
                        for (k, v) in headers {
                            r = r.header(k, v);
                        }
                        Ok::<_, Infallible>(r.body(Full::new(Bytes::from(b))).unwrap())
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    let mut roots = RootCertStore::empty();
    roots.add(pki.ca.clone()).unwrap();
    let up = Upstream::with_roots(roots, Arc::new(Loopback { port }), Duration::from_secs(5));
    Mock { seen, answer, up }
}

impl Mock {
    fn answer(&self, status: u16, headers: Vec<(&'static str, String)>, body: Vec<u8>) {
        *self.answer.lock().unwrap() = (status, headers, body);
    }
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

/// `application/x-www-form-urlencoded` into pairs.
fn form(body: &str) -> BTreeMap<String, String> {
    body.split('&')
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap();
            let v = percent_encoding::percent_decode_str(v)
                .decode_utf8()
                .unwrap()
                .into_owned();
            (k.to_string(), v)
        })
        .collect()
}

/// Checks an RS256 JWT with the fixture's public key and returns its
/// header and claims.
fn verify_jwt(jwt: &str) -> (serde_json::Value, serde_json::Value) {
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "a JWT has three parts");
    let pair = RsaKeyPair::from_pkcs8(&key_der()).unwrap();
    let public = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, pair.public().as_ref());
    let sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
    let signed = format!("{}.{}", parts[0], parts[1]);
    public
        .verify(signed.as_bytes(), &sig)
        .expect("the signature verifies with the public key");
    // A changed claim no longer verifies.
    assert!(public
        .verify(format!("{signed}x").as_bytes(), &sig)
        .is_err());
    let dec = |s: &str| -> serde_json::Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(s).unwrap()).unwrap()
    };
    (dec(parts[0]), dec(parts[1]))
}

// ---------------------------------------------------------------- tests

#[tokio::test]
async fn gcp_assertion_verifies_with_public_key() {
    let m = mock().await;
    let key = parse_gcp_key(&gcp_fields()).unwrap();
    let t = mint(&m.up, gcp_request(&key, SCOPE_GCS, now()).unwrap())
        .await
        .unwrap();
    assert_eq!(t.access.as_str(), ACCESS);

    let seen = m.seen();
    assert_eq!(seen.len(), 1);
    let f = form(&seen[0].body);
    assert_eq!(
        f["grant_type"],
        "urn:ietf:params:oauth:grant-type:jwt-bearer"
    );
    assert_eq!(f.len(), 2, "{:?}", f.keys());
    let (header, claims) = verify_jwt(&f["assertion"]);
    assert_eq!(header["alg"], "RS256");
    assert_eq!(header["typ"], "JWT");
    assert_eq!(header["kid"], KEY_ID);
    assert_eq!(claims["iss"], EMAIL);
    assert_eq!(claims["aud"], GCP_TOKEN_URL);
    assert_eq!(claims["aud"], "https://oauth2.googleapis.com/token");
    assert_eq!(claims["scope"], SCOPE_GCS);
    let iat = claims["iat"].as_i64().unwrap();
    assert_eq!(iat, now().unix_timestamp());
    assert_eq!(claims["exp"].as_i64().unwrap() - iat, 3600);
    assert!(claims.get("sub").is_none());

    // The same assertion, made directly, also verifies.
    let jwt = assertion(&key, SCOPE_GCS, now()).unwrap();
    let (_, c) = verify_jwt(&jwt);
    assert_eq!(c["scope"], SCOPE_GCS);
}

#[tokio::test]
async fn gcp_mint_against_loopback() {
    let m = mock().await;
    let mut f = gcp_fields();
    // A key file's own token_uri is never used: the endpoint is pinned.
    f.insert(
        "token_uri".into(),
        Zeroizing::new("https://evil.example.test/token".into()),
    );
    let key = parse_gcp_key(&f).unwrap();
    let d = format!("{key:?}");
    assert!(d.contains(EMAIL), "{d}");
    assert_clean("GcpKey Debug", &d, &secrets(&[KEY_ID]));

    let req = gcp_request(&key, SCOPE_GCS, now()).unwrap();
    assert_eq!(req.uri.to_string(), GCP_TOKEN_URL);
    let rd = format!("{req:?}");
    let body = std::str::from_utf8(req.body.as_ref().unwrap())
        .unwrap()
        .to_string();
    let jwt = form(&body)["assertion"].clone();
    assert_clean("Built Debug", &rd, &secrets(&[&jwt]));

    let t = mint(&m.up, req).await.unwrap();
    assert_eq!(t.access.as_str(), ACCESS);
    assert_eq!(t.ttl, Duration::from_secs(3599));
    assert!(t.refresh.is_none());
    let seen = m.seen();
    assert_eq!(seen[0].host, GCP_HOST);
    assert_eq!(seen[0].path, "/token");
    assert_eq!(seen[0].content_type, "application/x-www-form-urlencoded");

    // Keys that are not usable are refused, naming the field only.
    let short = fields(&[("client_email", EMAIL), ("private_key_id", KEY_ID)]);
    let e = parse_gcp_key(&short).unwrap_err().to_string();
    assert!(e.contains("private_key"), "{e}");
    let mut bad = gcp_fields();
    let mangled = key_pem().replace('A', "B");
    bad.insert("private_key".into(), Zeroizing::new(mangled.clone()));
    let e = parse_gcp_key(&bad).unwrap_err();
    assert_clean("key error", &format!("{e} {e:?}"), &secrets(&[&mangled]));
    let mut pkcs1 = gcp_fields();
    pkcs1.insert(
        "private_key".into(),
        Zeroizing::new(
            key_pem()
                .replace("BEGIN PRIVATE", "BEGIN RSA PRIVATE")
                .replace("END PRIVATE", "END RSA PRIVATE"),
        ),
    );
    assert!(parse_gcp_key(&pkcs1).is_err(), "only PKCS#8 is accepted");
}

#[tokio::test]
async fn azure_mint_against_loopback() {
    let m = mock().await;
    m.answer(
        200,
        vec![],
        format!(
            r#"{{"token_type":"Bearer","expires_in":"3599","ext_expires_in":3599,"access_token":"{ACCESS}"}}"#
        )
        .into_bytes(),
    );
    let req = azure_request(&azure_fields(), None, SCOPE_ARM).unwrap();
    assert_eq!(
        req.uri.to_string(),
        format!("https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token")
    );
    assert_clean("Built Debug", &format!("{req:?}"), &secrets(&[]));
    let t = mint(&m.up, req).await.unwrap();
    assert_eq!(t.access.as_str(), ACCESS);
    assert_eq!(t.ttl, Duration::from_secs(3599));

    let seen = m.seen();
    assert_eq!(seen[0].host, "login.microsoftonline.com");
    assert_eq!(seen[0].path, format!("/{TENANT}/oauth2/v2.0/token"));
    assert_eq!(seen[0].content_type, "application/x-www-form-urlencoded");
    let f = form(&seen[0].body);
    assert_eq!(f["grant_type"], "client_credentials");
    assert_eq!(f["client_id"], CLIENT_ID);
    assert_eq!(f["client_secret"], CLIENT_SECRET);
    assert_eq!(f["scope"], SCOPE_ARM);
    assert_eq!(f.len(), 4);

    // A listed sovereign authority and a domain tenant.
    let mut f = azure_fields();
    f.insert(
        "tenant_id".into(),
        Zeroizing::new("contoso.onmicrosoft.us".into()),
    );
    let req = azure_request(&f, Some("login.microsoftonline.us"), SCOPE_ARM).unwrap();
    mint(&m.up, req).await.unwrap();
    let seen = m.seen();
    assert_eq!(seen[1].host, "login.microsoftonline.us");
    assert_eq!(seen[1].path, "/contoso.onmicrosoft.us/oauth2/v2.0/token");
}

#[test]
fn azure_authority_not_listed_refused() {
    for a in [
        "evil.example.test",
        "login.microsoftonline.com.evil.test",
        "login.microsoftonline.com:8443",
        "",
    ] {
        let e = azure_request(&azure_fields(), Some(a), SCOPE_ARM).unwrap_err();
        assert!(matches!(e, CloudError::Key(_)), "{a}: {e:?}");
    }
    // A tenant cannot steer the path.
    for t in ["../evil", "a/b", "contoso.com/x?y", "", "x"] {
        let mut f = azure_fields();
        f.insert("tenant_id".into(), Zeroizing::new(t.into()));
        let e = azure_request(&f, None, SCOPE_ARM).unwrap_err();
        assert!(matches!(e, CloudError::Key(_)), "{t}: {e:?}");
    }
    let mut f = azure_fields();
    f.remove("client_secret");
    let e = azure_request(&f, None, SCOPE_ARM).unwrap_err().to_string();
    assert!(e.contains("client_secret"), "{e}");
}

#[tokio::test]
async fn token_response_table() {
    let ok = |b: &str| parse_token_response(200, b.as_bytes());
    let t = ok(&format!(
        r#"{{"access_token":"{ACCESS}","token_type":"bearer","expires_in":"60"}}"#
    ))
    .unwrap();
    assert_eq!(t.ttl, Duration::from_secs(60));
    assert_clean("Token Debug", &format!("{t:?}"), &secrets(&[]));

    let long = "a".repeat(8 * 1024 + 1);
    for bad in [
        // a missing expires_in
        format!(r#"{{"access_token":"{ACCESS}","token_type":"Bearer"}}"#),
        format!(r#"{{"access_token":"{ACCESS}","token_type":"Bearer","expires_in":0}}"#),
        format!(r#"{{"access_token":"{ACCESS}","token_type":"Bearer","expires_in":86401}}"#),
        format!(r#"{{"access_token":"{ACCESS}","token_type":"Bearer","expires_in":"soon"}}"#),
        format!(r#"{{"access_token":"{ACCESS}","token_type":"Bearer","expires_in":-5}}"#),
        // token_type mac, or none
        format!(r#"{{"access_token":"{ACCESS}","token_type":"mac","expires_in":3600}}"#),
        format!(r#"{{"access_token":"{ACCESS}","expires_in":3600}}"#),
        // no usable token
        r#"{"token_type":"Bearer","expires_in":3600}"#.to_string(),
        r#"{"access_token":"","token_type":"Bearer","expires_in":3600}"#.to_string(),
        r#"{"access_token":"a b","token_type":"Bearer","expires_in":3600}"#.to_string(),
        r#"{"access_token":"a\nb","token_type":"Bearer","expires_in":3600}"#.to_string(),
        format!(r#"{{"access_token":"{long}","token_type":"Bearer","expires_in":3600}}"#),
        // non-JSON
        "<html>ok</html>".to_string(),
        "[]".to_string(),
    ] {
        let e = ok(&bad).unwrap_err();
        assert!(matches!(e, CloudError::Response(_)), "{bad}: {e:?}");
        assert_clean("response error", &format!("{e} {e:?}"), &secrets(&[]));
    }

    // A 400 invalid_grant: only the code survives.
    let desc = "Invalid JWT Signature for robot@proj-1, see secret-hint-zz";
    let e = parse_token_response(
        400,
        format!(r#"{{"error":"invalid_grant","error_description":"{desc}"}}"#).as_bytes(),
    )
    .unwrap_err();
    match &e {
        CloudError::Endpoint { code } => assert_eq!(code, "invalid_grant"),
        other => panic!("{other:?}"),
    }
    let shown = format!("{e} {e:?}");
    assert!(shown.contains("invalid_grant"), "{shown}");
    assert!(
        !shown.contains("secret-hint-zz") && !shown.contains("Signature"),
        "{shown}"
    );
    // An error field on a 200, an odd code, a non-JSON error page.
    let code = |s: u16, b: &str| match parse_token_response(s, b.as_bytes()) {
        Err(CloudError::Endpoint { code }) => code,
        other => panic!("{other:?}"),
    };
    assert_eq!(code(200, r#"{"error":"invalid_client"}"#), "invalid_client");
    assert_eq!(code(401, r#"{"error":"has space <x>"}"#), "unrecognized");
    assert_eq!(code(401, r#"{"error":{"x":1}}"#), "unrecognized");
    assert_eq!(code(503, "<html>down, secret-hint-zz</html>"), "http_503");

    // More than 64 KiB is refused, through the real exchange.
    let m = mock().await;
    let mut big =
        format!(r#"{{"access_token":"{ACCESS}","token_type":"Bearer","expires_in":3600,"pad":""#)
            .into_bytes();
    big.extend(std::iter::repeat_n(b'x', 64 * 1024));
    big.extend(b"\"}");
    m.answer(200, vec![], big);
    let e = mint(
        &m.up,
        azure_request(&azure_fields(), None, SCOPE_ARM).unwrap(),
    )
    .await
    .unwrap_err();
    assert!(matches!(e, CloudError::TooLarge), "{e:?}");
}

#[tokio::test]
async fn mint_errors_hold_no_secret() {
    let m = mock().await;
    // An endpoint that echoes the whole request back in its error.
    let key = parse_gcp_key(&gcp_fields()).unwrap();
    let req = gcp_request(&key, SCOPE_GCS, now()).unwrap();
    let body = std::str::from_utf8(req.body.as_ref().unwrap())
        .unwrap()
        .to_string();
    let jwt = form(&body)["assertion"].clone();
    let az = azure_request(&azure_fields(), None, SCOPE_ARM).unwrap();
    let az_body = std::str::from_utf8(az.body.as_ref().unwrap())
        .unwrap()
        .to_string();
    let all = secrets(&[&jwt, &body, &az_body]);
    let echo = serde_json::json!({
        "error": "invalid_grant",
        "error_description": format!("{body} {az_body} {ACCESS} {CLIENT_SECRET} {}", key_pem()),
    })
    .to_string();

    for (status, req) in [(400, req.clone()), (401, az.clone()), (500, req.clone())] {
        m.answer(status, vec![], echo.clone().into_bytes());
        let e = mint(&m.up, req).await.unwrap_err();
        assert!(matches!(e, CloudError::Endpoint { .. }), "{e:?}");
        assert_clean("mint error", &format!("{e} {e:?}"), &all);
    }
    // The echo as a non-JSON page, and as a success that is not one.
    for (status, b) in [
        (502, format!("{body} {CLIENT_SECRET}")),
        (
            200,
            format!(r#"{{"token_type":"mac","access_token":"{ACCESS}","x":"{CLIENT_SECRET}"}}"#),
        ),
        (200, format!("{body} {CLIENT_SECRET}")),
    ] {
        m.answer(status, vec![], b.into_bytes());
        let e = mint(&m.up, az.clone()).await.unwrap_err();
        assert_clean("mint error", &format!("{e} {e:?}"), &all);
    }
    // A transport failure: nothing listens for this name.
    let mut stray = az.clone();
    stray.uri = "https://login.chinacloudapi.cn/contoso.cn/oauth2/v2.0/token"
        .parse()
        .unwrap();
    let dead = Upstream::with_roots(
        RootCertStore::empty(),
        Arc::new(Loopback { port: 1 }),
        Duration::from_secs(2),
    );
    let e = mint(&dead, stray).await.unwrap_err();
    assert!(matches!(e, CloudError::Transport(_)), "{e:?}");
    assert_clean("transport error", &format!("{e} {e:?}"), &all);
    // A request to anywhere but a pinned endpoint is never sent.
    let before = m.seen().len();
    let mut elsewhere = az.clone();
    elsewhere.uri = "https://evil.example.test/token".parse().unwrap();
    let e = mint(&m.up, elsewhere).await.unwrap_err();
    assert!(matches!(e, CloudError::Key(_)), "{e:?}");
    assert_clean("refusal", &format!("{e} {e:?}"), &all);
    assert_eq!(m.seen().len(), before);
}

#[tokio::test]
async fn token_endpoint_redirect_refused() {
    let m = mock().await;
    for (status, location) in [
        (302, "https://evil.example.test/token".to_string()),
        (307, "/token2".to_string()),
        (308, format!("https://{GCP_HOST}/token")),
        (301, "/x".to_string()),
    ] {
        let before = m.seen().len();
        m.answer(status, vec![("location", location.clone())], ok_body());
        let key = parse_gcp_key(&gcp_fields()).unwrap();
        let e = mint(&m.up, gcp_request(&key, SCOPE_GCS, now()).unwrap())
            .await
            .unwrap_err();
        assert!(
            matches!(e, CloudError::Transport(BrokerError::RedirectRefused)),
            "{status} {location}: {e:?}"
        );
        assert_eq!(m.seen().len(), before + 1, "the redirect is not followed");
    }
    // A 3xx that is not a redirect the client follows is refused too.
    m.answer(300, vec![], ok_body());
    let e = mint(
        &m.up,
        azure_request(&azure_fields(), None, SCOPE_ARM).unwrap(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(e, CloudError::Transport(BrokerError::RedirectRefused)),
        "{e:?}"
    );
}
