//! STS `AssumeRole` and the session policy (plan 15, Task 7). The STS
//! endpoint is a loopback hyper server with an `rcgen` certificate for
//! `sts.us-east-1.amazonaws.com`; nothing leaves 127.0.0.1. Every credential
//! value is built at runtime.

use bytes::Bytes;
use http::{HeaderMap, Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;
use saiife_broker::cloud::session_policy::{self, SessionPolicy, MAX_POLICY};
use saiife_broker::cloud::sigv4::AwsCreds;
use saiife_broker::cloud::sts::{
    assume, assume_role_request, parse_assume_role, session_name, AssumeRole, LEASE_SECONDS,
    MAX_RESPONSE,
};
use saiife_broker::cloud::CloudError;
use saiife_broker::upstream::{Resolver, Upstream};
use saiife_broker::Manifest;
use saiife_policy::ServiceOverlay;
use saiife_policy::{decide, Capability, Mode, Request as PolicyRequest, ServiceCfg, Verdict};
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use time::OffsetDateTime;
use tokio::net::TcpListener;
use zeroize::Zeroizing;

const STS_HOST: &str = "sts.us-east-1.amazonaws.com";
const ROLE: &str = "arn:aws:iam::123456789012:role/saiife-reports";

// ------------------------------------------------------------ values

fn new_ak() -> String {
    concat!("AS", "IA", "TESTSTS0000NEW1").to_string()
}
fn new_sk() -> String {
    concat!("sTsSecret", "Key/0123456789", "+abcdefghijKLMN").to_string()
}
fn new_token() -> String {
    concat!(
        "FwoGZXIvY",
        "XdzEPT//////////",
        "wEaDTestSessionToken0123",
        "456789+/="
    )
    .to_string()
}
fn base() -> AwsCreds {
    AwsCreds {
        access_key_id: Zeroizing::new(concat!("AK", "IA", "TESTBASE00000001").to_string()),
        secret_access_key: Zeroizing::new(
            concat!("baseSecret", "Key/9876543210", "abcdEFGH").to_string(),
        ),
        session_token: None,
    }
}
fn secrets() -> Vec<String> {
    vec![
        new_ak(),
        new_sk(),
        new_token(),
        base().access_key_id.to_string(),
        base().secret_access_key.to_string(),
    ]
}

fn assert_clean(text: &str) {
    for s in secrets() {
        assert!(!text.contains(&s), "a credential value leaked: {text}");
    }
}

/// The AWS docs response shape, with runtime values.
fn fixture(ak: &str, sk: &str, tok: &str, exp: &str) -> String {
    format!(
        r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
  <SourceIdentity>Alice</SourceIdentity>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::123456789012:assumed-role/demo/TestAR</Arn>
      <AssumedRoleId>ARO123EXAMPLE123:TestAR</AssumedRoleId>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>{ak}</AccessKeyId>
      <SecretAccessKey>{sk}</SecretAccessKey>
      <SessionToken>
       {tok}
      </SessionToken>
      <Expiration>{exp}</Expiration>
    </Credentials>
    <PackedPolicySize>6</PackedPolicySize>
  </AssumeRoleResult>
  <ResponseMetadata>
    <RequestId>c6104cbe-af31-11e0-8154-cbc7ccf896c7</RequestId>
  </ResponseMetadata>
</AssumeRoleResponse>
"#
    )
}

fn good() -> String {
    fixture(&new_ak(), &new_sk(), &new_token(), "2019-11-09T13:34:41Z")
}

fn error_doc(code: &str, message: &str) -> String {
    format!(
        r#"<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>{code}</Code>
    <Message>{message}</Message>
  </Error>
  <RequestId>4b1c4a1e-0000-0000-0000-000000000000</RequestId>
</ErrorResponse>"#
    )
}

fn utc(y: i32, mo: u8, d: u8, h: u8, mi: u8, se: u8) -> OffsetDateTime {
    let date = time::Date::from_calendar_date(y, time::Month::try_from(mo).unwrap(), d).unwrap();
    time::PrimitiveDateTime::new(date, time::Time::from_hms(h, mi, se).unwrap()).assume_utc()
}

fn err_text(e: &CloudError) -> String {
    format!("{e} {e:?}")
}

// ------------------------------------------------------------ parsing

#[test]
fn parse_assume_role_fixture() {
    let (c, exp) = parse_assume_role(200, good().as_bytes()).unwrap();
    assert_eq!(c.access_key_id.as_str(), new_ak());
    assert_eq!(c.secret_access_key.as_str(), new_sk());
    assert_eq!(
        c.session_token.as_deref().map(|s| s.as_str()),
        Some(new_token().as_str())
    );
    assert_eq!(exp, utc(2019, 11, 9, 13, 34, 41));
    assert_clean(&format!("{c:?}"));
    // With an XML declaration and fractional seconds.
    let doc = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
        fixture(
            &new_ak(),
            &new_sk(),
            &new_token(),
            "2011-07-15T23:28:33.359Z"
        )
    );
    let (_, exp) = parse_assume_role(200, doc.as_bytes()).unwrap();
    assert_eq!(exp, utc(2011, 7, 15, 23, 28, 33));
}

#[test]
fn sts_error_code_only() {
    let msg = format!("User {} with key {} is not authorized", new_ak(), new_sk());
    let e = parse_assume_role(403, error_doc("AccessDenied", &msg).as_bytes()).unwrap_err();
    match &e {
        CloudError::Endpoint { code } => assert_eq!(code, "AccessDenied"),
        other => panic!("{other:?}"),
    }
    let t = err_text(&e);
    assert!(!t.contains("not authorized"), "{t}");
    assert_clean(&t);
    // A code outside [A-Za-z0-9_.]{1,64} is not echoed.
    let e = parse_assume_role(400, error_doc(&format!("Bad {}", new_sk()), "m").as_bytes())
        .unwrap_err();
    assert!(
        matches!(&e, CloudError::Endpoint { code } if code == "unknown"),
        "{e:?}"
    );
    assert_clean(&err_text(&e));
    // No code at all, or a body that is not XML.
    for body in [
        "<ErrorResponse><Error><Message>x</Message></Error></ErrorResponse>",
        "oops",
    ] {
        let e = parse_assume_role(500, body.as_bytes()).unwrap_err();
        assert!(matches!(e, CloudError::Response(_)), "{e:?}");
    }
    // An error document with a 200 has no credentials.
    let e = parse_assume_role(200, error_doc("Throttling", &msg).as_bytes()).unwrap_err();
    assert_clean(&err_text(&e));
}

#[test]
fn xml_entities_unescaped() {
    let raw_sk = format!("{}&amp;x&lt;y&gt;&quot;&apos;", new_sk());
    let doc = fixture(&new_ak(), &raw_sk, &new_token(), "2019-11-09T13:34:41Z");
    let (c, _) = parse_assume_role(200, doc.as_bytes()).unwrap();
    assert_eq!(
        c.secret_access_key.as_str(),
        format!("{}&x<y>\"'", new_sk())
    );

    let good = good();
    let refused: Vec<String> = vec![
        // Entities beyond the five, numeric references.
        good.replace("<SourceIdentity>Alice", "<SourceIdentity>&#65;lice"),
        good.replace("<SourceIdentity>Alice", "<SourceIdentity>&nbsp;"),
        good.replace("<SourceIdentity>Alice", "<SourceIdentity>&xxe;"),
        good.replace("<SourceIdentity>Alice", "<SourceIdentity>A & B"),
        // A DTD and entity declarations.
        format!("<!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n{good}"),
        format!("<?xml version=\"1.0\"?><!DOCTYPE AssumeRoleResponse>{good}"),
        // Comments, CDATA, processing instructions.
        good.replace("<Credentials>", "<Credentials><!-- c -->"),
        good.replace(&new_token(), &format!("<![CDATA[{}]]>", new_token())),
        good.replace("<Credentials>", "<Credentials><?pi x?>"),
        // Mixed content, unbalanced tags, two roots, trailing text.
        good.replace("<Credentials>", "<Credentials>text"),
        good.replace("</Credentials>", "</Credential>"),
        good.replace("</AssumeRoleResponse>", ""),
        format!("{good}<AssumeRoleResponse/>"),
        format!("{good}junk"),
        good.replace("<Expiration>", "<Expiration><b>x</b>"),
    ];
    for doc in refused {
        let e = parse_assume_role(200, doc.as_bytes()).unwrap_err();
        assert!(matches!(e, CloudError::Response(_)), "{e:?}");
        assert_clean(&err_text(&e));
    }
    // Not UTF-8.
    let mut bytes = good.clone().into_bytes();
    bytes.insert(10, 0xff);
    assert!(parse_assume_role(200, &bytes).is_err());
    // Size bound.
    let big = good.replace(
        "<PackedPolicySize>",
        &format!("<Pad>{}</Pad><PackedPolicySize>", "a".repeat(MAX_RESPONSE)),
    );
    assert!(matches!(
        parse_assume_role(200, big.as_bytes()),
        Err(CloudError::TooLarge)
    ));
    // Nesting bound.
    let deep = format!("{}{}", "<a>".repeat(64), "</a>".repeat(64));
    assert!(parse_assume_role(200, deep.as_bytes()).is_err());
}

#[test]
fn duplicate_or_missing_credentials_refused() {
    let good = good();
    for f in [
        "AccessKeyId",
        "SecretAccessKey",
        "SessionToken",
        "Expiration",
    ] {
        let open = format!("<{f}>");
        let start = good.find(&open).unwrap();
        let close = format!("</{f}>");
        let end = good.find(&close).unwrap() + close.len();
        let elem = &good[start..end];
        // Missing.
        let doc = good.replace(elem, "");
        let e = parse_assume_role(200, doc.as_bytes()).unwrap_err();
        assert!(err_text(&e).contains(f), "{e}");
        assert_clean(&err_text(&e));
        // Twice.
        let doc = good.replace(elem, &format!("{elem}{elem}"));
        let e = parse_assume_role(200, doc.as_bytes()).unwrap_err();
        assert_clean(&err_text(&e));
        // Empty element.
        let doc = good.replace(elem, &format!("<{f}/>"));
        assert!(parse_assume_role(200, doc.as_bytes()).is_err(), "{f} empty");
    }
    // A second Credentials element, even with other fields.
    let doc = good.replace(
        "</Credentials>",
        "</Credentials><Credentials></Credentials>",
    );
    assert!(parse_assume_role(200, doc.as_bytes()).is_err());
    // Fields outside the Credentials path do not count.
    let doc = good
        .replace("<Credentials>", "<Other>")
        .replace("</Credentials>", "</Other>");
    assert!(parse_assume_role(200, doc.as_bytes()).is_err());
    // Values that cannot be credentials.
    for doc in [
        fixture("short", &new_sk(), &new_token(), "2019-11-09T13:34:41Z"),
        fixture(&new_ak(), "has space", &new_token(), "2019-11-09T13:34:41Z"),
        fixture(&new_ak(), &new_sk(), "tok en", "2019-11-09T13:34:41Z"),
        fixture(&new_ak(), &new_sk(), &new_token(), "tomorrow"),
    ] {
        let e = parse_assume_role(200, doc.as_bytes()).unwrap_err();
        assert_clean(&err_text(&e));
    }
}

// ------------------------------------------------------------ request

fn lease(policy: Option<&str>) -> AssumeRole<'_> {
    AssumeRole {
        role_arn: ROLE,
        session_name: session_name(1000),
        duration_s: LEASE_SECONDS,
        policy,
        external_id: Some("ext-id-1"),
    }
}

#[test]
fn request_shape_and_refusals() {
    let b = assume_role_request("us-east-1", &lease(Some("{\"a\":1}"))).unwrap();
    assert_eq!(b.method, http::Method::POST);
    assert_eq!(b.uri.to_string(), format!("https://{STS_HOST}/"));
    assert!(matches!(
        assume_role_request("us-east-1/x", &lease(None)),
        Err(CloudError::Key(_))
    ));
    assert!(matches!(
        assume_role_request("evil.test#", &lease(None)),
        Err(CloudError::Key(_))
    ));
    let mut p = lease(None);
    p.duration_s = 899;
    assert!(assume_role_request("us-east-1", &p).is_err());
    let mut p = lease(None);
    p.role_arn = "arn:aws:iam::123:role/x";
    assert!(assume_role_request("us-east-1", &p).is_err());
    let mut p = lease(None);
    p.session_name = "bad name".into();
    assert!(assume_role_request("us-east-1", &p).is_err());
    let long = "x".repeat(MAX_POLICY + 1);
    assert!(assume_role_request("us-east-1", &lease(Some(&long))).is_err());
}

struct Pki {
    leaf: CertificateDer<'static>,
    leaf_key: PrivatePkcs8KeyDer<'static>,
    roots: RootCertStore,
}

fn pki() -> Pki {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![STS_HOST.to_string()])
        .unwrap()
        .signed_by(&leaf_key, &ca)
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    Pki {
        leaf: leaf.der().clone(),
        leaf_key: PrivatePkcs8KeyDer::from(leaf_key.serialize_der()),
        roots,
    }
}

/// The real STS name is 127.0.0.1 at the mock's port.
struct Loopback(u16);

impl Resolver for Loopback {
    fn resolve(&self, host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
        if host == STS_HOST {
            Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, self.0))])
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "unknown test host"))
        }
    }
}

#[derive(Default)]
struct Mock {
    answer: Mutex<(u16, String)>,
    seen: Mutex<Vec<(String, HeaderMap, String)>>,
}

async fn handle(req: Request<Incoming>, m: Arc<Mock>) -> Result<Response<Full<Bytes>>, Infallible> {
    let (parts, body) = req.into_parts();
    let body = body
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    m.seen.lock().unwrap().push((
        format!("{} {}", parts.method, parts.uri),
        parts.headers,
        String::from_utf8_lossy(&body).into_owned(),
    ));
    let (status, text) = m.answer.lock().unwrap().clone();
    Ok(Response::builder()
        .status(status)
        .header("content-type", "text/xml")
        .body(Full::new(Bytes::from(text)))
        .unwrap())
}

async fn serve() -> (Arc<Mock>, Upstream) {
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
    let mock = Arc::new(Mock::default());
    let m2 = mock.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let m = m2.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let svc = service_fn(move |req| handle(req, m.clone()));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    let up = Upstream::with_roots(pki.roots, Arc::new(Loopback(port)), Duration::from_secs(5));
    (mock, up)
}

fn stamp(t: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc().replace_nanosecond(0).unwrap()
}

fn form(body: &str) -> BTreeMap<String, String> {
    body.split('&')
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap();
            let v = percent_encoding::percent_decode_str(v)
                .decode_utf8()
                .unwrap();
            (k.to_string(), v.into_owned())
        })
        .collect()
}

#[tokio::test]
async fn assume_role_signed_and_sent_to_loopback() {
    let (mock, up) = serve().await;
    let at = now();
    let exp = at + time::Duration::seconds(3600);
    *mock.answer.lock().unwrap() = (
        200,
        fixture(&new_ak(), &new_sk(), &new_token(), &stamp(exp)),
    );
    let pol = build(
        &svc(r#"allow = ["s3:read:arn:aws:s3:::reports/**"]"#),
        &s3(),
    )
    .unwrap();
    let p = lease(Some(&pol.json));
    let (c, _) = assume(&up, &base(), "us-east-1", &p, at).await.unwrap();
    assert_eq!(c.access_key_id.as_str(), new_ak());
    assert_eq!(
        c.session_token.as_deref().map(|s| s.as_str()),
        Some(new_token().as_str())
    );

    let seen = std::mem::take(&mut *mock.seen.lock().unwrap());
    assert_eq!(seen.len(), 1);
    let (line, headers, body) = &seen[0];
    assert_eq!(line, "POST /");
    let f = form(body);
    assert_eq!(f["Action"], "AssumeRole");
    assert_eq!(f["Version"], "2011-06-15");
    assert_eq!(f["DurationSeconds"], "900");
    assert_eq!(f["RoleArn"], ROLE);
    assert_eq!(f["RoleSessionName"], p.session_name);
    assert_eq!(f["ExternalId"], "ext-id-1");
    assert_eq!(f["Policy"], pol.json);
    let auth = headers["authorization"].to_str().unwrap();
    let scope = format!(
        "Credential={}/{:04}{:02}{:02}/us-east-1/sts/aws4_request",
        base().access_key_id.as_str(),
        at.year(),
        u8::from(at.month()),
        at.day()
    );
    assert!(auth.starts_with("AWS4-HMAC-SHA256 "), "{auth}");
    assert!(auth.contains(&scope), "{auth}");
    assert!(auth.contains("SignedHeaders="), "{auth}");
    assert!(headers.contains_key("x-amz-date"));
    assert!(!headers.contains_key("x-amz-content-sha256"));
    assert_eq!(headers["host"], STS_HOST);
    assert!(!auth.contains(base().secret_access_key.as_str()));
    assert!(!body.contains(base().secret_access_key.as_str()));

    // An STS refusal keeps the code only.
    let msg = format!("not authorized: {}", base().access_key_id.as_str());
    *mock.answer.lock().unwrap() = (403, error_doc("AccessDenied", &msg));
    let e = assume(&up, &base(), "us-east-1", &lease(None), at)
        .await
        .unwrap_err();
    assert!(
        matches!(&e, CloudError::Endpoint { code } if code == "AccessDenied"),
        "{e:?}"
    );
    assert_clean(&err_text(&e));

    // An answer over the cap.
    *mock.answer.lock().unwrap() = (200, "a".repeat(MAX_RESPONSE + 10));
    let e = assume(&up, &base(), "us-east-1", &lease(None), at)
        .await
        .unwrap_err();
    assert!(matches!(e, CloudError::TooLarge), "{e:?}");
}

#[tokio::test]
async fn expiration_capped_at_requested_duration() {
    let (mock, up) = serve().await;
    let at = now();
    let answer = |exp: OffsetDateTime| {
        (
            200,
            fixture(&new_ak(), &new_sk(), &new_token(), &stamp(exp)),
        )
    };

    *mock.answer.lock().unwrap() = answer(at + time::Duration::hours(1));
    let (_, exp) = assume(&up, &base(), "us-east-1", &lease(None), at)
        .await
        .unwrap();
    assert_eq!(exp, at + time::Duration::seconds(900));

    *mock.answer.lock().unwrap() = answer(at + time::Duration::seconds(300));
    let (_, exp) = assume(&up, &base(), "us-east-1", &lease(None), at)
        .await
        .unwrap();
    assert_eq!(exp, at + time::Duration::seconds(300));

    *mock.answer.lock().unwrap() = answer(at - time::Duration::seconds(1));
    let e = assume(&up, &base(), "us-east-1", &lease(None), at)
        .await
        .unwrap_err();
    assert!(matches!(e, CloudError::Response(_)), "{e:?}");
    assert_clean(&err_text(&e));
}

// ------------------------------------------------------------ session policy

const S3: &str = r#"
id = "s3-test"
version = 1
title = "S3 test"
base_url = "https://s3.{region}.amazonaws.com"
hosts = ["s3.{region}.amazonaws.com"]
auth = [{ kind = "aws_sigv4", service = "s3" }]

[params.region]
type = "string"
pattern = "^[a-z0-9-]+$"
required = true

[[operation]]
id = "s3.list_buckets"
capability = "s3:admin"
kind = "read"
method = "GET"
path = "/"
iam_action = "s3:ListAllMyBuckets"

[[operation]]
id = "s3.list_objects"
capability = "s3:read"
qualifier = "arn:aws:s3:::{bucket}"
kind = "read"
method = "GET"
path = "/{bucket}"
path_params = { bucket = "string:[a-z0-9.-]{3,63}" }
fixed_query = { "list-type" = "2" }
iam_action = "s3:ListBucket"

[[operation]]
id = "s3.get_object"
capability = "s3:read"
qualifier = "arn:aws:s3:::{bucket}/{key}"
kind = "read"
method = "GET"
path = "/{bucket}/{key}"
path_params = { bucket = "string:[a-z0-9.-]{3,63}", key = "objectkey" }
iam_action = "s3:GetObject"

[[operation]]
id = "s3.put_object"
capability = "s3:write"
qualifier = "arn:aws:s3:::{bucket}/{key}"
kind = "write"
method = "PUT"
path = "/{bucket}/{key}"
path_params = { bucket = "string:[a-z0-9.-]{3,63}", key = "objectkey" }
body = "raw"
iam_action = "s3:PutObject"

[[operation]]
id = "s3.delete_object"
capability = "s3:delete"
qualifier = "arn:aws:s3:::{bucket}/{key}"
kind = "delete"
method = "DELETE"
path = "/{bucket}/{key}"
path_params = { bucket = "string:[a-z0-9.-]{3,63}", key = "objectkey" }
iam_action = "s3:DeleteObject"
"#;

/// The same, plus an operation without `iam_action`.
fn s3_with_unmapped() -> Manifest {
    Manifest::parse(&format!(
        "{S3}\n[[operation]]\nid = \"s3.get_acl\"\ncapability = \"s3:export\"\n\
         qualifier = \"arn:aws:s3:::{{bucket}}\"\nkind = \"read\"\nmethod = \"GET\"\n\
         path = \"/{{bucket}}\"\npath_params = {{ bucket = \"string:[a-z0-9.-]{{3,63}}\" }}\n\
         fixed_query = {{ \"acl\" = \"1\" }}\n"
    ))
    .unwrap()
}

fn s3() -> Manifest {
    Manifest::parse(S3).unwrap()
}

fn svc(body: &str) -> ServiceCfg {
    toml::from_str(&format!("connector = \"s3-test\"\nmode = \"sts\"\n{body}")).unwrap()
}

#[derive(Debug)]
struct Stmt {
    allow: bool,
    actions: Vec<String>,
    resources: Vec<String>,
}

fn statements(p: &SessionPolicy) -> Vec<Stmt> {
    let v: serde_json::Value = serde_json::from_str(&p.json).unwrap();
    assert_eq!(v["Version"], "2012-10-17");
    let strs = |v: &serde_json::Value| -> Vec<String> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect()
    };
    v["Statement"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| Stmt {
            allow: match s["Effect"].as_str().unwrap() {
                "Allow" => true,
                "Deny" => false,
                e => panic!("{e}"),
            },
            actions: strs(&s["Action"]),
            resources: strs(&s["Resource"]),
        })
        .collect()
}

/// IAM resource matching per the IAM docs: `?` is one character and `*`
/// any run, neither crossing `:`, except that a trailing `*` matches any
/// rest. Case-sensitive.
fn iam_match(pat: &str, text: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = text.chars().collect();
    fn go(p: &[char], t: &[char]) -> bool {
        match p.first() {
            None => t.is_empty(),
            Some('*') if p.len() == 1 => true,
            Some('*') => (0..=t.len())
                .take_while(|&k| k == 0 || t[k - 1] != ':')
                .any(|k| go(&p[1..], &t[k..])),
            Some('?') => t.first().is_some_and(|c| *c != ':') && go(&p[1..], &t[1..]),
            Some(c) => t.first() == Some(c) && go(&p[1..], &t[1..]),
        }
    }
    go(&p, &t)
}

/// The IAM decision for one request: an Allow matches and no Deny does.
fn iam_allows(st: &[Stmt], action: &str, arn: &str) -> bool {
    let hit = |s: &&Stmt| {
        s.actions.iter().any(|a| a.eq_ignore_ascii_case(action))
            && s.resources.iter().any(|r| iam_match(r, arn))
    };
    st.iter().filter(|s| s.allow).any(|s| hit(&s))
        && !st.iter().filter(|s| !s.allow).any(|s| hit(&s))
}

const KEYS: &[&str] = &[
    "reports",
    "reports/a.csv",
    "reports/x/y.csv",
    "reports/a:b/c",
    "Reports/a.csv",
    "reportsX/a",
    "other/a.csv",
    "reports/secret/k",
    "reports/SECRET/k",
    "reports/Secret/deep/k",
    "reports/public/k",
    "reports/PUBLIC/k",
    "reports/pub/k",
];

/// Every (operation, ARN) the saiife policy allows is allowed by IAM, and
/// back again when `exact`; IAM never allows what saiife does not.
fn compare(svc: &ServiceCfg, m: &Manifest, exact: bool) -> SessionPolicy {
    compare_with(svc, None, Mode::Locked, m, exact)
}

fn build(svc: &ServiceCfg, m: &Manifest) -> Result<SessionPolicy, CloudError> {
    session_policy::build(svc, m, None, Mode::Locked)
}

/// As [`compare`], with a project overlay in `mode`.
fn compare_with(
    svc: &ServiceCfg,
    overlay: Option<&ServiceOverlay>,
    mode: Mode,
    m: &Manifest,
    exact: bool,
) -> SessionPolicy {
    let pol = session_policy::build(svc, m, overlay, mode).unwrap();
    let st = statements(&pol);
    let mut allowed = 0;
    for op in &m.operation {
        let Some(action) = op.iam_action.as_deref() else {
            continue;
        };
        for key in KEYS {
            let arn = format!("arn:aws:s3:::{key}");
            let cap = match &op.qualifier {
                Some(_) => format!("{}:{arn}", op.capability),
                None => op.capability.clone(),
            };
            let cap = Capability::parse(&cap).unwrap();
            let params = BTreeMap::new();
            let saiife = decide(
                svc,
                overlay,
                mode,
                &PolicyRequest {
                    capability: &cap,
                    params: &params,
                },
            ) == Verdict::Allow;
            let iam = iam_allows(&st, action, &arn);
            assert!(
                !iam || saiife,
                "IAM is wider: {} {arn}\npolicy {}",
                op.id,
                pol.json
            );
            if exact {
                assert_eq!(iam, saiife, "{} {arn}\npolicy {}", op.id, pol.json);
            }
            allowed += usize::from(iam);
        }
    }
    assert!(allowed > 0, "the table allows nothing: {}", pol.json);
    pol
}

#[test]
fn session_policy_table() {
    let m = s3();
    // `reports/**` → Allow s3:GetObject on reports/*.
    let pol = compare(
        &svc(r#"allow = ["s3:read:arn:aws:s3:::reports/**"]"#),
        &m,
        true,
    );
    let st = statements(&pol);
    assert_eq!(st.len(), 1, "{}", pol.json);
    assert!(st[0].allow);
    assert!(
        st[0].actions.contains(&"s3:GetObject".to_string()),
        "{}",
        pol.json
    );
    assert!(
        !st[0].actions.contains(&"s3:PutObject".to_string()),
        "{}",
        pol.json
    );
    assert_eq!(st[0].resources, vec!["arn:aws:s3:::reports/*"]);

    // `s3:read` → Resource "*".
    let pol = compare(&svc(r#"allow = ["s3:read"]"#), &m, true);
    let st = statements(&pol);
    assert_eq!(st.len(), 1);
    assert_eq!(st[0].actions, vec!["s3:GetObject", "s3:ListBucket"]);
    assert_eq!(st[0].resources, vec!["*"]);

    // The rest of the table: (policy, exact).
    let rows: &[(&str, bool)] = &[
        (r#"allow = ["s3:read:arn:aws:s3:::reports/a.csv"]"#, true),
        (
            r#"allow = ["*:read:arn:aws:s3:::reports/a.csv", "s3:write:arn:aws:s3:::reports/x/**"]"#,
            true,
        ),
        (r#"allow = ["s3:*"]"#, true),
        (r#"allow = ["*:*:arn:aws:s3:::reports/**"]"#, true),
        (
            "allow = [\"s3:read\", \"s3:write:arn:aws:s3:::reports/**\"]\n\
             deny = [\"s3:read:arn:aws:s3:::reports/secret/*\"]\n\
             ask = [\"s3:write:arn:aws:s3:::reports/public/**\"]",
            false,
        ),
        (
            "allow = [\"s3:*\"]\ndeny = [\"*:delete\", \"s3:admin:arn:aws:s3:::x\"]",
            true,
        ),
        (
            "[[rule]]\ncapability = \"s3:read:arn:aws:s3:::reports/**\"\naction = \"allow\"\n\
             [[rule]]\ncapability = \"s3:read:arn:aws:s3:::reports/secret/**\"\n\
             when = { key = \"k*\" }\naction = \"deny\"",
            false,
        ),
    ];
    for (body, exact) in rows {
        compare(&svc(body), &m, *exact);
    }
}

fn refused(body: &str, m: &Manifest) -> String {
    match build(&svc(body), m) {
        Err(CloudError::Unrepresentable { pattern, .. }) => pattern,
        other => panic!("{body}: {other:?}"),
    }
}

#[test]
fn session_policy_never_wider() {
    let m = s3();
    for p in [
        "s3:read:arn:aws:s3:::reports/*",
        "s3:read:arn:aws:s3:::rep?rts/**",
        "s3:read:arn:aws:s3:::${aws:username}/**",
        "s3:read:arn:aws:s3:::{bucket}/**",
        "s3:read:arn:aws:s3:::reports/**/x",
        "s3:read:arn:aws:s3:::reports/***",
        "s3:read:**",
        "s3:read:ARN:aws:s3:::reports/**",
        "s3:read:arn:aws:s*:::reports/**",
        "s3:read:arn:aws:s3:::r\u{e9}ports/**",
        "s3:read:reports/**",
    ] {
        assert_eq!(refused(&format!("allow = [{p:?}]"), &m), p);
    }
    // An allow rule with `when`.
    let r = "[[rule]]\ncapability = \"s3:read:arn:aws:s3:::reports/**\"\n\
             when = { key = \"a*\" }\naction = \"allow\"";
    assert_eq!(refused(r, &m), "s3:read:arn:aws:s3:::reports/**");
    // An allowed operation without an iam_action.
    assert_eq!(
        refused(r#"allow = ["s3:export"]"#, &s3_with_unmapped()),
        "s3:export"
    );
    assert_eq!(refused(r#"allow = ["s3:*"]"#, &s3_with_unmapped()), "s3:*");
    // A deny on it is fine: there is no IAM action to deny, and nothing
    // allows it.
    build(
        &svc("allow = [\"s3:read\"]\ndeny = [\"s3:export\"]"),
        &s3_with_unmapped(),
    )
    .unwrap();
    // A fixed parameter narrows saiife in a way IAM cannot follow.
    assert_eq!(
        refused(
            "allow = [\"s3:read\"]\nfixed = { bucket = \"reports\" }",
            &m
        ),
        "fixed.bucket"
    );
    // Nothing allowed.
    assert!(matches!(
        build(&svc(r#"deny = ["s3:read"]"#), &m),
        Err(CloudError::Unrepresentable { .. })
    ));
    // STS mode is AWS only.
    let gcs = Manifest::parse(
        "id = \"gcs-test\"\nversion = 1\ntitle = \"G\"\nbase_url = \"https://storage.googleapis.com\"\n\
         hosts = [\"storage.googleapis.com\"]\n\
         auth = [{ kind = \"gcp_sa\", scope = \"https://www.googleapis.com/auth/devstorage.read_only\" }]\n\
         [[operation]]\nid = \"o.get\"\ncapability = \"storage:read\"\nkind = \"read\"\n\
         method = \"GET\"\npath = \"/storage/v1/b\"\n",
    )
    .unwrap();
    assert_eq!(refused(r#"allow = ["storage:read"]"#, &gcs), "gcs-test");
}

#[test]
fn ask_and_deny_become_deny() {
    let m = s3();
    let body = "allow = [\"s3:read\", \"s3:write\"]\n\
                ask = [\"s3:write:arn:aws:s3:::reports/public/**\"]\n\
                deny = [\"s3:read:arn:aws:s3:::reports/Secret/*\"]\n\
                [[rule]]\ncapability = \"s3:delete:arn:aws:s3:::reports/k\"\n\
                when = { key = \"x\" }\naction = \"ask\"";
    let s = svc(body);
    let pol = compare(&s, &m, false);
    let st = statements(&pol);
    let deny: Vec<&Stmt> = st.iter().filter(|s| !s.allow).collect();
    let find = |action: &str| -> Vec<String> {
        deny.iter()
            .filter(|s| s.actions.iter().any(|a| a == action))
            .flat_map(|s| s.resources.clone())
            .collect()
    };
    // The deny's `*` crosses `/` and its case is ignored: letters become `?`.
    let read = find("s3:GetObject");
    assert_eq!(read, vec!["arn:aws:s3:::???????/??????/*"], "{}", pol.json);
    assert_eq!(find("s3:ListBucket"), read);
    assert_eq!(find("s3:PutObject"), vec!["arn:aws:s3:::???????/??????/*"]);
    // The ask rule is a deny whatever its `when`.
    assert_eq!(find("s3:DeleteObject"), vec!["arn:aws:s3:::???????/?"]);
    // Case variants saiife denies are denied by IAM too.
    for key in ["reports/secret/k", "reports/SECRET/k", "REPORTS/Secret/a/b"] {
        assert!(
            !iam_allows(&st, "s3:GetObject", &format!("arn:aws:s3:::{key}")),
            "{key}"
        );
    }
    assert!(!iam_allows(
        &st,
        "s3:PutObject",
        "arn:aws:s3:::reports/PUBLIC/k"
    ));
    assert!(iam_allows(
        &st,
        "s3:GetObject",
        "arn:aws:s3:::reports/a.csv"
    ));

    // A qualified deny on an unqualified operation denies it everywhere;
    // a deny without a qualifier denies `*`.
    let pol = compare(
        &svc("allow = [\"s3:*\"]\ndeny = [\"s3:admin:arn:aws:s3:::x\", \"s3:delete\"]"),
        &m,
        true,
    );
    let st = statements(&pol);
    let d: Vec<&Stmt> = st.iter().filter(|s| !s.allow).collect();
    assert_eq!(d.len(), 1, "{}", pol.json);
    assert_eq!(d[0].actions, vec!["s3:DeleteObject", "s3:ListAllMyBuckets"]);
    assert_eq!(d[0].resources, vec!["*"]);
}

#[test]
fn policy_too_large() {
    let m = s3();
    let pats: Vec<String> = (0..200)
        .map(|i| format!("\"s3:read:arn:aws:s3:::bucket-{i:03}/**\""))
        .collect();
    let body = format!("allow = [{}]", pats.join(", "));
    assert!(matches!(build(&svc(&body), &m), Err(CloudError::TooLarge)));
    // A handful fits.
    let body = format!("allow = [{}]", pats[..5].join(", "));
    let pol = build(&svc(&body), &m).unwrap();
    assert!(pol.json.len() <= MAX_POLICY);
}

#[test]
fn policy_deterministic() {
    let m = s3();
    let a = "allow = [\"s3:read:arn:aws:s3:::b-two/**\", \"s3:read:arn:aws:s3:::b-one/**\", \"s3:write\"]\n\
             deny = [\"s3:delete\", \"s3:read:arn:aws:s3:::b-one/x/*\"]";
    let b = "deny = [\"s3:read:arn:aws:s3:::b-one/x/*\", \"s3:delete\"]\n\
             allow = [\"s3:write\", \"s3:read:arn:aws:s3:::b-one/**\", \"s3:read:arn:aws:s3:::b-two/**\"]";
    let p1 = build(&svc(a), &m).unwrap();
    let p2 = build(&svc(a), &m).unwrap();
    let p3 = build(&svc(b), &m).unwrap();
    assert_eq!(p1, p2);
    assert_eq!(p1, p3);
    assert!(
        !p1.json.contains(' ') && !p1.json.contains('\n'),
        "{}",
        p1.json
    );
    use sha2::Digest;
    let sha: String = sha2::Sha256::digest(p1.json.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(p1.sha256, sha);
    assert_eq!(p1.sha256.len(), 64);
    // Allow statements come first, each statement's lists are sorted.
    let st = statements(&p1);
    assert!(st[0].allow);
    for s in &st {
        let mut a = s.actions.clone();
        a.sort();
        assert_eq!(a, s.actions);
        let mut r = s.resources.clone();
        r.sort();
        assert_eq!(r, s.resources);
    }
}

/// S3 plus a `ListBucket` whose qualifier holds its `{prefix}` query param:
/// the qualifier is `bucket/prefix`, but IAM sees only the bucket ARN.
fn s3_with_prefix_list() -> Manifest {
    Manifest::parse(&format!(
        "{S3}\n[[operation]]\nid = \"s3.list_prefix\"\ncapability = \"s3:read\"\n\
         qualifier = \"arn:aws:s3:::{{bucket}}/{{prefix}}\"\nkind = \"read\"\nmethod = \"GET\"\n\
         path = \"/{{bucket}}\"\npath_params = {{ bucket = \"string:[a-z0-9.-]{{3,63}}\" }}\n\
         query = {{ prefix = \"string\" }}\nfixed_query = {{ \"list-type\" = \"1\" }}\n\
         iam_action = \"s3:ListBucket\"\n"
    ))
    .unwrap()
}

#[test]
fn qualifier_from_a_query_param_never_widens() {
    let m = s3_with_prefix_list();
    // Saiife allows `s3.list_prefix` on reports/<anything>, i.e. listing the
    // whole `reports` bucket with a prefix; IAM's ListBucket on
    // `reports/*` would match no bucket ARN, and on the bucket ARN it would
    // allow listing the bucket under every prefix. Refused either way.
    let p = "s3:read:arn:aws:s3:::reports/**";
    assert_eq!(refused(&format!("allow = [{p:?}]"), &m), p);
    let p = "s3:read:arn:aws:s3:::reports/public/**";
    assert_eq!(refused(&format!("allow = [{p:?}]"), &m), p);
    // Unqualified, the qualifier does not matter.
    let pol = build(&svc(r#"allow = ["s3:read"]"#), &m).unwrap();
    assert!(pol.json.contains("s3:ListBucket"), "{}", pol.json);
    // A deny on it cannot be narrowed to the qualifier: ListBucket is
    // denied everywhere, GetObject only on the widened resource.
    let pol = build(
        &svc("allow = [\"s3:read\"]\ndeny = [\"s3:read:arn:aws:s3:::reports/secret/**\"]"),
        &m,
    )
    .unwrap();
    let st = statements(&pol);
    for arn in ["arn:aws:s3:::reports", "arn:aws:s3:::other"] {
        assert!(!iam_allows(&st, "s3:ListBucket", arn), "{arn} {}", pol.json);
    }
    assert!(!iam_allows(
        &st,
        "s3:GetObject",
        "arn:aws:s3:::reports/secret/k"
    ));
    assert!(iam_allows(
        &st,
        "s3:GetObject",
        "arn:aws:s3:::reports/a.csv"
    ));
}

#[test]
fn shared_iam_action_refused() {
    // `s3.download` is GetObject under another verb.
    let m = Manifest::parse(&format!(
        "{S3}\n[[operation]]\nid = \"s3.download\"\ncapability = \"s3:export\"\n\
         qualifier = \"arn:aws:s3:::{{bucket}}/{{key}}\"\nkind = \"read\"\nmethod = \"GET\"\n\
         path = \"/{{bucket}}/{{key}}\"\n\
         path_params = {{ bucket = \"string:[a-z0-9.-]{{3,63}}\", key = \"objectkey\" }}\n\
         fixed_query = {{ \"response-content-disposition\" = \"attachment\" }}\n\
         iam_action = \"s3:GetObject\"\n"
    ))
    .unwrap();
    for p in ["s3:read", "s3:read:arn:aws:s3:::reports/**", "s3:export"] {
        assert_eq!(refused(&format!("allow = [{p:?}]"), &m), p);
    }
    // Allowing both verbs is fine.
    build(&svc(r#"allow = ["s3:*"]"#), &m).unwrap();
    build(&svc(r#"allow = ["*:*:arn:aws:s3:::reports/**"]"#), &m).unwrap();
    // A qualified allow whose action an unqualified operation shares.
    let m = Manifest::parse(&format!(
        "{S3}\n[[operation]]\nid = \"s3.get_any\"\ncapability = \"s3:read\"\nkind = \"read\"\n\
         method = \"GET\"\npath = \"/any/{{key}}\"\npath_params = {{ key = \"objectkey\" }}\n\
         iam_action = \"s3:GetObject\"\n"
    ))
    .unwrap();
    let p = "s3:read:arn:aws:s3:::reports/**";
    assert_eq!(refused(&format!("allow = [{p:?}]"), &m), p);
    build(&svc(r#"allow = ["s3:read"]"#), &m).unwrap();
}

fn overlay(allow: &[&str], ask: &[&str], deny: &[&str]) -> ServiceOverlay {
    let v = |x: &[&str]| x.iter().map(|s| s.to_string()).collect();
    ServiceOverlay {
        allow: v(allow),
        ask: v(ask),
        deny: v(deny),
    }
}

#[test]
fn overlay_mirrors_decide() {
    let m = s3();
    let base = svc(r#"allow = ["s3:read", "s3:write:arn:aws:s3:::reports/**"]"#);
    let rows: &[(ServiceOverlay, bool)] = &[
        (
            overlay(&[], &[], &["s3:read:arn:aws:s3:::reports/secret/*"]),
            false,
        ),
        (
            overlay(&[], &["s3:write:arn:aws:s3:::reports/public/**"], &[]),
            false,
        ),
        (
            overlay(&["s3:delete:arn:aws:s3:::reports/tmp/**"], &[], &[]),
            true,
        ),
        (overlay(&["s3:delete"], &[], &["s3:read"]), true),
    ];
    for (o, exact) in rows {
        for mode in [Mode::Locked, Mode::Developer] {
            compare_with(&base, Some(o), mode, &m, *exact);
        }
    }
    // The overlay's allow counts in developer mode only; its deny always.
    let o = overlay(
        &["s3:delete"],
        &[],
        &["s3:read:arn:aws:s3:::reports/secret/*"],
    );
    let locked = statements(&session_policy::build(&base, &m, Some(&o), Mode::Locked).unwrap());
    let dev = statements(&session_policy::build(&base, &m, Some(&o), Mode::Developer).unwrap());
    let del = "arn:aws:s3:::reports/a.csv";
    assert!(!iam_allows(&locked, "s3:DeleteObject", del));
    assert!(iam_allows(&dev, "s3:DeleteObject", del));
    for st in [&locked, &dev] {
        assert!(!iam_allows(
            st,
            "s3:GetObject",
            "arn:aws:s3:::reports/SECRET/k"
        ));
        assert!(iam_allows(st, "s3:GetObject", "arn:aws:s3:::reports/a.csv"));
    }
    // An unrepresentable overlay allow is refused only where it counts.
    let o = overlay(&["s3:delete:arn:aws:s3:::reports/*"], &[], &[]);
    session_policy::build(&base, &m, Some(&o), Mode::Locked).unwrap();
    assert!(matches!(
        session_policy::build(&base, &m, Some(&o), Mode::Developer),
        Err(CloudError::Unrepresentable { .. })
    ));
}
