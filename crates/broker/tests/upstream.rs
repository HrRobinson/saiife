//! The pinned HTTPS client against a loopback hyper server with an `rcgen`
//! certificate for `acme.example.test`. Nothing leaves 127.0.0.1.

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request, Response, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;
use saiife_broker::request::Built;
use saiife_broker::upstream::{Resolver, Upstream, UpstreamResponse};
use saiife_broker::BrokerError;
use std::convert::Infallible;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;

const HOST: &str = "acme.example.test";

/// A CA and the `acme.example.test` leaf it signed.
struct Pki {
    ca: CertificateDer<'static>,
    leaf: CertificateDer<'static>,
    leaf_key: PrivatePkcs8KeyDer<'static>,
    ca_pem: String,
}

fn pki() -> Pki {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![HOST.to_string(), "other.example.test".to_string()])
        .unwrap()
        .signed_by(&leaf_key, &ca)
        .unwrap();
    // `other.example.test` is in the leaf only for the redirect test; the
    // client refuses that redirect before it connects anywhere.
    Pki {
        ca: ca.der().clone(),
        leaf: leaf.der().clone(),
        leaf_key: PrivatePkcs8KeyDer::from(leaf_key.serialize_der()),
        ca_pem: ca.pem(),
    }
}

/// Maps the test host names to the loopback server; everything else fails.
struct Loopback {
    names: Vec<&'static str>,
}

impl Resolver for Loopback {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        if self.names.contains(&host) {
            Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, port))])
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "unknown test host"))
        }
    }
}

#[derive(Default)]
struct Seen {
    requests: Vec<(Method, String, HeaderMap, usize)>,
}

struct Server {
    port: u16,
    seen: Arc<Mutex<Seen>>,
}

fn redirect(status: u16, location: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("location", location)
        .body(Full::new(Bytes::from_static(b"moved")))
        .unwrap()
}

async fn handle(
    req: Request<Incoming>,
    port: u16,
    seen: Arc<Mutex<Seen>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let (parts, body) = req.into_parts();
    let body = body
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let path = parts.uri.path().to_string();
    seen.lock().unwrap().requests.push((
        parts.method.clone(),
        parts.uri.to_string(),
        parts.headers.clone(),
        body.len(),
    ));
    let ok = |b: Bytes| Response::new(Full::new(b));
    let resp = if path == "/hello" {
        ok(Bytes::from_static(b"hello world"))
    } else if let Some(n) = path.strip_prefix("/r/") {
        let n: u32 = n.parse().unwrap();
        if n == 0 {
            ok(Bytes::from_static(b"done"))
        } else if n.is_multiple_of(2) {
            redirect(302, format!("/r/{}", n - 1))
        } else {
            redirect(308, format!("https://{HOST}:{port}/r/{}", n - 1))
        }
    } else {
        match path.as_str() {
            "/other-host" => redirect(302, format!("https://other.example.test:{port}/hello")),
            "/other-port" => redirect(307, format!("https://{HOST}:{}/hello", port ^ 1)),
            "/default-port" => redirect(301, format!("https://{HOST}/hello")),
            "/downgrade" => redirect(301, format!("http://{HOST}:{port}/hello")),
            "/userinfo" => redirect(302, format!("https://u:p@{HOST}:{port}/hello")),
            "/see-other" => redirect(303, "/method".to_string()),
            "/method" => ok(Bytes::from(format!("{} {}", parts.method, body.len()))),
            "/slow" => {
                tokio::time::sleep(Duration::from_secs(3)).await;
                ok(Bytes::from_static(b"late"))
            }
            "/big" => ok(Bytes::from(vec![b'a'; 10_000])),
            _ => Response::builder()
                .status(404)
                .body(Full::new(Bytes::from_static(b"not found")))
                .unwrap(),
        }
    };
    Ok(resp)
}

async fn serve(pki: &Pki) -> Server {
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
    let seen = Arc::new(Mutex::new(Seen::default()));
    let seen2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let seen = seen2.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let svc = service_fn(move |req| handle(req, port, seen.clone()));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    Server { port, seen }
}

fn client(pki: &Pki, timeout: Duration) -> Upstream {
    let mut roots = RootCertStore::empty();
    roots.add(pki.ca.clone()).unwrap();
    Upstream::with_roots(
        roots,
        Arc::new(Loopback {
            names: vec![HOST, "other.example.test"],
        }),
        timeout,
    )
}

fn get(port: u16, path: &str) -> Built {
    let mut headers = HeaderMap::new();
    headers.insert("x-token", HeaderValue::from_static("tok-1"));
    Built {
        method: Method::GET,
        uri: format!("https://{HOST}:{port}{path}")
            .parse::<Uri>()
            .unwrap(),
        headers,
        body: None,
    }
}

async fn setup() -> (Pki, Server, Upstream) {
    let pki = pki();
    let server = serve(&pki).await;
    let up = client(&pki, Duration::from_secs(5));
    (pki, server, up)
}

fn hits(s: &Server) -> usize {
    s.seen.lock().unwrap().requests.len()
}

#[tokio::test]
async fn sends_over_tls_and_reads_body() {
    let (_pki, server, up) = setup().await;
    let r: UpstreamResponse = up.send(get(server.port, "/hello"), 1 << 20).await.unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(&r.body[..], b"hello world");
    assert!(!r.truncated);
    let seen = server.seen.lock().unwrap();
    let (method, uri, headers, _) = &seen.requests[0];
    assert_eq!(method, Method::GET);
    assert_eq!(uri, "/hello");
    assert_eq!(headers["x-token"], "tok-1");
    assert_eq!(headers["host"], format!("{HOST}:{}", server.port).as_str());
}

#[tokio::test]
async fn non_2xx_status_is_returned() {
    let (_pki, server, up) = setup().await;
    let r = up.send(get(server.port, "/nope"), 1024).await.unwrap();
    assert_eq!(r.status, 404);
    assert_eq!(&r.body[..], b"not found");
}

#[tokio::test]
async fn redirect_same_origin_followed_max_3() {
    let (_pki, server, up) = setup().await;
    // /r/3 -> /r/2 -> /r/1 -> /r/0: three redirects, relative and absolute.
    let r = up.send(get(server.port, "/r/3"), 1024).await.unwrap();
    assert_eq!((r.status, &r.body[..]), (200, &b"done"[..]));
    assert_eq!(hits(&server), 4);
    // The auth-carrying headers went along on the same origin.
    for (_, _, h, _) in &server.seen.lock().unwrap().requests {
        assert_eq!(h["x-token"], "tok-1");
    }
    let before = hits(&server);
    let err = up.send(get(server.port, "/r/4"), 1024).await.unwrap_err();
    assert!(matches!(err, BrokerError::RedirectRefused), "{err:?}");
    assert_eq!(
        hits(&server) - before,
        4,
        "the 4th redirect is not followed"
    );
}

#[tokio::test]
async fn redirect_other_host_refused() {
    let (_pki, server, up) = setup().await;
    let err = up
        .send(get(server.port, "/other-host"), 1024)
        .await
        .unwrap_err();
    assert!(matches!(err, BrokerError::RedirectRefused), "{err:?}");
    assert_eq!(hits(&server), 1);
}

#[tokio::test]
async fn redirect_other_port_refused() {
    let (_pki, server, up) = setup().await;
    for path in ["/other-port", "/default-port"] {
        let err = up.send(get(server.port, path), 1024).await.unwrap_err();
        assert!(
            matches!(err, BrokerError::RedirectRefused),
            "{path}: {err:?}"
        );
    }
    assert_eq!(hits(&server), 2);
}

#[tokio::test]
async fn redirect_downgrade_refused() {
    let (_pki, server, up) = setup().await;
    for path in ["/downgrade", "/userinfo"] {
        let err = up.send(get(server.port, path), 1024).await.unwrap_err();
        assert!(
            matches!(err, BrokerError::RedirectRefused),
            "{path}: {err:?}"
        );
    }
    assert_eq!(hits(&server), 2);
}

#[tokio::test]
async fn see_other_becomes_get_without_body() {
    let (_pki, server, up) = setup().await;
    let mut b = get(server.port, "/see-other");
    b.method = Method::POST;
    b.headers
        .insert("content-type", HeaderValue::from_static("application/json"));
    b.body = Some(Bytes::from_static(b"{\"a\":1}"));
    let r = up.send(b, 1024).await.unwrap();
    assert_eq!(&r.body[..], b"GET 0");
    let seen = server.seen.lock().unwrap();
    assert_eq!(seen.requests[0].0, Method::POST);
    assert_eq!(seen.requests[0].3, 7);
    assert!(seen.requests[1].2.get("content-type").is_none());
}

#[tokio::test]
async fn timeout_is_enforced() {
    let pki = pki();
    let server = serve(&pki).await;
    let up = client(&pki, Duration::from_millis(200));
    let t0 = std::time::Instant::now();
    let err = up.send(get(server.port, "/slow"), 1024).await.unwrap_err();
    assert!(matches!(err, BrokerError::Timeout), "{err:?}");
    assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
}

#[tokio::test]
async fn read_limit_sets_truncated() {
    let (_pki, server, up) = setup().await;
    let r = up.send(get(server.port, "/big"), 100).await.unwrap();
    assert_eq!(r.body.len(), 100);
    assert!(r.truncated);
    let r = up.send(get(server.port, "/big"), 10_000).await.unwrap();
    assert_eq!(r.body.len(), 10_000);
    assert!(!r.truncated, "exactly the limit is not truncated");
    let r = up.send(get(server.port, "/big"), 9_999).await.unwrap();
    assert!(r.truncated);
}

#[tokio::test]
async fn untrusted_cert_refused() {
    let pki_server = pki();
    let server = serve(&pki_server).await;
    // A client that trusts a different CA.
    let up = client(&pki(), Duration::from_secs(5));
    let err = up.send(get(server.port, "/hello"), 1024).await.unwrap_err();
    assert!(matches!(err, BrokerError::Upstream(_)), "{err:?}");
    assert_eq!(hits(&server), 0);
    // No roots at all.
    let up = Upstream::with_roots(
        RootCertStore::empty(),
        Arc::new(Loopback { names: vec![HOST] }),
        Duration::from_secs(5),
    );
    assert!(up.send(get(server.port, "/hello"), 1024).await.is_err());
}

#[tokio::test]
async fn name_mismatch_refused() {
    let (_pki, server, _) = setup().await;
    let pki = pki();
    let mut roots = RootCertStore::empty();
    roots.add(pki.ca.clone()).unwrap();
    let up = Upstream::with_roots(
        roots,
        Arc::new(Loopback {
            names: vec!["wrong.example.test"],
        }),
        Duration::from_secs(5),
    );
    let mut b = get(server.port, "/hello");
    b.uri = format!("https://wrong.example.test:{}/hello", server.port)
        .parse()
        .unwrap();
    let err = up.send(b, 1024).await.unwrap_err();
    assert!(matches!(err, BrokerError::Upstream(_)), "{err:?}");
}

#[tokio::test]
async fn plain_http_is_never_sent() {
    let (_pki, server, up) = setup().await;
    let mut b = get(server.port, "/hello");
    b.uri = format!("http://{HOST}:{}/hello", server.port)
        .parse()
        .unwrap();
    let err = up.send(b, 1024).await.unwrap_err();
    assert!(matches!(err, BrokerError::Upstream(_)), "{err:?}");
    assert_eq!(hits(&server), 0);
}

#[tokio::test]
async fn userinfo_in_uri_refused() {
    let (_pki, server, up) = setup().await;
    let mut b = get(server.port, "/hello");
    b.uri = format!("https://u:p@{HOST}:{}/hello", server.port)
        .parse()
        .unwrap();
    assert!(up.send(b, 1024).await.is_err());
    assert_eq!(hits(&server), 0);
}

#[tokio::test]
async fn resolver_failure_is_an_upstream_error() {
    let (_pki, server, up) = setup().await;
    let mut b = get(server.port, "/hello");
    b.uri = format!("https://unknown.example.test:{}/hello", server.port)
        .parse()
        .unwrap();
    let err = up.send(b, 1024).await.unwrap_err();
    assert!(matches!(err, BrokerError::Upstream(_)), "{err:?}");
}

#[test]
fn new_loads_pem_files_from_ca_dir() {
    let pki = pki();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("test-ca.pem"), &pki.ca_pem).unwrap();
    std::fs::write(dir.path().join("ignored.txt"), "not a cert").unwrap();
    assert!(Upstream::new(dir.path(), Duration::from_secs(30)).is_ok());
    // A missing directory means no extra CAs.
    assert!(Upstream::new(&dir.path().join("missing"), Duration::from_secs(30)).is_ok());
    // A .pem file that holds no certificate is an error, not a silent skip.
    std::fs::write(dir.path().join("bad.pem"), "garbage").unwrap();
    assert!(Upstream::new(dir.path(), Duration::from_secs(30)).is_err());
}
