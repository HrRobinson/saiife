//! The pinned HTTPS client (spec §6.7.1 step 9): rustls with the `ring`
//! provider, the system roots plus the admin's CA directory, HTTP/1.1 only,
//! one connection per request, and a connector this module builds itself,
//! so no proxy environment variable (`HTTP_PROXY` and friends) is ever read.
//!
//! Redirects are followed only to the same scheme, host and port, with no
//! userinfo, at most [`MAX_REDIRECTS`] times. The timeout covers the whole
//! exchange: resolving, connecting, TLS, every redirect and the body.

use crate::request::Built;
use crate::BrokerError;
use bytes::{Bytes, BytesMut};
use http::header::{CONTENT_LENGTH, CONTENT_TYPE, HOST, LOCATION};
use http::{HeaderMap, HeaderValue, Method, Request, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

/// Redirects followed per request; one more is [`BrokerError::RedirectRefused`].
pub const MAX_REDIRECTS: usize = 3;

/// Turns a host name into addresses. The daemon uses [`SystemResolver`];
/// tests map their names to the loopback server.
pub trait Resolver: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
}

/// The system resolver (`getaddrinfo`).
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok((host, port).to_socket_addrs()?.collect())
    }
}

#[derive(Debug, Clone)]
pub struct UpstreamResponse {
    pub status: u16,
    pub headers: HeaderMap,
    /// At most `read_limit` bytes.
    pub body: Bytes,
    /// More body was available than `read_limit`.
    pub truncated: bool,
}

pub struct Upstream {
    tls: tokio_rustls::TlsConnector,
    resolver: Arc<dyn Resolver>,
    timeout: Duration,
    /// Plain `http://` is sent only by unit tests that ask for it.
    #[cfg(test)]
    allow_http: bool,
}

fn up(what: &str, e: impl std::fmt::Display) -> BrokerError {
    BrokerError::Upstream(format!("{what}: {e}"))
}

/// The `*.pem` files of `dir`, in name order. A missing directory is none.
fn load_ca_dir(dir: &Path, roots: &mut RootCertStore) -> Result<(), BrokerError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(up(&format!("CA directory {}", dir.display()), e)),
    };
    let mut paths = Vec::new();
    for e in entries {
        let e = e.map_err(|e| up(&format!("CA directory {}", dir.display()), e))?;
        let p = e.path();
        if p.extension().is_some_and(|x| x == "pem") {
            paths.push(p);
        }
    }
    paths.sort();
    for p in paths {
        let what = format!("CA file {}", p.display());
        let file = std::fs::File::open(&p).map_err(|e| up(&what, e))?;
        let mut n = 0;
        for cert in rustls_pemfile::certs(&mut io::BufReader::new(file)) {
            let cert = cert.map_err(|e| up(&what, e))?;
            roots.add(cert).map_err(|e| up(&what, e))?;
            n += 1;
        }
        if n == 0 {
            return Err(up(&what, "holds no certificate"));
        }
    }
    Ok(())
}

fn client_config(roots: RootCertStore) -> Result<ClientConfig, BrokerError> {
    let mut cfg =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| up("TLS", e))?
            .with_root_certificates(roots)
            .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

/// Aborts the connection task when the exchange is done or abandoned.
struct ConnGuard(JoinHandle<()>);

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn default_port(scheme: &str) -> u16 {
    if scheme == "http" {
        80
    } else {
        443
    }
}

/// `(scheme, lowercase host, effective port)` of a URI without userinfo.
fn origin(uri: &Uri) -> Option<(String, String, u16)> {
    let scheme = uri.scheme_str()?.to_ascii_lowercase();
    let authority = uri.authority()?;
    if authority.as_str().contains('@') {
        return None;
    }
    let port = authority.port_u16().unwrap_or(default_port(&scheme));
    Some((scheme, authority.host().to_ascii_lowercase(), port))
}

/// The redirect target of `location` from `current`, if it is an absolute
/// URL, a scheme-relative one or an absolute path. Anything else (a
/// relative path, garbage) is refused by the caller.
fn redirect_target(current: &Uri, location: &str) -> Option<Uri> {
    let scheme = current.scheme_str()?;
    let text = if location.starts_with("//") {
        format!("{scheme}:{location}")
    } else if location.starts_with('/') {
        format!("{scheme}://{}{location}", current.authority()?.as_str())
    } else {
        location.to_string()
    };
    let uri: Uri = text.parse().ok()?;
    uri.scheme()?;
    Some(uri)
}

impl Upstream {
    /// The production client: the native roots plus every `*.pem` in
    /// `ca_dir` (`/etc/saiife/ca`; missing means none).
    pub fn new(ca_dir: &Path, timeout: Duration) -> Result<Upstream, BrokerError> {
        let mut roots = RootCertStore::empty();
        // Unreadable platform certificates are skipped, as every rustls
        // client does; an empty store is refused below.
        let native = rustls_native_certs::load_native_certs();
        roots.add_parsable_certificates(native.certs);
        load_ca_dir(ca_dir, &mut roots)?;
        if roots.is_empty() {
            return Err(BrokerError::Upstream("no trusted root certificates".into()));
        }
        Ok(Upstream {
            tls: tokio_rustls::TlsConnector::from(Arc::new(client_config(roots)?)),
            resolver: Arc::new(SystemResolver),
            timeout,
            #[cfg(test)]
            allow_http: false,
        })
    }

    /// The test seam: the given roots and resolver.
    pub fn with_roots(
        roots: RootCertStore,
        resolver: Arc<dyn Resolver>,
        timeout: Duration,
    ) -> Upstream {
        let cfg = client_config(roots).expect("the ring provider supports the default versions");
        Upstream {
            tls: tokio_rustls::TlsConnector::from(Arc::new(cfg)),
            resolver,
            timeout,
            #[cfg(test)]
            allow_http: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn allow_http_for_tests(mut self) -> Self {
        self.allow_http = true;
        self
    }

    fn scheme_allowed(&self, scheme: &str) -> bool {
        #[cfg(test)]
        if self.allow_http && scheme == "http" {
            return true;
        }
        scheme == "https"
    }

    /// Sends `b`, follows same-origin redirects and reads the body up to
    /// `read_limit` bytes, all within the timeout.
    pub async fn send(&self, b: Built, read_limit: usize) -> Result<UpstreamResponse, BrokerError> {
        match tokio::time::timeout(self.timeout, self.exchange(b, read_limit)).await {
            Ok(r) => r,
            Err(_) => Err(BrokerError::Timeout),
        }
    }

    async fn exchange(
        &self,
        mut b: Built,
        read_limit: usize,
    ) -> Result<UpstreamResponse, BrokerError> {
        let start =
            origin(&b.uri).ok_or_else(|| up("request", "the URL needs a host and no userinfo"))?;
        if !self.scheme_allowed(&start.0) {
            return Err(up("request", "only https is sent"));
        }
        let mut redirects = 0;
        loop {
            let (resp, guard) = self.once(&b).await?;
            let status = resp.status().as_u16();
            if matches!(status, 301 | 302 | 303 | 307 | 308) {
                if redirects == MAX_REDIRECTS {
                    return Err(BrokerError::RedirectRefused);
                }
                let target = resp
                    .headers()
                    .get(LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|l| redirect_target(&b.uri, l))
                    .ok_or(BrokerError::RedirectRefused)?;
                if origin(&target).as_ref() != Some(&start) {
                    return Err(BrokerError::RedirectRefused);
                }
                drop(guard);
                redirects += 1;
                b.uri = target;
                if status == 303 {
                    b.method = Method::GET;
                    b.body = None;
                    b.headers.remove(CONTENT_TYPE);
                    b.headers.remove(CONTENT_LENGTH);
                }
                continue;
            }
            let (parts, body) = resp.into_parts();
            let (body, truncated) = read_capped(body, read_limit).await?;
            drop(guard);
            return Ok(UpstreamResponse {
                status,
                headers: parts.headers,
                body,
                truncated,
            });
        }
    }

    /// One request on a fresh connection.
    async fn once(&self, b: &Built) -> Result<(http::Response<Incoming>, ConnGuard), BrokerError> {
        let (scheme, host, port) =
            origin(&b.uri).ok_or_else(|| up("request", "the URL needs a host and no userinfo"))?;
        let resolver = self.resolver.clone();
        let h = host.clone();
        let addrs = tokio::task::spawn_blocking(move || resolver.resolve(&h, port))
            .await
            .map_err(|e| up("resolve", e))?
            .map_err(|e| up(&format!("resolve {host}"), e))?;
        let mut tcp = None;
        let mut last = io::Error::new(io::ErrorKind::NotFound, "no address");
        for a in addrs {
            match TcpStream::connect(a).await {
                Ok(s) => {
                    tcp = Some(s);
                    break;
                }
                Err(e) => last = e,
            }
        }
        let tcp = tcp.ok_or_else(|| up(&format!("connect {host}:{port}"), last))?;
        let _ = tcp.set_nodelay(true);

        let path = b.uri.path_and_query().map_or("/", |p| p.as_str());
        let mut req = Request::builder()
            .method(b.method.clone())
            .uri(path)
            .body(Full::new(b.body.clone().unwrap_or_default()))
            .map_err(|e| up("request", e))?;
        *req.headers_mut() = b.headers.clone();
        let authority = b.uri.authority().map_or("", |a| a.as_str());
        req.headers_mut().insert(
            HOST,
            HeaderValue::from_str(authority).map_err(|e| up("request", e))?,
        );

        if scheme == "http" {
            return exchange_on(tcp, req).await;
        }
        let name = ServerName::try_from(host.clone()).map_err(|e| up("TLS server name", e))?;
        let tls = self
            .tls
            .connect(name, tcp)
            .await
            .map_err(|e| up(&format!("TLS {host}"), e))?;
        exchange_on(tls, req).await
    }
}

async fn exchange_on<S>(
    io: S,
    req: Request<Full<Bytes>>,
) -> Result<(http::Response<Incoming>, ConnGuard), BrokerError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(|e| up("HTTP", e))?;
    let guard = ConnGuard(tokio::spawn(async move {
        let _ = conn.await;
    }));
    let resp = sender.send_request(req).await.map_err(|e| up("HTTP", e))?;
    Ok((resp, guard))
}

/// Reads at most `limit` bytes; `true` when more was available.
async fn read_capped(mut body: Incoming, limit: usize) -> Result<(Bytes, bool), BrokerError> {
    let mut buf = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| up("response body", e))?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if buf.len() + data.len() > limit {
            buf.extend_from_slice(&data[..limit - buf.len()]);
            return Ok((buf.freeze(), true));
        }
        buf.extend_from_slice(&data);
    }
    Ok((buf.freeze(), false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::service::service_fn;
    use std::net::Ipv4Addr;

    #[test]
    fn redirect_targets() {
        let cur: Uri = "https://a.test:8443/x/y?q=1".parse().unwrap();
        let t = |l: &str| redirect_target(&cur, l).map(|u| u.to_string());
        assert_eq!(t("/z").as_deref(), Some("https://a.test:8443/z"));
        assert_eq!(t("//b.test/z").as_deref(), Some("https://b.test/z"));
        assert_eq!(
            t("https://a.test:8443/z").as_deref(),
            Some("https://a.test:8443/z")
        );
        assert_eq!(t("z"), None);
        assert_eq!(t(""), None);
        assert_eq!(t("ht tp://x"), None);
    }

    #[test]
    fn origins() {
        let o = |s: &str| origin(&s.parse().unwrap());
        assert_eq!(
            o("https://A.test/x"),
            Some(("https".into(), "a.test".into(), 443))
        );
        assert_eq!(o("https://a.test:443/"), o("https://a.test/"));
        assert_eq!(
            o("http://a.test/"),
            Some(("http".into(), "a.test".into(), 80))
        );
        assert_eq!(o("https://u@a.test/"), None);
        assert_eq!(o("/relative"), None);
    }

    struct Local;
    impl Resolver for Local {
        fn resolve(&self, _: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
            Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, port))])
        }
    }

    /// The plain-HTTP seam exists only here, and without it `http://` is
    /// refused before any connection.
    #[tokio::test]
    async fn plain_http_only_through_the_test_seam() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let svc = service_fn(|_req| async {
                        Ok::<_, std::convert::Infallible>(http::Response::new(Full::new(
                            Bytes::from_static(b"plain"),
                        )))
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tcp), svc)
                        .await;
                });
            }
        });
        let built = || Built {
            method: Method::GET,
            uri: format!("http://plain.test:{port}/").parse().unwrap(),
            headers: HeaderMap::new(),
            body: None,
        };
        let strict = Upstream::with_roots(
            RootCertStore::empty(),
            Arc::new(Local),
            Duration::from_secs(5),
        );
        assert!(matches!(
            strict.send(built(), 1024).await,
            Err(BrokerError::Upstream(_))
        ));
        let seam = Upstream::with_roots(
            RootCertStore::empty(),
            Arc::new(Local),
            Duration::from_secs(5),
        )
        .allow_http_for_tests();
        let r = seam.send(built(), 1024).await.unwrap();
        assert_eq!(&r.body[..], b"plain");
    }
}
