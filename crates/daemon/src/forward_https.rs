//! The `https` forwarding target (plan 12 decision 5): batches POSTed to a
//! URL through the broker's pinned client (rustls, the system roots plus
//! `/etc/saiife/ca` or the target's `ca`, no proxy variables, a POST never
//! follows a redirect), with a 30 s timeout per POST.
//!
//! - A POST carries at most 500 records and at most 1 MiB of body. A batch
//!   that would be larger is sent as several POSTs, in order; one record
//!   longer than 1 MiB goes alone (refused, the error names its `seq` and
//!   size and says to raise the SIEM's body limit). When a later POST of a
//!   batch fails, the whole batch goes again, the accepted parts included:
//!   at least once.
//! - `json`: the body is a JSON array whose elements are the lines,
//!   embedded byte for byte (each line is checked to be UTF-8 and one JSON
//!   value first). A line that is not JSON (it cannot be in a chain that
//!   verifies, but a foreign line can sit in a month file) would make the
//!   array invalid, so it is sent as a JSON string holding the line instead
//!   (invalid UTF-8 replaced): the batch still goes through, the SIEM still
//!   sees the line, and `verify` on the copy reports it as it would locally.
//! - `splunk-hec`: newline-separated `{"event": <the line as a JSON
//!   string>, "sourcetype": "saiife"}` objects; decoding the string gives
//!   back the exact line.
//! - `auth_secret` names a vault secret read at each send: a `token` secret
//!   is sent as `Authorization: Bearer <token>`, a `header` secret's value
//!   as it is. Its value never appears in an error, a record or `Debug`; a
//!   locked vault or a missing secret is a retry.
//! - A 2xx answer means accepted. Every other answer (a 3xx, a 4xx, 429,
//!   5xx) and every network error is retried with backoff: nothing is ever
//!   dropped because of an answer.

use crate::forwarder::{SendError, SendFuture, TargetClient, Transport, SEND_TIMEOUT};
use crate::notifier::Secret;
use crate::vault::Kind;
use bytes::Bytes;
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue, Method, Uri};
use saiife_broker::mask::Masker;
use saiife_broker::request::Built;
use saiife_broker::BrokerError;
use saiife_policy::HttpsFormat;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Records per POST.
pub const MAX_RECORDS: usize = 500;
/// Body bytes per POST.
pub const MAX_BYTES: usize = 1 << 20;

/// Looks up a vault secret by name (`None`: locked vault or no such secret).
pub type Secrets = Arc<dyn Fn(&str) -> Option<Secret> + Send + Sync>;

/// POSTs batches to one URL.
pub struct HttpsTransport {
    uri: Uri,
    format: HttpsFormat,
    auth_secret: Option<String>,
    secrets: Secrets,
    client: TargetClient,
}

impl std::fmt::Debug for HttpsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsTransport")
            .field("uri", &self.uri)
            .field("format", &self.format)
            .field("auth_secret", &self.auth_secret)
            .finish()
    }
}

/// One line as an element of the `json` array: the line itself when it is
/// UTF-8 and one JSON value, else the line as a JSON string.
fn json_element(line: &[u8], out: &mut Vec<u8>) {
    let raw = std::str::from_utf8(line)
        .is_ok_and(|l| serde_json::from_str::<serde::de::IgnoredAny>(l).is_ok());
    if raw {
        out.extend_from_slice(line);
    } else {
        let s = serde_json::to_string(&String::from_utf8_lossy(line)).unwrap_or_default();
        out.extend_from_slice(s.as_bytes());
    }
}

fn hec_element(line: &[u8], out: &mut Vec<u8>) {
    let s = serde_json::to_string(&String::from_utf8_lossy(line)).unwrap_or_default();
    out.extend_from_slice(b"{\"event\": ");
    out.extend_from_slice(s.as_bytes());
    out.extend_from_slice(b", \"sourcetype\": \"saiife\"}");
}

/// One POST: its body, and the record when it is a single one over
/// [`MAX_BYTES`] (`(seq, body bytes)`), for the error if it is refused.
pub struct Body {
    pub bytes: Vec<u8>,
    pub oversized: Option<(Option<u64>, usize)>,
}

/// The bodies of a batch, in order: each at most [`MAX_RECORDS`] records
/// and [`MAX_BYTES`] bytes, except a single record that is larger alone.
pub fn bodies(format: HttpsFormat, lines: &[Bytes]) -> Vec<Body> {
    let seq = |line: &[u8]| {
        serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(line)
            .ok()
            .and_then(|m| m.get("seq").and_then(|s| s.as_u64()))
    };
    let mut first: Vec<&Bytes> = Vec::new();
    let raw = bodies_raw(format, lines, &mut first);
    raw.into_iter()
        .zip(first)
        .map(|((bytes, n), line)| {
            let oversized = (n == 1 && bytes.len() > MAX_BYTES).then(|| (seq(line), bytes.len()));
            Body { bytes, oversized }
        })
        .collect()
}

/// `(body, records)` per POST; `first` gets each POST's first line.
fn bodies_raw<'l>(
    format: HttpsFormat,
    lines: &'l [Bytes],
    first: &mut Vec<&'l Bytes>,
) -> Vec<(Vec<u8>, usize)> {
    let (open, sep, close): (&[u8], &[u8], &[u8]) = match format {
        HttpsFormat::Json => (b"[", b",", b"]"),
        HttpsFormat::SplunkHec => (b"", b"\n", b""),
    };
    let mut out = Vec::new();
    let mut body: Vec<u8> = Vec::new();
    let mut n = 0;
    let mut el = Vec::new();
    for line in lines {
        el.clear();
        match format {
            HttpsFormat::Json => json_element(line, &mut el),
            HttpsFormat::SplunkHec => hec_element(line, &mut el),
        }
        let grown = body.len() + sep.len() + el.len() + close.len();
        if n > 0 && (n == MAX_RECORDS || grown > MAX_BYTES) {
            body.extend_from_slice(close);
            out.push((std::mem::take(&mut body), n));
            n = 0;
        }
        if n == 0 {
            first.push(line);
            body.extend_from_slice(open);
        } else {
            body.extend_from_slice(sep);
        }
        body.extend_from_slice(&el);
        n += 1;
    }
    if n > 0 {
        body.extend_from_slice(close);
        out.push((body, n));
    }
    out
}

impl HttpsTransport {
    /// `url` was validated (`https://host[:port]/...`).
    pub fn new(
        url: &str,
        format: HttpsFormat,
        auth_secret: Option<String>,
        secrets: Secrets,
        client: TargetClient,
    ) -> Result<HttpsTransport, String> {
        let uri: Uri = url
            .parse()
            .map_err(|_| "the forward url is not a valid URL".to_string())?;
        Ok(HttpsTransport {
            uri,
            format,
            auth_secret,
            secrets,
            client,
        })
    }

    /// The `Authorization` value, and the forms of it to mask.
    fn authorization(&self) -> Result<Option<(HeaderValue, Zeroizing<String>)>, SendError> {
        let Some(name) = &self.auth_secret else {
            return Ok(None);
        };
        let secret = (self.secrets)(name).ok_or_else(|| {
            SendError::Retry(format!(
                "secret {name} is not available (vault locked or no such secret)"
            ))
        })?;
        let field = |k: &str| secret.fields.get(k).map(|v| v.as_str());
        let (value, raw) = match secret.kind {
            Kind::Token => {
                let t = field("token")
                    .ok_or_else(|| SendError::Retry(format!("secret {name} holds no token")))?;
                (
                    Zeroizing::new(format!("Bearer {t}")),
                    Zeroizing::new(t.to_string()),
                )
            }
            Kind::Header => {
                let v = field("value")
                    .ok_or_else(|| SendError::Retry(format!("secret {name} holds no value")))?;
                (Zeroizing::new(v.to_string()), Zeroizing::new(v.to_string()))
            }
            Kind::Basic => {
                return Err(SendError::Retry(format!(
                    "secret {name} must be of kind token or header"
                )))
            }
        };
        let mut hv = HeaderValue::from_str(&value)
            .map_err(|_| SendError::Retry(format!("secret {name} is not a valid header value")))?;
        hv.set_sensitive(true);
        Ok(Some((hv, raw)))
    }

    async fn post(&self, body: Vec<u8>) -> Result<(), SendError> {
        let auth = self.authorization()?;
        let masker = Masker::new(
            &auth
                .as_ref()
                .map(|(_, raw)| raw.as_str())
                .into_iter()
                .collect::<Vec<_>>(),
        );
        let clean = |e: String| masker.mask_text(&e);
        let up = self.client.get().map_err(|e| SendError::Retry(clean(e)))?;
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Some((hv, _)) = auth {
            headers.insert(AUTHORIZATION, hv);
        }
        let built = Built {
            method: Method::POST,
            uri: self.uri.clone(),
            headers,
            body: Some(Bytes::from(body)),
        };
        match tokio::time::timeout(SEND_TIMEOUT, up.send(built, 4096)).await {
            Err(_) => Err(SendError::Retry("the https target timed out".into())),
            Ok(Err(BrokerError::RedirectRefused)) => Err(SendError::Retry(
                "the https target redirected; redirects are not followed".into(),
            )),
            Ok(Err(BrokerError::Timeout)) => {
                Err(SendError::Retry("the https target timed out".into()))
            }
            Ok(Err(e)) => Err(SendError::Retry(clean(e.to_string()))),
            Ok(Ok(r)) if (200..300).contains(&r.status) => Ok(()),
            Ok(Ok(r)) => Err(SendError::Retry(format!(
                "the https target answered {}",
                r.status
            ))),
        }
    }
}

impl Transport for HttpsTransport {
    fn send<'a>(&'a self, lines: &'a [Bytes]) -> SendFuture<'a> {
        Box::pin(async move {
            for body in bodies(self.format, lines) {
                match (self.post(body.bytes).await, body.oversized) {
                    (Ok(()), _) => {}
                    (Err(SendError::Retry(why)), Some((seq, size))) => {
                        let seq =
                            seq.map_or_else(|| "without a seq".into(), |s| format!("seq {s}"));
                        return Err(SendError::Retry(format!(
                            "{why}; record {seq} alone is a {size}-byte body, over the 1 MiB \
                             batch limit: raise the SIEM's request body limit"
                        )));
                    }
                    (Err(e), _) => return Err(e),
                }
            }
            Ok(())
        })
    }

    fn max_batch(&self) -> (usize, usize) {
        (MAX_RECORDS, MAX_BYTES)
    }
}

/// Loopback TLS for the transport tests: an `rcgen` CA, a leaf for
/// [`TEST_HOST`], and a client that resolves every name to 127.0.0.1.
#[cfg(test)]
pub(crate) mod testing {
    use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use saiife_broker::upstream::{Resolver, Upstream};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    pub const TEST_HOST: &str = "siem.example.test";

    pub struct Pki {
        pub ca: CertificateDer<'static>,
        pub ca_pem: String,
        pub leaf: CertificateDer<'static>,
        pub key: PrivatePkcs8KeyDer<'static>,
    }

    pub fn pki() -> Pki {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
        let key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec![TEST_HOST.to_string()])
            .unwrap()
            .signed_by(&key, &ca)
            .unwrap();
        Pki {
            ca: ca.der().clone(),
            ca_pem: ca.pem(),
            leaf: leaf.der().clone(),
            key: PrivatePkcs8KeyDer::from(key.serialize_der()),
        }
    }

    pub fn acceptor(p: &Pki, alpn: &[&[u8]]) -> tokio_rustls::TlsAcceptor {
        let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![p.leaf.clone()],
            PrivateKeyDer::Pkcs8(p.key.clone_key()),
        )
        .unwrap();
        cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
        tokio_rustls::TlsAcceptor::from(Arc::new(cfg))
    }

    struct Loopback;

    impl Resolver for Loopback {
        fn resolve(&self, _host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
            Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, port))])
        }
    }

    pub fn upstream(roots: rustls::RootCertStore) -> Upstream {
        Upstream::with_roots(roots, Arc::new(Loopback), Duration::from_secs(10))
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{acceptor, pki, upstream, Pki, TEST_HOST};
    use super::*;
    use http_body_util::{BodyExt, Full};
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use tokio::net::TcpListener;

    #[derive(Debug, Clone)]
    struct Seen {
        auth: Option<String>,
        content_type: Option<String>,
        body: Vec<u8>,
    }

    struct Mock {
        port: u16,
        seen: Arc<Mutex<Vec<Seen>>>,
        /// The status of every answer; 302 adds a Location.
        status: Arc<Mutex<u16>>,
        /// What the answer body says (to see it never reaches an error).
        echo_auth: bool,
    }

    async fn mock(p: &Pki, echo_auth: bool) -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acc = acceptor(p, &[b"http/1.1"]);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let status = Arc::new(Mutex::new(200u16));
        let (s2, st2) = (seen.clone(), status.clone());
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acc = acc.clone();
                let (seen, status) = (s2.clone(), st2.clone());
                tokio::spawn(async move {
                    let Ok(tls) = acc.accept(tcp).await else {
                        return;
                    };
                    let svc = service_fn(move |req: http::Request<Incoming>| {
                        let (seen, status) = (seen.clone(), status.clone());
                        async move {
                            let h = |n| {
                                req.headers()
                                    .get(n)
                                    .map(|v: &HeaderValue| v.to_str().unwrap().to_string())
                            };
                            let auth = h(AUTHORIZATION);
                            let content_type = h(CONTENT_TYPE);
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            seen.lock().unwrap().push(Seen {
                                auth: auth.clone(),
                                content_type,
                                body: body.to_vec(),
                            });
                            let code = *status.lock().unwrap();
                            let text = if echo_auth {
                                format!("bad auth: {}", auth.unwrap_or_default())
                            } else {
                                String::new()
                            };
                            let mut resp = http::Response::new(Full::new(Bytes::from(text)));
                            *resp.status_mut() = http::StatusCode::from_u16(code).unwrap();
                            if code == 302 {
                                resp.headers_mut().insert(
                                    http::header::LOCATION,
                                    HeaderValue::from_static("/elsewhere"),
                                );
                            }
                            Ok::<_, std::convert::Infallible>(resp)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), svc)
                        .await;
                });
            }
        });
        Mock {
            port,
            seen,
            status,
            echo_auth,
        }
    }

    fn no_secrets() -> Secrets {
        Arc::new(|_| None)
    }

    fn secrets(name: &'static str, kind: Kind, field: &'static str, value: String) -> Secrets {
        Arc::new(move |n| {
            (n == name).then(|| Secret {
                kind,
                fields: BTreeMap::from([(field.to_string(), Zeroizing::new(value.clone()))]),
            })
        })
    }

    fn transport(
        p: &Pki,
        m: &Mock,
        format: HttpsFormat,
        auth: Option<&str>,
        s: Secrets,
    ) -> HttpsTransport {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(p.ca.clone()).unwrap();
        let up = upstream(roots);
        HttpsTransport::new(
            &format!("https://{TEST_HOST}:{}/services/collector/event", m.port),
            format,
            auth.map(str::to_string),
            s,
            TargetClient::new(move || Ok(up.with_timeout(SEND_TIMEOUT))),
        )
        .unwrap()
    }

    fn rec(seq: usize, pad: usize) -> Bytes {
        Bytes::from(format!(
            r#"{{"v":1,"seq":{seq},"ts":"2026-10-27T10:11:12.345Z","input":"q \"x\" ü {}"}}"#,
            "p".repeat(pad)
        ))
    }

    #[tokio::test]
    async fn https_json_body_is_the_exact_lines() {
        let p = pki();
        let m = mock(&p, false);
        let m = m.await;
        let t = transport(&p, &m, HttpsFormat::Json, None, no_secrets());
        let lines = [rec(1, 0), rec(2, 3), Bytes::from_static(b"not json \"x\"")];
        t.send(&lines).await.unwrap();
        let seen = m.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].content_type.as_deref(), Some("application/json"));
        assert_eq!(seen[0].auth, None);
        let want = [
            b"[" as &[u8],
            &lines[0],
            b",",
            &lines[1],
            b",",
            br#""not json \"x\"""#,
            b"]",
        ]
        .concat();
        assert_eq!(seen[0].body, want);
        let v: Vec<serde_json::Value> = serde_json::from_slice(&seen[0].body).unwrap();
        assert_eq!(v.len(), 3);
    }

    #[tokio::test]
    async fn https_batch_limits_500_and_1mib() {
        let p = pki();
        let m = mock(&p, false).await;
        let t = transport(&p, &m, HttpsFormat::Json, None, no_secrets());
        assert_eq!(t.max_batch(), (500, 1 << 20));
        // 1200 small records: 500, 500, 200, in order.
        let lines: Vec<Bytes> = (0..1200).map(|i| rec(i, 0)).collect();
        t.send(&lines).await.unwrap();
        let counts: Vec<usize> = m
            .seen
            .lock()
            .unwrap()
            .iter()
            .map(|s| {
                serde_json::from_slice::<Vec<serde_json::Value>>(&s.body)
                    .unwrap()
                    .len()
            })
            .collect();
        assert_eq!(counts, [500, 500, 200]);
        m.seen.lock().unwrap().clear();
        // 300 KiB records: 3 fit in 1 MiB, the 4th starts a new POST; one
        // record over 1 MiB goes alone.
        let lines: Vec<Bytes> = (0..5)
            .map(|i| rec(i, 300 * 1024))
            .chain([rec(9, 1100 * 1024)])
            .collect();
        t.send(&lines).await.unwrap();
        let seen = m.seen.lock().unwrap().clone();
        let counts: Vec<usize> = seen
            .iter()
            .map(|s| {
                serde_json::from_slice::<Vec<serde_json::Value>>(&s.body)
                    .unwrap()
                    .len()
            })
            .collect();
        assert_eq!(counts, [3, 2, 1]);
        assert!(seen[..2].iter().all(|s| s.body.len() <= 1 << 20));
        // The same for HEC, whose escaping makes a body longer than its lines.
        m.seen.lock().unwrap().clear();
        let t = transport(&p, &m, HttpsFormat::SplunkHec, None, no_secrets());
        let lines: Vec<Bytes> = (0..4).map(|i| rec(i, 300 * 1024)).collect();
        t.send(&lines).await.unwrap();
        let seen = m.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 2);
        assert!(seen.iter().all(|s| s.body.len() <= 1 << 20));
    }

    #[tokio::test]
    async fn https_json_non_utf8_line_is_a_string() {
        let p = pki();
        let m = mock(&p, false).await;
        let t = transport(&p, &m, HttpsFormat::Json, None, no_secrets());
        let bad = Bytes::from_static(b"{\"a\":\"x\xff\"}");
        t.send(&[rec(1, 0), bad]).await.unwrap();
        let seen = m.seen.lock().unwrap().clone();
        let v: Vec<serde_json::Value> = serde_json::from_slice(&seen[0].body).unwrap();
        assert!(v[0].is_object());
        assert_eq!(
            v[1],
            serde_json::Value::String("{\"a\":\"x\u{fffd}\"}".into())
        );
    }

    #[tokio::test]
    async fn https_oversized_record_refused_names_seq_and_size() {
        let p = pki();
        let m = mock(&p, false).await;
        *m.status.lock().unwrap() = 413;
        let t = transport(&p, &m, HttpsFormat::Json, None, no_secrets());
        let err = t.send(&[rec(77, 1100 * 1024)]).await.unwrap_err();
        let SendError::Retry(w) = &err else {
            panic!("{err:?}")
        };
        assert!(w.contains("413") && w.contains("seq 77"), "{w}");
        assert!(
            w.contains("-byte body") && w.contains("raise the SIEM"),
            "{w}"
        );
        // A normal record refused says only the answer.
        let err = t.send(&[rec(78, 0)]).await.unwrap_err();
        assert!(!format!("{err}").contains("raise"), "{err}");
    }

    #[tokio::test]
    async fn https_splunk_hec_shape() {
        let p = pki();
        let m = mock(&p, false).await;
        let t = transport(&p, &m, HttpsFormat::SplunkHec, None, no_secrets());
        let lines = [rec(1, 0), rec(2, 0)];
        t.send(&lines).await.unwrap();
        let seen = m.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        let body = String::from_utf8(seen[0].body.clone()).unwrap();
        let objs: Vec<&str> = body.split('\n').collect();
        assert_eq!(objs.len(), 2);
        for (o, line) in objs.iter().zip(&lines) {
            let line = std::str::from_utf8(line).unwrap();
            assert_eq!(
                *o,
                format!(
                    "{{\"event\": {}, \"sourcetype\": \"saiife\"}}",
                    serde_json::to_string(line).unwrap()
                )
            );
            let v: serde_json::Value = serde_json::from_str(o).unwrap();
            // Decoding the event string gives back the exact line.
            assert_eq!(v["event"].as_str(), Some(line));
            assert_eq!(v["sourcetype"], "saiife");
        }
    }

    #[tokio::test]
    async fn https_auth_from_vault_never_logged() {
        let p = pki();
        let m = mock(&p, true).await;
        let token = concat!("hec", "-tok", "en-", "7f3a9c1d2e4b");
        let t = transport(
            &p,
            &m,
            HttpsFormat::Json,
            Some("hec"),
            secrets("hec", Kind::Token, "token", token.to_string()),
        );
        t.send(&[rec(1, 0)]).await.unwrap();
        assert_eq!(
            m.seen.lock().unwrap()[0].auth.as_deref(),
            Some(format!("Bearer {token}").as_str())
        );
        // A refusal whose body echoes the header: the error names the code only.
        *m.status.lock().unwrap() = 401;
        let err = t.send(&[rec(2, 0)]).await.unwrap_err();
        assert!(m.echo_auth);
        let text = format!("{err} {err:?} {t:?}");
        assert!(text.contains("401"), "{text}");
        assert!(!text.contains(token), "{text}");
        assert!(!text.contains("7f3a9c1d2e4b"), "{text}");

        // A `header` secret is sent as it is.
        let value = concat!("Splunk ", "abcd", "-1234-", "secretvalue");
        let t = transport(
            &p,
            &m,
            HttpsFormat::Json,
            Some("hdr"),
            secrets("hdr", Kind::Header, "value", value.to_string()),
        );
        *m.status.lock().unwrap() = 200;
        t.send(&[rec(3, 0)]).await.unwrap();
        assert_eq!(m.seen.lock().unwrap()[2].auth.as_deref(), Some(value));
        assert!(!format!("{t:?}").contains("secretvalue"));
        // A network failure names the target, never the value.
        let mut roots = rustls::RootCertStore::empty();
        roots.add(pki().ca).unwrap();
        let up = upstream(roots);
        let bad = HttpsTransport::new(
            &format!("https://{TEST_HOST}:{}/x", m.port),
            HttpsFormat::Json,
            Some("hdr".into()),
            secrets("hdr", Kind::Header, "value", value.to_string()),
            TargetClient::new(move || Ok(up.with_timeout(SEND_TIMEOUT))),
        )
        .unwrap();
        let err = bad.send(&[rec(4, 0)]).await.unwrap_err();
        assert!(!format!("{err:?}").contains("secretvalue"), "{err:?}");

        // A locked vault (no secret) or a basic secret: retried, not sent
        // without the header.
        let before = m.seen.lock().unwrap().len();
        let locked = transport(&p, &m, HttpsFormat::Json, Some("hec"), no_secrets());
        assert!(
            matches!(locked.send(&[rec(5, 0)]).await, Err(SendError::Retry(w)) if w.contains("not available"))
        );
        let basic = transport(
            &p,
            &m,
            HttpsFormat::Json,
            Some("b"),
            secrets("b", Kind::Basic, "password", "pw-1234567890".into()),
        );
        assert!(matches!(
            basic.send(&[rec(5, 0)]).await,
            Err(SendError::Retry(_))
        ));
        assert_eq!(m.seen.lock().unwrap().len(), before);
    }

    #[tokio::test]
    async fn https_4xx_retries_not_drops() {
        let p = pki();
        let m = mock(&p, false).await;
        let t = transport(&p, &m, HttpsFormat::Json, None, no_secrets());
        for code in [400u16, 403, 404, 413, 429, 500, 503] {
            *m.status.lock().unwrap() = code;
            let err = t.send(&[rec(1, 0)]).await.unwrap_err();
            assert!(
                matches!(&err, SendError::Retry(w) if w.contains(&code.to_string())),
                "{code}: {err:?}"
            );
        }
        // The same batch goes through once the target takes it.
        *m.status.lock().unwrap() = 204;
        t.send(&[rec(1, 0)]).await.unwrap();
        // Nothing listening: a retry too.
        let dead = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        let m2 = Mock {
            port: dead,
            seen: Arc::default(),
            status: Arc::default(),
            echo_auth: false,
        };
        let t = transport(&p, &m2, HttpsFormat::Json, None, no_secrets());
        assert!(matches!(
            t.send(&[rec(1, 0)]).await,
            Err(SendError::Retry(_))
        ));
    }

    #[tokio::test]
    async fn https_no_redirect() {
        let p = pki();
        let m = mock(&p, false).await;
        *m.status.lock().unwrap() = 302;
        let t = transport(&p, &m, HttpsFormat::Json, None, no_secrets());
        let err = t.send(&[rec(1, 0)]).await.unwrap_err();
        assert!(
            matches!(&err, SendError::Retry(w) if w.contains("redirect")),
            "{err:?}"
        );
        // One POST, to the configured path only: the Location was not followed.
        assert_eq!(m.seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn https_untrusted_cert_refused() {
        let p = pki();
        let m = mock(&p, false).await;
        let other = pki();
        let t = transport(&other, &m, HttpsFormat::Json, None, no_secrets());
        assert!(matches!(
            t.send(&[rec(1, 0)]).await,
            Err(SendError::Retry(_))
        ));
        assert!(m.seen.lock().unwrap().is_empty());
    }
}
