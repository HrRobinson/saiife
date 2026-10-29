//! Cloud sign mode end to end in process (plan 15, Task 9): a daemon context
//! on temp dirs (the real audit writer and vault), the built-in cloud
//! manifests, and one loopback TLS mock with an `rcgen` certificate for the
//! real host names (S3, STS, the GCP and Azure token endpoints, GCS, ARM).
//! The test resolver maps those names to 127.0.0.1; nothing leaves the host.
//! Calls go through `api.call` as a client would send them.
#![cfg(target_os = "linux")]

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use bytes::Bytes;
use http::{HeaderMap, Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;
use saiife_audit::{ChainWriter, WriterOptions};
use saiife_broker::cloud::sigv4::{self, AwsCreds};
use saiife_broker::limits::Limiter;
use saiife_broker::pipeline::PolicySnapshot;
use saiife_broker::request::Built;
use saiife_broker::upstream::{Resolver, Upstream};
use saiife_broker::{Catalog, Manifest};
use saiife_daemon::ops::{Ctx, CtxInit, GatewayPolicy, PolicyState};
use saiife_daemon::sessions::RealProc;
use saiife_daemon::tokens::Tokens;
use saiife_daemon::vault::{self, Entry, Kind, VaultState};
use saiife_daemon::writer::{self, WriterConfig};
use saiife_ipc::msg::Request as IpcRequest;
use saiife_ipc::peer::PeerCred;
use saiife_policy::{Directory, Event, Fsync, GroupEntry, Mode, SystemConfig, UserEntry};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use time::OffsetDateTime;
use tokio::net::TcpListener;
use zeroize::Zeroizing;

const REGION: &str = "eu-west-1";
const S3_HOST: &str = "s3.eu-west-1.amazonaws.com";
const STS_HOST: &str = "sts.eu-west-1.amazonaws.com";
const GCP_TOKEN_HOST: &str = "oauth2.googleapis.com";
const GCS_HOST: &str = "storage.googleapis.com";
const AZ_LOGIN_HOST: &str = "login.microsoftonline.com";
const ARM_HOST: &str = "management.azure.com";
const AZ_US_HOST: &str = "login.microsoftonline.us";
const SF_HOST: &str = "acme.sf.test";
/// What the resolver knows. `login.chinacloudapi.cn` is not here: a
/// service on that authority fails its mint with `network`.
const HOSTS: [&str; 8] = [
    S3_HOST,
    STS_HOST,
    GCP_TOKEN_HOST,
    GCS_HOST,
    AZ_LOGIN_HOST,
    AZ_US_HOST,
    ARM_HOST,
    SF_HOST,
];

const SCOPE_GCS: &str = "https://www.googleapis.com/auth/devstorage.read_write";
const SCOPE_OTHER: &str = "https://www.googleapis.com/auth/devstorage.read_only";
const SCOPE_ARM: &str = "https://management.azure.com/.default";
const ROLE: &str = "arn:aws:iam::123456789012:role/saiife-reader";
const EMAIL: &str = "robot@proj-1.iam.gserviceaccount.com";
const KEY_ID: &str = "0123456789abcdef0123456789abcdef01234567";
const TENANT: &str = "11111111-2222-3333-4444-555555555555";
const CLIENT_ID: &str = "66666666-7777-8888-9999-000000000000";
const SUB: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

// Built at runtime: no token-shaped literal in the source.
const VAULT_AK: &str = concat!("AK", "IA", "TESTVAULT0000001");
const VAULT_SK: &str = concat!("vaultSecret", "Key/0123456789", "abcdEFGH+xyz");
const SESSION_AK: &str = concat!("AS", "IA", "TESTSESSN0000001");
const SESSION_SK: &str = concat!("sessionSecret", "Key/9876543210", "ZYXWvuts");
const SESSION_TOKEN: &str = concat!("testSession", "EXAMPLEsession", "TokenValue0042==");
const AZ_SECRET: &str = concat!("az", "-client-secret~", "Qz9.x-k2");

const MANIFEST_SF: &str = r#"
id = "sfx"
version = 1
title = "SF test"
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
"#;

fn gcp_token(n: usize) -> String {
    format!("gtok-{n}-{}", "m4".repeat(12))
}

fn az_token(n: usize) -> String {
    format!("aztok-{n}-{}", "w8".repeat(12))
}

fn sf_access(n: usize) -> String {
    format!("at-{n}-{}", "q7".repeat(8))
}

fn sf_client_secret() -> String {
    format!("cs-{}", "k9".repeat(10))
}

fn sf_refresh() -> String {
    format!("rt-initial-{}", "5f".repeat(8))
}

/// The throwaway 2048-bit RSA test key of plan 15 Task 6 (hex PKCS#8 DER).
fn key_der() -> Vec<u8> {
    let hex: String = include_str!("../../broker/tests/fixtures/gcp/test-rsa-2048.pk8.hex")
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

/// Every secret value a test may use: none may reach a record, an
/// answer, `Debug` output, a notification or stderr.
fn secret_values() -> Vec<String> {
    let mut v = vec![
        VAULT_AK.to_string(),
        SESSION_AK.to_string(),
        VAULT_SK.to_string(),
        SESSION_SK.to_string(),
        SESSION_TOKEN.to_string(),
        AZ_SECRET.to_string(),
        sf_client_secret(),
        sf_refresh(),
        STANDARD.encode(key_der()),
    ];
    // The PEM body lines.
    for l in key_pem().lines().filter(|l| !l.starts_with("-----")) {
        if l.len() >= 32 {
            v.push(l.to_string());
        }
    }
    for n in 1..=40 {
        v.push(gcp_token(n));
        v.push(az_token(n));
        v.push(sf_access(n));
    }
    v
}

fn assert_clean(what: &str, text: &str) {
    for s in secret_values() {
        assert!(!text.contains(&s), "a secret value leaked into {what}");
    }
}

// ---------------------------------------------------------------- mock

/// What the mock does and what it saw.
#[derive(Default)]
struct State {
    /// AWS keys the mock knows, by access key id: (secret, session token).
    keys: HashMap<String, (String, Option<String>)>,
    /// STS calls: the access key id that signed each, and whether the
    /// signature checked out.
    sts: Vec<(String, bool)>,
    /// The `ExternalId` each STS call sent.
    sts_external: Vec<Option<String>>,
    sts_status: u16,
    /// S3 requests: what the mock saw.
    s3: Vec<S3Seen>,
    /// GCP token POSTs: the JWT claims of each.
    gcp_mints: Vec<Value>,
    gcp_status: u16,
    /// Azure token POSTs: the form of each, and the login host.
    az_mints: Vec<BTreeMap<String, String>>,
    az_hosts: Vec<String>,
    az_status: u16,
    /// API requests to GCS and ARM: (host, bearer).
    api: Vec<(String, String)>,
    /// Bearer tokens the APIs accept.
    issued: Vec<String>,
    /// oauth2 (the sfx manifest): token POSTs, and the access token the API
    /// accepts.
    sf_posts: usize,
    sf_current: String,
    /// How long the token endpoints take.
    delay_ms: u64,
}

#[derive(Clone, Debug)]
struct S3Seen {
    akid: String,
    sig_ok: bool,
    /// The request target as received.
    target: String,
    headers: HeaderMap,
}

type Shared = Arc<Mutex<State>>;

struct Loopback(u16);

impl Resolver for Loopback {
    fn resolve(&self, host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
        if HOSTS.contains(&host) {
            Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, self.0))])
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "unknown test host"))
        }
    }
}

fn form(body: &[u8]) -> BTreeMap<String, String> {
    String::from_utf8_lossy(body)
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| {
            (
                k.to_string(),
                percent_encoding::percent_decode_str(v)
                    .decode_utf8_lossy()
                    .into_owned(),
            )
        })
        .collect()
}

/// `20261028T123456Z`.
fn parse_amz_date(s: &str) -> Option<OffsetDateTime> {
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<u32>().ok();
    let month = time::Month::try_from(u8::try_from(n(4..6)?).ok()?).ok()?;
    let date = time::Date::from_calendar_date(i32::try_from(n(0..4)?).ok()?, month, n(6..8)? as u8)
        .ok()?;
    let t = time::Time::from_hms(n(9..11)? as u8, n(11..13)? as u8, n(13..15)? as u8).ok()?;
    Some(time::PrimitiveDateTime::new(date, t).assume_utc())
}

/// Recomputes the SigV4 signature of a received request from its bytes:
/// the signed headers as received, the target as received, the body as
/// received, the time from `x-amz-date`, the key from the access key id.
/// `true` when the `Authorization` and the target the signer produces
/// equal the received ones (what was signed is what was sent).
fn verify_sigv4(
    keys: &HashMap<String, (String, Option<String>)>,
    parts: &http::request::Parts,
    host: &str,
    body: &Bytes,
    service: &str,
) -> (String, bool) {
    let Some(auth) = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
    else {
        return (String::new(), false);
    };
    let Some(rest) = auth.strip_prefix("AWS4-HMAC-SHA256 ") else {
        return (String::new(), false);
    };
    let mut cred = "";
    let mut signed = "";
    for p in rest.split(", ") {
        if let Some(c) = p.strip_prefix("Credential=") {
            cred = c;
        } else if let Some(s) = p.strip_prefix("SignedHeaders=") {
            signed = s;
        }
    }
    let akid = cred.split('/').next().unwrap_or_default().to_string();
    let Some((sk, tok)) = keys.get(&akid) else {
        return (akid, false);
    };
    let Some(at) = parts
        .headers
        .get("x-amz-date")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_amz_date)
    else {
        return (akid, false);
    };
    let target = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_default();
    let mut headers = HeaderMap::new();
    for name in signed.split(';') {
        if name == "authorization" {
            return (akid, false);
        }
        for v in parts.headers.get_all(name) {
            headers.append(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                v.clone(),
            );
        }
    }
    let mut b = Built {
        method: parts.method.clone(),
        uri: format!("https://{host}{target}").parse().unwrap(),
        headers,
        body: (!body.is_empty()).then(|| body.clone()),
    };
    let creds = AwsCreds {
        access_key_id: Zeroizing::new(akid.clone()),
        secret_access_key: Zeroizing::new(sk.clone()),
        session_token: tok.clone().map(Zeroizing::new),
    };
    if sigv4::sign(&mut b, &creds, &sigv4::for_service(REGION, service), at).is_err() {
        return (akid, false);
    }
    let ours = b
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let same_target = b.uri.path_and_query().map(|p| p.as_str()) == Some(target.as_str());
    (akid, ours == auth && same_target)
}

fn sts_xml() -> String {
    format!(
        r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::123456789012:assumed-role/saiife-reader/s</Arn>
      <AssumedRoleId>AROTESTROLEID:s</AssumedRoleId>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>{SESSION_AK}</AccessKeyId>
      <SecretAccessKey>{SESSION_SK}</SecretAccessKey>
      <SessionToken>{SESSION_TOKEN}</SessionToken>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>
"#
    )
}

async fn answer(req: Request<Incoming>, st: Shared) -> Result<Response<Full<Bytes>>, Infallible> {
    let (parts, body) = req.into_parts();
    let body = body
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let reply = |status: u16, ct: &str, b: String| {
        Response::builder()
            .status(status)
            .header("content-type", ct)
            .body(Full::new(Bytes::from(b)))
            .unwrap()
    };
    let json = |status: u16, b: String| reply(status, "application/json", b);
    let host = parts
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .split(':')
        .next()
        .unwrap_or_default()
        .to_string();
    let bearer = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
        .to_string();
    let is_token = matches!(
        host.as_str(),
        GCP_TOKEN_HOST | AZ_LOGIN_HOST | AZ_US_HOST | STS_HOST
    ) || parts.uri.path() == "/services/oauth2/token";
    if is_token {
        let delay = st.lock().unwrap().delay_ms;
        if delay > 0 {
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
    }
    let mut s = st.lock().unwrap();
    match host.as_str() {
        STS_HOST => {
            let (akid, ok) = verify_sigv4(&s.keys, &parts, &host, &body, "sts");
            s.sts.push((akid, ok));
            s.sts_external.push(form(&body).get("ExternalId").cloned());
            if s.sts_status != 200 {
                return Ok(reply(
                    s.sts_status,
                    "text/xml",
                    format!(
                        "<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code>\
                         <Message>not allowed: {VAULT_SK}</Message></Error></ErrorResponse>"
                    ),
                ));
            }
            let f = form(&body);
            if f.get("Action").map(String::as_str) != Some("AssumeRole")
                || f.get("RoleArn").map(String::as_str) != Some(ROLE)
                || f.get("DurationSeconds").map(String::as_str) != Some("3600")
                || f.contains_key("Policy")
            {
                return Ok(reply(400, "text/xml", "<bad/>".into()));
            }
            Ok(reply(200, "text/xml", sts_xml()))
        }
        S3_HOST => {
            let (akid, sig_ok) = verify_sigv4(&s.keys, &parts, &host, &body, "s3");
            let target = parts
                .uri
                .path_and_query()
                .map(|p| p.as_str().to_string())
                .unwrap_or_default();
            s.s3.push(S3Seen {
                akid,
                sig_ok,
                target,
                headers: parts.headers.clone(),
            });
            if !sig_ok {
                return Ok(reply(403, "application/xml", "<Error/>".into()));
            }
            // The upstream echoes the credential that signed (and the
            // vault key behind a session): the answer must come back
            // masked.
            let signer = s.s3.last().map(|x| x.akid.clone()).unwrap_or_default();
            let sk = s.keys.get(&signer).map(|k| k.0.clone()).unwrap_or_default();
            Ok(reply(
                200,
                "application/xml",
                format!(
                    "<Echo><Id>{signer}</Id><Token>{}</Token><Secret>{sk}</Secret><Vault>{VAULT_SK}</Vault></Echo>",
                    parts
                        .headers
                        .get("x-amz-security-token")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("none")
                ),
            ))
        }
        GCP_TOKEN_HOST => {
            let f = form(&body);
            let claims = f
                .get("assertion")
                .and_then(|a| a.split('.').nth(1))
                .and_then(|p| URL_SAFE_NO_PAD.decode(p).ok())
                .and_then(|p| serde_json::from_slice::<Value>(&p).ok())
                .unwrap_or(Value::Null);
            s.gcp_mints.push(claims);
            if s.gcp_status != 200 {
                // An error description that echoes what was sent.
                let d = f.get("assertion").cloned().unwrap_or_default();
                return Ok(json(
                    s.gcp_status,
                    json!({"error": "invalid_grant", "error_description": d}).to_string(),
                ));
            }
            let t = gcp_token(s.gcp_mints.len());
            s.issued.push(t.clone());
            Ok(json(
                200,
                json!({"access_token": t, "expires_in": 3599, "token_type": "Bearer"}).to_string(),
            ))
        }
        AZ_LOGIN_HOST | AZ_US_HOST => {
            let f = form(&body);
            let ok_path = parts.uri.path() == format!("/{TENANT}/oauth2/v2.0/token");
            s.az_mints.push(f.clone());
            s.az_hosts.push(host.clone());
            if s.az_status != 200 || !ok_path {
                let d = f.get("client_secret").cloned().unwrap_or_default();
                return Ok(json(
                    if ok_path { s.az_status } else { 404 },
                    json!({"error": "invalid_client", "error_description": format!("bad secret {d}")})
                        .to_string(),
                ));
            }
            let t = az_token(s.az_mints.len());
            s.issued.push(t.clone());
            Ok(json(
                200,
                json!({"access_token": t, "expires_in": 3599, "token_type": "Bearer"}).to_string(),
            ))
        }
        GCS_HOST | ARM_HOST => {
            s.api.push((host.clone(), bearer.clone()));
            if !s.issued.contains(&bearer) {
                return Ok(json(401, r#"{"error":"unauthenticated"}"#.into()));
            }
            Ok(json(
                200,
                json!({"items": [], "value": [], "seen": bearer}).to_string(),
            ))
        }
        SF_HOST => {
            if parts.uri.path() == "/services/oauth2/token" {
                s.sf_posts += 1;
                let access = sf_access(s.sf_posts);
                s.sf_current = access.clone();
                return Ok(json(
                    200,
                    json!({"access_token": access, "token_type": "Bearer",
                           "instance_url": "https://acme.sf.test"})
                    .to_string(),
                ));
            }
            s.api.push((host.clone(), bearer.clone()));
            if bearer != s.sf_current {
                return Ok(json(401, r#"[{"errorCode":"INVALID_SESSION_ID"}]"#.into()));
            }
            Ok(json(200, json!({"ok": true, "seen": bearer}).to_string()))
        }
        _ => Ok(json(404, "{}".into())),
    }
}

async fn mock(st: Shared) -> Upstream {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(HOSTS.iter().map(|h| h.to_string()).collect::<Vec<_>>())
        .unwrap()
        .signed_by(&leaf_key, &ca)
        .unwrap();
    let leaf_der: CertificateDer<'static> = leaf.der().clone();
    let key = PrivatePkcs8KeyDer::from(leaf_key.serialize_der());
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![leaf_der], PrivateKeyDer::Pkcs8(key))
    .unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let st = st.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let svc = service_fn(move |req| answer(req, st.clone()));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    // Generous: a loaded machine (many test binaries at once) must not turn
    // a slow loopback handshake into a `network` mint failure. Mints are
    // capped at 15 s by `token::MINT_TIMEOUT`.
    Upstream::with_roots(roots, Arc::new(Loopback(port)), Duration::from_secs(30))
}

// ---------------------------------------------------------------- daemon

/// The caller (`agent`, the context's own user) is in group `admins`.
struct Dir;

impl Directory for Dir {
    fn user(&self, _name: &str) -> Option<UserEntry> {
        None
    }
    fn name_of(&self, _uid: u32) -> Option<String> {
        None
    }
    fn group(&self, _name: &str) -> Option<GroupEntry> {
        None
    }
    fn groups_of(&self, _user: &str) -> Vec<String> {
        vec!["admins".into()]
    }
}

struct World {
    ctx: Arc<Ctx>,
    st: Shared,
    audit: PathBuf,
    _tmp: tempfile::TempDir,
}

fn scratch() -> tempfile::TempDir {
    let base = std::env::var_os("SAIIFE_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    std::fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
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

fn entry(name: &str, kind: Kind, f: BTreeMap<String, Zeroizing<String>>, svcs: &[&str]) -> Entry {
    Entry {
        name: name.into(),
        kind,
        fields: f,
        allowed_services: svcs.iter().map(|s| s.to_string()).collect(),
        created_by: 0,
        created: "2026-10-28T00:00:00Z".into(),
        last_used: None,
        rotate_after: None,
    }
}

fn builtin(file: &str) -> Manifest {
    let text = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../broker/connectors")
            .join(file),
    )
    .unwrap();
    Manifest::parse(&text).unwrap()
}

const CONFIG: &str = r#"version = 2
locked = true

[[scope]]
name = "agents"
users = ["agent"]
services = ["s3", "s3role", "s3role_x", "gcs", "gcs2", "gcs_ask", "arm", "arm_us", "arm_cn",
            "sf", "gcs_wrong"]

[services.s3]
connector = "aws-s3"
secret = "aws-keys"
params = { region = "eu-west-1" }
allow = ["s3:read"]

[services.s3role]
connector = "aws-s3"
secret = "aws-keys"
params = { region = "eu-west-1" }
allow = ["s3:read"]
[services.s3role.cloud]
role_arn = "arn:aws:iam::123456789012:role/saiife-reader"

[services.s3role_x]
connector = "aws-s3"
secret = "aws-keys"
params = { region = "eu-west-1" }
allow = ["s3:read"]
[services.s3role_x.cloud]
role_arn = "arn:aws:iam::123456789012:role/saiife-reader"
external_id = "ext-id-1234"

[services.gcs_ask]
connector = "gcp-storage"
secret = "gcp-sa"
ask = ["storage:read"]

[services.gcs]
connector = "gcp-storage"
secret = "gcp-sa"
allow = ["storage:read"]
deny = ["storage:delete"]

[services.gcs2]
connector = "gcp-other"
secret = "gcp-sa"
allow = ["storage:read"]

[services.gcs_wrong]
connector = "gcp-storage"
secret = "aws-keys"
allow = ["storage:read"]

[services.arm]
connector = "azure-arm"
secret = "az-sp"
allow = ["resourcegroups:read"]

[services.arm_us]
connector = "azure-arm"
secret = "az-sp"
allow = ["resourcegroups:read"]
[services.arm_us.cloud]
authority_host = "login.microsoftonline.us"

[services.arm_cn]
connector = "azure-arm"
secret = "az-sp"
allow = ["resourcegroups:read"]
[services.arm_cn.cloud]
authority_host = "login.chinacloudapi.cn"

[services.sf]
connector = "sfx"
secret = "sf-oauth"
params = { instance_host = "acme.sf.test" }
allow = ["limits:read"]
"#;

async fn world(setup: impl FnOnce(&mut State)) -> World {
    let tmp = scratch();
    let audit = tmp.path().join("audit");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&audit).unwrap();
    std::fs::create_dir_all(tmp.path().join("proc")).unwrap();
    std::fs::create_dir_all(tmp.path().join("run")).unwrap();
    let cw = ChainWriter::open(
        &audit,
        WriterOptions {
            mode: "locked".into(),
            saiife: "test".into(),
            key: None,
        },
    )
    .unwrap();
    let wcfg = WriterConfig {
        checkpoint_every: 1000,
        checkpoint_interval: Duration::from_secs(900),
        fsync: Fsync::Always,
    };
    let (handle, _join) = writer::spawn(cw, wcfg, None).unwrap();

    let key_file = tmp.path().join("vault-key");
    std::fs::write(&key_file, [7u8; 32]).unwrap();
    let vault_file = state.join("vault").join("vault.bin");
    let mut vault = vault::open(&key_file, &vault_file);
    let VaultState::Ready(v) = &mut vault else {
        panic!("vault not ready");
    };
    for e in [
        entry(
            "aws-keys",
            Kind::Aws,
            fields(&[("access_key_id", VAULT_AK), ("secret_access_key", VAULT_SK)]),
            &["s3", "s3role", "s3role_x", "gcs_wrong"],
        ),
        entry(
            "gcp-sa",
            Kind::GcpSa,
            gcp_fields(),
            &["gcs", "gcs2", "gcs_ask"],
        ),
        entry(
            "az-sp",
            Kind::AzureSp,
            fields(&[
                ("tenant_id", TENANT),
                ("client_id", CLIENT_ID),
                ("client_secret", AZ_SECRET),
            ]),
            &["arm", "arm_us", "arm_cn"],
        ),
        entry(
            "sf-oauth",
            Kind::OAuth2,
            fields(&[
                ("client_id", "cid-test"),
                ("client_secret", &sf_client_secret()),
                ("refresh_token", &sf_refresh()),
            ]),
            &["sf"],
        ),
    ] {
        v.put(e).unwrap();
    }

    let config: SystemConfig = toml::from_str(CONFIG).unwrap();
    // A second GCS manifest with another scope: the same secret, two
    // cache entries.
    let other = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../broker/connectors/gcp-storage.toml"),
    )
    .unwrap()
    .replace("id = \"gcp-storage\"", "id = \"gcp-other\"")
    .replace(SCOPE_GCS, SCOPE_OTHER);
    let manifests = vec![
        builtin("aws-s3.toml"),
        builtin("gcp-storage.toml"),
        builtin("azure-arm.toml"),
        Manifest::parse(&other).unwrap(),
        Manifest::parse(MANIFEST_SF).unwrap(),
    ];
    let policy = PolicyState {
        hash: Some("sha256:test".into()),
        ok: true,
        min_free_mb: 0,
        admin_groups: vec!["admins".into()],
        system: Some(Arc::new(config.clone())),
        gateway: Some(Arc::new(GatewayPolicy {
            snap: PolicySnapshot {
                config,
                hash: "sha256:test".into(),
                mode: Mode::Locked,
                env: None,
            },
            by_env: Default::default(),
            catalog: Catalog::new(&[], manifests),
        })),
    };

    let mut s = State {
        sts_status: 200,
        gcp_status: 200,
        az_status: 200,
        ..State::default()
    };
    s.keys
        .insert(VAULT_AK.into(), (VAULT_SK.into(), None::<String>));
    s.keys.insert(
        SESSION_AK.into(),
        (SESSION_SK.into(), Some(SESSION_TOKEN.into())),
    );
    setup(&mut s);
    let st: Shared = Arc::new(Mutex::new(s));
    let up = mock(st.clone()).await;
    let ctx = Arc::new(Ctx::new(CtxInit {
        own_user: "agent".into(),
        audit_dir: audit.clone(),
        socket_dir: tmp.path().join("run"),
        key_path: state.join("keys/audit.ed25519"),
        config_path: tmp.path().join("config.toml"),
        catalog: Vec::new(),
        policy,
        proc: Box::new(RealProc::new(tmp.path().join("proc"))),
        vault,
        vault_path: vault_file,
        backup_dir: state.join("import-backup"),
        limiter: Limiter::new(),
        upstream: Ok(up),
        tokens: Arc::new(Tokens::memory_with_clock(Arc::new(|| 1_800_000_000))),
        approvals: saiife_daemon::approvals::Store::open(&state.join("approvals"))
            .map_err(|e| e.to_string()),
        lockdown: saiife_daemon::lockdown::Store::memory(),
        grants: saiife_daemon::grants::Grants::memory(),
        ..CtxInit::minimal(handle, wcfg, Arc::new(Dir), &state)
    }));
    World {
        ctx,
        st,
        audit,
        _tmp: tmp,
    }
}

fn peer() -> PeerCred {
    PeerCred {
        uid: rustix::process::getuid().as_raw(),
        gid: rustix::process::getgid().as_raw(),
        pid: std::process::id(),
    }
}

impl World {
    async fn op(&self, op: &str, args: Value) -> Value {
        let req = IpcRequest {
            id: 1,
            op: op.into(),
            args: args.as_object().unwrap().clone(),
        };
        saiife_daemon::ops::dispatch(&self.ctx, &peer(), req).await
    }

    async fn call(&self, service: &str, operation: &str, params: Value) -> Value {
        self.call_h(service, operation, params, json!([])).await
    }

    async fn call_h(&self, service: &str, operation: &str, params: Value, headers: Value) -> Value {
        self.op(
            "api.call",
            json!({"service": service, "operation": operation, "params": params,
                   "headers": headers}),
        )
        .await
    }

    async fn gcs(&self) -> Value {
        self.call(
            "gcs",
            "storage.objects.list",
            json!({"bucket": "my-bucket"}),
        )
        .await
    }

    async fn gcs2(&self) -> Value {
        self.call(
            "gcs2",
            "storage.objects.list",
            json!({"bucket": "my-bucket"}),
        )
        .await
    }

    async fn arm(&self) -> Value {
        self.call(
            "arm",
            "resourcegroups.list",
            json!({"subscription_id": SUB}),
        )
        .await
    }

    async fn s3(&self, service: &str) -> Value {
        self.call(
            service,
            "s3.get_object",
            json!({"bucket": "reports", "key": "2026/q3 summary+final.txt"}),
        )
        .await
    }

    fn audit_text(&self) -> String {
        let mut s = String::new();
        for e in std::fs::read_dir(&self.audit).unwrap() {
            s.push_str(&std::fs::read_to_string(e.unwrap().path()).unwrap_or_default());
        }
        s
    }

    fn records(&self, kind: &str) -> Vec<Value> {
        self.audit_text()
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|v| v["kind"] == kind)
            .collect()
    }

    fn refresh_failed(&self) -> Vec<Value> {
        self.records("secret")
            .into_iter()
            .filter(|r| r["event"] == "refresh_failed")
            .collect()
    }

    fn notifications(&self) -> Vec<saiife_daemon::notifier::NotifyEvent> {
        self.ctx
            .notifier
            .queued_events()
            .into_iter()
            .filter(|e| e.event == Event::RefreshFailed)
            .collect()
    }

    fn gcp_mints(&self) -> usize {
        self.st.lock().unwrap().gcp_mints.len()
    }

    /// The records, `Debug` of the cache and the notifications hold no
    /// secret value; nor do `answers` (with their bodies).
    fn assert_no_values(&self, answers: &[Value]) {
        assert_clean("the audit log", &self.audit_text());
        assert_clean("Debug of the cache", &format!("{:?}", self.ctx.oauth));
        for e in self.ctx.notifier.queued_events() {
            assert_clean("a notification", &format!("{e:?}"));
        }
        for a in answers {
            assert_clean("an answer", &a.to_string());
            if a["body_b64"].is_string() {
                assert_clean("an answer body", &body(a));
            }
        }
    }
}

fn status(a: &Value) -> u64 {
    assert_eq!(a["ok"], true, "{a}");
    a["status"].as_u64().unwrap()
}

fn body(a: &Value) -> String {
    let b = STANDARD.decode(a["body_b64"].as_str().unwrap()).unwrap();
    String::from_utf8(b).unwrap()
}

fn rule(a: &Value) -> String {
    assert_eq!(a["ok"], false, "{a}");
    a["rule"].as_str().unwrap_or_default().to_string()
}

// ---------------------------------------------------------------- tests

#[tokio::test]
async fn s3_get_object_signed_end_to_end() {
    let w = world(|_| {}).await;
    let a = w.s3("s3").await;
    assert_eq!(status(&a), 200, "{}", body(&a));
    let seen = w.st.lock().unwrap().s3.clone();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].sig_ok, "the mock's recomputed signature differs");
    assert_eq!(seen[0].akid, VAULT_AK);
    // Path style, each segment encoded the AWS way: `+` is never a space.
    assert_eq!(seen[0].target, "/reports/2026/q3%20summary%2Bfinal.txt");
    assert_eq!(
        seen[0].headers["x-amz-content-sha256"],
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert!(seen[0].headers.get("x-amz-security-token").is_none());
    // No STS call without a role.
    assert!(w.st.lock().unwrap().sts.is_empty());
    let rec = w.records("connector");
    assert_eq!(rec.len(), 1);
    assert_eq!(rec[0]["secret"], "aws-keys");
    assert_eq!(rec[0]["decision"], "allow");
    // The upstream echoed the vault secret key: masked.
    let b = body(&a);
    assert!(b.contains("[MASKED]"), "{b}");
    assert!(!b.contains(VAULT_AK) && !b.contains(VAULT_SK), "{b}");
    w.assert_no_values(&[a]);
    assert!(!w.audit_text().contains(VAULT_AK), "the key id in a record");
}

#[tokio::test]
async fn sign_mode_assume_role_cached() {
    let w = world(|_| {}).await;
    let mut answers = Vec::new();
    for _ in 0..3 {
        let a = w.s3("s3role").await;
        assert_eq!(status(&a), 200, "{}", body(&a));
        answers.push(a);
    }
    let st = w.st.lock().unwrap();
    assert_eq!(st.sts.len(), 1, "one AssumeRole for three requests");
    assert_eq!(
        st.sts[0],
        (VAULT_AK.to_string(), true),
        "signed with the vault keys"
    );
    assert_eq!(st.s3.len(), 3);
    for s in &st.s3 {
        assert!(s.sig_ok);
        assert_eq!(s.akid, SESSION_AK, "signed with the session");
        assert_eq!(s.headers["x-amz-security-token"], SESSION_TOKEN);
    }
    drop(st);
    for a in &answers {
        let b = body(a);
        for v in [SESSION_TOKEN, SESSION_SK, SESSION_AK, VAULT_SK] {
            assert!(!b.contains(v), "{b}");
        }
    }
    w.assert_no_values(&answers);
}

#[tokio::test]
async fn gcp_storage_list_with_minted_token() {
    let w = world(|_| {}).await;
    let a = w.gcs().await;
    assert_eq!(status(&a), 200, "{}", body(&a));
    let st = w.st.lock().unwrap();
    assert_eq!(st.gcp_mints.len(), 1);
    let c = &st.gcp_mints[0];
    assert_eq!(c["iss"], EMAIL);
    assert_eq!(c["scope"], SCOPE_GCS, "the manifest's scope");
    assert_eq!(c["aud"], "https://oauth2.googleapis.com/token");
    assert_eq!(st.api, vec![(GCS_HOST.to_string(), gcp_token(1))]);
    drop(st);
    let rec = w.records("connector");
    assert_eq!(rec[0]["secret"], "gcp-sa");
    w.assert_no_values(&[a]);
}

#[tokio::test]
async fn azure_arm_list_with_minted_token() {
    let w = world(|_| {}).await;
    let a = w.arm().await;
    assert_eq!(status(&a), 200, "{}", body(&a));
    {
        let st = w.st.lock().unwrap();
        assert_eq!(st.az_mints.len(), 1);
        let f = &st.az_mints[0];
        assert_eq!(f["grant_type"], "client_credentials");
        assert_eq!(f["client_id"], CLIENT_ID);
        assert_eq!(f["scope"], SCOPE_ARM);
        assert_eq!(st.api, vec![(ARM_HOST.to_string(), az_token(1))]);
    }
    // A second call reuses the token.
    assert_eq!(status(&w.arm().await), 200);
    assert_eq!(w.st.lock().unwrap().az_mints.len(), 1);
    w.assert_no_values(&[a]);
}

#[tokio::test]
async fn cloud_scope_from_manifest_only() {
    let w = world(|_| {}).await;
    // The agent cannot name a scope: an unknown param is refused before
    // anything is minted, and a header is not the scope either.
    let a = w
        .call(
            "gcs",
            "storage.objects.list",
            json!({"bucket": "my-bucket", "scope": "https://www.googleapis.com/auth/cloud-platform"}),
        )
        .await;
    assert_eq!(rule(&a), "bad_param");
    assert_eq!(w.gcp_mints(), 0);
    let a = w
        .call_h(
            "arm",
            "resourcegroups.list",
            json!({"subscription_id": SUB}),
            json!([
                ["scope", "https://graph.microsoft.com/.default"],
                ["X-Scope", "https://graph.microsoft.com/.default"]
            ]),
        )
        .await;
    assert_eq!(status(&a), 200);
    let a = w.gcs().await;
    assert_eq!(status(&a), 200);
    let st = w.st.lock().unwrap();
    assert_eq!(st.az_mints.len(), 1);
    assert_eq!(st.az_mints[0]["scope"], SCOPE_ARM);
    assert_eq!(st.gcp_mints.len(), 1);
    assert_eq!(st.gcp_mints[0]["scope"], SCOPE_GCS);
}

#[tokio::test]
async fn single_flight_per_secret_and_scope() {
    let w = Arc::new(world(|s| s.delay_ms = 200).await);
    let mut tasks = Vec::new();
    for _ in 0..20 {
        let w = Arc::clone(&w);
        tasks.push(tokio::spawn(async move { w.gcs().await }));
    }
    for t in tasks {
        assert_eq!(status(&t.await.unwrap()), 200);
    }
    assert_eq!(w.gcp_mints(), 1, "one mint for 20 concurrent calls");
    // The same secret for another scope: a second mint, then none.
    assert_eq!(status(&w.gcs2().await), 200);
    assert_eq!(status(&w.gcs2().await), 200);
    assert_eq!(status(&w.gcs().await), 200);
    let st = w.st.lock().unwrap();
    assert_eq!(st.gcp_mints.len(), 2);
    assert_eq!(st.gcp_mints[0]["scope"], SCOPE_GCS);
    assert_eq!(st.gcp_mints[1]["scope"], SCOPE_OTHER);
}

#[tokio::test]
async fn failed_mint_not_cached() {
    let w = world(|s| s.gcp_status = 503).await;
    assert_eq!(rule(&w.gcs().await), "token_mint_failed");
    // No backoff for a cloud mint: the next call tries again.
    assert_eq!(rule(&w.gcs().await), "token_mint_failed");
    assert_eq!(w.gcp_mints(), 2);
    w.st.lock().unwrap().gcp_status = 200;
    let a = w.gcs().await;
    assert_eq!(status(&a), 200);
    assert_eq!(w.gcp_mints(), 3);
    assert!(
        w.st.lock().unwrap().api.len() == 1,
        "nothing sent without a token"
    );
    w.assert_no_values(&[a]);
}

#[tokio::test]
async fn minted_token_masked_in_response() {
    let w = world(|_| {}).await;
    let g = w.gcs().await;
    let az = w.arm().await;
    let s3 = w.s3("s3role").await;
    for (a, t) in [(&g, gcp_token(1)), (&az, az_token(1))] {
        assert_eq!(status(a), 200);
        let b = body(a);
        assert!(!b.contains(&t), "{b}");
        assert!(b.contains("[MASKED]"), "{b}");
    }
    assert_eq!(status(&s3), 200);
    let b = body(&s3);
    for v in [SESSION_TOKEN, SESSION_SK, VAULT_SK] {
        assert!(!b.contains(v), "{b}");
    }
    w.assert_no_values(&[g, az, s3]);
}

#[tokio::test]
async fn denied_request_mints_nothing() {
    let w = world(|_| {}).await;
    // Denied by the policy, refused as unknown, and outside the allow list.
    let d = w
        .call(
            "gcs",
            "storage.objects.delete",
            json!({"bucket": "my-bucket", "object": "a"}),
        )
        .await;
    assert_eq!(d["ok"], false, "{d}");
    let u = w.call("gcs", "storage.nope", json!({})).await;
    assert_eq!(rule(&u), "unknown_operation");
    let s = w
        .call(
            "s3role",
            "s3.delete_object",
            json!({"bucket": "reports", "key": "a"}),
        )
        .await;
    assert_eq!(s["ok"], false, "{s}");
    let z = w
        .call("arm", "vms.list", json!({"subscription_id": SUB}))
        .await;
    assert_eq!(z["ok"], false, "{z}");
    let st = w.st.lock().unwrap();
    assert!(st.gcp_mints.is_empty() && st.az_mints.is_empty() && st.sts.is_empty());
    assert!(st.api.is_empty() && st.s3.is_empty());
}

#[tokio::test]
async fn mint_failure_records_refresh_failed_and_notifies_once_per_hour() {
    let w = world(|s| s.az_status = 401).await;
    let a1 = w.arm().await;
    let a2 = w.arm().await;
    assert_eq!(rule(&a1), "token_mint_failed");
    assert_eq!(rule(&a2), "token_mint_failed");
    let f = w.refresh_failed();
    assert_eq!(f.len(), 2, "one record per failed mint");
    for r in &f {
        assert_eq!(r["reason"], "endpoint:invalid_client");
        assert_eq!(r["name"], "az-sp");
        assert_eq!(r["service"], "arm");
        assert_eq!(r["decision"], "deny");
        let t = r.to_string();
        assert!(!t.contains("bad secret"), "an error description: {t}");
    }
    let ev = w.notifications();
    assert_eq!(ev.len(), 1, "at most one notification per secret per hour");
    assert_eq!(ev[0].reason.as_deref(), Some("endpoint:invalid_client"));
    assert_eq!(ev[0].service.as_deref(), Some("arm"));
    // The STS failure: its `Error/Code`, never its `Message`.
    w.st.lock().unwrap().sts_status = 403;
    assert_eq!(rule(&w.s3("s3role").await), "token_mint_failed");
    let f = w.refresh_failed();
    assert_eq!(f.len(), 3);
    assert_eq!(f[2]["reason"], "endpoint:AccessDenied");
    assert_eq!(f[2]["name"], "aws-keys");
    assert_eq!(w.notifications().len(), 2, "another secret");
    w.assert_no_values(&[a1, a2]);
}

#[tokio::test]
async fn rotate_forgets_every_scope() {
    let w = world(|_| {}).await;
    assert_eq!(status(&w.gcs().await), 200);
    assert_eq!(status(&w.gcs2().await), 200);
    assert_eq!(status(&w.s3("s3role").await), 200);
    assert_eq!(w.gcp_mints(), 2);
    let f: BTreeMap<String, String> = gcp_fields()
        .into_iter()
        .map(|(k, v)| (k, v.to_string()))
        .collect();
    let a = w
        .op("secret.rotate", json!({"name": "gcp-sa", "fields": f}))
        .await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(status(&w.gcs().await), 200);
    assert_eq!(status(&w.gcs2().await), 200);
    assert_eq!(w.gcp_mints(), 4, "both scopes minted again");
    // Another secret's entry stays.
    assert_eq!(status(&w.s3("s3role").await), 200);
    assert_eq!(w.st.lock().unwrap().sts.len(), 1);
    let a = w
        .op(
            "secret.rotate",
            json!({"name": "aws-keys", "fields": {
                "access_key_id": VAULT_AK, "secret_access_key": VAULT_SK}}),
        )
        .await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(status(&w.s3("s3role").await), 200);
    assert_eq!(w.st.lock().unwrap().sts.len(), 2);
}

#[tokio::test]
async fn oauth2_still_refreshes_and_retries_on_401() {
    let w = world(|_| {}).await;
    let a = w.call("sf", "limits", json!({})).await;
    assert_eq!(status(&a), 200);
    assert_eq!(status(&w.call("sf", "limits", json!({})).await), 200);
    assert_eq!(w.st.lock().unwrap().sf_posts, 1, "cached");
    // Revoked upstream: one forced refresh, one resend.
    w.st.lock().unwrap().sf_current = String::new();
    let a = w.call("sf", "limits", json!({})).await;
    assert_eq!(status(&a), 200);
    assert_eq!(w.st.lock().unwrap().sf_posts, 2);
    let rec = w.records("connector");
    assert_eq!(rec[2]["auth_retry"], true, "{}", rec[2]);
    let b = body(&a);
    assert!(!b.contains(&sf_access(2)), "{b}");
    w.assert_no_values(&[a]);
}

#[tokio::test]
async fn wrong_kind_for_connector_is_secret_missing() {
    let w = world(|_| {}).await;
    // An `aws` secret for a `gcp_sa` connector.
    let a = w
        .call(
            "gcs_wrong",
            "storage.objects.list",
            json!({"bucket": "my-bucket"}),
        )
        .await;
    assert_eq!(rule(&a), "secret_missing");
    let st = w.st.lock().unwrap();
    assert!(st.gcp_mints.is_empty() && st.api.is_empty() && st.sts.is_empty());
}

#[tokio::test]
async fn agent_authorization_and_x_amz_headers_dropped() {
    let w = world(|_| {}).await;
    let evil = "evil-value-0042";
    let a = w
        .call_h(
            "s3",
            "s3.get_object",
            json!({"bucket": "reports", "key": "a.txt"}),
            json!([
                ["Authorization", format!("Bearer {evil}")],
                ["X-Amz-Date", "20200101T000000Z"],
                ["X-Amz-Security-Token", evil],
                ["X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD"],
                ["x-amz-acl", "public-read"],
                ["x-amz-copy-source", "/other/key"],
                ["Host", "evil.example"],
                ["Range", "bytes=0-9"],
            ]),
        )
        .await;
    assert_eq!(status(&a), 200, "{}", body(&a));
    let seen = w.st.lock().unwrap().s3[0].clone();
    assert!(seen.sig_ok);
    for (k, v) in &seen.headers {
        let v = v.to_str().unwrap_or_default();
        assert!(!v.contains(evil), "{k}: {v}");
    }
    assert!(seen.headers.get("x-amz-acl").is_none());
    assert!(seen.headers.get("x-amz-copy-source").is_none());
    assert!(seen.headers.get("x-amz-security-token").is_none());
    assert_eq!(seen.headers["host"], S3_HOST);
    assert_ne!(seen.headers["x-amz-date"], "20200101T000000Z");
    assert_ne!(seen.headers["x-amz-content-sha256"], "UNSIGNED-PAYLOAD");
    // The allowlisted header is sent, and signed like every header present.
    assert_eq!(seen.headers["range"], "bytes=0-9");
    let auth = seen.headers["authorization"].to_str().unwrap();
    assert!(
        auth.contains("SignedHeaders=accept-encoding;host;range;x-amz-content-sha256;x-amz-date,"),
        "{auth}"
    );

    // A bearer connector: the agent's Authorization never wins.
    let a = w
        .call_h(
            "gcs",
            "storage.objects.list",
            json!({"bucket": "my-bucket"}),
            json!([["Authorization", format!("Bearer {evil}")]]),
        )
        .await;
    assert_eq!(status(&a), 200);
    assert_eq!(
        w.st.lock().unwrap().api,
        vec![(GCS_HOST.to_string(), gcp_token(1))]
    );
}

#[tokio::test]
async fn one_mint_per_outage() {
    let w = Arc::new(
        world(|s| {
            s.gcp_status = 503;
            s.delay_ms = 200;
        })
        .await,
    );
    let mut tasks = Vec::new();
    for _ in 0..20 {
        let w = Arc::clone(&w);
        tasks.push(tokio::spawn(async move { w.gcs().await }));
    }
    for t in tasks {
        assert_eq!(rule(&t.await.unwrap()), "token_mint_failed");
    }
    assert_eq!(
        w.gcp_mints(),
        1,
        "the waiters share the failed mint: {:?}",
        w.refresh_failed()
    );
    assert_eq!(w.refresh_failed().len(), 1, "one record for the outage");
    assert_eq!(w.notifications().len(), 1);
    // A call that arrives after the failure tries again (no backoff).
    assert_eq!(rule(&w.gcs().await), "token_mint_failed");
    assert_eq!(w.gcp_mints(), 2);
    assert_eq!(w.refresh_failed().len(), 2);
    w.st.lock().unwrap().gcp_status = 200;
    assert_eq!(status(&w.gcs().await), 200);
    assert_eq!(w.gcp_mints(), 3);
    w.assert_no_values(&[]);
}

#[tokio::test]
async fn cache_key_covers_authority_and_external_id() {
    let w = world(|_| {}).await;
    // One secret, one scope, two authorities: two tokens.
    assert_eq!(status(&w.arm().await), 200);
    let a = w
        .call(
            "arm_us",
            "resourcegroups.list",
            json!({"subscription_id": SUB}),
        )
        .await;
    assert_eq!(status(&a), 200, "{}", body(&a));
    assert_eq!(status(&w.arm().await), 200);
    {
        let st = w.st.lock().unwrap();
        assert_eq!(st.az_hosts, vec![AZ_LOGIN_HOST, AZ_US_HOST]);
        assert_eq!(
            st.api,
            vec![
                (ARM_HOST.to_string(), az_token(1)),
                (ARM_HOST.to_string(), az_token(2)),
                (ARM_HOST.to_string(), az_token(1)),
            ],
            "each service keeps its own token"
        );
    }
    // One secret, one role, two external ids: two sessions.
    assert_eq!(status(&w.s3("s3role").await), 200);
    assert_eq!(status(&w.s3("s3role_x").await), 200);
    assert_eq!(status(&w.s3("s3role_x").await), 200);
    assert_eq!(status(&w.s3("s3role").await), 200);
    let st = w.st.lock().unwrap();
    assert_eq!(st.sts_external, vec![None, Some("ext-id-1234".to_string())]);
}

#[tokio::test]
async fn mint_network_failure_recorded() {
    // The resolver does not know login.chinacloudapi.cn.
    let w = world(|_| {}).await;
    let a = w
        .call(
            "arm_cn",
            "resourcegroups.list",
            json!({"subscription_id": SUB}),
        )
        .await;
    assert_eq!(rule(&a), "token_mint_failed");
    let f = w.refresh_failed();
    assert_eq!(f.len(), 1);
    assert_eq!(f[0]["reason"], "network");
    assert_eq!(f[0]["name"], "az-sp");
    assert_eq!(f[0]["service"], "arm_cn");
    assert_eq!(w.notifications()[0].reason.as_deref(), Some("network"));
    let st = w.st.lock().unwrap();
    assert!(st.az_mints.is_empty() && st.api.is_empty());
    drop(st);
    w.assert_no_values(&[a]);
}

#[tokio::test]
async fn ask_verdict_mints_nothing() {
    let w = world(|_| {}).await;
    let a = w
        .call(
            "gcs_ask",
            "storage.objects.list",
            json!({"bucket": "my-bucket"}),
        )
        .await;
    assert_eq!(a["ok"], true, "{a}");
    assert!(a["pending"].is_u64(), "the request waits for approval: {a}");
    assert_eq!(w.gcp_mints(), 0, "nothing minted for a request that waits");
    assert!(w.st.lock().unwrap().api.is_empty());
}

/// Set in the child run of [`cloud_values_never_in_stderr`].
const LEAK_CHILD: &str = "SAIIFE_CLOUD_SIGN_LEAK_CHILD";

/// The daemon's stderr holds no secret value: the test binary runs this
/// test again as a child (`--nocapture`, so `eprintln!` reaches the real
/// stderr) and reads what it wrote.
#[test]
fn cloud_values_never_in_stderr() {
    if std::env::var_os(LEAK_CHILD).is_some() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(leak_scenario());
        return;
    }
    let o = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "cloud_values_never_in_stderr",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(LEAK_CHILD, "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&o.stderr).into_owned();
    let stdout = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(o.status.success(), "child failed:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("1 passed"),
        "the child ran nothing:\n{stdout}"
    );
    assert_clean("stderr", &stderr);
    assert_clean("stdout", &stdout);
}

async fn leak_scenario() {
    let w = world(|s| {
        s.gcp_status = 400;
        s.sts_status = 403;
    })
    .await;
    let mut answers = vec![w.gcs().await, w.s3("s3role").await, w.s3("s3").await];
    {
        let mut s = w.st.lock().unwrap();
        s.gcp_status = 200;
        s.sts_status = 200;
        s.az_status = 401;
    }
    answers.push(w.gcs().await);
    answers.push(w.s3("s3role").await);
    answers.push(w.arm().await);
    w.st.lock().unwrap().az_status = 200;
    answers.push(w.arm().await);
    answers.push(w.call("sf", "limits", json!({})).await);
    w.assert_no_values(&answers);
    assert!(w.refresh_failed().len() >= 3);
}
