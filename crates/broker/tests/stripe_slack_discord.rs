//! Stripe, Slack and Discord connectors (plan 14, wave 2, Task 8): manifests,
//! golden requests, built bodies, qualifiers, pagination, policy and the
//! pipeline end to end over a loopback TLS upstream. Offline. Fixtures are in
//! each vendor's documented shape (see the docs URL at the top of each
//! manifest); they were written without internet access.

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;
use saiife_broker::amount;
use saiife_broker::limits::Limiter;
use saiife_broker::manifest::{
    builtin, qualifier_for, AuthSpec, Manifest, OpKind, Operation, Pagination, Unit,
};
use saiife_broker::params::validate;
use saiife_broker::pipeline::{
    prepare_body, record, run, ApprovalFuture, Call, Env, OpRef, Outcome, PendingCall,
    PolicySnapshot, Pools, Via,
};
use saiife_broker::request::{build, next_cursor, AuthMaterial, Built};
use saiife_broker::resolve::named;
use saiife_broker::upstream::{Resolver, Upstream};
use saiife_broker::Catalog;
use saiife_policy::{Mode, PolicyError, Scope};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

const STRIPE_KEY: &str = concat!("rk_li", "ve_51Hq0abcDEF456ghi789jklMNO");
const SLACK_TOKEN: &str = concat!("xox", "b-1234567890-0987654321-AbCdEfGhIjKlMnOpQrStUvWx");
const DISCORD_TOKEN: &str = concat!(
    "MTEwMDAw",
    "MDAwMDAwMDAwMDA.Gx4kQa.abcdefghijklmnopqrstuvwxyz0123"
);

fn manifest(id: &str) -> &'static Manifest {
    builtin()
        .iter()
        .find(|m| m.id == id)
        .unwrap_or_else(|| panic!("{id} is a built-in manifest"))
}

fn op(m: &'static Manifest, id: &str) -> &'static Operation {
    named(m, id).unwrap_or_else(|| panic!("no operation {id}"))
}

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// `(operation id, capability, kind)` of every operation of a manifest.
fn shape(m: &Manifest) -> Vec<(&str, &str, OpKind)> {
    m.operation
        .iter()
        .map(|o| (o.id.as_str(), o.capability.as_str(), o.kind))
        .collect()
}

/// Builds the request of `op_id` as the pipeline does: validated params, a
/// built or raw body, the vault token in the manifest's auth.
fn go(
    m: &'static Manifest,
    token: &str,
    svc: &[(&str, &str)],
    op_id: &str,
    params: &[(&str, &str)],
) -> (Built, Option<Value>) {
    let o = op(m, op_id);
    let params = validate(o, &map(params), &BTreeMap::new()).unwrap();
    let body = prepare_body(o, &params, None).unwrap();
    let auth = AuthMaterial::from_spec(
        &m.auth[0],
        [("token".to_string(), Zeroizing::new(token.to_string()))].into(),
    );
    let headers = vec![("Accept".to_string(), "application/json".to_string())];
    let mut built = build(
        m,
        o,
        &map(svc),
        &params,
        &headers,
        body.bytes.clone(),
        &auth,
    )
    .unwrap();
    // The pipeline sets the content type of a built body after `build`.
    if let Some(ct) = body.content_type {
        built.headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static(ct),
        );
    }
    (built, body.json)
}

fn header<'a>(b: &'a Built, name: &str) -> &'a str {
    b.headers[name].to_str().unwrap()
}

// ------------------------------------------------------------------ Stripe

fn stripe(op_id: &str, params: &[(&str, &str)]) -> (Built, Option<Value>) {
    go(
        manifest("stripe"),
        STRIPE_KEY,
        &[("currency", "EUR")],
        op_id,
        params,
    )
}

#[test]
fn stripe_manifest_shape() {
    let m = manifest("stripe");
    assert_eq!(m.base_url, "https://api.stripe.com/v1");
    assert_eq!(m.hosts, ["api.stripe.com"]);
    assert_eq!(m.request_headers, ["Idempotency-Key", "Accept"]);
    use OpKind::{Read, Write};
    assert_eq!(
        shape(m),
        [
            ("customers.list", "customers:read", Read),
            ("customers.get", "customers:read", Read),
            ("charges.list", "charges:read", Read),
            ("charges.get", "charges:read", Read),
            ("payment_intents.list", "payment_intents:read", Read),
            ("payment_intents.get", "payment_intents:read", Read),
            ("invoices.list", "invoices:read", Read),
            ("invoices.get", "invoices:read", Read),
            ("refunds.list", "refunds:read", Read),
            ("refunds.create", "refunds:write", Write),
        ]
    );
}

#[test]
fn stripe_golden_reads() {
    let (b, body) = stripe(
        "customers.list",
        &[("limit", "3"), ("starting_after", "cus_NffrFeUfNV2Hib")],
    );
    assert_eq!(b.method, "GET");
    assert_eq!(
        b.uri.to_string(),
        "https://api.stripe.com/v1/customers?limit=3&starting_after=cus_NffrFeUfNV2Hib"
    );
    assert_eq!(header(&b, "authorization"), format!("Bearer {STRIPE_KEY}"));
    assert!(b.body.is_none() && body.is_none());
    for (op_id, param, id, path) in [
        (
            "customers.get",
            "customer_id",
            "cus_NffrFeUfNV2Hib",
            "customers",
        ),
        (
            "charges.get",
            "charge_id",
            "ch_3MmlLrLkdIwHu7ix0snN0B15",
            "charges",
        ),
        (
            "charges.get",
            "charge_id",
            "py_3MmlLrLkdIwHu7ix0snN0B15",
            "charges",
        ),
        (
            "payment_intents.get",
            "payment_intent_id",
            "pi_3MtwBwLkdIwHu7ix28a3tqPa",
            "payment_intents",
        ),
        (
            "invoices.get",
            "invoice_id",
            "in_1MtHbELkdIwHu7ixl4OzzPMv",
            "invoices",
        ),
    ] {
        let (b, _) = stripe(op_id, &[(param, id)]);
        assert_eq!(
            b.uri.to_string(),
            format!("https://api.stripe.com/v1/{path}/{id}")
        );
    }
}

#[test]
fn stripe_ids_and_filters_are_checked() {
    let m = manifest("stripe");
    for (op_id, p, bad) in [
        ("customers.get", "customer_id", "ch_123"),
        ("customers.get", "customer_id", "cus_1/../x"),
        ("charges.list", "customer", "cus_1&limit=100"),
        ("customers.list", "limit", "101"),
        ("customers.list", "starting_after", "cus_1%26x"),
        ("invoices.list", "status", "bogus"),
    ] {
        assert!(
            validate(op(m, op_id), &map(&[(p, bad)]), &BTreeMap::new()).is_err(),
            "{op_id} {p}={bad}"
        );
    }
}

#[test]
fn stripe_refund_is_a_built_form_body() {
    let (b, json) = stripe(
        "refunds.create",
        &[
            ("charge", "ch_3MmlLrLkdIwHu7ix0snN0B15"),
            ("amount", "1250"),
            ("reason", "requested_by_customer"),
        ],
    );
    assert_eq!(b.method, "POST");
    assert_eq!(b.uri.to_string(), "https://api.stripe.com/v1/refunds");
    assert_eq!(
        b.body.as_deref(),
        Some(&b"amount=1250&charge=ch_3MmlLrLkdIwHu7ix0snN0B15&reason=requested_by_customer"[..])
    );
    assert_eq!(
        header(&b, "content-type"),
        "application/x-www-form-urlencoded"
    );
    // The amount the caps see is the amount sent, in the admin currency.
    let spec = op(manifest("stripe"), "refunds.create")
        .amount
        .clone()
        .unwrap();
    assert_eq!(spec.unit, Unit::Minor);
    assert_eq!(
        amount::extract(&spec, &json.unwrap(), &map(&[("currency", "EUR")])).unwrap(),
        (1250, "EUR".to_string())
    );
}

#[test]
fn stripe_refund_params_are_constrained() {
    let o = op(manifest("stripe"), "refunds.create");
    for (k, bad) in [
        ("amount", "0"),
        ("amount", "-5"),
        ("amount", "100000000"),
        ("amount", "12.50"),
        ("reason", "because"),
        ("charge", "pi_1"),
        ("payment_intent", "ch_1"),
        ("metadata", "x"), // not a param: the agent cannot add fields
    ] {
        assert!(
            validate(o, &map(&[(k, bad)]), &BTreeMap::new()).is_err(),
            "{k}={bad}"
        );
    }
}

#[test]
fn stripe_raw_refund_body_is_refused() {
    let o = op(manifest("stripe"), "refunds.create");
    let raw = Bytes::from_static(br#"{"charge":"ch_1","amount":1}"#);
    assert_eq!(
        prepare_body(o, &BTreeMap::new(), Some(&raw)).unwrap_err(),
        "bad_param"
    );
}

#[test]
fn stripe_refund_without_amount_fails_the_amount_check() {
    let (_, json) = stripe(
        "refunds.create",
        &[("charge", "ch_3MmlLrLkdIwHu7ix0snN0B15")],
    );
    let spec = op(manifest("stripe"), "refunds.create")
        .amount
        .clone()
        .unwrap();
    assert!(amount::extract(&spec, &json.unwrap(), &map(&[("currency", "EUR")])).is_err());
}

#[test]
fn stripe_currency_param_is_admin_only_and_checked() {
    let p = &manifest("stripe").params["currency"];
    assert!(p.required);
    let re = regex::Regex::new(p.pattern.as_deref().unwrap()).unwrap();
    assert!(re.is_match("EUR") && !re.is_match("eur") && !re.is_match("EURO"));
}

#[test]
fn stripe_pagination_is_a_cursor_on_the_last_id() {
    let m = manifest("stripe");
    for id in [
        "customers.list",
        "charges.list",
        "payment_intents.list",
        "invoices.list",
        "refunds.list",
    ] {
        assert_eq!(
            op(m, id).pagination,
            Some(Pagination::Cursor {
                param: "starting_after".into(),
                next: "data[-1].id".into(),
                more: Some("has_more".into()),
            }),
            "{id}"
        );
    }
    let p = op(m, "customers.list").pagination.clone().unwrap();
    // https://docs.stripe.com/api/customers/list: a list object.
    let page = json!({"object": "list", "url": "/v1/customers", "has_more": true,
        "data": [{"id": "cus_NffrFeUfNV2Hib"}, {"id": "cus_NeGhb2PTcUHDsR"}]});
    assert_eq!(
        next_cursor(&p, &page),
        Some(("starting_after".into(), "cus_NeGhb2PTcUHDsR".into()))
    );
    let last = json!({"object": "list", "has_more": false, "data": [{"id": "cus_1"}]});
    assert_eq!(next_cursor(&p, &last), None);
    let empty = json!({"object": "list", "has_more": true, "data": []});
    assert_eq!(next_cursor(&p, &empty), None);
}

// ------------------------------------------------------------------- Slack

fn slack(op_id: &str, params: &[(&str, &str)]) -> (Built, Option<Value>) {
    go(manifest("slack"), SLACK_TOKEN, &[], op_id, params)
}

#[test]
fn slack_manifest_shape() {
    let m = manifest("slack");
    assert_eq!(m.base_url, "https://slack.com/api");
    assert_eq!(m.hosts, ["slack.com"]);
    use OpKind::{Read, Write};
    assert_eq!(
        shape(m),
        [
            ("conversations.list", "channels:read", Read),
            ("conversations.history", "messages:read", Read),
            ("conversations.replies", "messages:read", Read),
            ("users.list", "users:read", Read),
            ("users.info", "users:read", Read),
            ("chat.postMessage", "messages:write", Write),
        ]
    );
}

#[test]
fn slack_golden_requests() {
    let (b, _) = slack(
        "conversations.history",
        &[("channel", "C012AB3CD"), ("limit", "20")],
    );
    assert_eq!(
        b.uri.to_string(),
        "https://slack.com/api/conversations.history?channel=C012AB3CD&limit=20"
    );
    assert_eq!(header(&b, "authorization"), format!("Bearer {SLACK_TOKEN}"));
    let (b, _) = slack(
        "conversations.replies",
        &[("channel", "C012AB3CD"), ("ts", "1512085950.000216")],
    );
    assert_eq!(
        b.uri.to_string(),
        "https://slack.com/api/conversations.replies?channel=C012AB3CD&ts=1512085950.000216"
    );
    let (b, _) = slack("users.info", &[("user", "W1234567890")]);
    assert_eq!(
        b.uri.to_string(),
        "https://slack.com/api/users.info?user=W1234567890"
    );
    let (b, _) = slack(
        "conversations.list",
        &[("types", "public_channel,private_channel")],
    );
    assert_eq!(
        b.uri.to_string(),
        "https://slack.com/api/conversations.list?types=public_channel%2Cprivate_channel"
    );
}

#[test]
fn slack_multiline_message_is_built_into_json() {
    let text = "Deploy done.\n\t- api: ok\n\t- web: ok\nSee \"status\" & <https://x.test|link>";
    let (b, json) = slack(
        "chat.postMessage",
        &[
            ("channel", "C012AB3CD"),
            ("text", text),
            ("thread_ts", "1512085950.000216"),
        ],
    );
    assert_eq!(b.method, "POST");
    assert_eq!(b.uri.to_string(), "https://slack.com/api/chat.postMessage");
    assert_eq!(header(&b, "content-type"), "application/json");
    let sent: Value = serde_json::from_slice(b.body.as_deref().unwrap()).unwrap();
    assert_eq!(
        sent,
        json!({"channel": "C012AB3CD", "text": text, "thread_ts": "1512085950.000216"})
    );
    assert_eq!(json.unwrap(), sent);
}

#[test]
fn slack_params_are_constrained() {
    let m = manifest("slack");
    for (op_id, k, bad) in [
        ("chat.postMessage", "channel", "general"),
        ("chat.postMessage", "channel", "C01&x=1"),
        ("chat.postMessage", "text", ""),
        ("chat.postMessage", "text", "bad\u{1}char"),
        ("chat.postMessage", "thread_ts", "yesterday"),
        ("chat.postMessage", "blocks", "[]"),
        ("conversations.history", "cursor", "a&limit=1"),
        ("conversations.history", "channel", "c012ab3cd"),
        ("users.info", "user", "U1/../x"),
    ] {
        assert!(
            validate(op(m, op_id), &map(&[(k, bad)]), &BTreeMap::new()).is_err(),
            "{op_id} {k}={bad:?}"
        );
    }
    let long = "x".repeat(4001);
    assert!(validate(
        op(m, "chat.postMessage"),
        &map(&[("text", &long)]),
        &BTreeMap::new()
    )
    .is_err());
}

#[test]
fn slack_channel_is_the_qualifier() {
    let m = manifest("slack");
    for id in [
        "conversations.history",
        "conversations.replies",
        "chat.postMessage",
    ] {
        let o = op(m, id);
        assert_eq!(
            qualifier_for(o, &map(&[("channel", "C012AB3CD")])).as_deref(),
            Some("channel=C012AB3CD"),
            "{id}"
        );
        // No channel, no qualifier: a qualified allow does not match.
        assert_eq!(qualifier_for(o, &BTreeMap::new()), None, "{id}");
    }
    assert!(op(m, "users.list").qualifier.is_none());
}

#[test]
fn slack_pagination_and_the_last_page() {
    let m = manifest("slack");
    let p = op(m, "conversations.list").pagination.clone().unwrap();
    assert_eq!(
        p,
        Pagination::Cursor {
            param: "cursor".into(),
            next: "response_metadata.next_cursor".into(),
            more: None
        }
    );
    // https://api.slack.com/methods/conversations.list
    let page = json!({"ok": true, "channels": [{"id": "C012AB3CD", "name": "general"}],
        "response_metadata": {"next_cursor": "dGVhbTpDMDYxRkE1UEI="}});
    assert_eq!(
        next_cursor(&p, &page),
        Some(("cursor".into(), "dGVhbTpDMDYxRkE1UEI=".into()))
    );
    // An empty cursor is the last page.
    let last = json!({"ok": true, "channels": [], "response_metadata": {"next_cursor": ""}});
    assert_eq!(next_cursor(&p, &last), None);
    // The next cursor is accepted as a parameter of the next call.
    let (b, _) = slack("conversations.list", &[("cursor", "dGVhbTpDMDYxRkE1UEI=")]);
    assert_eq!(
        b.uri.to_string(),
        "https://slack.com/api/conversations.list?cursor=dGVhbTpDMDYxRkE1UEI%3D"
    );
}

// ----------------------------------------------------------------- Discord

fn discord(op_id: &str, params: &[(&str, &str)]) -> (Built, Option<Value>) {
    go(manifest("discord"), DISCORD_TOKEN, &[], op_id, params)
}

#[test]
fn discord_manifest_shape() {
    let m = manifest("discord");
    assert_eq!(m.base_url, "https://discord.com/api/v10");
    assert_eq!(m.hosts, ["discord.com"]);
    use OpKind::{Read, Write};
    assert_eq!(
        shape(m),
        [
            ("guilds.channels", "channels:read", Read),
            ("channels.get", "channels:read", Read),
            ("messages.list", "messages:read", Read),
            ("messages.create", "messages:write", Write),
        ]
    );
    let AuthSpec { kind, prefix, .. } = &m.auth[0];
    assert_eq!((kind.as_str(), prefix.as_deref()), ("header", Some("Bot ")));
}

#[test]
fn discord_golden_requests() {
    let (b, _) = discord(
        "messages.list",
        &[
            ("channel_id", "41771983423143937"),
            ("limit", "50"),
            ("before", "41771983423143999"),
        ],
    );
    assert_eq!(
        b.uri.to_string(),
        "https://discord.com/api/v10/channels/41771983423143937/messages?before=41771983423143999&limit=50"
    );
    assert_eq!(header(&b, "authorization"), format!("Bot {DISCORD_TOKEN}"));
    assert!(b.headers["user-agent"]
        .to_str()
        .unwrap()
        .starts_with("DiscordBot ("));
    let (b, _) = discord("guilds.channels", &[("guild_id", "41771983423143937")]);
    assert_eq!(
        b.uri.to_string(),
        "https://discord.com/api/v10/guilds/41771983423143937/channels"
    );
    let (b, _) = discord("channels.get", &[("channel_id", "41771983423143937")]);
    assert_eq!(
        b.uri.to_string(),
        "https://discord.com/api/v10/channels/41771983423143937"
    );
}

#[test]
fn discord_message_pings_nobody_and_may_be_multiline() {
    let content = "Build 42 passed.\nNotes:\n\t- @everyone please look\n\t- <@&123> too";
    let (b, _) = discord(
        "messages.create",
        &[("channel_id", "41771983423143937"), ("content", content)],
    );
    assert_eq!(b.method, "POST");
    let sent: Value = serde_json::from_slice(b.body.as_deref().unwrap()).unwrap();
    assert_eq!(
        sent,
        json!({"content": content, "allowed_mentions": {"parse": []}})
    );
}

#[test]
fn discord_params_are_constrained() {
    let m = manifest("discord");
    for (op_id, k, bad) in [
        ("messages.create", "content", ""),
        ("messages.create", "allowed_mentions", "{}"),
        ("messages.create", "channel_id", "12/../3"),
        ("messages.list", "limit", "5&before=1"),
        ("messages.list", "before", "abc"),
        ("messages.list", "after", "123456789012345678901"),
        ("guilds.channels", "guild_id", "x"),
    ] {
        assert!(
            validate(op(m, op_id), &map(&[(k, bad)]), &BTreeMap::new()).is_err(),
            "{op_id} {k}={bad:?}"
        );
    }
    let o = op(m, "messages.create");
    let with = |c: &str| {
        validate(
            o,
            &map(&[("channel_id", "1"), ("content", c)]),
            &BTreeMap::new(),
        )
    };
    assert!(with(&"x".repeat(2001)).is_err());
    assert!(with(&"x".repeat(2000)).is_ok());
    // A raw body is refused: the broker builds it.
    let raw = Bytes::from_static(br#"{"content":"x","allowed_mentions":{"parse":["everyone"]}}"#);
    assert_eq!(
        prepare_body(o, &BTreeMap::new(), Some(&raw)).unwrap_err(),
        "bad_param"
    );
}

#[test]
fn discord_qualifiers() {
    let m = manifest("discord");
    assert_eq!(
        qualifier_for(op(m, "guilds.channels"), &map(&[("guild_id", "7")])).as_deref(),
        Some("guild=7")
    );
    for id in ["channels.get", "messages.list", "messages.create"] {
        assert_eq!(
            qualifier_for(op(m, id), &map(&[("channel_id", "9")])).as_deref(),
            Some("channel=9"),
            "{id}"
        );
    }
    // Discord returns no `next`: nothing paginates.
    assert!(m.operation.iter().all(|o| o.pagination.is_none()));
}

// ----------------------------------------------------- pipeline, end to end

struct Mock {
    hits: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<(String, http::HeaderMap, Bytes)>>>,
}

struct Loopback(u16);

impl Resolver for Loopback {
    fn resolve(&self, host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
        match host {
            "api.stripe.com" | "slack.com" | "discord.com" => {
                Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, self.0))])
            }
            _ => Err(io::Error::new(io::ErrorKind::NotFound, "unknown test host")),
        }
    }
}

type Seen = Arc<Mutex<Vec<(String, http::HeaderMap, Bytes)>>>;

async fn answer(
    req: Request<Incoming>,
    hits: Arc<AtomicUsize>,
    seen: Seen,
) -> Result<Response<Full<Bytes>>, Infallible> {
    hits.fetch_add(1, Ordering::SeqCst);
    let (parts, body) = req.into_parts();
    let body = body
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    seen.lock()
        .unwrap()
        .push((parts.uri.to_string(), parts.headers.clone(), body));
    // Slack's style: a refused call is still a 200.
    Ok(Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from_static(br#"{"ok":true,"id":"re_1"}"#)))
        .unwrap())
}

async fn mock() -> (Mock, Upstream) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![
        "api.stripe.com".to_string(),
        "slack.com".to_string(),
        "discord.com".to_string(),
    ])
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
    let hits = Arc::new(AtomicUsize::new(0));
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let (h2, s2) = (hits.clone(), seen.clone());
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let (h, s) = (h2.clone(), s2.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let svc = service_fn(move |req| answer(req, h.clone(), s.clone()));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let up = Upstream::with_roots(roots, Arc::new(Loopback(port)), Duration::from_secs(2));
    (Mock { hits, seen }, up)
}

struct FakeEnv {
    service: &'static str,
    token: &'static str,
    pools: Pools,
}

impl Env for FakeEnv {
    fn lockdown(&self) -> Option<saiife_broker::pipeline::Lockdown> {
        None
    }
    fn scope(&self, _user: &str) -> Result<Option<Scope>, PolicyError> {
        Ok(Some(Scope {
            name: "agents".into(),
            users: vec!["agent".into()],
            projects: vec![],
            services: vec![self.service.into()],
            env: None,
        }))
    }
    fn secret(
        &self,
        _name: &str,
        _service: &str,
        auth: &[AuthSpec],
    ) -> Result<AuthMaterial, &'static str> {
        let fields = [("token".to_string(), Zeroizing::new(self.token.to_string()))].into();
        Ok(AuthMaterial::from_spec(&auth[0], fields))
    }
    fn secret_values(&self, _name: &str) -> Option<Vec<Zeroizing<String>>> {
        Some(vec![Zeroizing::new(self.token.to_string())])
    }
    fn pool(&self, service: &str) -> Arc<Semaphore> {
        self.pools.get(service)
    }
    fn create_approval<'a>(&'a self, _p: &'a PendingCall) -> ApprovalFuture<'a> {
        Box::pin(async { Ok(42) })
    }
}

fn env_for(service: &'static str, token: &'static str) -> FakeEnv {
    FakeEnv {
        service,
        token,
        pools: Pools::new(),
    }
}

fn snap(text: &str) -> PolicySnapshot {
    PolicySnapshot {
        config: toml::from_str(&format!("version = 2\nlocked = true\n{text}")).unwrap(),
        hash: "sha256:test".into(),
        mode: Mode::Locked,
        env: None,
    }
}

fn call(service: &str, op_id: &str, params: &[(&str, &str)]) -> Call {
    Call {
        uid: 1001,
        user: "agent".into(),
        session: Some("sess-1".into()),
        project: "/srv/app".into(),
        service: service.into(),
        op: OpRef::Named(op_id.into()),
        params: map(params),
        body: None,
        headers: vec![],
        overlay: None,
        via: Via::Cli,
        collection: None,
    }
}

fn catalog() -> Catalog {
    Catalog::new(builtin(), vec![])
}

fn rule(o: &Outcome) -> &str {
    match o {
        Outcome::Denied { rule } => rule,
        other => panic!("expected a deny, got {other:?}"),
    }
}

/// No record may hold a vault value.
fn assert_clean(
    c: &Call,
    s: &PolicySnapshot,
    tr: &saiife_broker::pipeline::Trace,
    o: &Outcome,
    secret: &str,
) {
    let r = serde_json::to_string(&record(c, s, tr, o, "", "0.2.0")).unwrap();
    assert!(!r.contains(secret), "{r}");
}

const STRIPE_POLICY: &str = r#"[services.pay]
connector = "stripe"
secret = "stripe-tok"
params = { currency = "EUR" }
allow = ["refunds:write", "customers:read"]
[services.pay.limits]
amount_per_day = { max = 500, currency = "EUR" }
"#;

#[tokio::test]
async fn refund_without_amount_denied_bad_amount() {
    let (m, up) = mock().await;
    let s = snap(STRIPE_POLICY);
    let env = env_for("pay", STRIPE_KEY);
    let c = call(
        "pay",
        "refunds.create",
        &[("charge", "ch_3MmlLrLkdIwHu7ix0snN0B15")],
    );
    let (o, tr) = run(&c, &s, &catalog(), &Limiter::new(), &env, Some(&up)).await;
    assert_eq!(rule(&o), "bad_amount");
    assert!(!tr.sent);
    assert_eq!(m.hits.load(Ordering::SeqCst), 0);
    assert_clean(&c, &s, &tr, &o, STRIPE_KEY);
}

/// Refunds under `amount_per_day = 500 EUR`: 200.00 and 250.00 go through
/// (as 20000 and 25000 cents), the next 100.00 would make 550 and is denied
/// before sending.
#[tokio::test]
async fn refund_amount_cap_end_to_end() {
    let (m, up) = mock().await;
    let s = snap(STRIPE_POLICY);
    let (cat, lim, env) = (catalog(), Limiter::new(), env_for("pay", STRIPE_KEY));
    let refund = |cents: &str| {
        call(
            "pay",
            "refunds.create",
            &[
                ("payment_intent", "pi_3MtwBwLkdIwHu7ix28a3tqPa"),
                ("amount", cents),
            ],
        )
    };
    for a in ["20000", "25000"] {
        let (o, tr) = run(&refund(a), &s, &cat, &lim, &env, Some(&up)).await;
        assert!(matches!(o, Outcome::Done { .. }), "{a}: {o:?}");
        assert!(tr.sent);
    }
    let c = refund("10000");
    let (o, tr) = run(&c, &s, &cat, &lim, &env, Some(&up)).await;
    assert!(
        matches!(
            o,
            Outcome::Limited {
                limit: "amount_per_day"
            }
        ),
        "{o:?}"
    );
    assert_eq!(tr.amount, Some((10_000, "EUR".to_string())));
    assert_eq!(m.hits.load(Ordering::SeqCst), 2);
    let seen = m.seen.lock().unwrap();
    assert_eq!(seen[0].0, "/v1/refunds");
    assert_eq!(seen[0].1["authorization"], format!("Bearer {STRIPE_KEY}"));
    assert_eq!(
        seen[0].1["content-type"],
        "application/x-www-form-urlencoded"
    );
    assert_eq!(
        &seen[0].2[..],
        b"amount=20000&payment_intent=pi_3MtwBwLkdIwHu7ix28a3tqPa"
    );
    drop(seen);
    assert_clean(&c, &s, &tr, &o, STRIPE_KEY);
}

#[tokio::test]
async fn refund_in_the_wrong_currency_is_not_possible() {
    // The currency is the admin's: a cap in USD does not cover a EUR service.
    let (m, up) = mock().await;
    let s = snap(&STRIPE_POLICY.replace(
        "max = 500, currency = \"EUR\"",
        "max = 500, currency = \"USD\"",
    ));
    let env = env_for("pay", STRIPE_KEY);
    let c = call(
        "pay",
        "refunds.create",
        &[("charge", "ch_3MmlLrLkdIwHu7ix0snN0B15"), ("amount", "100")],
    );
    let (o, _) = run(&c, &s, &catalog(), &Limiter::new(), &env, Some(&up)).await;
    assert!(!matches!(o, Outcome::Done { .. }), "{o:?}");
    assert_eq!(m.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn slack_post_is_decided_by_channel() {
    let (m, up) = mock().await;
    let s = snap(
        r#"[services.chat]
connector = "slack"
secret = "slack-tok"
allow = ["messages:write:channel=C012AB3CD", "messages:read:channel=C012AB3CD"]
"#,
    );
    let (cat, lim, env) = (catalog(), Limiter::new(), env_for("chat", SLACK_TOKEN));
    let post = |channel: &str| {
        call(
            "chat",
            "chat.postMessage",
            &[("channel", channel), ("text", "line one\nline two")],
        )
    };
    let (o, tr) = run(&post("C012AB3CD"), &s, &cat, &lim, &env, Some(&up)).await;
    assert!(matches!(o, Outcome::Done { .. }), "{o:?}");
    assert_eq!(
        tr.capability.as_deref(),
        Some("messages:write:channel=C012AB3CD")
    );
    let c = post("C999ZZ999");
    let (o, tr) = run(&c, &s, &cat, &lim, &env, Some(&up)).await;
    assert_eq!(rule(&o), "default_deny");
    assert_eq!(
        tr.capability.as_deref(),
        Some("messages:write:channel=C999ZZ999")
    );
    assert_clean(&c, &s, &tr, &o, SLACK_TOKEN);
    // Reading another channel is denied the same way.
    let h = call("chat", "conversations.history", &[("channel", "C999ZZ999")]);
    let (o, _) = run(&h, &s, &cat, &lim, &env, Some(&up)).await;
    assert_eq!(rule(&o), "default_deny");
    assert_eq!(m.hits.load(Ordering::SeqCst), 1);
    let seen = m.seen.lock().unwrap();
    assert_eq!(seen[0].0, "/api/chat.postMessage");
    assert_eq!(seen[0].1["authorization"], format!("Bearer {SLACK_TOKEN}"));
    let sent: Value = serde_json::from_slice(&seen[0].2).unwrap();
    assert_eq!(sent["text"], "line one\nline two");
}

#[tokio::test]
async fn discord_post_suppresses_mentions_end_to_end() {
    let (m, up) = mock().await;
    let s = snap(
        r#"[services.dc]
connector = "discord"
secret = "dc-tok"
allow = ["messages:write:channel=41771983423143937"]
"#,
    );
    let (cat, lim, env) = (catalog(), Limiter::new(), env_for("dc", DISCORD_TOKEN));
    let post = |channel: &str| {
        call(
            "dc",
            "messages.create",
            &[("channel_id", channel), ("content", "hi @everyone\nbye")],
        )
    };
    let (o, _) = run(&post("41771983423143937"), &s, &cat, &lim, &env, Some(&up)).await;
    assert!(matches!(o, Outcome::Done { .. }), "{o:?}");
    let c = post("41771983423143938");
    let (o, tr) = run(&c, &s, &cat, &lim, &env, Some(&up)).await;
    assert_eq!(rule(&o), "default_deny");
    assert_clean(&c, &s, &tr, &o, DISCORD_TOKEN);
    assert_eq!(m.hits.load(Ordering::SeqCst), 1);
    let seen = m.seen.lock().unwrap();
    assert_eq!(seen[0].0, "/api/v10/channels/41771983423143937/messages");
    assert_eq!(seen[0].1["authorization"], format!("Bot {DISCORD_TOKEN}"));
    let sent: Value = serde_json::from_slice(&seen[0].2).unwrap();
    assert_eq!(
        sent,
        json!({"content": "hi @everyone\nbye", "allowed_mentions": {"parse": []}})
    );
}
