//! Salesforce connector (plan 14, Task 12): manifest, golden requests,
//! fixtures, the SOQL and locator params, the policy outcomes of the
//! suggested policies (docs/connectors/salesforce.md), and OAuth2 calls
//! through the whole pipeline against one loopback TLS mock that serves both
//! the token endpoint and the API. The env's `oauth_token` uses the broker's
//! own `oauth2::token_request` and `oauth2::parse_token`, as the daemon does.
//! Nothing leaves 127.0.0.1.

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;
use saiife_broker::limits::Limiter;
use saiife_broker::manifest::{builtin, qualifier_for, AuthSpec, Manifest, OpKind};
use saiife_broker::oauth2;
use saiife_broker::params::validate;
use saiife_broker::pipeline::{
    record, run, ApprovalFuture, Call, Env, Lockdown, OpRef, Outcome, PendingCall, PolicySnapshot,
    Pools, TokenFuture, Via,
};
use saiife_broker::request::{build, AuthMaterial, Built};
use saiife_broker::resolve::{named, proxy};
use saiife_broker::upstream::{Resolver, Upstream};
use saiife_broker::{BrokerError, Catalog};
use saiife_policy::{decide, Capability, Mode, PolicyError, Request as PolicyRequest, Scope};
use saiife_policy::{ServiceCfg, Verdict};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

const HOST: &str = "acme.my.salesforce.com";
const BASE: &str = "https://acme.my.salesforce.com/services/data/v60.0";

// Built at runtime: no token-shaped literal in the source.
fn client_id() -> String {
    format!("3MVG9{}", "cid".repeat(6))
}
fn client_secret() -> String {
    format!("cs-{}", "k9".repeat(12))
}
fn initial_refresh() -> String {
    format!("5Aep{}", "r1".repeat(16))
}
fn access(n: usize) -> String {
    format!("00D{n}!{}", "q7".repeat(16))
}
fn rotated(n: usize) -> String {
    format!("5Aep{n}{}", "c3".repeat(16))
}

fn salesforce() -> &'static Manifest {
    builtin()
        .iter()
        .find(|m| m.id == "salesforce")
        .expect("salesforce is a built-in manifest")
}

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn svc_params() -> BTreeMap<String, String> {
    map(&[("instance_host", HOST), ("api_version", "v60.0")])
}

fn fixture(name: &str) -> Value {
    let path = format!(
        "{}/tests/fixtures/salesforce/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
}

// ---------------------------------------------------------------- offline

fn try_go(op_id: &str, params: &[(&str, &str)], body: Option<&str>) -> Result<Built, BrokerError> {
    let m = salesforce();
    let op = named(m, op_id).unwrap_or_else(|| panic!("no operation {op_id}"));
    let params = validate(op, &map(params), &BTreeMap::new())?;
    let auth = AuthMaterial::from_spec(
        &m.auth[0],
        BTreeMap::from([("access_token".to_string(), Zeroizing::new(access(0)))]),
    );
    let headers = vec![
        (
            "Authorization".to_string(),
            "Bearer agent-guess".to_string(),
        ),
        ("Accept".to_string(), "application/json".to_string()),
        ("Sforce-Call-Options".to_string(), "client=x".to_string()),
    ];
    build(
        m,
        op,
        &svc_params(),
        &params,
        &headers,
        body.map(|b| Bytes::from(b.to_string())),
        &auth,
    )
}

fn go(op_id: &str, params: &[(&str, &str)], body: Option<&str>) -> Built {
    try_go(op_id, params, body).unwrap()
}

#[test]
fn manifest_shape() {
    let m = salesforce();
    assert_eq!(m.hosts, ["{instance_host}"]);
    assert_eq!(
        m.base_url,
        "https://{instance_host}/services/data/{api_version}"
    );
    assert_eq!(m.auth.len(), 1);
    assert_eq!(m.auth[0].kind, "oauth2");
    assert_eq!(
        m.auth[0].token_path.as_deref(),
        Some("/services/oauth2/token")
    );
    assert!(m.params["instance_host"].required);
    assert!(m.params["api_version"].required);
    let want = [
        ("query", "query:read", OpKind::Read, None),
        ("query.more", "query:read", OpKind::Read, None),
        ("sobjects.list", "sobjects:read", OpKind::Read, None),
        (
            "sobjects.describe",
            "sobjects:read",
            OpKind::Read,
            Some("sobject={sobject}"),
        ),
        (
            "records.get",
            "records:read",
            OpKind::Read,
            Some("sobject={sobject}"),
        ),
        (
            "records.create",
            "records:write",
            OpKind::Write,
            Some("sobject={sobject}"),
        ),
        (
            "records.update",
            "records:write",
            OpKind::Write,
            Some("sobject={sobject}"),
        ),
        (
            "records.delete",
            "records:delete",
            OpKind::Delete,
            Some("sobject={sobject}"),
        ),
    ];
    let ids: Vec<&str> = m.operation.iter().map(|o| o.id.as_str()).collect();
    assert_eq!(ids, want.map(|w| w.0));
    for (id, cap, kind, qual) in want {
        let op = named(m, id).unwrap();
        assert_eq!((op.capability.as_str(), op.kind), (cap, kind), "{id}");
        assert_eq!(op.qualifier.as_deref(), qual, "{id}");
        assert!(op.amount.is_none(), "{id}");
        // Salesforce returns no `next`: the docs show the follow-up call.
        assert_eq!(op.pagination, None, "{id}");
    }
}

#[test]
fn golden_requests_carry_the_bearer_from_memory() {
    let b = go(
        "records.get",
        &[("sobject", "Account"), ("id", "001D000000IRFmaIAH")],
        None,
    );
    assert_eq!(b.method, "GET");
    assert_eq!(
        b.uri.to_string(),
        format!("{BASE}/sobjects/Account/001D000000IRFmaIAH")
    );
    // The agent's Authorization is dropped; the access token goes out.
    assert_eq!(
        b.headers.get("authorization").unwrap(),
        format!("Bearer {}", access(0)).as_str()
    );
    assert_eq!(b.headers.get("accept").unwrap(), "application/json");
    assert!(b.headers.get("sforce-call-options").is_none());

    let b = go(
        "records.get",
        &[
            ("sobject", "Account"),
            ("id", "001D000000IRFma"),
            ("fields", "Name,Industry"),
        ],
        None,
    );
    assert!(b.uri.query().unwrap().starts_with("fields=Name"));

    assert_eq!(
        go("sobjects.list", &[], None).uri.to_string(),
        format!("{BASE}/sobjects")
    );
    assert_eq!(
        go("sobjects.describe", &[("sobject", "My_Object__c")], None)
            .uri
            .to_string(),
        format!("{BASE}/sobjects/My_Object__c/describe")
    );

    let body = fixture("records.create")["_request"].to_string();
    let b = go("records.create", &[("sobject", "Account")], Some(&body));
    assert_eq!(b.method, "POST");
    assert_eq!(b.uri.to_string(), format!("{BASE}/sobjects/Account"));
    assert_eq!(b.body.as_deref(), Some(body.as_bytes()));
    let b = go(
        "records.update",
        &[("sobject", "Account"), ("id", "001D000000IRFmaIAH")],
        Some(r#"{"Industry":"Retail"}"#),
    );
    assert_eq!(b.method, "PATCH");
    assert_eq!(
        b.uri.path(),
        "/services/data/v60.0/sobjects/Account/001D000000IRFmaIAH"
    );
    let b = go(
        "records.delete",
        &[("sobject", "Account"), ("id", "001D000000IRFmaIAH")],
        None,
    );
    assert_eq!(b.method, "DELETE");
    assert!(b.body.is_none());
}

/// The one `q` value in a query string, decoded.
fn q_of(b: &Built) -> String {
    let query = b.uri.query().unwrap();
    let pairs: Vec<&str> = query.split('&').collect();
    assert_eq!(pairs.len(), 1, "{query}");
    let v = pairs[0].strip_prefix("q=").unwrap();
    percent_encoding::percent_decode_str(&v.replace('+', " "))
        .decode_utf8()
        .unwrap()
        .into_owned()
}

#[test]
fn soql_is_one_encoded_query_value() {
    // `&`, `=`, `#` and quotes in SOQL stay inside the one `q` value: they
    // cannot add a parameter or end the query string.
    let soql = "SELECT Id, Name FROM Account WHERE Name = 'A&B=1#x' LIMIT 5";
    let b = go("query", &[("q", soql)], None);
    assert_eq!(b.uri.path(), "/services/data/v60.0/query");
    assert_eq!(q_of(&b), soql);
    assert!(b.uri.query().unwrap().is_ascii());
}

#[test]
fn soql_refuses_control_characters_and_is_capped_at_4000_bytes() {
    let op = named(salesforce(), "query").unwrap();
    let ok = |q: &str| validate(op, &map(&[("q", q)]), &BTreeMap::new()).is_ok();
    assert!(ok("SELECT Id FROM Contact"));
    assert!(ok(&"x".repeat(4000)));
    assert!(!ok(&"x".repeat(4001)));
    // Control characters anywhere: line breaks, tab, NUL, DEL, and the C1
    // controls; non-ASCII is refused too, which keeps the cap in bytes.
    for bad in [
        "SELECT Id FROM Account\nWHERE Name = 'x'",
        "SELECT Id FROM Account\r",
        "SELECT\tId FROM Account",
        "SELECT Id FROM Account\0",
        "SELECT Id FROM Account\u{7f}",
        "SELECT Id FROM Account\u{85}",
        "SELECT Id FROM Account WHERE Name = 'Müller'",
        "",
    ] {
        assert!(!ok(bad), "{bad:?}");
    }
    // The cap counts bytes: 4000 ASCII bytes pass, 4000 two-byte chars do not.
    assert!(!ok(&"é".repeat(2000)));
}

#[test]
fn sobject_qualifier_refuses_control_characters_and_paths() {
    let m = salesforce();
    for id in [
        "sobjects.describe",
        "records.get",
        "records.create",
        "records.update",
        "records.delete",
    ] {
        let op = named(m, id).unwrap();
        for bad in [
            "Account\n",
            "Account\r\nX: 1",
            "Acc\tount",
            "Account\0",
            "Account/../User",
            "Account%2F..",
            "Account?x=1",
            "Account*",
            "sobject=User",
            "1Account",
            "",
        ] {
            let mut p = map(&[("sobject", bad)]);
            if op.path_params.contains_key("id") {
                p.insert("id".into(), "001D000000IRFmaIAH".into());
            }
            assert!(validate(op, &p, &BTreeMap::new()).is_err(), "{id} {bad:?}");
        }
    }
    let op = named(m, "records.get").unwrap();
    let p = map(&[("sobject", "My_Object__c"), ("id", "a01D000000IRFmaIAH")]);
    let p = validate(op, &p, &BTreeMap::new()).unwrap();
    assert_eq!(
        qualifier_for(op, &p).as_deref(),
        Some("sobject=My_Object__c")
    );
    for bad in [
        "describe",
        "001D000000IRFma/x",
        "001D000000IRFmaIAHX",
        "../User",
    ] {
        let p = map(&[("sobject", "Account"), ("id", bad)]);
        assert!(validate(op, &p, &BTreeMap::new()).is_err(), "{bad:?}");
    }
}

#[test]
fn fields_cannot_traverse_relationships() {
    // `fields` names the object's own fields only: a dotted relationship
    // path would read another object under a per-sobject qualifier.
    let op = named(salesforce(), "records.get").unwrap();
    let ok = |f: &str| {
        let p = map(&[ACC, REC, ("fields", f)]);
        validate(op, &p, &BTreeMap::new()).is_ok()
    };
    assert!(ok("Name,Industry,My_Field__c"));
    for bad in [
        "Account.Name",
        "Owner.Email",
        "Name,Account.Owner.Email",
        "Parent.Parent.Name",
        "Name\n",
        "",
    ] {
        assert!(!ok(bad), "{bad:?}");
    }
}

#[test]
fn query_more_locator_single_segment() {
    let m = salesforce();
    let op = named(m, "query.more").unwrap();
    // The follow-up locator is the last segment of the fixture's
    // nextRecordsUrl, and the call sends it as one segment.
    let next = fixture("query")["nextRecordsUrl"]
        .as_str()
        .unwrap()
        .to_string();
    let locator = next.rsplit('/').next().unwrap();
    assert_eq!(locator, "01gD0000002HU6KIAW-2000");
    let b = go("query.more", &[("locator", locator)], None);
    assert_eq!(b.uri.to_string(), format!("{BASE}/query/{locator}"));
    assert_eq!(b.uri.path(), next);
    assert!(fixture("query_last")["nextRecordsUrl"].is_null());
    assert_eq!(fixture("query_last")["done"], true);
    // Never more than one segment, and never a whole URL or path.
    for bad in [
        next.as_str(),
        "01gD0000002HU6KIAW-2000/../../sobjects",
        "01gD0000002HU6KIAW-2000%2F..",
        "01gD0000002HU6KIAW-2000?q=x",
        "01gD0000002HU6KIAW-2000#",
        "..",
        "01gD0000002HU6KIAW",
        "01gD0000002HU6KIAW-",
        "01gD0000002HU6KIAW-2000\n",
        "https://evil.test/x",
        "",
    ] {
        assert!(
            validate(op, &map(&[("locator", bad)]), &BTreeMap::new()).is_err(),
            "{bad:?}"
        );
    }
    // On the proxy path a locator with a slash is a different (unknown) path.
    assert!(proxy(m, "GET", "/query/01gD0000002HU6KIAW-2000/x").is_err());
    let (o, p) = proxy(m, "GET", "/query/01gD0000002HU6KIAW-2000").unwrap();
    assert_eq!(o.id, "query.more");
    assert_eq!(p["locator"], "01gD0000002HU6KIAW-2000");
}

#[test]
fn proxy_paths_resolve_to_the_same_capabilities() {
    let m = salesforce();
    let id = |method: &str, path: &str| proxy(m, method, path).map(|(o, _)| o.id.clone());
    assert_eq!(
        id("GET", "/sobjects/Account/describe").unwrap(),
        "sobjects.describe"
    );
    assert_eq!(
        id("GET", "/sobjects/Account/001D000000IRFmaIAH").unwrap(),
        "records.get"
    );
    assert_eq!(
        id("GET", "/query?q=SELECT+Id+FROM+Account").unwrap(),
        "query"
    );
    assert_eq!(
        id("DELETE", "/sobjects/Account/001D000000IRFmaIAH").unwrap(),
        "records.delete"
    );
    // Endpoints not in the manifest are unknown: no queryAll, composite,
    // search (SOSL), Apex REST or tooling.
    for (method, path) in [
        ("GET", "/queryAll?q=SELECT+Id+FROM+Account"),
        ("GET", "/search?q=FIND+%7Bx%7D"),
        ("POST", "/composite"),
        ("POST", "/composite/sobjects"),
        ("GET", "/tooling/query?q=x"),
        ("GET", "/sobjects/Account"),
        ("PUT", "/sobjects/Account/001D000000IRFmaIAH"),
    ] {
        assert!(id(method, path).is_err(), "{method} {path}");
    }
}

#[test]
fn instance_host_and_api_version_are_admin_pins() {
    let cat = Catalog::new(builtin(), Vec::new());
    let check = |host: &str, version: &str| {
        let cfg: saiife_policy::SystemConfig = toml::from_str(&format!(
            "version = 2\n[services.sf]\nconnector = \"salesforce\"\nsecret = \"s\"\n\
             [services.sf.params]\ninstance_host = {host:?}\napi_version = {version:?}\n"
        ))
        .unwrap();
        saiife_broker::catalog::validate(&cfg, &cat)
    };
    for good in [HOST, "acme--dev.sandbox.my.salesforce.com"] {
        check(good, "v60.0").unwrap_or_else(|e| panic!("{good}: {e}"));
    }
    for bad in [
        "acme.salesforce.com",
        "login.salesforce.com",
        "evil.test",
        "acme.my.salesforce.com.evil.test",
        "acme.my.salesforce.com.",
        "ACME.my.salesforce.com",
        "acme.my.salesforce.com:8443",
        "x@acme.my.salesforce.com",
        "evil.test/acme.my.salesforce.com",
        "a.b.my.salesforce.com",
        "acme.scratch.my.salesforce.com",
        "",
    ] {
        assert!(check(bad, "v60.0").is_err(), "{bad:?}");
    }
    for bad in [
        "v60", "60.0", "v60.1", "v6.0", "v6000.0", "v60.0/..", "v60.0?x", "V60.0", "",
    ] {
        assert!(check(HOST, bad).is_err(), "{bad:?}");
    }
    // Both are required.
    let cfg: saiife_policy::SystemConfig = toml::from_str(&format!(
        "version = 2\n[services.sf]\nconnector = \"salesforce\"\nsecret = \"s\"\n\
         [services.sf.params]\ninstance_host = {HOST:?}\n"
    ))
    .unwrap();
    assert!(saiife_broker::catalog::validate(&cfg, &cat).is_err());
    // The token endpoint is on the admin's host, whatever the agent sends.
    let fields: BTreeMap<String, Zeroizing<String>> = [
        ("client_id", client_id()),
        ("client_secret", client_secret()),
        ("refresh_token", initial_refresh()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), Zeroizing::new(v)))
    .collect();
    let m = salesforce();
    let t = oauth2::token_request(&m.auth[0], m, &svc_params(), &fields).unwrap();
    assert_eq!(
        t.uri.to_string(),
        format!("https://{HOST}/services/oauth2/token")
    );
    assert!(oauth2::instance_required(m));
    assert!(!format!("{t:?}").contains(&client_secret()));
}

#[test]
fn fixtures_parse_to_documented_shape() {
    assert!(fixture("query")["records"][0]["attributes"]["type"].is_string());
    assert_eq!(fixture("query")["done"], false);
    assert!(fixture("sobjects.list")["sobjects"][0]["name"].is_string());
    assert!(fixture("sobjects.describe")["fields"][0]["name"].is_string());
    assert!(fixture("records.get")["Id"].is_string());
    assert_eq!(fixture("records.create")["success"], true);
    assert_eq!(
        fixture("invalid_session")[0]["errorCode"],
        "INVALID_SESSION_ID"
    );
}

fn svc(text: &str) -> ServiceCfg {
    toml::from_str(&format!("connector = \"salesforce\"\n{text}")).unwrap()
}

fn verdict(s: &ServiceCfg, op_id: &str, call: &[(&str, &str)]) -> Verdict {
    let o = named(salesforce(), op_id).unwrap();
    let params = map(call);
    let mut cap = Capability::parse(&o.capability).unwrap();
    cap.qualifier = qualifier_for(o, &params);
    decide(
        s,
        None,
        Mode::Locked,
        &PolicyRequest {
            capability: &cap,
            params: &params,
        },
    )
}

fn default_deny() -> Verdict {
    Verdict::Deny {
        rule: "default_deny".into(),
    }
}

const ACC: (&str, &str) = ("sobject", "Account");
const REC: (&str, &str) = ("id", "001D000000IRFmaIAH");

#[test]
fn suggested_policies_keep_soql_and_writes_under_ask() {
    // The read-only policy of the docs page.
    let ro = svc(r#"allow = ["sobjects:read", "records:read"]
ask = ["query:read"]"#);
    assert_eq!(verdict(&ro, "records.get", &[ACC, REC]), Verdict::Allow);
    assert_eq!(verdict(&ro, "sobjects.list", &[]), Verdict::Allow);
    assert_eq!(
        verdict(&ro, "query", &[("q", "SELECT Id FROM User")]),
        Verdict::Ask
    );
    assert_eq!(
        verdict(&ro, "query.more", &[("locator", "01gD0000002HU6KIAW-2000")]),
        Verdict::Ask
    );
    for id in ["records.create", "records.update", "records.delete"] {
        assert_eq!(verdict(&ro, id, &[ACC, REC]), default_deny(), "{id}");
    }
    // Every write under ask.
    let ask = svc(r#"allow = ["sobjects:read", "records:read"]
ask = ["query:read", "records:write", "records:delete"]"#);
    for id in ["records.create", "records.update", "records.delete"] {
        assert_eq!(verdict(&ask, id, &[ACC, REC]), Verdict::Ask, "{id}");
    }
}

#[test]
fn sobject_qualifier_policy() {
    let s = svc(
        r#"allow = ["records:read:sobject=Account", "records:write:sobject=Case"]
deny = ["records:delete:sobject=Account"]
ask = ["records:delete"]"#,
    );
    assert_eq!(verdict(&s, "records.get", &[ACC, REC]), Verdict::Allow);
    // Allow compares case exactly: another spelling is not allowed.
    assert_eq!(
        verdict(&s, "records.get", &[("sobject", "account"), REC]),
        default_deny()
    );
    assert_eq!(
        verdict(&s, "records.get", &[("sobject", "Contact"), REC]),
        default_deny()
    );
    assert_eq!(
        verdict(&s, "records.create", &[("sobject", "Case")]),
        Verdict::Allow
    );
    assert_eq!(verdict(&s, "records.create", &[ACC]), default_deny());
    // Deny ignores case: Salesforce object names are case-insensitive.
    for name in ["Account", "account", "ACCOUNT"] {
        assert!(
            matches!(verdict(&s, "records.delete", &[("sobject", name), REC]), Verdict::Deny { ref rule } if rule.starts_with("deny:")),
            "{name}"
        );
    }
    assert_eq!(
        verdict(&s, "records.delete", &[("sobject", "Case"), REC]),
        Verdict::Ask
    );
    // A sobject-qualified allow never covers SOQL: query has no qualifier.
    assert_eq!(
        verdict(&s, "query", &[("q", "SELECT Id FROM Account")]),
        default_deny()
    );
}

// ---------------------------------------------------------------- loopback

#[derive(Default)]
struct State {
    /// Token POSTs: each form, raw.
    forms: Vec<String>,
    /// Host header of each token POST.
    token_hosts: Vec<String>,
    /// API requests: path and query, and the bearer.
    api: Vec<(String, String)>,
    /// Access tokens the API accepts.
    valid: BTreeSet<String>,
    /// Each refresh returns a new refresh token.
    rotate: bool,
    /// `instance_url` of the token response (none when empty).
    instance: String,
    /// The API answers 401 whatever the token.
    always_401: bool,
}

type Shared = Arc<Mutex<State>>;

struct Loopback(u16);

impl Resolver for Loopback {
    fn resolve(&self, host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
        if host.ends_with(".my.salesforce.com") {
            Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, self.0))])
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "unknown test host"))
        }
    }
}

fn form_field(form: &str, name: &str) -> String {
    form.split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{name}=")))
        .map(|v| {
            percent_encoding::percent_decode_str(v)
                .decode_utf8_lossy()
                .into_owned()
        })
        .unwrap_or_default()
}

async fn answer(req: Request<Incoming>, st: Shared) -> Result<Response<Full<Bytes>>, Infallible> {
    let (parts, body) = req.into_parts();
    let body = body
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let reply = |status: u16, b: String| {
        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(b)))
            .unwrap()
    };
    let mut s = st.lock().unwrap();
    if parts.uri.path() == "/services/oauth2/token" {
        let form = String::from_utf8_lossy(&body).into_owned();
        s.forms.push(form);
        s.token_hosts.push(
            parts
                .headers
                .get("host")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("")
                .to_string(),
        );
        let n = s.forms.len();
        let at = access(n);
        s.valid.insert(at.clone());
        // Shape per the refresh token flow docs.
        let mut o = json!({
            "access_token": at,
            "signature": "c2lnbmF0dXJl",
            "scope": "api refresh_token",
            "id": "https://login.salesforce.com/id/00D/005",
            "token_type": "Bearer",
            "issued_at": "1278448384422",
        });
        if !s.instance.is_empty() {
            o["instance_url"] = s.instance.clone().into();
        }
        if s.rotate {
            o["refresh_token"] = rotated(n).into();
        }
        return Ok(reply(200, o.to_string()));
    }
    let bearer = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
        .to_string();
    let pq = parts
        .uri
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_default();
    s.api.push((pq, bearer.clone()));
    if s.always_401 || !s.valid.contains(&bearer) {
        return Ok(reply(401, fixture("invalid_session").to_string()));
    }
    // The upstream echoes the token: the response must come back masked.
    let mut v = fixture("query");
    v["echo"] = bearer.into();
    Ok(reply(200, v.to_string()))
}

async fn mock(st: Shared) -> Upstream {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![HOST.to_string()])
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
    Upstream::with_roots(roots, Arc::new(Loopback(port)), Duration::from_secs(5))
}

/// A pipeline env with an in-memory vault entry (kind oauth2) and a token
/// cache. `oauth_token` refreshes as the daemon does: the broker's token
/// request to the admin host, the broker's response check, the rotated
/// refresh token stored before the access token is returned.
struct SfEnv<'a> {
    pools: Pools,
    up: &'a Upstream,
    vault: Mutex<BTreeMap<String, Zeroizing<String>>>,
    cache: tokio::sync::Mutex<Option<Zeroizing<String>>>,
}

impl<'a> SfEnv<'a> {
    fn new(up: &'a Upstream) -> Self {
        let vault = [
            ("client_id", client_id()),
            ("client_secret", client_secret()),
            ("refresh_token", initial_refresh()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), Zeroizing::new(v)))
        .collect();
        SfEnv {
            pools: Pools::new(),
            up,
            vault: Mutex::new(vault),
            cache: tokio::sync::Mutex::new(None),
        }
    }

    fn refresh_in_vault(&self) -> String {
        self.vault.lock().unwrap()["refresh_token"].to_string()
    }
}

impl Env for SfEnv<'_> {
    fn lockdown(&self) -> Option<Lockdown> {
        None
    }
    fn scope(&self, _user: &str) -> Result<Option<Scope>, PolicyError> {
        Ok(Some(Scope {
            name: "crm-agents".into(),
            users: vec!["agent".into()],
            projects: vec![],
            services: vec!["sf".into()],
            env: None,
        }))
    }
    fn secret(
        &self,
        _name: &str,
        _service: &str,
        auth: &[AuthSpec],
    ) -> Result<AuthMaterial, &'static str> {
        Ok(AuthMaterial::from_spec(
            &auth[0],
            self.vault.lock().unwrap().clone(),
        ))
    }
    fn secret_values(&self, _name: &str) -> Option<Vec<Zeroizing<String>>> {
        Some(self.vault.lock().unwrap().values().cloned().collect())
    }
    fn pool(&self, service: &str) -> Arc<Semaphore> {
        self.pools.get(service)
    }
    fn create_approval<'b>(&'b self, _p: &'b PendingCall) -> ApprovalFuture<'b> {
        Box::pin(async { Err("approvals_unavailable".to_string()) })
    }
    fn oauth_token<'b>(
        &'b self,
        _secret: &'b str,
        _service: &'b str,
        spec: &'b AuthSpec,
        m: &'b Manifest,
        svc_params: &'b BTreeMap<String, String>,
        force: bool,
    ) -> TokenFuture<'b> {
        Box::pin(async move {
            let mut cached = self.cache.lock().await;
            if !force {
                if let Some(t) = cached.as_ref() {
                    return Ok(t.clone());
                }
            }
            *cached = None;
            let fields = self.vault.lock().unwrap().clone();
            let built = oauth2::token_request(spec, m, svc_params, &fields)
                .map_err(|_| "policy_invalid")?;
            let host = built.uri.host().unwrap_or_default().to_string();
            let resp = self
                .up
                .send(built, oauth2::MAX_RESPONSE)
                .await
                .map_err(|_| "refresh_failed")?;
            if resp.status != 200 {
                return Err("refresh_failed");
            }
            let tok = oauth2::parse_token(&resp.body, &host, oauth2::instance_required(m))
                .map_err(|_| "refresh_failed")?;
            if let Some(r) = tok.refresh {
                self.vault.lock().unwrap().insert("refresh_token".into(), r);
            }
            *cached = Some(tok.access.clone());
            Ok(tok.access)
        })
    }
}

fn snapshot() -> PolicySnapshot {
    let config = toml::from_str(&format!(
        r#"version = 2
locked = true
[services.sf]
connector = "salesforce"
secret = "sf-oauth"
params = {{ instance_host = "{HOST}", api_version = "v60.0" }}
allow = ["query:read", "sobjects:read", "records:read"]
"#
    ))
    .unwrap();
    PolicySnapshot {
        config,
        hash: "sha256:test".into(),
        mode: Mode::Locked,
        env: None,
    }
}

fn call(op: &str, params: &[(&str, &str)]) -> Call {
    Call {
        uid: 1001,
        user: "agent".into(),
        session: Some("sess-1".into()),
        project: "/srv/crm".into(),
        service: "sf".into(),
        op: OpRef::Named(op.into()),
        params: params
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        body: None,
        headers: vec![("Authorization".into(), "Bearer agent-guess".into())],
        overlay: None,
        via: Via::Cli,
        collection: None,
    }
}

/// The outcome, and everything printable about the call: its audit record,
/// the outcome (with the masked response body) and the call's `Debug`.
async fn go_live(c: &Call, env: &SfEnv<'_>, up: &Upstream) -> (Outcome, String) {
    let snap = snapshot();
    let cat = Catalog::new(builtin(), Vec::new());
    let (o, tr) = run(c, &snap, &cat, &Limiter::new(), env, Some(up)).await;
    let body = match &o {
        Outcome::Done { finished, .. } => String::from_utf8_lossy(&finished.body).into_owned(),
        _ => String::new(),
    };
    let out = format!(
        "{}\n{o:?}\n{c:?}\n{body}",
        serde_json::to_string(&record(c, &snap, &tr, &o, "", "0.2.0")).unwrap()
    );
    (o, out)
}

fn status(o: &Outcome) -> u16 {
    match o {
        Outcome::Done { finished, .. } => finished.status,
        other => panic!("expected done, got {other:?}"),
    }
}

/// Every secret value the test used, including the issued tokens.
fn secrets(issued: usize) -> Vec<String> {
    let mut v = vec![client_secret(), initial_refresh()];
    for n in 1..=issued {
        v.push(access(n));
        v.push(rotated(n));
    }
    v
}

fn assert_no_secret(printed: &str, issued: usize) {
    for needle in secrets(issued) {
        assert!(!printed.contains(&needle), "leaked {needle}");
    }
}

#[tokio::test]
async fn end_to_end_with_token_refresh() {
    let st: Shared = Arc::new(Mutex::new(State {
        rotate: true,
        instance: format!("https://{HOST}"),
        ..State::default()
    }));
    let up = mock(st.clone()).await;
    let env = SfEnv::new(&up);
    let mut printed = String::new();

    // Cold: one refresh, then the API with the new access token.
    let (o, out) = go_live(
        &call("query", &[("q", "SELECT Id, Name FROM Account")]),
        &env,
        &up,
    )
    .await;
    assert_eq!(status(&o), 200, "{out}");
    printed.push_str(&out);
    {
        let s = st.lock().unwrap();
        assert_eq!(s.forms.len(), 1);
        assert_eq!(s.token_hosts, [HOST]);
        let f = &s.forms[0];
        assert_eq!(form_field(f, "grant_type"), "refresh_token");
        assert_eq!(form_field(f, "client_id"), client_id());
        assert_eq!(form_field(f, "client_secret"), client_secret());
        assert_eq!(form_field(f, "refresh_token"), initial_refresh());
        assert_eq!(s.api.len(), 1);
        assert!(
            s.api[0].0.starts_with("/services/data/v60.0/query?q="),
            "{:?}",
            s.api
        );
        assert_eq!(s.api[0].1, access(1));
    }
    // The rotated refresh token is in the vault.
    assert_eq!(env.refresh_in_vault(), rotated(1));
    // The response echoed the access token: masked.
    assert!(out.contains("Edge Communications"), "{out}");
    assert!(!out.contains(&access(1)));

    // Warm: the cached access token, no second refresh.
    let (o, out) = go_live(
        &call(
            "records.get",
            &[("sobject", "Account"), ("id", "001D000000IRFmaIAH")],
        ),
        &env,
        &up,
    )
    .await;
    assert_eq!(status(&o), 200, "{out}");
    printed.push_str(&out);
    {
        let s = st.lock().unwrap();
        assert_eq!(s.forms.len(), 1);
        assert_eq!(
            s.api[1].0,
            "/services/data/v60.0/sobjects/Account/001D000000IRFmaIAH"
        );
        assert_eq!(s.api[1].1, access(1));
    }
    // The follow-up page.
    let (o, out) = go_live(
        &call("query.more", &[("locator", "01gD0000002HU6KIAW-2000")]),
        &env,
        &up,
    )
    .await;
    assert_eq!(status(&o), 200, "{out}");
    printed.push_str(&out);
    assert_eq!(
        st.lock().unwrap().api[2].0,
        "/services/data/v60.0/query/01gD0000002HU6KIAW-2000"
    );

    // The agent's guess never reached the upstream.
    assert!(st
        .lock()
        .unwrap()
        .api
        .iter()
        .all(|(_, b)| b != "agent-guess"));
    assert!(!printed.contains("auth_retry"));
    assert_no_secret(&printed, 1);
}

#[tokio::test]
async fn session_expired_401_retry() {
    let st: Shared = Arc::new(Mutex::new(State {
        rotate: true,
        instance: format!("https://{HOST}"),
        ..State::default()
    }));
    let up = mock(st.clone()).await;
    let env = SfEnv::new(&up);
    let mut printed = String::new();
    let q = call("query", &[("q", "SELECT Id FROM Contact")]);

    let (o, out) = go_live(&q, &env, &up).await;
    assert_eq!(status(&o), 200, "{out}");
    printed.push_str(&out);

    // The session expires upstream (INVALID_SESSION_ID): one forced refresh
    // with the rotated refresh token, one resend, and the record says so.
    st.lock().unwrap().valid.clear();
    let (o, out) = go_live(&q, &env, &up).await;
    assert_eq!(status(&o), 200, "{out}");
    assert!(out.contains("\"auth_retry\":true"), "{out}");
    printed.push_str(&out);
    {
        let s = st.lock().unwrap();
        assert_eq!(s.forms.len(), 2);
        assert_eq!(form_field(&s.forms[1], "refresh_token"), rotated(1));
        let bearers: Vec<&str> = s.api.iter().map(|(_, b)| b.as_str()).collect();
        let (a1, a2) = (access(1), access(2));
        assert_eq!(bearers, [a1.as_str(), a1.as_str(), a2.as_str()]);
    }
    assert_eq!(env.refresh_in_vault(), rotated(2));

    // Revoked for good: the refresh works but the API still says 401. The
    // second 401 is the answer (exit 1); there is no third send.
    st.lock().unwrap().always_401 = true;
    let (o, out) = go_live(&q, &env, &up).await;
    assert_eq!(status(&o), 401, "{out}");
    assert!(out.contains("INVALID_SESSION_ID"), "{out}");
    printed.push_str(&out);
    {
        let s = st.lock().unwrap();
        assert_eq!(s.forms.len(), 3);
        assert_eq!(s.api.len(), 5);
    }
    assert_no_secret(&printed, 3);
}

#[tokio::test]
async fn token_response_for_another_instance_is_refused() {
    for instance in [
        "https://evil.my.salesforce.com".to_string(),
        format!("http://{HOST}"),
        format!("https://x@{HOST}"),
        String::new(), // instance_url is required for this connector
    ] {
        let st: Shared = Arc::new(Mutex::new(State {
            instance: instance.clone(),
            ..State::default()
        }));
        let up = mock(st.clone()).await;
        let env = SfEnv::new(&up);
        let (o, out) = go_live(&call("sobjects.list", &[]), &env, &up).await;
        assert!(
            matches!(&o, Outcome::Denied { rule } if rule == "refresh_failed"),
            "{instance:?}: {o:?}"
        );
        assert!(st.lock().unwrap().api.is_empty(), "{instance:?}");
        assert_no_secret(&out, 1);
    }
}
