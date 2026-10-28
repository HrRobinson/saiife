//! Zendesk Support connector (plan 14, Task 11): manifest, golden requests,
//! fixtures, cursor pagination and the policy outcomes of the suggested
//! policies (docs/connectors/zendesk.md). Offline: no sockets, fixtures are
//! shaped per the vendor docs.

use base64::Engine as _;
use bytes::Bytes;
use saiife_broker::manifest::{builtin, Manifest, OpKind, Pagination};
use saiife_broker::params::validate;
use saiife_broker::request::{build, next_cursor, AuthMaterial, Built};
use saiife_broker::resolve::{named, proxy};
use saiife_broker::BrokerError;
use saiife_policy::{decide, Capability, Mode, Request, ServiceCfg, Verdict};
use serde_json::Value;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

// Built at runtime: no token-shaped literal in the source.
fn user() -> String {
    format!("agent@acme.test{}", "/token")
}
fn pass() -> String {
    ["zd", "api", "pw", "7731"].join("_")
}

fn zendesk() -> &'static Manifest {
    builtin()
        .iter()
        .find(|m| m.id == "zendesk")
        .expect("zendesk is a built-in manifest")
}

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn fixture(name: &str) -> Value {
    let path = format!(
        "{}/tests/fixtures/zendesk/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn material() -> AuthMaterial {
    AuthMaterial::from_spec(
        &zendesk().auth[0],
        BTreeMap::from([
            ("username".to_string(), Zeroizing::new(user())),
            ("password".to_string(), Zeroizing::new(pass())),
        ]),
    )
}

fn try_go(
    op_id: &str,
    svc: &[(&str, &str)],
    params: &[(&str, &str)],
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> Result<Built, BrokerError> {
    let m = zendesk();
    let op = named(m, op_id).unwrap_or_else(|| panic!("no operation {op_id}"));
    let params = validate(op, &map(params), &BTreeMap::new())?;
    let headers: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    build(
        m,
        op,
        &map(svc),
        &params,
        &headers,
        body.map(|b| Bytes::from(b.to_string())),
        &material(),
    )
}

fn go(op_id: &str, params: &[(&str, &str)], headers: &[(&str, &str)], body: Option<&str>) -> Built {
    try_go(op_id, &[("subdomain", "acme")], params, headers, body).unwrap()
}

fn basic() -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", user(), pass()))
    )
}

const BASE: &str = "https://acme.zendesk.com/api/v2";

#[test]
fn manifest_shape() {
    let m = zendesk();
    assert_eq!(m.hosts, ["*.zendesk.com"]);
    assert_eq!(m.base_url, "https://{subdomain}.zendesk.com/api/v2");
    assert_eq!(m.auth.len(), 1);
    assert_eq!(m.auth[0].kind, "basic");
    let want = [
        ("tickets.list", "tickets:read", OpKind::Read),
        ("tickets.get", "tickets:read", OpKind::Read),
        ("tickets.comments", "tickets:read", OpKind::Read),
        ("tickets.create", "tickets:write", OpKind::Write),
        ("tickets.update", "tickets:write", OpKind::Write),
        ("users.get", "users:read", OpKind::Read),
        ("search", "search:read", OpKind::Read),
    ];
    let ids: Vec<&str> = m.operation.iter().map(|o| o.id.as_str()).collect();
    assert_eq!(ids, want.map(|w| w.0));
    for (id, cap, kind) in want {
        let op = named(m, id).unwrap();
        assert_eq!((op.capability.as_str(), op.kind), (cap, kind), "{id}");
        assert!(op.amount.is_none(), "{id}");
    }
}

#[test]
fn golden_requests_carry_basic_auth() {
    let b = go(
        "tickets.get",
        &[("ticket_id", "35436")],
        &[
            ("Accept", "application/json"),
            ("Authorization", "Bearer agent-guess"),
            ("X-Not-Listed", "1"),
        ],
        None,
    );
    assert_eq!(b.method, "GET");
    assert_eq!(b.uri.to_string(), format!("{BASE}/tickets/35436"));
    assert_eq!(b.headers.get("authorization").unwrap(), &basic());
    assert_eq!(b.headers.get("accept").unwrap(), "application/json");
    assert!(b.headers.get("x-not-listed").is_none());
    assert!(b.body.is_none());

    let b = go(
        "tickets.list",
        &[("page[size]", "2"), ("sort", "-updated_at")],
        &[],
        None,
    );
    assert_eq!(b.uri.path(), "/api/v2/tickets");
    let q = b.uri.query().unwrap();
    assert!(q.contains("sort=-updated_at"), "{q}");
    assert!(
        q.contains("page%5Bsize%5D=2") || q.contains("page[size]=2"),
        "{q}"
    );

    let b = go("tickets.comments", &[("ticket_id", "9")], &[], None);
    assert_eq!(b.uri.path(), "/api/v2/tickets/9/comments");
    let b = go("users.get", &[("user_id", "20978392")], &[], None);
    assert_eq!(b.uri.path(), "/api/v2/users/20978392");
    let b = go(
        "search",
        &[("query", "type:ticket status:open"), ("per_page", "50")],
        &[],
        None,
    );
    assert_eq!(b.uri.path(), "/api/v2/search.json");
    assert!(b.uri.query().unwrap().contains("per_page=50"));
}

#[test]
fn golden_writes() {
    let body = fixture("tickets.create")["_request"].to_string();
    let b = go(
        "tickets.create",
        &[],
        &[("Content-Type", "application/json")],
        Some(&body),
    );
    assert_eq!(b.method, "POST");
    assert_eq!(b.uri.to_string(), format!("{BASE}/tickets"));
    assert_eq!(b.body.as_deref(), Some(body.as_bytes()));
    assert_eq!(b.headers.get("content-type").unwrap(), "application/json");
    let b = go(
        "tickets.update",
        &[("ticket_id", "35436")],
        &[],
        Some(r#"{"ticket":{"status":"solved"}}"#),
    );
    assert_eq!(b.method, "PUT");
    assert_eq!(b.uri.path(), "/api/v2/tickets/35436");
}

#[test]
fn subdomain_cannot_leave_the_zendesk_host() {
    // The service param is admin-set, but a wrong one still never forms a URL
    // outside *.zendesk.com.
    for bad in [
        "acme.evil.test/x",
        "acme@evil.test",
        "evil.test#",
        "ACME",
        "acme.evil",
        "",
    ] {
        let r = try_go(
            "tickets.get",
            &[("subdomain", bad)],
            &[("ticket_id", "1")],
            &[],
            None,
        );
        // A pattern failure is a policy error before this point; the builder
        // either refuses the value or produces a *.zendesk.com host.
        match r {
            Err(_) => {}
            Ok(b) => {
                let host = b.uri.host().unwrap_or("").to_string();
                assert!(host.ends_with(".zendesk.com"), "{bad:?} -> {host}");
                assert!(!host.contains("evil"), "{bad:?} -> {host}");
            }
        }
    }
    // The missing param is an error.
    assert!(try_go("tickets.get", &[], &[("ticket_id", "1")], &[], None).is_err());
}

#[test]
fn path_ids_and_cursor_values_are_constrained() {
    for bad in ["1/../2", "abc", "1?x=2", ""] {
        let m = zendesk();
        let op = named(m, "tickets.get").unwrap();
        assert!(
            validate(op, &map(&[("ticket_id", bad)]), &BTreeMap::new()).is_err(),
            "{bad:?}"
        );
    }
    let op = named(zendesk(), "tickets.list").unwrap();
    for bad in ["a&page[size]=1", "x y", "a/b", ""] {
        assert!(
            validate(op, &map(&[("page[after]", bad)]), &BTreeMap::new()).is_err(),
            "{bad:?}"
        );
    }
    assert!(validate(op, &map(&[("page[size]", "101")]), &BTreeMap::new()).is_err());
}

#[test]
fn no_proxy_route_for_unlisted_paths() {
    let m = zendesk();
    // Paths outside the manifest are unknown operations on the proxy path.
    assert!(proxy(m, "DELETE", "/tickets/1").is_err());
    assert!(proxy(m, "POST", "/users").is_err());
    assert!(proxy(m, "GET", "/tickets/1").is_ok());
}

#[test]
fn fixtures_parse_to_documented_shape() {
    assert!(fixture("tickets.list")["tickets"][0]["id"].is_u64());
    assert!(fixture("tickets.get")["ticket"]["id"].is_u64());
    assert!(fixture("tickets.comments")["comments"][0]["body"].is_string());
    assert!(fixture("users.get")["user"]["email"].is_string());
    assert!(fixture("search")["results"][0]["result_type"].is_string());
    assert!(fixture("tickets.create")["_request"]["ticket"]["subject"].is_string());
}

#[test]
fn cursor_pagination() {
    let m = zendesk();
    for id in ["tickets.list", "tickets.comments"] {
        let op = named(m, id).unwrap();
        let Some(p @ Pagination::Cursor { param, next, more }) = &op.pagination else {
            panic!("{id}: {:?}", op.pagination)
        };
        assert_eq!(param, "page[after]");
        assert_eq!(next, "meta.after_cursor");
        assert_eq!(more.as_deref(), Some("meta.has_more"));
        assert!(op.query.contains_key("page[after]"));
        // A page with more: the cursor comes back as the next param, and the
        // cursor is accepted as the next call's param.
        let (k, v) = next_cursor(p, &fixture("tickets.list")).expect("next page");
        assert_eq!(k, "page[after]");
        assert_eq!(v, "eyJvIjoibmljZV9pZCIsInYiOiJhUUVBQUFBQUFBQUEifQ==");
        let mut next = map(&[(k.as_str(), v.as_str())]);
        if id == "tickets.comments" {
            next.insert("ticket_id".into(), "1".into());
        }
        validate(op, &next, &BTreeMap::new()).unwrap();
        // The last page has an after_cursor too, but has_more is false.
        assert_eq!(next_cursor(p, &fixture("tickets.list_last")), None);
    }
    assert_eq!(named(m, "tickets.get").unwrap().pagination, None);
    assert_eq!(named(m, "search").unwrap().pagination, None);
}

fn svc(text: &str) -> ServiceCfg {
    toml::from_str(&format!("connector = \"zendesk\"\n{text}")).unwrap()
}

fn verdict(s: &ServiceCfg, op_id: &str) -> Verdict {
    let cap = Capability::parse(&named(zendesk(), op_id).unwrap().capability).unwrap();
    let params = BTreeMap::new();
    decide(
        s,
        None,
        Mode::Locked,
        &Request {
            capability: &cap,
            params: &params,
        },
    )
}

#[test]
fn read_only_policy_denies_writes() {
    let s = svc(r#"allow = ["tickets:read", "users:read", "search:read"]"#);
    for id in [
        "tickets.list",
        "tickets.get",
        "tickets.comments",
        "users.get",
        "search",
    ] {
        assert_eq!(verdict(&s, id), Verdict::Allow, "{id}");
    }
    for id in ["tickets.create", "tickets.update"] {
        assert_eq!(
            verdict(&s, id),
            Verdict::Deny {
                rule: "default_deny".into()
            },
            "{id}"
        );
    }
}

#[test]
fn ask_policy_asks_for_writes() {
    let s = svc(r#"allow = ["tickets:read", "users:read", "search:read"]
ask = ["tickets:write"]"#);
    for id in ["tickets.create", "tickets.update"] {
        assert_eq!(verdict(&s, id), Verdict::Ask, "{id}");
    }
    assert_eq!(verdict(&s, "tickets.get"), Verdict::Allow);
}

#[test]
fn secret_values_stay_out_of_debug_output() {
    let dbg = format!("{:?}", material());
    assert!(!dbg.contains(&pass()), "{dbg}");
    assert!(!dbg.contains(&user()), "{dbg}");
}
