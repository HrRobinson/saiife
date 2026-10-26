//! Shopify Admin API connector (plan 10, Task 12): the built-in manifest,
//! golden requests, fixture parses, pagination, policy and amounts. Offline.
//! Fixtures are in Shopify's documented shape (see each `_source`); they were
//! written without internet access ("shape per vendor docs; not fetched").

use bytes::Bytes;
use saiife_broker::amount::{exponent, extract};
use saiife_broker::manifest::{builtin, Manifest, OpKind, Pagination, Unit};
use saiife_broker::params::validate;
use saiife_broker::request::{build, AuthMaterial, Built};
use saiife_broker::resolve::named;
use saiife_policy::{decide, Capability, Mode, Request, ServiceCfg, Verdict};
use serde_json::Value;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

const TOKEN: &str = "shpat_SECRET123";

fn shopify() -> &'static Manifest {
    builtin()
        .iter()
        .find(|m| m.id == "shopify")
        .expect("shopify is a built-in manifest")
}

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn fixture(name: &str) -> Value {
    let path = format!(
        "{}/tests/fixtures/shopify/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn go(op_id: &str, params: &[(&str, &str)], headers: &[(&str, &str)], body: Option<&str>) -> Built {
    let m = shopify();
    let op = named(m, op_id).unwrap_or_else(|| panic!("no operation {op_id}"));
    let params = validate(op, &map(params), &BTreeMap::new()).unwrap();
    let auth = AuthMaterial::from_spec(
        &m.auth[0],
        BTreeMap::from([("token".to_string(), Zeroizing::new(TOKEN.to_string()))]),
    );
    let headers: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    build(
        m,
        op,
        &map(&[("shop", "acme")]),
        &params,
        &headers,
        body.map(|b| Bytes::from(b.to_string())),
        &auth,
    )
    .unwrap()
}

/// `METHOD URI`, then `name: value` per header, sorted; the token is shown
/// as `<AUTH>` after checking it is the vault value.
fn render(b: &Built) -> String {
    let mut lines: Vec<String> = b
        .headers
        .iter()
        .map(|(k, v)| {
            let v = v.to_str().unwrap();
            let v = if v == TOKEN { "<AUTH>" } else { v };
            format!("{}: {v}", k.as_str())
        })
        .collect();
    lines.sort();
    let mut out = format!("{} {}\n", b.method, b.uri);
    for l in lines {
        out.push_str(&l);
        out.push('\n');
    }
    out
}

const BASE: &str = "https://acme.myshopify.com/admin/api/2026-07";
const AUTH: &str = "x-shopify-access-token: <AUTH>\n";
const ACCEPT: &str = "accept: application/json\n";

#[test]
fn every_builtin_manifest_loads() {
    let ids: Vec<&str> = builtin().iter().map(|m| m.id.as_str()).collect();
    assert!(ids.contains(&"shopify"), "{ids:?}");
    let m = shopify();
    assert_eq!(m.hosts, ["*.myshopify.com"]);
    assert_eq!(m.base_url, BASE.replace("acme", "{shop}"));
    assert_eq!(
        m.request_headers,
        ["Content-Type", "Accept", "Idempotency-Key"]
    );
    let ops: Vec<&str> = m.operation.iter().map(|o| o.id.as_str()).collect();
    assert_eq!(
        ops,
        [
            "orders.list",
            "orders.get",
            "products.list",
            "products.get",
            "products.update",
            "customers.list",
            "customers.export",
            "refunds.create",
            "discounts.create"
        ]
    );
}

#[test]
fn capabilities_and_kinds() {
    let m = shopify();
    let want = [
        ("orders.list", "orders:read", OpKind::Read),
        ("orders.get", "orders:read", OpKind::Read),
        ("products.list", "products:read", OpKind::Read),
        ("products.get", "products:read", OpKind::Read),
        ("products.update", "products:write", OpKind::Write),
        ("customers.list", "customers:read", OpKind::Read),
        ("customers.export", "customers:export", OpKind::Bulk),
        ("refunds.create", "refunds:write", OpKind::Write),
        ("discounts.create", "discounts:write", OpKind::Write),
    ];
    for (id, cap, kind) in want {
        let op = named(m, id).unwrap();
        assert_eq!((op.capability.as_str(), op.kind), (cap, kind), "{id}");
    }
}

#[test]
fn golden_orders_list() {
    let b = go(
        "orders.list",
        &[("status", "open"), ("limit", "50")],
        &[
            ("Accept", "application/json"),
            ("X-Not-Listed", "1"),
            ("Authorization", "Bearer agent"),
            ("X-Shopify-Access-Token", "agent-guess"),
        ],
        None,
    );
    assert_eq!(
        render(&b),
        format!("GET {BASE}/orders.json?limit=50&status=open\n{ACCEPT}{AUTH}")
    );
    assert!(b.body.is_none());
}

#[test]
fn golden_gets() {
    let cases = [
        (
            "orders.get",
            "order_id",
            "450789469",
            "orders/450789469.json",
        ),
        (
            "products.get",
            "product_id",
            "632910392",
            "products/632910392.json",
        ),
    ];
    for (op, name, id, path) in cases {
        let b = go(op, &[(name, id)], &[("Accept", "application/json")], None);
        assert_eq!(render(&b), format!("GET {BASE}/{path}\n{ACCEPT}{AUTH}"));
    }
}

#[test]
fn golden_lists_and_export() {
    let b = go(
        "products.list",
        &[("status", "active"), ("limit", "1")],
        &[],
        None,
    );
    assert_eq!(
        render(&b),
        format!("GET {BASE}/products.json?limit=1&status=active\n{AUTH}")
    );
    let b = go("customers.list", &[("limit", "50")], &[], None);
    assert_eq!(
        render(&b),
        format!("GET {BASE}/customers.json?limit=50\n{AUTH}")
    );
    let b = go(
        "customers.export",
        &[("query", "country:DK"), ("limit", "250")],
        &[],
        None,
    );
    assert_eq!(
        render(&b),
        format!("GET {BASE}/customers/search.json?limit=250&query=country%3ADK\n{AUTH}")
    );
}

#[test]
fn list_limits_are_enforced() {
    let m = shopify();
    for (op, limit) in [("orders.list", "251"), ("customers.list", "251")] {
        let op = named(m, op).unwrap();
        assert!(validate(op, &map(&[("limit", limit)]), &BTreeMap::new()).is_err());
    }
    let op = named(m, "orders.list").unwrap();
    assert!(validate(op, &map(&[("status", "bogus")]), &BTreeMap::new()).is_err());
    assert!(validate(
        op,
        &map(&[("created_at_min", "yesterday")]),
        &BTreeMap::new()
    )
    .is_err());
}

#[test]
fn golden_writes() {
    let hdr = [
        ("Content-Type", "application/json"),
        ("Idempotency-Key", "k-1"),
    ];
    let body = r#"{"product":{"id":632910392,"title":"New product title"}}"#;
    let b = go(
        "products.update",
        &[("product_id", "632910392")],
        &hdr,
        Some(body),
    );
    assert_eq!(
        render(&b),
        format!(
            "PUT {BASE}/products/632910392.json\ncontent-type: application/json\nidempotency-key: k-1\n{AUTH}"
        )
    );
    assert_eq!(b.body.as_deref(), Some(body.as_bytes()));

    let b = go(
        "refunds.create",
        &[("order_id", "450789469")],
        &hdr,
        Some("{}"),
    );
    assert_eq!(
        render(&b),
        format!(
            "POST {BASE}/orders/450789469/refunds.json\ncontent-type: application/json\nidempotency-key: k-1\n{AUTH}"
        )
    );

    let b = go("discounts.create", &[], &hdr, Some("{}"));
    assert_eq!(
        render(&b),
        format!(
            "POST {BASE}/price_rules.json\ncontent-type: application/json\nidempotency-key: k-1\n{AUTH}"
        )
    );
}

#[test]
fn free_string_params_are_constrained() {
    let m = shopify();
    let check = |op: &str, k: &str, v: &str| {
        validate(named(m, op).unwrap(), &map(&[(k, v)]), &BTreeMap::new())
    };
    // Cursor smuggling is refused; a plain cursor is fine.
    let long = "a".repeat(513);
    for bad in [
        "abc&limit=250",
        "abc%26fields%3Dx",
        "abc=",
        "a b",
        "",
        &long,
    ] {
        assert!(check("orders.list", "page_info", bad).is_err(), "{bad:?}");
    }
    assert!(check("orders.list", "page_info", "eyJsYXN0X2lkIjo0NTA3ODk0NjkyfQ").is_ok());
    assert!(check("customers.export", "order", "orders_count desc").is_ok());
    for bad in [
        "orders_count",
        "orders_count DESC",
        "x asc,y desc",
        "a asc&b=1",
    ] {
        assert!(check("customers.export", "order", bad).is_err(), "{bad:?}");
    }
    assert!(check("customers.export", "query", "").is_err());
    assert!(check("customers.export", "query", &"q".repeat(257)).is_err());
    // A legitimate value with `&` is accepted and percent-encoded.
    let b = go("customers.export", &[("query", "name:a&b=c")], &[], None);
    assert_eq!(b.uri.query().unwrap(), "query=name%3Aa%26b%3Dc");
}

#[test]
fn path_ids_must_be_integers() {
    let op = named(shopify(), "orders.get").unwrap();
    for bad in ["1/2", "..", "12 34", "abc", ""] {
        assert!(
            validate(op, &map(&[("order_id", bad)]), &BTreeMap::new()).is_err(),
            "{bad:?}"
        );
    }
    assert!(validate(op, &BTreeMap::new(), &BTreeMap::new()).is_err());
}

#[test]
fn fixtures_parse_to_documented_shape() {
    let cases = [
        ("orders.list", "orders", true),
        ("orders.get", "order", false),
        ("products.list", "products", true),
        ("products.get", "product", false),
        ("products.update", "product", false),
        ("customers.list", "customers", true),
        ("customers.export", "customers", true),
        ("refunds.create", "refund", false),
        ("discounts.create", "price_rule", false),
    ];
    for (name, key, is_list) in cases {
        let v = fixture(name);
        let src = v["_source"].as_str().unwrap();
        assert!(
            src.starts_with("https://shopify.dev/docs/api/admin-rest/2026-07/"),
            "{name}"
        );
        assert!(src.contains("not fetched"), "{name}");
        let data = &v[key];
        assert!(data.is_array() == is_list && !data.is_null(), "{name}");
        let first = if is_list { &data[0] } else { data };
        assert!(first["id"].is_u64(), "{name}");
    }
    assert_eq!(fixture("orders.list")["orders"][0]["name"], "#1001");
}

/// The `page_info` value of the `rel="next"` entry of a `Link` header.
fn next_page_info(link: &str) -> Option<String> {
    link.split(',').find_map(|part| {
        let (url, rel) = part.split_once(';')?;
        if !rel.contains("rel=\"next\"") {
            return None;
        }
        let url = url.trim().trim_start_matches('<').trim_end_matches('>');
        let q = url.split_once('?')?.1;
        q.split('&')
            .find_map(|kv| kv.strip_prefix("page_info=").map(str::to_string))
    })
}

// TODO(Task 9): replace `next_page_info` with the pipeline's real `next`
// extraction from the Link header once it exists.
#[test]
fn pagination_next() {
    let m = shopify();
    for id in [
        "orders.list",
        "products.list",
        "customers.list",
        "customers.export",
    ] {
        let op = named(m, id).unwrap();
        assert_eq!(op.pagination, Some(Pagination::LinkHeader), "{id}");
        assert!(op.query.contains_key("page_info"), "{id}");
        let link = fixture(id)["_link"].as_str().unwrap().to_string();
        let next = next_page_info(&link).unwrap_or_else(|| panic!("{id}: no next in {link}"));
        // The next page's params are accepted and reach the upstream URL.
        let b = go(id, &[("limit", "2"), ("page_info", &next)], &[], None);
        assert!(
            b.uri
                .query()
                .unwrap()
                .contains(&format!("page_info={next}")),
            "{id}: {}",
            b.uri
        );
    }
    for id in ["orders.get", "products.get", "refunds.create"] {
        assert_eq!(named(m, id).unwrap().pagination, None, "{id}");
    }
}

fn svc(text: &str) -> ServiceCfg {
    toml::from_str(&format!("connector = \"shopify\"\n{text}")).unwrap()
}

fn verdict(s: &ServiceCfg, op_id: &str) -> Verdict {
    let cap = Capability::parse(&named(shopify(), op_id).unwrap().capability).unwrap();
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

const WRITES: [&str; 3] = ["products.update", "refunds.create", "discounts.create"];

#[test]
fn writes_are_denied_by_default() {
    // Even with every read allowed, a write is a default deny.
    let s = svc(r#"allow = ["orders:read", "products:read", "customers:read"]"#);
    for id in WRITES {
        assert_eq!(
            verdict(&s, id),
            Verdict::Deny {
                rule: "default_deny".into()
            },
            "{id}"
        );
    }
    assert_eq!(verdict(&s, "orders.get"), Verdict::Allow);
    // The bulk export needs its own grant.
    assert!(matches!(
        verdict(&s, "customers.export"),
        Verdict::Deny { .. }
    ));
}

#[test]
fn writes_are_allowed_by_policy() {
    let s = svc(r#"allow = ["products:write", "refunds:write", "discounts:write"]"#);
    for id in WRITES {
        assert_eq!(verdict(&s, id), Verdict::Allow, "{id}");
    }
    let ask = svc(r#"ask = ["products:write", "refunds:write", "discounts:write"]"#);
    for id in WRITES {
        assert_eq!(verdict(&ask, id), Verdict::Ask, "{id}");
    }
    let deny = svc(r#"allow = ["*:write"]
deny = ["customers:export"]"#);
    assert!(matches!(
        verdict(&deny, "customers.export"),
        Verdict::Deny { .. }
    ));
}

#[test]
fn refund_amount_is_extracted_from_the_documented_body() {
    let m = shopify();
    let spec = named(m, "refunds.create").unwrap().amount.clone().unwrap();
    assert_eq!(spec.unit, Unit::Major);
    // Two transactions in EUR: 41.94 + 10.00.
    let body = &fixture("refunds.create")["_request"];
    assert_eq!(extract(&spec, body).unwrap(), (5194, "EUR".to_string()));
    // Other operations carry no amount spec.
    for id in ["products.update", "discounts.create"] {
        assert!(named(m, id).unwrap().amount.is_none(), "{id}");
    }
}

#[test]
fn refund_amount_cap_arithmetic() {
    // The daily cap of the spec example: 500 EUR, in major units.
    let spec = named(shopify(), "refunds.create")
        .unwrap()
        .amount
        .clone()
        .unwrap();
    let cap_minor = 500 * 10u64.pow(exponent("EUR").unwrap());
    let refund = |amount: &str| -> u64 {
        let body = serde_json::json!({"refund": {"currency": "EUR",
            "transactions": [{"amount": amount, "kind": "refund"}]}});
        extract(&spec, &body).unwrap().0
    };
    assert!(refund("499.99") <= cap_minor);
    assert!(refund("500.00") <= cap_minor);
    assert!(refund("500.01") > cap_minor);
    // Two transactions add up.
    let body = serde_json::json!({"refund": {"currency": "eur", "transactions": [
        {"amount": "300.00"}, {"amount": "250.00"}]}});
    let (total, cur) = extract(&spec, &body).unwrap();
    assert_eq!((total, cur.as_str()), (55000, "EUR"));
    assert!(total > cap_minor);
}

#[test]
fn refund_without_amount_or_currency_is_an_error() {
    let spec = named(shopify(), "refunds.create")
        .unwrap()
        .amount
        .clone()
        .unwrap();
    for body in [
        serde_json::json!({"refund": {"currency": "EUR"}}),
        serde_json::json!({"refund": {"transactions": [{"amount": "1.00"}]}}),
        serde_json::json!({"refund": {"currency": "EUR", "transactions": [{"amount": "x"}]}}),
        serde_json::json!({}),
    ] {
        assert!(extract(&spec, &body).is_err(), "{body}");
    }
}
