//! WooCommerce connector (plan 14, Task 11): manifest, golden requests with
//! basic auth, the admin host and currency params, Link pagination, fixtures,
//! refund amounts and the policy outcomes (docs/connectors/woocommerce.md).
//! Offline: no sockets, fixtures are shaped per the vendor docs.

use base64::Engine as _;
use bytes::Bytes;
use http::HeaderMap;
use saiife_broker::amount::extract;
use saiife_broker::manifest::{builtin, Manifest, OpKind, Pagination, Unit};
use saiife_broker::params::validate;
use saiife_broker::request::{build, next_from_link, AuthMaterial, Built};
use saiife_broker::resolve::named;
use saiife_broker::{catalog, BrokerError, Catalog};
use saiife_policy::{decide, Capability, Mode, Request, ServiceCfg, SystemConfig, Verdict};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

// Built at runtime: no key-shaped literal in the source.
fn ck() -> String {
    ["ck", "consumer", "3a9f"].join("_")
}
fn cs() -> String {
    ["cs", "secret", "81bd"].join("_")
}

fn woo() -> &'static Manifest {
    builtin()
        .iter()
        .find(|m| m.id == "woocommerce")
        .expect("woocommerce is a built-in manifest")
}

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn fixture(name: &str) -> Value {
    let path = format!(
        "{}/tests/fixtures/woocommerce/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn material() -> AuthMaterial {
    AuthMaterial::from_spec(
        &woo().auth[0],
        BTreeMap::from([
            ("username".to_string(), Zeroizing::new(ck())),
            ("password".to_string(), Zeroizing::new(cs())),
        ]),
    )
}

const SVC: [(&str, &str); 2] = [("host", "shop.acme.test"), ("currency", "EUR")];

fn try_go(
    op_id: &str,
    svc: &[(&str, &str)],
    params: &[(&str, &str)],
    body: Option<&str>,
) -> Result<Built, BrokerError> {
    let m = woo();
    let op = named(m, op_id).unwrap_or_else(|| panic!("no operation {op_id}"));
    let params = validate(op, &map(params), &BTreeMap::new())?;
    build(
        m,
        op,
        &map(svc),
        &params,
        &[(
            "Authorization".to_string(),
            "Bearer agent-guess".to_string(),
        )],
        body.map(|b| Bytes::from(b.to_string())),
        &material(),
    )
}

fn go(op_id: &str, params: &[(&str, &str)], body: Option<&str>) -> Built {
    try_go(op_id, &SVC, params, body).unwrap()
}

const BASE: &str = "https://shop.acme.test/wp-json/wc/v3";

#[test]
fn manifest_shape() {
    let m = woo();
    assert_eq!(m.base_url, "https://{host}/wp-json/wc/v3");
    assert_eq!(m.hosts, ["{host}"]);
    assert_eq!(m.auth[0].kind, "basic");
    assert!(m.params["currency"].required);
    assert!(m.params["host"].required);
    let want = [
        ("orders.list", "orders:read", OpKind::Read),
        ("orders.get", "orders:read", OpKind::Read),
        ("orders.update", "orders:write", OpKind::Write),
        ("products.list", "products:read", OpKind::Read),
        ("products.get", "products:read", OpKind::Read),
        ("products.update", "products:write", OpKind::Write),
        ("customers.list", "customers:read", OpKind::Read),
        ("refunds.create", "refunds:write", OpKind::Write),
    ];
    let ids: Vec<&str> = m.operation.iter().map(|o| o.id.as_str()).collect();
    assert_eq!(ids, want.map(|w| w.0));
    for (id, cap, kind) in want {
        let op = named(m, id).unwrap();
        assert_eq!((op.capability.as_str(), op.kind), (cap, kind), "{id}");
    }
}

#[test]
fn golden_requests_use_header_basic_auth_only() {
    let want = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", ck(), cs()))
    );
    let b = go(
        "orders.list",
        &[("per_page", "2"), ("status", "processing")],
        None,
    );
    assert_eq!(b.method, "GET");
    assert_eq!(b.uri.host(), Some("shop.acme.test"));
    assert_eq!(b.uri.path(), "/wp-json/wc/v3/orders");
    assert_eq!(b.uri.query().unwrap(), "per_page=2&status=processing");
    assert_eq!(b.headers.get("authorization").unwrap(), &want);
    // The secrets never reach the URL (no query-string auth).
    let uri = b.uri.to_string();
    assert!(!uri.contains(&ck()) && !uri.contains(&cs()) && !uri.contains("consumer_"));

    for (op, p, path) in [
        ("orders.get", ("order_id", "727"), "/orders/727"),
        ("products.get", ("product_id", "794"), "/products/794"),
    ] {
        let b = go(op, &[p], None);
        assert_eq!(b.uri.to_string(), format!("{BASE}{path}"));
        assert_eq!(b.headers.get("authorization").unwrap(), &want);
    }
    let b = go("customers.list", &[("search", "doe")], None);
    assert_eq!(b.uri.to_string(), format!("{BASE}/customers?search=doe"));
}

#[test]
fn golden_writes() {
    let b = go(
        "orders.update",
        &[("order_id", "727")],
        Some(r#"{"status":"completed"}"#),
    );
    assert_eq!(b.method, "PUT");
    assert_eq!(b.uri.to_string(), format!("{BASE}/orders/727"));
    assert_eq!(b.body.as_deref(), Some(&br#"{"status":"completed"}"#[..]));
    let b = go(
        "products.update",
        &[("product_id", "794")],
        Some(r#"{"regular_price":"24.00"}"#),
    );
    assert_eq!(
        (b.method.as_str(), b.uri.path()),
        ("PUT", "/wp-json/wc/v3/products/794")
    );
    let b = go(
        "refunds.create",
        &[
            ("order_id", "727"),
            ("amount", "10.00"),
            ("reason", "Wrong\nsize"),
        ],
        None,
    );
    assert_eq!(b.method, "POST");
    let op = named(woo(), "refunds.create").unwrap();
    let p = validate(
        op,
        &map(&[
            ("order_id", "727"),
            ("amount", "10.00"),
            ("reason", "Wrong\nsize"),
        ]),
        &BTreeMap::new(),
    )
    .unwrap();
    let sent = saiife_broker::request::build_body(op, &p).unwrap().unwrap();
    assert_eq!(
        sent,
        json!({"amount": "10.00", "reason": "Wrong\nsize", "api_refund": false})
    );
    assert_eq!(b.uri.to_string(), format!("{BASE}/orders/727/refunds"));
}

#[test]
fn host_param_is_a_bare_hostname_and_pins_the_host() {
    let cat = Catalog::new(builtin(), Vec::new());
    let cfg = |host: &str| -> SystemConfig {
        toml::from_str(&format!(
            "version = 2\n[services.w]\nconnector = \"woocommerce\"\nsecret = \"s\"\n\
             [services.w.params]\nhost = \"{host}\"\ncurrency = \"EUR\"\n"
        ))
        .unwrap()
    };
    assert!(catalog::validate(&cfg("shop.acme.test"), &cat).is_ok());
    for bad in [
        "shop.acme.test@evil.test",
        "evil.test/x",
        "evil.test:8443",
        "Shop.Acme.Test",
        "shop.acme.test.",
        "127.0.0.1",
        "",
    ] {
        assert!(catalog::validate(&cfg(bad), &cat).is_err(), "{bad:?}");
    }
    // The builder refuses such a host too, whatever the policy said.
    for bad in ["shop.acme.test@evil.test", "evil.test/x", "evil.test:8443"] {
        let r = try_go(
            "orders.get",
            &[("host", bad), ("currency", "EUR")],
            &[("order_id", "1")],
            None,
        );
        assert!(r.is_err(), "{bad:?}");
    }
}

#[test]
fn currency_is_required() {
    let cat = Catalog::new(builtin(), Vec::new());
    let cfg = |params: &str| -> SystemConfig {
        toml::from_str(&format!(
            "version = 2\n[services.w]\nconnector = \"woocommerce\"\nsecret = \"s\"\n\
             [services.w.params]\nhost = \"shop.acme.test\"\n{params}"
        ))
        .unwrap()
    };
    assert!(catalog::validate(&cfg("currency = \"EUR\"\n"), &cat).is_ok());
    assert!(catalog::validate(&cfg(""), &cat).is_err());
    assert!(catalog::validate(&cfg("currency = \"EURO\"\n"), &cat).is_err());
}

#[test]
fn path_ids_and_filters_are_constrained() {
    let op = named(woo(), "orders.get").unwrap();
    for bad in ["1/../2", "abc", "1?x=2", ""] {
        assert!(
            validate(op, &map(&[("order_id", bad)]), &BTreeMap::new()).is_err(),
            "{bad:?}"
        );
    }
    let op = named(woo(), "orders.list").unwrap();
    assert!(validate(op, &map(&[("per_page", "101")]), &BTreeMap::new()).is_err());
    assert!(validate(
        op,
        &map(&[("status", "x&consumer_key=1")]),
        &BTreeMap::new()
    )
    .is_err());
    // There is no consumer_key / consumer_secret query param to smuggle.
    for id in ["orders.list", "products.list", "customers.list"] {
        let op = named(woo(), id).unwrap();
        assert!(validate(op, &map(&[("consumer_key", "x")]), &BTreeMap::new()).is_err());
    }
}

#[test]
fn fixtures_parse_to_documented_shape() {
    assert_eq!(fixture("orders.list")["data"][0]["id"], 727);
    assert!(fixture("orders.get")["total"].is_string());
    assert!(fixture("products.list")["data"][0]["price"].is_string());
    assert!(fixture("products.get")["id"].is_u64());
    assert!(fixture("customers.list")["data"][0]["email"].is_string());
    assert!(fixture("refunds.create")["_request"]["amount"].is_string());
}

fn link_headers(link: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("link", link.parse().unwrap());
    h
}

#[test]
fn link_pagination() {
    let m = woo();
    for id in ["orders.list", "products.list", "customers.list"] {
        let op = named(m, id).unwrap();
        assert_eq!(op.pagination, Some(Pagination::LinkHeader), "{id}");
        assert!(op.query.contains_key("page"), "{id}");
        let link = fixture(id)["_link"].as_str().unwrap().to_string();
        let given = map(&[("per_page", "2")]);
        let next = next_from_link(op, &given, &link_headers(&link))
            .unwrap_or_else(|| panic!("{id}: no next in {link}"));
        assert!(next["page"].parse::<u32>().unwrap() >= 2, "{id}: {next:?}");
        // The next page's params are accepted by the operation.
        validate(op, &next, &BTreeMap::new()).unwrap();
    }
    // The last page has no rel="next".
    let op = named(m, "orders.list").unwrap();
    let last = r#"<https://shop.acme.test/wp-json/wc/v3/orders?page=2>; rel="prev""#;
    assert_eq!(
        next_from_link(op, &BTreeMap::new(), &link_headers(last)),
        None
    );
    for id in ["orders.get", "products.get", "refunds.create"] {
        assert_eq!(named(m, id).unwrap().pagination, None, "{id}");
    }
}

#[test]
fn refund_amount_is_read_in_the_admin_currency() {
    let spec = named(woo(), "refunds.create")
        .unwrap()
        .amount
        .clone()
        .unwrap();
    assert_eq!(spec.field, "amount");
    assert_eq!(spec.currency_param.as_deref(), Some("currency"));
    assert_eq!(spec.currency_field, None);
    assert_eq!(spec.unit, Unit::Major);
    let svc = map(&SVC);
    let body = &fixture("refunds.create")["_request"];
    assert_eq!(
        extract(&spec, body, &svc).unwrap(),
        (1000, "EUR".to_string())
    );
    // Another shop currency changes the exponent: JPY has no minor unit.
    let jpy = map(&[("host", "shop.acme.test"), ("currency", "JPY")]);
    assert_eq!(
        extract(&spec, &json!({"amount": "1000"}), &jpy).unwrap(),
        (1000, "JPY".to_string())
    );
    // Other operations carry no amount spec.
    for id in ["orders.update", "products.update"] {
        assert!(named(woo(), id).unwrap().amount.is_none(), "{id}");
    }
}

#[test]
fn refund_body_is_built_from_params_only() {
    let op = named(woo(), "refunds.create").unwrap();
    assert!(op.builds_body());
    for extra in ["line_items", "meta_data", "api_refund", "refund_payment"] {
        let r = validate(
            op,
            &map(&[("order_id", "1"), ("amount", "1.00"), (extra, "x")]),
            &BTreeMap::new(),
        );
        assert!(r.is_err(), "{extra}");
    }
    for bad in ["1e3", "-1", "1,00", "10.", ".5", "1.0000001", ""] {
        let r = validate(
            op,
            &map(&[("order_id", "1"), ("amount", bad)]),
            &BTreeMap::new(),
        );
        assert!(r.is_err(), "{bad:?}");
    }
}

#[test]
fn refund_without_amount_is_an_error() {
    let spec = named(woo(), "refunds.create")
        .unwrap()
        .amount
        .clone()
        .unwrap();
    let svc = map(&SVC);
    for body in [
        json!({"reason": "full refund by omission"}),
        json!({"api_refund": true, "line_items": [{"id": 1, "quantity": 1}]}),
        json!({"amount": "ten"}),
        json!({"amount": "-5.00"}),
        json!({}),
    ] {
        assert!(extract(&spec, &body, &svc).is_err(), "{body}");
    }
    // And without the admin currency there is nothing to count in.
    assert!(extract(&spec, &json!({"amount": "1.00"}), &BTreeMap::new()).is_err());
}

fn svc_cfg(text: &str) -> ServiceCfg {
    toml::from_str(&format!("connector = \"woocommerce\"\n{text}")).unwrap()
}

fn verdict(s: &ServiceCfg, op_id: &str) -> Verdict {
    let cap = Capability::parse(&named(woo(), op_id).unwrap().capability).unwrap();
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

const WRITES: [&str; 3] = ["orders.update", "products.update", "refunds.create"];

#[test]
fn read_only_policy_denies_writes() {
    let s = svc_cfg(r#"allow = ["orders:read", "products:read", "customers:read"]"#);
    for id in [
        "orders.list",
        "orders.get",
        "products.list",
        "products.get",
        "customers.list",
    ] {
        assert_eq!(verdict(&s, id), Verdict::Allow, "{id}");
    }
    for id in WRITES {
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
    let s = svc_cfg(
        r#"allow = ["orders:read", "products:read", "customers:read"]
ask = ["orders:write", "products:write", "refunds:write"]"#,
    );
    for id in WRITES {
        assert_eq!(verdict(&s, id), Verdict::Ask, "{id}");
    }
}

#[test]
fn secret_values_stay_out_of_debug_output() {
    let dbg = format!("{:?}", material());
    assert!(!dbg.contains(&ck()) && !dbg.contains(&cs()), "{dbg}");
}
