//! Fix round 1: anchoring, specificity, query values, auth.

use saiife_broker::catalog::{validate as catalog_validate, Catalog};
use saiife_broker::manifest::{from_http_service, Manifest};
use saiife_broker::params::{validate, ParamType};
use saiife_broker::resolve::proxy;
use saiife_broker::BrokerError;
use saiife_policy::{AuthCfg, ServiceCfg, SystemConfig};
use std::collections::BTreeMap;

const ECHO: &str = include_str!("../connectors/test-echo.toml");

fn echo() -> Manifest {
    Manifest::parse(ECHO).unwrap()
}

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn with_ops(extra: &str) -> String {
    format!("{ECHO}\n{extra}")
}

#[test]
fn param_pattern_is_anchored() {
    let t = ParamType::parse("string", Some("[a-z]+")).unwrap();
    assert!(t.check("acme").is_ok());
    assert!(t.check("evil.com#x").is_err());
    assert!(t.check("a.b").is_err());
    let svc = ServiceCfg {
        connector: "test-echo".into(),
        params: map(&[("shop", "evil.com#x")]),
        ..Default::default()
    };
    let mut cfg: SystemConfig = toml::from_str("version = 2\n").unwrap();
    cfg.services.insert("s".into(), svc);
    let cat = Catalog::new(&[echo()], vec![]);
    assert!(catalog_validate(&cfg, &cat).is_err());
}

const MIXED: &str = r#"
[[operation]]
id = "orders.get_json"
capability = "orders:read"
kind = "read"
method = "GET"
path = "/orders/{id}.json"
path_params = { id = "int" }

[[operation]]
id = "orders.count"
capability = "orders:read"
kind = "read"
method = "GET"
path = "/orders/count.json"
"#;

#[test]
fn literal_beats_placeholder_and_mixed_segments_work() {
    let m = Manifest::parse(&with_ops(MIXED)).unwrap();
    let (o, p) = proxy(&m, "GET", "/orders/count.json").unwrap();
    assert_eq!(o.id, "orders.count");
    assert!(p.is_empty());
    let (o, p) = proxy(&m, "GET", "/orders/42.json").unwrap();
    assert_eq!(o.id, "orders.get_json");
    assert_eq!(p["id"], "42");
    // A bare `/orders/{order_id}` also matches "7.json"; the suffixed
    // placeholder is more specific.
    let (o, _) = proxy(&m, "GET", "/orders/7.json").unwrap();
    assert_eq!(o.id, "orders.get_json");
    let (o, _) = proxy(&m, "GET", "/orders/7").unwrap();
    assert_eq!(o.id, "orders.get");
    // An empty capture does not match the suffixed placeholder; the bare one
    // takes ".json" and the int type then refuses it.
    let (o, p) = proxy(&m, "GET", "/orders/.json").unwrap();
    assert_eq!(o.id, "orders.get");
    assert!(validate(o, &p, &map(&[])).is_err());
}

#[test]
fn manifest_refuses_same_shape_and_duplicate_placeholders() {
    let same = r#"
[[operation]]
id = "orders.get2"
capability = "orders:read"
kind = "read"
method = "GET"
path = "/orders/{other}"
path_params = { other = "int" }
"#;
    assert!(matches!(
        Manifest::parse(&with_ops(same)),
        Err(BrokerError::Manifest(_))
    ));
    let dup = r#"
[[operation]]
id = "dup"
capability = "orders:read"
kind = "read"
method = "GET"
path = "/a/{x}/{x}"
path_params = { x = "int" }
"#;
    assert!(matches!(
        Manifest::parse(&with_ops(dup)),
        Err(BrokerError::Manifest(_))
    ));
}

#[test]
fn query_values_are_not_traversal_checked() {
    let m = echo();
    let (o, p) = proxy(&m, "GET", "/orders.json?created_at_min=2026-01-01").unwrap();
    assert_eq!(o.id, "orders.list");
    assert_eq!(p["created_at_min"], "2026-01-01");
    let (_, p) = proxy(&m, "GET", "/orders.json?after=YWJj%2FZGVm").unwrap();
    assert_eq!(p["after"], "YWJj/ZGVm");
    // Still refused: a fragment; a control character fails validation.
    assert!(proxy(&m, "GET", "/orders.json?a=b#c").is_err());
    let (o, p) = proxy(&m, "GET", "/orders.json?status=a%0ab").unwrap();
    assert!(validate(o, &p, &map(&[])).is_err());
}

#[test]
fn basic_auth_has_no_secret_field() {
    let svc = ServiceCfg {
        connector: "http".into(),
        base_url: Some("https://erp.acme.internal".into()),
        auth: Some(AuthCfg {
            kind: "basic".into(),
            name: None,
        }),
        ..Default::default()
    };
    let m = from_http_service("erp", &svc).unwrap();
    assert_eq!(m.auth[0].kind, "basic");
    assert_eq!(m.auth[0].secret_field, "");
    let basic = ECHO.replace(
        "{ kind = \"header\", name = \"X-Echo-Token\", secret_field = \"token\" }",
        "{ kind = \"basic\" }",
    );
    assert!(Manifest::parse(&basic).is_ok());
    let no_field = ECHO.replace(", secret_field = \"token\"", "");
    assert!(matches!(
        Manifest::parse(&no_field),
        Err(BrokerError::Manifest(_))
    ));
}
