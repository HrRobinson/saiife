//! HubSpot CRM connector: manifest, golden requests, fixtures, pagination
//! and the policy outcomes of the suggested policies (docs/connectors/hubspot.md).
//! Offline: no sockets, fixtures are shaped per the vendor docs.

use bytes::Bytes;
use saiife_broker::manifest::{builtin, Manifest, OpKind, Operation, Pagination};
use saiife_broker::params::validate;
use saiife_broker::request::{build, next_cursor, AuthMaterial, Built};
use saiife_broker::resolve::{named, proxy};
use saiife_broker::BrokerError;
use saiife_policy::{decide, Capability, Mode, Request, ServiceCfg, Verdict};
use serde_json::Value;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

const TOKEN: &str = "pat-na1-SECRET-0000";

fn hubspot() -> &'static Manifest {
    builtin()
        .iter()
        .find(|m| m.id == "hubspot")
        .expect("hubspot is built in")
}

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn hdrs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn auth() -> AuthMaterial {
    AuthMaterial::from_spec(
        &hubspot().auth[0],
        [("token".to_string(), Zeroizing::new(TOKEN.to_string()))].into(),
    )
}

fn op(id: &str) -> &'static Operation {
    named(hubspot(), id).unwrap_or_else(|| panic!("operation {id}"))
}

fn call(
    id: &str,
    params: &[(&str, &str)],
    headers: &[(&str, &str)],
    body: Option<&'static str>,
) -> Result<Built, BrokerError> {
    let o = op(id);
    let p = validate(o, &map(params), &BTreeMap::new())?;
    build(
        hubspot(),
        o,
        &BTreeMap::new(),
        &p,
        &hdrs(headers),
        body.map(|b| Bytes::from_static(b.as_bytes())),
        &auth(),
    )
}

fn render(b: &Built) -> String {
    let mut lines: Vec<String> = b
        .headers
        .iter()
        .map(|(k, v)| format!("{}: {}", k.as_str(), v.to_str().unwrap()))
        .collect();
    lines.sort();
    let mut out = format!("{} {}\n", b.method, b.uri);
    for l in lines {
        out.push_str(&l);
        out.push('\n');
    }
    out
}

fn golden(name: &str) -> String {
    let path = format!("{}/tests/golden/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{path}: {e}"))
        .replace("<AUTH>", TOKEN)
}

fn fixture(name: &str) -> Value {
    let path = format!(
        "{}/tests/fixtures/hubspot/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
}

#[test]
fn every_builtin_manifest_loads() {
    for m in builtin() {
        assert!(!m.id.is_empty());
        m.check().unwrap();
    }
    let m = hubspot();
    assert_eq!(m.base_url, "https://api.hubapi.com");
    assert_eq!(m.hosts, ["api.hubapi.com"]);
    assert_eq!(m.request_headers, ["Content-Type", "Accept"]);
    assert_eq!(m.auth.len(), 1);
    assert_eq!(m.auth[0].kind, "bearer");
    assert!(m.params.is_empty());
    let table: Vec<(&str, &str, OpKind, &str)> = m
        .operation
        .iter()
        .map(|o| {
            (
                o.id.as_str(),
                o.capability.as_str(),
                o.kind,
                o.method.as_str(),
            )
        })
        .collect();
    assert_eq!(
        table,
        [
            ("contacts.list", "contacts:read", OpKind::Read, "GET"),
            ("contacts.get", "contacts:read", OpKind::Read, "GET"),
            ("contacts.update", "contacts:write", OpKind::Write, "PATCH"),
            ("companies.list", "companies:read", OpKind::Read, "GET"),
            ("companies.get", "companies:read", OpKind::Read, "GET"),
            ("deals.list", "deals:read", OpKind::Read, "GET"),
            ("deals.get", "deals:read", OpKind::Read, "GET"),
            ("deals.update", "deals:write", OpKind::Write, "PATCH"),
        ]
    );
    for o in &m.operation {
        assert!(o.path.starts_with("/crm/v3/objects/"), "{}", o.id);
        // No HubSpot operation carries a money cap in wave 1.
        assert!(o.amount.is_none(), "{}", o.id);
        assert_eq!(o.pagination.is_some(), o.id.ends_with(".list"), "{}", o.id);
        assert_eq!(o.body.is_some(), o.kind == OpKind::Write, "{}", o.id);
    }
}

#[test]
fn golden_contacts_list() {
    let b = call(
        "contacts.list",
        &[
            ("limit", "2"),
            ("after", "52"),
            ("properties", "email,firstname"),
        ],
        &[
            ("Accept", "application/json"),
            ("X-Not-Listed", "1"),
            // The agent may not choose the credential.
            ("Authorization", "Bearer agent-guess"),
        ],
        None,
    )
    .unwrap();
    assert_eq!(render(&b), golden("hubspot_contacts_list.http"));
    assert!(b.body.is_none());
}

#[test]
fn golden_deals_get() {
    let b = call(
        "deals.get",
        &[("deal_id", "7001"), ("properties", "dealname,amount")],
        &[("accept", "application/json")],
        None,
    )
    .unwrap();
    assert_eq!(render(&b), golden("hubspot_deals_get.http"));
}

#[test]
fn golden_contacts_update() {
    let body = r#"{"properties":{"firstname":"Augusta"}}"#;
    let b = call(
        "contacts.update",
        &[("contact_id", "51")],
        &[("Content-Type", "application/json")],
        Some(body),
    )
    .unwrap();
    assert_eq!(render(&b), golden("hubspot_contacts_update.http"));
    assert_eq!(b.body.as_deref(), Some(body.as_bytes()));
}

#[test]
fn bearer_goes_in_the_authorization_header_and_is_sensitive() {
    let b = call("companies.get", &[("company_id", "9001")], &[], None).unwrap();
    let v = b.headers.get("authorization").unwrap();
    assert_eq!(v.to_str().unwrap(), format!("Bearer {TOKEN}"));
    assert!(v.is_sensitive());
    assert_eq!(
        b.uri.to_string(),
        "https://api.hubapi.com/crm/v3/objects/companies/9001"
    );
}

#[test]
fn path_ids_are_one_segment() {
    for bad in ["../deals/1", "1/2", "..", "", "-"] {
        let r = call("contacts.get", &[("contact_id", bad)], &[], None);
        assert!(r.is_err(), "{bad:?} was accepted");
    }
    // Ids are numeric: anything else is refused before a request is built.
    for bad in ["a b", "1?x=1", "1%2f2", "abc"] {
        assert!(
            call("contacts.get", &[("contact_id", bad)], &[], None).is_err(),
            "{bad:?}"
        );
    }
}

#[test]
fn properties_and_after_are_pattern_checked() {
    for ok in ["email,firstname", "hs_object_id", "a_b,c"] {
        assert!(call("contacts.list", &[("properties", ok)], &[], None).is_ok());
    }
    let long_p = "x".repeat(513);
    for bad in ["a b", "a&limit=1", "a#b", "a%2cb", "", long_p.as_str()] {
        assert!(
            call("contacts.list", &[("properties", bad)], &[], None).is_err(),
            "properties {bad:?}"
        );
    }
    for ok in ["NTI1Cg==", "a.b-c_d"] {
        assert!(call("contacts.list", &[("after", ok)], &[], None).is_ok());
    }
    let long_a = "x".repeat(257);
    for bad in ["a b", "a&b=1", "a/b", "", long_a.as_str()] {
        assert!(
            call("contacts.list", &[("after", bad)], &[], None).is_err(),
            "after {bad:?}"
        );
    }
}

#[test]
fn unknown_and_out_of_range_params_are_refused() {
    assert!(call("contacts.list", &[("limit", "101")], &[], None).is_err());
    assert!(call("contacts.list", &[("limit", "0")], &[], None).is_err());
    assert!(call("contacts.list", &[("filter", "x")], &[], None).is_err());
    assert!(call("contacts.get", &[], &[], None).is_err());
}

#[test]
fn fixtures_parse_with_vendor_shape() {
    for name in [
        "contacts_list",
        "contacts_list_last",
        "companies_list",
        "deals_list",
    ] {
        let f = fixture(name);
        assert!(f["_source"]
            .as_str()
            .unwrap()
            .contains("developers.hubspot.com/docs/api/crm/"));
        assert!(f["_source"].as_str().unwrap().contains("not fetched"));
        let results = f["results"].as_array().unwrap();
        assert!(!results.is_empty());
        for r in results {
            assert!(r["id"].is_string());
            assert!(r["properties"].is_object());
            assert_eq!(r["archived"], Value::Bool(false));
        }
    }
    for name in ["contacts_get", "companies_get", "deals_get", "update_ok"] {
        let f = fixture(name);
        assert!(f["id"].is_string(), "{name}");
        assert!(f["properties"]["hs_object_id"].is_string(), "{name}");
    }
    assert_eq!(fixture("deals_get")["properties"]["amount"], "1500.00");
}

#[test]
fn pagination_is_a_cursor_on_after() {
    for id in ["contacts.list", "companies.list", "deals.list"] {
        assert_eq!(
            op(id).pagination,
            Some(Pagination::Cursor {
                param: "after".into(),
                next: "paging.next.after".into(),
                more: None,
            }),
            "{id}"
        );
    }
}

#[test]
fn next_cursor_from_fixtures() {
    let p = op("contacts.list").pagination.clone().unwrap();
    assert_eq!(
        next_cursor(&p, &fixture("contacts_list")),
        Some(("after".into(), "52".into()))
    );
    assert_eq!(
        next_cursor(
            &op("companies.list").pagination.clone().unwrap(),
            &fixture("companies_list")
        ),
        Some(("after".into(), "9002".into()))
    );
    assert_eq!(
        next_cursor(
            &op("deals.list").pagination.clone().unwrap(),
            &fixture("deals_list")
        ),
        Some(("after".into(), "7002".into()))
    );
    // Last page: no `paging`.
    assert_eq!(next_cursor(&p, &fixture("contacts_list_last")), None);
    // Not a cursor, empty or wrongly typed.
    assert_eq!(
        next_cursor(&Pagination::LinkHeader, &fixture("contacts_list")),
        None
    );
    let empty: Value = serde_json::from_str(r#"{"paging":{"next":{"after":""}}}"#).unwrap();
    assert_eq!(next_cursor(&p, &empty), None);
    let obj: Value = serde_json::from_str(r#"{"paging":{"next":{"after":{"x":1}}}}"#).unwrap();
    assert_eq!(next_cursor(&p, &obj), None);
}

#[test]
fn next_cursor_refuses_unsafe_values() {
    let p = op("contacts.list").pagination.clone().unwrap();
    let with = |v: Value| serde_json::json!({"paging":{"next":{"after": v}}});
    let long = "a".repeat(257);
    assert_eq!(next_cursor(&p, &with(Value::String(long))), None);
    let ok = "a".repeat(256);
    assert!(next_cursor(&p, &with(Value::String(ok))).is_some());
    for bad in ["52\r\nX-Evil: 1", "a b", "a&b=c", "a\\b", "é"] {
        assert_eq!(
            next_cursor(&p, &with(Value::String(bad.into()))),
            None,
            "{bad:?}"
        );
    }
    assert_eq!(next_cursor(&p, &with(serde_json::json!({"x": "1"}))), None);
    assert!(next_cursor(&p, &with(serde_json::json!(52))).is_some());
}

#[test]
fn next_page_request_carries_the_cursor() {
    let p = op("contacts.list").pagination.clone().unwrap();
    let (param, value) = next_cursor(&p, &fixture("contacts_list")).unwrap();
    let b = call(
        "contacts.list",
        &[(param.as_str(), value.as_str())],
        &[],
        None,
    )
    .unwrap();
    assert_eq!(
        b.uri.to_string(),
        "https://api.hubapi.com/crm/v3/objects/contacts?after=52"
    );
}

#[test]
fn hubspot_cursor_refuses_slash_and_plus() {
    // next_cursor admits `/` and `+` for other connectors; hubspot's own
    // `after` pattern must still refuse them.
    let o = op("contacts.list");
    for bad in ["a/b", "a+b"] {
        assert!(
            validate(o, &map(&[("after", bad)]), &BTreeMap::new()).is_err(),
            "{bad:?}"
        );
    }
}

#[test]
fn proxy_paths_resolve_to_operations() {
    let m = hubspot();
    let id = |method: &str, path: &str| proxy(m, method, path).map(|(o, _)| o.id.clone());
    assert_eq!(
        id("GET", "/crm/v3/objects/contacts?limit=5").unwrap(),
        "contacts.list"
    );
    assert_eq!(
        id("GET", "/crm/v3/objects/deals/7001").unwrap(),
        "deals.get"
    );
    assert_eq!(
        id("PATCH", "/crm/v3/objects/deals/7001").unwrap(),
        "deals.update"
    );
    assert_eq!(
        id("PATCH", "/crm/v3/objects/contacts/51").unwrap(),
        "contacts.update"
    );
    // Not in the manifest: company writes, deletes, creates, other objects.
    assert!(id("PATCH", "/crm/v3/objects/companies/9001").is_err());
    assert!(id("DELETE", "/crm/v3/objects/contacts/51").is_err());
    assert!(id("POST", "/crm/v3/objects/contacts").is_err());
    assert!(id("GET", "/crm/v3/objects/tickets").is_err());
    assert!(id("GET", "/crm/v3/objects/contacts/%2e%2e/deals").is_err());
}

// --- policy outcomes of the documented policies ---

const READ_ONLY: &str = r#"
connector = "hubspot"
secret = "hubspot-prod"
allow = ["contacts:read", "companies:read", "deals:read"]
deny  = ["*:delete"]
"#;

const WRITES_ASK: &str = r#"
connector = "hubspot"
secret = "hubspot-prod"
allow = ["contacts:read", "companies:read", "deals:read"]
ask   = ["contacts:write", "deals:write"]
deny  = ["*:delete"]
"#;

fn verdict(policy: &str, op_id: &str) -> Verdict {
    let svc: ServiceCfg = toml::from_str(policy).unwrap();
    let cap = Capability::parse(&op(op_id).capability).unwrap();
    let params = BTreeMap::new();
    decide(
        &svc,
        None,
        Mode::Locked,
        &Request {
            capability: &cap,
            params: &params,
        },
    )
}

#[test]
fn writes_are_denied_by_default() {
    let empty = r#"connector = "hubspot""#;
    for id in ["contacts.update", "deals.update", "contacts.list"] {
        assert_eq!(
            verdict(empty, id),
            Verdict::Deny {
                rule: "default_deny".into()
            },
            "{id}"
        );
    }
}

#[test]
fn read_only_policy_allows_reads_and_denies_writes() {
    for id in [
        "contacts.list",
        "contacts.get",
        "companies.list",
        "companies.get",
        "deals.list",
        "deals.get",
    ] {
        assert_eq!(verdict(READ_ONLY, id), Verdict::Allow, "{id}");
    }
    for id in ["contacts.update", "deals.update"] {
        assert_eq!(
            verdict(READ_ONLY, id),
            Verdict::Deny {
                rule: "default_deny".into()
            },
            "{id}"
        );
    }
}

#[test]
fn writes_ask_policy_asks_for_every_write() {
    for id in ["contacts.update", "deals.update"] {
        assert_eq!(verdict(WRITES_ASK, id), Verdict::Ask, "{id}");
    }
    assert_eq!(verdict(WRITES_ASK, "deals.get"), Verdict::Allow);
}

#[test]
fn writes_are_allowed_when_the_policy_says_so() {
    let allow = r#"
connector = "hubspot"
allow = ["contacts:read", "contacts:write"]
"#;
    assert_eq!(verdict(allow, "contacts.update"), Verdict::Allow);
    assert_eq!(
        verdict(allow, "deals.update"),
        Verdict::Deny {
            rule: "default_deny".into()
        }
    );
}
