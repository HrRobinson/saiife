//! Segment Tracking API connector (plan 14, Task 11): manifest, golden
//! requests with the `basic_token` write key, region hosts, fixtures and the
//! policy outcomes (docs/connectors/segment.md). Offline: no sockets.

use base64::Engine as _;
use bytes::Bytes;
use saiife_broker::manifest::{builtin, Manifest, OpKind};
use saiife_broker::params::validate;
use saiife_broker::request::{build, AuthMaterial, Built};
use saiife_broker::resolve::named;
use saiife_broker::{catalog, BrokerError, Catalog};
use saiife_policy::{decide, Capability, Mode, Request, ServiceCfg, SystemConfig, Verdict};
use serde_json::Value;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// The write key, built at runtime (no token-shaped literal in the source).
fn key() -> String {
    ["sg", "write", "key", "4417"].join("_")
}

fn segment() -> &'static Manifest {
    builtin()
        .iter()
        .find(|m| m.id == "segment")
        .expect("segment is a built-in manifest")
}

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn fixture(name: &str) -> Value {
    let path = format!(
        "{}/tests/fixtures/segment/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn material() -> AuthMaterial {
    AuthMaterial::from_spec(
        &segment().auth[0],
        BTreeMap::from([("token".to_string(), Zeroizing::new(key()))]),
    )
}

fn try_go(
    op_id: &str,
    host: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> Result<Built, BrokerError> {
    let m = segment();
    let op = named(m, op_id).unwrap_or_else(|| panic!("no operation {op_id}"));
    let params = validate(op, &BTreeMap::new(), &BTreeMap::new())?;
    let headers: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    build(
        m,
        op,
        &map(&[("host", host)]),
        &params,
        &headers,
        body.map(|b| Bytes::from(b.to_string())),
        &material(),
    )
}

fn expected_auth() -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{}:", key()))
    )
}

#[test]
fn manifest_shape() {
    let m = segment();
    assert_eq!(m.base_url, "https://{host}/v1");
    assert_eq!(m.hosts, ["api.segment.io", "events.eu1.segmentapis.com"]);
    assert_eq!(m.auth[0].kind, "basic_token");
    let want = [
        ("track", "events:write", OpKind::Write),
        ("identify", "users:write", OpKind::Write),
        ("group", "groups:write", OpKind::Write),
        ("batch", "events:write", OpKind::Bulk),
    ];
    let ids: Vec<&str> = m.operation.iter().map(|o| o.id.as_str()).collect();
    assert_eq!(ids, want.map(|w| w.0));
    for (id, cap, kind) in want {
        let op = named(m, id).unwrap();
        assert_eq!((op.capability.as_str(), op.kind), (cap, kind), "{id}");
        assert_eq!(op.method, "POST", "{id}");
    }
    // Write-only: no read operation at all.
    assert!(m.operation.iter().all(|o| o.kind != OpKind::Read));
}

#[test]
fn golden_requests_in_both_regions() {
    for (op, fx) in [
        ("track", "track"),
        ("identify", "identify"),
        ("group", "group"),
        ("batch", "batch"),
    ] {
        let body = fixture(fx)["_request"].to_string();
        for host in ["api.segment.io", "events.eu1.segmentapis.com"] {
            let b = try_go(
                op,
                host,
                &[
                    ("Content-Type", "application/json"),
                    ("Authorization", "Bearer agent-guess"),
                ],
                Some(&body),
            )
            .unwrap();
            assert_eq!(b.method, "POST");
            assert_eq!(b.uri.to_string(), format!("https://{host}/v1/{op}"));
            assert_eq!(b.body.as_deref(), Some(body.as_bytes()));
            assert_eq!(b.headers.get("authorization").unwrap(), &expected_auth());
            assert_eq!(b.headers.get("content-type").unwrap(), "application/json");
        }
    }
}

#[test]
fn write_key_is_basic_with_empty_password() {
    let b = try_go("track", "api.segment.io", &[], Some("{}")).unwrap();
    let v = b.headers.get("authorization").unwrap().to_str().unwrap();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(v.strip_prefix("Basic ").unwrap())
        .unwrap();
    assert_eq!(String::from_utf8(raw).unwrap(), format!("{}:", key()));
}

#[test]
fn other_hosts_are_refused() {
    for bad in [
        "evil.test",
        "api.segment.io.evil.test",
        "api.segment.io@evil.test",
        "api.segment.io/x",
        "API.SEGMENT.IO",
        "",
    ] {
        let r = try_go("track", bad, &[], Some("{}"));
        assert!(r.is_err(), "{bad:?} -> {:?}", r.map(|b| b.uri));
    }
    // The host param is an enum of the two regions, so a policy naming any
    // other host does not load.
    let cat = Catalog::new(builtin(), Vec::new());
    let cfg = |host: &str| -> SystemConfig {
        toml::from_str(&format!(
            "version = 2\n[services.seg]\nconnector = \"segment\"\nsecret = \"s\"\n\
             [services.seg.params]\nhost = \"{host}\"\n"
        ))
        .unwrap()
    };
    assert!(catalog::validate(&cfg("events.eu1.segmentapis.com"), &cat).is_ok());
    assert!(catalog::validate(&cfg("evil.test"), &cat).is_err());
    assert!(catalog::validate(&cfg("api.segment.io@evil.test"), &cat).is_err());
}

#[test]
fn fixtures_parse_to_documented_shape() {
    assert_eq!(fixture("track")["_request"]["event"], "Order Completed");
    assert!(fixture("identify")["_request"]["traits"].is_object());
    assert!(fixture("group")["_request"]["groupId"].is_string());
    assert!(fixture("batch")["_request"]["batch"].is_array());
    for fx in ["track", "identify", "group", "batch"] {
        assert_eq!(fixture(fx)["success"], true);
    }
}

fn svc(text: &str) -> ServiceCfg {
    toml::from_str(&format!("connector = \"segment\"\n{text}")).unwrap()
}

fn verdict(s: &ServiceCfg, op_id: &str) -> Verdict {
    let cap = Capability::parse(&named(segment(), op_id).unwrap().capability).unwrap();
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
fn empty_read_only_policy_denies_everything() {
    let s = svc("");
    for id in ["track", "identify", "group", "batch"] {
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
fn ask_policy_asks_for_every_write() {
    let s = svc(r#"ask = ["events:write", "users:write", "groups:write"]"#);
    for id in ["track", "identify", "group", "batch"] {
        assert_eq!(verdict(&s, id), Verdict::Ask, "{id}");
    }
}

#[test]
fn write_key_stays_out_of_debug_output() {
    let dbg = format!("{:?}", material());
    assert!(!dbg.contains(&key()), "{dbg}");
}
