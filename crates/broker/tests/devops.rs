//! GitLab, Sentry and PagerDuty connectors (plan 14, wave 2, Task 9): host
//! params, prefixed auth, fixed headers, Link and offset pagination, policy.
//! Offline. Fixtures are in the vendors' documented shape (see each `_source`).

use bytes::Bytes;
use http::{HeaderMap, HeaderValue};
use saiife_broker::manifest::{builtin, Manifest, OpKind, Pagination};
use saiife_broker::params::validate;
use saiife_broker::request::{build, next_cursor, next_from_link, AuthMaterial, Built};
use saiife_broker::resolve::named;
use saiife_broker::{catalog, BrokerError, Catalog};
use saiife_policy::{decide, Capability, Mode, Request, ServiceCfg, SystemConfig, Verdict};
use serde_json::Value;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

fn tok() -> String {
    ["fake", "-", "devops", "-", "0042"].concat()
}

fn manifest(id: &str) -> &'static Manifest {
    builtin()
        .iter()
        .find(|m| m.id == id)
        .unwrap_or_else(|| panic!("{id} is a built-in manifest"))
}

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn fixture(dir: &str, name: &str) -> Value {
    let path = format!(
        "{}/tests/fixtures/{dir}/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn go(
    id: &str,
    op_id: &str,
    svc: &[(&str, &str)],
    params: &[(&str, &str)],
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> Built {
    let m = manifest(id);
    let op = named(m, op_id).unwrap_or_else(|| panic!("no operation {op_id}"));
    let params = validate(op, &map(params), &BTreeMap::new()).unwrap();
    let auth = AuthMaterial::from_spec(
        &m.auth[0],
        BTreeMap::from([("token".to_string(), Zeroizing::new(tok()))]),
    );
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
        &auth,
    )
    .unwrap()
}

fn header(b: &Built, name: &str) -> Vec<String> {
    b.headers
        .get_all(name)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

// ------------------------------------------------------------ shape

#[test]
fn manifests_load_with_the_documented_operations() {
    type Ops = &'static [(&'static str, &'static str, OpKind)];
    let want: [(&str, Ops); 3] = [
        (
            "gitlab",
            &[
                ("projects.get", "projects:read", OpKind::Read),
                ("issues.list", "issues:read", OpKind::Read),
                ("issues.get", "issues:read", OpKind::Read),
                ("issues.create", "issues:write", OpKind::Write),
                ("issues.comment", "issues:write", OpKind::Write),
                ("merge_requests.list", "merge_requests:read", OpKind::Read),
                ("merge_requests.get", "merge_requests:read", OpKind::Read),
                ("pipelines.list", "pipelines:read", OpKind::Read),
            ],
        ),
        (
            "sentry",
            &[
                ("projects.list", "projects:read", OpKind::Read),
                ("issues.list", "issues:read", OpKind::Read),
                ("issues.get", "issues:read", OpKind::Read),
                ("issues.events", "events:read", OpKind::Read),
                ("events.latest", "events:read", OpKind::Read),
                ("issues.update", "issues:write", OpKind::Write),
            ],
        ),
        (
            "pagerduty",
            &[
                ("incidents.list", "incidents:read", OpKind::Read),
                ("incidents.get", "incidents:read", OpKind::Read),
                ("incidents.notes", "incidents:read", OpKind::Read),
                ("incidents.create", "incidents:write", OpKind::Write),
                ("incidents.update", "incidents:write", OpKind::Write),
                ("notes.create", "incidents:write", OpKind::Write),
                ("services.list", "services:read", OpKind::Read),
                ("oncalls.list", "oncalls:read", OpKind::Read),
            ],
        ),
    ];
    for (id, ops) in want {
        let m = manifest(id);
        let got: Vec<&str> = m.operation.iter().map(|o| o.id.as_str()).collect();
        let exp: Vec<&str> = ops.iter().map(|o| o.0).collect();
        assert_eq!(got, exp, "{id}");
        for (op_id, cap, kind) in ops {
            let op = named(m, op_id).unwrap();
            assert_eq!(
                (op.capability.as_str(), op.kind),
                (*cap, *kind),
                "{id} {op_id}"
            );
        }
    }
    assert_eq!(manifest("gitlab").hosts, ["{host}"]);
    assert_eq!(manifest("sentry").hosts, ["{host}"]);
    assert_eq!(manifest("pagerduty").hosts, ["api.pagerduty.com"]);
}

// ------------------------------------------------------------ GitLab

#[test]
fn gitlab_golden_requests() {
    let b = go(
        "gitlab",
        "issues.list",
        &[("host", "gitlab.acme.test")],
        &[("project_id", "42"), ("state", "opened"), ("per_page", "2")],
        &[
            ("Authorization", "Bearer agent"),
            ("PRIVATE-TOKEN", "guess"),
        ],
        None,
    );
    assert_eq!(b.method, "GET");
    assert_eq!(
        b.uri.to_string(),
        "https://gitlab.acme.test/api/v4/projects/42/issues?per_page=2&state=opened"
    );
    assert_eq!(header(&b, "private-token"), [tok()]);
    assert!(header(&b, "authorization").is_empty());

    let b = go(
        "gitlab",
        "issues.comment",
        &[("host", "gitlab.acme.test")],
        &[("project_id", "42"), ("issue_iid", "6")],
        &[("Content-Type", "application/json")],
        Some(r#"{"body":"looks fine"}"#),
    );
    assert_eq!(b.method, "POST");
    assert_eq!(
        b.uri.to_string(),
        "https://gitlab.acme.test/api/v4/projects/42/issues/6/notes"
    );
    assert!(b.body.is_some());
}

#[test]
fn gitlab_project_id_is_an_integer() {
    let m = manifest("gitlab");
    for op_id in ["projects.get", "issues.list", "pipelines.list"] {
        let op = named(m, op_id).unwrap();
        for bad in ["group/project", "group%2Fproject", "4 2", "-1x", ""] {
            assert!(
                validate(op, &map(&[("project_id", bad)]), &BTreeMap::new()).is_err(),
                "{op_id}: {bad:?}"
            );
        }
    }
}

#[test]
fn gitlab_qualifier_is_the_project() {
    let m = manifest("gitlab");
    for op in &m.operation {
        assert_eq!(
            op.qualifier.as_deref(),
            Some("project={project_id}"),
            "{}",
            op.id
        );
    }
    let op = named(m, "issues.get").unwrap();
    let p = validate(
        op,
        &map(&[("project_id", "42"), ("issue_iid", "6")]),
        &BTreeMap::new(),
    )
    .unwrap();
    assert_eq!(
        saiife_broker::manifest::qualifier_for(op, &p).as_deref(),
        Some("project=42")
    );
}

#[test]
fn gitlab_link_pagination() {
    let m = manifest("gitlab");
    let op = named(m, "issues.list").unwrap();
    assert_eq!(op.pagination, Some(Pagination::LinkHeader));
    let f = fixture("gitlab", "issues.list");
    assert!(f["_source"].as_str().unwrap().contains("not fetched"));
    assert_eq!(f["body"][0]["iid"], 6);
    let mut h = HeaderMap::new();
    h.insert(
        "link",
        HeaderValue::from_str(f["_link"].as_str().unwrap()).unwrap(),
    );
    let given = map(&[("project_id", "42"), ("per_page", "2")]);
    assert_eq!(
        next_from_link(op, &given, &h),
        Some(map(&[
            ("project_id", "42"),
            ("state", "opened"),
            ("per_page", "2"),
            ("page", "2")
        ]))
    );
}

// ------------------------------------------------------------ host params

fn cfg(connector: &str, host: &str) -> SystemConfig {
    let text = format!(
        "version = 2\n[services.s]\nconnector = \"{connector}\"\nparams = {{ host = {} }}\n",
        toml::Value::String(host.to_string())
    );
    toml::from_str(&text).unwrap()
}

#[test]
fn host_param_is_a_bare_hostname() {
    let cat = Catalog::new(builtin(), Vec::new());
    for c in ["gitlab", "sentry"] {
        catalog::validate(&cfg(c, "git.acme.com"), &cat).unwrap();
        for bad in [
            "gitlab.acme.com@evil.test",
            "evil.test/x",
            "evil.test:8443",
            "Evil.test",
            "evil.test.",
            "127.0.0.1",
            "localhost",
            "",
        ] {
            let err = catalog::validate(&cfg(c, bad), &cat).unwrap_err();
            assert!(
                matches!(err, BrokerError::BadValue { .. }),
                "{c} {bad:?}: {err:?}"
            );
        }
    }
    // A missing host is refused too (required).
    let none: SystemConfig =
        toml::from_str("version = 2\n[services.s]\nconnector = \"gitlab\"\n").unwrap();
    assert!(catalog::validate(&none, &cat).is_err());
}

#[test]
fn the_agent_cannot_pick_the_host() {
    let m = manifest("gitlab");
    let op = named(m, "projects.get").unwrap();
    // Not a declared op param: refused.
    assert!(validate(
        op,
        &map(&[("project_id", "1"), ("host", "evil.test")]),
        &BTreeMap::new()
    )
    .is_err());
}

// ------------------------------------------------------------ Sentry

#[test]
fn sentry_golden_requests() {
    let b = go(
        "sentry",
        "issues.list",
        &[("host", "sentry.acme.test")],
        &[
            ("org", "acme"),
            ("project", "web"),
            ("query", "is:unresolved"),
        ],
        &[("Authorization", "Bearer guess")],
        None,
    );
    assert_eq!(
        b.uri.to_string(),
        "https://sentry.acme.test/api/0/projects/acme/web/issues/?query=is%3Aunresolved"
    );
    assert_eq!(header(&b, "authorization"), [format!("Bearer {}", tok())]);

    let b = go(
        "sentry",
        "events.latest",
        &[("host", "sentry.acme.test")],
        &[("org", "acme"), ("issue_id", "1234567")],
        &[],
        None,
    );
    assert_eq!(
        b.uri.to_string(),
        "https://sentry.acme.test/api/0/organizations/acme/issues/1234567/events/latest/"
    );

    let b = go(
        "sentry",
        "issues.update",
        &[("host", "sentry.acme.test")],
        &[("org", "acme"), ("issue_id", "1234567")],
        &[("Content-Type", "application/json")],
        Some(r#"{"status":"resolved"}"#),
    );
    assert_eq!(b.method, "PUT");
}

#[test]
fn sentry_org_is_pinned_by_fixed() {
    let m = manifest("sentry");
    let op = named(m, "issues.get").unwrap();
    let fixed = map(&[("org", "acme")]);
    assert!(validate(op, &map(&[("org", "other"), ("issue_id", "1")]), &fixed).is_err());
    let p = validate(op, &map(&[("issue_id", "1")]), &fixed).unwrap();
    assert_eq!(p["org"], "acme");
    // Slugs cannot carry path syntax.
    for bad in ["a/b", "..", "a b", "A", ""] {
        assert!(
            validate(
                op,
                &map(&[("org", bad), ("issue_id", "1")]),
                &BTreeMap::new()
            )
            .is_err(),
            "{bad:?}"
        );
    }
}

#[test]
fn sentry_project_qualifier() {
    let m = manifest("sentry");
    let op = named(m, "issues.list").unwrap();
    assert_eq!(op.qualifier.as_deref(), Some("project={project}"));
    let p = validate(
        op,
        &map(&[("org", "acme"), ("project", "web")]),
        &BTreeMap::new(),
    )
    .unwrap();
    assert_eq!(
        saiife_broker::manifest::qualifier_for(op, &p).as_deref(),
        Some("project=web")
    );
}

#[test]
fn sentry_link_pagination_stops_at_results_false() {
    let m = manifest("sentry");
    let op = named(m, "issues.list").unwrap();
    let f = fixture("sentry", "issues.list");
    let given = map(&[("org", "acme"), ("project", "web")]);
    let link = |key: &str| {
        let mut h = HeaderMap::new();
        h.insert(
            "link",
            HeaderValue::from_str(f[key].as_str().unwrap()).unwrap(),
        );
        h
    };
    assert_eq!(
        next_from_link(op, &given, &link("_link")),
        Some(map(&[
            ("org", "acme"),
            ("project", "web"),
            ("cursor", "100:100:0")
        ]))
    );
    assert_eq!(next_from_link(op, &given, &link("_link_last")), None);
    // The next cursor is accepted by the operation's own query pattern.
    let p = validate(
        op,
        &map(&[("org", "acme"), ("project", "web"), ("cursor", "100:100:0")]),
        &BTreeMap::new(),
    );
    assert!(p.is_ok(), "{p:?}");
}

// ------------------------------------------------------------ PagerDuty

#[test]
fn pagerduty_prefix_and_fixed_headers() {
    let b = go(
        "pagerduty",
        "incidents.list",
        &[("from", "ops@acme.test")],
        &[("limit", "25"), ("offset", "25")],
        &[
            ("Authorization", "Bearer guess"),
            ("From", "attacker@evil.test"),
            ("Accept", "text/plain"),
        ],
        None,
    );
    assert_eq!(
        b.uri.to_string(),
        "https://api.pagerduty.com/incidents?limit=25&offset=25"
    );
    assert_eq!(
        header(&b, "authorization"),
        [format!("Token token={}", tok())]
    );
    assert_eq!(header(&b, "from"), ["ops@acme.test"]);
    assert_eq!(
        header(&b, "accept"),
        ["application/vnd.pagerduty+json;version=2"]
    );
}

#[test]
fn pagerduty_from_is_required_and_an_email() {
    let m = manifest("pagerduty");
    let p = &m.params["from"];
    assert!(p.required);
    let cat = Catalog::new(builtin(), Vec::new());
    let cfg = |p: &str| -> SystemConfig {
        toml::from_str(&format!(
            "version = 2\n[services.s]\nconnector = \"pagerduty\"\nparams = {{ from = {} }}\n",
            toml::Value::String(p.to_string())
        ))
        .unwrap()
    };
    catalog::validate(&cfg("ops@acme.com"), &cat).unwrap();
    for bad in ["", "no-at-sign", "a@b\r\nX-Evil: 1", "a b@c.d"] {
        assert!(catalog::validate(&cfg(bad), &cat).is_err(), "{bad:?}");
    }
    let none: SystemConfig =
        toml::from_str("version = 2\n[services.s]\nconnector = \"pagerduty\"\n").unwrap();
    assert!(catalog::validate(&none, &cat).is_err());
}

#[test]
fn pagerduty_incident_ids_are_constrained() {
    let m = manifest("pagerduty");
    let op = named(m, "incidents.get").unwrap();
    validate(op, &map(&[("incident_id", "PT4KHLK")]), &BTreeMap::new()).unwrap();
    for bad in ["../services", "pt4khlk", "P/T", "", "P T"] {
        assert!(
            validate(op, &map(&[("incident_id", bad)]), &BTreeMap::new()).is_err(),
            "{bad:?}"
        );
    }
}

#[test]
fn pagerduty_offset_pagination() {
    let m = manifest("pagerduty");
    let want = Pagination::Offset {
        param: "offset".into(),
        limit_field: "limit".into(),
        more: "more".into(),
    };
    for id in ["incidents.list", "services.list", "oncalls.list"] {
        assert_eq!(named(m, id).unwrap().pagination, Some(want.clone()), "{id}");
    }
    let f = fixture("pagerduty", "incidents.list");
    assert_eq!(
        next_cursor(&want, &f),
        Some(("offset".to_string(), "50".to_string()))
    );
    let mut last = f.clone();
    last["more"] = Value::Bool(false);
    assert_eq!(next_cursor(&want, &last), None);
}

// ------------------------------------------------------------ policy

fn svc(connector: &str, text: &str) -> ServiceCfg {
    toml::from_str(&format!("connector = \"{connector}\"\n{text}")).unwrap()
}

fn verdict(s: &ServiceCfg, id: &str, op_id: &str, params: &BTreeMap<String, String>) -> Verdict {
    let op = named(manifest(id), op_id).unwrap();
    let mut cap = Capability::parse(&op.capability).unwrap();
    cap.qualifier = saiife_broker::manifest::qualifier_for(op, params);
    decide(
        s,
        None,
        Mode::Locked,
        &Request {
            capability: &cap,
            params,
        },
    )
}

#[test]
fn writes_are_denied_by_default_and_ask_when_listed() {
    let writes = [
        ("gitlab", "issues.create"),
        ("gitlab", "issues.comment"),
        ("sentry", "issues.update"),
        ("pagerduty", "incidents.create"),
        ("pagerduty", "incidents.update"),
        ("pagerduty", "notes.create"),
    ];
    for (id, op) in writes {
        let reads = svc(id, r#"allow = ["*:read"]"#);
        assert_eq!(
            verdict(&reads, id, op, &BTreeMap::new()),
            Verdict::Deny {
                rule: "default_deny".into()
            },
            "{id} {op}"
        );
        let ask = svc(id, r#"ask = ["*:write"]"#);
        assert_eq!(
            verdict(&ask, id, op, &BTreeMap::new()),
            Verdict::Ask,
            "{id} {op}"
        );
    }
}

#[test]
fn gitlab_rule_limited_to_one_project() {
    let s = svc("gitlab", r#"allow = ["issues:read:project=42"]"#);
    let m = manifest("gitlab");
    let p = |id: &str| {
        let op = named(m, "issues.get").unwrap();
        validate(
            op,
            &map(&[("project_id", id), ("issue_iid", "1")]),
            &BTreeMap::new(),
        )
        .unwrap()
    };
    assert_eq!(
        verdict(&s, "gitlab", "issues.get", &p("42")),
        Verdict::Allow
    );
    assert!(matches!(
        verdict(&s, "gitlab", "issues.get", &p("43")),
        Verdict::Deny { .. }
    ));
}
