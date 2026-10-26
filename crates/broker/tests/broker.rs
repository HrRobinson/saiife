use saiife_broker::catalog::{validate as catalog_validate, Catalog};
use saiife_broker::manifest::{builtin, from_http_service, load_local_with, Manifest, OpKind};
use saiife_broker::params::{validate, ParamType};
use saiife_broker::resolve::{named, proxy};
use saiife_broker::BrokerError;
use saiife_policy::{AuthCfg, HttpOperationCfg, ServiceCfg, SystemConfig};
use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;

const ECHO: &str = include_str!("../connectors/test-echo.toml");

fn echo() -> Manifest {
    Manifest::parse(ECHO).expect("test-echo parses")
}

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn op<'m>(m: &'m Manifest, id: &str) -> &'m saiife_broker::manifest::Operation {
    named(m, id).unwrap()
}

#[test]
fn every_builtin_manifest_loads() {
    // Parsing panics on a bad manifest; the list may be empty until Task 12.
    for m in builtin() {
        assert!(!m.id.is_empty());
    }
    let e = echo();
    assert_eq!(e.id, "test-echo");
    assert_eq!(op(&e, "orders.list").kind, OpKind::Read);
}

#[test]
fn unknown_manifest_key_is_error() {
    let bad = format!("bogus = 1\n{ECHO}");
    assert!(matches!(
        Manifest::parse(&bad),
        Err(BrokerError::Manifest(_))
    ));
    let bad_op = ECHO.replace("kind = \"read\"", "kind = \"read\"\nwat = 1");
    assert!(matches!(
        Manifest::parse(&bad_op),
        Err(BrokerError::Manifest(_))
    ));
    let bad_type = ECHO.replace("int:1..250", "int:9..1");
    assert!(matches!(
        Manifest::parse(&bad_type),
        Err(BrokerError::Manifest(_))
    ));
}

#[test]
fn param_types_table() {
    let t = |s: &str| ParamType::parse(s, None).unwrap();
    let ok = |ty: &str, v: &str| t(ty).check(v).is_ok();
    assert!(ok("int:1..250", "1"));
    assert!(ok("int:1..250", "250"));
    assert!(!ok("int:1..250", "0"));
    assert!(!ok("int:1..250", "251"));
    assert!(!ok("int", "1.5"));
    assert!(!ok("int", "+1"));
    assert!(ok("enum:open,closed", "open"));
    assert!(!ok("enum:open,closed", "Open"));
    assert!(ok("datetime", "2026-10-26T12:30:00Z"));
    assert!(ok("datetime", "2026-10-26T12:30:00.5+02:00"));
    assert!(!ok("datetime", "2026-13-01"));
    assert!(!ok("datetime", "2026-13-01T00:00:00Z"));
    assert!(!ok("datetime", "2026-02-30T00:00:00Z"));
    assert!(ok("bool", "true"));
    assert!(!ok("bool", "yes"));
    assert!(ok("string", "anything"));
    let p = ParamType::parse("string", Some("^[a-z]+$")).unwrap();
    assert!(p.check("abc").is_ok());
    assert!(p.check("ab1").is_err());
    assert!(ParamType::parse("float", None).is_err());
}

#[test]
fn fixed_param_cannot_be_overridden() {
    let m = echo();
    let fixed = map(&[("shop", "acme")]);
    let err = validate(op(&m, "orders.list"), &map(&[("shop", "evil")]), &fixed).unwrap_err();
    assert!(matches!(err, BrokerError::FixedParam(ref n) if n == "shop"));
    let out = validate(op(&m, "orders.list"), &map(&[("limit", "5")]), &fixed).unwrap();
    assert_eq!(out["limit"], "5");
    assert_eq!(out["shop"], "acme");
    let err = validate(op(&m, "orders.list"), &map(&[("nope", "1")]), &fixed).unwrap_err();
    assert!(matches!(err, BrokerError::UnknownParam(ref n) if n == "nope"));
    let err = validate(op(&m, "orders.list"), &map(&[("limit", "0")]), &fixed).unwrap_err();
    assert!(matches!(err, BrokerError::BadValue { .. }));
    let err = validate(op(&m, "orders.list"), &map(&[("status", "a\nb")]), &fixed).unwrap_err();
    assert!(matches!(err, BrokerError::BadValue { .. }));
    let err = validate(op(&m, "orders.get"), &map(&[]), &fixed).unwrap_err();
    assert!(matches!(err, BrokerError::MissingParam(ref n) if n == "order_id"));
}

#[test]
fn path_param_double_encoded_slash_rejected() {
    let m = echo();
    let f = map(&[]);
    for bad in [
        "%252f",
        "%2F",
        "%2f",
        "a/b",
        "\u{ff0f}",
        "\u{2215}",
        "..",
        "a..b",
        "",
        "a\\b",
        "%255c",
        ".",
        "%2e",
        "%252e",
        "a?b",
        "a#b",
        "a;b",
        "%3f",
        "%3F",
        "%23",
        "%3b",
        "%3B",
        "%253f",
        "%2523",
        "\u{ff0e}",
        "\u{2044}",
        "\u{202e}",
        "\u{85}",
        "caf\u{e9}",
        "%c3%a9",
        // five rounds of encoding of "A" is still changing after the last round
        "%2525252541",
    ] {
        let r = validate(op(&m, "files.get"), &map(&[("name", bad)]), &f);
        assert!(matches!(r, Err(BrokerError::BadValue { .. })), "{bad:?}");
    }
    let ok = validate(op(&m, "files.get"), &map(&[("name", "report 1.pdf")]), &f).unwrap();
    assert_eq!(ok["name"], "report 1.pdf");
}

#[test]
fn proxy_rejects_traversal_table() {
    let m = echo();
    for bad in [
        "/../admin",
        "/%2e%2e/x",
        "/%2E%2E/x",
        "/a//b",
        "http://evil/x",
        "//evil/x",
        "/a%2fb",
        "/a%2Fb",
        "/a\\b",
        "/a%5cb",
        "/a#b",
        "/a\0b",
        "orders.json",
        "",
        "/orders.json?x=\u{ff0f}",
    ] {
        let r = proxy(&m, "GET", bad);
        assert!(matches!(r, Err(BrokerError::BadPath(_))), "{bad:?}: {r:?}");
    }
}

#[test]
fn proxy_matches_template_and_query() {
    let m = echo();
    let (o, p) = proxy(&m, "GET", "/orders.json?status=open").unwrap();
    assert_eq!(o.id, "orders.list");
    assert_eq!(p, map(&[("status", "open")]));

    let (o, p) = proxy(&m, "GET", "/orders/42").unwrap();
    assert_eq!(o.id, "orders.get");
    assert_eq!(p, map(&[("order_id", "42")]));

    let (o, p) = proxy(&m, "POST", "/orders/42/refunds.json").unwrap();
    assert_eq!(o.id, "refunds.create");
    assert_eq!(p["order_id"], "42");

    // Captured once-decoded; validation then rejects the decoded `%2f`.
    let (o, p) = proxy(&m, "GET", "/files/a%20b").unwrap();
    assert_eq!(o.id, "files.get");
    assert_eq!(p["name"], "a b");
    let (o, p) = proxy(&m, "GET", "/files/%252f").unwrap();
    assert!(validate(o, &p, &map(&[])).is_err());

    // Duplicate query keys are ambiguous.
    assert!(matches!(
        proxy(&m, "GET", "/orders.json?status=open&status=closed"),
        Err(BrokerError::BadValue { .. })
    ));
}

#[test]
fn proxy_method_mismatch_is_unknown_operation() {
    let m = echo();
    for (method, path) in [
        ("POST", "/orders.json"),
        ("GET", "/nope"),
        ("GET", "/orders/42/"),
        ("GET", "/orders"),
        ("GET", "/files/a/b"),
    ] {
        let r = proxy(&m, method, path);
        assert!(
            matches!(r, Err(BrokerError::UnknownOperation(_))),
            "{method} {path}: {r:?}"
        );
    }
}

fn own_uid(dir: &std::path::Path) -> u32 {
    std::fs::metadata(dir).unwrap().uid()
}

#[test]
fn local_manifest_cannot_shadow_builtin() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    std::fs::write(dir.join("echo.toml"), ECHO).unwrap();
    let uid = own_uid(dir);
    let fake_builtin = vec![echo()];
    let r = load_local_with(dir, &fake_builtin, uid);
    assert!(matches!(r, Err(BrokerError::ShadowsBuiltin(ref id)) if id == "test-echo"));
    // Without the clash it loads.
    let ok = load_local_with(dir, &[], uid).unwrap();
    assert_eq!(ok.len(), 1);
    // A file not owned by the required uid is refused.
    let r = load_local_with(dir, &[], uid + 1);
    assert!(matches!(r, Err(BrokerError::Manifest(_))));
    // Missing directory means no local manifests.
    assert!(load_local_with(&dir.join("absent"), &[], uid)
        .unwrap()
        .is_empty());
    // The generic connector name is reserved.
    std::fs::write(
        dir.join("echo.toml"),
        ECHO.replace("id = \"test-echo\"", "id = \"http\""),
    )
    .unwrap();
    assert!(matches!(
        load_local_with(dir, &[], uid),
        Err(BrokerError::ShadowsBuiltin(_))
    ));
}

#[test]
fn local_manifest_refuses_symlink_and_writable() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let uid = own_uid(dir);
    std::fs::write(dir.join("a.toml"), ECHO).unwrap();
    std::fs::set_permissions(dir.join("a.toml"), std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(matches!(
        load_local_with(dir, &[], uid),
        Err(BrokerError::Manifest(_))
    ));
    std::fs::set_permissions(dir.join("a.toml"), std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::remove_file(dir.join("a.toml")).unwrap();
    std::fs::write(dir.join("real"), ECHO).unwrap();
    std::os::unix::fs::symlink(dir.join("real"), dir.join("b.toml")).unwrap();
    assert!(matches!(
        load_local_with(dir, &[], uid),
        Err(BrokerError::Manifest(_))
    ));
}

fn erp() -> ServiceCfg {
    ServiceCfg {
        connector: "http".into(),
        secret: Some("erp-token".into()),
        base_url: Some("https://erp.acme.internal/api".into()),
        auth: Some(AuthCfg {
            kind: "header".into(),
            name: Some("X-Api-Key".into()),
        }),
        operation: vec![HttpOperationCfg {
            id: "invoices.list".into(),
            capability: "invoices:read".into(),
            kind: "read".into(),
            method: "GET".into(),
            path: "/v2/invoices".into(),
            query: vec!["status".into(), "from".into(), "to".into()],
            body: None,
        }],
        ..Default::default()
    }
}

#[test]
fn http_service_becomes_manifest() {
    let m = from_http_service("erp", &erp()).unwrap();
    assert_eq!(m.hosts, vec!["erp.acme.internal".to_string()]);
    assert_eq!(m.base_url, "https://erp.acme.internal/api");
    assert_eq!(m.auth[0].kind, "header");
    assert_eq!(m.auth[0].name.as_deref(), Some("X-Api-Key"));
    let (o, p) = proxy(&m, "GET", "/v2/invoices?status=paid").unwrap();
    assert_eq!(o.id, "invoices.list");
    assert_eq!(p["status"], "paid");
    assert!(validate(o, &map(&[("from", "2026-01-01")]), &map(&[])).is_ok());
    assert!(validate(o, &map(&[("zzz", "1")]), &map(&[])).is_err());

    let mut no_url = erp();
    no_url.base_url = None;
    assert!(matches!(
        from_http_service("erp", &no_url),
        Err(BrokerError::Manifest(_))
    ));
    let mut plain = erp();
    plain.base_url = Some("http://erp.acme.internal".into());
    assert!(from_http_service("erp", &plain).is_err());
    let mut creds = erp();
    creds.base_url = Some("https://u:p@erp.acme.internal".into());
    assert!(from_http_service("erp", &creds).is_err());
}

fn cfg_with(svc: ServiceCfg) -> SystemConfig {
    let mut c: SystemConfig = toml::from_str("version = 2\n").unwrap();
    c.services.insert("s".into(), svc);
    c
}

#[test]
fn catalog_validate_missing_required_param() {
    let cat = Catalog::new(&[echo()], vec![]);
    let svc = |params: &[(&str, &str)]| ServiceCfg {
        connector: "test-echo".into(),
        params: map(params),
        ..Default::default()
    };
    let r = catalog_validate(&cfg_with(svc(&[])), &cat);
    assert!(matches!(r, Err(BrokerError::MissingParam(_))));
    let r = catalog_validate(&cfg_with(svc(&[("shop", "acme"), ("extra", "x")])), &cat);
    assert!(matches!(r, Err(BrokerError::UnknownParam(_))));
    let r = catalog_validate(&cfg_with(svc(&[("shop", "Bad Shop")])), &cat);
    assert!(matches!(r, Err(BrokerError::BadValue { .. })));
    let ok = catalog_validate(&cfg_with(svc(&[("shop", "acme")])), &cat).unwrap();
    assert!(ok.is_empty());

    let mut s = svc(&[("shop", "acme")]);
    s.allow = vec!["orders:read".into(), "invoices:*".into()];
    s.deny = vec!["refunds:write".into()];
    let warns = catalog_validate(&cfg_with(s), &cat).unwrap();
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].contains("invoices:*"));

    let unknown = ServiceCfg {
        connector: "nope".into(),
        ..Default::default()
    };
    assert!(matches!(
        catalog_validate(&cfg_with(unknown), &cat),
        Err(BrokerError::UnknownConnector(_))
    ));
    // `http` services get their manifest from the service config.
    assert!(catalog_validate(&cfg_with(erp()), &cat).is_ok());
}
