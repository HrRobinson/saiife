//! The GitHub REST connector (Task 14): golden requests, fixtures,
//! pagination, the write operations and the `repo=` qualifier. Offline.

use bytes::Bytes;
use saiife_broker::manifest::{builtin, qualifier_for, Manifest, OpKind, Pagination};
use saiife_broker::params::validate;
use saiife_broker::request::{build, AuthMaterial, Built};
use saiife_broker::resolve::named;
use saiife_policy::{decide, Capability, Mode, Request, ServiceCfg, Verdict};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

const GITHUB: &str = include_str!("../connectors/github.toml");
const TOKEN: &str = "ghp_SECRET123";

fn github() -> Manifest {
    Manifest::parse(GITHUB).expect("github parses")
}

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn fixture(name: &str) -> String {
    let p = format!(
        "{}/tests/fixtures/github/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn golden(name: &str) -> String {
    let p = format!("{}/tests/golden/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("{p}: {e}"))
        .replace("<AUTH>", &format!("Bearer {TOKEN}"))
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

/// Validates `call`, builds the request the way the pipeline does, with the
/// headers GitHub documents.
fn built(m: &Manifest, op_id: &str, call: &[(&str, &str)], body: Option<&str>) -> Built {
    let op = named(m, op_id).unwrap();
    let params = validate(op, &map(call), &BTreeMap::new()).unwrap();
    let mut headers = vec![
        (
            "Accept".to_string(),
            "application/vnd.github+json".to_string(),
        ),
        ("X-GitHub-Api-Version".to_string(), "2022-11-28".to_string()),
        (
            "Authorization".to_string(),
            "Bearer agent-guess".to_string(),
        ),
    ];
    if body.is_some() {
        headers.push(("Content-Type".to_string(), "application/json".to_string()));
    }
    let auth = AuthMaterial::from_spec(
        &m.auth[0],
        [("token".to_string(), Zeroizing::new(TOKEN.to_string()))].into(),
    );
    build(
        m,
        op,
        &BTreeMap::new(),
        &params,
        &headers,
        body.map(|b| Bytes::from(b.to_string())),
        &auth,
    )
    .unwrap()
}

type Case<'a> = (&'a str, Vec<(&'a str, &'a str)>, Option<&'a str>, &'a str);
type WriteCase<'a> = (&'a str, Vec<(&'a str, &'a str)>, &'a str);

const REPO: [(&str, &str); 2] = [("owner", "acme"), ("repo", "web")];

fn with<'a>(extra: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut v: Vec<(&str, &str)> = REPO.to_vec();
    v.extend_from_slice(extra);
    v
}

#[test]
fn every_builtin_manifest_loads() {
    assert!(builtin().iter().any(|m| m.id == "github"));
    let m = github();
    assert_eq!(m.hosts, ["api.github.com"]);
    assert_eq!(m.auth[0].kind, "bearer");
    for op in &m.operation {
        assert_eq!(
            op.qualifier.as_deref(),
            Some("repo={owner}/{repo}"),
            "{}",
            op.id
        );
    }
    let caps: Vec<(&str, &str, OpKind)> = m
        .operation
        .iter()
        .map(|o| (o.id.as_str(), o.capability.as_str(), o.kind))
        .collect();
    assert_eq!(
        caps,
        [
            ("repos.get", "repos:read", OpKind::Read),
            ("issues.list", "issues:read", OpKind::Read),
            ("issues.get", "issues:read", OpKind::Read),
            ("issues.create", "issues:write", OpKind::Write),
            ("issues.comment", "issues:write", OpKind::Write),
            ("pulls.list", "pulls:read", OpKind::Read),
            ("pulls.get", "pulls:read", OpKind::Read),
            ("pulls.create", "pulls:write", OpKind::Write),
        ]
    );
}

#[test]
fn golden_requests() {
    let m = github();
    let cases: Vec<Case> = vec![
        ("repos.get", with(&[]), None, "github_repos_get.http"),
        (
            "issues.list",
            with(&[("state", "open"), ("per_page", "30")]),
            None,
            "github_issues_list.http",
        ),
        (
            "issues.get",
            with(&[("issue_number", "1347")]),
            None,
            "github_issues_get.http",
        ),
        (
            "issues.create",
            with(&[]),
            Some(r#"{"title":"Found a bug"}"#),
            "github_issues_create.http",
        ),
        (
            "issues.comment",
            with(&[("issue_number", "1347")]),
            Some(r#"{"body":"Me too"}"#),
            "github_issues_comment.http",
        ),
        (
            "pulls.list",
            with(&[("state", "open"), ("base", "main")]),
            None,
            "github_pulls_list.http",
        ),
        (
            "pulls.get",
            with(&[("pull_number", "1347")]),
            None,
            "github_pulls_get.http",
        ),
        (
            "pulls.create",
            with(&[]),
            Some(r#"{"title":"x","head":"new-topic","base":"main"}"#),
            "github_pulls_create.http",
        ),
    ];
    for (op, call, body, file) in cases {
        let b = built(&m, op, &call, body);
        assert_eq!(render(&b), golden(file), "{op}");
        // The agent's own Authorization never reaches the wire.
        assert!(!render(&b).contains("agent-guess"));
        assert_eq!(b.body.is_some(), body.is_some(), "{op}");
    }
}

#[test]
fn bad_path_params_are_refused() {
    let m = github();
    let op = named(&m, "issues.get").unwrap();
    let no = |call: &[(&str, &str)]| validate(op, &map(call), &BTreeMap::new()).is_err();
    assert!(no(&[
        ("owner", "acme"),
        ("repo", "web"),
        ("issue_number", "x")
    ]));
    assert!(no(&[("owner", "acme"), ("repo", "web")]));
    for bad in ["acme/evil", "..", "%2e%2e", "%2F", "%2f", "a\\b", ""] {
        assert!(
            no(&[("owner", bad), ("repo", "web"), ("issue_number", "1")]),
            "owner {bad:?}"
        );
        assert!(
            no(&[("owner", "acme"), ("repo", bad), ("issue_number", "1")]),
            "repo {bad:?}"
        );
    }
}

#[test]
fn qualifier_with_unknown_placeholder_is_refused() {
    let bad = GITHUB.replacen("repo={owner}/{repo}", "repo={owner}/{nope}", 1);
    assert!(Manifest::parse(&bad).is_err());
    let unclosed = GITHUB.replacen("repo={owner}/{repo}", "repo={owner}/{repo", 1);
    assert!(Manifest::parse(&unclosed).is_err());
}

#[test]
fn fixtures_parse_and_have_documented_fields() {
    let obj = |name: &str| -> serde_json::Value {
        let v: serde_json::Value = serde_json::from_str(&fixture(name)).unwrap();
        v
    };
    for (name, field) in [
        ("repos_get.json", "full_name"),
        ("issues_get.json", "number"),
        ("issues_create.json", "number"),
        ("issues_comment.json", "body"),
        ("pulls_get.json", "head"),
        ("pulls_create.json", "number"),
    ] {
        let v = obj(name);
        let src = v["_source"].as_str().unwrap();
        assert!(src.contains("docs.github.com/en/rest"), "{name}");
        assert!(src.contains("not fetched"), "{name}");
        assert!(!v[field].is_null(), "{name}.{field}");
    }
    assert_eq!(obj("repos_get.json")["full_name"], "acme/web");
    for name in ["issues_list.json", "pulls_list.json"] {
        let v = obj(name);
        assert_eq!(v.as_array().unwrap().len(), 1, "{name}");
        assert!(v[0]["number"].is_number());
    }
    assert!(fixture("README.md").contains("not fetched"));
}

#[test]
fn pagination_is_link_header() {
    let m = github();
    for id in ["issues.list", "pulls.list"] {
        assert_eq!(
            named(&m, id).unwrap().pagination,
            Some(Pagination::LinkHeader)
        );
    }
    for id in ["repos.get", "issues.get", "pulls.get", "issues.create"] {
        assert_eq!(named(&m, id).unwrap().pagination, None);
    }
    // The fixture is GitHub's documented Link header: it holds a next page.
    let link = fixture("link_header.txt");
    let next = link
        .split(',')
        .find(|p| p.contains(r#"rel="next""#))
        .and_then(|p| p.split(['<', '>']).nth(1))
        .unwrap();
    assert!(next.starts_with("https://api.github.com/") && next.ends_with("page=3"));
    // `page` and `per_page` are the parameters the next page is asked with.
    let op = named(&m, "issues.list").unwrap();
    validate(
        op,
        &map(&with(&[("page", "3"), ("per_page", "1")])),
        &BTreeMap::new(),
    )
    .unwrap();
    assert!(validate(op, &map(&with(&[("per_page", "101")])), &BTreeMap::new()).is_err());
}

fn svc(toml_src: &str) -> ServiceCfg {
    toml::from_str(toml_src).unwrap()
}

/// The policy verdict for operation `op_id` called with `call`, qualifier
/// filled the way the pipeline does it.
fn verdict(s: &ServiceCfg, op_id: &str, call: &[(&str, &str)]) -> Verdict {
    let m = github();
    let op = named(&m, op_id).unwrap();
    let params = map(call);
    let mut cap = Capability::parse(&op.capability).unwrap();
    cap.qualifier = qualifier_for(op, &params);
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

fn deny_default() -> Verdict {
    Verdict::Deny {
        rule: "default_deny".into(),
    }
}

#[test]
fn qualifier_template_is_filled_from_params() {
    let m = github();
    let op = named(&m, "issues.create").unwrap();
    assert_eq!(
        qualifier_for(op, &map(&REPO)).as_deref(),
        Some("repo=acme/web")
    );
    // A missing placeholder value gives no qualifier (fail closed).
    assert_eq!(qualifier_for(op, &map(&[("owner", "acme")])), None);
}

#[test]
fn qualifier_policy() {
    // This is the policy half of `qualifier_policy_end_to_end`; the pipeline
    // (Task 9) will add the full path.
    let s = svc("connector = \"github\"\nallow = [\"issues:write:repo=acme/*\"]\n");
    let acme = with(&[("issue_number", "1")]);
    assert_eq!(verdict(&s, "issues.create", &REPO), Verdict::Allow);
    assert_eq!(verdict(&s, "issues.comment", &acme), Verdict::Allow);
    let other = [("owner", "other"), ("repo", "web")];
    assert_eq!(verdict(&s, "issues.create", &other), deny_default());
    // The allow is case-exact: a different case is not allowed.
    let upper = [("owner", "ACME"), ("repo", "web")];
    assert_eq!(verdict(&s, "issues.create", &upper), deny_default());
    // The pattern scopes the capability too: no other write is opened.
    assert_eq!(verdict(&s, "pulls.create", &REPO), deny_default());
    // A deny matches case-insensitively and beats the allow.
    let s = svc(
        "connector = \"github\"\nallow = [\"issues:write:repo=acme/*\"]\ndeny = [\"issues:write:repo=ACME/secret\"]\n",
    );
    assert_eq!(verdict(&s, "issues.create", &REPO), Verdict::Allow);
    let secret = [("owner", "acme"), ("repo", "secret")];
    let s2 = svc("connector = \"github\"\nallow = [\"issues:write:repo=acme/*\"]\ndeny = [\"issues:write:repo=acme/secret\"]\n");
    let upper_secret = [("owner", "ACME"), ("repo", "secret")];
    assert!(matches!(
        verdict(&s2, "issues.create", &upper_secret),
        Verdict::Deny { ref rule } if rule.starts_with("deny:")
    ));
    assert!(matches!(
        verdict(&s, "issues.create", &secret),
        Verdict::Deny { ref rule } if rule.starts_with("deny:")
    ));
}

#[test]
fn writes_denied_by_default_and_allowed_by_policy() {
    let writes: [WriteCase; 3] = [
        ("issues.create", with(&[]), "issues:write"),
        (
            "issues.comment",
            with(&[("issue_number", "1")]),
            "issues:write",
        ),
        ("pulls.create", with(&[]), "pulls:write"),
    ];
    let none =
        svc("connector = \"github\"\nallow = [\"issues:read\", \"pulls:read\", \"repos:read\"]\n");
    for (op, call, cap) in writes {
        assert_eq!(verdict(&none, op, &call), deny_default(), "{op}");
        let s = svc(&format!("connector = \"github\"\nallow = [\"{cap}\"]\n"));
        assert_eq!(verdict(&s, op, &call), Verdict::Allow, "{op}");
        let ask = svc(&format!("connector = \"github\"\nask = [\"{cap}\"]\n"));
        assert_eq!(verdict(&ask, op, &call), Verdict::Ask, "{op}");
    }
    // Reads are allowed by a read-only policy, writes are not.
    for (op, call) in [
        ("repos.get", with(&[])),
        ("issues.list", with(&[])),
        ("issues.get", with(&[("issue_number", "1")])),
        ("pulls.list", with(&[])),
        ("pulls.get", with(&[("pull_number", "1")])),
    ] {
        assert_eq!(verdict(&none, op, &call), Verdict::Allow, "{op}");
    }
}

#[test]
fn no_amount_on_any_operation() {
    assert!(github().operation.iter().all(|o| o.amount.is_none()));
}
