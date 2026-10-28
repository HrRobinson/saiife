//! Linear (GraphQL), Intercom (regional host, fixed version header) and
//! Airtable (offset cursor): manifests, built requests, pagination and the
//! policy outcomes of the documented policies. Offline; fixtures follow the
//! vendors' documented shapes.

use bytes::Bytes;
use saiife_broker::manifest::{builtin, qualifier_for, Manifest, OpKind, Operation, Pagination};
use saiife_broker::params::validate;
use saiife_broker::pipeline::prepare_body;
use saiife_broker::request::{build, next_cursor, AuthMaterial, Built};
use saiife_broker::resolve::{named, proxy};
use saiife_broker::BrokerError;
use saiife_policy::{decide, Capability, Mode, Request, ServiceCfg, Verdict};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn manifest(id: &'static str) -> &'static Manifest {
    builtin()
        .iter()
        .find(|m| m.id == id)
        .unwrap_or_else(|| panic!("{id} is built in"))
}

fn op(m: &'static Manifest, id: &str) -> &'static Operation {
    named(m, id).unwrap_or_else(|| panic!("operation {id}"))
}

fn fixture(dir: &str, name: &str) -> Value {
    let path = format!(
        "{}/tests/fixtures/{dir}/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let v: Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"));
    assert!(v["_source"]
        .as_str()
        .unwrap()
        .contains("Shape per vendor docs"));
    v
}

fn token(label: &str) -> String {
    format!("{}{}", concat!("tok", "-", "SECRET-"), label)
}

/// Validates, builds the body the way the pipeline does and builds the request.
fn built(
    m: &'static Manifest,
    op_id: &str,
    svc: &[(&str, &str)],
    call: &[(&str, &str)],
    agent_headers: &[(&str, &str)],
    tok: &str,
) -> Result<Built, BrokerError> {
    let o = op(m, op_id);
    let p = validate(o, &map(call), &BTreeMap::new())?;
    let body = prepare_body(o, &p, None).map_err(|r| BrokerError::Manifest(r.to_string()))?;
    let headers: Vec<(String, String)> = agent_headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let auth = AuthMaterial::from_spec(
        &m.auth[0],
        [("token".to_string(), Zeroizing::new(tok.to_string()))].into(),
    );
    build(m, o, &map(svc), &p, &headers, body.bytes, &auth)
}

fn svc_cfg(src: &str) -> ServiceCfg {
    toml::from_str(src).unwrap()
}

fn verdict(m: &'static Manifest, s: &ServiceCfg, op_id: &str, call: &[(&str, &str)]) -> Verdict {
    let o = op(m, op_id);
    let params = map(call);
    let mut cap = Capability::parse(&o.capability).unwrap();
    cap.qualifier = qualifier_for(o, &params);
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

fn table(m: &Manifest) -> Vec<(&str, &str, OpKind)> {
    m.operation
        .iter()
        .map(|o| (o.id.as_str(), o.capability.as_str(), o.kind))
        .collect()
}

// ------------------------------------------------------------------ Linear

fn linear() -> &'static Manifest {
    manifest("linear")
}

#[test]
fn linear_manifest() {
    let m = linear();
    m.check().unwrap();
    assert_eq!(m.base_url, "https://api.linear.app");
    assert_eq!(m.auth[0].kind, "header");
    assert_eq!(m.auth[0].name.as_deref(), Some("Authorization"));
    assert_eq!(m.auth[0].prefix, None);
    assert_eq!(
        table(m),
        [
            ("teams.list", "teams:read", OpKind::Read),
            ("issues.list", "issues:read", OpKind::Read),
            ("issues.get", "issues:read", OpKind::Read),
            ("issues.create", "issues:write", OpKind::Write),
            ("issues.comment", "issues:write", OpKind::Write),
        ]
    );
    for o in &m.operation {
        assert_eq!((o.method.as_str(), o.path.as_str()), ("POST", "/graphql"));
        assert!(o.graphql.is_some(), "{}", o.id);
        assert_eq!(o.body.as_deref(), Some("json"));
    }
}

#[test]
fn linear_request_is_the_fixed_document_with_variables() {
    let tok = token("linear");
    let b = built(
        linear(),
        "issues.list",
        &[],
        &[("team", "ENG"), ("first", "2"), ("after", "abc-1")],
        &[("Authorization", "Bearer agent-guess")],
        &tok,
    )
    .unwrap();
    assert_eq!(b.method, "POST");
    assert_eq!(b.uri.to_string(), "https://api.linear.app/graphql");
    // The key goes out raw, with no Bearer prefix, and is sensitive.
    let a = b.headers.get("authorization").unwrap();
    assert_eq!(a.to_str().unwrap(), tok);
    assert!(a.is_sensitive());
    let body: Value = serde_json::from_slice(&b.body.unwrap()).unwrap();
    assert_eq!(
        body["query"].as_str(),
        op(linear(), "issues.list").graphql.as_deref()
    );
    assert_eq!(
        body["variables"],
        json!({"team": "ENG", "first": 2, "after": "abc-1"})
    );
}

#[test]
fn linear_mutations_carry_only_variables() {
    let tok = token("linear");
    let b = built(
        linear(),
        "issues.create",
        &[],
        &[
            ("team_id", "9cfb482a-81e3-4154-b5b9-2c805e70a02d"),
            ("title", "Crash on save"),
            ("description", "Steps:\n1. open\n2. \"save\""),
        ],
        &[],
        &tok,
    )
    .unwrap();
    let body: Value = serde_json::from_slice(&b.body.unwrap()).unwrap();
    assert!(body["query"].as_str().unwrap().starts_with("mutation"));
    assert_eq!(body["variables"]["title"], "Crash on save");
    assert_eq!(
        body["variables"]["description"],
        "Steps:\n1. open\n2. \"save\""
    );
    // A value never becomes GraphQL: it stays a JSON string.
    let b = built(
        linear(),
        "issues.comment",
        &[],
        &[
            ("issue_id", "ENG-101"),
            ("body", "x\") { id } mutation { issueDelete"),
        ],
        &[],
        &tok,
    )
    .unwrap();
    let body: Value = serde_json::from_slice(&b.body.unwrap()).unwrap();
    assert_eq!(
        body["query"].as_str(),
        op(linear(), "issues.comment").graphql.as_deref()
    );
    assert_eq!(
        body["variables"]["body"],
        "x\") { id } mutation { issueDelete"
    );
}

#[test]
fn agent_cannot_send_graphql() {
    let m = linear();
    for id in ["teams.list", "issues.create", "issues.comment"] {
        let raw =
            Bytes::from_static(br#"{"query":"mutation { issueDelete(id: \"x\") { success } }"}"#);
        assert_eq!(
            prepare_body(op(m, id), &BTreeMap::new(), Some(&raw)).unwrap_err(),
            "bad_param",
            "{id}"
        );
    }
    // An unknown variable and a hand-made query param are refused.
    assert!(validate(
        op(m, "issues.list"),
        &map(&[("query", "{ viewer { id } }")]),
        &BTreeMap::new()
    )
    .is_err());
    // /v1/proxy never reaches a GraphQL operation.
    for (method, path) in [("POST", "/graphql"), ("GET", "/graphql"), ("POST", "/")] {
        let err = proxy(m, method, path).unwrap_err();
        assert!(matches!(err, BrokerError::UnknownOperation(_)), "{err:?}");
    }
}

#[test]
fn linear_variables_are_pattern_checked() {
    let m = linear();
    let o = op(m, "issues.list");
    let ok = |c: &[(&str, &str)]| validate(o, &map(c), &BTreeMap::new()).is_ok();
    assert!(ok(&[("team", "ENG")]));
    assert!(!ok(&[("team", "ENG\" }")]));
    assert!(!ok(&[("team", "")]));
    assert!(!ok(&[("first", "0")]));
    assert!(!ok(&[("first", "101")]));
    assert!(!ok(&[("after", "a b")]));
    assert!(!ok(&[("after", "a\"b")]));
}

#[test]
fn linear_pagination() {
    for (id, root) in [("issues.list", "issues"), ("teams.list", "teams")] {
        assert_eq!(
            op(linear(), id).pagination,
            Some(Pagination::Cursor {
                param: "after".into(),
                next: format!("data.{root}.pageInfo.endCursor"),
                more: Some(format!("data.{root}.pageInfo.hasNextPage")),
            }),
            "{id}"
        );
    }
    let p = op(linear(), "issues.list").pagination.clone().unwrap();
    let (param, cursor) = next_cursor(&p, &fixture("linear", "issues_list")).unwrap();
    assert_eq!(param, "after");
    assert_eq!(cursor, "7e6d5c4b-3a29-4817-96f5-e4d3c2b1a098");
    // hasNextPage false: the last page, though endCursor is set.
    assert_eq!(
        next_cursor(&p, &fixture("linear", "issues_list_last")),
        None
    );
    let t = op(linear(), "teams.list").pagination.clone().unwrap();
    assert_eq!(next_cursor(&t, &fixture("linear", "teams_list")), None);
    // The cursor goes back as a variable.
    let tok = token("linear");
    let b = built(
        linear(),
        "issues.list",
        &[],
        &[("team", "ENG"), ("after", cursor.as_str())],
        &[],
        &tok,
    )
    .unwrap();
    let body: Value = serde_json::from_slice(&b.body.unwrap()).unwrap();
    assert_eq!(body["variables"]["after"], cursor.as_str());
}

#[test]
fn linear_team_qualifier_and_policy() {
    let m = linear();
    assert_eq!(
        qualifier_for(op(m, "issues.list"), &map(&[("team", "ENG")])).as_deref(),
        Some("team=ENG")
    );
    assert_eq!(
        qualifier_for(op(m, "issues.create"), &map(&[("team_id", "t-1")])).as_deref(),
        Some("team=t-1")
    );
    assert_eq!(qualifier_for(op(m, "issues.list"), &map(&[])), None);
    let s = svc_cfg("connector = \"linear\"\nallow = [\"issues:read:team=ENG\", \"teams:read\"]\n");
    assert_eq!(
        verdict(m, &s, "issues.list", &[("team", "ENG")]),
        Verdict::Allow
    );
    assert_eq!(
        verdict(m, &s, "issues.list", &[("team", "OPS")]),
        deny_default()
    );
    assert_eq!(verdict(m, &s, "issues.list", &[]), deny_default());
    assert_eq!(verdict(m, &s, "teams.list", &[]), Verdict::Allow);
    for id in ["issues.create", "issues.comment"] {
        assert_eq!(
            verdict(m, &s, id, &[("team_id", "ENG")]),
            deny_default(),
            "{id}"
        );
    }
    let ask = svc_cfg("connector = \"linear\"\nask = [\"issues:write\"]\n");
    assert_eq!(
        verdict(m, &ask, "issues.create", &[("team_id", "t")]),
        Verdict::Ask
    );
    assert_eq!(verdict(m, &ask, "issues.comment", &[]), Verdict::Ask);
}

// ---------------------------------------------------------------- Intercom

fn intercom() -> &'static Manifest {
    manifest("intercom")
}

const IC_SVC: [(&str, &str); 2] = [("host", "api.eu.intercom.io"), ("api_version", "2.11")];

#[test]
fn intercom_manifest() {
    let m = intercom();
    m.check().unwrap();
    assert_eq!(m.base_url, "https://{host}");
    assert_eq!(
        m.hosts,
        [
            "api.intercom.io",
            "api.eu.intercom.io",
            "api.au.intercom.io"
        ]
    );
    assert_eq!(m.headers["Intercom-Version"], "{api_version}");
    assert!(m.params["host"].required && m.params["api_version"].required);
    assert_eq!(
        table(m),
        [
            ("contacts.list", "contacts:read", OpKind::Read),
            ("contacts.get", "contacts:read", OpKind::Read),
            ("conversations.list", "conversations:read", OpKind::Read),
            ("conversations.get", "conversations:read", OpKind::Read),
            ("conversations.reply", "conversations:write", OpKind::Write),
        ]
    );
}

#[test]
fn intercom_host_and_version_header() {
    let tok = token("intercom");
    let b = built(
        intercom(),
        "contacts.get",
        &IC_SVC,
        &[("contact_id", "530370b477ad7120001d")],
        &[("Accept", "application/json"), ("Intercom-Version", "0.1")],
        &tok,
    )
    .unwrap();
    assert_eq!(
        b.uri.to_string(),
        "https://api.eu.intercom.io/contacts/530370b477ad7120001d"
    );
    // The fixed header wins over the agent's.
    assert_eq!(b.headers.get("intercom-version").unwrap(), "2.11");
    assert_eq!(
        b.headers.get("authorization").unwrap().to_str().unwrap(),
        format!("Bearer {tok}")
    );
    for host in ["api.intercom.io", "api.au.intercom.io"] {
        let svc = [("host", host), ("api_version", "2.11")];
        let b = built(intercom(), "contacts.list", &svc, &[], &[], &tok).unwrap();
        assert_eq!(b.uri.to_string(), format!("https://{host}/contacts"));
    }
}

#[test]
fn intercom_bad_host_or_version_is_refused() {
    let tok = token("intercom");
    for host in [
        "evil.test",
        "api.intercom.io.evil.test",
        "api.intercom.io@evil.test",
        "api.intercom.io:8443",
        "API.INTERCOM.IO",
        "",
    ] {
        let svc = [("host", host), ("api_version", "2.11")];
        assert!(
            built(intercom(), "contacts.list", &svc, &[], &[], &tok).is_err(),
            "{host:?}"
        );
    }
    for v in ["2", "2.11.1", "latest", "2.11\r\nX: y", ""] {
        let svc = [("host", "api.intercom.io"), ("api_version", v)];
        let r = built(intercom(), "contacts.list", &svc, &[], &[], &tok);
        // The pattern is the admin's check at policy load; the request is
        // still never built with a header holding CR or LF.
        if let Ok(b) = r {
            let h = b.headers.get("intercom-version").unwrap().to_str().unwrap();
            assert!(!h.contains(['\r', '\n']), "{v:?}");
        }
    }
    let spec = &intercom().params["api_version"];
    let ty = spec.param_type().unwrap();
    for ok in ["2.11", "2.0", "10.4"] {
        assert!(ty.check(ok).is_ok(), "{ok}");
    }
    for bad in ["2", "2.11.1", "v2.11", "2.11\n", " 2.11", "2.x"] {
        assert!(ty.check(bad).is_err(), "{bad:?}");
    }
    // Missing service params fail.
    assert!(built(intercom(), "contacts.list", &[], &[], &[], &tok).is_err());
}

#[test]
fn intercom_pagination() {
    let p = op(intercom(), "contacts.list").pagination.clone().unwrap();
    assert_eq!(
        p,
        Pagination::Cursor {
            param: "starting_after".into(),
            next: "pages.next.starting_after".into(),
            more: None,
        }
    );
    let (param, cur) = next_cursor(&p, &fixture("intercom", "contacts_list")).unwrap();
    assert_eq!(param, "starting_after");
    assert_eq!(cur, "WzE3MDAwMDAwMDAwMDAsNTMwMzcwYjQ3N2FkNzEyMDAwMWUsMl0=");
    assert_eq!(
        next_cursor(&p, &fixture("intercom", "contacts_list_last")),
        None
    );
    let tok = token("intercom");
    let b = built(
        intercom(),
        "contacts.list",
        &IC_SVC,
        &[("starting_after", cur.as_str()), ("per_page", "2")],
        &[],
        &tok,
    )
    .unwrap();
    assert_eq!(
        b.uri.to_string(),
        "https://api.eu.intercom.io/contacts?per_page=2&starting_after=WzE3MDAwMDAwMDAwMDAsNTMwMzcwYjQ3N2FkNzEyMDAwMWUsMl0%3D"
    );
    let c = op(intercom(), "conversations.list")
        .pagination
        .clone()
        .unwrap();
    assert_eq!(
        next_cursor(&c, &fixture("intercom", "conversations_list"))
            .unwrap()
            .1,
        "WzE3MDAwMDAwMDAwMDAsMjE1NDY3MDAwMDAwMDAxLDJd"
    );
}

#[test]
fn intercom_reply_body_is_built() {
    let tok = token("intercom");
    let b = built(
        intercom(),
        "conversations.reply",
        &IC_SVC,
        &[
            ("conversation_id", "215467000000001"),
            ("message_type", "note"),
            ("admin_id", "3156780"),
            ("body", "Checked with ops."),
        ],
        &[("Content-Type", "application/json")],
        &tok,
    )
    .unwrap();
    assert_eq!(b.method, "POST");
    assert_eq!(
        b.uri.to_string(),
        "https://api.eu.intercom.io/conversations/215467000000001/reply"
    );
    let body: Value = serde_json::from_slice(&b.body.unwrap()).unwrap();
    assert_eq!(
        body,
        json!({"type": "admin", "message_type": "note", "admin_id": "3156780", "body": "Checked with ops."})
    );
    // The agent cannot send a raw body or change the author type.
    let raw = Bytes::from_static(br#"{"type":"user","body":"x"}"#);
    assert_eq!(
        prepare_body(
            op(intercom(), "conversations.reply"),
            &BTreeMap::new(),
            Some(&raw)
        )
        .unwrap_err(),
        "bad_param"
    );
    assert!(validate(
        op(intercom(), "conversations.reply"),
        &map(&[("conversation_id", "1"), ("type", "user")]),
        &BTreeMap::new()
    )
    .is_err());
    assert!(validate(
        op(intercom(), "conversations.reply"),
        &map(&[("conversation_id", "1"), ("message_type", "close")]),
        &BTreeMap::new()
    )
    .is_err());
}

#[test]
fn intercom_proxy_and_policy() {
    let m = intercom();
    let id = |method: &str, path: &str| proxy(m, method, path).map(|(o, _)| o.id.clone());
    assert_eq!(id("GET", "/contacts?per_page=5").unwrap(), "contacts.list");
    assert_eq!(id("GET", "/conversations/1").unwrap(), "conversations.get");
    assert_eq!(
        id("POST", "/conversations/1/reply").unwrap(),
        "conversations.reply"
    );
    assert!(id("DELETE", "/contacts/1").is_err());
    assert!(id("POST", "/contacts").is_err());
    assert!(id("POST", "/messages").is_err());
    let ro =
        svc_cfg("connector = \"intercom\"\nallow = [\"contacts:read\", \"conversations:read\"]\n");
    assert_eq!(verdict(m, &ro, "contacts.get", &[]), Verdict::Allow);
    assert_eq!(verdict(m, &ro, "conversations.reply", &[]), deny_default());
    let ask = svc_cfg(
        "connector = \"intercom\"\nallow = [\"contacts:read\"]\nask = [\"conversations:write\"]\n",
    );
    assert_eq!(verdict(m, &ask, "conversations.reply", &[]), Verdict::Ask);
}

#[test]
fn intercom_base64_cursor_plus_is_encoded() {
    let p = op(intercom(), "contacts.list").pagination.clone().unwrap();
    let body = json!({"pages": {"next": {"starting_after": "ab+cd=="}}});
    assert_eq!(next_cursor(&p, &body).unwrap().1, "ab+cd==");
    let tok = token("intercom");
    let b = built(
        intercom(),
        "conversations.list",
        &IC_SVC,
        &[("starting_after", "ab+cd==")],
        &[],
        &tok,
    )
    .unwrap();
    assert_eq!(
        b.uri.to_string(),
        "https://api.eu.intercom.io/conversations?starting_after=ab%2Bcd%3D%3D"
    );
    // No other connector's cursor pattern accepts `+`, except GCS, whose
    // `nextPageToken` is standard base64 like Intercom's (and is encoded the
    // same way, as `%2B`).
    for m in builtin()
        .iter()
        .filter(|m| m.id != "intercom" && m.id != "gcp-storage")
    {
        for o in &m.operation {
            if let Some(Pagination::Cursor { param, .. }) = &o.pagination {
                let ty = o.query.get(param).or_else(|| o.body_params.get(param));
                let ty = saiife_broker::params::ParamType::parse(ty.unwrap(), None).unwrap();
                assert!(ty.check("a+b").is_err(), "{} {}", m.id, o.id);
            }
        }
    }
}

// ---------------------------------------------------------------- Airtable

fn airtable() -> &'static Manifest {
    manifest("airtable")
}

const BASE: (&str, &str) = ("base_id", "appAbCdEfGhIjKlMn");

#[test]
fn airtable_manifest() {
    let m = airtable();
    m.check().unwrap();
    assert_eq!(m.base_url, "https://api.airtable.com/v0");
    assert_eq!(
        table(m),
        [
            ("records.list", "records:read", OpKind::Read),
            ("records.get", "records:read", OpKind::Read),
            ("records.create", "records:write", OpKind::Write),
            ("records.update", "records:write", OpKind::Write),
            ("records.delete", "records:delete", OpKind::Delete),
        ]
    );
    for o in &m.operation {
        assert_eq!(o.qualifier.as_deref(), Some("base={base_id}"), "{}", o.id);
        assert!(o.amount.is_none());
    }
    // No bases.list: /meta/bases would collide with /{base_id}/{table}.
    assert!(named(m, "bases.list").is_none());
}

#[test]
fn airtable_requests() {
    let tok = token("airtable");
    let b = built(
        airtable(),
        "records.list",
        &[],
        &[
            BASE,
            ("table", "Tasks"),
            ("pageSize", "2"),
            ("view", "Grid view"),
        ],
        &[],
        &tok,
    )
    .unwrap();
    assert_eq!(
        b.uri.to_string(),
        "https://api.airtable.com/v0/appAbCdEfGhIjKlMn/Tasks?pageSize=2&view=Grid%20view"
    );
    assert_eq!(
        b.headers.get("authorization").unwrap().to_str().unwrap(),
        format!("Bearer {tok}")
    );
    let b = built(
        airtable(),
        "records.update",
        &[],
        &[
            BASE,
            ("table", "tblXyz123"),
            ("record_id", "recAbCdEfGh12345"),
        ],
        &[("Content-Type", "application/json")],
        &tok,
    );
    assert!(b.is_ok());
    let b = built(
        airtable(),
        "records.delete",
        &[],
        &[
            BASE,
            ("table", "tblXyz123"),
            ("record_id", "recAbCdEfGh12345"),
        ],
        &[],
        &tok,
    )
    .unwrap();
    assert_eq!(b.method, "DELETE");
    assert_eq!(
        b.uri.to_string(),
        "https://api.airtable.com/v0/appAbCdEfGhIjKlMn/tblXyz123/recAbCdEfGh12345"
    );
}

#[test]
fn airtable_ids_are_one_segment() {
    let o = op(airtable(), "records.get");
    for bad in [
        [
            ("base_id", "meta"),
            ("table", "bases"),
            ("record_id", "recAbCdEfGh12345"),
        ],
        [
            ("base_id", "appAbCdEfGhIjKlMn"),
            ("table", ".."),
            ("record_id", "recAbCdEfGh12345"),
        ],
        [
            ("base_id", "appAbCdEfGhIjKlMn"),
            ("table", "a/b"),
            ("record_id", "recAbCdEfGh12345"),
        ],
        [
            ("base_id", "appAbCdEfGhIjKlMn"),
            ("table", "t"),
            ("record_id", "rec/../x"),
        ],
        [
            ("base_id", "app1/../x"),
            ("table", "t"),
            ("record_id", "recAbCdEfGh12345"),
        ],
    ] {
        assert!(
            validate(o, &map(&bad), &BTreeMap::new()).is_err(),
            "{bad:?}"
        );
    }
}

#[test]
fn airtable_offset_pagination_keeps_the_slash() {
    let p = op(airtable(), "records.list").pagination.clone().unwrap();
    assert_eq!(
        p,
        Pagination::Cursor {
            param: "offset".into(),
            next: "offset".into(),
            more: None
        }
    );
    let (param, cur) = next_cursor(&p, &fixture("airtable", "records_list")).unwrap();
    assert_eq!(param, "offset");
    assert_eq!(cur, "itrJpWBvDzAuqzZ6j/recZyXwVuTs67890");
    assert_eq!(
        next_cursor(&p, &fixture("airtable", "records_list_last")),
        None
    );
    let tok = token("airtable");
    let b = built(
        airtable(),
        "records.list",
        &[],
        &[BASE, ("table", "Tasks"), ("offset", cur.as_str())],
        &[],
        &tok,
    )
    .unwrap();
    assert_eq!(
        b.uri.to_string(),
        "https://api.airtable.com/v0/appAbCdEfGhIjKlMn/Tasks?offset=itrJpWBvDzAuqzZ6j%2FrecZyXwVuTs67890"
    );
    // A cursor with a dot-dot or a space is refused by the op's own pattern.
    for bad in ["../x", "a b", "a?b", "a&b"] {
        assert!(
            validate(
                op(airtable(), "records.list"),
                &map(&[BASE, ("table", "T"), ("offset", bad)]),
                &BTreeMap::new()
            )
            .is_err(),
            "{bad:?}"
        );
    }
}

#[test]
fn airtable_proxy_resolution() {
    let m = airtable();
    let id = |method: &str, path: &str| proxy(m, method, path).map(|(o, _)| o.id.clone());
    assert_eq!(
        id("GET", "/appAbCdEfGhIjKlMn/Tasks").unwrap(),
        "records.list"
    );
    assert_eq!(
        id("GET", "/appAbCdEfGhIjKlMn/Tasks/recAbCdEfGh12345").unwrap(),
        "records.get"
    );
    assert_eq!(
        id("POST", "/appAbCdEfGhIjKlMn/Tasks").unwrap(),
        "records.create"
    );
    assert_eq!(
        id("PATCH", "/appAbCdEfGhIjKlMn/Tasks/recAbCdEfGh12345").unwrap(),
        "records.update"
    );
    assert_eq!(
        id("DELETE", "/appAbCdEfGhIjKlMn/Tasks/recAbCdEfGh12345").unwrap(),
        "records.delete"
    );
    // /meta/bases resolves to records.list with base_id=meta, which the
    // base_id pattern then refuses: the agent cannot list bases.
    let (o, params) = proxy(m, "GET", "/meta/bases").unwrap();
    assert_eq!(o.id, "records.list");
    assert!(validate(o, &params, &BTreeMap::new()).is_err());
    assert!(id("PUT", "/appAbCdEfGhIjKlMn/Tasks").is_err());
}

#[test]
fn airtable_base_qualifier_policy() {
    let m = airtable();
    let t = ("table", "Tasks");
    let rec = ("record_id", "recAbCdEfGh12345");
    let s = svc_cfg(
        "connector = \"airtable\"\nallow = [\"records:read\", \"records:write:base=appAbCdEfGhIjKlMn\"]\nask = [\"records:delete\"]\n",
    );
    assert_eq!(verdict(m, &s, "records.list", &[BASE, t]), Verdict::Allow);
    assert_eq!(verdict(m, &s, "records.create", &[BASE, t]), Verdict::Allow);
    let other = ("base_id", "appZzZzZzZzZzZzZz");
    assert_eq!(
        verdict(m, &s, "records.create", &[other, t]),
        deny_default()
    );
    assert_eq!(
        verdict(m, &s, "records.delete", &[BASE, t, rec]),
        Verdict::Ask
    );
    let ro = svc_cfg(
        "connector = \"airtable\"\nallow = [\"records:read\"]\ndeny = [\"records:delete\"]\n",
    );
    assert_eq!(
        verdict(m, &ro, "records.update", &[BASE, t, rec]),
        deny_default()
    );
    assert!(matches!(
        verdict(m, &ro, "records.delete", &[BASE, t, rec]),
        Verdict::Deny { ref rule } if rule.starts_with("deny:")
    ));
}
