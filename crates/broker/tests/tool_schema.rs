//! MCP tool names and input schemas from connector manifests (plan 17
//! Task 3): every built-in connector, and the exact schemas of the ones
//! agents use most.

use saiife_broker::manifest::{builtin, Manifest, Operation};
use saiife_broker::params::ParamType;
use saiife_broker::tool_schema::{
    body_arg, input_schema, param_schema, tool_name, BodyArg, MAX_TOOL_NAME,
    OBJECT_KEY_DESCRIPTION, OBJECT_NAME_DESCRIPTION, RAW_BODY_DESCRIPTION,
};
use saiife_policy::ServiceCfg;
use serde_json::{json, Value};

const ECHO: &str = include_str!("../connectors/test-echo.toml");

fn svc(toml_text: &str) -> ServiceCfg {
    toml::from_str(toml_text).unwrap()
}

fn plain(connector: &str) -> ServiceCfg {
    svc(&format!("connector = {connector:?}"))
}

fn manifest(id: &str) -> &'static Manifest {
    builtin()
        .iter()
        .find(|m| m.id == id)
        .unwrap_or_else(|| panic!("no built-in {id}"))
}

fn op<'a>(m: &'a Manifest, id: &str) -> &'a Operation {
    m.operation.iter().find(|o| o.id == id).unwrap()
}

fn schema_of(connector: &str, op_id: &str) -> Value {
    let m = manifest(connector);
    input_schema(m, op(m, op_id), &plain(connector))
}

/// The property names, sorted (`serde_json` may keep insertion order).
fn props(s: &Value) -> Vec<String> {
    let mut k: Vec<String> = s["properties"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    k.sort();
    k
}

/// The anchored source the broker checks for `string:<re>`.
fn anchored(re: &str) -> String {
    format!("^(?:{re})$")
}

#[test]
fn schema_for_test_echo_orders_list() {
    let m = Manifest::parse(ECHO).unwrap();
    let s = input_schema(
        &m,
        op(&m, "orders.list"),
        &svc("connector = \"test-echo\"\nparams = { shop = \"acme\" }"),
    );
    assert_eq!(
        s,
        json!({
            "type": "object",
            "properties": {
                "status": {"type": "string", "enum": ["open", "closed", "cancelled", "any"]},
                "limit": {"type": "integer", "minimum": 1, "maximum": 250},
                "since_id": {"type": "integer"},
                "created_at_min": {"type": "string", "format": "date-time"},
            },
            "additionalProperties": false,
        })
    );
}

#[test]
fn fixed_and_service_params_hidden() {
    let m = Manifest::parse(ECHO).unwrap();
    // `status` is fixed by the policy; `limit` collides with a service
    // param name: neither is the agent's to give.
    let s = input_schema(
        &m,
        op(&m, "orders.list"),
        &svc(
            "connector = \"test-echo\"\nparams = { shop = \"acme\", limit = \"5\" }\n\
              fixed = { status = \"open\" }",
        ),
    );
    assert_eq!(props(&s), vec!["created_at_min", "since_id"]);
    // The service param `shop` (base_url) is never a property.
    for o in &m.operation {
        let s = input_schema(&m, o, &plain("test-echo"));
        assert!(s["properties"].get("shop").is_none(), "{}", o.id);
    }
}

#[test]
fn path_params_required() {
    let m = Manifest::parse(ECHO).unwrap();
    let s = input_schema(&m, op(&m, "orders.get"), &plain("test-echo"));
    assert_eq!(s["properties"]["order_id"], json!({"type": "integer"}));
    assert_eq!(s["required"], json!(["order_id"]));
    // No path params: no `required` at all.
    let s = input_schema(&m, op(&m, "orders.list"), &plain("test-echo"));
    assert!(s.get("required").is_none(), "{s}");
}

#[test]
fn json_body_property() {
    let m = Manifest::parse(ECHO).unwrap();
    let o = op(&m, "refunds.create");
    let s = input_schema(&m, o, &plain("test-echo"));
    assert_eq!(s["properties"]["body"], json!({"type": "object"}));
    assert_eq!(s["required"], json!(["order_id"]));
    assert_eq!(body_arg(o), Some(BodyArg::Json));
    // Sent as its compact JSON; anything but an object is refused.
    assert_eq!(
        BodyArg::Json.encode(&json!({"a": 1})).unwrap(),
        br#"{"a":1}"#
    );
    assert_eq!(BodyArg::Json.encode(&json!("x")), None);
    assert_eq!(BodyArg::Json.encode(&json!([1])), None);
}

#[test]
fn stripe_refunds_create_schema() {
    let s = schema_of("stripe", "refunds.create");
    assert_eq!(
        s,
        json!({
            "type": "object",
            "properties": {
                "payment_intent": {"type": "string", "pattern": anchored("pi_[A-Za-z0-9]{1,64}")},
                "charge": {"type": "string", "pattern": anchored("(ch|py)_[A-Za-z0-9]{1,64}")},
                "amount": {"type": "integer", "minimum": 1, "maximum": 99999999},
                "reason": {"type": "string",
                           "enum": ["duplicate", "fraudulent", "requested_by_customer"]},
            },
            "additionalProperties": false,
        })
    );
    let m = manifest("stripe");
    assert_eq!(body_arg(op(m, "refunds.create")), None);
}

#[test]
fn slack_chat_post_message_schema() {
    let s = schema_of("slack", "chat.postMessage");
    assert_eq!(props(&s), vec!["channel", "text", "thread_ts"]);
    assert_eq!(
        s["properties"]["channel"],
        json!({"type": "string", "pattern": anchored("[CGD][A-Z0-9]{2,31}")})
    );
    assert!(s["properties"].get("body").is_none());
    assert_eq!(s["additionalProperties"], false);
    assert_eq!(
        tool_name("slack", "chat.postMessage").unwrap(),
        "slack_chat_postMessage"
    );
}

#[test]
fn linear_graphql_op_schema() {
    let s = schema_of("linear", "issues.create");
    assert_eq!(
        s,
        json!({
            "type": "object",
            "properties": {
                "team_id": {"type": "string", "pattern": anchored("[A-Za-z0-9-]{1,64}")},
                "title": {"type": "string", "pattern": anchored(".{1,256}")},
                "description": {"type": "string"},
            },
            "additionalProperties": false,
        })
    );
    // A variable named `body` is a param, never the free body.
    let m = manifest("linear");
    let o = op(m, "issues.comment");
    let s = input_schema(m, o, &plain("linear"));
    assert_eq!(s["properties"]["body"], json!({"type": "string"}));
    assert_eq!(body_arg(o), None);
    for o in &m.operation {
        let s = input_schema(m, o, &plain("linear"));
        assert!(s["properties"].get("query").is_none(), "{}", o.id);
    }
}

#[test]
fn mail_send_schema() {
    let m = manifest("email");
    let o = op(m, "mail.send");
    let s = input_schema(
        m,
        o,
        &svc(
            "connector = \"email\"\nparams = { smtp_host = \"smtp.x.test\", \
              imap_host = \"imap.x.test\", from = \"bot@x.test\" }",
        ),
    );
    assert_eq!(props(&s), vec!["body", "subject", "to"]);
    assert_eq!(s["properties"]["body"], json!({"type": "string"}));
    assert_eq!(
        s["properties"]["subject"],
        json!({"type": "string", "pattern": anchored(".{1,998}")})
    );
    let to = s["properties"]["to"]["pattern"].as_str().unwrap();
    assert!(to.starts_with("^(?:[^@\\s,;<>%!]{1,64}@"), "{to}");
    // `from` is an admin (service) param.
    assert!(s["properties"].get("from").is_none());
}

#[test]
fn text_body_sent_as_utf8() {
    let m = manifest("email");
    let arg = body_arg(op(m, "mail.send")).unwrap();
    assert_eq!(arg, BodyArg::Text);
    assert_eq!(arg.as_str(), "text");
    assert_eq!(
        arg.encode(&json!("Grüße\nline two")).unwrap(),
        "Grüße\nline two".as_bytes()
    );
    // An object is not a text body.
    assert_eq!(arg.encode(&json!({"a": 1})), None);
}

#[test]
fn form_without_body_params_has_no_body() {
    let mut m = Manifest::parse(ECHO).unwrap();
    let mut o = op(&m, "refunds.create").clone();
    o.body = Some("form".into());
    o.amount = None;
    m.operation = vec![o.clone()];
    let s = input_schema(&m, &o, &plain("test-echo"));
    assert_eq!(props(&s), vec!["order_id"]);
    assert_eq!(body_arg(&o), None);
}

#[test]
fn body_const_fields_hidden() {
    // Intercom's reply: `type` is a fixed body field, `body` a param.
    let m = manifest("intercom");
    let o = m
        .operation
        .iter()
        .find(|o| !o.body_const.is_empty())
        .unwrap();
    let s = input_schema(m, o, &plain("intercom"));
    for k in o.body_const.keys() {
        assert!(s["properties"].get(k).is_none(), "{k}");
    }
    assert_eq!(body_arg(o), None);
}

#[test]
fn param_schema_table() {
    let t = |spec: &str| param_schema(&ParamType::parse(spec, None).unwrap());
    assert_eq!(t("string"), json!({"type": "string"}));
    assert_eq!(
        t("string:[a-z]+"),
        json!({"type": "string", "pattern": "^(?:[a-z]+)$"})
    );
    assert_eq!(t("int"), json!({"type": "integer"}));
    assert_eq!(t("int:5.."), json!({"type": "integer", "minimum": 5}));
    assert_eq!(t("int:..9"), json!({"type": "integer", "maximum": 9}));
    assert_eq!(t("enum:a,b"), json!({"type": "string", "enum": ["a", "b"]}));
    assert_eq!(
        t("datetime"),
        json!({"type": "string", "format": "date-time"})
    );
    assert_eq!(t("bool"), json!({"type": "boolean"}));
}

#[test]
fn tool_name_table() {
    assert_eq!(
        tool_name("test-echo", "orders.list").as_deref(),
        Some("test_echo_orders_list")
    );
    assert_eq!(
        tool_name("shopify", "orders.list").as_deref(),
        Some("shopify_orders_list")
    );
    // 51 chars fit; 52 do not.
    let svc51 = "s".repeat(MAX_TOOL_NAME - 2);
    assert_eq!(tool_name(&svc51, "x").map(|n| n.len()), Some(51));
    let svc52 = "s".repeat(MAX_TOOL_NAME - 1);
    assert_eq!(tool_name(&svc52, "x"), None);
    // `__` is the gateway namespace, also when made by the mapping.
    assert_eq!(tool_name("a", "_b"), None);
    assert_eq!(tool_name("a_", "b"), None);
    assert_eq!(tool_name("a", "x.-y"), None);
    assert_eq!(tool_name("a__b", "c"), None);
    // Reserved, empty and odd chars.
    assert_eq!(tool_name("saiife", "result"), None);
    assert_eq!(tool_name("", "x"), None);
    assert_eq!(tool_name("a", ""), None);
    assert_eq!(tool_name("a", "b/c"), None);
    assert_eq!(tool_name("a", "b c"), None);
}

/// Every operation of every built-in connector gets a well-formed schema:
/// an object with `additionalProperties: false`, `required` ⊆ properties,
/// every property typed, and `body` only as the free body or a param.
#[test]
fn every_builtin_op_has_a_schema() {
    let mut n = 0;
    for m in builtin() {
        let s = plain(&m.id);
        for o in &m.operation {
            let sch = input_schema(m, o, &s);
            let what = format!("{} {}", m.id, o.id);
            assert_eq!(sch["type"], "object", "{what}");
            assert_eq!(sch["additionalProperties"], false, "{what}");
            let p = sch["properties"].as_object().unwrap();
            for (k, v) in p {
                assert!(v["type"].is_string(), "{what} {k}: {v}");
            }
            if let Some(r) = sch.get("required") {
                for k in r.as_array().unwrap() {
                    assert!(p.contains_key(k.as_str().unwrap()), "{what} {k}");
                }
            }
            // Every declared param that is not a service param is listed.
            for k in o
                .path_params
                .keys()
                .chain(o.query.keys())
                .chain(o.body_params.keys())
            {
                if !m.params.contains_key(k) && !o.body_const.contains_key(k) {
                    assert!(p.contains_key(k), "{what}: {k} missing");
                }
            }
            let free = body_arg(o);
            if o.builds_body() {
                assert_eq!(free, None, "{what}");
            }
            match free {
                Some(BodyArg::Json) => assert_eq!(p["body"], json!({"type": "object"})),
                Some(BodyArg::Text) if o.body.as_deref() == Some("raw") => assert_eq!(
                    p["body"],
                    json!({"type": "string", "description": RAW_BODY_DESCRIPTION})
                ),
                Some(BodyArg::Text) => assert_eq!(p["body"], json!({"type": "string"})),
                None => assert!(
                    !p.contains_key("body")
                        || o.body_params.contains_key("body")
                        || o.query.contains_key("body")
                        || o.path_params.contains_key("body"),
                    "{what}"
                ),
            }
            // A tool name fits for every built-in operation.
            assert!(tool_name(&m.id, &o.id).is_some(), "{what}");
            n += 1;
        }
    }
    assert!(n > 100, "only {n} operations");
}

/// Plan 15's `objectkey` path param and `raw` body: the key is a string
/// with the key rules; the body is a string, sent as its UTF-8 bytes
/// (`prepare_body` takes a raw body unparsed).
#[test]
fn s3_put_object_schema() {
    let o = op(manifest("aws-s3"), "s3.put_object");
    assert_eq!(body_arg(o), Some(BodyArg::Text));
    let s = schema_of("aws-s3", "s3.put_object");
    assert_eq!(
        s,
        json!({
            "type": "object",
            "properties": {
                "bucket": {
                    "type": "string",
                    "pattern": anchored("[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]"),
                },
                "key": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 1024,
                    "description": OBJECT_KEY_DESCRIPTION,
                },
                "body": {"type": "string", "description": RAW_BODY_DESCRIPTION},
            },
            "required": ["bucket", "key"],
            "additionalProperties": false,
        })
    );
    assert!(OBJECT_KEY_DESCRIPTION.contains("1024 bytes"));
    // A raw body is the string's bytes, as given.
    assert_eq!(
        BodyArg::Text.encode(&json!("a,b\n1,2\n")).unwrap(),
        b"a,b\n1,2\n"
    );
    assert_eq!(BodyArg::Text.encode(&json!({"a": 1})), None);
}

/// Plan 15's `objectname` (GCS): a string with the same key rules, sent
/// whole.
#[test]
fn objectname_param_schema() {
    assert_eq!(
        param_schema(&ParamType::ObjectName),
        json!({
            "type": "string",
            "minLength": 1,
            "maxLength": 1024,
            "description": OBJECT_NAME_DESCRIPTION,
        })
    );
    assert!(OBJECT_NAME_DESCRIPTION.contains("%2F"));
    let gcs = manifest("gcp-storage");
    let with_name: Vec<&Operation> = gcs
        .operation
        .iter()
        .filter(|o| o.path_params.values().any(|t| t == "objectname"))
        .collect();
    assert!(!with_name.is_empty());
    for o in with_name {
        let s = input_schema(gcs, o, &plain("gcp-storage"));
        let (name, _) = o
            .path_params
            .iter()
            .find(|(_, t)| *t == "objectname")
            .unwrap();
        assert_eq!(
            s["properties"][name]["description"], OBJECT_NAME_DESCRIPTION,
            "{}",
            o.id
        );
    }
}
