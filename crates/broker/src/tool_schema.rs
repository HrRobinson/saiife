//! MCP tool names and input schemas generated from connector manifests
//! (plan 17 decisions 4 and 5).
//!
//! A tool's arguments are the operation's call params plus, for an
//! operation that takes an agent body, one `body` argument. Every argument
//! is sent the way `saiife api` sends it: params as strings, `body` as
//! `body_b64` (of its compact JSON for [`BodyArg::Json`], of its UTF-8
//! bytes for [`BodyArg::Text`]). The schema describes; the daemon still
//! validates every value (`params::validate`), so a schema is never a
//! control.

use crate::manifest::{Manifest, Operation};
use crate::params::ParamType;
use saiife_policy::ServiceCfg;
use serde_json::{json, Map, Value};

/// Claude's `mcp__saiife__` prefix plus the name must fit 64 chars.
pub const MAX_TOOL_NAME: usize = 51;
/// The built-in result tool of `saiife mcp`; no connector tool may take it.
pub const RESULT_TOOL: &str = "saiife_result";

/// The connector tool name `<service>_<op>`, with `.` and `-` turned into
/// `_` (decision 5). `None` when the name is longer than
/// [`MAX_TOOL_NAME`], holds `__` (the gateway namespace), holds any other
/// char outside `[A-Za-z0-9_]`, or is reserved.
pub fn tool_name(service: &str, op_id: &str) -> Option<String> {
    if service.is_empty() || op_id.is_empty() {
        return None;
    }
    let name: String = format!("{service}_{op_id}")
        .chars()
        .map(|c| if c == '.' || c == '-' { '_' } else { c })
        .collect();
    let ok = name.len() <= MAX_TOOL_NAME
        && !name.contains("__")
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && name != RESULT_TOOL;
    ok.then_some(name)
}

/// How a tool's `body` argument is sent, when the operation takes an
/// agent body at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyArg {
    /// `body = "json"`: a JSON object, sent as its compact JSON.
    Json,
    /// `body = "text"` and `body = "raw"`: a string, sent as its UTF-8
    /// bytes. A raw body reaches the upstream as those bytes, never parsed;
    /// a binary upload cannot be sent as an MCP string.
    Text,
}

impl BodyArg {
    pub fn as_str(self) -> &'static str {
        match self {
            BodyArg::Json => "json",
            BodyArg::Text => "text",
        }
    }

    /// The bytes sent as `body_b64` for the argument `v`; `None` when `v`
    /// has the wrong shape (an object for `Json`, a string for `Text`).
    pub fn encode(self, v: &Value) -> Option<Vec<u8>> {
        match (self, v) {
            (BodyArg::Json, Value::Object(_)) => serde_json::to_vec(v).ok(),
            (BodyArg::Text, Value::String(s)) => Some(s.as_bytes().to_vec()),
            _ => None,
        }
    }
}

// A new entry in `BODY_FORMATS` stops the build until `body_arg` below
// maps it (`json`, `form`, `text`, `raw` are mapped).
const _: () = assert!(
    crate::manifest::BODY_FORMATS.len() == 4,
    "a new body format: map it in tool_schema::body_arg"
);

/// The description of an `objectkey` property (decision 5 of plan 15, as
/// `params::object_value_problem` checks it).
pub const OBJECT_KEY_DESCRIPTION: &str = "An object key: 1 to 1024 bytes; `/` separates \
    path segments and is kept; no empty, `.` or `..` segment, no backslash, no control \
    character, at any depth of percent-decoding.";
/// The description of an `objectname` property: the same rules, the whole
/// name sent as one segment (`/` as `%2F`).
pub const OBJECT_NAME_DESCRIPTION: &str = "An object name: 1 to 1024 bytes, sent whole \
    (`/` is encoded as %2F); no empty, `.` or `..` segment between `/`, no backslash, no \
    control character, at any depth of percent-decoding.";
/// The description of the `body` property of a `body = "raw"` operation.
pub const RAW_BODY_DESCRIPTION: &str =
    "The request body, sent as its UTF-8 bytes exactly as given (never parsed).";

/// The free `body` argument of `op`. None with a built body
/// (`body_params`, `body_const`, `graphql`: the agent sends params only),
/// for `form` (an agent form body is never sent as one argument), without
/// a body, and when a param of the operation is itself named `body`
/// (Linear's `issues.comment`, Intercom's reply): that name is the param.
pub fn body_arg(op: &Operation) -> Option<BodyArg> {
    if op.builds_body() || op.path_params.contains_key("body") || op.query.contains_key("body") {
        return None;
    }
    match op.body.as_deref() {
        Some("json") => Some(BodyArg::Json),
        // `raw` (plan 15): the agent's bytes as they are; over MCP, a
        // string's UTF-8 bytes (`prepare_body` takes them unparsed).
        Some("text") | Some("raw") => Some(BodyArg::Text),
        // `form` without body_params, none, or a format the manifest check
        // refuses: no body argument (fail closed).
        _ => None,
    }
}

/// The JSON Schema of one param type. The match is exhaustive on purpose:
/// a new param type stops the build here until it is mapped.
pub fn param_schema(t: &ParamType) -> Value {
    match t {
        ParamType::String { pattern: None } => json!({"type": "string"}),
        // The anchored source (`^(?:..)$`), exactly what the broker checks.
        ParamType::String { pattern: Some(re) } => {
            json!({"type": "string", "pattern": re.as_str()})
        }
        ParamType::Int { min, max } => {
            let mut o = Map::new();
            o.insert("type".into(), "integer".into());
            if let Some(m) = min {
                o.insert("minimum".into(), (*m).into());
            }
            if let Some(m) = max {
                o.insert("maximum".into(), (*m).into());
            }
            Value::Object(o)
        }
        ParamType::Enum(vals) => json!({"type": "string", "enum": vals}),
        ParamType::Datetime => json!({"type": "string", "format": "date-time"}),
        ParamType::Bool => json!({"type": "boolean"}),
        // `maxLength` counts chars, the broker bytes: the broker still
        // refuses a longer key.
        ParamType::ObjectKey => json!({
            "type": "string",
            "minLength": 1,
            "maxLength": crate::params::MAX_OBJECT_KEY,
            "description": OBJECT_KEY_DESCRIPTION,
        }),
        ParamType::ObjectName => json!({
            "type": "string",
            "minLength": 1,
            "maxLength": crate::params::MAX_OBJECT_KEY,
            "description": OBJECT_NAME_DESCRIPTION,
        }),
    }
}

/// The input schema of the tool for `op` of service `svc` (manifest `m`):
/// path, query and body params as properties (path params `required`),
/// params the policy fixes and service params left out, the free `body`
/// per [`body_arg`], and `additionalProperties: false`.
pub fn input_schema(_m: &Manifest, op: &Operation, svc: &ServiceCfg) -> Value {
    // Destructured without `..`: a new operation field stops the build
    // here until it is decided whether the schema shows it.
    let Operation {
        id: _,
        capability: _,
        qualifier: _,
        kind: _,
        method: _,
        path: _,
        path_params,
        query,
        body: _,
        body_params,
        // Fixed body fields: never an argument.
        body_const,
        // The fixed document: never an argument; its variables are
        // `body_params`.
        graphql: _,
        pagination: _,
        amount: _,
        // Plan 15: set by the manifest (headers fill `{param}` from service
        // params only), never by the agent: not arguments.
        headers: _,
        fixed_query,
        iam_action: _,
    } = op;
    let hidden = |name: &str| {
        svc.fixed.contains_key(name)
            || svc.params.contains_key(name)
            || body_const.contains_key(name)
            || fixed_query.contains_key(name)
    };
    let mut props = Map::new();
    let mut required = Vec::new();
    let all = path_params
        .iter()
        .map(|(n, t)| (n, t, true))
        .chain(query.iter().map(|(n, t)| (n, t, false)))
        .chain(body_params.iter().map(|(n, t)| (n, t, false)));
    for (name, ty, is_path) in all {
        if hidden(name) {
            continue;
        }
        // The manifest check parsed every type; one that does not parse is
        // left out (the agent cannot send it).
        let Ok(t) = ParamType::parse(ty, None) else {
            continue;
        };
        props.insert(name.clone(), param_schema(&t));
        if is_path {
            required.push(Value::String(name.clone()));
        }
    }
    match body_arg(op) {
        Some(BodyArg::Json) => {
            props.insert("body".into(), json!({"type": "object"}));
        }
        Some(BodyArg::Text) if op.body.as_deref() == Some("raw") => {
            props.insert(
                "body".into(),
                json!({"type": "string", "description": RAW_BODY_DESCRIPTION}),
            );
        }
        Some(BodyArg::Text) => {
            props.insert("body".into(), json!({"type": "string"}));
        }
        None => {}
    }
    let mut o = Map::new();
    o.insert("type".into(), "object".into());
    o.insert("properties".into(), Value::Object(props));
    if !required.is_empty() {
        o.insert("required".into(), Value::Array(required));
    }
    o.insert("additionalProperties".into(), false.into());
    Value::Object(o)
}
