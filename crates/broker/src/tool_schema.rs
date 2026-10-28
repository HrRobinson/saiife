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
    /// `body = "text"` (and plan 15's `"raw"`): a string, sent as its
    /// UTF-8 bytes.
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

// Plan 15 adds `body = "raw"` to `BODY_FORMATS`. This stops the build until
// `body_arg` below maps it (to `BodyArg::Text`): plan 17 owns the mapping.
const _: () = assert!(
    crate::manifest::BODY_FORMATS.len() == 3,
    "a new body format: map it in tool_schema::body_arg (plan 15's raw is BodyArg::Text)"
);

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
        Some("text") => Some(BodyArg::Text),
        // `form` without body_params, none, or a format the manifest check
        // refuses: no body argument (fail closed).
        _ => None,
    }
}

/// The JSON Schema of one param type. The match is exhaustive on purpose:
/// plan 15's `ObjectKey` and `ObjectName` stop the build here until they
/// are mapped, to `{"type":"string","maxLength":1024}` (plan 17 owns it).
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
        // PLAN 15: ParamType::ObjectKey | ParamType::ObjectName =>
        //     json!({"type": "string", "maxLength": 1024}),
    }
}

/// The input schema of the tool for `op` of service `svc` (manifest `m`):
/// path, query and body params as properties (path params `required`),
/// params the policy fixes and service params left out, the free `body`
/// per [`body_arg`], and `additionalProperties: false`.
pub fn input_schema(_m: &Manifest, op: &Operation, svc: &ServiceCfg) -> Value {
    // Destructured without `..`: a new operation field (plan 15's
    // `fixed_query` and per-op `headers`) stops the build here until it is
    // decided whether the schema shows it. Plan 15's fixed values are set
    // by the manifest, never by the agent: leave them out.
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
    } = op;
    let hidden = |name: &str| {
        svc.fixed.contains_key(name)
            || svc.params.contains_key(name)
            || body_const.contains_key(name)
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
