//! Request and answer shapes.
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const PROTO: u64 = 1;
pub const SOCKET_NAME: &str = "saiife.sock";
/// The HTTP/1.1 connector gateway (spec §8.8), beside [`SOCKET_NAME`].
pub const GATEWAY_SOCKET_NAME: &str = "gateway.sock";
pub const OP_HELLO: &str = "hello";
pub const OP_AUDIT_APPEND: &str = "audit.append";
pub const OP_STATUS: &str = "status";
pub const OP_AUDIT_ROTATE_KEY: &str = "audit.rotate_key";
/// The caller's own audit records (an auditor: all with `all: true`).
/// `{since?, kind?, service?, agent?, project?, blocked?, all?, limit?
/// (<= 5000), after?, after_seq?}` -> `{records, more, next?, next_seq?}`.
/// `next` is an opaque log position to pass back as `after`; `after_seq`
/// and `next_seq` page by seq and are only exact on a single-chain log.
pub const OP_AUDIT_QUERY: &str = "audit.query";
pub const OP_SECRET_ADD: &str = "secret.add";
pub const OP_SECRET_ROTATE: &str = "secret.rotate";
pub const OP_SECRET_REMOVE: &str = "secret.remove";
pub const OP_SECRET_LIST: &str = "secret.list";
pub const OP_SECRET_LEASE: &str = "secret.lease";
pub const OP_API_CALL: &str = "api.call";
pub const OP_API_LIST: &str = "api.list";
pub const OP_API_RESULT: &str = "api.result";
/// A bearer token for the gateway's loopback TCP listener: `{token, expires}`.
pub const OP_API_TOKEN: &str = "api.token";
/// Turn lockdown on or off (admin or approver): `{on, scope?, reason?}`.
pub const OP_LOCKDOWN_SET: &str = "lockdown.set";
/// What a user may see of the policy: `{user?, effective?}` -> the user's
/// scope view, the policy `hash` and, with `effective`, the whole merged
/// policy. Anyone sees their own scope; `user` (another) and `effective`
/// are for root and `[admin] groups`.
pub const OP_POLICY_SHOW: &str = "policy.show";
/// Root and `[admin] groups`: load the policy again, as on SIGHUP.
/// `{}` -> `{result: "loaded"}` or `{result: "rejected", reason}`.
pub const OP_POLICY_RELOAD: &str = "policy.reload";
/// Approval requests: approvers see all, a requester its own.
/// `{states?: ["pending", ...], own?: bool}` -> `{items}`.
pub const OP_APPROVAL_LIST: &str = "approval.list";
/// `{request}` -> `{item}` (the masked request). The id is `request`: a
/// frame's `id` is its own.
pub const OP_APPROVAL_SHOW: &str = "approval.show";
/// `{request, action: "approve"|"reject", note?}` -> `{request, state}`.
pub const OP_APPROVAL_DECIDE: &str = "approval.decide";
/// The managed hook, for a call a `[guard] ask` rule denied: use up the
/// caller's grant for it. `{rec}` (the guard record it will send; the
/// daemon computes the key from the peer uid and `agent`, `project`,
/// `tool`, `input`) -> `{granted: bool, approval?}`.
pub const OP_GRANT_CONSUME: &str = "grant.consume";
/// The managed hook, when there was no grant: a command request for the
/// call. `{rec}` (with `pack` and `rule_id` naming the `[guard] ask`
/// rule) -> `{request}`.
pub const OP_APPROVAL_CREATE: &str = "approval.create";
/// The MCP gateway's tools for the caller (plan 17, Task 7):
/// `{overlays?: {"mcp:<name>": {allow, ask, deny}}}` ->
/// `{servers: [{name, tools: [{name, title?, description, inputSchema,
/// action}]}], tools_hash}`. Only the servers of the caller's scope that
/// are running, and only their tools whose action is `allow` or `ask`.
/// `tools_hash` is `sha256:<hex>` of the canonical JSON of `servers`.
pub const OP_MCP_LIST: &str = "mcp.list";
/// One `tools/call` of a gateway server, through the whole pipeline:
/// `{server, tool, arguments, project?, overlay?, via?}`. `arguments` is the
/// JSON text of the arguments object (a string: the daemon parses it,
/// refusing duplicate keys, so what the policy and the approver see is
/// what is sent); `overlay` is the project's `{allow, ask, deny}` for
/// `mcp:<server>`; `via` is `cli` or `mcp` (attribution only). Answers as
/// `api.call` does: `{status: null, result, truncated}` (`result` is the
/// masked `CallToolResult`), `{pending}`, or an error with code `denied`
/// (`rule`), `limited` (`limit`) or `upstream_failed` (`reason`).
pub const OP_MCP_CALL: &str = "mcp.call";

/// Largest `rec` that `audit.append` takes, as compact JSON
/// (`serde_json::to_vec`). The daemon refuses a larger one with
/// `bad_request`; the managed hook shrinks its record to fit, so a denied
/// call can never escape the audit record. Shared so the two never
/// disagree.
pub const MAX_RECORD_BYTES: usize = 64 * 1024;

#[derive(Clone, PartialEq)]
pub struct Request {
    pub id: u64,
    pub op: String,
    pub args: Map<String, Value>,
}

/// `args` can hold a secret value (`secret.add` fields): Debug shows the
/// keys only.
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("id", &self.id)
            .field("op", &self.op)
            .field("args", &self.args.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl Request {
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("id".into(), Value::from(self.id));
        m.insert("op".into(), Value::from(self.op.clone()));
        for (k, v) in &self.args {
            if k != "id" && k != "op" {
                m.insert(k.clone(), v.clone());
            }
        }
        Value::Object(m)
    }

    pub fn from_map(mut m: Map<String, Value>) -> Result<Request, ErrorCode> {
        let id = m
            .remove("id")
            .and_then(|v| v.as_u64())
            .ok_or(ErrorCode::BadRequest)?;
        let op = match m.remove("op") {
            Some(Value::String(s)) => s,
            _ => return Err(ErrorCode::BadRequest),
        };
        Ok(Request { id, op, args: m })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadFrame,
    BadRequest,
    HelloRequired,
    UnknownOp,
    Forbidden,
    Busy,
    LowDisk,
    Unavailable,
    Internal,
    /// The credential vault cannot be read.
    VaultUnavailable,
    /// A policy rule refused the request; the message starts with the rule
    /// (connector calls also carry it in `rule`).
    Denied,
    /// A connector call hit a limit (`limit` names it).
    Limited,
    /// The upstream failed, or its answer was withheld (`rule` or
    /// `reason`).
    UpstreamFailed,
    /// The change was made, but its audit record could not be written.
    Unrecorded,
    /// Lockdown (scope `all`) is on: the hook's record was written and the
    /// call is denied; `message` says why.
    Lockdown,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::BadFrame => "bad_frame",
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::HelloRequired => "hello_required",
            ErrorCode::UnknownOp => "unknown_op",
            ErrorCode::Forbidden => "forbidden",
            ErrorCode::Busy => "busy",
            ErrorCode::LowDisk => "low_disk",
            ErrorCode::Unavailable => "unavailable",
            ErrorCode::Internal => "internal",
            ErrorCode::VaultUnavailable => "vault_unavailable",
            ErrorCode::Denied => "denied",
            ErrorCode::Limited => "limited",
            ErrorCode::UpstreamFailed => "upstream_failed",
            ErrorCode::Unrecorded => "unrecorded",
            ErrorCode::Lockdown => "lockdown",
        }
    }
}

/// `{"id", "ok": true, ...fields}`.
pub fn ok(id: u64, fields: Map<String, Value>) -> Value {
    let mut m = Map::new();
    m.insert("id".into(), Value::from(id));
    m.insert("ok".into(), Value::Bool(true));
    for (k, v) in fields {
        if k != "id" && k != "ok" {
            m.insert(k, v);
        }
    }
    Value::Object(m)
}

/// `{"id", "ok": false, "error", "message"}`.
pub fn err(id: u64, code: ErrorCode, message: &str) -> Value {
    let mut m = Map::new();
    m.insert("id".into(), Value::from(id));
    m.insert("ok".into(), Value::Bool(false));
    m.insert("error".into(), Value::from(code.as_str()));
    m.insert("message".into(), Value::from(message));
    Value::Object(m)
}

/// [`err`] plus `extra` fields (`rule`, `limit`, ...); `extra` cannot
/// replace `id`, `ok`, `error` or `message`.
pub fn err_with(id: u64, code: ErrorCode, message: &str, extra: Map<String, Value>) -> Value {
    let mut v = err(id, code, message);
    if let Value::Object(m) = &mut v {
        for (k, x) in extra {
            if !matches!(k.as_str(), "id" | "ok" | "error" | "message") {
                m.insert(k, x);
            }
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn err_with_adds_fields_but_keeps_the_shape() {
        let mut x = serde_json::Map::new();
        x.insert("rule".into(), json!("no_scope"));
        x.insert("error".into(), json!("spoofed"));
        assert_eq!(
            err_with(4, ErrorCode::Denied, "denied (no_scope)", x),
            json!({"id":4,"ok":false,"error":"denied","message":"denied (no_scope)","rule":"no_scope"})
        );
        assert_eq!(ErrorCode::Limited.as_str(), "limited");
        assert_eq!(
            serde_json::to_value(ErrorCode::UpstreamFailed).unwrap(),
            "upstream_failed"
        );
    }

    #[test]
    fn request_without_id_is_bad_request() {
        let m = json!({"op":"status"});
        let r = Request::from_map(m.as_object().unwrap().clone());
        assert_eq!(r.unwrap_err(), ErrorCode::BadRequest);
        let m = json!({"id":-1,"op":"status"});
        assert!(Request::from_map(m.as_object().unwrap().clone()).is_err());
        let m = json!({"id":1});
        assert!(Request::from_map(m.as_object().unwrap().clone()).is_err());
    }

    #[test]
    fn request_debug_shows_arg_keys_only() {
        let m = json!({"id":1,"op":"secret.add","fields":{"token":"hunter2-value"},"name":"n"});
        let r = Request::from_map(m.as_object().unwrap().clone()).unwrap();
        let d = format!("{r:?}");
        assert!(d.contains("fields") && d.contains("secret.add"), "{d}");
        assert!(!d.contains("hunter2-value"), "{d}");
    }

    #[test]
    fn request_round_trip() {
        let m = json!({"id":3,"op":"audit.append","kind":"guard"});
        let r = Request::from_map(m.as_object().unwrap().clone()).unwrap();
        assert_eq!((r.id, r.op.as_str()), (3, OP_AUDIT_APPEND));
        assert_eq!(r.args["kind"], "guard");
        assert_eq!(r.to_value(), m);
    }

    #[test]
    fn error_codes_serialize_snake_case() {
        assert_eq!(
            serde_json::to_value(ErrorCode::HelloRequired).unwrap(),
            "hello_required"
        );
        assert_eq!(
            serde_json::to_value(ErrorCode::LowDisk).unwrap(),
            "low_disk"
        );
        assert_eq!(ErrorCode::LowDisk.as_str(), "low_disk");
        assert_eq!(
            serde_json::to_value(ErrorCode::VaultUnavailable).unwrap(),
            "vault_unavailable"
        );
        assert_eq!(ErrorCode::VaultUnavailable.as_str(), "vault_unavailable");
    }

    #[test]
    fn ok_and_err_shapes() {
        let mut f = serde_json::Map::new();
        f.insert("proto".into(), json!(1));
        assert_eq!(ok(2, f), json!({"id":2,"ok":true,"proto":1}));
        assert_eq!(
            err(2, ErrorCode::Busy, "slow down"),
            json!({"id":2,"ok":false,"error":"busy","message":"slow down"})
        );
    }
}
