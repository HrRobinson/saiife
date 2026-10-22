//! Request and answer shapes.
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const PROTO: u64 = 1;
pub const SOCKET_NAME: &str = "saiife.sock";
pub const OP_HELLO: &str = "hello";
pub const OP_AUDIT_APPEND: &str = "audit.append";
pub const OP_STATUS: &str = "status";
pub const OP_AUDIT_ROTATE_KEY: &str = "audit.rotate_key";

/// Largest `rec` that `audit.append` takes, as compact JSON
/// (`serde_json::to_vec`). The daemon refuses a larger one with
/// `bad_request`; the managed hook shrinks its record to fit, so a denied
/// call can never escape the audit record. Shared so the two never
/// disagree.
pub const MAX_RECORD_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub id: u64,
    pub op: String,
    pub args: Map<String, Value>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
