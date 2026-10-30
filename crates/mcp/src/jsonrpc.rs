//! JSON-RPC 2.0 messages (<https://www.jsonrpc.org/specification>).

use serde_json::{Map, Number, Value};

/// Invalid JSON.
pub const PARSE_ERROR: i64 = -32700;
/// Valid JSON that is not a JSON-RPC 2.0 message saiife accepts.
pub const INVALID_REQUEST: i64 = -32600;
/// The method does not exist.
pub const METHOD_NOT_FOUND: i64 = -32601;
/// Bad method parameters.
pub const INVALID_PARAMS: i64 = -32602;
/// An internal JSON-RPC error.
pub const INTERNAL_ERROR: i64 = -32603;

/// A request id: an integer (kept exact, as received) or a string. `null`
/// is not an id; fractional numbers are refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(untagged, try_from = "Value")]
pub enum Id {
    Number(Number),
    String(String),
}

impl Id {
    /// The id of a JSON value, if it is a valid one.
    pub fn from_value(v: &Value) -> Option<Id> {
        match v {
            Value::String(s) => Some(Id::String(s.clone())),
            Value::Number(n) if n.is_i64() || n.is_u64() => Some(Id::Number(n.clone())),
            _ => None,
        }
    }

    pub fn to_value(&self) -> Value {
        match self {
            Id::Number(n) => Value::Number(n.clone()),
            Id::String(s) => Value::String(s.clone()),
        }
    }
}

impl TryFrom<Value> for Id {
    type Error = &'static str;
    fn try_from(v: Value) -> Result<Id, &'static str> {
        Id::from_value(&v).ok_or("an id is an integer or a string")
    }
}

impl From<i64> for Id {
    fn from(n: i64) -> Id {
        Id::Number(n.into())
    }
}

impl From<u64> for Id {
    fn from(n: u64) -> Id {
        Id::Number(n.into())
    }
}

/// A JSON-RPC error object.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("{code}: {message}")]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    /// Boxed: keeps `Result<_, DecodeError>` small.
    pub data: Option<Box<Value>>,
}

impl RpcError {
    pub fn new(code: i64, message: impl Into<String>) -> RpcError {
        RpcError {
            code,
            message: message.into(),
            data: None,
        }
    }

    pub fn parse_error() -> RpcError {
        RpcError::new(PARSE_ERROR, "Parse error")
    }

    pub fn invalid_request(why: impl Into<String>) -> RpcError {
        RpcError::new(INVALID_REQUEST, why)
    }

    pub fn method_not_found(method: &str) -> RpcError {
        RpcError::new(METHOD_NOT_FOUND, format!("method not found: {method}"))
    }

    pub fn invalid_params(why: impl Into<String>) -> RpcError {
        RpcError::new(INVALID_PARAMS, why)
    }

    pub fn internal_error(why: impl Into<String>) -> RpcError {
        RpcError::new(INTERNAL_ERROR, why)
    }

    pub(crate) fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("code".into(), self.code.into());
        m.insert("message".into(), self.message.clone().into());
        if let Some(d) = &self.data {
            m.insert("data".into(), (**d).clone());
        }
        Value::Object(m)
    }
}

/// One JSON-RPC 2.0 message. Batches are not messages: saiife refuses them.
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    /// A call that expects an answer. `params` is an object or an array.
    Request {
        id: Id,
        method: String,
        params: Option<Value>,
    },
    /// A call with no answer.
    Notification {
        method: String,
        params: Option<Value>,
    },
    /// A successful answer.
    Response { id: Id, result: Value },
    /// An error answer. `id` is `None` (sent as `null`) only when the
    /// request's id could not be read.
    Error { id: Option<Id>, error: RpcError },
}

impl Message {
    pub fn request(id: impl Into<Id>, method: &str, params: Option<Value>) -> Message {
        Message::Request {
            id: id.into(),
            method: method.into(),
            params,
        }
    }

    pub fn notification(method: &str, params: Option<Value>) -> Message {
        Message::Notification {
            method: method.into(),
            params,
        }
    }

    pub fn response(id: Id, result: Value) -> Message {
        Message::Response { id, result }
    }

    pub fn error(id: Option<Id>, error: RpcError) -> Message {
        Message::Error { id, error }
    }

    /// The method of a request or notification.
    pub fn method(&self) -> Option<&str> {
        match self {
            Message::Request { method, .. } | Message::Notification { method, .. } => Some(method),
            _ => None,
        }
    }

    /// The message as a JSON value, with `"jsonrpc": "2.0"`.
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("jsonrpc".into(), "2.0".into());
        match self {
            Message::Request { id, method, params } => {
                m.insert("id".into(), id.to_value());
                m.insert("method".into(), method.clone().into());
                if let Some(p) = params {
                    m.insert("params".into(), p.clone());
                }
            }
            Message::Notification { method, params } => {
                m.insert("method".into(), method.clone().into());
                if let Some(p) = params {
                    m.insert("params".into(), p.clone());
                }
            }
            Message::Response { id, result } => {
                m.insert("id".into(), id.to_value());
                m.insert("result".into(), result.clone());
            }
            Message::Error { id, error } => {
                m.insert("id".into(), id.as_ref().map_or(Value::Null, Id::to_value));
                m.insert("error".into(), error.to_value());
            }
        }
        Value::Object(m)
    }

    /// Reads a message from a parsed JSON value. The value must already
    /// have passed the codec's bounds; see [`crate::codec::decode_line`].
    pub fn from_value(v: Value) -> Result<Message, crate::codec::DecodeError> {
        use crate::codec::DecodeError;
        let bad = |id: Option<Id>, why: &str| DecodeError {
            id,
            error: RpcError::invalid_request(why),
        };
        let mut obj = match v {
            Value::Object(o) => o,
            Value::Array(_) => return Err(bad(None, "batches are not supported")),
            _ => return Err(bad(None, "a message is a JSON object")),
        };
        // Read the id first, so that later errors can name it.
        let raw_id = obj.remove("id");
        let id = raw_id.as_ref().and_then(Id::from_value);
        if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Err(bad(id, "jsonrpc must be \"2.0\""));
        }
        let params = obj.remove("params");
        let result = obj.remove("result");
        let error = obj.remove("error");
        if let Some(method) = obj.remove("method") {
            let Value::String(method) = method else {
                return Err(bad(id, "method must be a string"));
            };
            if result.is_some() || error.is_some() {
                return Err(bad(id, "a request has no result or error"));
            }
            if let Some(p) = &params {
                if !p.is_object() && !p.is_array() {
                    return Err(bad(id, "params must be an object or an array"));
                }
            }
            return match raw_id {
                None => Ok(Message::Notification { method, params }),
                Some(_) => match id {
                    Some(id) => Ok(Message::Request { id, method, params }),
                    None => Err(bad(None, "id must be an integer or a string")),
                },
            };
        }
        if params.is_some() {
            return Err(bad(id, "a response has no params"));
        }
        match (result, error) {
            (Some(result), None) => match id {
                Some(id) => Ok(Message::Response { id, result }),
                None => Err(bad(None, "id must be an integer or a string")),
            },
            (None, Some(error)) => {
                if id.is_none() && !matches!(raw_id, Some(Value::Null)) {
                    return Err(bad(None, "id must be an integer, a string or null"));
                }
                let error = read_error(error).ok_or_else(|| bad(id.clone(), "malformed error"))?;
                Ok(Message::Error { id, error })
            }
            (Some(_), Some(_)) => Err(bad(id, "a response has a result or an error, not both")),
            (None, None) => Err(bad(id, "no method, result or error")),
        }
    }
}

fn read_error(v: Value) -> Option<RpcError> {
    let Value::Object(mut o) = v else {
        return None;
    };
    let code = o.get("code")?.as_i64()?;
    let Value::String(message) = o.remove("message")? else {
        return None;
    };
    Some(RpcError {
        code,
        message,
        data: o.remove("data").map(Box::new),
    })
}
