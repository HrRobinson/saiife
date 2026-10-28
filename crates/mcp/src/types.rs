//! Serde types for the MCP subset saiife uses (plan 17, decision 1), with
//! MCP's camelCase field names. Unknown fields are ignored on input, so
//! newer peers stay readable; optional fields are left out on output.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::jsonrpc::Id;

pub const INITIALIZE: &str = "initialize";
pub const INITIALIZED: &str = "notifications/initialized";
pub const PING: &str = "ping";
pub const TOOLS_LIST: &str = "tools/list";
pub const TOOLS_CALL: &str = "tools/call";
pub const CANCELLED: &str = "notifications/cancelled";
pub const PROGRESS: &str = "notifications/progress";
pub const TOOLS_LIST_CHANGED: &str = "notifications/tools/list_changed";

/// A progress token: a string or an integer, like an id.
pub type ProgressToken = Id;

/// A client or server name and version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Implementation {
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

/// `initialize` params.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeParams {
    pub protocol_version: String,
    /// The client's capabilities. saiife declares none as a client and
    /// reads none as a server, so they stay opaque.
    #[serde(default)]
    pub capabilities: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_info: Option<Implementation>,
}

/// `initialize` result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    pub protocol_version: String,
    #[serde(default)]
    pub capabilities: ServerCapabilities,
    pub server_info: Implementation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
}

/// The server capabilities saiife reads or declares: tools only.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerCapabilities {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolsCapability>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolsCapability {
    #[serde(default)]
    pub list_changed: bool,
}

/// `tools/list` params.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListToolsParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// `tools/list` result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListToolsResult {
    pub tools: Vec<Tool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// One tool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub input_schema: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<ToolAnnotations>,
}

/// Tool hints. saiife sets them for connector tools only; hints from a
/// third-party server are untrusted and not passed on.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolAnnotations {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destructive_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotent_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_world_hint: Option<bool>,
}

/// `_meta` of a request.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestMeta {
    /// A token that is not a valid id (a float, say) is dropped: the call
    /// goes on without progress notifications.
    #[serde(
        default,
        deserialize_with = "lenient_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub progress_token: Option<ProgressToken>,
}

/// `tools/call` params.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallToolParams {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Map<String, Value>>,
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<RequestMeta>,
}

/// `tools/call` result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallToolResult {
    pub content: Vec<Content>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured_content: Option<Value>,
    #[serde(default)]
    pub is_error: bool,
}

/// One content item of a result that saiife emits. Closed on purpose:
/// `saiife mcp` only ever writes text and embedded resources. Results from
/// third-party gateway servers are not read into this type; they are
/// handled as `serde_json::Value` (plan 17, Tasks 6 and 7): text and
/// resource strings are masked, image and audio items are replaced with a
/// text placeholder, and resource_link strings are masked.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Content {
    Text { text: String },
    Resource { resource: ResourceContents },
}

/// An embedded resource: `text` or base64 `blob`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceContents {
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>,
}

impl ResourceContents {
    /// An embedded resource carries exactly one of `text` and `blob`.
    pub fn validate(&self) -> Result<(), &'static str> {
        match (&self.text, &self.blob) {
            (Some(_), None) | (None, Some(_)) => Ok(()),
            (None, None) => Err("a resource has text or a blob"),
            (Some(_), Some(_)) => Err("a resource has text or a blob, not both"),
        }
    }
}

/// Reads an optional id, dropping a value that is not a valid one.
fn lenient_id<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Id>, D::Error> {
    let v = Option::<Value>::deserialize(d)?;
    Ok(v.as_ref().and_then(Id::from_value))
}

/// `notifications/progress` params.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressParams {
    pub progress_token: ProgressToken,
    pub progress: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// `notifications/cancelled` params.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelledParams {
    /// Missing or not a valid id: the cancel names no request and is
    /// ignored.
    #[serde(
        default,
        deserialize_with = "lenient_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub request_id: Option<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
