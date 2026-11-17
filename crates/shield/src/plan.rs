//! Plan 45: the planner's reply (spec §2.3.2): a method, an answer template,
//! optional self-checks and an intent line.

use crate::sql::ErrorClass;
use serde::{Deserialize, Serialize};

/// Byte caps on the reply fields (and characters for `intent`).
pub const METHOD_MAX: usize = 8 * 1024;
pub const TEMPLATE_MAX: usize = 4 * 1024;
pub const INTENT_MAX_CHARS: usize = 300;
pub const CHECKS_MAX: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanReply {
    pub method: String,
    pub template: String,
    #[serde(default)]
    pub checks: Vec<SelfCheck>,
    pub intent: String,
    /// Spec §3.1: the planner says exact mode cannot answer; method and
    /// template may then be empty.
    #[serde(default)]
    pub needs_judgment: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SelfCheck {
    /// The method's result has between `min` and `max` rows.
    RowsBetween { min: u64, max: u64 },
    /// Two scalar queries give the same value.
    Equal { a: String, b: String },
}

/// JSON Schema of [`PlanReply`] for the planner's structured output (plan 47).
pub const PLAN_SCHEMA: &str = r#"{
  "type": "object",
  "additionalProperties": false,
  "required": ["method", "template", "intent"],
  "properties": {
    "method": { "type": "string", "maxLength": 8192 },
    "template": { "type": "string", "maxLength": 4096 },
    "checks": {
      "type": "array",
      "maxItems": 4,
      "items": {
        "oneOf": [
          {
            "type": "object",
            "additionalProperties": false,
            "required": ["kind", "min", "max"],
            "properties": {
              "kind": { "const": "rows_between" },
              "min": { "type": "integer", "minimum": 0 },
              "max": { "type": "integer", "minimum": 0 }
            }
          },
          {
            "type": "object",
            "additionalProperties": false,
            "required": ["kind", "a", "b"],
            "properties": {
              "kind": { "const": "equal" },
              "a": { "type": "string", "maxLength": 8192 },
              "b": { "type": "string", "maxLength": 8192 }
            }
          }
        ]
      }
    },
    "intent": { "type": "string", "maxLength": 300 },
    "needs_judgment": { "type": "boolean" }
  }
}"#;

/// Parse the planner's reply text. Any shape or size problem is `syntax`;
/// the serde error text is never kept (it can quote the reply).
pub fn parse_reply(text: &str) -> Result<PlanReply, ErrorClass> {
    let r: PlanReply = serde_json::from_str(text).map_err(|_| ErrorClass::Syntax)?;
    let checks_ok = r.checks.len() <= CHECKS_MAX
        && r.checks.iter().all(|c| match c {
            SelfCheck::RowsBetween { .. } => true,
            SelfCheck::Equal { a, b } => a.len() <= METHOD_MAX && b.len() <= METHOD_MAX,
        });
    if r.method.len() > METHOD_MAX
        || r.template.len() > TEMPLATE_MAX
        || r.intent.chars().count() > INTENT_MAX_CHARS
        || !checks_ok
    {
        return Err(ErrorClass::Syntax);
    }
    Ok(r)
}
