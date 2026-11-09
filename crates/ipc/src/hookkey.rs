//! The key of one hook call (plan 20): the agent, the session, the tool call
//! id and the SHA-256 of `tool_input` in a canonical JSON form. The command
//! hook (from stdin) and the daemon's co-signer (from the HTTP body) compute
//! it with the same function, so the two agree even when the agent formats
//! the payload differently (key order, whitespace, `\u` escapes).

use std::io::Write;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The payload cap of [`hook_key`]: the managed hook's own `PARSE_MAX_BYTES`
/// (64 MiB).
pub const HOOK_KEY_MAX_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HookKey {
    pub agent: String,
    pub session: Option<String>,
    pub tool_use_id: Option<String>,
    /// Lowercase hex of [`canonical_sha256`] of `tool_input` (`null` when absent).
    pub input_sha256: String,
}

impl HookKey {
    /// Whether the Claude Code co-signer can match this call: a Claude Code
    /// call with a session and a tool call id.
    pub fn cosignable(&self) -> bool {
        let set = |s: &Option<String>| s.as_deref().is_some_and(|s| !s.is_empty());
        self.agent == "claude" && set(&self.session) && set(&self.tool_use_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("hook payload is not a JSON object: {0}")]
    Json(String),
    #[error("hook payload too large for a key")]
    TooLarge,
}

/// [`hook_key_bounded`] with [`HOOK_KEY_MAX_BYTES`].
pub fn hook_key(agent: &str, payload: &str) -> Result<HookKey, KeyError> {
    hook_key_bounded(agent, payload, HOOK_KEY_MAX_BYTES)
}

/// The key of a hook payload. `session_id`/`sessionId` and
/// `tool_use_id`/`toolUseId` are read as the guard's `HookContext` reads them
/// (the snake-case field first; empty or not a string is absent); the input
/// is `tool_input`, else `toolInput`, else `null`.
pub fn hook_key_bounded(agent: &str, payload: &str, max_bytes: usize) -> Result<HookKey, KeyError> {
    if payload.len() > max_bytes {
        return Err(KeyError::TooLarge);
    }
    let v: Value = serde_json::from_str(payload).map_err(|e| KeyError::Json(e.to_string()))?;
    let Value::Object(map) = v else {
        return Err(KeyError::Json("not an object".into()));
    };
    let field = |a: &str, b: &str| {
        [map.get(a), map.get(b)]
            .into_iter()
            .flatten()
            .find_map(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let input = [map.get("tool_input"), map.get("toolInput")]
        .into_iter()
        .flatten()
        .find(|v| !v.is_null())
        .unwrap_or(&Value::Null);
    Ok(HookKey {
        agent: agent.to_string(),
        session: field("session_id", "sessionId"),
        tool_use_id: field("tool_use_id", "toolUseId"),
        input_sha256: canonical_sha256(input),
    })
}

/// Lowercase hex SHA-256 of `v` as compact JSON with the keys of every
/// object sorted by byte order, arrays in order, and serde_json's own number
/// and string formatting. Independent of map order (the workspace builds
/// serde_json with `preserve_order`).
pub fn canonical_sha256(v: &Value) -> String {
    let mut h = HashWriter(Sha256::new());
    write_canonical(&mut h, v);
    h.0.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

struct HashWriter(Sha256);

impl Write for HashWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A key or a leaf value, in serde_json's own formatting. Writing into a
/// hasher never fails, and serde_json fails only on a map with non-string
/// keys, which a `Value` cannot hold.
fn scalar<T: Serialize + ?Sized>(h: &mut HashWriter, v: &T) {
    let _ = serde_json::to_writer(h, v);
}

fn write_canonical(h: &mut HashWriter, v: &Value) {
    match v {
        Value::Array(items) => {
            h.0.update(b"[");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    h.0.update(b",");
                }
                write_canonical(h, item);
            }
            h.0.update(b"]");
        }
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_unstable_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            h.0.update(b"{");
            for (i, (k, item)) in entries.into_iter().enumerate() {
                if i > 0 {
                    h.0.update(b",");
                }
                scalar(h, k);
                h.0.update(b":");
                write_canonical(h, item);
            }
            h.0.update(b"}");
        }
        other => scalar(h, other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../cli/tests/fixtures/claude/bash-allow.json");

    fn sha256_hex(b: &[u8]) -> String {
        Sha256::digest(b)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn sha(payload: &str) -> String {
        hook_key("claude", payload).unwrap().input_sha256
    }

    #[test]
    fn key_of_the_claude_fixture() {
        let k = hook_key("claude", FIXTURE).unwrap();
        assert_eq!(k.agent, "claude");
        assert_eq!(k.session.as_deref(), Some("c-1"));
        assert_eq!(k.tool_use_id.as_deref(), Some("toolu_02"));
        assert_eq!(
            k.input_sha256,
            sha256_hex(br#"{"command":"ls -la","description":"List files"}"#)
        );
        assert!(k.cosignable());
    }

    #[test]
    fn key_ignores_order_whitespace_and_escapes() {
        let a = sha(r#"{"tool_input":{"b":1,"a":"é"}}"#);
        let b = sha("{ \"tool_input\" : { \"a\" : \"\\u00e9\", \"b\" : 1 } }");
        let c = sha("{\n  \"tool_input\": {\n    \"a\": \"é\",\n    \"b\": 1\n  }\n}");
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_eq!(a, sha256_hex("{\"a\":\"é\",\"b\":1}".as_bytes()));
    }

    #[test]
    fn nested_objects_are_sorted_too() {
        let a = sha(r#"{"tool_input":{"z":[{"y":1,"x":{"q":2,"p":3}}],"a":null}}"#);
        let b = sha(r#"{"tool_input":{"a":null,"z":[{"x":{"p":3,"q":2},"y":1}]}}"#);
        assert_eq!(a, b);
        assert_eq!(
            a,
            sha256_hex(br#"{"a":null,"z":[{"x":{"p":3,"q":2},"y":1}]}"#)
        );
    }

    #[test]
    fn key_changes_with_any_value() {
        let base = sha(
            r#"{"tool_input":{"command":"ls -la","description":"List files","n":[1,[2,"x"]]}}"#,
        );
        for changed in [
            r#"{"tool_input":{"command":"ls -lb","description":"List files","n":[1,[2,"x"]]}}"#,
            r#"{"tool_input":{"command":"ls -la","description":"List filez","n":[1,[2,"x"]]}}"#,
            r#"{"tool_input":{"command":"ls -la","description":"List files","n":[1,[2,"y"]]}}"#,
            r#"{"tool_input":{"command":"ls -la","description":"List files","n":[[2,"x"],1]}}"#,
        ] {
            assert_ne!(sha(changed), base, "{changed}");
        }
    }

    #[test]
    fn missing_tool_input_hashes_null() {
        let null = sha256_hex(b"null");
        assert_eq!(sha(r#"{"session_id":"s"}"#), null);
        assert_eq!(sha(r#"{"tool_input":null}"#), null);
        assert_eq!(canonical_sha256(&Value::Null), null);
    }

    #[test]
    fn camel_case_fields_read() {
        let k = hook_key(
            "claude",
            r#"{"sessionId":"s-2","toolUseId":"t-3","toolInput":{"command":"ls"}}"#,
        )
        .unwrap();
        assert_eq!(k.session.as_deref(), Some("s-2"));
        assert_eq!(k.tool_use_id.as_deref(), Some("t-3"));
        assert_eq!(k.input_sha256, sha256_hex(br#"{"command":"ls"}"#));
        assert!(k.cosignable());
    }

    #[test]
    fn not_cosignable_without_tool_use_id() {
        let k = hook_key("claude", r#"{"session_id":"s","tool_input":{}}"#).unwrap();
        assert_eq!(k.tool_use_id, None);
        assert!(!k.cosignable());
        let k = hook_key("claude", r#"{"session_id":"s","tool_use_id":""}"#).unwrap();
        assert!(!k.cosignable());
        let k = hook_key("claude", r#"{"tool_use_id":"t"}"#).unwrap();
        assert!(!k.cosignable());
    }

    #[test]
    fn not_cosignable_for_codex() {
        let k = hook_key("codex", FIXTURE).unwrap();
        assert!(!k.cosignable());
    }

    #[test]
    fn oversize_payload_is_too_large() {
        let payload = r#"{"tool_input":{"command":"ls"}}"#;
        assert!(payload.len() > 16);
        assert_eq!(
            hook_key_bounded("claude", payload, 16),
            Err(KeyError::TooLarge)
        );
        assert!(hook_key_bounded("claude", payload, payload.len()).is_ok());
    }

    #[test]
    fn bad_json_is_an_error() {
        assert!(matches!(
            hook_key("claude", "{nope"),
            Err(KeyError::Json(_))
        ));
        assert!(matches!(hook_key("claude", "[1]"), Err(KeyError::Json(_))));
    }

    #[test]
    fn key_round_trips_as_op_args() {
        let k = hook_key("claude", FIXTURE).unwrap();
        let v = serde_json::to_value(&k).unwrap();
        for f in ["agent", "session", "tool_use_id", "input_sha256"] {
            assert!(v.get(f).is_some(), "{f}");
        }
        assert_eq!(serde_json::from_value::<HookKey>(v).unwrap(), k);
    }
}
