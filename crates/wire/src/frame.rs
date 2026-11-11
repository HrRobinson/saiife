//! The signed frame a Workspace browser sends, and its strict parsing.

use crate::{b64, WireError};
use serde_json::{Map, Value};

pub const FRAME_VERSION: u32 = 1;
pub const MAX_BODY_BYTES: usize = 64 * 1024;
pub const MAX_TTL_SECS: u64 = 300;
pub const SKEW_SECS: u64 = 60;

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Frame {
    pub v: u32,
    pub machine_id: String,
    pub epoch: String,
    pub device_id: String,
    pub action: String,
    pub args: Map<String, Value>,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// What link forwards: the exact body bytes as a string, the signature, and
/// for Touch actions the WebAuthn proof (plan 31 fills it).
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedFrame {
    pub body: String,
    pub sig: String,
    #[serde(default)]
    pub touch: Option<TouchProof>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct TouchProof {
    pub request_id: String,
    pub credential_id: String,
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
}

/// Parses a JSON body, refusing a duplicate object key anywhere (two
/// parsers that keep the first and the last value would see different
/// amounts). serde_json's recursion limit applies. Copy of the broker's
/// `pipeline::strict_json` (the wire crate must not depend on tokio).
pub fn strict_json(b: &[u8]) -> Option<Value> {
    use serde::de::{DeserializeSeed, Deserializer, Error, MapAccess, SeqAccess, Visitor};

    struct Strict;

    impl<'de> DeserializeSeed<'de> for Strict {
        type Value = Value;
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
            d.deserialize_any(Strict)
        }
    }

    impl<'de> Visitor<'de> for Strict {
        type Value = Value;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("JSON")
        }
        fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
            Ok(Value::Bool(v))
        }
        fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
            Ok(v.into())
        }
        fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
            Ok(v.into())
        }
        fn visit_f64<E: Error>(self, v: f64) -> Result<Value, E> {
            serde_json::Number::from_f64(v)
                .map(Value::Number)
                .ok_or_else(|| E::custom("not a finite number"))
        }
        fn visit_str<E>(self, v: &str) -> Result<Value, E> {
            Ok(Value::String(v.to_string()))
        }
        fn visit_string<E>(self, v: String) -> Result<Value, E> {
            Ok(Value::String(v))
        }
        fn visit_unit<E>(self) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_none<E>(self) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
            let mut out = Vec::new();
            while let Some(v) = a.next_element_seed(Strict)? {
                out.push(v);
            }
            Ok(Value::Array(out))
        }
        fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
            let mut out = Map::new();
            while let Some(k) = a.next_key::<String>()? {
                let v = a.next_value_seed(Strict)?;
                if out.insert(k, v).is_some() {
                    return Err(A::Error::custom("duplicate key"));
                }
            }
            Ok(Value::Object(out))
        }
    }

    let mut de = serde_json::Deserializer::from_slice(b);
    let v = Strict.deserialize(&mut de).ok()?;
    de.end().ok()?;
    Some(v)
}

fn bad(m: &str) -> WireError {
    WireError::Malformed(m.to_string())
}

/// Strictly parses a frame body: size, duplicate keys, unknown fields,
/// version, TTL, nonce and action shape.
pub fn parse_body(body: &[u8]) -> Result<Frame, WireError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(bad("body too large"));
    }
    let v = strict_json(body).ok_or_else(|| bad("not strict JSON"))?;
    let f: Frame = serde_json::from_value(v).map_err(|e| WireError::Malformed(e.to_string()))?;
    if f.v != FRAME_VERSION {
        return Err(bad("unsupported frame version"));
    }
    if f.expires_at <= f.issued_at {
        return Err(bad("expires_at is not after issued_at"));
    }
    if f.expires_at - f.issued_at > MAX_TTL_SECS {
        return Err(bad("lifetime too long"));
    }
    b64::dec_n::<16>(&f.nonce)?;
    let ok_action = (1..=64).contains(&f.action.len())
        && f.action
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'_');
    if !ok_action {
        return Err(bad("bad action name"));
    }
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WireError;

    fn body_with(action: &str, extra: &str, issued: u64, expires: u64) -> String {
        format!(
            r#"{{"v":1,"machine_id":"m","epoch":"e","device_id":"d-0","action":"{action}","args":{{}},"nonce":"{}","issued_at":{issued},"expires_at":{expires}{extra}}}"#,
            crate::b64::enc(&[1u8; 16])
        )
    }

    fn ok_body() -> String {
        body_with("box.list", "", 1000, 1100)
    }

    #[test]
    fn parses_a_valid_body() {
        let f = parse_body(ok_body().as_bytes()).unwrap();
        assert_eq!(f.action, "box.list");
        assert_eq!(f.v, FRAME_VERSION);
        assert_eq!(f.expires_at - f.issued_at, 100);
    }

    #[test]
    fn duplicate_key_is_refused() {
        let b = ok_body().replacen(
            r#""action":"box.list""#,
            r#""action":"box.list","action":"box.stop""#,
            1,
        );
        assert!(matches!(
            parse_body(b.as_bytes()),
            Err(WireError::Malformed(_))
        ));
    }

    #[test]
    fn unknown_field_is_refused() {
        let b = body_with("box.list", r#","admin":true"#, 1000, 1100);
        assert!(matches!(
            parse_body(b.as_bytes()),
            Err(WireError::Malformed(_))
        ));
    }

    #[test]
    fn oversize_body_is_refused() {
        let b = vec![b' '; MAX_BODY_BYTES + 1];
        assert_eq!(b.len(), 65_537);
        assert!(matches!(parse_body(&b), Err(WireError::Malformed(_))));
    }

    #[test]
    fn float_time_is_refused() {
        let b = ok_body().replace(r#""expires_at":1100"#, r#""expires_at":1.5"#);
        assert!(matches!(
            parse_body(b.as_bytes()),
            Err(WireError::Malformed(_))
        ));
    }

    #[test]
    fn ttl_over_300_is_refused() {
        let b = body_with("box.list", "", 1000, 1301);
        assert!(matches!(
            parse_body(b.as_bytes()),
            Err(WireError::Malformed(_))
        ));
        let b = body_with("box.list", "", 1000, 1300);
        assert!(parse_body(b.as_bytes()).is_ok());
        let b = body_with("box.list", "", 1000, 1000);
        assert!(matches!(
            parse_body(b.as_bytes()),
            Err(WireError::Malformed(_))
        ));
    }

    #[test]
    fn bad_action_chars_are_refused() {
        for a in ["box.stop ", "Box.Stop", ""] {
            let b = body_with(a, "", 1000, 1100);
            assert!(
                matches!(parse_body(b.as_bytes()), Err(WireError::Malformed(_))),
                "{a:?}"
            );
        }
    }

    #[test]
    fn bad_version_and_nonce_are_refused() {
        let b = ok_body().replace(r#""v":1"#, r#""v":2"#);
        assert!(matches!(
            parse_body(b.as_bytes()),
            Err(WireError::Malformed(_))
        ));
        let short = crate::b64::enc(&[1u8; 15]);
        let b = ok_body().replace(&crate::b64::enc(&[1u8; 16]), &short);
        assert!(matches!(
            parse_body(b.as_bytes()),
            Err(WireError::Malformed(_))
        ));
    }

    #[test]
    fn non_object_args_is_refused() {
        let b = ok_body().replace(r#""args":{}"#, r#""args":[]"#);
        assert!(matches!(
            parse_body(b.as_bytes()),
            Err(WireError::Malformed(_))
        ));
    }
}
