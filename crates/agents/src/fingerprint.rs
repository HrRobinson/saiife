//! SHA-256 fingerprints for tamper detection (spec §7.5).

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Lower-case hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// `v` as compact JSON with every object's keys sorted, so the same entry
/// always yields the same text whatever order its keys were written in.
pub fn canonical_json(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let fields: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", Value::String(k.clone()), canonical_json(&map[k])))
                .collect();
            format!("{{{}}}", fields.join(","))
        }
        Value::Array(items) => {
            let items: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", items.join(","))
        }
        other => other.to_string(),
    }
}

/// Fingerprint of a hook entry given as JSON.
pub fn of_json(v: &Value) -> String {
    sha256_hex(canonical_json(v).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn known_digest() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn key_order_does_not_change_the_fingerprint() {
        let a: Value = serde_json::from_str(r#"{"b":1,"a":{"y":[1,"x"],"x":null}}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a":{"x":null,"y":[1,"x"]},"b":1}"#).unwrap();
        assert_eq!(of_json(&a), of_json(&b));
        assert_eq!(canonical_json(&a), r#"{"a":{"x":null,"y":[1,"x"]},"b":1}"#);
    }

    #[test]
    fn any_value_change_does() {
        assert_ne!(
            of_json(&json!({"timeout": 10})),
            of_json(&json!({"timeout": 11}))
        );
        assert_ne!(
            of_json(&json!({"m": "Bash"})),
            of_json(&json!({"m": "Bash|Read"}))
        );
    }
}
