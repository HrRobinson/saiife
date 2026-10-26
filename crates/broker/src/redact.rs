//! Response field redaction (spec §6.7.3, plan 10 decision 5).
//!
//! A field path such as `customer.email` matches as a **suffix** of the key
//! path of any value in the JSON tree. Arrays are transparent: the path of
//! `orders[3].customer.email` is `orders.customer.email`. `*` matches
//! exactly one key, so `*.billing_address` hits `order.billing_address` but
//! not a `billing_address` at the root. A matched value, whatever its type,
//! becomes the JSON string `"[REDACTED]"`; its children are not visited.

use serde_json::Value;

pub const REDACTED: &str = "[REDACTED]";

/// Redact every value whose key path ends with one of `fields`. Returns how
/// many values were replaced.
pub fn redact(v: &mut Value, fields: &[String]) -> usize {
    let patterns: Vec<Vec<&str>> = fields
        .iter()
        .map(|f| f.split('.').collect::<Vec<_>>())
        .filter(|p| p.iter().all(|seg| !seg.is_empty()))
        .collect();
    if patterns.is_empty() {
        return 0;
    }
    let mut path = Vec::new();
    walk(v, &patterns, &mut path)
}

fn walk(v: &mut Value, patterns: &[Vec<&str>], path: &mut Vec<String>) -> usize {
    match v {
        Value::Array(items) => items.iter_mut().map(|i| walk(i, patterns, path)).sum(),
        Value::Object(map) => {
            let mut n = 0;
            for (key, child) in map.iter_mut() {
                path.push(key.clone());
                if patterns.iter().any(|p| suffix_matches(p, path)) {
                    *child = Value::String(REDACTED.to_string());
                    n += 1;
                } else {
                    n += walk(child, patterns, path);
                }
                path.pop();
            }
            n
        }
        _ => 0,
    }
}

fn suffix_matches(pattern: &[&str], path: &[String]) -> bool {
    if pattern.len() > path.len() {
        return false;
    }
    let tail = &path[path.len() - pattern.len()..];
    pattern
        .iter()
        .zip(tail)
        .all(|(p, k)| *p == "*" || *p == k.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn f(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn redact_suffix_paths() {
        let mut v = json!({
            "orders": [
                {"id": 1, "customer": {"email": "a@x.dk", "name": "A"}},
                {"id": 2, "customer": {"email": "b@x.dk", "name": "B"}}
            ],
            "order": {"billing_address": {"street": "Vej 1"}, "total": "9.50"},
            "billing_address": "root stays"
        });
        let n = redact(&mut v, &f(&["customer.email", "*.billing_address"]));
        assert_eq!(n, 3);
        assert_eq!(v["orders"][0]["customer"]["email"], "[REDACTED]");
        assert_eq!(v["orders"][1]["customer"]["email"], "[REDACTED]");
        assert_eq!(v["orders"][0]["customer"]["name"], "A");
        assert_eq!(v["order"]["billing_address"], "[REDACTED]");
        assert_eq!(v["order"]["total"], "9.50");
        assert_eq!(v["billing_address"], "root stays");
    }

    #[test]
    fn redact_single_key_matches_anywhere() {
        let mut v = json!({"a": {"phone": 1}, "phone": [2], "b": [{"c": {"phone": null}}]});
        assert_eq!(redact(&mut v, &f(&["phone"])), 3);
        assert_eq!(
            v,
            json!({"a": {"phone": "[REDACTED]"}, "phone": "[REDACTED]",
                             "b": [{"c": {"phone": "[REDACTED]"}}]})
        );
    }

    #[test]
    fn redact_star_is_one_key_only() {
        let mut v = json!({"x": {"y": {"z": 1}}});
        // `*.z` needs one key before `z`: `y` qualifies.
        assert_eq!(redact(&mut v, &f(&["*.*.*.z"])), 0);
        assert_eq!(redact(&mut v, &f(&["*.*.z"])), 1);
    }

    #[test]
    fn redact_no_fields_or_empty_segments_is_noop() {
        let mut v = json!({"a": 1});
        assert_eq!(redact(&mut v, &[]), 0);
        assert_eq!(redact(&mut v, &f(&["", "a..b"])), 0);
        assert_eq!(v, json!({"a": 1}));
    }
}
