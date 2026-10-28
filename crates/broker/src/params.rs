//! Parameter types and validation (spec §6.7.1 step 5, §8.4).

use crate::manifest::Operation;
use crate::BrokerError;
use percent_encoding::percent_decode_str;
use regex::Regex;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub enum ParamType {
    String {
        pattern: Option<Regex>,
    },
    Int {
        min: Option<i64>,
        max: Option<i64>,
    },
    Enum(Vec<String>),
    /// RFC 3339.
    Datetime,
    Bool,
    /// An object key that keeps its `/` (S3, Azure blobs), encoded segment
    /// by segment ([`object_value_problem`]).
    ObjectKey,
    /// An object name encoded whole, `/` as `%2F` (GCS).
    ObjectName,
}

impl ParamType {
    /// Parses `string`, `string:<regex>`, `int`, `int:1..250`, `enum:a,b`, `datetime`, `bool`.
    /// `pattern` (a regex) is only allowed on `string`.
    pub fn parse(spec: &str, pattern: Option<&str>) -> Result<ParamType, BrokerError> {
        let bad = |why: String| BrokerError::Manifest(format!("param type {spec:?}: {why}"));
        // `string:<regex>` is the inline form for operation parameters.
        let (spec, pattern) = match spec.strip_prefix("string:") {
            Some(re) if pattern.is_none() => ("string", Some(re)),
            Some(_) => return Err(bad("two patterns".into())),
            None => (spec, pattern),
        };
        if pattern.is_some() && spec != "string" {
            return Err(bad("pattern is only allowed on string".into()));
        }
        match spec {
            "string" => {
                let pattern = pattern
                    // Always anchored: a value like `evil.com#x` must not pass
                    // `[a-z]+` by matching a part of it.
                    .map(|p| Regex::new(&format!("^(?:{p})$")))
                    .transpose()
                    .map_err(|e| bad(format!("pattern: {e}")))?;
                Ok(ParamType::String { pattern })
            }
            "int" => Ok(ParamType::Int {
                min: None,
                max: None,
            }),
            "datetime" => Ok(ParamType::Datetime),
            "bool" => Ok(ParamType::Bool),
            "objectkey" => Ok(ParamType::ObjectKey),
            "objectname" => Ok(ParamType::ObjectName),
            _ => {
                if let Some(range) = spec.strip_prefix("int:") {
                    let (lo, hi) = range
                        .split_once("..")
                        .ok_or_else(|| bad("expected int:MIN..MAX".into()))?;
                    let num = |s: &str| -> Result<Option<i64>, BrokerError> {
                        if s.is_empty() {
                            Ok(None)
                        } else {
                            s.parse().map(Some).map_err(|_| bad("bad bound".into()))
                        }
                    };
                    let (min, max) = (num(lo)?, num(hi)?);
                    if let (Some(a), Some(b)) = (min, max) {
                        if a > b {
                            return Err(bad("min is above max".into()));
                        }
                    }
                    Ok(ParamType::Int { min, max })
                } else if let Some(list) = spec.strip_prefix("enum:") {
                    let vals: Vec<String> = list.split(',').map(str::to_string).collect();
                    if vals.iter().any(|v| v.is_empty()) {
                        return Err(bad("empty enum value".into()));
                    }
                    Ok(ParamType::Enum(vals))
                } else {
                    Err(bad("unknown type".into()))
                }
            }
        }
    }

    /// Checks one value. The error is a reason without the value.
    pub fn check(&self, v: &str) -> Result<(), String> {
        match self {
            ParamType::String { pattern } => match pattern {
                Some(re) if !re.is_match(v) => Err("does not match the pattern".into()),
                _ => Ok(()),
            },
            ParamType::Int { min, max } => {
                let digits = v.strip_prefix('-').unwrap_or(v);
                if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("not an integer".into());
                }
                let n: i64 = v.parse().map_err(|_| "not an integer".to_string())?;
                if min.is_some_and(|m| n < m) || max.is_some_and(|m| n > m) {
                    return Err("out of range".into());
                }
                Ok(())
            }
            ParamType::Enum(vals) => {
                if vals.iter().any(|x| x == v) {
                    Ok(())
                } else {
                    Err("not one of the allowed values".into())
                }
            }
            ParamType::Datetime => {
                if rfc3339(v) {
                    Ok(())
                } else {
                    Err("not an RFC 3339 date-time".into())
                }
            }
            ParamType::Bool => {
                if v == "true" || v == "false" {
                    Ok(())
                } else {
                    Err("not true or false".into())
                }
            }
            ParamType::ObjectKey | ParamType::ObjectName => match object_value_problem(v) {
                Some(why) => Err(why.into()),
                None => Ok(()),
            },
        }
    }

    /// An object key or name: `/` is allowed, with the checks of
    /// [`object_value_problem`] instead of the single-segment ones.
    pub fn is_object(&self) -> bool {
        matches!(self, ParamType::ObjectKey | ParamType::ObjectName)
    }
}

/// The longest object key or name, in bytes (S3's and GCS's limit).
pub const MAX_OBJECT_KEY: usize = 1024;

/// Decision 5: an object key or name may hold `/` but never escape the
/// path structure: it is not empty, at most 1024 bytes, and has no control
/// character, no `\`, no empty segment and no `.` or `..` segment, as
/// given and after each of up to four rounds of percent-decoding (an
/// upstream that decodes once more never sees a traversal either).
pub fn object_value_problem(v: &str) -> Option<&'static str> {
    if v.is_empty() {
        return Some("empty");
    }
    if v.len() > MAX_OBJECT_KEY {
        return Some("longer than 1024 bytes");
    }
    let mut cur = v.to_string();
    for _ in 0..5 {
        if has_control(&cur) {
            return Some("contains a control character");
        }
        if cur.contains('\\') {
            return Some("contains a backslash");
        }
        for seg in cur.split('/') {
            if seg.is_empty() {
                return Some("has an empty segment");
            }
            if seg == "." || seg == ".." {
                return Some("has a . or .. segment");
            }
        }
        let next = percent_decode_str(&cur).decode_utf8_lossy().into_owned();
        if next == cur {
            return None;
        }
        cur = next;
    }
    Some("too deeply percent-encoded")
}

/// `YYYY-MM-DDTHH:MM:SS[.frac](Z|+HH:MM|-HH:MM)`.
fn rfc3339(s: &str) -> bool {
    let b = s.as_bytes();
    let digits = |r: std::ops::Range<usize>| -> Option<u32> {
        let part = b.get(r)?;
        if part.iter().all(u8::is_ascii_digit) {
            std::str::from_utf8(part).ok()?.parse().ok()
        } else {
            None
        }
    };
    let at = |i: usize, c: u8| b.get(i) == Some(&c);
    let (Some(y), Some(mo), Some(d)) = (digits(0..4), digits(5..7), digits(8..10)) else {
        return false;
    };
    if !(at(4, b'-') && at(7, b'-') && (at(10, b'T') || at(10, b't'))) {
        return false;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = match mo {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    if d == 0 || d > dim {
        return false;
    }
    let (Some(h), Some(mi), Some(se)) = (digits(11..13), digits(14..16), digits(17..19)) else {
        return false;
    };
    if !(at(13, b':') && at(16, b':')) || h > 23 || mi > 59 || se > 60 {
        return false;
    }
    let mut i = 19;
    if at(i, b'.') {
        let start = i + 1;
        i = start;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    match b.get(i) {
        Some(b'Z') | Some(b'z') => i + 1 == b.len(),
        Some(b'+') | Some(b'-') => {
            let (Some(oh), Some(om)) = (digits(i + 1..i + 3), digits(i + 4..i + 6)) else {
                return false;
            };
            at(i + 3, b':') && oh < 24 && om < 60 && i + 6 == b.len()
        }
        _ => false,
    }
}

fn bad_value(name: &str, reason: impl Into<String>) -> BrokerError {
    BrokerError::BadValue {
        name: name.to_string(),
        reason: reason.into(),
    }
}

fn has_control(v: &str) -> bool {
    v.chars().any(|c| (c as u32) < 0x20 || c == '\u{7f}')
}

/// A path parameter may not smuggle a separator, a traversal or an encoded
/// form of one. The value is checked as given and after each of up to four
/// rounds of percent-decoding.
fn path_value_problem(v: &str) -> Option<&'static str> {
    if v.is_empty() {
        return Some("empty");
    }
    let mut cur = v.to_string();
    for _ in 0..5 {
        if !cur.is_ascii() {
            return Some("contains a non-ASCII character");
        }
        if cur == "." {
            return Some("is a . segment");
        }
        if cur.contains(['/', '\\', '?', '#', ';']) {
            return Some("contains a path or URL delimiter");
        }
        if cur.contains("..") {
            return Some("contains ..");
        }
        let lower = cur.to_ascii_lowercase();
        if ["%2f", "%5c", "%3f", "%23", "%3b"]
            .iter()
            .any(|e| lower.contains(e))
        {
            return Some("contains an encoded path or URL delimiter");
        }
        let next = percent_decode_str(&cur).decode_utf8_lossy().into_owned();
        if next == cur {
            return None;
        }
        cur = next;
    }
    Some("too deeply percent-encoded")
}

/// Where a parameter goes, which decides the characters it may hold.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Place {
    Path,
    Query,
    /// A JSON or form body field: escaped by the encoder, so a line break
    /// or a tab (a multi-line message) is safe.
    Body,
}

fn type_of(op: &Operation, name: &str) -> Result<Option<(ParamType, Place)>, BrokerError> {
    if let Some(t) = op.path_params.get(name) {
        return Ok(Some((ParamType::parse(t, None)?, Place::Path)));
    }
    if let Some(t) = op.query.get(name) {
        return Ok(Some((ParamType::parse(t, None)?, Place::Query)));
    }
    // Body params are checked like query params (decision 2), except that
    // `\n` and `\t` are allowed.
    // A param that fills the capability qualifier never takes a line break
    // or a tab: a multi-line qualifier would be read differently by the
    // policy matcher and by whatever shows or records it.
    if let Some(t) = op.body_params.get(name) {
        let in_qualifier = op
            .qualifier
            .as_deref()
            .is_some_and(|q| q.contains(&format!("{{{name}}}")));
        let place = if in_qualifier {
            Place::Query
        } else {
            Place::Body
        };
        return Ok(Some((ParamType::parse(t, None)?, place)));
    }
    Ok(None)
}

fn check_one(name: &str, v: &str, ty: Option<&(ParamType, Place)>) -> Result<(), BrokerError> {
    let body = matches!(ty, Some((_, Place::Body)));
    let control = if body {
        v.chars()
            .any(|c| c != '\n' && c != '\t' && ((c as u32) < 0x20 || c == '\u{7f}'))
    } else {
        has_control(v)
    };
    if control {
        return Err(bad_value(name, "contains a control character"));
    }
    if let Some((t, place)) = ty {
        // An object key or name has its own segment checks (in `t.check`).
        if *place == Place::Path && !t.is_object() {
            if let Some(why) = path_value_problem(v) {
                return Err(bad_value(name, why));
            }
        }
        t.check(v).map_err(|why| bad_value(name, why))?;
    }
    Ok(())
}

/// Validates the parameters of a call against `op` (spec §6.7.1 step 5).
/// `fixed` holds the values the policy sets; the agent may not give them.
/// The result is `given` plus `fixed`, every value checked.
pub fn validate(
    op: &Operation,
    given: &BTreeMap<String, String>,
    fixed: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, BrokerError> {
    for k in given.keys() {
        if fixed.contains_key(k) {
            return Err(BrokerError::FixedParam(k.clone()));
        }
    }
    let mut out = BTreeMap::new();
    for (k, v) in given {
        let ty = type_of(op, k)?.ok_or_else(|| BrokerError::UnknownParam(k.clone()))?;
        check_one(k, v, Some(&ty))?;
        out.insert(k.clone(), v.clone());
    }
    for (k, v) in fixed {
        let ty = type_of(op, k)?;
        check_one(k, v, ty.as_ref())?;
        out.insert(k.clone(), v.clone());
    }
    for name in op.path_params.keys() {
        if !out.contains_key(name) {
            return Err(BrokerError::MissingParam(name.clone()));
        }
    }
    Ok(out)
}
