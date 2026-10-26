//! Amount extraction (spec §6.9.4). Integer minor units only: no floats.

use crate::manifest::{AmountSpec, Unit};
use crate::BrokerError;
use serde_json::Value;

/// ISO 4217 minor-unit exponent (default 2).
pub fn exponent(currency: &str) -> u32 {
    match currency.to_ascii_uppercase().as_str() {
        "JPY" | "KRW" | "CLP" | "ISK" | "VND" => 0,
        "BHD" | "JOD" | "KWD" | "OMR" | "TND" => 3,
        _ => 2,
    }
}

fn bad(why: &str) -> BrokerError {
    BrokerError::BadAmount(why.to_string())
}

/// Collect every value at `path` (`a.b[].c`; `[]` fans out over an array).
fn collect<'a>(v: &'a Value, path: &str) -> Vec<&'a Value> {
    let mut cur = vec![v];
    for seg in path.split('.') {
        let (key, fan) = match seg.strip_suffix("[]") {
            Some(k) => (k, true),
            None => (seg, false),
        };
        let mut next = Vec::new();
        for c in cur {
            let item = if key.is_empty() { Some(c) } else { c.get(key) };
            match item {
                Some(Value::Array(a)) if fan => next.extend(a.iter()),
                Some(x) if !fan => next.push(x),
                _ => {}
            }
        }
        cur = next;
    }
    cur
}

/// Parse `digits[.digits]` digit by digit into minor units.
fn parse_minor(text: &str, unit: Unit, exp: u32) -> Result<u64, BrokerError> {
    let (int, frac) = match text.split_once('.') {
        Some((i, f)) => (i, f),
        None => (text, ""),
    };
    let digits_only = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if int.is_empty() || !digits_only(int) || !digits_only(frac) {
        return Err(bad("not a non-negative decimal number"));
    }
    if text.contains('.') && frac.is_empty() {
        return Err(bad("not a non-negative decimal number"));
    }
    let (decimals, scale) = match unit {
        Unit::Major => (exp as usize, exp as usize),
        Unit::Minor => (0, 0),
    };
    if frac.len() > decimals {
        return Err(bad("too many decimals for the currency"));
    }
    let mut acc: u64 = 0;
    for b in int.bytes().chain(frac.bytes()) {
        acc = acc
            .checked_mul(10)
            .and_then(|a| a.checked_add(u64::from(b - b'0')))
            .ok_or_else(|| bad("amount out of range"))?;
    }
    for _ in frac.len()..scale {
        acc = acc
            .checked_mul(10)
            .ok_or_else(|| bad("amount out of range"))?;
    }
    Ok(acc)
}

/// Extract `(minor units, upper-case currency)` from a request body.
pub fn extract(spec: &AmountSpec, body: &Value) -> Result<(u64, String), BrokerError> {
    let mut currency: Option<String> = None;
    for c in collect(body, &spec.currency_field) {
        let s = c
            .as_str()
            .ok_or_else(|| bad("currency is not a string"))?
            .to_ascii_uppercase();
        match &currency {
            None => currency = Some(s),
            Some(p) if *p == s => {}
            Some(_) => return Err(bad("mixed currencies")),
        }
    }
    let currency = currency.ok_or_else(|| bad("currency missing"))?;
    if currency.len() != 3 || !currency.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(bad("currency is not a 3-letter code"));
    }
    let exp = exponent(&currency);
    let vals = collect(body, &spec.field);
    if vals.is_empty() {
        return Err(bad("amount missing"));
    }
    let mut total: u64 = 0;
    for v in vals {
        let text = match v {
            Value::Number(n) => n.to_string(),
            Value::String(s) => s.clone(),
            _ => return Err(bad("amount is not a number")),
        };
        let m = parse_minor(&text, spec.unit, exp)?;
        total = total
            .checked_add(m)
            .ok_or_else(|| bad("amount out of range"))?;
    }
    Ok((total, currency))
}
