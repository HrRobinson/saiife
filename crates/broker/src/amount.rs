//! Amount extraction (spec §6.9.4). Integer minor units only: no floats.

use crate::manifest::{AmountSpec, Unit};
use crate::BrokerError;
use serde_json::Value;

/// Minor-unit exponent of an active ISO 4217 currency (list as of the
/// current amendment; funds codes included, metals and test codes excluded).
/// `None` for an unknown code, which callers must deny.
pub fn exponent(currency: &str) -> Option<u32> {
    const ZERO: &[&str] = &[
        "BIF", "CLP", "DJF", "GNF", "ISK", "JPY", "KMF", "KRW", "PYG", "RWF", "UGX", "UYI", "VND",
        "VUV", "XAF", "XOF", "XPF",
    ];
    const TWO: &[&str] = &[
        "AED", "AFN", "ALL", "AMD", "ANG", "AOA", "ARS", "AUD", "AWG", "AZN", "BAM", "BBD", "BDT",
        "BGN", "BMD", "BND", "BOB", "BOV", "BRL", "BSD", "BTN", "BWP", "BYN", "BZD", "CAD", "CDF",
        "CHE", "CHF", "CHW", "CNY", "COP", "COU", "CRC", "CUP", "CVE", "CZK", "DKK", "DOP", "DZD",
        "EGP", "ERN", "ETB", "EUR", "FJD", "FKP", "GBP", "GEL", "GHS", "GIP", "GMD", "GTQ", "GYD",
        "HKD", "HNL", "HTG", "HUF", "IDR", "ILS", "INR", "IRR", "JMD", "KES", "KGS", "KHR", "KPW",
        "KYD", "KZT", "LAK", "LBP", "LKR", "LRD", "LSL", "MAD", "MDL", "MGA", "MKD", "MMK", "MNT",
        "MOP", "MRU", "MUR", "MVR", "MWK", "MXN", "MXV", "MYR", "MZN", "NAD", "NGN", "NIO", "NOK",
        "NPR", "NZD", "PAB", "PEN", "PGK", "PHP", "PKR", "PLN", "QAR", "RON", "RSD", "RUB", "SAR",
        "SBD", "SCR", "SDG", "SEK", "SGD", "SHP", "SLE", "SOS", "SRD", "SSP", "STN", "SVC", "SYP",
        "SZL", "THB", "TJS", "TMT", "TOP", "TRY", "TTD", "TWD", "TZS", "UAH", "USD", "USN", "UZS",
        "VED", "VES", "WST", "XCD", "YER", "ZAR", "ZMW", "ZWG",
    ];
    const THREE: &[&str] = &["BHD", "IQD", "JOD", "KWD", "LYD", "OMR", "TND"];
    const FOUR: &[&str] = &["CLF", "UYW"];
    let c = currency.to_ascii_uppercase();
    let c = c.as_str();
    if ZERO.contains(&c) {
        Some(0)
    } else if TWO.contains(&c) {
        Some(2)
    } else if THREE.contains(&c) {
        Some(3)
    } else if FOUR.contains(&c) {
        Some(4)
    } else {
        None
    }
}

fn bad(why: &str) -> BrokerError {
    BrokerError::BadAmount(why.to_string())
}

/// Collect every value at `path` (`a.b[].c`; `[]` fans out over an array).
/// Strict: every branch must yield a value, otherwise `BadAmount`.
fn collect<'a>(v: &'a Value, path: &str) -> Result<Vec<&'a Value>, BrokerError> {
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
                _ => return Err(bad("path missing on a branch")),
            }
        }
        cur = next;
    }
    Ok(cur)
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
    for c in collect(body, &spec.currency_field)? {
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
    let exp = exponent(&currency).ok_or_else(|| bad("unknown currency"))?;
    let vals = collect(body, &spec.field)?;
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
