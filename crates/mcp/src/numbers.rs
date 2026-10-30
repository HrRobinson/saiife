//! Whether the numbers of a JSON text survive saiife's f64 parse and
//! re-encoding unchanged. Shared by the daemon's `mcp.call` (gateway tool
//! arguments) and `saiife mcp` (connector JSON bodies, which the broker
//! parses and re-encodes): a number that would change is refused, never
//! rewritten.

/// Whether every number in the JSON text `b` (already parsed, so valid)
/// keeps its meaning through the parser and canonical JSON: no exponent
/// form (`1e2` would become `100.0`) and no integer outside the i64/u64
/// range (it would become a float and lose digits). Decimals like `1.5`
/// are kept.
pub fn numbers_exact(b: &[u8]) -> bool {
    let mut i = 0;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        if in_str {
            match c {
                b'\\' => i += 1,
                b'"' => in_str = false,
                _ => {}
            }
            i += 1;
            continue;
        }
        if c == b'"' {
            in_str = true;
            i += 1;
            continue;
        }
        if c == b'-' || c.is_ascii_digit() {
            let start = i;
            while i < b.len() && b"0123456789+-.eE".contains(&b[i]) {
                i += 1;
            }
            let tok = &b[start..i];
            if tok.iter().any(|&x| x == b'e' || x == b'E') {
                return false;
            }
            let t = std::str::from_utf8(tok).unwrap_or("");
            if !tok.contains(&b'.') {
                if t.parse::<i64>().is_err() && t.parse::<u64>().is_err() {
                    return false;
                }
            } else if !decimal_exact(t) {
                return false;
            }
            continue;
        }
        i += 1;
    }
    true
}

/// Whether the decimal `t` (`-?digits.digits`) survives the f64 round trip
/// with the same value: its value, as significant digits and a decimal
/// exponent, equals that of the shortest f64 text, whichever form that
/// text takes (`0.000001` prints `1e-6`, `10000000000000000.0` prints
/// `1e16`). `123456789012345.678` does not (f64 prints
/// `123456789012345.69`), nor does `10000000000000000.5` (`1e16`).
fn decimal_exact(t: &str) -> bool {
    let Ok(x) = t.parse::<f64>() else {
        return false;
    };
    let Some(n) = serde_json::Number::from_f64(x) else {
        return false;
    };
    match (decimal_norm(t), decimal_norm(&n.to_string())) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// A JSON number's value as `(negative, significant digits, exponent)`:
/// the value is `0.<digits> * 10^exponent`, the digits without leading or
/// trailing zeros. Zero is `(false, "", 0)`, however it is signed.
fn decimal_norm(s: &str) -> Option<(bool, String, i64)> {
    let (neg, s) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s),
    };
    let (mant, exp) = match s.find(['e', 'E']) {
        Some(p) => (&s[..p], s[p + 1..].parse::<i64>().ok()?),
        None => (s, 0),
    };
    let (int, frac) = mant.split_once('.').unwrap_or((mant, ""));
    if int.is_empty() || !int.bytes().chain(frac.bytes()).all(|b| b.is_ascii_digit()) {
        return None;
    }
    let all = format!("{int}{frac}");
    let lead = all.len() - all.trim_start_matches('0').len();
    let digits = all.trim_start_matches('0').trim_end_matches('0');
    if digits.is_empty() {
        return Some((false, String::new(), 0));
    }
    let pos = (int.len() as i64)
        .checked_add(exp)?
        .checked_sub(lead as i64)?;
    Some((neg, digits.to_string(), pos))
}
