//! Durations in the system config: `<n>s`, `<n>m` or `<n>h`, with n ≥ 1.

use std::time::Duration;

/// Parses `<n>s`, `<n>m` or `<n>h` (n ≥ 1, decimal digits only).
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let bad = || format!("invalid duration {s:?}: expected <n>s, <n>m or <n>h with n >= 1");
    let (digits, mult) = if let Some(d) = s.strip_suffix('s') {
        (d, 1)
    } else if let Some(d) = s.strip_suffix('m') {
        (d, 60)
    } else if let Some(d) = s.strip_suffix('h') {
        (d, 3600)
    } else {
        return Err(bad());
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let n: u64 = digits.parse().map_err(|_| bad())?;
    if n == 0 {
        return Err(bad());
    }
    n.checked_mul(mult).map(Duration::from_secs).ok_or_else(bad)
}

/// Serde glue: read a duration string, write whole seconds (the effective
/// policy shows durations as seconds).
pub(crate) mod as_secs {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let s = String::deserialize(d)?;
        super::parse_duration(&s).map_err(serde::de::Error::custom)
    }

    pub fn serialize<S: Serializer>(v: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(v.as_secs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units() {
        assert_eq!(parse_duration("30s"), Ok(Duration::from_secs(30)));
        assert_eq!(parse_duration("15m"), Ok(Duration::from_secs(900)));
        assert_eq!(parse_duration("2h"), Ok(Duration::from_secs(7200)));
    }

    #[test]
    fn rejects_bad_input() {
        for bad in [
            "",
            "s",
            "0s",
            "-1s",
            "+1s",
            "1",
            "1d",
            "1.5m",
            " 1s",
            "1s ",
            "1 s",
            "1S",
            "99999999999999999999h",
            "1é",
            "é",
        ] {
            assert!(parse_duration(bad).is_err(), "{bad:?} must be rejected");
        }
    }
}
