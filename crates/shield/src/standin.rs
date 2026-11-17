//! Dataset key sets and keyed stand-ins (plan 44, R44-4). A stand-in is
//! `<Word>_<base32>` from an HMAC under the session key, so it is stable
//! inside one session and unrelated to any other.

use crate::error::ShieldError;
use ring::hmac;
use zeroize::{Zeroize, Zeroizing};

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Longest stand-in code: 32 HMAC bytes are 52 base32 characters.
pub(crate) const MAX_CODE_LEN: usize = 52;

/// RFC 4648 base32, no padding.
fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(B32[((acc >> bits) & 31) as usize]));
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(B32[((acc << (5 - bits)) & 31) as usize]));
    }
    out
}

/// Standard base64 with padding, appended to `out`.
fn base64_encode_into(out: &mut Vec<u8>, data: &[u8]) {
    for chunk in data.chunks(3) {
        let n = match chunk.len() {
            3 => (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]),
            2 => (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8),
            _ => u32::from(chunk[0]) << 16,
        };
        out.push(B64[((n >> 18) & 63) as usize]);
        out.push(B64[((n >> 12) & 63) as usize]);
        out.push(if chunk.len() > 1 {
            B64[((n >> 6) & 63) as usize]
        } else {
            b'='
        });
        out.push(if chunk.len() > 2 {
            B64[(n & 63) as usize]
        } else {
            b'='
        });
    }
}

#[cfg(test)]
fn base64_encode(data: &[u8]) -> String {
    let mut v = Vec::new();
    base64_encode_into(&mut v, data);
    String::from_utf8(v).unwrap_or_default()
}

fn b64_val(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Strict standard base64 (padding required). The result is zeroized on drop.
fn base64_decode(s: &str) -> Option<Zeroizing<Vec<u8>>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(b.len() / 4 * 3));
    let groups = b.len() / 4;
    for (gi, g) in b.chunks(4).enumerate() {
        let last = gi + 1 == groups;
        let pad = g.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n: u32 = 0;
        for &c in &g[..4 - pad] {
            n = (n << 6) | b64_val(c)?;
        }
        n <<= 6 * pad as u32;
        // Non-canonical trailing bits are refused.
        if pad == 2 && (n & 0xffff) != 0 || pad == 1 && (n & 0xff) != 0 {
            return None;
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// Seconds since the epoch for `YYYY-MM-DD` or `YYYY-MM-DDTHH:MM:SS[Z]`.
fn parse_unix(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let part = b.get(r)?;
        if part.is_empty() || !part.iter().all(u8::is_ascii_digit) {
            return None;
        }
        part.iter()
            .try_fold(0i64, |a, &c| Some(a * 10 + i64::from(c - b'0')))
    };
    if b.len() < 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let mut secs = 0i64;
    if b.len() > 10 {
        if (b[10] != b'T' && b[10] != b' ') || b.len() < 19 || b[13] != b':' || b[16] != b':' {
            return None;
        }
        secs = num(11..13)? * 3600 + num(14..16)? * 60 + num(17..19)?;
    }
    // Days from civil (Howard Hinnant).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + secs).ok()
}

pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], ShieldError> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|_| ShieldError::Io("random source unavailable".into()))?;
    Ok(b)
}

fn random_key() -> Result<Zeroizing<[u8; 32]>, ShieldError> {
    let mut k = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut k[..]).map_err(|_| ShieldError::Io("random source unavailable".into()))?;
    Ok(k)
}

#[derive(Clone)]
pub struct RetiredKey {
    pub version: u32,
    pub standin: Zeroizing<[u8; 32]>,
    pub retired_at: String,
}

impl PartialEq for RetiredKey {
    fn eq(&self, o: &Self) -> bool {
        self.version == o.version && *self.standin == *o.standin && self.retired_at == o.retired_at
    }
}

impl std::fmt::Debug for RetiredKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetiredKey")
            .field("version", &self.version)
            .field("retired_at", &self.retired_at)
            .finish_non_exhaustive()
    }
}

/// The dataset's keys: the stand-in key (sessions derive from it) and the
/// index key (plan 43 builds the keyed index from it).
#[derive(Clone)]
pub struct KeySet {
    pub version: u32,
    pub standin: Zeroizing<[u8; 32]>,
    pub index: Zeroizing<[u8; 32]>,
    pub created: String,
    pub retired: Vec<RetiredKey>,
}

impl PartialEq for KeySet {
    fn eq(&self, o: &Self) -> bool {
        self.version == o.version
            && *self.standin == *o.standin
            && *self.index == *o.index
            && self.created == o.created
            && self.retired == o.retired
    }
}

impl std::fmt::Debug for KeySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeySet")
            .field("version", &self.version)
            .field("created", &self.created)
            .field("retired", &self.retired)
            .finish_non_exhaustive()
    }
}

/// Wire form; the strings hold base64 key text and are wiped on drop.
#[derive(serde::Deserialize)]
struct WireKeySet {
    version: u32,
    standin: String,
    index: String,
    created: String,
    retired: Vec<WireRetired>,
}

#[derive(serde::Deserialize)]
struct WireRetired {
    version: u32,
    standin: String,
    retired_at: String,
}

impl Drop for WireKeySet {
    fn drop(&mut self) {
        self.standin.zeroize();
        self.index.zeroize();
        for r in &mut self.retired {
            r.standin.zeroize();
        }
    }
}

fn key_from_b64(s: &str) -> Result<Zeroizing<[u8; 32]>, ShieldError> {
    let raw = base64_decode(s).ok_or(ShieldError::Corrupt("key set"))?;
    let mut k = Zeroizing::new([0u8; 32]);
    if raw.len() != 32 {
        return Err(ShieldError::Corrupt("key set"));
    }
    k.copy_from_slice(&raw);
    Ok(k)
}

fn push_json_str(out: &mut Vec<u8>, s: &str) {
    // serde_json string escaping of a plain &str cannot fail.
    out.extend_from_slice(serde_json::to_string(s).unwrap_or_default().as_bytes());
}

impl KeySet {
    pub fn generate(now: &str) -> Result<KeySet, ShieldError> {
        Ok(KeySet {
            version: 1,
            standin: random_key()?,
            index: random_key()?,
            created: now.to_string(),
            retired: Vec::new(),
        })
    }

    /// A new stand-in key; the old one moves to `retired` for the grace period.
    pub fn rotate(&mut self, now: &str) -> Result<(), ShieldError> {
        let fresh = random_key()?;
        let old = std::mem::replace(&mut self.standin, fresh);
        self.retired.push(RetiredKey {
            version: self.version,
            standin: old,
            retired_at: now.to_string(),
        });
        self.version += 1;
        Ok(())
    }

    /// Drops retired keys older than `grace_days`. A retired key whose date
    /// cannot be read is kept.
    pub fn purge_retired(&mut self, now_unix: u64, grace_days: u32) {
        let grace = u64::from(grace_days) * 86_400;
        self.retired.retain(|r| match parse_unix(&r.retired_at) {
            Some(t) => t.saturating_add(grace) > now_unix,
            None => true,
        });
    }

    /// JSON with base64 keys; the daemon seals these bytes (plan 47).
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(512));
        out.extend_from_slice(format!("{{\"version\":{},\"standin\":\"", self.version).as_bytes());
        base64_encode_into(&mut out, &*self.standin);
        out.extend_from_slice(b"\",\"index\":\"");
        base64_encode_into(&mut out, &*self.index);
        out.extend_from_slice(b"\",\"created\":");
        push_json_str(&mut out, &self.created);
        out.extend_from_slice(b",\"retired\":[");
        for (i, r) in self.retired.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            out.extend_from_slice(format!("{{\"version\":{},\"standin\":\"", r.version).as_bytes());
            base64_encode_into(&mut out, &*r.standin);
            out.extend_from_slice(b"\",\"retired_at\":");
            push_json_str(&mut out, &r.retired_at);
            out.push(b'}');
        }
        out.extend_from_slice(b"]}");
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<KeySet, ShieldError> {
        let w: WireKeySet =
            serde_json::from_slice(b).map_err(|_| ShieldError::Corrupt("key set"))?;
        let mut retired = Vec::with_capacity(w.retired.len());
        for r in &w.retired {
            retired.push(RetiredKey {
                version: r.version,
                standin: key_from_b64(&r.standin)?,
                retired_at: r.retired_at.clone(),
            });
        }
        Ok(KeySet {
            version: w.version,
            standin: key_from_b64(&w.standin)?,
            index: key_from_b64(&w.index)?,
            created: w.created.clone(),
            retired,
        })
    }
}

/// `HMAC(session_key, "standin" ‖ table ‖ 0x00 ‖ key (8 bytes, big endian))`
/// as RFC 4648 base32, first `len` characters (at most 52).
fn code(session_key: &[u8; 32], table: &str, key: i64, len: usize) -> String {
    let k = hmac::Key::new(hmac::HMAC_SHA256, session_key);
    let mut ctx = hmac::Context::with_key(&k);
    ctx.update(b"standin");
    ctx.update(table.as_bytes());
    ctx.update(&[0]);
    ctx.update(&key.to_be_bytes());
    let tag = ctx.sign();
    let mut s = base32_encode(tag.as_ref());
    s.truncate(len.min(MAX_CODE_LEN));
    s
}

fn capitalize(word: &str) -> String {
    let mut w: String = word.chars().filter(char::is_ascii_alphanumeric).collect();
    if w.is_empty() {
        w.push_str("entity");
    }
    let mut out = String::with_capacity(w.len());
    for (i, c) in w.chars().enumerate() {
        out.push(if i == 0 {
            c.to_ascii_uppercase()
        } else {
            c.to_ascii_lowercase()
        });
    }
    out
}

/// The stand-in symbol `<Word>_<len base32 chars>` (R44-4); `len` is 4 or 6.
pub fn standin(session_key: &[u8; 32], word: &str, table: &str, key: i64, len: usize) -> String {
    format!(
        "{}_{}",
        capitalize(word),
        code(session_key, table, key, len)
    )
}

/// `user_<4>@example.invalid`; not used in stage 1.
pub fn standin_email(session_key: &[u8; 32], table: &str, key: i64) -> String {
    format!("user_{}@example.invalid", code(session_key, table, key, 4))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn base32_rfc4648_vectors() {
        for (i, o) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32_encode(i.as_bytes()), o);
        }
    }

    #[test]
    fn base64_rfc4648_vectors() {
        for (i, o) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(i.as_bytes()), o);
            assert_eq!(
                base64_decode(o).as_deref().map(Vec::as_slice),
                Some(i.as_bytes())
            );
        }
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(
            base64_decode(&base64_encode(&all))
                .as_deref()
                .map(Vec::as_slice),
            Some(&all[..])
        );
        for bad in [
            "Zg=", "Zg", "Z===", "Zh==", "Zm9=", "Zm9v====", "Zm=v", "Zm9!",
        ] {
            assert!(base64_decode(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn dates_parse_to_unix() {
        assert_eq!(parse_unix("1970-01-01"), Some(0));
        assert_eq!(parse_unix("2026-11-17T10:00:00Z"), Some(1_794_909_600));
        assert_eq!(parse_unix("2000-03-01T00:00:00Z"), Some(951_868_800));
        assert_eq!(parse_unix("nonsense"), None);
        assert_eq!(parse_unix("2026-13-01"), None);
    }

    #[test]
    fn standin_is_stable_and_keyed() {
        let a = standin(&key(1), "customer", "customers", 7, 4);
        assert_eq!(a, standin(&key(1), "customer", "customers", 7, 4));
        assert_ne!(a, standin(&key(2), "customer", "customers", 7, 4));
        assert_ne!(a, standin(&key(1), "customer", "customers", 8, 4));
        assert_ne!(a, standin(&key(1), "customer", "orders", 7, 4));
        let (w, c) = a.split_once('_').unwrap();
        assert_eq!(w, "Customer");
        assert!(c.len() == 4 && c.bytes().all(|x| matches!(x, b'A'..=b'Z' | b'2'..=b'7')));
        let six = standin(&key(1), "customer", "customers", 7, 6);
        assert!(six.starts_with(&a) && six.len() == a.len() + 2);
        let e = standin_email(&key(1), "customers", 7);
        assert!(e.starts_with("user_") && e.ends_with("@example.invalid") && e.len() == 5 + 4 + 16);
    }

    #[test]
    fn rotate_keeps_retired_for_grace() {
        let mut ks = KeySet::generate("2026-01-01T00:00:00Z").unwrap();
        let old = ks.standin.clone();
        ks.rotate("2026-02-01T00:00:00Z").unwrap();
        assert_eq!(ks.version, 2);
        assert_ne!(*ks.standin, *old);
        assert_eq!(ks.retired.len(), 1);
        assert_eq!(*ks.retired[0].standin, *old);
        assert_eq!(ks.retired[0].version, 1);
        let day = 86_400u64;
        let t0 = parse_unix("2026-02-01T00:00:00Z").unwrap();
        ks.purge_retired(t0 + 29 * day, 30);
        assert_eq!(ks.retired.len(), 1);
        ks.purge_retired(t0 + 31 * day, 30);
        assert!(ks.retired.is_empty());
    }

    #[test]
    fn keyset_round_trip_and_debug() {
        let mut ks = KeySet::generate("2026-01-01T00:00:00Z").unwrap();
        ks.rotate("2026-02-01T00:00:00Z").unwrap();
        let bytes = ks.to_bytes();
        let back = KeySet::from_bytes(&bytes).unwrap();
        assert_eq!(back, ks);
        let dbg = format!("{ks:?}");
        let mut all: Vec<&[u8; 32]> = vec![&ks.standin, &ks.index];
        all.extend(ks.retired.iter().map(|r| &*r.standin));
        for k in all {
            let hex: String = k.iter().map(|b| format!("{b:02x}")).collect();
            assert!(!dbg.contains(&hex));
            assert!(!dbg.contains(&base64_encode(k)));
            assert!(!dbg.contains(&format!("{:?}", &k[..])));
        }
        assert!(dbg.contains("version") && dbg.contains("2026-02-01"));
        assert!(KeySet::from_bytes(b"{}").is_err());
        assert!(KeySet::from_bytes(b"not json").is_err());
        let bad = br#"{"version":1,"standin":"AAAA","index":"AAAA","created":"x","retired":[]}"#;
        assert!(matches!(
            KeySet::from_bytes(bad),
            Err(ShieldError::Corrupt(_))
        ));
    }
}
