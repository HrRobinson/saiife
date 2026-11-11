//! Byte encodings shared by the JSON forms: base64url without padding for
//! bytes, lowercase hex for hashes. Use them as `#[serde(with = "...")]`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serializer};

pub(crate) use crate::action::hex;

/// base64url, no padding.
pub(crate) fn b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

/// Decodes base64url without padding; anything else is `None`.
pub(crate) fn unb64(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}

/// Decodes lowercase (or uppercase) hex of exactly `N` bytes.
pub(crate) fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let s = s.as_bytes();
    if s.len() != 2 * N {
        return None;
    }
    let nib = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = nib(s[2 * i])? << 4 | nib(s[2 * i + 1])?;
    }
    Some(out)
}

/// `Vec<u8>` as base64url.
pub(crate) mod b64 {
    use super::*;

    pub(crate) fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&b64(v))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        unb64(&s).ok_or_else(|| D::Error::custom("expected base64url without padding"))
    }
}

/// `Vec<Vec<u8>>` as a list of base64url strings.
pub(crate) mod b64_list {
    use super::*;
    use serde::ser::SerializeSeq;

    pub(crate) fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for b in v {
            seq.serialize_element(&b64(b))?;
        }
        seq.end()
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|s| unb64(s).ok_or_else(|| D::Error::custom("expected base64url without padding")))
            .collect()
    }
}

/// `[u8; 32]` as 64 hex digits.
pub(crate) mod hex32 {
    use super::*;

    pub(crate) fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex(v))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        unhex::<32>(&s).ok_or_else(|| D::Error::custom("expected 64 hex digits"))
    }
}

/// A `CoseKey` as base64url of its COSE encoding; trailing bytes are refused.
pub(crate) mod cose_b64 {
    use super::*;
    use crate::cose::CoseKey;

    pub(crate) fn serialize<S: Serializer>(k: &CoseKey, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&b64(&k.to_cose()))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<CoseKey, D::Error> {
        let s = String::deserialize(d)?;
        let raw =
            unb64(&s).ok_or_else(|| D::Error::custom("expected base64url without padding"))?;
        match CoseKey::parse(&raw) {
            Ok((k, used)) if used == raw.len() => Ok(k),
            _ => Err(D::Error::custom("expected an ES256 or Ed25519 COSE key")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_and_b64_round_trip() {
        let b = [0xab_u8; 32];
        assert_eq!(unhex::<32>(&hex(&b)), Some(b));
        assert_eq!(unhex::<32>("ab"), None);
        assert_eq!(unhex::<2>("zz00"), None);
        assert_eq!(b64(&[0xfb, 0xff]), "-_8");
        assert_eq!(unb64("-_8"), Some(vec![0xfb, 0xff]));
        assert_eq!(unb64("-_8="), None);
        assert_eq!(unb64("+/8"), None);
    }
}
