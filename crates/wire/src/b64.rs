//! base64url without padding (the only base64 on the wire) and lowercase hex.

use crate::WireError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

/// Encode as base64url, no padding.
pub fn enc(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

/// Decode base64url, no padding. Padding or the standard alphabet is `Malformed`.
pub fn dec(s: &str) -> Result<Vec<u8>, WireError> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| WireError::Malformed(format!("base64url: {e}")))
}

/// Decode into exactly `N` bytes.
pub fn dec_n<const N: usize>(s: &str) -> Result<[u8; N], WireError> {
    let v = dec(s)?;
    <[u8; N]>::try_from(v.as_slice())
        .map_err(|_| WireError::Malformed(format!("expected {N} bytes, got {}", v.len())))
}

/// Lowercase hex.
pub fn hex(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(D[(x >> 4) as usize] as char);
        s.push(D[(x & 15) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_url_safe_no_pad() {
        assert_eq!(enc(&[0xfb, 0xff]), "-_8");
        assert_eq!(dec("-_8").unwrap(), vec![0xfb, 0xff]);
    }

    #[test]
    fn padding_is_malformed() {
        assert!(matches!(dec("AA=="), Err(WireError::Malformed(_))));
    }

    #[test]
    fn standard_alphabet_is_malformed() {
        assert!(matches!(dec("+/8"), Err(WireError::Malformed(_))));
    }

    #[test]
    fn dec_n_checks_length() {
        let s = enc(&[7u8; 15]);
        assert!(matches!(dec_n::<16>(&s), Err(WireError::Malformed(_))));
        assert_eq!(dec_n::<15>(&s).unwrap(), [7u8; 15]);
    }

    #[test]
    fn hex_is_lowercase() {
        assert_eq!(hex(&[0x0a, 0xff, 0x00]), "0aff00");
    }
}
