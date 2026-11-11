//! WebAuthn authenticator data (§6.1).

use crate::cbor::{self, Item};
use crate::cose::CoseKey;
use crate::TouchError;

/// User present.
pub const UP: u8 = 0x01;
/// User verified.
pub const UV: u8 = 0x04;
/// Attested credential data follows.
pub const AT: u8 = 0x40;
/// Extension data follows.
pub const ED: u8 = 0x80;

/// Attested credential data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attested {
    pub aaguid: [u8; 16],
    pub credential_id: Vec<u8>,
    pub public_key: CoseKey,
}

/// Parsed authenticator data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthData<'a> {
    pub rp_id_hash: [u8; 32],
    pub flags: u8,
    pub sign_count: u32,
    pub attested: Option<Attested>,
    #[allow(dead_code)]
    raw: &'a [u8],
}

/// Parses authenticator data; any trailing byte is `Malformed`.
pub fn parse(raw: &[u8]) -> Result<AuthData<'_>, TouchError> {
    if raw.len() < 37 {
        return Err(TouchError::Malformed);
    }
    let rp_id_hash: [u8; 32] = raw[..32].try_into().map_err(|_| TouchError::Malformed)?;
    let flags = raw[32];
    let sign_count = u32::from_be_bytes([raw[33], raw[34], raw[35], raw[36]]);
    let mut rest = &raw[37..];
    let mut attested = None;
    if flags & AT != 0 {
        if rest.len() < 18 {
            return Err(TouchError::Malformed);
        }
        let aaguid: [u8; 16] = rest[..16].try_into().map_err(|_| TouchError::Malformed)?;
        let len = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
        if !(1..=1023).contains(&len) {
            return Err(TouchError::Malformed);
        }
        rest = &rest[18..];
        if rest.len() < len {
            return Err(TouchError::Malformed);
        }
        let credential_id = rest[..len].to_vec();
        rest = &rest[len..];
        let (public_key, used) = CoseKey::parse(rest)?;
        rest = &rest[used..];
        attested = Some(Attested {
            aaguid,
            credential_id,
            public_key,
        });
    }
    if flags & ED != 0 {
        let (item, r) = cbor::read(rest)?;
        if !matches!(item, Item::Map(_)) {
            return Err(TouchError::Malformed);
        }
        rest = r;
    }
    if !rest.is_empty() {
        return Err(TouchError::Malformed);
    }
    Ok(AuthData {
        rp_id_hash,
        flags,
        sign_count,
        attested,
        raw,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(flags: u8) -> Vec<u8> {
        let mut v = vec![9u8; 32];
        v.push(flags);
        v.extend([0, 0, 1, 0]);
        v
    }

    #[test]
    fn authdata_without_at() {
        let b = head(0x05);
        let a = parse(&b).unwrap();
        assert_eq!((a.flags, a.sign_count), (5, 256));
        assert_eq!(a.rp_id_hash, [9; 32]);
        assert!(a.attested.is_none());
        let mut long = b;
        long.push(0);
        assert_eq!(parse(&long).unwrap_err(), TouchError::Malformed);
    }

    #[test]
    fn authdata_with_attested_credential() {
        let key = CoseKey::Es256 {
            x: [1; 32],
            y: [2; 32],
        };
        let mut b = head(0x45);
        b.extend([7u8; 16]);
        b.extend([0, 3, 1, 2, 3]);
        b.extend(key.to_cose());
        let a = parse(&b).unwrap();
        assert_eq!(
            a.attested,
            Some(Attested {
                aaguid: [7; 16],
                credential_id: vec![1, 2, 3],
                public_key: key
            })
        );
        assert_eq!(parse(&b[..b.len() - 1]).unwrap_err(), TouchError::Malformed);
    }

    #[test]
    fn authdata_skips_extensions() {
        let mut b = head(0x81);
        b.push(0xa1);
        b.push(0x6b);
        b.extend(b"credProtect");
        b.push(0x02);
        assert!(parse(&b).is_ok());
        b.push(0);
        assert_eq!(parse(&b).unwrap_err(), TouchError::Malformed);
    }

    #[test]
    fn authdata_rejects_bad_id_length() {
        let mut b = head(0x40);
        b.extend([0u8; 16]);
        b.extend([0, 0]);
        assert_eq!(parse(&b).unwrap_err(), TouchError::Malformed);
    }
}
