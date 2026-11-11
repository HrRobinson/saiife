//! COSE public keys (RFC 9052): ES256 and Ed25519 only.

use crate::cbor::{self, Item};
use crate::{CoseAlg, TouchError};

/// A credential public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoseKey {
    /// P-256 point, affine coordinates.
    Es256 { x: [u8; 32], y: [u8; 32] },
    /// Ed25519 public key.
    Ed25519 { x: [u8; 32] },
}

fn label(map: &[(Item<'_>, Item<'_>)], l: i128) -> Option<i128> {
    map.iter().find_map(|(k, v)| {
        let kk = match k {
            Item::Uint(u) => i128::from(*u),
            Item::Nint(n) => *n,
            _ => return None,
        };
        match (kk == l, v) {
            (true, Item::Uint(u)) => Some(i128::from(*u)),
            (true, Item::Nint(n)) => Some(*n),
            _ => None,
        }
    })
}

fn coord(map: &[(Item<'_>, Item<'_>)], l: i128) -> Result<[u8; 32], TouchError> {
    for (k, v) in map {
        let kk = match k {
            Item::Uint(u) => i128::from(*u),
            Item::Nint(n) => *n,
            _ => continue,
        };
        if kk == l {
            if let Item::Bytes(b) = v {
                return <[u8; 32]>::try_from(*b).map_err(|_| TouchError::Malformed);
            }
            return Err(TouchError::Malformed);
        }
    }
    Err(TouchError::Malformed)
}

impl CoseKey {
    /// Parses one COSE key and returns it with the number of bytes used.
    pub fn parse(bytes: &[u8]) -> Result<(CoseKey, usize), TouchError> {
        let (item, rest) = cbor::read(bytes)?;
        let Item::Map(map) = item else {
            return Err(TouchError::Malformed);
        };
        let used = bytes.len() - rest.len();
        let kty = label(&map, 1);
        let alg = label(&map, 3);
        let crv = label(&map, -1);
        let key = match (kty, alg, crv) {
            (Some(2), Some(-7), Some(1)) => CoseKey::Es256 {
                x: coord(&map, -2)?,
                y: coord(&map, -3)?,
            },
            (Some(1), Some(-8), Some(6)) => CoseKey::Ed25519 {
                x: coord(&map, -2)?,
            },
            _ => return Err(TouchError::Malformed),
        };
        Ok((key, used))
    }

    /// Encodes the key as a COSE_Key map, labels in the order 1, 3, -1, -2, -3.
    pub fn to_cose(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            CoseKey::Es256 { x, y } => {
                out.extend([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
                out.extend(x);
                out.extend([0x22, 0x58, 0x20]);
                out.extend(y);
            }
            CoseKey::Ed25519 { x } => {
                out.extend([0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20]);
                out.extend(x);
            }
        }
        out
    }

    /// The signature algorithm of this key.
    pub fn alg(&self) -> CoseAlg {
        match self {
            CoseKey::Es256 { .. } => CoseAlg::Es256,
            CoseKey::Ed25519 { .. } => CoseAlg::Ed25519,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cose_es256_round_trip() {
        let k = CoseKey::Es256 {
            x: [1; 32],
            y: [2; 32],
        };
        let b = k.to_cose();
        assert_eq!(CoseKey::parse(&b).unwrap(), (k.clone(), b.len()));
        assert_eq!(k.alg(), CoseAlg::Es256);
    }

    #[test]
    fn cose_ed25519_round_trip() {
        let k = CoseKey::Ed25519 { x: [3; 32] };
        let b = k.to_cose();
        assert_eq!(CoseKey::parse(&b).unwrap(), (k.clone(), b.len()));
        assert_eq!(k.alg(), CoseAlg::Ed25519);
    }

    #[test]
    fn cose_rejects_other_algs() {
        let mut rs = vec![
            0xa5, 0x01, 0x02, 0x03, 0x39, 0x01, 0x00, 0x20, 0x01, 0x21, 0x58, 0x20,
        ];
        rs.extend([1u8; 32]);
        rs.extend([0x22, 0x58, 0x20]);
        rs.extend([2u8; 32]);
        assert_eq!(CoseKey::parse(&rs).unwrap_err(), TouchError::Malformed);
        let mut p384 = CoseKey::Es256 {
            x: [1; 32],
            y: [2; 32],
        }
        .to_cose();
        p384[6] = 0x02; // crv 2
        assert_eq!(CoseKey::parse(&p384).unwrap_err(), TouchError::Malformed);
    }

    #[test]
    fn cose_ignores_unknown_labels() {
        let mut b = CoseKey::Ed25519 { x: [3; 32] }.to_cose();
        b[0] = 0xa5;
        b.extend([0x18, 0x63, 0x01]);
        let (k, used) = CoseKey::parse(&b).unwrap();
        assert_eq!(k, CoseKey::Ed25519 { x: [3; 32] });
        assert_eq!(used, b.len());
    }
}
