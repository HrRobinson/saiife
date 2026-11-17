//! A bounded, strict CBOR reader (RFC 8949 subset: definite lengths, no tags, no floats).

use crate::TouchError;

const MAX_DEPTH: usize = 8;
const MAX_ITEMS: u64 = 64;

/// One decoded CBOR item, borrowing from the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Item<'a> {
    Uint(u64),
    Nint(i128),
    Bytes(&'a [u8]),
    Text(&'a str),
    Array(Vec<Item<'a>>),
    Map(Vec<(Item<'a>, Item<'a>)>),
    Bool(bool),
    Null,
}

/// Reads one item and returns it with the rest of the input.
pub(crate) fn read(input: &[u8]) -> Result<(Item<'_>, &[u8]), TouchError> {
    read_at(input, 0)
}

fn take(input: &[u8], n: usize) -> Result<(&[u8], &[u8]), TouchError> {
    if n > input.len() {
        return Err(TouchError::Malformed);
    }
    Ok(input.split_at(n))
}

fn read_at(input: &[u8], depth: usize) -> Result<(Item<'_>, &[u8]), TouchError> {
    if depth > MAX_DEPTH {
        return Err(TouchError::Malformed);
    }
    let (&head, rest) = input.split_first().ok_or(TouchError::Malformed)?;
    let major = head >> 5;
    let info = head & 0x1f;
    if major == 7 {
        return match info {
            20 => Ok((Item::Bool(false), rest)),
            21 => Ok((Item::Bool(true), rest)),
            22 => Ok((Item::Null, rest)),
            _ => Err(TouchError::Malformed),
        };
    }
    if major == 6 {
        return Err(TouchError::Malformed);
    }
    let (arg, rest) = match info {
        0..=23 => (u64::from(info), rest),
        24..=27 => {
            let n = 1usize << (info - 24);
            let (b, rest) = take(rest, n)?;
            (b.iter().fold(0u64, |a, &x| (a << 8) | u64::from(x)), rest)
        }
        _ => return Err(TouchError::Malformed),
    };
    match major {
        0 => Ok((Item::Uint(arg), rest)),
        1 => Ok((Item::Nint(-1 - i128::from(arg)), rest)),
        2 | 3 => {
            let n = usize::try_from(arg).map_err(|_| TouchError::Malformed)?;
            let (b, rest) = take(rest, n)?;
            if major == 2 {
                Ok((Item::Bytes(b), rest))
            } else {
                let s = std::str::from_utf8(b).map_err(|_| TouchError::Malformed)?;
                Ok((Item::Text(s), rest))
            }
        }
        4 => {
            if arg > MAX_ITEMS {
                return Err(TouchError::Malformed);
            }
            let mut items = Vec::new();
            let mut rest = rest;
            for _ in 0..arg {
                let (it, r) = read_at(rest, depth + 1)?;
                items.push(it);
                rest = r;
            }
            Ok((Item::Array(items), rest))
        }
        _ => {
            if arg > MAX_ITEMS {
                return Err(TouchError::Malformed);
            }
            let mut items = Vec::new();
            let mut rest = rest;
            for _ in 0..arg {
                let (k, r) = read_at(rest, depth + 1)?;
                let (v, r) = read_at(r, depth + 1)?;
                items.push((k, v));
                rest = r;
            }
            Ok((Item::Map(items), rest))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbor_reads_the_basics() {
        assert_eq!(read(&[0x18, 0x2a]).unwrap(), (Item::Uint(42), &[][..]));
        assert_eq!(read(&[0x38, 0x63]).unwrap().0, Item::Nint(-100));
        assert_eq!(read(&[0x43, 1, 2, 3]).unwrap().0, Item::Bytes(&[1, 2, 3]));
        assert_eq!(
            read(&[0xa1, 0x01, 0x02]).unwrap().0,
            Item::Map(vec![(Item::Uint(1), Item::Uint(2))])
        );
        let (it, rest) = read(&[0x01, 0xff, 0xee]).unwrap();
        assert_eq!(it, Item::Uint(1));
        assert_eq!(rest, &[0xff, 0xee]);
        assert_eq!(
            read(&[0x63, b'a', b'b', b'c']).unwrap().0,
            Item::Text("abc")
        );
        assert_eq!(read(&[0xf5]).unwrap().0, Item::Bool(true));
        assert_eq!(read(&[0xf6]).unwrap().0, Item::Null);
    }

    #[test]
    fn cbor_rejects_hostile_input() {
        let mut float = vec![0xfb];
        float.extend([0u8; 8]);
        let mut huge = vec![0x5b];
        huge.extend(u64::MAX.to_be_bytes());
        let mut huge_arr = vec![0x9b];
        huge_arr.extend((1u64 << 63).to_be_bytes());
        let mut nested = vec![0x81; 9];
        nested.push(0x00);
        let mut deep = vec![0x81; 100];
        deep.push(0x00);
        let cases: Vec<Vec<u8>> = vec![
            vec![0x5f],
            vec![0xc0, 0x00],
            float,
            huge,
            huge_arr,
            vec![0x42, 0x01],
            nested,
            deep,
            vec![0x98, 65],
            vec![0xa1, 0x01],
            vec![0x62, 0xff, 0xfe],
            vec![0xfc],
            vec![0xf7],
            vec![0x1c],
            vec![],
        ];
        for c in cases {
            assert_eq!(read(&c).unwrap_err(), TouchError::Malformed, "{c:02x?}");
        }
        // Eight levels deep is the limit and is fine.
        let mut ok = vec![0x81; 8];
        ok.push(0x00);
        assert!(read(&ok).is_ok());
    }
}
