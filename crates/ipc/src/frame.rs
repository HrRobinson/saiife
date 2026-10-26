//! Frame codec: `u32` big-endian length, then UTF-8 JSON object, at most 1 MiB.
use serde_json::{Map, Value};
use std::io::{Read, Write};

pub const MAX_FRAME: usize = 1_048_576;
/// The largest frame the daemon sends and a client reads: an `api.call`
/// answer carries up to `max_response_bytes` (5 MiB by default) as base64.
/// Requests stay at [`MAX_FRAME`].
pub const MAX_ANSWER_FRAME: usize = 16 * 1_048_576;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("empty frame")]
    Empty,
    #[error("frame of {0} bytes exceeds the size limit")]
    TooLarge(usize),
    #[error("frame body is not UTF-8")]
    NotUtf8,
    #[error("frame body is not JSON")]
    NotJson,
    #[error("frame body is not a JSON object")]
    NotObject,
    #[error("connection closed")]
    Closed,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Header plus body bytes for `v`.
pub fn encode(v: &Value) -> Result<Vec<u8>, FrameError> {
    encode_max(v, MAX_FRAME)
}

/// [`encode`] with another size limit (the daemon's answers:
/// [`MAX_ANSWER_FRAME`]).
pub fn encode_max(v: &Value, max: usize) -> Result<Vec<u8>, FrameError> {
    let body = serde_json::to_vec(v).map_err(|_| FrameError::NotJson)?;
    if body.is_empty() {
        return Err(FrameError::Empty);
    }
    if body.len() > max {
        return Err(FrameError::TooLarge(body.len()));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Validated body length from a header.
pub fn body_len(header: [u8; 4]) -> Result<usize, FrameError> {
    body_len_max(header, MAX_FRAME)
}

/// [`body_len`] with another size limit.
pub fn body_len_max(header: [u8; 4], max: usize) -> Result<usize, FrameError> {
    let n = u32::from_be_bytes(header) as usize;
    match n {
        0 => Err(FrameError::Empty),
        n if n > max => Err(FrameError::TooLarge(n)),
        n => Ok(n),
    }
}

pub fn decode(body: &[u8]) -> Result<Map<String, Value>, FrameError> {
    let s = std::str::from_utf8(body).map_err(|_| FrameError::NotUtf8)?;
    match serde_json::from_str::<Value>(s).map_err(|_| FrameError::NotJson)? {
        Value::Object(m) => Ok(m),
        _ => Err(FrameError::NotObject),
    }
}

fn read_exact_closed(r: &mut impl Read, buf: &mut [u8]) -> Result<(), FrameError> {
    r.read_exact(buf).map_err(|e| match e.kind() {
        std::io::ErrorKind::UnexpectedEof => FrameError::Closed,
        _ => FrameError::Io(e),
    })
}

pub fn read_frame(r: &mut impl Read) -> Result<Map<String, Value>, FrameError> {
    read_frame_max(r, MAX_FRAME)
}

/// [`read_frame`] with another size limit (a client reading the daemon's
/// answers: [`MAX_ANSWER_FRAME`]).
pub fn read_frame_max(r: &mut impl Read, max: usize) -> Result<Map<String, Value>, FrameError> {
    let mut h = [0u8; 4];
    read_exact_closed(r, &mut h)?;
    let n = body_len_max(h, max)?;
    let mut body = vec![0u8; n];
    read_exact_closed(r, &mut body)?;
    decode(&body)
}

pub fn write_frame(w: &mut impl Write, v: &Value) -> Result<(), FrameError> {
    let b = encode(v)?;
    w.write_all(&b)?;
    w.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn round_trip() {
        let v = json!({"id":1,"op":"hello","args":[1,2]});
        let bytes = encode(&v).unwrap();
        let m = read_frame(&mut &bytes[..]).unwrap();
        assert_eq!(serde_json::Value::Object(m), v);
        let mut out = Vec::new();
        write_frame(&mut out, &v).unwrap();
        assert_eq!(out, bytes);
    }

    #[test]
    fn header_is_big_endian_length() {
        let b = encode(&json!({"a":1})).unwrap();
        assert_eq!(&b[..4], &[0, 0, 0, 7]);
        assert_eq!(&b[4..], br#"{"a":1}"#);
    }

    #[test]
    fn exactly_1_mib_accepted_one_more_refused() {
        assert_eq!(body_len(1_048_576u32.to_be_bytes()).unwrap(), 1_048_576);
        assert!(matches!(
            body_len(1_048_577u32.to_be_bytes()),
            Err(FrameError::TooLarge(1_048_577))
        ));
    }

    #[test]
    fn encode_refuses_oversize() {
        let v = json!({"a": "x".repeat(MAX_FRAME)});
        assert!(matches!(encode(&v), Err(FrameError::TooLarge(_))));
    }

    #[test]
    fn zero_length_is_empty() {
        assert!(matches!(body_len([0; 4]), Err(FrameError::Empty)));
    }

    #[test]
    fn non_utf8_refused() {
        assert!(matches!(decode(&[0xff, 0xfe]), Err(FrameError::NotUtf8)));
    }

    #[test]
    fn bad_json_and_array_refused() {
        assert!(matches!(decode(b"{nope"), Err(FrameError::NotJson)));
        assert!(matches!(decode(b"[1]"), Err(FrameError::NotObject)));
    }

    #[test]
    fn eof_inside_body_is_closed() {
        let mut b = encode(&json!({"a":1})).unwrap();
        b.truncate(6);
        assert!(matches!(read_frame(&mut &b[..]), Err(FrameError::Closed)));
        assert!(matches!(read_frame(&mut &b[..2]), Err(FrameError::Closed)));
        assert!(matches!(read_frame(&mut &b[..0]), Err(FrameError::Closed)));
    }
}
