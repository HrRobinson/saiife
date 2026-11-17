//! Length-prefixed frames: tag (1 byte), big-endian u32 length, body.

use serde::{de::DeserializeOwned, Serialize};
use std::io::{self, Read, Write};

/// Largest body a frame may carry.
pub const MAX_FRAME: usize = 1 << 20;

const TAG_JSON: u8 = 0x01;
const TAG_BYTES: u8 = 0x02;

/// One frame: a JSON value or raw bytes.
#[derive(Debug, Clone, PartialEq)]
pub enum Frame {
    Json(serde_json::Value),
    Bytes(Vec<u8>),
}

/// Why a frame could not be read.
#[derive(Debug)]
pub enum FrameError {
    Io(io::Error),
    TooLarge(usize),
    BadTag(u8),
    BadJson(String),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Io(e) => write!(f, "frame io: {e}"),
            FrameError::TooLarge(n) => write!(f, "frame of {n} bytes exceeds {MAX_FRAME}"),
            FrameError::BadTag(t) => write!(f, "unknown frame tag {t:#04x}"),
            FrameError::BadJson(e) => write!(f, "bad frame json: {e}"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<io::Error> for FrameError {
    fn from(e: io::Error) -> Self {
        FrameError::Io(e)
    }
}

/// Writes one frame; refuses a body above `MAX_FRAME`.
pub fn write_frame(w: &mut impl Write, f: &Frame) -> io::Result<()> {
    let (tag, body) = match f {
        Frame::Json(v) => (
            TAG_JSON,
            serde_json::to_vec(v).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
        ),
        Frame::Bytes(b) => (TAG_BYTES, b.clone()),
    };
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("frame of {} bytes exceeds {MAX_FRAME}", body.len()),
        ));
    }
    let mut out = Vec::with_capacity(5 + body.len());
    out.push(tag);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    w.write_all(&out)?;
    w.flush()
}

/// Reads one frame. `None` is a clean EOF before the tag byte. The length is
/// checked against `MAX_FRAME` before any body byte is read.
pub fn read_frame(r: &mut impl Read) -> Result<Option<Frame>, FrameError> {
    let mut tag = [0u8; 1];
    loop {
        match r.read(&mut tag) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    let tag = tag[0];
    if tag != TAG_JSON && tag != TAG_BYTES {
        return Err(FrameError::BadTag(tag));
    }
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    let mut body = Vec::new();
    let got = r.take(len as u64).read_to_end(&mut body)?;
    if got < len {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
    }
    if tag == TAG_BYTES {
        return Ok(Some(Frame::Bytes(body)));
    }
    serde_json::from_slice(&body)
        .map(|v| Some(Frame::Json(v)))
        .map_err(|e| FrameError::BadJson(e.to_string()))
}

/// Writes a message as a JSON frame.
pub fn write_msg<T: Serialize>(w: &mut impl Write, m: &T) -> io::Result<()> {
    let v = serde_json::to_value(m).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    write_frame(w, &Frame::Json(v))
}

/// Reads a JSON frame as a message. A bytes frame is `BadJson`.
pub fn read_msg<T: DeserializeOwned>(r: &mut impl Read) -> Result<Option<T>, FrameError> {
    match read_frame(r)? {
        None => Ok(None),
        Some(Frame::Json(v)) => serde_json::from_value(v)
            .map(Some)
            .map_err(|e| FrameError::BadJson(e.to_string())),
        Some(Frame::Bytes(_)) => Err(FrameError::BadJson(
            "expected a json frame, got bytes".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frame_roundtrip_json_and_bytes() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &Frame::Json(serde_json::json!({"a": 1}))).unwrap();
        write_frame(&mut buf, &Frame::Bytes(vec![0, 1, 2])).unwrap();
        assert_eq!(buf[0], 0x01);
        let mut r = Cursor::new(buf);
        assert_eq!(
            read_frame(&mut r).unwrap(),
            Some(Frame::Json(serde_json::json!({"a": 1})))
        );
        assert_eq!(
            read_frame(&mut r).unwrap(),
            Some(Frame::Bytes(vec![0, 1, 2]))
        );
        assert_eq!(read_frame(&mut r).unwrap(), None);
    }

    #[test]
    fn oversized_frame_is_refused() {
        // Header only: the body is never read (the reader would hit EOF if it tried).
        let mut buf = vec![0x02];
        buf.extend_from_slice(&((MAX_FRAME as u32) + 1).to_be_bytes());
        let mut r = Cursor::new(buf);
        match read_frame(&mut r) {
            Err(FrameError::TooLarge(n)) => assert_eq!(n, MAX_FRAME + 1),
            other => panic!("{other:?}"),
        }
        assert_eq!(r.position(), 5);
        let err = write_frame(&mut Vec::new(), &Frame::Bytes(vec![0; MAX_FRAME + 1])).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        write_frame(&mut Vec::new(), &Frame::Bytes(vec![0; MAX_FRAME])).unwrap();
    }

    #[test]
    fn bad_tag_is_refused() {
        let mut r = Cursor::new(vec![0x07, 0, 0, 0, 0]);
        assert!(matches!(read_frame(&mut r), Err(FrameError::BadTag(7))));
    }

    #[test]
    fn clean_eof_is_none() {
        assert_eq!(read_frame(&mut Cursor::new(Vec::new())).unwrap(), None);
    }

    #[test]
    fn truncated_frame_is_io_error() {
        for bytes in [vec![0x01], vec![0x01, 0, 0], vec![0x02, 0, 0, 0, 5, 1, 2]] {
            match read_frame(&mut Cursor::new(bytes)) {
                Err(FrameError::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof),
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn bad_json_and_bytes_as_msg() {
        let mut buf = vec![0x01, 0, 0, 0, 1, b'{'];
        assert!(matches!(
            read_frame(&mut Cursor::new(buf.clone())),
            Err(FrameError::BadJson(_))
        ));
        buf.clear();
        write_frame(&mut buf, &Frame::Bytes(vec![1])).unwrap();
        let r: Result<Option<crate::msg::Reply>, _> = read_msg(&mut Cursor::new(buf));
        assert!(matches!(r, Err(FrameError::BadJson(_))));
        let mut buf = Vec::new();
        write_msg(&mut buf, &crate::msg::Reply::Ok).unwrap();
        let r: Option<crate::msg::Reply> = read_msg(&mut Cursor::new(buf)).unwrap();
        assert_eq!(r, Some(crate::msg::Reply::Ok));
    }
}
