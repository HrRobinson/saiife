//! The stdio framing: one UTF-8 JSON-RPC message per line (plan 17,
//! decision 2), read from peers saiife does not trust.
//!
//! Bounds, each tested in `tests/codec.rs`:
//! - a line is at most `max` bytes (the caller's cap; `\n` and a trailing
//!   `\r` not counted). [`LineReader`] discards an over-cap line as it
//!   reads, so it never buffers more than `max` + one read;
//! - JSON values nest at most [`MAX_DEPTH`] arrays/objects deep, checked
//!   before serde_json recurses further, so no input overflows the stack;
//! - a duplicate object key anywhere is a parse error (two parsers that
//!   keep the first and the last value would see different messages);
//! - a batch (a JSON array) is `-32600`;
//! - no input panics.

use std::io::{self, BufRead};

use serde::de::{DeserializeSeed, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use crate::jsonrpc::{Id, Message, RpcError};

/// The deepest nesting of arrays and objects a message may have. The
/// envelope is depth 1, `params`/`result` depth 2. Kept well below
/// serde_json's own recursion limit (128).
pub const MAX_DEPTH: usize = 48;

/// A message that could not be read, with the id to answer it under
/// (`None` means `null`: the id was missing or unreadable).
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("{error}")]
pub struct DecodeError {
    pub id: Option<Id>,
    pub error: RpcError,
}

impl DecodeError {
    fn parse() -> DecodeError {
        DecodeError {
            id: None,
            error: RpcError::parse_error(),
        }
    }

    fn too_long(max: usize) -> DecodeError {
        DecodeError {
            id: None,
            error: RpcError::invalid_request(format!("message over {max} bytes")),
        }
    }

    /// The error response to send back.
    pub fn into_message(self) -> Message {
        Message::Error {
            id: self.id,
            error: self.error,
        }
    }
}

/// Decodes one line (without its `\n`). One trailing `\r` is stripped,
/// and only one: a line still ending in `\r` after that is refused.
pub fn decode_line(line: &[u8], max: usize) -> Result<Message, DecodeError> {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.len() > max {
        return Err(DecodeError::too_long(max));
    }
    if line.ends_with(b"\r") {
        return Err(DecodeError::parse());
    }
    let v = parse_strict(line).ok_or_else(DecodeError::parse)?;
    Message::from_value(v)
}

/// Encodes a message as one line ending in `\n`. JSON string escaping
/// turns every newline and carriage return in the content into `\n`/`\r`,
/// so the result never holds a raw line break before the last byte.
pub fn encode(m: &Message) -> String {
    let mut s = m.to_value().to_string();
    s.push('\n');
    s
}

/// Parses `b` as one JSON value, enforcing [`MAX_DEPTH`] and refusing
/// duplicate keys. `None` on any failure.
pub fn parse_strict(b: &[u8]) -> Option<Value> {
    let mut de = serde_json::Deserializer::from_slice(b);
    let v = Strict { depth: 0 }.deserialize(&mut de).ok()?;
    de.end().ok()?;
    Some(v)
}

/// A seed that knows how deep it is.
#[derive(Clone, Copy)]
struct Strict {
    depth: usize,
}

impl Strict {
    fn enter<E: serde::de::Error>(self) -> Result<Strict, E> {
        let depth = self.depth + 1;
        if depth > MAX_DEPTH {
            return Err(E::custom("nested too deep"));
        }
        Ok(Strict { depth })
    }
}

impl<'de> DeserializeSeed<'de> for Strict {
    type Value = Value;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Strict {
    type Value = Value;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JSON")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("not a finite number"))
    }
    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_string()))
    }
    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
        let inner = self.enter()?;
        let mut out = Vec::new();
        while let Some(v) = a.next_element_seed(inner)? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
        let inner = self.enter()?;
        let mut out = Map::new();
        while let Some(k) = a.next_key::<String>()? {
            let v = a.next_value_seed(inner)?;
            if out.insert(k, v).is_some() {
                return Err(A::Error::custom("duplicate key"));
            }
        }
        Ok(Value::Object(out))
    }
}

/// Reads messages one line at a time from `R`, holding at most `max`
/// bytes of a line. Empty lines are skipped.
pub struct LineReader<R: BufRead> {
    inner: R,
    max: usize,
    buf: Vec<u8>,
    /// The rest of an over-cap line, already reported, is still unread.
    draining: bool,
    /// The exact text of `params.arguments` of the last `tools/call`.
    raw_arguments: Option<Box<str>>,
}

/// The exact text of `params.arguments` in a line that already passed
/// [`parse_strict`] (so keys are unique and depth is bounded). `None` when
/// absent or `null`.
pub fn raw_call_arguments(line: &[u8]) -> Option<Box<str>> {
    #[derive(serde::Deserialize)]
    struct P<'a> {
        #[serde(borrow)]
        arguments: Option<&'a serde_json::value::RawValue>,
    }
    #[derive(serde::Deserialize)]
    struct M<'a> {
        #[serde(borrow)]
        params: Option<P<'a>>,
    }
    let m: M = serde_json::from_slice(line).ok()?;
    Some(m.params?.arguments?.get().into())
}

impl<R: BufRead> LineReader<R> {
    pub fn new(inner: R, max: usize) -> LineReader<R> {
        LineReader {
            inner,
            max,
            buf: Vec::new(),
            draining: false,
            raw_arguments: None,
        }
    }

    /// The exact text of `params.arguments` of the `tools/call` request
    /// `next_message` returned last (once; `None` for any other message).
    /// Numbers and escapes in it are as the client wrote them.
    pub fn take_raw_arguments(&mut self) -> Option<Box<str>> {
        self.raw_arguments.take()
    }

    /// The next message: `Ok(None)` at end of input, `Ok(Some(Err(_)))`
    /// for a line that is not a message, `Err` for an I/O error. An
    /// over-cap line is reported (`-32600`) as soon as it crosses the cap;
    /// the rest of it is skipped by the next call, before anything else.
    pub fn next_message(&mut self) -> io::Result<Option<Result<Message, DecodeError>>> {
        loop {
            match self.next_line()? {
                None => return Ok(None),
                Some(Err(e)) => return Ok(Some(Err(e))),
                Some(Ok(())) => {
                    // Blank lines are skipped; `decode_line` strips the
                    // one `\r` of a CRLF line itself.
                    if self.buf.is_empty() || self.buf == b"\r" {
                        continue;
                    }
                    self.raw_arguments = None;
                    let m = decode_line(&self.buf, self.max);
                    if matches!(&m, Ok(Message::Request { method, .. }) if method == crate::types::TOOLS_CALL)
                    {
                        self.raw_arguments = raw_call_arguments(&self.buf);
                    }
                    return Ok(Some(m));
                }
            }
        }
    }

    /// Skips the rest of an over-cap line. `false` at end of input.
    fn drain(&mut self) -> io::Result<bool> {
        while self.draining {
            let chunk = match self.inner.fill_buf() {
                Ok(c) => c,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if chunk.is_empty() {
                self.draining = false;
                return Ok(false);
            }
            match chunk.iter().position(|&b| b == b'\n') {
                Some(i) => {
                    self.inner.consume(i + 1);
                    self.draining = false;
                }
                None => {
                    let n = chunk.len();
                    self.inner.consume(n);
                }
            }
        }
        Ok(true)
    }

    /// Reads one line into `self.buf` (without the `\n`), or reports an
    /// over-cap line the moment it crosses the cap.
    fn next_line(&mut self) -> io::Result<Option<Result<(), DecodeError>>> {
        self.buf.clear();
        if !self.drain()? {
            return Ok(None);
        }
        // One spare byte for a trailing `\r`.
        let cap = self.max.saturating_add(1);
        let mut read_any = false;
        loop {
            let chunk = match self.inner.fill_buf() {
                Ok(c) => c,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if chunk.is_empty() {
                // End of input: a final line without `\n` still counts.
                if !read_any {
                    return Ok(None);
                }
                return Ok(Some(Ok(())));
            }
            read_any = true;
            let (take, done) = match chunk.iter().position(|&b| b == b'\n') {
                Some(i) => (i, true),
                None => (chunk.len(), false),
            };
            if take > cap - self.buf.len() {
                self.buf.clear();
                self.inner.consume(if done { take + 1 } else { take });
                self.draining = !done;
                return Ok(Some(Err(DecodeError::too_long(self.max))));
            }
            self.buf.extend_from_slice(&chunk[..take]);
            self.inner.consume(if done { take + 1 } else { take });
            if done {
                return Ok(Some(Ok(())));
            }
        }
    }

    /// The underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }
}
