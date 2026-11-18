//! Plan 46: the `saiife-ner/1` wire protocol (newline-delimited JSON).
//! The helper never echoes request text; error texts are fixed.

use crate::ner::{NameSpan, SpanLabel};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub const PROTO: u32 = 1;
pub const MAX_LINE: usize = 65_536;
pub const MAX_TEXT: usize = 8_192;
pub const MAX_ERROR: usize = 256;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
pub enum Request {
    Detect { id: u64, text: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "lowercase", deny_unknown_fields)]
pub enum Answer {
    Hello {
        proto: u32,
        version: String,
        labels: Vec<String>,
    },
    Spans {
        id: u64,
        spans: Vec<WireSpan>,
    },
    Error {
        id: u64,
        error: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireSpan {
    pub start: usize,
    pub end: usize,
    pub label: String,
    pub score: f32,
}

impl WireSpan {
    /// Checks bounds and char boundaries; maps PER/ORG/LOC/MISC.
    pub fn to_span(&self, text: &str) -> Option<NameSpan> {
        let label = match self.label.as_str() {
            "PER" => SpanLabel::Person,
            "ORG" => SpanLabel::Org,
            "LOC" => SpanLabel::Location,
            "MISC" => SpanLabel::Misc,
            _ => return None,
        };
        if self.start >= self.end
            || self.end > text.len()
            || !text.is_char_boundary(self.start)
            || !text.is_char_boundary(self.end)
        {
            return None;
        }
        Some(NameSpan {
            start: self.start,
            end: self.end,
            label,
        })
    }
}

/// One JSON line plus `\n`.
pub fn encode<T: Serialize>(v: &T) -> Vec<u8> {
    let mut out = serde_json::to_vec(v).unwrap_or_default();
    out.push(b'\n');
    out
}

/// Parses one line (a trailing `\n` or `\r\n` is allowed); refuses more
/// than `MAX_LINE` bytes. Errors are fixed texts.
pub fn decode<T: DeserializeOwned>(line: &[u8]) -> Result<T, String> {
    if line.len() > MAX_LINE {
        return Err("line too long".to_string());
    }
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    serde_json::from_slice(line).map_err(|_| "malformed line".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proto_round_trip() {
        let r = Request::Detect {
            id: 7,
            text: "Hvad skylder Søren?".into(),
        };
        let b = encode(&r);
        assert_eq!(b.last(), Some(&b'\n'));
        assert_eq!(decode::<Request>(&b).unwrap(), r);
        let answers = [
            Answer::Hello {
                proto: PROTO,
                version: "0.2.0".into(),
                labels: vec!["PER".into(), "ORG".into(), "LOC".into(), "MISC".into()],
            },
            Answer::Spans {
                id: 7,
                spans: vec![WireSpan {
                    start: 12,
                    end: 18,
                    label: "PER".into(),
                    score: 0.5,
                }],
            },
            Answer::Error {
                id: 7,
                error: "bad".into(),
            },
        ];
        for a in answers {
            assert_eq!(decode::<Answer>(&encode(&a)).unwrap(), a);
        }
        assert!(String::from_utf8(encode(&r))
            .unwrap()
            .starts_with(r#"{"op":"detect""#));
        // unknown field refused
        assert!(decode::<Request>(br#"{"op":"detect","id":1,"text":"a","x":1}"#).is_err());
        assert!(decode::<Answer>(br#"{"t":"error","id":1,"error":"a","x":1}"#).is_err());
        assert!(decode::<Answer>(
            br#"{"t":"spans","id":1,"spans":[{"start":0,"end":1,"label":"PER","score":1.0,"x":1}]}"#
        )
        .is_err());
        // too long refused
        let mut long = br#"{"op":"detect","id":1,"text":""}"#.to_vec();
        long.resize(MAX_LINE + 1, b' ');
        assert_eq!(decode::<Request>(&long).unwrap_err(), "line too long");
        long.truncate(MAX_LINE);
        assert!(decode::<Request>(&long).is_ok());
    }

    #[test]
    fn to_span_checks() {
        let text = "Søren er her";
        let w = |s, e, l: &str| WireSpan {
            start: s,
            end: e,
            label: l.into(),
            score: 1.0,
        };
        assert_eq!(
            w(0, 6, "PER").to_span(text).unwrap().label,
            SpanLabel::Person
        );
        assert_eq!(w(0, 6, "ORG").to_span(text).unwrap().label, SpanLabel::Org);
        assert_eq!(
            w(0, 6, "LOC").to_span(text).unwrap().label,
            SpanLabel::Location
        );
        assert_eq!(
            w(0, 6, "MISC").to_span(text).unwrap().label,
            SpanLabel::Misc
        );
        assert!(w(0, 6, "per").to_span(text).is_none());
        assert!(w(0, 2, "PER").to_span(text).is_none()); // inside ø
        assert!(w(6, 6, "PER").to_span(text).is_none());
        assert!(w(7, 3, "PER").to_span(text).is_none());
        assert!(w(0, 99, "PER").to_span(text).is_none());
        assert!(w(usize::MAX, usize::MAX, "PER").to_span(text).is_none());
    }
}
