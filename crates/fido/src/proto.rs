//! The line protocol between saiife and saiife-fido-helper: one JSON object
//! per line, `\n`-terminated. Byte strings are base64url without padding,
//! the challenge is 64 hex digits.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const PROTO: u32 = 1;
/// The longest line either side reads, newline included.
pub const MAX_LINE: usize = 65_536;
/// The longest error text an answer carries, in chars.
pub const MAX_ERROR_CHARS: usize = 512;

/// `(credential_id, auth_data, signature)` of an assertion.
pub type AssertParts = (Vec<u8>, Vec<u8>, Vec<u8>);

/// The helper's first line: `{"t":"hello",...}` inside `Answer`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub proto: u32,
    pub version: String,
    pub devices: usize,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Request {
    Assert(AssertReq),
    Enrol(EnrolReq),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssertReq {
    pub rp_id: String,
    #[serde(with = "hex32")]
    pub challenge: [u8; 32],
    #[serde(with = "b64_list")]
    pub allow: Vec<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<Zeroizing<String>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolReq {
    pub rp_id: String,
    #[serde(with = "hex32")]
    pub challenge: [u8; 32],
    #[serde(with = "b64")]
    pub user_id: Vec<u8>,
    pub user_name: String,
    #[serde(with = "b64_list")]
    pub exclude: Vec<Vec<u8>>,
    pub pin: Zeroizing<String>,
}

// The PIN never shows in a Debug line, and compares as its text.
impl std::fmt::Debug for AssertReq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssertReq")
            .field("rp_id", &self.rp_id)
            .field("allow", &self.allow.len())
            .field("pin", &self.pin.as_ref().map(|_| "<set>"))
            .finish()
    }
}
impl std::fmt::Debug for EnrolReq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrolReq")
            .field("rp_id", &self.rp_id)
            .field("user_name", &self.user_name)
            .field("pin", &"<set>")
            .finish()
    }
}
impl PartialEq for AssertReq {
    fn eq(&self, o: &Self) -> bool {
        self.rp_id == o.rp_id
            && self.challenge == o.challenge
            && self.allow == o.allow
            && self.pin.as_deref() == o.pin.as_deref()
    }
}
impl PartialEq for EnrolReq {
    fn eq(&self, o: &Self) -> bool {
        self.rp_id == o.rp_id
            && self.challenge == o.challenge
            && self.user_id == o.user_id
            && self.user_name == o.user_name
            && self.exclude == o.exclude
            && *self.pin == *o.pin
    }
}
impl PartialEq for Request {
    fn eq(&self, o: &Self) -> bool {
        match (self, o) {
            (Self::Assert(a), Self::Assert(b)) => a == b,
            (Self::Enrol(a), Self::Enrol(b)) => a == b,
            _ => false,
        }
    }
}
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Assert(a) => a.fmt(f),
            Self::Enrol(e) => e.fmt(f),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "lowercase", deny_unknown_fields)]
pub enum Answer {
    Hello(Hello),
    Assertion {
        #[serde(with = "b64")]
        credential_id: Vec<u8>,
        #[serde(with = "b64")]
        auth_data: Vec<u8>,
        #[serde(with = "b64")]
        signature: Vec<u8>,
    },
    Attestation {
        #[serde(with = "b64")]
        auth_data: Vec<u8>,
    },
    Error {
        error: String,
    },
}

impl Answer {
    /// An error answer; the text is cut to `MAX_ERROR_CHARS` chars.
    pub fn error(msg: &str) -> Self {
        Self::Error {
            error: msg.chars().take(MAX_ERROR_CHARS).collect(),
        }
    }
}

/// One line, `\n`-terminated. Wiped on drop: a request carries the PIN.
pub fn encode<T: Serialize>(v: &T) -> Zeroizing<Vec<u8>> {
    // Plain structs of strings and numbers: serialising cannot fail.
    let mut out = Zeroizing::new(serde_json::to_vec(v).unwrap_or_default());
    out.push(b'\n');
    out
}

/// Parses one line (a trailing newline is fine); refuses more than
/// `MAX_LINE` bytes and unknown fields.
pub fn decode<T: DeserializeOwned>(line: &[u8]) -> Result<T, String> {
    if line.len() > MAX_LINE {
        return Err(format!("line longer than {MAX_LINE} bytes"));
    }
    serde_json::from_slice(line).map_err(|e| e.to_string())
}

mod b64_codec {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    pub(super) fn enc(b: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(b)
    }
    pub(super) fn dec(s: &str) -> Option<Vec<u8>> {
        URL_SAFE_NO_PAD.decode(s).ok()
    }
}

/// `Vec<u8>` as base64url.
mod b64 {
    use super::b64_codec::{dec, enc};
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&enc(v))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        dec(&s).ok_or_else(|| D::Error::custom("expected base64url without padding"))
    }
}

/// `Vec<Vec<u8>>` as a list of base64url strings.
mod b64_list {
    use super::b64_codec::{dec, enc};
    use serde::de::Error as _;
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for b in v {
            seq.serialize_element(&enc(b))?;
        }
        seq.end()
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|s| dec(s).ok_or_else(|| D::Error::custom("expected base64url without padding")))
            .collect()
    }
}

/// `[u8; 32]` as 64 lowercase hex digits.
mod hex32 {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        let mut out = String::with_capacity(64);
        for b in v {
            out.push_str(&format!("{b:02x}"));
        }
        s.serialize_str(&out)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let bad = || D::Error::custom("expected 64 hex digits");
        if s.len() != 64 {
            return Err(bad());
        }
        let nib = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
        let mut out = [0u8; 32];
        for (o, p) in out.iter_mut().zip(s.as_bytes().chunks(2)) {
            *o = nib(p[0]).ok_or_else(bad)? << 4 | nib(p[1]).ok_or_else(bad)?;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_string())
    }

    fn requests() -> Vec<Request> {
        vec![
            Request::Assert(AssertReq {
                rp_id: "saiife.local".into(),
                challenge: [0xab; 32],
                allow: vec![vec![1, 2, 3], vec![0xfb, 0xff]],
                pin: Some(pin("1234")),
            }),
            Request::Assert(AssertReq {
                rp_id: "saiife.local".into(),
                challenge: [0; 32],
                allow: vec![],
                pin: None,
            }),
            Request::Enrol(EnrolReq {
                rp_id: "saiife.local".into(),
                challenge: [7; 32],
                user_id: vec![9, 9],
                user_name: "jonas".into(),
                exclude: vec![vec![5]],
                pin: pin("9876"),
            }),
        ]
    }

    fn answers() -> Vec<Answer> {
        vec![
            Answer::Hello(Hello {
                proto: PROTO,
                version: "0.2.0".into(),
                devices: 1,
            }),
            Answer::Assertion {
                credential_id: vec![1, 2],
                auth_data: vec![0xfb, 0xff],
                signature: vec![3],
            },
            Answer::Attestation {
                auth_data: vec![4, 5],
            },
            Answer::error("0x31 CTAP2_ERR_PIN_INVALID"),
        ]
    }

    fn one_line(b: &[u8]) {
        assert_eq!(b.last(), Some(&b'\n'));
        assert!(!b[..b.len() - 1].contains(&b'\n'));
    }

    #[test]
    fn proto_round_trip() {
        for r in requests() {
            let line = encode(&r);
            one_line(&line);
            assert_eq!(decode::<Request>(&line), Ok(r));
        }
        for a in answers() {
            let line = encode(&a);
            one_line(&line);
            assert_eq!(decode::<Answer>(&line), Ok(a));
        }
        let text = String::from_utf8(encode(&requests()[0]).to_vec()).unwrap();
        assert!(
            text.contains(&format!("\"challenge\":\"{}\"", "ab".repeat(32))),
            "{text}"
        );
        assert!(text.contains("\"allow\":[\"AQID\",\"-_8\"]"), "{text}");
        assert!(text.contains("\"op\":\"assert\""), "{text}");
        let hello = String::from_utf8(encode(&answers()[0]).to_vec()).unwrap();
        assert!(hello.contains("\"t\":\"hello\""), "{hello}");
    }

    #[test]
    fn proto_refuses_unknown_fields() {
        let r = br#"{"op":"assert","rp_id":"x","challenge":"0000000000000000000000000000000000000000000000000000000000000000","allow":[],"extra":1}"#;
        assert!(decode::<Request>(r).is_err());
        let a = br#"{"t":"attestation","auth_data":"AQ","extra":1}"#;
        assert!(decode::<Answer>(a).is_err());
        let h = br#"{"t":"hello","proto":1,"version":"x","devices":0,"extra":1}"#;
        assert!(decode::<Answer>(h).is_err());
        // The known form still parses.
        assert!(decode::<Answer>(br#"{"t":"attestation","auth_data":"AQ"}"#).is_ok());
        // Bad hex and bad base64url are refused.
        let short = br#"{"op":"assert","rp_id":"x","challenge":"00","allow":[]}"#;
        assert!(decode::<Request>(short).is_err());
        let pad = br#"{"t":"attestation","auth_data":"AQ=="}"#;
        assert!(decode::<Answer>(pad).is_err());
    }

    #[test]
    fn proto_refuses_long_lines() {
        let long = vec![b' '; MAX_LINE + 1];
        assert!(decode::<Answer>(&long).is_err());
        let ok = format!(
            "{}{}",
            r#"{"t":"error","error":"x"}"#,
            " ".repeat(MAX_LINE - 25)
        );
        assert_eq!(ok.len(), MAX_LINE);
        assert!(decode::<Answer>(ok.as_bytes()).is_ok());
    }

    #[test]
    fn error_text_is_cut() {
        let long = "é".repeat(MAX_ERROR_CHARS + 10);
        match Answer::error(&long) {
            Answer::Error { error } => {
                assert_eq!(error.chars().count(), MAX_ERROR_CHARS);
                assert!(long.starts_with(&error));
            }
            _ => panic!("not an error"),
        }
        assert_eq!(
            Answer::error("short"),
            Answer::Error {
                error: "short".into()
            }
        );
    }
}
