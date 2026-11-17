//! The action record and its challenge (plan 26, task 2).

use std::collections::BTreeMap;
use std::fmt::Write as _;

use ring::digest;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The domain tag of the challenge preimage (15 bytes).
const DOMAIN: &[u8] = b"saiife-touch-v1";

/// What a touch is for. Serialised as its `name()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TouchClass {
    Land,
    PushProtected,
    Deploy,
    SecretSensitive,
    EgressExternal,
    Enrol,
    Remove,
    Test,
    /// A Workspace steer window (plan 31).
    Steer,
    /// Data Shield (plan 43): release an answer that passed the gates.
    BlindRelease,
    /// Data Shield: reveal a masked value.
    BlindReveal,
    /// Data Shield: create or rotate a dataset key.
    BlindKeys,
    /// Data Shield: loosen a dataset's limits.
    BlindLoosen,
    /// Data Shield: approve a pending release.
    BlindApprove,
    /// Data Shield: name an entity.
    BlindName,
}

impl TouchClass {
    pub fn name(self) -> &'static str {
        match self {
            Self::Land => "land",
            Self::PushProtected => "push_protected",
            Self::Deploy => "deploy",
            Self::SecretSensitive => "secret:sensitive",
            Self::EgressExternal => "egress:external",
            Self::Enrol => "touch_enrol",
            Self::Remove => "touch_remove",
            Self::Test => "touch_test",
            Self::Steer => "steer",
            Self::BlindRelease => "blind:release",
            Self::BlindReveal => "blind:reveal",
            Self::BlindKeys => "blind:keys",
            Self::BlindLoosen => "blind:loosen",
            Self::BlindApprove => "blind:approve",
            Self::BlindName => "blind:name",
        }
    }

    pub fn from_name(s: &str) -> Option<TouchClass> {
        Some(match s {
            "land" => Self::Land,
            "push_protected" => Self::PushProtected,
            "deploy" => Self::Deploy,
            "secret:sensitive" => Self::SecretSensitive,
            "egress:external" => Self::EgressExternal,
            "touch_enrol" => Self::Enrol,
            "touch_remove" => Self::Remove,
            "touch_test" => Self::Test,
            "steer" => Self::Steer,
            "blind:release" => Self::BlindRelease,
            "blind:reveal" => Self::BlindReveal,
            "blind:keys" => Self::BlindKeys,
            "blind:loosen" => Self::BlindLoosen,
            "blind:approve" => Self::BlindApprove,
            "blind:name" => Self::BlindName,
            _ => return None,
        })
    }

    /// Whether the class demands user verification (D4).
    pub fn needs_uv(self) -> bool {
        !matches!(self, Self::PushProtected | Self::EgressExternal)
    }

    /// The class that can only get stronger (D8): the one needing UV if
    /// exactly one does, else `a`, else `b`.
    pub fn stronger(a: Option<TouchClass>, b: Option<TouchClass>) -> Option<TouchClass> {
        match (a, b) {
            (Some(x), Some(y)) => Some(if !x.needs_uv() && y.needs_uv() { y } else { x }),
            (x, None) => x,
            (None, y) => y,
        }
    }
}

impl Serialize for TouchClass {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.name())
    }
}

impl<'de> Deserialize<'de> for TouchClass {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        TouchClass::from_name(&s)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown touch class {s:?}")))
    }
}

/// The action a touch approves.
///
/// `fields` carry the policy-relevant detail. Box plans use `repo`,
/// `base_commit`, `target_ref`, `diff_sha256` and `remote` (reserved names).
/// `expires_at` is in Unix seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionRecord {
    pub instance_id: [u8; 16],
    pub request_id: u64,
    pub class: TouchClass,
    pub summary: String,
    pub fields: BTreeMap<String, String>,
    pub nonce: [u8; 32],
    pub expires_at: u64,
}

#[derive(Serialize)]
struct Canon<'a> {
    class: &'a str,
    fields: &'a BTreeMap<String, String>,
    summary: &'a str,
}

impl ActionRecord {
    /// Compact JSON, keys sorted (D2).
    pub fn canonical_action(&self) -> String {
        let c = Canon {
            class: self.class.name(),
            fields: &self.fields,
            summary: &self.summary,
        };
        serde_json::to_string(&c).expect("a string-keyed map of strings always serialises")
    }

    pub fn action_digest(&self) -> [u8; 32] {
        sha256(self.canonical_action().as_bytes())
    }

    /// `tag || instance_id || request_id || nonce || expires_at || action_digest`
    /// (111 bytes; every field has a fixed length).
    pub fn preimage(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(111);
        v.extend_from_slice(DOMAIN);
        v.extend_from_slice(&self.instance_id);
        v.extend_from_slice(&self.request_id.to_be_bytes());
        v.extend_from_slice(&self.nonce);
        v.extend_from_slice(&self.expires_at.to_be_bytes());
        v.extend_from_slice(&self.action_digest());
        v
    }
}

/// The action-bound challenge: SHA-256 of the preimage.
pub fn challenge(a: &ActionRecord) -> [u8; 32] {
    sha256(&a.preimage())
}

/// The six-digit code shown on both screens (D9).
pub fn short_code(c: &[u8; 32]) -> String {
    format!(
        "{:06}",
        u32::from_be_bytes([0, c[0], c[1], c[2]]) % 1_000_000
    )
}

pub(crate) fn sha256(b: &[u8]) -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, b);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

pub(crate) fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> ActionRecord {
        let mut fields = BTreeMap::new();
        fields.insert("service".to_string(), "erp".to_string());
        fields.insert("body_sha256".to_string(), "0".repeat(64));
        fields.insert("operation".to_string(), "payments.create".to_string());
        ActionRecord {
            instance_id: [0x11; 16],
            request_id: 42,
            class: TouchClass::Deploy,
            summary: "#42 erp payments.create".to_string(),
            fields,
            nonce: [0x22; 32],
            expires_at: 1_800_000_000,
        }
    }

    const ALL: [TouchClass; 14] = [
        TouchClass::Land,
        TouchClass::PushProtected,
        TouchClass::Deploy,
        TouchClass::SecretSensitive,
        TouchClass::EgressExternal,
        TouchClass::Enrol,
        TouchClass::Remove,
        TouchClass::Test,
        TouchClass::BlindRelease,
        TouchClass::BlindReveal,
        TouchClass::BlindKeys,
        TouchClass::BlindLoosen,
        TouchClass::BlindApprove,
        TouchClass::BlindName,
    ];

    #[test]
    fn canonical_action_is_pinned() {
        let want = format!(
            "{{\"class\":\"deploy\",\"fields\":{{\"body_sha256\":\"{}\",\"operation\":\"payments.create\",\"service\":\"erp\"}},\"summary\":\"#42 erp payments.create\"}}",
            "0".repeat(64)
        );
        assert_eq!(fixture().canonical_action(), want);
    }

    #[test]
    fn challenge_vector() {
        let a = fixture();
        assert_eq!(
            hex(&a.action_digest()),
            "88ecaf20f077c770f26a6f953e63558f39df0306fb088ead47646deda999d1b7"
        );
        assert_eq!(a.preimage().len(), 111);
        let c = challenge(&a);
        assert_eq!(
            hex(&c),
            "9759e53f34fc0f4308fe8e0d10a32b4bd0e0d85365c969948afca55866496db6"
        );
        assert_eq!(short_code(&c), "918949");
    }

    #[test]
    fn every_field_changes_the_challenge() {
        let base = challenge(&fixture());
        let mut muts: Vec<ActionRecord> = Vec::new();
        let mut a = fixture();
        a.instance_id[0] ^= 1;
        muts.push(a);
        let mut a = fixture();
        a.request_id += 1;
        muts.push(a);
        let mut a = fixture();
        a.class = TouchClass::Land;
        muts.push(a);
        let mut a = fixture();
        a.summary.push('x');
        muts.push(a);
        let mut a = fixture();
        a.fields.insert("service".into(), "erp2".into());
        muts.push(a);
        let mut a = fixture();
        let v = a.fields.remove("service").unwrap();
        a.fields.insert("service2".into(), v);
        muts.push(a);
        let mut a = fixture();
        a.nonce[31] ^= 1;
        muts.push(a);
        let mut a = fixture();
        a.expires_at += 1;
        muts.push(a);
        for m in muts {
            assert_ne!(challenge(&m), base);
        }
    }

    #[test]
    fn class_names_round_trip() {
        for c in ALL {
            assert_eq!(TouchClass::from_name(c.name()), Some(c));
            let j = serde_json::to_string(&c).unwrap();
            assert_eq!(j, format!("\"{}\"", c.name()));
            assert_eq!(serde_json::from_str::<TouchClass>(&j).unwrap(), c);
        }
        assert_eq!(TouchClass::from_name("Deploy"), None);
        assert!(serde_json::from_str::<TouchClass>("\"bogus\"").is_err());
    }

    #[test]
    fn needs_uv_table() {
        let want = [
            true, false, true, true, false, true, true, true, true, true, true, true, true, true,
        ];
        for (c, w) in ALL.iter().zip(want) {
            assert_eq!(c.needs_uv(), w, "{}", c.name());
        }
    }

    #[test]
    fn blind_classes_need_uv() {
        for c in &ALL[8..] {
            assert!(c.name().starts_with("blind:"));
            assert!(c.needs_uv(), "{}", c.name());
        }
    }

    #[test]
    fn steer_class_roundtrip() {
        let c = TouchClass::Steer;
        assert_eq!(c.name(), "steer");
        assert_eq!(TouchClass::from_name("steer"), Some(c));
        assert_eq!(serde_json::to_string(&c).unwrap(), "\"steer\"");
        assert_eq!(serde_json::from_str::<TouchClass>("\"steer\"").unwrap(), c);
        assert!(c.needs_uv());
    }

    #[test]
    fn stronger_with_steer() {
        use TouchClass::*;
        assert_eq!(
            TouchClass::stronger(Some(EgressExternal), Some(Steer)),
            Some(Steer)
        );
        assert_eq!(
            TouchClass::stronger(Some(Steer), Some(PushProtected)),
            Some(Steer)
        );
        assert_eq!(TouchClass::stronger(None, Some(Steer)), Some(Steer));
    }

    #[test]
    fn stronger_prefers_uv() {
        use TouchClass::*;
        assert_eq!(
            TouchClass::stronger(Some(EgressExternal), Some(Deploy)),
            Some(Deploy)
        );
        assert_eq!(TouchClass::stronger(Some(Deploy), None), Some(Deploy));
        assert_eq!(
            TouchClass::stronger(None, Some(EgressExternal)),
            Some(EgressExternal)
        );
        assert_eq!(TouchClass::stronger(Some(Land), Some(Deploy)), Some(Land));
        assert_eq!(TouchClass::stronger(None, None), None);
    }

    #[test]
    fn non_ascii_summary_is_stable() {
        let mut a = fixture();
        a.summary = "#1 café".to_string();
        assert_eq!(a.action_digest(), a.clone().action_digest());
        assert!(a.canonical_action().contains("café"));
        assert!(!a.canonical_action().contains("\\u"));
    }
}
