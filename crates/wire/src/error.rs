//! The one error type of the wire, with the `rule()` string an answer carries.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    Malformed(String),
    BadSignature,
    UnknownDevice,
    DevicePending,
    WrongMachine,
    StaleEpoch,
    Expired,
    NotYetValid,
    Replayed,
    Busy,
    UnknownAction(String),
    MachineOnly(String),
    PairExpired,
    PairProof,
    PairFull,
    Seal(String),
    Store(String),
}

impl WireError {
    /// The string the daemon puts in an answer's `rule`.
    pub fn rule(&self) -> &'static str {
        match self {
            Self::Malformed(_) => "bad_frame",
            Self::BadSignature => "bad_signature",
            Self::UnknownDevice => "unknown_device",
            Self::DevicePending => "device_pending",
            Self::WrongMachine => "wrong_machine",
            Self::StaleEpoch => "stale_epoch",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::Replayed => "replayed",
            Self::Busy => "busy",
            Self::UnknownAction(_) => "unknown_action",
            Self::MachineOnly(_) => "machine_only",
            Self::PairExpired => "pair_expired",
            Self::PairProof => "pair_proof",
            Self::PairFull => "pair_full",
            Self::Seal(_) => "seal",
            Self::Store(_) => "store",
        }
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "malformed frame: {m}"),
            Self::BadSignature => f.write_str("the frame signature does not verify"),
            Self::UnknownDevice => f.write_str("this browser is not paired with this machine"),
            Self::DevicePending => {
                f.write_str("this browser is waiting for confirmation on the machine")
            }
            Self::WrongMachine => f.write_str("the frame is for another machine"),
            Self::StaleEpoch => f.write_str("the daemon restarted; reload the page"),
            Self::Expired => f.write_str("the frame has expired"),
            Self::NotYetValid => {
                f.write_str("the frame is from the future; check this device's clock")
            }
            Self::Replayed => f.write_str("the frame was already used"),
            Self::Busy => f.write_str("too many frames in flight; try again shortly"),
            Self::UnknownAction(a) => write!(f, "unknown action {a:?}"),
            Self::MachineOnly(a) => write!(f, "{a} can only be done on the machine"),
            Self::PairExpired => f.write_str(
                "this pairing code has expired or was used; run saiife workspace pair again",
            ),
            Self::PairProof => f.write_str("the pairing proof does not match"),
            Self::PairFull => f.write_str("too many open pairing codes; wait for one to expire"),
            Self::Seal(m) => write!(f, "sealed channel: {m}"),
            Self::Store(m) => write!(f, "device store: {m}"),
        }
    }
}

impl std::error::Error for WireError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_has_a_rule() {
        let all = [
            WireError::Malformed(String::new()),
            WireError::BadSignature,
            WireError::UnknownDevice,
            WireError::DevicePending,
            WireError::WrongMachine,
            WireError::StaleEpoch,
            WireError::Expired,
            WireError::NotYetValid,
            WireError::Replayed,
            WireError::Busy,
            WireError::UnknownAction(String::new()),
            WireError::MachineOnly(String::new()),
            WireError::PairExpired,
            WireError::PairProof,
            WireError::PairFull,
            WireError::Seal(String::new()),
            WireError::Store(String::new()),
        ];
        let mut seen = std::collections::HashSet::new();
        for e in &all {
            let r = e.rule();
            assert!(!r.is_empty() && r.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
            assert!(seen.insert(r), "duplicate rule {r}");
            assert!(!e.to_string().is_empty());
        }
        assert_eq!(seen.len(), all.len());
    }

    #[test]
    fn display_samples() {
        assert_eq!(
            WireError::UnknownAction("a b".into()).to_string(),
            "unknown action \"a b\""
        );
        assert_eq!(
            WireError::MachineOnly("lockdown.off".into()).to_string(),
            "lockdown.off can only be done on the machine"
        );
    }
}
