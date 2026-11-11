//! Touch errors and the policy rule each maps to.

use std::fmt;

/// Why a touch was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchError {
    Unavailable,
    Mismatch,
    BadSignature,
    Replayed,
    Expired,
    UnknownCredential,
    Malformed,
    NotPresent,
    NotVerified,
}

impl TouchError {
    /// The audit/deny rule name.
    pub fn rule(&self) -> &'static str {
        match self {
            Self::Unavailable => "touch_unavailable",
            Self::Mismatch | Self::UnknownCredential => "touch_mismatch",
            _ => "touch_failed",
        }
    }
}

impl fmt::Display for TouchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "no enrolled touch device answered",
            Self::Mismatch => "the touch was for a different action, device or origin",
            Self::UnknownCredential => "this device is not enrolled for you",
            Self::BadSignature => "the touch signature does not verify",
            Self::Replayed => "the touch was used before (its signature counter did not advance)",
            Self::Expired => {
                "no live challenge for this touch: it expired, was used, or the daemon restarted"
            }
            Self::Malformed => "the touch data is malformed",
            Self::NotPresent => "the device reported no touch",
            Self::NotVerified => {
                "this needs user verification on the device (its PIN or fingerprint)"
            }
        })
    }
}

impl std::error::Error for TouchError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_and_display() {
        use TouchError::*;
        let rows = [
            (
                Unavailable,
                "touch_unavailable",
                "no enrolled touch device answered",
            ),
            (
                Mismatch,
                "touch_mismatch",
                "the touch was for a different action, device or origin",
            ),
            (
                UnknownCredential,
                "touch_mismatch",
                "this device is not enrolled for you",
            ),
            (
                BadSignature,
                "touch_failed",
                "the touch signature does not verify",
            ),
            (
                Replayed,
                "touch_failed",
                "the touch was used before (its signature counter did not advance)",
            ),
            (
                Expired,
                "touch_failed",
                "no live challenge for this touch: it expired, was used, or the daemon restarted",
            ),
            (Malformed, "touch_failed", "the touch data is malformed"),
            (NotPresent, "touch_failed", "the device reported no touch"),
            (
                NotVerified,
                "touch_failed",
                "this needs user verification on the device (its PIN or fingerprint)",
            ),
        ];
        for (e, rule, text) in rows {
            assert_eq!(e.rule(), rule);
            assert_eq!(e.to_string(), text);
        }
    }
}
