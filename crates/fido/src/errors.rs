//! The error table for ctap-hid-fido2 error texts, and the device rules.

use saiife_touch::TouchError;

pub const BLOCKED: &str = "the key's PIN is blocked; reset it with your key's tool";
pub const SET_PIN: &str =
    "set a PIN on the key first (for a YubiKey: ykman fido access change-pin)";
pub const CANCELLED: &str = "the touch was cancelled or not given";
/// The catch-all hint; the error's first line is printed after it.
pub const DID_NOT_ANSWER: &str = "the key did not answer";
/// D2's two texts.
pub const PLUG_IN: &str = "plug in your key";
pub const ONLY_ONE: &str = "more than one FIDO key is plugged in; leave only the one to use";

/// D2: exactly one FIDO key may be plugged in.
pub fn one_of(n: usize) -> Result<(), (TouchError, &'static str)> {
    match n {
        1 => Ok(()),
        0 => Err((TouchError::Unavailable, PLUG_IN)),
        _ => Err((TouchError::Unavailable, ONLY_ONE)),
    }
}

/// The error and hint for an error text of ctap-hid-fido2 (`format!("{e:#}")`).
/// The substrings are the status names 3.6.0 renders in
/// `ctapdef::get_ctap_status_message` (`0x31 CTAP2_ERR_PIN_INVALID   PIN Invalid.`),
/// and the device texts of `FidoKeyHidFactory::create` (lib.rs:99, :102).
pub fn classify(msg: &str) -> (TouchError, &'static str) {
    use TouchError::*;
    let has = |names: &[&str]| names.iter().any(|n| msg.contains(n));
    if has(&["CTAP2_ERR_PIN_INVALID"]) {
        (NotVerified, "wrong PIN")
    } else if has(&["CTAP2_ERR_PIN_BLOCKED", "CTAP2_ERR_PIN_AUTH_BLOCKED"]) {
        (NotVerified, BLOCKED)
    } else if has(&["CTAP2_ERR_PIN_NOT_SET", "CTAP2_ERR_PIN_REQUIRED"]) {
        (NotVerified, SET_PIN)
    } else if has(&["CTAP2_ERR_NO_CREDENTIALS"]) {
        (
            UnknownCredential,
            "this key is not enrolled for you (saiife touch ls)",
        )
    } else if has(&["CTAP2_ERR_CREDENTIAL_EXCLUDED"]) {
        (Mismatch, "this key is already enrolled")
    } else if has(&["FIDO device not found"]) {
        (Unavailable, PLUG_IN)
    } else if has(&["Multiple FIDO devices found"]) {
        (Unavailable, ONLY_ONE)
    } else if has(&[
        "CTAP2_ERR_OPERATION_DENIED",
        "CTAP2_ERR_USER_ACTION_TIMEOUT",
        "CTAP2_ERR_KEEPALIVE_CANCEL",
    ]) {
        (NotPresent, CANCELLED)
    } else {
        (Unavailable, DID_NOT_ANSWER)
    }
}

/// The first line of an error text.
pub fn first_line(msg: &str) -> &str {
    msg.lines().next().unwrap_or("")
}

/// The credential an assertion is from: the id the key gave, or, when it
/// gave none, the one entry of a single-entry allow list (CTAP 2.1
/// §6.2.2 lets a key omit the id then).
pub fn credential_of(given: Vec<u8>, allow: &[Vec<u8>]) -> Vec<u8> {
    match allow {
        [only] if given.is_empty() => only.clone(),
        _ => given,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use TouchError::*;

    /// Review Focus 2: one text per row, as ctap-hid-fido2 3.6.0 renders the
    /// status (`ctapdef::get_ctap_status_message`).
    #[test]
    fn classify_ctap_errors() {
        let rows = [
            ("0x31 CTAP2_ERR_PIN_INVALID   PIN Invalid.", NotVerified, "wrong PIN"),
            ("0x32 CTAP2_ERR_PIN_BLOCKED PIN Blocked.", NotVerified, BLOCKED),
            (
                "0x34 CTAP2_ERR_PIN_AUTH_BLOCKED PIN authentication, pinAuth, blocked.Requires power recycle to reset.",
                NotVerified,
                BLOCKED,
            ),
            ("0x35 CTAP2_ERR_PIN_NOT_SET No PIN has been set.", NotVerified, SET_PIN),
            (
                "0x36 CTAP2_ERR_PIN_REQUIRED  PIN is required for the selected operation.",
                NotVerified,
                SET_PIN,
            ),
            (
                "0x2E CTAP2_ERR_NO_CREDENTIALS    No valid credentials provided.",
                UnknownCredential,
                "this key is not enrolled for you (saiife touch ls)",
            ),
            (
                "0x19 CTAP2_ERR_CREDENTIAL_EXCLUDED   Valid credential found in the exclude list.",
                Mismatch,
                "this key is already enrolled",
            ),
            (
                "0x27 CTAP2_ERR_OPERATION_DENIED  Not authorized for requested operation.",
                NotPresent,
                CANCELLED,
            ),
            (
                "0x2F CTAP2_ERR_USER_ACTION_TIMEOUT   Timeout waiting for user interaction.",
                NotPresent,
                CANCELLED,
            ),
            (
                "0x2D CTAP2_ERR_KEEPALIVE_CANCEL  Pending keep alive was cancelled.",
                NotPresent,
                CANCELLED,
            ),
            // `FidoKeyHidFactory::create` (lib.rs:99, :102): the key was
            // pulled, or another plugged in, after `one_device`.
            ("FIDO device not found.", Unavailable, "plug in your key"),
            (
                "Multiple FIDO devices found.",
                Unavailable,
                "more than one FIDO key is plugged in; leave only the one to use",
            ),
            ("unexpected HID read error", Unavailable, DID_NOT_ANSWER),
            (
                "0x33 CTAP2_ERR_PIN_AUTH_INVALID PIN authentication, pinAuth, verification failed.",
                Unavailable,
                DID_NOT_ANSWER,
            ),
        ];
        for (msg, err, hint) in rows {
            assert_eq!(classify(msg), (err, hint), "{msg}");
            // anyhow's `{:#}` puts context first: the status still classifies.
            assert_eq!(classify(&format!("get_assertion: {msg}")), (err, hint));
        }
        assert_eq!(
            BLOCKED,
            "the key's PIN is blocked; reset it with your key's tool"
        );
        assert_eq!(
            SET_PIN,
            "set a PIN on the key first (for a YubiKey: ykman fido access change-pin)"
        );
        assert_eq!(CANCELLED, "the touch was cancelled or not given");
        assert_eq!(DID_NOT_ANSWER, "the key did not answer");
        assert_eq!(first_line("a\nb"), "a");
    }

    /// R-F: a key may omit the credential id for a single-entry allow list.
    #[test]
    fn omitted_id_is_the_one_allowed() {
        let (a, b) = (vec![1u8, 2, 3], vec![4u8, 5]);
        assert_eq!(credential_of(vec![], std::slice::from_ref(&a)), a);
        assert_eq!(credential_of(b.clone(), std::slice::from_ref(&a)), b);
        // Two allowed, or none: the key's own answer, even when empty.
        assert_eq!(
            credential_of(vec![], &[a.clone(), b.clone()]),
            Vec::<u8>::new()
        );
        assert_eq!(credential_of(vec![], &[]), Vec::<u8>::new());
        assert_eq!(credential_of(b.clone(), &[a, b.clone()]), b);
    }

    #[test]
    fn pick_one_device_rules() {
        assert_eq!(one_of(1), Ok(()));
        assert_eq!(one_of(0), Err((Unavailable, "plug in your key")));
        let many = Err((
            Unavailable,
            "more than one FIDO key is plugged in; leave only the one to use",
        ));
        assert_eq!(one_of(2), many);
        assert_eq!(one_of(3), many);
    }
}
