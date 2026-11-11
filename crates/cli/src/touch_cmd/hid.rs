//! A FIDO2 key over USB HID (feature `fido-hid`), driven by ctap-hid-fido2.
//! Never run in tests: only `classify`, `one_of` and `credential_of` are
//! tested.

use ctap_hid_fido2::fidokey::{
    CredentialSupportedKeyType, GetAssertionArgsBuilder, MakeCredentialArgsBuilder,
};
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::{get_fidokey_devices, FidoKeyHid, FidoKeyHidFactory, LibCfg};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use saiife_touch::{Assertion, EnrolRequest, Touch, TouchError, TouchRequest};

use super::{prompt_limit, run_touch};

/// Asks for the key's PIN (D3): `tty::read_hidden` outside tests.
type PinPrompt = Box<dyn Fn() -> Result<Zeroizing<String>, String> + Send + Sync>;

/// The one plugged-in FIDO2 key (D2).
pub(crate) struct HidAuthenticator {
    pin: PinPrompt,
}

const BLOCKED: &str = "the key's PIN is blocked; reset it with your key's tool";
const SET_PIN: &str = "set a PIN on the key first (for a YubiKey: ykman fido access change-pin)";
const CANCELLED: &str = "the touch was cancelled or not given";
/// The catch-all hint; the error's first line is printed after it.
const DID_NOT_ANSWER: &str = "the key did not answer";
/// D2's two texts.
const PLUG_IN: &str = "plug in your key";
const ONLY_ONE: &str = "more than one FIDO key is plugged in; leave only the one to use";

/// D2: exactly one FIDO key may be plugged in.
pub(crate) fn one_of(n: usize) -> Result<(), (TouchError, &'static str)> {
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
pub(crate) fn classify(msg: &str) -> (TouchError, &'static str) {
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

fn first_line(msg: &str) -> &str {
    msg.lines().next().unwrap_or("")
}

/// Prints `saiife: <hint>` for a ctap-hid-fido2 error and gives its error.
fn fail(e: impl std::fmt::Display) -> TouchError {
    let msg = format!("{e:#}");
    let (err, hint) = classify(&msg);
    if hint == DID_NOT_ANSWER {
        eprintln!("saiife: {hint}: {}", first_line(&msg));
    } else {
        eprintln!("saiife: {hint}");
    }
    err
}

/// D2, on the devices plugged in now.
fn one_device() -> Result<(), TouchError> {
    one_of(get_fidokey_devices().len()).map_err(|(e, hint)| {
        eprintln!("saiife: {hint}");
        e
    })
}

/// The key, without the crate's own keep-alive line (it goes to stdout):
/// saiife prints `touch your key now` itself.
fn open() -> Result<FidoKeyHid, TouchError> {
    let cfg = LibCfg {
        enable_keep_alive_msg: false,
        ..LibCfg::init()
    };
    FidoKeyHidFactory::create(&cfg).map_err(fail)
}

/// The credential an assertion is from: the id the key gave, or, when it
/// gave none, the one entry of a single-entry allow list (CTAP 2.1
/// §6.2.2 lets a key omit the id then).
pub(crate) fn credential_of(given: Vec<u8>, allow: &[Vec<u8>]) -> Vec<u8> {
    match allow {
        [only] if given.is_empty() => only.clone(),
        _ => given,
    }
}

fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

impl HidAuthenticator {
    pub(crate) fn new(pin: PinPrompt) -> Self {
        Self { pin }
    }

    /// D3: no PIN at the prompt is `NotVerified`, and nothing is sent.
    fn ask_pin(&self) -> Result<Zeroizing<String>, TouchError> {
        (self.pin)().map_err(|e| {
            eprintln!("saiife: {e}");
            TouchError::NotVerified
        })
    }
}

impl Touch for HidAuthenticator {
    fn request(&self, r: &TouchRequest) -> Result<Assertion, TouchError> {
        one_device()?;
        let pin = if r.uv { Some(self.ask_pin()?) } else { None };
        eprintln!("saiife: touch your key now");
        let r = r.clone();
        run_touch(
            move || {
                let key = open()?;
                let mut b = GetAssertionArgsBuilder::new(&r.rp_id, &r.challenge);
                for id in &r.allow {
                    b = b.add_credential_id(id);
                }
                b = match &pin {
                    Some(p) => b.pin(p),
                    None => b.without_pin_and_uv(),
                };
                let got = key.get_assertion_with_args(&b.build()).map_err(fail)?;
                let a = got.into_iter().next().ok_or_else(|| {
                    eprintln!("saiife: {DID_NOT_ANSWER}: no assertion");
                    TouchError::Unavailable
                })?;
                Ok(Assertion::Ctap2 {
                    credential_id: credential_of(a.credential_id, &r.allow),
                    auth_data: a.auth_data,
                    signature: a.signature,
                    client_data_hash: sha256(&r.challenge),
                })
            },
            prompt_limit(),
        )
    }

    fn enrol(&self, r: &EnrolRequest) -> Result<Vec<u8>, TouchError> {
        one_device()?;
        let pin = self.ask_pin()?;
        eprintln!("saiife: touch your key now");
        let r = r.clone();
        run_touch(
            move || {
                let key = open()?;
                let user = PublicKeyCredentialUserEntity::new(
                    Some(&r.user_id),
                    Some(&r.user_name),
                    Some(&r.user_name),
                );
                let mut b = MakeCredentialArgsBuilder::new(&r.rp_id, &r.challenge)
                    .pin(&pin)
                    .key_type(CredentialSupportedKeyType::Ecdsa256);
                for id in &r.exclude {
                    b = b.exclude_authenticator(id);
                }
                let args = b.user_entity(&user).build();
                let att = key.make_credential_with_args(&args).map_err(fail)?;
                Ok(att.auth_data)
            },
            prompt_limit(),
        )
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
