//! A FIDO2 key over USB HID, driven by ctap-hid-fido2. No printing, no
//! prompts: errors come back as `format!("{e:#}")` for `errors::classify`.
//! Never run in tests.

use ctap_hid_fido2::fidokey::{
    CredentialSupportedKeyType, GetAssertionArgsBuilder, MakeCredentialArgsBuilder,
};
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::{get_fidokey_devices, FidoKeyHid, FidoKeyHidFactory, LibCfg};

use crate::proto::{AssertParts, AssertReq, EnrolReq};

/// The FIDO keys plugged in now.
pub fn device_count() -> usize {
    get_fidokey_devices().len()
}

/// The key, without the crate's own keep-alive line (it goes to stdout).
fn open() -> Result<FidoKeyHid, String> {
    let cfg = LibCfg {
        enable_keep_alive_msg: false,
        ..LibCfg::init()
    };
    FidoKeyHidFactory::create(&cfg).map_err(|e| format!("{e:#}"))
}

/// `(credential_id, auth_data, signature)` of the first assertion.
pub fn assert(r: &AssertReq) -> Result<AssertParts, String> {
    let key = open()?;
    let mut b = GetAssertionArgsBuilder::new(&r.rp_id, &r.challenge);
    for id in &r.allow {
        b = b.add_credential_id(id);
    }
    b = match &r.pin {
        Some(p) => b.pin(p),
        None => b.without_pin_and_uv(),
    };
    let got = key
        .get_assertion_with_args(&b.build())
        .map_err(|e| format!("{e:#}"))?;
    let a = got
        .into_iter()
        .next()
        .ok_or_else(|| "no assertion".to_string())?;
    Ok((a.credential_id, a.auth_data, a.signature))
}

/// The attestation's auth data.
pub fn enrol(r: &EnrolReq) -> Result<Vec<u8>, String> {
    let key = open()?;
    let user = PublicKeyCredentialUserEntity::new(
        Some(&r.user_id),
        Some(&r.user_name),
        Some(&r.user_name),
    );
    let mut b = MakeCredentialArgsBuilder::new(&r.rp_id, &r.challenge)
        .pin(&r.pin)
        .key_type(CredentialSupportedKeyType::Ecdsa256);
    for id in &r.exclude {
        b = b.exclude_authenticator(id);
    }
    let args = b.user_entity(&user).build();
    let att = key
        .make_credential_with_args(&args)
        .map_err(|e| format!("{e:#}"))?;
    Ok(att.auth_data)
}
