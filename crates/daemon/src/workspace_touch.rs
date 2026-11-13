//! Workspace touches (plan 31): the origin list and the web assertion.
//!
//! The browser and the hub are untrusted: the origin an assertion was made
//! for is read from its own `clientDataJSON` (which `verify` binds to the
//! signature) and must be one the machine's config lists. The RP id is
//! derived from the configured origin, never from the browser.

use crate::ops::Ctx;
use saiife_touch::{Assertion, TouchError};
use saiife_wire::frame::TouchProof;

/// `[workspace] origins` of the loaded policy, else the default.
pub fn origins(ctx: &Ctx) -> Vec<String> {
    ctx.policy()
        .system
        .map(|s| s.workspace.origins.clone())
        .unwrap_or_else(saiife_policy::system::default_origins)
}

/// The RP id of a configured origin: its host (`localhost` for
/// `http://localhost:<port>`). None for anything that is not a plain
/// `http://localhost:<port>` or `https://<host>[:port]` origin. Call it on
/// an origin from the config list, never on one the browser sent.
pub fn rp_id_of(origin: &str) -> Option<String> {
    let rest = origin
        .strip_prefix("http://localhost:")
        .map(|p| ("localhost", Some(p)))
        .or_else(|| {
            let r = origin.strip_prefix("https://")?;
            Some(match r.split_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (r, None),
            })
        })?;
    let (host, port) = rest;
    let host_ok = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.');
    let port_ok = port.is_none_or(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    (host_ok && port_ok).then(|| host.to_string())
}

/// Builds the WebAuthn assertion of a touch frame. The origin comes from the
/// `clientDataJSON` and must be in `origins` (else `Mismatch`); everything
/// else (type, challenge, crossOrigin, RP id hash, UV, counter) is
/// `saiife_touch::verify`'s.
pub fn web_assertion(
    p: &TouchProof,
    origins: &[String],
) -> Result<(Assertion, String), TouchError> {
    let dec = |s: &str| saiife_wire::b64::dec(s).map_err(|_| TouchError::Malformed);
    let credential_id = dec(&p.credential_id)?;
    let auth_data = dec(&p.authenticator_data)?;
    let client_data_json = dec(&p.client_data_json)?;
    let signature = dec(&p.signature)?;
    let v: serde_json::Value =
        serde_json::from_slice(&client_data_json).map_err(|_| TouchError::Malformed)?;
    let origin = v
        .as_object()
        .and_then(|o| o.get("origin"))
        .and_then(|o| o.as_str())
        .ok_or(TouchError::Malformed)?
        .to_string();
    if !origins.contains(&origin) {
        return Err(TouchError::Mismatch);
    }
    Ok((
        Assertion::WebAuthn {
            credential_id,
            auth_data,
            signature,
            client_data_json,
            origin: origin.clone(),
        },
        origin,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use saiife_wire::b64;

    fn proof(cdj: &[u8]) -> TouchProof {
        TouchProof {
            request_id: "7".into(),
            credential_id: b64::enc(b"cred"),
            authenticator_data: b64::enc(b"auth"),
            client_data_json: b64::enc(cdj),
            signature: b64::enc(b"sig"),
        }
    }

    fn list() -> Vec<String> {
        vec![
            "http://localhost:47810".to_string(),
            "https://app.saiife.com".to_string(),
        ]
    }

    #[test]
    fn rp_id_of_cases() {
        assert_eq!(
            rp_id_of("http://localhost:47810").as_deref(),
            Some("localhost")
        );
        assert_eq!(
            rp_id_of("https://app.saiife.com:8443").as_deref(),
            Some("app.saiife.com")
        );
        assert_eq!(
            rp_id_of("https://app.saiife.com").as_deref(),
            Some("app.saiife.com")
        );
        assert_eq!(rp_id_of("javascript:x"), None);
        assert_eq!(rp_id_of("http://evil.test"), None);
        assert_eq!(rp_id_of("https://"), None);
        assert_eq!(rp_id_of("https://a.test/x"), None);
    }

    #[test]
    fn web_assertion_rules() {
        let o = list();
        let mm = |p: &TouchProof| web_assertion(p, &o).unwrap_err();
        // Bad base64 in each field.
        for f in 0..4 {
            let mut p = proof(br#"{"origin":"http://localhost:47810"}"#);
            let bad = "a=b*".to_string();
            match f {
                0 => p.credential_id = bad,
                1 => p.authenticator_data = bad,
                2 => p.client_data_json = bad,
                _ => p.signature = bad,
            }
            assert_eq!(mm(&p), TouchError::Malformed, "field {f}");
        }
        // Not an object, not JSON, no origin, origin not a string.
        for cdj in [
            &b"[1]"[..],
            b"\"x\"",
            b"nope",
            b"{}",
            br#"{"origin":5}"#,
            br#"{"type":"webauthn.get"}"#,
        ] {
            assert_eq!(
                mm(&proof(cdj)),
                TouchError::Malformed,
                "{}",
                String::from_utf8_lossy(cdj)
            );
        }
        // Outside the list.
        for origin in [
            "http://evil.test",
            "http://localhost:47811",
            "https://localhost:47810",
            "https://app.saiife.com/",
            "https://APP.saiife.com",
            "",
        ] {
            let cdj = format!(r#"{{"origin":"{origin}"}}"#);
            assert_eq!(mm(&proof(cdj.as_bytes())), TouchError::Mismatch, "{origin}");
        }
        // An empty list refuses everything.
        let p = proof(br#"{"origin":"http://localhost:47810"}"#);
        assert_eq!(web_assertion(&p, &[]).unwrap_err(), TouchError::Mismatch);
        // A good one keeps every byte.
        let cdj = br#"{"type":"webauthn.get","challenge":"x","origin":"https://app.saiife.com","crossOrigin":false}"#;
        let (a, origin) = web_assertion(&proof(cdj), &o).unwrap();
        assert_eq!(origin, "https://app.saiife.com");
        match a {
            Assertion::WebAuthn {
                credential_id,
                auth_data,
                signature,
                client_data_json,
                origin,
            } => {
                assert_eq!(credential_id, b"cred");
                assert_eq!(auth_data, b"auth");
                assert_eq!(signature, b"sig");
                assert_eq!(client_data_json, cdj);
                assert_eq!(origin, "https://app.saiife.com");
            }
            other => panic!("not a web assertion: {other:?}"),
        }
    }
}
