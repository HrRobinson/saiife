//! The GCP service-account key and the RS256 JWT assertion of Google's
//! OAuth2 service-account flow (RFC 7523). Pure and sync; the exchange is
//! in [`super::token`].
//!
//! The private key is parsed once into a `ring` key pair. The PEM and the
//! decoded DER are zeroized on drop, and no `Debug`, error or log line ever
//! shows them: [`GcpKey`]'s `Debug` shows the client email only.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use zeroize::Zeroizing;

use super::token::GCP_TOKEN_URL;
use super::CloudError;

/// The lifetime of an assertion (Google's maximum).
pub const ASSERTION_TTL_SECS: i64 = 3600;
/// The smallest RSA modulus accepted.
const MIN_RSA_BITS: usize = 2048;

/// A parsed `gcp_sa` vault entry. `Debug` shows the client email only.
pub struct GcpKey {
    pub client_email: String,
    /// The key's `private_key_id`, sent as the JWT `kid`.
    pub key_id: String,
    pair: RsaKeyPair,
}

impl std::fmt::Debug for GcpKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpKey")
            .field("client_email", &self.client_email)
            .finish_non_exhaustive()
    }
}

fn field<'a>(
    fields: &'a BTreeMap<String, Zeroizing<String>>,
    name: &str,
) -> Result<&'a str, CloudError> {
    fields
        .get(name)
        .map(|v| v.as_str())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| CloudError::Key(format!("gcp_sa: the secret has no field {name:?}")))
}

/// The key of a `gcp_sa` secret: `client_email`, `private_key_id` and the
/// PKCS#8 PEM `private_key`, an RSA key of at least 2048 bits. A refusal
/// names the field, never its value.
pub fn parse_gcp_key(fields: &BTreeMap<String, Zeroizing<String>>) -> Result<GcpKey, CloudError> {
    let client_email = field(fields, "client_email")?;
    let key_id = field(fields, "private_key_id")?;
    if !client_email.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(CloudError::Key(
            "gcp_sa: client_email is not printable".into(),
        ));
    }
    if !key_id.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(CloudError::Key(
            "gcp_sa: private_key_id is not alphanumeric".into(),
        ));
    }
    let pem = field(fields, "private_key")?;
    let not_key = || CloudError::Key("gcp_sa: private_key is not a PKCS#8 PEM RSA key".into());
    let der = Zeroizing::new(
        rustls_pemfile::private_key(&mut pem.as_bytes())
            .map_err(|_| not_key())?
            .ok_or_else(not_key)?,
    );
    let rustls::pki_types::PrivateKeyDer::Pkcs8(pk8) = &*der else {
        return Err(not_key());
    };
    let pair = RsaKeyPair::from_pkcs8(pk8.secret_pkcs8_der()).map_err(|_| not_key())?;
    if pair.public().modulus_len() * 8 < MIN_RSA_BITS {
        return Err(CloudError::Key(
            "gcp_sa: private_key is shorter than 2048 bits".into(),
        ));
    }
    Ok(GcpKey {
        client_email: client_email.to_string(),
        key_id: key_id.to_string(),
        pair,
    })
}

/// The signed JWT for `scope`: header `{"alg":"RS256","typ":"JWT","kid"}`,
/// claims `iss` (the client email), `scope`, `aud` ([`GCP_TOKEN_URL`]),
/// `iat` (`now`) and `exp` (`now` + 3600 s). It is a credential, so it is
/// zeroized on drop.
pub fn assertion(
    k: &GcpKey,
    scope: &str,
    now: OffsetDateTime,
) -> Result<Zeroizing<String>, CloudError> {
    if scope.is_empty() || !scope.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
        return Err(CloudError::Key("gcp_sa: the scope is not printable".into()));
    }
    let iat = now.unix_timestamp();
    let header = serde_json::json!({"alg": "RS256", "typ": "JWT", "kid": k.key_id});
    let claims = serde_json::json!({
        "iss": k.client_email,
        "scope": scope,
        "aud": GCP_TOKEN_URL,
        "iat": iat,
        "exp": iat + ASSERTION_TTL_SECS,
    });
    let (header, claims) = (header.to_string(), claims.to_string());
    let sig_len = k.pair.public().modulus_len();
    // Sized once, so the buffer never reallocates and leaves no copy behind.
    let b64 = |n: usize| base64::encoded_len(n, false).unwrap_or(usize::MAX);
    let cap = b64(header.len())
        .saturating_add(b64(claims.len()))
        .saturating_add(b64(sig_len))
        .saturating_add(2);
    let mut jwt = Zeroizing::new(String::with_capacity(cap));
    URL_SAFE_NO_PAD.encode_string(&header, &mut jwt);
    jwt.push('.');
    URL_SAFE_NO_PAD.encode_string(&claims, &mut jwt);
    let mut sig = Zeroizing::new(vec![0u8; sig_len]);
    k.pair
        .sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            jwt.as_bytes(),
            &mut sig,
        )
        .map_err(|_| CloudError::Key("gcp_sa: signing the assertion failed".into()))?;
    jwt.push('.');
    URL_SAFE_NO_PAD.encode_string(&*sig, &mut jwt);
    debug_assert!(jwt.len() <= cap);
    Ok(jwt)
}
