//! Credential store types.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::action::sha256;
use crate::authdata::{self, AT, UP};
use crate::codec::hex;
use crate::cose::CoseKey;
use crate::TouchError;

/// A COSE signature algorithm saiife accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CoseAlg {
    /// ECDSA P-256 with SHA-256 (COSE -7).
    Es256,
    /// EdDSA over Ed25519 (COSE -8).
    Ed25519,
}

/// An enrolled credential. Bytes are base64url in JSON; the public key is
/// base64url of its COSE encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    #[serde(with = "crate::codec::b64")]
    pub id: Vec<u8>,
    #[serde(with = "crate::codec::cose_b64")]
    pub public_key: CoseKey,
    /// `"fido2"` or `"webauthn"`.
    pub kind: String,
    pub rp_id: String,
    /// The browser origins a WebAuthn credential may sign for.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub origins: Vec<String>,
    pub label: String,
    pub owner_uid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_sid: Option<String>,
    pub sign_count: u32,
    pub created: String,
    /// Hex.
    pub aaguid: String,
}

/// The most credentials one uid may enrol.
const MAX_PER_UID: usize = 16;

/// The enrolled credentials of every user, as one JSON file (`v` is 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialFile {
    pub v: u32,
    pub credentials: Vec<Credential>,
}

impl Default for CredentialFile {
    /// An empty file at version 1, which `save` and `load` agree on.
    fn default() -> Self {
        CredentialFile {
            v: 1,
            credentials: Vec::new(),
        }
    }
}

fn invalid(path: &Path, why: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{}: {why}", path.display()),
    )
}

impl CredentialFile {
    /// Reads the file. A missing file is empty (`v = 1`); unparsable JSON or
    /// `v != 1` is `InvalidData` naming the path.
    pub fn load(path: &Path) -> io::Result<CredentialFile> {
        let raw = match std::fs::read(path) {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(CredentialFile {
                    v: 1,
                    credentials: Vec::new(),
                })
            }
            Err(e) => return Err(io::Error::new(e.kind(), format!("{}: {e}", path.display()))),
        };
        let f: CredentialFile = serde_json::from_slice(&raw).map_err(|e| invalid(path, e))?;
        if f.v != 1 {
            return Err(invalid(path, format!("unsupported version {}", f.v)));
        }
        Ok(f)
    }

    /// Writes `<path>.tmp` (mode 0600 on Unix), syncs it, renames it over
    /// `path`, then syncs the directory (Unix).
    pub fn save(&self, path: &Path) -> io::Result<()> {
        use std::io::Write as _;
        let mut name = path.file_name().unwrap_or_default().to_os_string();
        name.push(".tmp");
        let tmp: PathBuf = path.with_file_name(name);
        let body = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(&body)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)?;
        #[cfg(unix)]
        {
            let dir = match path.parent() {
                Some(d) if !d.as_os_str().is_empty() => d,
                _ => Path::new("."),
            };
            std::fs::File::open(dir)?.sync_all()?;
        }
        Ok(())
    }

    /// The credentials `uid` enrolled.
    pub fn of_uid(&self, uid: u32) -> Vec<Credential> {
        self.credentials
            .iter()
            .filter(|c| c.owner_uid == uid)
            .cloned()
            .collect()
    }

    /// Adds a credential; refuses a duplicate id, a 17th credential of one
    /// uid and a bad label.
    pub fn add(&mut self, c: Credential) -> Result<(), String> {
        check_label(&c.label)?;
        if self.credentials.iter().any(|x| x.id == c.id) {
            return Err("already enrolled".into());
        }
        if self.of_uid(c.owner_uid).len() >= MAX_PER_UID {
            return Err("at most 16 devices per user".into());
        }
        self.credentials.push(c);
        Ok(())
    }

    /// Removes and returns the credential with this id.
    pub fn remove(&mut self, id: &[u8]) -> Option<Credential> {
        let i = self.credentials.iter().position(|c| c.id == id)?;
        Some(self.credentials.remove(i))
    }

    /// Stores a new sign counter; false when the id is unknown.
    pub fn set_count(&mut self, id: &[u8], n: u32) -> bool {
        match self.credentials.iter_mut().find(|c| c.id == id) {
            Some(c) => {
                c.sign_count = n;
                true
            }
            None => false,
        }
    }
}

/// Unicode format (Cf) characters and the line and paragraph separators.
/// The ranges are copied from `is_format` in `crates/daemon/src/approvals.rs`
/// (this crate must not depend on the daemon); keep the two in step.
fn is_format(c: char) -> bool {
    matches!(
        c as u32,
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x180E
            | 0x200B..=0x200F
            | 0x2028..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0001
            | 0xE0020..=0xE007F
    )
}

/// A device label: 1 to 64 characters, no control or format characters.
pub fn check_label(l: &str) -> Result<(), String> {
    let n = l.chars().count();
    if !(1..=64).contains(&n) {
        return Err("a label is 1 to 64 characters".into());
    }
    if l.chars().any(|c| c.is_control() || is_format(c)) {
        return Err("a label cannot contain control or invisible characters".into());
    }
    Ok(())
}

/// Builds the credential from attestation authData (enrolment, D10). Needs
/// AT (else `Malformed`), UP and `rp_id_hash == sha256(rp_id)` (else
/// `Mismatch`). The attestation statement is not checked. `kind` is
/// `"fido2"`; `sign_count` is the authData's.
pub fn credential_from_attestation(
    auth_data: &[u8],
    rp_id: &str,
    label: &str,
    owner_uid: u32,
    owner_sid: Option<String>,
    created: &str,
) -> Result<Credential, TouchError> {
    let ad = authdata::parse(auth_data)?;
    let att = match ad.attested {
        Some(a) if ad.flags & AT != 0 => a,
        _ => return Err(TouchError::Malformed),
    };
    if ad.flags & UP == 0 || ad.rp_id_hash != sha256(rp_id.as_bytes()) {
        return Err(TouchError::Mismatch);
    }
    Ok(Credential {
        id: att.credential_id,
        public_key: att.public_key,
        kind: "fido2".into(),
        rp_id: rp_id.into(),
        origins: Vec::new(),
        label: label.into(),
        owner_uid,
        owner_sid,
        sign_count: ad.sign_count,
        created: created.into(),
        aaguid: hex(&att.aaguid),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred() -> Credential {
        Credential {
            id: vec![0xfb, 0xff, 1],
            public_key: CoseKey::Ed25519 { x: [3; 32] },
            kind: "fido2".into(),
            rp_id: "saiife.local".into(),
            origins: vec![],
            label: "key".into(),
            owner_uid: 1000,
            owner_sid: None,
            sign_count: 7,
            created: "2026-01-01T00:00:00.000Z".into(),
            aaguid: "00".repeat(16),
        }
    }

    use crate::client::{EnrolRequest, Touch};
    use crate::soft::SoftAuthenticator;
    use crate::{TouchError, LOCAL_RP_ID};

    fn with_id(id: u8, uid: u32) -> Credential {
        Credential {
            id: vec![id; 16],
            owner_uid: uid,
            ..cred()
        }
    }

    #[test]
    fn file_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("touch.json");
        let mut f = CredentialFile::default();
        f.add(with_id(1, 1000)).unwrap();
        f.add(with_id(2, 1001)).unwrap();
        f.save(&path).unwrap();
        assert_eq!(CredentialFile::load(&path).unwrap(), f);
        assert_eq!(f.of_uid(1000).len(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert!(!dir.path().join("touch.json.tmp").exists());
        assert!(f.set_count(&[1; 16], 9));
        assert!(!f.set_count(&[7; 16], 9));
        assert_eq!(f.of_uid(1000)[0].sign_count, 9);
        assert!(f.remove(&[1; 16]).is_some() && f.remove(&[1; 16]).is_none());
    }

    #[test]
    fn default_file_saves_and_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("touch.json");
        let mut f = CredentialFile::default();
        assert_eq!(f.v, 1);
        f.add(with_id(3, 1000)).unwrap();
        f.save(&path).unwrap();
        assert_eq!(CredentialFile::load(&path).unwrap(), f);
    }

    #[test]
    fn missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let f = CredentialFile::load(&dir.path().join("none.json")).unwrap();
        assert_eq!(f.v, 1);
        assert!(f.credentials.is_empty());
    }

    #[test]
    fn bad_file_is_invalid_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("touch.json");
        for body in [
            "{",
            r#"{"v":2,"credentials":[]}"#,
            r#"{"v":1,"credentials":[],"extra":1}"#,
        ] {
            std::fs::write(&path, body).unwrap();
            let e = CredentialFile::load(&path).unwrap_err();
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidData, "{body}");
            assert!(e.to_string().contains("touch.json"), "{e}");
        }
    }

    #[test]
    fn add_limits() {
        let mut f = CredentialFile::default();
        f.add(with_id(1, 1000)).unwrap();
        assert_eq!(f.add(with_id(1, 1000)).unwrap_err(), "already enrolled");
        assert_eq!(f.add(with_id(1, 1001)).unwrap_err(), "already enrolled");
        for i in 2..=16 {
            f.add(with_id(i, 1000)).unwrap();
        }
        assert_eq!(
            f.add(with_id(17, 1000)).unwrap_err(),
            "at most 16 devices per user"
        );
        f.add(with_id(17, 1001)).unwrap();
        for bad in ["", &"a".repeat(65), "a\u{202e}b", "a\nb"] {
            let mut c = with_id(99, 5);
            c.label = bad.into();
            assert_eq!(f.add(c).unwrap_err(), check_label(bad).unwrap_err());
            assert!(check_label(bad).is_err(), "{bad:?}");
        }
        assert!(check_label(&"é".repeat(64)).is_ok());
        assert!(check_label("my yubikey").is_ok());
    }

    #[test]
    fn from_attestation() {
        let ts = "2026-11-11T00:00:00.000Z";
        let req = EnrolRequest {
            rp_id: LOCAL_RP_ID.into(),
            rp_name: crate::RP_NAME.into(),
            user_id: vec![1],
            user_name: "jo".into(),
            challenge: [5; 32],
            exclude: vec![],
        };
        for soft in [
            SoftAuthenticator::new_es256(),
            SoftAuthenticator::new_ed25519(),
        ] {
            let ad = soft.enrol(&req).unwrap();
            let c =
                credential_from_attestation(&ad, LOCAL_RP_ID, "yubikey", 1000, None, ts).unwrap();
            assert_eq!(c.public_key, soft.public_key());
            assert_eq!(c.id, soft.credential_id());
            assert_eq!(
                (c.kind.as_str(), c.owner_uid, c.sign_count),
                ("fido2", 1000, 0)
            );
            assert_eq!(c.rp_id, LOCAL_RP_ID);
            assert_eq!(c.aaguid, "00".repeat(16));
            assert_eq!(
                credential_from_attestation(&ad, "other.example", "k", 1, None, ts).unwrap_err(),
                TouchError::Mismatch
            );
            let mut no_at = ad.clone();
            no_at[32] &= !0x40;
            no_at.truncate(37);
            assert_eq!(
                credential_from_attestation(&no_at, LOCAL_RP_ID, "k", 1, None, ts).unwrap_err(),
                TouchError::Malformed
            );
            let mut no_up = ad.clone();
            no_up[32] &= !0x01;
            assert_eq!(
                credential_from_attestation(&no_up, LOCAL_RP_ID, "k", 1, None, ts).unwrap_err(),
                TouchError::Mismatch
            );
        }
    }

    #[test]
    fn credential_json_shape() {
        let c = cred();
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["id"], "-_8B");
        assert_eq!(v["public_key"], crate::codec::b64(&c.public_key.to_cose()));
        assert!(v.get("origins").is_none() && v.get("owner_sid").is_none());
        assert_eq!(serde_json::from_value::<Credential>(v.clone()).unwrap(), c);
        let mut extra = v.clone();
        extra["bogus"] = 1.into();
        assert!(serde_json::from_value::<Credential>(extra).is_err());
        let mut bad_key = v;
        bad_key["public_key"] = crate::codec::b64(&[0xa0]).into();
        assert!(serde_json::from_value::<Credential>(bad_key).is_err());
    }
}
