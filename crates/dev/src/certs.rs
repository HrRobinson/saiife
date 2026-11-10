//! The local CA of `saiife dev`, name-constrained to `localhost`.
//!
//! The CA lives at `<state>/ca/` (0700): `ca.pem`, `ca-key.pem` (0600) and
//! `ca.json` (`{"created": <unix s>, "not_after": <unix s>}`). It is reloaded
//! with no X.509 parsing: the issuer is rebuilt from fixed parameters (the DN
//! carries the creation date from `ca.json`) and the stored key (plan 23 D3).
//! A broken or partial CA is never regenerated silently: that would quietly
//! break the trust the user installed.
use crate::paths::DevPaths;
use crate::DevError;
use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    NameConstraints, SanType,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use time::{Duration, OffsetDateTime};

/// Validity of the CA.
pub const CA_DAYS: i64 = 3650;
/// Validity of a project leaf.
pub const LEAF_DAYS: i64 = 365;
/// A certificate with fewer days left than this is renewed (a leaf) or refused (the CA).
pub const RENEW_BEFORE_DAYS: i64 = 30;

const CA_CERT: &str = "ca.pem";
const CA_KEY: &str = "ca-key.pem";
const CA_META: &str = "ca.json";

/// The local CA, as stored on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ca {
    pub cert_pem: String,
    pub key_path: PathBuf,
    pub cert_path: PathBuf,
}

/// Where a certificate and its key are stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct CaMeta {
    created: i64,
    not_after: i64,
}

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> DevError + '_ {
    move |source| DevError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn cert_err(e: rcgen::Error) -> DevError {
    DevError::Cert(e.to_string())
}

fn invalid(path: &Path, reason: impl Into<String>) -> DevError {
    DevError::CaInvalid {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

/// A suffix that no other writer, in this process or another, uses at the same time.
fn unique() -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!(
        "{}-{nanos}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

fn date(t: OffsetDateTime) -> String {
    const F: &[time::format_description::FormatItem<'static>] =
        time::macros::format_description!("[year]-[month]-[day]");
    t.format(F).unwrap_or_default()
}

/// Writes `bytes` to a dot-named temp file next to `path`, then renames it over
/// `path`. With `secret`, the file is created with mode 0600 (Unix).
pub(crate) fn write_atomic(path: &Path, bytes: &[u8], secret: bool) -> Result<(), DevError> {
    let name = path
        .file_name()
        .ok_or_else(|| DevError::Io {
            path: path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidInput, "no file name"),
        })?
        .to_string_lossy()
        .into_owned();
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(".{name}.{}.tmp", unique()));
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(if secret { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = secret;
    let written = opts.open(&tmp).and_then(|mut f| {
        f.write_all(bytes)?;
        f.sync_all()
    });
    if let Err(source) = written {
        let _ = fs::remove_file(&tmp);
        return Err(DevError::Io { path: tmp, source });
    }
    fs::rename(&tmp, path).map_err(|source| {
        let _ = fs::remove_file(&tmp);
        DevError::Io {
            path: path.to_path_buf(),
            source,
        }
    })
}

pub(crate) fn create_private_dir(dir: &Path, recursive: bool) -> io::Result<()> {
    let mut b = fs::DirBuilder::new();
    b.recursive(recursive);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
}

/// The CA parameters (D3). `created` fixes the DN, `now` the validity.
fn ca_params(created: OffsetDateTime, now: OffsetDateTime) -> CertificateParams {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "saiife dev CA");
    dn.push(
        DnType::OrganizationalUnitName,
        format!("created {}", date(created)),
    );
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    // DNS names only under `localhost`. A permitted DNS subtree leaves the other
    // name forms open (RFC 5280 4.2.1.10), so:
    // - every IPv4 and IPv6 address is excluded (/0);
    // - mail names are permitted only under the reserved `.invalid` (RFC 6761),
    //   because RFC 5280 has no "every mailbox" form for an exclusion. webpki
    //   refuses any mail SAN once a mail constraint exists.
    // rcgen 0.14.10 cannot encode a URI subtree, so URI names stay unconstrained.
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: vec![
            GeneralSubtree::DnsName("localhost".to_string()),
            GeneralSubtree::Rfc822Name(".invalid".to_string()),
        ],
        excluded_subtrees: vec![
            GeneralSubtree::IpAddress(CidrSubnet::V4([0; 4], [0; 4])),
            GeneralSubtree::IpAddress(CidrSubnet::V6([0; 16], [0; 16])),
        ],
    });
    params.not_before = now - Duration::hours(1);
    params.not_after = now + Duration::days(CA_DAYS);
    params
}

/// Ensures the local CA exists and is usable, creating it on first use.
pub fn ensure_ca(paths: &DevPaths) -> Result<Ca, DevError> {
    ensure_ca_at(paths, OffsetDateTime::now_utc())
}

pub(crate) fn ensure_ca_at(paths: &DevPaths, now: OffsetDateTime) -> Result<Ca, DevError> {
    let dir = paths.ca_dir();
    if fs::symlink_metadata(&dir).is_ok() {
        return load_ca(&dir, now);
    }
    create_private_dir(&paths.state, true).map_err(io_err(&paths.state))?;
    let tmp = paths.state.join(format!(".ca.tmp-{}", unique()));
    if let Err(e) = build_ca(&tmp, now) {
        let _ = fs::remove_dir_all(&tmp);
        return Err(e);
    }
    if let Err(source) = fs::rename(&tmp, &dir) {
        let _ = fs::remove_dir_all(&tmp);
        // Another `up` won the race: use its CA.
        if fs::symlink_metadata(&dir).is_err() {
            return Err(DevError::Io { path: dir, source });
        }
    }
    load_ca(&dir, now)
}

fn build_ca(tmp: &Path, now: OffsetDateTime) -> Result<(), DevError> {
    create_private_dir(tmp, false).map_err(io_err(tmp))?;
    let created = OffsetDateTime::from_unix_timestamp(now.unix_timestamp())
        .map_err(|e| DevError::Cert(e.to_string()))?;
    let params = ca_params(created, created);
    let key = KeyPair::generate().map_err(cert_err)?;
    let cert = params.self_signed(&key).map_err(cert_err)?;
    let meta = CaMeta {
        created: created.unix_timestamp(),
        not_after: params.not_after.unix_timestamp(),
    };
    let meta = serde_json::to_vec(&meta).map_err(|e| DevError::Cert(e.to_string()))?;
    write_atomic(&tmp.join(CA_KEY), key.serialize_pem().as_bytes(), true)?;
    write_atomic(&tmp.join(CA_CERT), cert.pem().as_bytes(), false)?;
    write_atomic(&tmp.join(CA_META), &meta, false)
}

fn read_meta(path: &Path) -> Result<CaMeta, DevError> {
    let text = fs::read_to_string(path).map_err(io_err(path))?;
    serde_json::from_str(&text).map_err(|e| invalid(path, format!("cannot parse: {e}")))
}

fn read_key(path: &Path) -> Result<KeyPair, DevError> {
    let pem = fs::read_to_string(path).map_err(io_err(path))?;
    KeyPair::from_pem(&pem).map_err(|e| invalid(path, format!("not a usable key: {e}")))
}

fn load_ca(dir: &Path, now: OffsetDateTime) -> Result<Ca, DevError> {
    let meta = fs::symlink_metadata(dir).map_err(io_err(dir))?;
    if !meta.is_dir() {
        return Err(invalid(dir, "not a directory (a symlink is refused too)"));
    }
    let cert_path = dir.join(CA_CERT);
    let key_path = dir.join(CA_KEY);
    let meta_path = dir.join(CA_META);
    for p in [&cert_path, &key_path, &meta_path] {
        match fs::symlink_metadata(p) {
            Ok(m) if m.is_file() => {}
            Ok(_) => return Err(invalid(p, "not a regular file")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(invalid(p, "missing"));
            }
            Err(e) => return Err(io_err(p)(e)),
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&key_path)
            .map_err(io_err(&key_path))?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            return Err(invalid(
                &key_path,
                format!("the CA key has mode {mode:04o}; it must be 0600 (owner only)"),
            ));
        }
    }
    let ca_meta = read_meta(&meta_path)?;
    let not_after = OffsetDateTime::from_unix_timestamp(ca_meta.not_after)
        .map_err(|e| invalid(&meta_path, format!("bad not_after: {e}")))?;
    OffsetDateTime::from_unix_timestamp(ca_meta.created)
        .map_err(|e| invalid(&meta_path, format!("bad created: {e}")))?;
    if not_after - now < Duration::days(RENEW_BEFORE_DAYS) {
        return Err(invalid(
            &cert_path,
            format!(
                "the CA expires on {} (fewer than {RENEW_BEFORE_DAYS} days left)",
                date(not_after)
            ),
        ));
    }
    read_key(&key_path)?;
    let cert_pem = fs::read_to_string(&cert_path).map_err(io_err(&cert_path))?;
    if !cert_pem.starts_with("-----BEGIN CERTIFICATE-----") {
        return Err(invalid(&cert_path, "not a PEM certificate"));
    }
    Ok(Ca {
        cert_pem,
        key_path,
        cert_path,
    })
}

/// The issuer of `ca`, rebuilt from `ca.json` and the stored key, and the CA's
/// raw public key (recorded in each leaf's `meta.json`).
pub(crate) fn ca_issuer(ca: &Ca) -> Result<(Issuer<'static, KeyPair>, Vec<u8>), DevError> {
    let dir = ca.cert_path.parent().unwrap_or(Path::new("."));
    let meta_path = dir.join(CA_META);
    let meta = read_meta(&meta_path)?;
    let created = OffsetDateTime::from_unix_timestamp(meta.created)
        .map_err(|e| invalid(&meta_path, format!("bad created: {e}")))?;
    let key = read_key(&ca.key_path)?;
    let raw = key.public_key_raw().to_vec();
    Ok((Issuer::new(ca_params(created, created), key), raw))
}

/// `<state>/tls`: the only certificate directory the proxy mounts (D9).
pub fn tls_dir(paths: &DevPaths) -> PathBuf {
    paths.state.join("tls")
}

/// The names a project's leaf covers; routes use the same rule for hosts.
pub fn project_sans(project: &str) -> Vec<String> {
    vec![
        format!("*.{project}.localhost"),
        format!("{project}.localhost"),
    ]
}

/// Ensures `<state>/tls/<project>/` holds a current leaf signed by `ca`.
pub fn ensure_project_cert(
    paths: &DevPaths,
    ca: &Ca,
    project: &str,
) -> Result<CertPaths, DevError> {
    ensure_project_cert_at(paths, ca, project, OffsetDateTime::now_utc())
}

const LEAF_CERT: &str = "cert.pem";
const LEAF_KEY: &str = "key.pem";
const LEAF_META: &str = "meta.json";

#[derive(Debug, Serialize, Deserialize)]
struct LeafMeta {
    sans: Vec<String>,
    ca_key: String,
    not_after: i64,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A leaf is reissued (with a new key every time, F14) when a file is missing,
/// `meta.json` does not match, or fewer than `RENEW_BEFORE_DAYS` remain.
pub(crate) fn ensure_project_cert_at(
    paths: &DevPaths,
    ca: &Ca,
    project: &str,
    now: OffsetDateTime,
) -> Result<CertPaths, DevError> {
    crate::project::check_name(project)?;
    let dir = tls_dir(paths).join(project);
    let out = CertPaths {
        cert: dir.join(LEAF_CERT),
        key: dir.join(LEAF_KEY),
    };
    let (issuer, ca_key) = ca_issuer(ca)?;
    let ca_key = hex(&ca_key);
    let sans = project_sans(project);
    let meta_path = dir.join(LEAF_META);
    let current = fs::read_to_string(&meta_path)
        .ok()
        .and_then(|t| serde_json::from_str::<LeafMeta>(&t).ok())
        .is_some_and(|m| {
            m.sans == sans
                && m.ca_key == ca_key
                && m.not_after - now.unix_timestamp() >= RENEW_BEFORE_DAYS * 86_400
        });
    if current && out.cert.is_file() && out.key.is_file() {
        return Ok(out);
    }

    create_private_dir(&dir, true).or_else(|e| {
        if dir.is_dir() {
            Ok(())
        } else {
            Err(io_err(&dir)(e))
        }
    })?;
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, format!("{project}.localhost"));
    params.distinguished_name = dn;
    params.subject_alt_names = sans
        .iter()
        .map(|s| {
            s.as_str()
                .try_into()
                .map(SanType::DnsName)
                .map_err(cert_err)
        })
        .collect::<Result<_, _>>()?;
    params.is_ca = IsCa::NoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.use_authority_key_identifier_extension = true;
    params.not_before = now - Duration::hours(1);
    params.not_after = now + Duration::days(LEAF_DAYS);
    let key = KeyPair::generate().map_err(cert_err)?;
    let cert = params.signed_by(&key, &issuer).map_err(cert_err)?;
    let meta = LeafMeta {
        sans,
        ca_key,
        not_after: params.not_after.unix_timestamp(),
    };
    let meta = serde_json::to_vec(&meta).map_err(|e| DevError::Cert(e.to_string()))?;
    // meta.json is written last: it is the commit marker the fast path trusts.
    match fs::remove_file(&meta_path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_err(&meta_path)(e)),
    }
    write_atomic(&out.key, key.serialize_pem().as_bytes(), true)?;
    write_atomic(&out.cert, cert.pem().as_bytes(), false)?;
    write_atomic(&meta_path, &meta, false)?;
    Ok(out)
}

/// Removes a project's certificate directory. Idempotent.
pub fn remove_project_cert(paths: &DevPaths, project: &str) -> Result<(), DevError> {
    crate::project::check_name(project)?;
    let dir = tls_dir(paths).join(project);
    match fs::remove_dir_all(&dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_err(&dir)(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, KeyPair, SanType};
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use std::sync::Arc;
    use time::Duration;

    fn dev_paths(tmp: &Path) -> DevPaths {
        DevPaths {
            state: tmp.join("state"),
            config: tmp.join("config"),
        }
    }

    /// A leaf for `name`, signed through `ca_issuer`.
    fn leaf_for(ca: &Ca, name: &str) -> CertificateDer<'static> {
        let (issuer, _) = ca_issuer(ca).unwrap();
        let mut params = CertificateParams::new(vec![name.to_string()]).unwrap();
        params.distinguished_name = DistinguishedName::new();
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::hours(1);
        params.not_after = now + Duration::days(1);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key = KeyPair::generate().unwrap();
        params.signed_by(&key, &issuer).unwrap().der().clone()
    }

    fn verify(ca_pem: &str, leaf: &CertificateDer<'_>, name: &str) -> Result<(), rustls::Error> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(ca_pem.as_bytes()).unwrap())
            .unwrap();
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap();
        verifier
            .verify_server_cert(
                leaf,
                &[],
                &ServerName::try_from(name.to_string()).unwrap(),
                &[],
                UnixTime::now(),
            )
            .map(|_| ())
    }

    #[test]
    fn first_call_creates_ca_files() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = dev_paths(tmp.path());
        let ca = ensure_ca(&paths).unwrap();
        let dir = paths.ca_dir();
        assert_eq!(ca.cert_path, dir.join("ca.pem"));
        assert_eq!(ca.key_path, dir.join("ca-key.pem"));
        assert!(dir.join("ca.json").is_file());
        assert!(ca.key_path.is_file());
        assert_eq!(ca.cert_pem, fs::read_to_string(&ca.cert_path).unwrap());
        let meta: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(dir.join("ca.json")).unwrap()).unwrap();
        let created = meta["created"].as_i64().unwrap();
        let not_after = meta["not_after"].as_i64().unwrap();
        assert_eq!(not_after - created, CA_DAYS * 86_400);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&ca.key_path), 0o600);
            assert_eq!(mode(&dir), 0o700);
        }
    }

    #[test]
    fn second_call_reuses_ca() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = dev_paths(tmp.path());
        let a = ensure_ca(&paths).unwrap();
        let b = ensure_ca(&paths).unwrap();
        assert_eq!(a.cert_pem, b.cert_pem);
    }

    #[test]
    fn ca_is_name_constrained_to_localhost() {
        let tmp = tempfile::tempdir().unwrap();
        let ca = ensure_ca(&dev_paths(tmp.path())).unwrap();

        let good = leaf_for(&ca, "web.shop.localhost");
        verify(&ca.cert_pem, &good, "web.shop.localhost").unwrap();

        let evil = leaf_for(&ca, "evil.example");
        let err = verify(&ca.cert_pem, &evil, "evil.example").unwrap_err();
        assert!(
            format!("{err:?}").contains("NameConstraintViolation"),
            "{err:?}"
        );
    }

    /// A leaf with exactly `sans`, signed through `ca_issuer`.
    fn leaf_with(ca: &Ca, sans: Vec<SanType>) -> CertificateDer<'static> {
        let (issuer, _) = ca_issuer(ca).unwrap();
        let mut params = CertificateParams::default();
        params.subject_alt_names = sans;
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::hours(1);
        params.not_after = now + Duration::days(1);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key = KeyPair::generate().unwrap();
        params.signed_by(&key, &issuer).unwrap().der().clone()
    }

    fn dns(s: &str) -> SanType {
        SanType::DnsName(s.try_into().unwrap())
    }

    fn ip(s: &str) -> SanType {
        SanType::IpAddress(s.parse().unwrap())
    }

    fn assert_constraint_violation(r: Result<(), rustls::Error>) {
        let err = r.unwrap_err();
        assert!(
            format!("{err:?}").contains("NameConstraintViolation"),
            "{err:?}"
        );
    }

    #[test]
    fn ip_sans_are_excluded() {
        let tmp = tempfile::tempdir().unwrap();
        let ca = ensure_ca(&dev_paths(tmp.path())).unwrap();

        let v4 = leaf_with(&ca, vec![ip("10.0.0.1"), ip("::1")]);
        assert_constraint_violation(verify(&ca.cert_pem, &v4, "10.0.0.1"));

        let v6 = leaf_with(&ca, vec![ip("::1")]);
        assert_constraint_violation(verify(&ca.cert_pem, &v6, "::1"));

        // An IP next to a good DNS name still taints the whole leaf.
        let mixed = leaf_with(&ca, vec![dns("web.shop.localhost"), ip("127.0.0.1")]);
        assert_constraint_violation(verify(&ca.cert_pem, &mixed, "web.shop.localhost"));

        let good = leaf_with(&ca, vec![dns("web.shop.localhost"), dns("shop.localhost")]);
        verify(&ca.cert_pem, &good, "web.shop.localhost").unwrap();
        verify(&ca.cert_pem, &good, "shop.localhost").unwrap();
    }

    #[test]
    fn email_sans_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let ca = ensure_ca(&dev_paths(tmp.path())).unwrap();
        for mail in ["a@evil.example", "a@shop.localhost"] {
            let leaf = leaf_with(
                &ca,
                vec![
                    dns("web.shop.localhost"),
                    SanType::Rfc822Name(mail.try_into().unwrap()),
                ],
            );
            assert_constraint_violation(verify(&ca.cert_pem, &leaf, "web.shop.localhost"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_ca_dir_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let elsewhere = dev_paths(&tmp.path().join("other"));
        ensure_ca(&elsewhere).unwrap();
        let paths = dev_paths(tmp.path());
        fs::create_dir_all(&paths.state).unwrap();
        std::os::unix::fs::symlink(elsewhere.ca_dir(), paths.ca_dir()).unwrap();
        match ensure_ca(&paths) {
            Err(DevError::CaInvalid { path, .. }) => assert_eq!(path, paths.ca_dir()),
            other => panic!("expected CaInvalid, got {other:?}"),
        }
    }

    #[test]
    fn reloaded_issuer_matches_stored_ca() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = dev_paths(tmp.path());
        let first = ensure_ca(&paths).unwrap();
        let again = ensure_ca(&paths).unwrap();
        let leaf = leaf_for(&again, "api.shop.localhost");
        let on_disk = fs::read_to_string(&first.cert_path).unwrap();
        verify(&on_disk, &leaf, "api.shop.localhost").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn loose_key_mode_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let paths = dev_paths(tmp.path());
        let ca = ensure_ca(&paths).unwrap();
        fs::set_permissions(&ca.key_path, fs::Permissions::from_mode(0o644)).unwrap();
        match ensure_ca(&paths) {
            Err(DevError::CaInvalid { path, .. }) => assert_eq!(path, ca.key_path),
            other => panic!("expected CaInvalid, got {other:?}"),
        }
    }

    #[test]
    fn partial_ca_dir_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = dev_paths(tmp.path());
        let ca = ensure_ca(&paths).unwrap();
        fs::remove_file(&ca.key_path).unwrap();
        let err = ensure_ca(&paths).unwrap_err();
        assert!(matches!(err, DevError::CaInvalid { .. }), "{err:?}");
        assert!(err.to_string().contains("delete"), "{err}");
        assert_eq!(fs::read_to_string(&ca.cert_path).unwrap(), ca.cert_pem);
        assert!(!ca.key_path.exists());
    }

    #[test]
    fn expiring_ca_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = dev_paths(tmp.path());
        let now = OffsetDateTime::now_utc();
        ensure_ca_at(&paths, now).unwrap();
        ensure_ca_at(&paths, now + Duration::days(CA_DAYS - 31)).unwrap();
        match ensure_ca_at(&paths, now + Duration::days(CA_DAYS - 29)) {
            Err(DevError::CaInvalid { reason, .. }) => {
                assert!(reason.contains("expires"), "{reason}")
            }
            other => panic!("expected CaInvalid, got {other:?}"),
        }
    }

    #[test]
    fn concurrent_ensure_ca_yields_one_ca() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = dev_paths(tmp.path());
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let p = paths.clone();
                std::thread::spawn(move || ensure_ca(&p).unwrap().cert_pem)
            })
            .collect();
        let pems: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(pems.iter().all(|p| p == &pems[0]));
        let leftovers: Vec<_> = fs::read_dir(&paths.state)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".ca.tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    fn verify_at(
        ca_pem: &str,
        leaf_pem: &str,
        name: &str,
        at: OffsetDateTime,
    ) -> Result<(), rustls::Error> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(ca_pem.as_bytes()).unwrap())
            .unwrap();
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap();
        let leaf = CertificateDer::from_pem_slice(leaf_pem.as_bytes()).unwrap();
        verifier
            .verify_server_cert(
                &leaf,
                &[],
                &ServerName::try_from(name.to_string()).unwrap(),
                &[],
                UnixTime::since_unix_epoch(std::time::Duration::from_secs(
                    at.unix_timestamp() as u64
                )),
            )
            .map(|_| ())
    }

    fn setup() -> (tempfile::TempDir, DevPaths, Ca) {
        let tmp = tempfile::tempdir().unwrap();
        let paths = dev_paths(tmp.path());
        let ca = ensure_ca(&paths).unwrap();
        (tmp, paths, ca)
    }

    #[test]
    fn leaf_verifies_for_project_hosts() {
        let (_t, paths, ca) = setup();
        let now = OffsetDateTime::now_utc();
        let c = ensure_project_cert_at(&paths, &ca, "shop", now).unwrap();
        assert_eq!(c.cert, tls_dir(&paths).join("shop").join("cert.pem"));
        assert_eq!(c.key, tls_dir(&paths).join("shop").join("key.pem"));
        let pem = fs::read_to_string(&c.cert).unwrap();
        verify_at(&ca.cert_pem, &pem, "web.shop.localhost", now).unwrap();
        verify_at(&ca.cert_pem, &pem, "shop.localhost", now).unwrap();
    }

    #[test]
    fn leaf_rejects_other_hosts() {
        let (_t, paths, ca) = setup();
        let now = OffsetDateTime::now_utc();
        let c = ensure_project_cert_at(&paths, &ca, "shop", now).unwrap();
        let pem = fs::read_to_string(&c.cert).unwrap();
        assert!(verify_at(&ca.cert_pem, &pem, "a.web.shop.localhost", now).is_err());
        assert!(verify_at(&ca.cert_pem, &pem, "web.other.localhost", now).is_err());
    }

    #[test]
    fn leaf_lifetime_is_365_days() {
        let (_t, paths, ca) = setup();
        let now = OffsetDateTime::now_utc();
        let c = ensure_project_cert_at(&paths, &ca, "shop", now).unwrap();
        let pem = fs::read_to_string(&c.cert).unwrap();
        let at = |d| now + Duration::days(d);
        verify_at(&ca.cert_pem, &pem, "shop.localhost", at(364)).unwrap();
        assert!(verify_at(&ca.cert_pem, &pem, "shop.localhost", at(366)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn leaf_key_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let (_t, paths, ca) = setup();
        let c = ensure_project_cert(&paths, &ca, "shop").unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&c.key), 0o600);
        assert_eq!(mode(&tls_dir(&paths)), 0o700);
        assert_eq!(mode(&tls_dir(&paths).join("shop")), 0o700);
    }

    #[test]
    fn crash_mid_reissue_is_repaired() {
        let (_t, paths, ca) = setup();
        let c = ensure_project_cert(&paths, &ca, "shop").unwrap();
        let dir = tls_dir(&paths).join("shop");
        fs::remove_file(&c.key).unwrap();
        fs::remove_file(&c.cert).unwrap();
        fs::create_dir(&c.cert).unwrap();
        assert!(ensure_project_cert(&paths, &ca, "shop").is_err());
        assert!(!dir.join("meta.json").exists());
        fs::remove_dir(&c.cert).unwrap();
        ensure_project_cert(&paths, &ca, "shop").unwrap();
        let key = KeyPair::from_pem(&fs::read_to_string(&c.key).unwrap()).unwrap();
        let cert = CertificateDer::from_pem_slice(fs::read(&c.cert).unwrap().as_slice()).unwrap();
        let spki = rcgen::PublicKeyData::subject_public_key_info(&key);
        assert!(cert.windows(spki.len()).any(|w| w == spki.as_slice()));
    }

    #[test]
    fn unchanged_leaf_is_reused() {
        let (_t, paths, ca) = setup();
        let a = ensure_project_cert(&paths, &ca, "shop").unwrap();
        let first = fs::read(&a.cert).unwrap();
        let b = ensure_project_cert(&paths, &ca, "shop").unwrap();
        assert_eq!(a, b);
        assert_eq!(first, fs::read(&b.cert).unwrap());
    }

    #[test]
    fn leaf_is_reissued() {
        let now = OffsetDateTime::now_utc();
        type Mutate = Box<dyn Fn(&DevPaths, &Ca) -> OffsetDateTime>;
        let cases: [(&str, Mutate); 3] = [
            (
                "near expiry",
                Box::new(move |_, _| now + Duration::days(336)),
            ),
            (
                "other ca_key",
                Box::new(move |paths, _| {
                    let p = tls_dir(paths).join("shop").join("meta.json");
                    let mut m: serde_json::Value =
                        serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
                    m["ca_key"] = "00".into();
                    fs::write(&p, serde_json::to_vec(&m).unwrap()).unwrap();
                    now
                }),
            ),
            (
                "key deleted",
                Box::new(move |paths, _| {
                    fs::remove_file(tls_dir(paths).join("shop").join("key.pem")).unwrap();
                    now
                }),
            ),
        ];
        for (name, mutate) in cases {
            let (_t, paths, ca) = setup();
            let a = ensure_project_cert_at(&paths, &ca, "shop", now).unwrap();
            let cert1 = fs::read(&a.cert).unwrap();
            let key1 = fs::read(&a.key).ok();
            let at = mutate(&paths, &ca);
            let b = ensure_project_cert_at(&paths, &ca, "shop", at).unwrap();
            assert_ne!(cert1, fs::read(&b.cert).unwrap(), "{name}: cert");
            assert_ne!(key1, fs::read(&b.key).ok(), "{name}: key");
        }
    }

    #[test]
    fn bad_project_name_is_refused() {
        let (_t, paths, ca) = setup();
        for bad in ["Shop", "a/b", ""] {
            assert!(
                matches!(
                    ensure_project_cert(&paths, &ca, bad),
                    Err(DevError::BadProjectName(_))
                ),
                "{bad:?}"
            );
            assert!(remove_project_cert(&paths, bad).is_err());
        }
        assert!(!tls_dir(&paths).exists());
    }

    #[test]
    fn remove_project_cert_is_idempotent() {
        let (_t, paths, ca) = setup();
        let c = ensure_project_cert(&paths, &ca, "shop").unwrap();
        ensure_project_cert(&paths, &ca, "other").unwrap();
        remove_project_cert(&paths, "shop").unwrap();
        remove_project_cert(&paths, "shop").unwrap();
        assert!(!c.cert.exists());
        assert!(tls_dir(&paths).join("other").join("cert.pem").exists());
    }

    #[test]
    fn write_atomic_replaces_and_leaves_no_temp() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("a.toml");
        write_atomic(&target, b"one", false).unwrap();
        write_atomic(&target, b"two", true).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"two");
        let names: Vec<_> = fs::read_dir(tmp.path()).unwrap().collect();
        assert_eq!(names.len(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
