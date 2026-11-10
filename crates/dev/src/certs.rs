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
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType, GeneralSubtree,
    IsCa, Issuer, KeyPair, KeyUsagePurpose, NameConstraints,
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

fn create_private_dir(dir: &Path, recursive: bool) -> io::Result<()> {
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
// Plan 23 Task 2 (`ensure_project_cert`) is the first caller outside the tests.
#[cfg_attr(not(test), allow(dead_code))]
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
