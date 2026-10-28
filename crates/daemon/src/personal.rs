//! Personal broker helpers (`saiife daemon --user`, plan 16).
//!
//! - The vault key lives in the user's keychain ([`VAULT_KEY`]), the secrets
//!   stay in `vault.bin` under it (decision 1). [`vault_key`] follows the
//!   key lifecycle of decision 11 and never re-keys an existing vault.
//! - [`ensure_config`] writes a minimal config when there is none.
//! - [`apply`] fixes the paths and synthesizes the `personal` scope
//!   (decision 5).
//! - [`admits`] is the same-uid peer check (decision 3).
//!
//! Personal broker mode is not a security boundary: any process of the same
//! user can read the key on Linux.

use crate::vault::{self, VaultState};
use saiife_keychain::{Keychain, VAULT_KEY, VAULT_KEY_LABEL};
use saiife_policy::{AdminCfg, DaemonCfg, Scope, SystemConfig};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// The config `saiife daemon --user` writes when there is none.
pub const PERSONAL_CONFIG: &str = "\
# saiife personal broker: not a security boundary (docs/personal-broker.md).
# saiife connect <service> writes policy.d/<service>.toml.
version = 2
";

/// The personal broker's own user and its fixed paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonalCfg {
    pub own_user: String,
    pub own_uid: u32,
    pub socket_dir: PathBuf,
    pub audit_dir: PathBuf,
}

/// The 32-byte vault key. Its `Debug` never shows the bytes.
pub struct VaultKey(Zeroizing<[u8; 32]>);

impl VaultKey {
    pub fn into_inner(self) -> Zeroizing<[u8; 32]> {
        self.0
    }
}

impl fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultKey(<redacted>)")
    }
}

/// The vault key from the keychain (decision 11):
/// - a stored key is used;
/// - neither a key nor `vault_file`: a new random key is created and stored;
/// - no key but a `vault_file` (or one that cannot be checked): an error,
///   never a new key, so the old vault stays as it is;
/// - a locked or unavailable keychain: an error, never "no key".
pub fn vault_key(kc: &dyn Keychain, vault_file: &Path) -> Result<VaultKey, String> {
    // Only the error's Display goes out; it never carries secret bytes.
    match kc.get(&VAULT_KEY) {
        Err(e) => Err(e.to_string()),
        Ok(Some(stored)) => {
            if stored.len() != 32 {
                return Err("the keychain's vault key is not 32 bytes".into());
            }
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&stored);
            Ok(VaultKey(key))
        }
        Ok(None) => {
            // Never re-key: a vault sealed under a lost key stays as it is.
            // A dangling symlink or an unreadable dir counts as present.
            match std::fs::symlink_metadata(vault_file) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                _ => {
                    return Err(format!(
                        "the vault key is missing from the keychain; {} was kept",
                        vault_file.display()
                    ))
                }
            }
            let mut key = Zeroizing::new([0u8; 32]);
            getrandom::fill(&mut key[..]).map_err(|e| format!("cannot make a vault key: {e}"))?;
            kc.set(&VAULT_KEY, VAULT_KEY_LABEL, &key[..])
                .map_err(|e| e.to_string())?;
            Ok(VaultKey(key))
        }
    }
}

/// The vault behind the keychain's key; any failure is `Unavailable(reason)`.
pub fn open_vault(kc: &dyn Keychain, vault_file: &Path) -> VaultState {
    match vault_key(kc, vault_file) {
        Ok(k) => vault::open_with_key(k.into_inner(), vault_file),
        Err(r) => VaultState::Unavailable(r),
    }
}

/// Write [`PERSONAL_CONFIG`] (0600, in a 0700 dir) when `path` is missing.
/// An existing file is never touched. `true` when the file was created.
pub fn ensure_config(path: &Path) -> io::Result<bool> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    if let Some(dir) = path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    // `create_new` never follows or replaces anything already there.
    let mut f = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
        Err(e) => return Err(e),
    };
    f.write_all(PERSONAL_CONFIG.as_bytes())?;
    f.sync_all()?;
    Ok(true)
}

/// Fit a loaded config to personal mode (decision 5) and return the
/// warnings. `raw` is the config file as written, to tell which sections
/// the user set.
pub fn apply(cfg: &mut SystemConfig, raw: &toml::Table, p: &PersonalCfg) -> Vec<String> {
    let mut warnings = Vec::new();
    if raw.contains_key("daemon") {
        warnings.push(format!(
            "personal broker: [daemon] is ignored; the sockets are in {}",
            p.socket_dir.display()
        ));
    }
    if raw.contains_key("admin") {
        warnings.push("personal broker: [admin] is ignored; your own user is the admin".into());
    }
    if raw
        .get("audit")
        .and_then(toml::Value::as_table)
        .is_some_and(|a| a.contains_key("dir"))
    {
        warnings.push(format!(
            "personal broker: [audit] dir is ignored; the audit dir is {}",
            p.audit_dir.display()
        ));
    }
    cfg.daemon = DaemonCfg {
        user: p.own_user.clone(),
        socket_dir: p.socket_dir.clone(),
    };
    cfg.admin = AdminCfg::default();
    cfg.audit.dir = p.audit_dir.clone();
    if cfg.scope.is_empty() {
        cfg.scope.push(Scope {
            name: "personal".to_string(),
            users: vec![p.own_user.clone()],
            projects: Vec::new(),
            services: cfg.services.keys().cloned().collect(),
            env: None,
        });
    } else if !cfg.scope.iter().any(|s| s.users.contains(&p.own_user)) {
        warnings.push(format!(
            "personal broker: no [[scope]] names your user {}; connector calls will find no scope",
            p.own_user
        ));
    }
    warnings
}

/// The personal broker talks to its own uid only; root is refused too.
pub fn admits(own_uid: u32, peer_uid: u32) -> bool {
    peer_uid == own_uid
}

#[cfg(test)]
mod tests {
    use super::*;
    use saiife_keychain::{FakeKeychain, KeychainError};
    use std::os::unix::fs::PermissionsExt;

    const KEY: [u8; 32] = *b"0123456789abcdef0123456789ABCDEF";

    fn file(t: &tempfile::TempDir) -> PathBuf {
        t.path().join("vault").join("vault.bin")
    }

    fn reason(s: VaultState) -> String {
        match s {
            VaultState::Ready(_) => panic!("ready"),
            VaultState::Unavailable(r) => r,
        }
    }

    #[test]
    fn fresh_key_created_once() {
        let t = tempfile::tempdir().unwrap();
        let kc = FakeKeychain::new();
        let a = vault_key(&kc, &file(&t)).unwrap().into_inner();
        assert_eq!(kc.calls(), vec!["get", "set"]);
        assert_ne!(*a, [0u8; 32]);
        let b = vault_key(&kc, &file(&t)).unwrap().into_inner();
        assert_eq!(kc.calls(), vec!["get", "set", "get"]);
        assert_eq!(*a, *b);
        assert_eq!(
            kc.get(&VAULT_KEY).unwrap().unwrap().as_slice(),
            a.as_slice()
        );
    }

    #[test]
    fn existing_key_used() {
        let t = tempfile::tempdir().unwrap();
        let kc = FakeKeychain::new();
        kc.set(&VAULT_KEY, VAULT_KEY_LABEL, &KEY).unwrap();
        let k = vault_key(&kc, &file(&t)).unwrap();
        assert_eq!(format!("{k:?}"), "VaultKey(<redacted>)");
        assert_eq!(*k.into_inner(), KEY);
        assert_eq!(kc.calls(), vec!["set", "get"]);
        // A vault sealed under that key opens through the keychain.
        let mut v = match open_vault(&kc, &file(&t)) {
            VaultState::Ready(v) => v,
            VaultState::Unavailable(r) => panic!("unavailable: {r}"),
        };
        let mut fields = std::collections::BTreeMap::new();
        fields.insert("token".to_string(), Zeroizing::new("x".to_string()));
        v.put(vault::Entry {
            name: "gh".into(),
            kind: vault::Kind::Token,
            fields,
            allowed_services: vec![],
            created_by: 1000,
            created: "2026-10-28T10:00:00Z".into(),
            last_used: None,
            rotate_after: None,
        })
        .unwrap();
        drop(v);
        match vault::open_with_key(Zeroizing::new(KEY), &file(&t)) {
            VaultState::Ready(v) => assert!(v.get("gh").is_some()),
            VaultState::Unavailable(r) => panic!("unavailable: {r}"),
        }
    }

    #[test]
    fn missing_key_with_existing_vault_never_rekeys() {
        let t = tempfile::tempdir().unwrap();
        let f = file(&t);
        std::fs::create_dir(f.parent().unwrap()).unwrap();
        std::fs::set_permissions(f.parent().unwrap(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let bytes = b"SAIIFEVL old vault bytes that must survive".to_vec();
        std::fs::write(&f, &bytes).unwrap();
        let kc = FakeKeychain::new();
        let want = format!(
            "the vault key is missing from the keychain; {} was kept",
            f.display()
        );
        assert_eq!(vault_key(&kc, &f).unwrap_err(), want);
        let r = reason(open_vault(&kc, &f));
        assert_eq!(r, want);
        assert!(r.contains(&f.display().to_string()));
        assert!(!kc.calls().contains(&"set"), "{:?}", kc.calls());
        assert!(kc.get(&VAULT_KEY).unwrap().is_none());
        assert_eq!(std::fs::read(&f).unwrap(), bytes);
        // A dangling symlink still counts as a vault: never re-key over it.
        std::fs::remove_file(&f).unwrap();
        std::os::unix::fs::symlink(t.path().join("nowhere"), &f).unwrap();
        assert!(vault_key(&kc, &f).is_err());
        assert!(!kc.calls().contains(&"set"));
    }

    #[test]
    fn locked_keychain_is_unavailable_with_reason() {
        let t = tempfile::tempdir().unwrap();
        let kc = FakeKeychain::new();
        kc.set_locked(true);
        let r = reason(open_vault(&kc, &file(&t)));
        assert_eq!(r, "keychain locked: the fake keychain is locked");
        assert!(!kc.calls().contains(&"set"));
        kc.set_locked(false);
        for e in [
            KeychainError::Unavailable("no session bus".into()),
            KeychainError::Other("boom".into()),
        ] {
            kc.fail_next(e.clone());
            assert_eq!(reason(open_vault(&kc, &file(&t))), e.to_string());
        }
        assert!(!kc.calls().contains(&"set"));
        // A failed store of a fresh key is an error too, not a key in memory
        // only.
        let kc = FakeKeychain::new();
        let kc2 = FailSet(kc);
        let e = vault_key(&kc2, &file(&t)).unwrap_err();
        assert_eq!(e, "keychain locked: dismissed");
    }

    /// Gets work, sets fail as locked.
    struct FailSet(FakeKeychain);
    impl Keychain for FailSet {
        fn get(
            &self,
            id: &saiife_keychain::ItemId,
        ) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
            self.0.get(id)
        }
        fn set(&self, _: &saiife_keychain::ItemId, _: &str, _: &[u8]) -> Result<(), KeychainError> {
            Err(KeychainError::Locked("dismissed".into()))
        }
        fn delete(&self, id: &saiife_keychain::ItemId) -> Result<bool, KeychainError> {
            self.0.delete(id)
        }
        fn backend(&self) -> &'static str {
            "failset"
        }
    }

    #[test]
    fn short_key_refused() {
        let t = tempfile::tempdir().unwrap();
        for bad in [&KEY[..31], &[KEY.as_slice(), b"x"].concat()[..], &[][..]] {
            let kc = FakeKeychain::new();
            kc.set(&VAULT_KEY, VAULT_KEY_LABEL, bad).unwrap();
            let e = vault_key(&kc, &file(&t)).unwrap_err();
            assert_eq!(e, "the keychain's vault key is not 32 bytes");
            let r = reason(open_vault(&kc, &file(&t)));
            assert_eq!(r, e);
            // Never replaced by a new key.
            assert_eq!(kc.calls(), vec!["set", "get", "get"]);
            assert_eq!(kc.get(&VAULT_KEY).unwrap().unwrap().as_slice(), bad);
        }
    }

    #[test]
    fn key_bytes_never_in_output() {
        let t = tempfile::tempdir().unwrap();
        let kc = FakeKeychain::new();
        kc.set(&VAULT_KEY, VAULT_KEY_LABEL, &KEY).unwrap();
        let ok = vault_key(&kc, &file(&t));
        let short = FakeKeychain::new();
        short.set(&VAULT_KEY, VAULT_KEY_LABEL, &KEY[..31]).unwrap();
        let err = vault_key(&short, &file(&t));
        let as_list = format!("{:?}", &KEY[..8]);
        let as_list = &as_list[1..as_list.len() - 1];
        for s in [
            format!("{ok:?}"),
            format!("{err:?}"),
            format!("{:?}", err.as_ref().err()),
        ] {
            assert!(!s.contains("0123456789"), "{s}");
            assert!(!s.contains(as_list), "{s}");
        }
        assert_eq!(format!("{ok:?}"), "Ok(VaultKey(<redacted>))");
    }

    #[test]
    fn ensure_config_creates_0600_never_overwrites() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("saiife").join("broker").join("config.toml");
        assert!(ensure_config(&p).unwrap());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), PERSONAL_CONFIG);
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(&p), 0o600);
        assert_eq!(mode(p.parent().unwrap()), 0o700);
        let cfg: SystemConfig = toml::from_str(PERSONAL_CONFIG).unwrap();
        assert_eq!(cfg.version, 2);
        assert!(!cfg.locked);
        assert!(PERSONAL_CONFIG.contains(
            "# saiife personal broker: not a security boundary (docs/personal-broker.md)."
        ));
        assert!(
            PERSONAL_CONFIG.contains("# saiife connect <service> writes policy.d/<service>.toml.")
        );
        std::fs::write(&p, "version = 2\n# mine\n").unwrap();
        assert!(!ensure_config(&p).unwrap());
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            "version = 2\n# mine\n"
        );
    }

    fn pcfg() -> PersonalCfg {
        PersonalCfg {
            own_user: "alice".into(),
            own_uid: 1000,
            socket_dir: PathBuf::from("/run/user/1000/saiife"),
            audit_dir: PathBuf::from("/home/alice/.local/share/saiife/broker/audit"),
        }
    }

    fn parse(text: &str) -> (SystemConfig, toml::Table) {
        let raw: toml::Table = text.parse().unwrap();
        (toml::from_str(text).unwrap(), raw)
    }

    const SERVICES: &str = r#"
[services.github]
connector = "github"
secret = "gh"

[services.mail]
connector = "smtp"
secret = "mail"
"#;

    #[test]
    fn apply_synthesizes_personal_scope() {
        let (mut cfg, raw) = parse(&format!("version = 2\n{SERVICES}"));
        let w = apply(&mut cfg, &raw, &pcfg());
        assert!(w.is_empty(), "{w:?}");
        assert_eq!(
            cfg.scope,
            vec![Scope {
                name: "personal".into(),
                users: vec!["alice".into()],
                projects: vec![],
                services: vec!["github".into(), "mail".into()],
                env: None,
            }]
        );
        let (mut cfg, raw) = parse("version = 2\n");
        apply(&mut cfg, &raw, &pcfg());
        assert_eq!(cfg.scope.len(), 1);
        assert!(cfg.scope[0].services.is_empty());
    }

    #[test]
    fn apply_keeps_given_scopes_and_warns_without_own_user() {
        let text = format!(
            "version = 2\n{SERVICES}\n[[scope]]\nname = \"work\"\nusers = [\"bob\"]\nservices = [\"github\"]\n"
        );
        let (mut cfg, raw) = parse(&text);
        let before = cfg.scope.clone();
        let w = apply(&mut cfg, &raw, &pcfg());
        assert_eq!(cfg.scope, before);
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("alice"), "{w:?}");
        let text = format!(
            "version = 2\n{SERVICES}\n[[scope]]\nname = \"work\"\nusers = [\"alice\"]\nservices = [\"github\"]\n"
        );
        let (mut cfg, raw) = parse(&text);
        let before = cfg.scope.clone();
        assert!(apply(&mut cfg, &raw, &pcfg()).is_empty());
        assert_eq!(cfg.scope, before);
    }

    #[test]
    fn apply_overrides_paths_and_warns_on_daemon_admin_audit_dir() {
        let (mut cfg, raw) = parse("version = 2\n");
        assert!(apply(&mut cfg, &raw, &pcfg()).is_empty());
        assert_eq!(cfg.daemon.socket_dir, pcfg().socket_dir);
        assert_eq!(cfg.audit.dir, pcfg().audit_dir);

        let (mut cfg, raw) = parse(
            "version = 2\n[daemon]\nsocket_dir = \"/srv/x\"\n[admin]\ngroups = [\"wheel\"]\n[audit]\ndir = \"/srv/audit\"\nretention_months = 3\n",
        );
        let w = apply(&mut cfg, &raw, &pcfg());
        assert_eq!(w.len(), 3, "{w:?}");
        assert!(w[0].contains("[daemon]"), "{w:?}");
        assert!(w[1].contains("[admin]"), "{w:?}");
        assert!(w[2].contains("[audit] dir"), "{w:?}");
        assert_eq!(cfg.daemon.socket_dir, pcfg().socket_dir);
        assert_eq!(cfg.audit.dir, pcfg().audit_dir);
        assert!(cfg.admin.groups.is_empty());
        // Other [audit] keys are kept, and alone they warn about nothing.
        assert_eq!(cfg.audit.retention_months, 3);
        let (mut cfg, raw) = parse("version = 2\n[audit]\nretention_months = 3\n");
        assert!(apply(&mut cfg, &raw, &pcfg()).is_empty());
        assert_eq!(cfg.audit.retention_months, 3);
    }

    #[test]
    fn admits_same_uid_only() {
        assert!(admits(1000, 1000));
        assert!(!admits(1000, 1001));
        assert!(!admits(1000, 0));
        assert!(!admits(1000, u32::MAX));
        assert!(!admits(0, 1000));
    }
}
