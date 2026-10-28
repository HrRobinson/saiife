//! The keychain trait, the fake and the debug-only dir seam.

use saiife_keychain::{FakeKeychain, ItemId, Keychain, KeychainError, VAULT_KEY, VAULT_KEY_LABEL};

const OTHER: ItemId = ItemId {
    service: "saiife",
    account: "other",
};

/// Our euid, as the owner of a dir we just created.
#[cfg(all(debug_assertions, unix))]
fn own_uid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    let t = tempfile::tempdir().unwrap();
    std::fs::metadata(t.path()).unwrap().uid()
}

#[test]
fn fake_roundtrip_get_set_delete() {
    let k = FakeKeychain::new();
    assert_eq!(k.backend(), "fake");
    assert_eq!(k.get(&VAULT_KEY).unwrap(), None);
    k.set(&VAULT_KEY, VAULT_KEY_LABEL, b"one").unwrap();
    assert_eq!(k.get(&VAULT_KEY).unwrap().unwrap().as_slice(), b"one");
    assert_eq!(k.get(&OTHER).unwrap(), None);
    k.set(&VAULT_KEY, VAULT_KEY_LABEL, b"two").unwrap();
    assert_eq!(k.get(&VAULT_KEY).unwrap().unwrap().as_slice(), b"two");
    assert!(k.delete(&VAULT_KEY).unwrap());
    assert!(!k.delete(&VAULT_KEY).unwrap());
    assert_eq!(k.get(&VAULT_KEY).unwrap(), None);
    assert_eq!(
        k.calls(),
        vec!["get", "set", "get", "get", "set", "get", "delete", "delete", "get"]
    );
}

#[test]
fn fake_locked_is_locked_error() {
    let k = FakeKeychain::new();
    k.set(&VAULT_KEY, VAULT_KEY_LABEL, b"key").unwrap();
    k.set_locked(true);
    assert!(matches!(k.get(&VAULT_KEY), Err(KeychainError::Locked(_))));
    assert!(matches!(
        k.set(&VAULT_KEY, VAULT_KEY_LABEL, b"x"),
        Err(KeychainError::Locked(_))
    ));
    assert!(matches!(
        k.delete(&VAULT_KEY),
        Err(KeychainError::Locked(_))
    ));
    k.set_locked(false);
    assert_eq!(k.get(&VAULT_KEY).unwrap().unwrap().as_slice(), b"key");
}

#[test]
fn fake_fail_next_once() {
    let k = FakeKeychain::new();
    k.fail_next(KeychainError::Unavailable("no bus".into()));
    assert_eq!(
        k.get(&VAULT_KEY),
        Err(KeychainError::Unavailable("no bus".into()))
    );
    assert_eq!(k.get(&VAULT_KEY), Ok(None));
    k.fail_next(KeychainError::Other("boom".into()));
    assert_eq!(
        k.set(&VAULT_KEY, VAULT_KEY_LABEL, b"x"),
        Err(KeychainError::Other("boom".into()))
    );
    // The failed set stored nothing.
    assert_eq!(k.get(&VAULT_KEY), Ok(None));
}

#[test]
fn error_display_never_has_secret() {
    let secret: &[u8] = b"s3cr3t-bytes";
    let needle = "s3cr3t";
    let k = FakeKeychain::new();
    k.set(&VAULT_KEY, VAULT_KEY_LABEL, secret).unwrap();
    let mut errs = Vec::new();
    for e in [
        KeychainError::Unavailable("no bus".into()),
        KeychainError::Locked("dismissed".into()),
        KeychainError::Other("boom".into()),
    ] {
        k.fail_next(e);
        errs.push(k.get(&VAULT_KEY).unwrap_err());
        k.fail_next(KeychainError::Other("again".into()));
        errs.push(k.set(&VAULT_KEY, VAULT_KEY_LABEL, secret).unwrap_err());
    }
    k.set_locked(true);
    errs.push(k.get(&VAULT_KEY).unwrap_err());
    errs.push(k.set(&VAULT_KEY, VAULT_KEY_LABEL, secret).unwrap_err());
    k.set_locked(false);
    #[cfg(all(debug_assertions, unix))]
    {
        use std::os::unix::fs::symlink;
        let t = tempfile::tempdir().unwrap();
        let d = saiife_keychain::DirKeychain::new(t.path().join("kc")).unwrap();
        d.set(&VAULT_KEY, VAULT_KEY_LABEL, secret).unwrap();
        let item = t.path().join("kc").join("saiife.vault-key");
        std::fs::rename(&item, t.path().join("real")).unwrap();
        symlink(t.path().join("real"), &item).unwrap();
        errs.push(d.get(&VAULT_KEY).unwrap_err());
        errs.push(d.set(&VAULT_KEY, VAULT_KEY_LABEL, secret).unwrap_err());
        let d_dbg = format!("{d:?}");
        assert!(!d_dbg.contains(needle), "{d_dbg}");

        // A real failing write whose input is the secret: the dir is
        // read-only, so creating the item fails with an io error.
        use std::os::unix::fs::PermissionsExt;
        let ro = t.path().join("ro");
        let r = saiife_keychain::DirKeychain::new(&ro).unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o500)).unwrap();
        let res = r.set(&VAULT_KEY, VAULT_KEY_LABEL, secret);
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Root ignores the mode; only assert where the call really failed.
        if let Err(e) = res {
            let shown = format!("{e} {e:?}");
            assert!(matches!(e, KeychainError::Other(_)), "{shown}");
            assert!(!shown.contains(needle), "{shown}");
            errs.push(e);
        } else {
            assert_eq!(own_uid(), 0, "the write should have failed");
        }
    }
    assert!(errs.len() >= 8);
    for e in &errs {
        let shown = format!("{e} {e:?}");
        assert!(!shown.contains(needle), "{shown}");
    }
    // The fake's own Debug never prints stored bytes either.
    let k_dbg = format!("{k:?}");
    assert!(!k_dbg.contains(needle), "{k_dbg}");
    // Display has a fixed prefix per kind.
    assert_eq!(
        KeychainError::Locked("dismissed".into()).to_string(),
        "keychain locked: dismissed"
    );
    assert_eq!(
        KeychainError::Unavailable("no bus".into()).to_string(),
        "keychain unavailable: no bus"
    );
    assert_eq!(
        KeychainError::Other("boom".into()).to_string(),
        "keychain error: boom"
    );
}

#[cfg(all(debug_assertions, unix))]
mod dir {
    use super::*;
    use saiife_keychain::DirKeychain;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn mode(p: &std::path::Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn dir_keychain_modes_0600_0700() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("kc");
        let k = DirKeychain::new(&dir).unwrap();
        assert_eq!(k.backend(), "dir");
        assert_eq!(mode(&dir), 0o700);
        k.set(&VAULT_KEY, VAULT_KEY_LABEL, b"key-bytes").unwrap();
        let item = dir.join("saiife.vault-key");
        assert_eq!(mode(&item), 0o600);
        assert_eq!(std::fs::read(&item).unwrap(), b"key-bytes");
        assert_eq!(k.get(&VAULT_KEY).unwrap().unwrap().as_slice(), b"key-bytes");
        // An overwrite keeps 0600 and leaves no temp file behind.
        k.set(&VAULT_KEY, VAULT_KEY_LABEL, b"new").unwrap();
        assert_eq!(mode(&item), 0o600);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        assert!(k.delete(&VAULT_KEY).unwrap());
        assert!(!item.exists());

        // An existing empty loose dir of our own is tightened to 0700.
        let loose = t.path().join("loose");
        std::fs::create_dir(&loose).unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).unwrap();
        DirKeychain::new(&loose).unwrap();
        assert_eq!(mode(&loose), 0o700);
    }

    #[test]
    fn dir_keychain_refuses_existing_loose_nonempty_dir() {
        let t = tempfile::tempdir().unwrap();
        // A missing dir with missing parents is created 0700.
        let nested = t.path().join("a").join("kc");
        DirKeychain::new(&nested).unwrap();
        assert_eq!(mode(&nested), 0o700);

        // An existing 0700 dir with items in it is fine and left alone.
        let k = DirKeychain::new(&nested).unwrap();
        k.set(&VAULT_KEY, VAULT_KEY_LABEL, b"k").unwrap();
        DirKeychain::new(&nested).unwrap();
        assert_eq!(mode(&nested), 0o700);

        // An existing non-empty dir that is not 0700 is refused and its mode
        // is not touched.
        let shared = t.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::write(shared.join("someone-elses"), b"x").unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).unwrap();
        let e = DirKeychain::new(&shared).unwrap_err();
        assert!(matches!(e, KeychainError::Unavailable(_)), "{e}");
        assert!(e.to_string().contains("0755"), "{e}");
        assert_eq!(mode(&shared), 0o755);

        // A dir owned by another uid is refused before any chmod. Only
        // testable where such a dir exists and we are not root.
        let root = std::path::Path::new("/");
        if own_uid() != 0 {
            let before = mode(root);
            let e = DirKeychain::new(root).unwrap_err();
            // Usually uid 0; in a user namespace (the offline CI job) it is
            // the overflow uid. Either way: someone else's.
            assert!(e.to_string().contains("is owned by uid "), "{e}");
            assert_eq!(mode(root), before);
        }
    }

    #[test]
    fn dir_keychain_refuses_symlinked_item() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("kc");
        let k = DirKeychain::new(&dir).unwrap();
        let target = t.path().join("elsewhere");
        std::fs::write(&target, b"outside").unwrap();
        let item = dir.join("saiife.vault-key");
        symlink(&target, &item).unwrap();
        assert!(matches!(k.get(&VAULT_KEY), Err(KeychainError::Other(_))));
        assert!(matches!(
            k.set(&VAULT_KEY, VAULT_KEY_LABEL, b"x"),
            Err(KeychainError::Other(_))
        ));
        assert!(matches!(k.delete(&VAULT_KEY), Err(KeychainError::Other(_))));
        // The target is untouched and the link is still there.
        assert_eq!(std::fs::read(&target).unwrap(), b"outside");
        assert!(std::fs::symlink_metadata(&item)
            .unwrap()
            .file_type()
            .is_symlink());

        // A symlinked keychain dir is refused too.
        let real = t.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = t.path().join("link");
        symlink(&real, &link).unwrap();
        assert!(matches!(
            DirKeychain::new(&link),
            Err(KeychainError::Unavailable(_))
        ));
    }

    #[test]
    fn dir_keychain_missing_is_none() {
        let t = tempfile::tempdir().unwrap();
        let k = DirKeychain::new(t.path().join("kc")).unwrap();
        assert_eq!(k.get(&VAULT_KEY).unwrap(), None);
        assert!(!k.delete(&VAULT_KEY).unwrap());
        k.set(&OTHER, "other", b"o").unwrap();
        assert_eq!(k.get(&VAULT_KEY).unwrap(), None);
    }
}
