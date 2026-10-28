//! `from_env` honours `SAIIFE_TEST_KEYCHAIN` in debug builds. Its own test
//! binary, because it sets a process-wide variable.

#[cfg(all(debug_assertions, unix))]
#[test]
fn from_env_selects_dir_keychain() {
    use saiife_keychain::{from_env, VAULT_KEY, VAULT_KEY_LABEL};
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("kc");
    std::env::set_var("SAIIFE_TEST_KEYCHAIN", &dir);
    let k = from_env().unwrap();
    assert_eq!(k.backend(), "dir");
    k.set(&VAULT_KEY, VAULT_KEY_LABEL, b"k").unwrap();
    assert!(dir.join("saiife.vault-key").is_file());
    std::env::remove_var("SAIIFE_TEST_KEYCHAIN");
}
