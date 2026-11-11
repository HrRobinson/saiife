//! `saiife touch`: the key layer (plan 27). `pick` chooses the source of
//! touches: the soft key seam (debug builds only), a FIDO2 key over USB HID
//! (feature `fido-hid`), or none (D1).

// Tasks 2 and 3 of plan 27 call the key layer (and drop this allow); until
// then only its tests use parts of it.
#![allow(dead_code)]

use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

use saiife_touch::{Touch, TouchError, PROMPT_TIMEOUT_SECS};

#[cfg(feature = "fido-hid")]
mod hid;

/// D1: a build without `fido-hid`.
#[cfg(not(feature = "fido-hid"))]
pub(crate) const NO_KEY_SUPPORT: &str =
    "this saiife build has no FIDO2 key support (a static Linux build); see docs/touch.md";

/// The source of touches, in order: the soft key seam (debug builds only),
/// the plugged-in FIDO2 key (`fido-hid`), or `Err` (D1). A seam file that is
/// missing or does not parse is `Err` too; callers exit 5 with the message.
pub(crate) fn pick() -> Result<Box<dyn Touch>, String> {
    #[cfg(debug_assertions)]
    if let Some(p) = std::env::var_os("SAIIFE_TEST_TOUCH_SOFT").filter(|p| !p.is_empty()) {
        return SoftFile::open(std::path::Path::new(&p));
    }
    device()
}

#[cfg(feature = "fido-hid")]
fn device() -> Result<Box<dyn Touch>, String> {
    Ok(Box::new(hid::HidAuthenticator::new(Box::new(|| {
        crate::tty::read_hidden("PIN for your security key: ")
    }))))
}

#[cfg(not(feature = "fido-hid"))]
fn device() -> Result<Box<dyn Touch>, String> {
    Err(NO_KEY_SUPPORT.into())
}

/// Runs `f` on a worker thread and waits at most `limit` for it (D4). When
/// the limit passes it prints `no touch within <s> s` and gives
/// `Unavailable`; the worker is left to end when the key gives up.
pub(crate) fn run_touch<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, TouchError> + Send + 'static,
    limit: Duration,
) -> Result<T, TouchError> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(limit) {
        Ok(r) => r,
        Err(RecvTimeoutError::Timeout) => {
            eprintln!("saiife: no touch within {} s", limit.as_secs());
            Err(TouchError::Unavailable)
        }
        // The worker panicked: no answer from the key.
        Err(RecvTimeoutError::Disconnected) => Err(TouchError::Unavailable),
    }
}

/// D5: `Unavailable` gives 5, every other touch error 2.
pub(crate) fn exit_for(e: TouchError) -> u8 {
    match e {
        TouchError::Unavailable => 5,
        _ => 2,
    }
}

/// How long one prompt waits for a touch: `PROMPT_TIMEOUT_SECS`, or in debug
/// builds `SAIIFE_TEST_TOUCH_TIMEOUT_MS` when it is set.
pub(crate) fn prompt_limit() -> Duration {
    #[cfg(debug_assertions)]
    if let Some(ms) = std::env::var("SAIIFE_TEST_TOUCH_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        return Duration::from_millis(ms);
    }
    Duration::from_secs(PROMPT_TIMEOUT_SECS)
}

#[cfg(debug_assertions)]
pub(crate) use soft_file::SoftFile;

/// The soft key seam (debug builds only): a key kept in a JSON file.
#[cfg(debug_assertions)]
mod soft_file {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use serde::{Deserialize, Serialize};

    use saiife_touch::soft::SoftAuthenticator;
    use saiife_touch::{Assertion, CoseAlg, EnrolRequest, Touch, TouchError, TouchRequest};

    use super::{prompt_limit, run_touch};

    fn yes() -> bool {
        true
    }

    /// `{alg, pkcs8, credential_id, counter, up?, uv?, delay_ms?}`; bytes are base64url.
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct KeyFile {
        alg: CoseAlg,
        pkcs8: String,
        credential_id: String,
        counter: u32,
        #[serde(default = "yes")]
        up: bool,
        #[serde(default = "yes")]
        uv: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        delay_ms: Option<u64>,
    }

    /// `{"chain": [<key file>, ...]}`: each touch takes the next key file,
    /// staying on the last ("unplug one key, plug in another").
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ChainFile {
        chain: Vec<PathBuf>,
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum SeamFile {
        Chain(ChainFile),
        Key(KeyFile),
    }

    /// One soft key in its file. After each `request` or `enrol` the file is
    /// written back with the new counter.
    pub(crate) struct SoftFile {
        pub(crate) path: PathBuf,
        /// Shared with the worker thread of `run_touch`.
        pub(crate) key: Arc<SoftAuthenticator>,
        delay: Option<u64>,
    }

    struct SoftChain {
        files: Vec<PathBuf>,
        next: AtomicUsize,
    }

    fn read(p: &Path) -> Result<SeamFile, String> {
        let raw = std::fs::read(p)
            .map_err(|e| format!("cannot read the soft key {}: {e}", p.display()))?;
        serde_json::from_slice(&raw)
            .map_err(|e| format!("the soft key {} does not parse: {e}", p.display()))
    }

    fn unb64(p: &Path, s: &str) -> Result<Vec<u8>, String> {
        URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| format!("the soft key {} does not parse: bad base64url", p.display()))
    }

    impl SoftFile {
        /// The seam: a key file, or a chain of key files.
        pub(crate) fn open(p: &Path) -> Result<Box<dyn Touch>, String> {
            match read(p)? {
                SeamFile::Key(k) => Ok(Box::new(Self::from_file(p, k)?)),
                SeamFile::Chain(c) if c.chain.is_empty() => Err(format!(
                    "the soft key {} does not parse: an empty chain",
                    p.display()
                )),
                SeamFile::Chain(c) => Ok(Box::new(SoftChain {
                    files: c.chain,
                    next: AtomicUsize::new(0),
                })),
            }
        }

        /// One key file (not a chain).
        pub(crate) fn load(p: &Path) -> Result<SoftFile, String> {
            match read(p)? {
                SeamFile::Key(k) => Self::from_file(p, k),
                SeamFile::Chain(_) => Err(format!(
                    "the soft key {} is a chain, not a key",
                    p.display()
                )),
            }
        }

        /// A new key file (tests only).
        pub(crate) fn create(p: &Path, alg: CoseAlg) -> Result<SoftFile, String> {
            let key = match alg {
                CoseAlg::Es256 => SoftAuthenticator::new_es256(),
                CoseAlg::Ed25519 => SoftAuthenticator::new_ed25519(),
            };
            let f = SoftFile {
                path: p.to_path_buf(),
                key: Arc::new(key),
                delay: None,
            };
            save(&f.path, &f.key, f.delay)?;
            Ok(f)
        }

        fn from_file(p: &Path, k: KeyFile) -> Result<SoftFile, String> {
            let pkcs8 = unb64(p, &k.pkcs8)?;
            let id = unb64(p, &k.credential_id)?;
            let mut key = SoftAuthenticator::from_parts(k.alg, &pkcs8, id, k.counter)
                .map_err(|e| format!("the soft key {} does not parse: {e}", p.display()))?;
            key.up = k.up;
            key.uv = k.uv;
            Ok(SoftFile {
                path: p.to_path_buf(),
                key: Arc::new(key),
                delay: k.delay_ms,
            })
        }

        /// Runs `f` on the key through `run_touch`, after `delay_ms`, then
        /// writes the file back.
        fn touch<T: Send + 'static>(
            &self,
            f: impl FnOnce(&SoftAuthenticator) -> Result<T, TouchError> + Send + 'static,
        ) -> Result<T, TouchError> {
            let (key, path, delay) = (Arc::clone(&self.key), self.path.clone(), self.delay);
            run_touch(
                move || {
                    if let Some(ms) = delay {
                        std::thread::sleep(Duration::from_millis(ms));
                    }
                    let out = f(&key)?;
                    save(&path, &key, delay).map_err(|e| {
                        eprintln!("saiife: {e}");
                        TouchError::Unavailable
                    })?;
                    Ok(out)
                },
                prompt_limit(),
            )
        }
    }

    fn save(p: &Path, key: &SoftAuthenticator, delay_ms: Option<u64>) -> Result<(), String> {
        let (alg, pkcs8, id, counter) = key.parts();
        let f = KeyFile {
            alg,
            pkcs8: URL_SAFE_NO_PAD.encode(pkcs8),
            credential_id: URL_SAFE_NO_PAD.encode(id),
            counter,
            up: key.up,
            uv: key.uv,
            delay_ms,
        };
        let json = serde_json::to_vec(&f).map_err(|e| e.to_string())?;
        std::fs::write(p, json)
            .map_err(|e| format!("cannot write the soft key {}: {e}", p.display()))
    }

    impl Touch for SoftFile {
        fn request(&self, r: &TouchRequest) -> Result<Assertion, TouchError> {
            let r = r.clone();
            self.touch(move |k| k.request(&r))
        }

        fn enrol(&self, r: &EnrolRequest) -> Result<Vec<u8>, TouchError> {
            let r = r.clone();
            self.touch(move |k| k.enrol(&r))
        }
    }

    impl SoftChain {
        /// The next key file in the chain, staying on the last.
        fn next(&self) -> Result<SoftFile, TouchError> {
            let i = self.next.fetch_add(1, Ordering::SeqCst);
            let p = &self.files[i.min(self.files.len() - 1)];
            SoftFile::load(p).map_err(|e| {
                eprintln!("saiife: {e}");
                TouchError::Unavailable
            })
        }
    }

    impl Touch for SoftChain {
        fn request(&self, r: &TouchRequest) -> Result<Assertion, TouchError> {
            self.next()?.request(r)
        }

        fn enrol(&self, r: &EnrolRequest) -> Result<Vec<u8>, TouchError> {
            self.next()?.enrol(r)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Instant;

    /// `pick` reads the environment; tests that touch it take this lock.
    static ENV: Mutex<()> = Mutex::new(());

    #[test]
    fn slow_key_times_out() {
        let t = Instant::now();
        let r = run_touch(
            || {
                std::thread::sleep(Duration::from_secs(2));
                Ok(())
            },
            Duration::from_millis(100),
        );
        assert_eq!(r, Err(TouchError::Unavailable));
        assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
        assert_eq!(run_touch(|| Ok(7), Duration::from_secs(5)), Ok(7));
        assert_eq!(
            run_touch::<()>(|| Err(TouchError::NotPresent), Duration::from_secs(5)),
            Err(TouchError::NotPresent)
        );
    }

    #[test]
    fn exit_codes() {
        assert_eq!(exit_for(TouchError::Unavailable), 5);
        assert_eq!(exit_for(TouchError::Mismatch), 2);
        assert_eq!(exit_for(TouchError::NotVerified), 2);
    }

    #[cfg(not(feature = "fido-hid"))]
    #[test]
    fn pick_without_hid_names_the_build() {
        let _env = ENV.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("SAIIFE_TEST_TOUCH_SOFT");
        let e = pick().err().expect("no key source in this build");
        assert!(e.contains("no FIDO2 key support"), "{e}");
        assert_eq!(e, NO_KEY_SUPPORT);
    }

    /// Review Focus 5: a release build ignores the soft key seam.
    #[cfg(not(debug_assertions))]
    #[test]
    fn soft_seam_is_debug_only() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        let _env = ENV.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("key.json");
        let (_, pkcs8, id, counter) = saiife_touch::soft::SoftAuthenticator::new_es256().parts();
        let file = serde_json::json!({
            "alg": "es256",
            "pkcs8": URL_SAFE_NO_PAD.encode(pkcs8),
            "credential_id": URL_SAFE_NO_PAD.encode(id),
            "counter": counter,
        });
        std::fs::write(&p, file.to_string()).unwrap();
        // A valid key file, then a missing one: neither changes what `pick` gives.
        for path in [p.clone(), dir.path().join("missing.json")] {
            std::env::set_var("SAIIFE_TEST_TOUCH_SOFT", &path);
            let r = pick();
            std::env::remove_var("SAIIFE_TEST_TOUCH_SOFT");
            #[cfg(not(feature = "fido-hid"))]
            assert_eq!(r.err().as_deref(), Some(NO_KEY_SUPPORT));
            // The HID key: built, never asked (no hardware in tests).
            #[cfg(feature = "fido-hid")]
            assert!(r.is_ok());
        }
    }

    #[cfg(debug_assertions)]
    mod soft {
        use super::super::*;
        use saiife_touch::{
            challenge, verify, ActionRecord, CoseAlg, TouchClass, TouchRequest, LOCAL_RP_ID,
        };
        use std::collections::BTreeMap;

        const NOW: u64 = 1_800_000_000;

        fn action(id: u64) -> ActionRecord {
            ActionRecord {
                instance_id: [0x11; 16],
                request_id: id,
                class: TouchClass::Deploy,
                summary: format!("#{id} deploy"),
                fields: BTreeMap::new(),
                nonce: [0x22; 32],
                expires_at: NOW + 300,
            }
        }

        fn request(a: &ActionRecord) -> TouchRequest {
            TouchRequest {
                rp_id: LOCAL_RP_ID.into(),
                challenge: challenge(a),
                allow: vec![],
                uv: true,
                summary: a.summary.clone(),
                short_code: "000000".into(),
            }
        }

        #[test]
        fn soft_file_round_trip() {
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("key.json");
            let made = SoftFile::create(&p, CoseAlg::Es256).unwrap();
            assert_eq!(made.key.parts().3, 0);
            let a = action(1);
            let asr = SoftFile::open(&p).unwrap().request(&request(&a)).unwrap();
            let again = SoftFile::load(&p).unwrap();
            assert_eq!(again.key.parts().3, 1);
            let cred = again.key.credential(LOCAL_RP_ID, 0, "k");
            let ev = verify(&[cred], &a, &asr, LOCAL_RP_ID, NOW).unwrap();
            assert_eq!(ev.sign_count, 1);
            assert!(ev.user_verified);
        }

        #[test]
        fn soft_file_knobs_and_chain() {
            let dir = tempfile::tempdir().unwrap();
            let (pa, pb) = (dir.path().join("a.json"), dir.path().join("b.json"));
            let ka = SoftFile::create(&pa, CoseAlg::Es256).unwrap().key;
            let kb = SoftFile::create(&pb, CoseAlg::Ed25519).unwrap().key;
            let chain = dir.path().join("chain.json");
            let list = serde_json::json!({ "chain": [pa, pb] });
            std::fs::write(&chain, list.to_string()).unwrap();
            let touch = SoftFile::open(&chain).unwrap();
            let ids: Vec<Vec<u8>> = (0..3)
                .map(|i| {
                    let asr = touch.request(&request(&action(i))).unwrap();
                    asr.credential_id().to_vec()
                })
                .collect();
            assert_eq!(
                ids,
                vec![ka.credential_id(), kb.credential_id(), kb.credential_id()]
            );
            assert_eq!(SoftFile::load(&pb).unwrap().key.parts().3, 2);

            // `up: false` is kept across a write back, and signs without UP.
            let mut v: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&pa).unwrap()).unwrap();
            v["up"] = false.into();
            std::fs::write(&pa, v.to_string()).unwrap();
            let a = action(9);
            let asr = SoftFile::open(&pa).unwrap().request(&request(&a)).unwrap();
            let k = SoftFile::load(&pa).unwrap().key;
            assert!(!k.up);
            assert_eq!(
                verify(
                    &[k.credential(LOCAL_RP_ID, 0, "a")],
                    &a,
                    &asr,
                    LOCAL_RP_ID,
                    NOW
                )
                .unwrap_err(),
                TouchError::NotPresent
            );
        }

        #[test]
        fn soft_file_bad_or_missing_is_err() {
            let dir = tempfile::tempdir().unwrap();
            assert!(SoftFile::open(&dir.path().join("missing.json")).is_err());
            let bad = dir.path().join("bad.json");
            std::fs::write(&bad, "{\"alg\":").unwrap();
            assert!(SoftFile::open(&bad).is_err());
            std::fs::write(&bad, "{\"chain\":[]}").unwrap();
            assert!(SoftFile::open(&bad).is_err());
        }
    }
}
