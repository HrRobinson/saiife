//! `saiife touch enrol | ls | rm | test` (plan 27), and the key layer.
//! `pick` chooses the source of touches: the soft key seam (debug builds
//! only), a FIDO2 key over USB HID (feature `fido-hid`), or none (D1).
//!
//! Exit codes: 0 done, 2 refused (by the daemon or the key), 5 the daemon
//! or the key cannot be reached (D5), as `saiife approvals`.

use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

use clap::Subcommand;
use saiife_touch::{Touch, TouchError, PROMPT_TIMEOUT_SECS};

#[derive(Subcommand)]
pub enum TouchAction {
    /// Enrol the plugged-in key as a new touch device. A second device is
    /// approved by a touch of one you have.
    Enrol {
        /// A name for the key (shown by `ls` and when it approves).
        #[arg(long)]
        label: String,
    },
    /// List your touch devices.
    Ls {
        /// Machine-readable output: one JSON array.
        #[arg(long)]
        json: bool,
        /// Every device on this machine (root or an admin).
        #[arg(long)]
        all: bool,
    },
    /// Remove one of your touch devices (a touch of one of them approves).
    Rm {
        /// The device's id, or a unique prefix of at least 8 characters.
        /// A base64url id may start with `-`.
        #[arg(allow_hyphen_values = true)]
        id: String,
        /// Remove without a touch, when every device is lost (root only).
        #[arg(long)]
        host: bool,
    },
    /// Touch an enrolled device, to check that it works.
    Test,
}

/// Review Focus 4: a daemon that predates plan 26.
const NO_DAEMON_SUPPORT: &str = "this saiife daemon has no touch support; update it";

#[cfg(not(any(unix, windows)))]
pub fn run(_config: Option<std::path::PathBuf>, _action: TouchAction) -> std::process::ExitCode {
    eprintln!("saiife: {}", saiife_system::NOT_SUPPORTED_OS);
    std::process::ExitCode::from(5)
}

#[cfg(any(unix, windows))]
pub use cmd::run;

#[cfg(any(unix, windows))]
mod cmd {
    use std::path::PathBuf;
    use std::process::ExitCode;

    use saiife_touch::{Assertion, EnrolRequest, Touch, TouchRequest};
    use serde::de::DeserializeOwned;
    use serde_json::{json, Map, Value};

    use super::{pick, TouchAction, NO_DAEMON_SUPPORT};
    use crate::approvals_cmd::client::{answer, call_raw, connect, finish, target, Stop};
    use crate::broker::Target;
    use crate::text::sanitize;

    /// The shortest id prefix `rm` takes.
    const MIN_PREFIX: usize = 8;
    /// The ID column of `ls`, in characters.
    const ID_CHARS: usize = 12;

    pub fn run(config: Option<PathBuf>, action: TouchAction) -> ExitCode {
        finish(target(config).and_then(|t| match action {
            TouchAction::Enrol { label } => enrol(&t, &label),
            TouchAction::Ls { json, all } => ls(&t, json, all),
            TouchAction::Rm { id, host } => rm(&t, &id, host),
            TouchAction::Test => test(&t),
        }))
    }

    /// One `touch.*` op on a new connection: a touch may take up to 120 s,
    /// and no connection waits idle for it (as D6). `unknown_op` names an
    /// old daemon (Review Focus 4).
    fn op(t: &Target, op: &str, args: Value) -> Result<Map<String, Value>, Stop> {
        let Value::Object(args) = args else {
            unreachable!("touch op arguments are an object")
        };
        let mut c = connect(t)?;
        let ans = call_raw(&mut c, op, args)?;
        if ans.get("error").and_then(Value::as_str) == Some("unknown_op") {
            return Err(Stop::Unavailable(NO_DAEMON_SUPPORT.into()));
        }
        answer(ans)
    }

    /// The source of touches; none is exit 5 with its message (D1).
    fn key() -> Result<Box<dyn Touch>, Stop> {
        pick().map_err(Stop::Unavailable)
    }

    /// `v[k]` (or all of `v` when `k` is empty) as a `T`.
    fn field<T: DeserializeOwned>(v: &Map<String, Value>, k: &str) -> Result<T, Stop> {
        let x = if k.is_empty() {
            Value::Object(v.clone())
        } else {
            v.get(k).cloned().unwrap_or(Value::Null)
        };
        serde_json::from_value(x).map_err(|e| {
            Stop::Unavailable(format!(
                "the saiife daemon sent a touch answer this saiife cannot read: {e}"
            ))
        })
    }

    fn s<'a>(v: &'a Map<String, Value>, k: &str) -> &'a str {
        v.get(k).and_then(Value::as_str).unwrap_or_default()
    }

    fn json_of(a: &Assertion) -> Value {
        serde_json::to_value(a).unwrap_or(Value::Null)
    }

    fn enrol(t: &Target, label: &str) -> Result<(), Stop> {
        let k = key()?;
        let b = op(
            t,
            "touch.begin",
            json!({"purpose": "enrol", "label": label}),
        )?;
        let er: EnrolRequest = field(&b, "")?;
        let proof_req: TouchRequest = field(&b, "touch")?;
        let approve_with: Option<TouchRequest> = match b.get("approve_with") {
            None | Some(Value::Null) => None,
            Some(_) => Some(field(&b, "approve_with")?),
        };
        let shown = sanitize(label);
        if approve_with.is_some() {
            eprintln!(
                "saiife: enrolling \"{shown}\": touch the new key twice, then one of your enrolled keys"
            );
        } else {
            eprintln!("saiife: enrolling \"{shown}\": touch the new key twice");
        }
        let auth_data = k.enrol(&er).map_err(Stop::Touch)?;
        let proof = k.request(&proof_req).map_err(Stop::Touch)?;
        let mut args = json!({
            "label": label,
            "auth_data": base64_url(&auth_data),
            "proof": json_of(&proof),
        });
        if let Some(r) = approve_with {
            // D2: one key is plugged in at a time.
            eprintln!("saiife: unplug the new key and plug in an enrolled one, then press Enter");
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line);
            let approval = k.request(&r).map_err(Stop::Touch)?;
            args["approval"] = json_of(&approval);
        }
        let done = op(t, "touch.enrol", args)?;
        // The new id is the proof's: the answer's `id` is the frame's own
        // (`ok` keeps the frame id), so it never names the credential.
        let id = base64_url(proof.credential_id());
        outln!(
            "enrolled \"{}\" ({})",
            sanitize(s(&done, "label")),
            &id[..id.len().min(8)]
        );
        // The first device: host access approved it, and no other device can.
        if s(&done, "approved_by") == "host" {
            eprintln!(
                "saiife: add a second device (spec §8.4): a lost key leaves only root to remove it"
            );
        }
        Ok(())
    }

    fn base64_url(b: &[u8]) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        URL_SAFE_NO_PAD.encode(b)
    }

    /// The devices of `touch.list {all}`.
    fn list(t: &Target, all: bool) -> Result<Vec<Value>, Stop> {
        let ans = op(t, "touch.list", json!({"all": all}))?;
        Ok(ans
            .get("credentials")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    fn ls(t: &Target, as_json: bool, all: bool) -> Result<(), Stop> {
        let items = list(t, all)?;
        if as_json {
            outln!("{}", Value::Array(items));
        } else if items.is_empty() {
            outln!("no touch devices enrolled; saiife touch enrol --label <name>");
        } else {
            table(&items, all);
        }
        // D1: listing needs no key, but nothing else works in this build.
        #[cfg(not(feature = "fido-hid"))]
        eprintln!("saiife: {}", super::NO_KEY_SUPPORT);
        Ok(())
    }

    fn table(items: &[Value], all: bool) {
        let mut head = vec!["ID", "LABEL", "KIND", "ALG", "ADDED", "COUNT"];
        if all {
            head.push("OWNER");
        }
        let text = |v: &Value| sanitize(v.as_str().unwrap_or_default());
        let rows: Vec<Vec<String>> = items
            .iter()
            .map(|i| {
                let mut r = vec![
                    text(&i["id"]).chars().take(ID_CHARS).collect(),
                    text(&i["label"]),
                    text(&i["kind"]),
                    text(&i["alg"]),
                    text(&i["created"]).chars().take(10).collect(),
                    i["sign_count"].as_u64().unwrap_or_default().to_string(),
                ];
                if all {
                    r.push(i["owner_uid"].as_u64().unwrap_or_default().to_string());
                }
                r
            })
            .collect();
        let head: Vec<String> = head.into_iter().map(String::from).collect();
        let mut w = vec![0usize; head.len()];
        for r in std::iter::once(&head).chain(rows.iter()) {
            for (i, c) in r.iter().enumerate() {
                w[i] = w[i].max(c.chars().count());
            }
        }
        for r in std::iter::once(&head).chain(rows.iter()) {
            let line: Vec<String> = r
                .iter()
                .enumerate()
                .map(|(i, c)| format!("{c}{}", " ".repeat(w[i] - c.chars().count())))
                .collect();
            outln!("{}", line.join("  ").trim_end());
        }
    }

    /// The one device whose id starts with `prefix` (at least 8 characters).
    fn resolve(items: Vec<Value>, prefix: &str) -> Result<Value, Stop> {
        if prefix.chars().count() < MIN_PREFIX {
            return Err(Stop::Refused(vec![format!(
                "give at least {MIN_PREFIX} characters of the id (saiife touch ls)"
            )]));
        }
        let mut hits: Vec<Value> = items
            .into_iter()
            .filter(|i| i["id"].as_str().is_some_and(|id| id.starts_with(prefix)))
            .collect();
        let shown = sanitize(prefix);
        match hits.len() {
            0 => Err(Stop::Refused(vec![format!(
                "no enrolled device starts with \"{shown}\" (saiife touch ls)"
            )])),
            1 => Ok(hits.remove(0)),
            _ => Err(Stop::Refused(vec![format!(
                "more than one enrolled device starts with \"{shown}\"; give more of the id"
            )])),
        }
    }

    fn rm(t: &Target, prefix: &str, host: bool) -> Result<(), Stop> {
        // `--host` (root's recovery) may remove any uid's device.
        let dev = resolve(list(t, host)?, prefix)?;
        let credential = dev["id"].as_str().unwrap_or_default().to_string();
        let done = if host {
            op(
                t,
                "touch.remove",
                json!({"credential": credential, "host": true}),
            )?
        } else {
            let k = key()?;
            let b = op(
                t,
                "touch.begin",
                json!({"purpose": "remove", "credential": credential}),
            )?;
            let r: TouchRequest = field(&b, "")?;
            eprintln!(
                "saiife: removing \"{}\": touch one of your enrolled keys",
                sanitize(dev["label"].as_str().unwrap_or_default())
            );
            let asr = k.request(&r).map_err(Stop::Touch)?;
            op(
                t,
                "touch.remove",
                json!({"credential": credential, "assertion": json_of(&asr)}),
            )?
        };
        outln!("removed \"{}\"", sanitize(s(&done, "label")));
        Ok(())
    }

    fn test(t: &Target) -> Result<(), Stop> {
        let k = key()?;
        let b = op(t, "touch.begin", json!({"purpose": "test"}))?;
        let r: TouchRequest = field(&b, "")?;
        eprintln!("saiife: touch one of your enrolled keys");
        let asr = k.request(&r).map_err(Stop::Touch)?;
        let done = op(t, "touch.check", json!({"assertion": json_of(&asr)}))?;
        let uv = if done.get("uv") == Some(&Value::Bool(true)) {
            "yes"
        } else {
            "no"
        };
        outln!(
            "ok: \"{}\" answered (user verified: {uv}, counter {})",
            sanitize(s(&done, "label")),
            done.get("sign_count")
                .and_then(Value::as_u64)
                .unwrap_or_default()
        );
        Ok(())
    }
}

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
// The soft key (debug builds) and the HID key call it.
#[cfg_attr(
    all(not(debug_assertions), not(feature = "fido-hid")),
    allow(dead_code)
)]
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
// The soft key (debug builds) and the HID key call it.
#[cfg_attr(
    all(not(debug_assertions), not(feature = "fido-hid")),
    allow(dead_code)
)]
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
        #[cfg(test)]
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
    use std::time::Instant;

    /// `pick` reads the environment; tests that touch it take this lock
    /// (only those of a build without `fido-hid`, or a release build).
    #[cfg(any(not(feature = "fido-hid"), not(debug_assertions)))]
    static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

    /// A base64url id may start with `-`: `rm` takes it as the id, and
    /// `--host` still as the flag.
    #[test]
    fn rm_takes_an_id_with_a_leading_hyphen() {
        use clap::Parser;
        #[derive(Parser)]
        struct T {
            #[command(subcommand)]
            a: TouchAction,
        }
        for (argv, want_host) in [
            (vec!["t", "rm", "-AbCdEfG"], false),
            (vec!["t", "rm", "-AbCdEfG", "--host"], true),
            (vec!["t", "rm", "--host", "-AbCdEfG"], true),
        ] {
            match T::try_parse_from(&argv).map(|t| t.a) {
                Ok(TouchAction::Rm { id, host }) => {
                    assert_eq!((id.as_str(), host), ("-AbCdEfG", want_host), "{argv:?}")
                }
                Ok(_) => panic!("{argv:?}: not rm"),
                Err(e) => panic!("{argv:?}: {e}"),
            }
        }
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
