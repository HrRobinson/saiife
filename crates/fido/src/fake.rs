//! A scripted FIDO helper for tests (plan 41 task 2): a soft key behind the
//! `saiife-fido/1` protocol. The knobs file is `<argv0>.json`; see `Knobs`.
//! Blocking modes sleep until the test kills the process.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use saiife_touch::soft::SoftAuthenticator;
use saiife_touch::{Assertion, CoseAlg, EnrolRequest, Touch};
use serde::{Deserialize, Serialize};

use crate::helper::{self, Backend};
use crate::proto::{decode, Answer, AssertParts, AssertReq, EnrolReq, Hello, Request, MAX_LINE};

const NO_CREDENTIALS: &str = "0x2E CTAP2_ERR_NO_CREDENTIALS   No credentials.";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Knobs {
    /// The soft key file (`KeyFile`); created by the first enrol.
    key: Option<PathBuf>,
    #[serde(default = "one")]
    devices: usize,
    /// ok | hang_after_hello | no_hello | exit_at_start:<code> | garbage |
    /// long_line | wrong_type | ctap_error:<text> | proto:<n> | version:<v>
    #[serde(default = "ok")]
    mode: String,
    log: Option<PathBuf>,
}

fn one() -> usize {
    1
}
fn ok() -> String {
    "ok".into()
}

/// `{pkcs8, credential_id, counter}`, base64url.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    pkcs8: String,
    credential_id: String,
    counter: u32,
}

fn load(path: &Path) -> Option<SoftAuthenticator> {
    let f: KeyFile = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    let d = |s: &str| URL_SAFE_NO_PAD.decode(s).ok();
    SoftAuthenticator::from_parts(
        CoseAlg::Es256,
        &d(&f.pkcs8)?,
        d(&f.credential_id)?,
        f.counter,
    )
    .ok()
}

fn save(path: &Path, k: &SoftAuthenticator) {
    let (_, pkcs8, id, counter) = k.parts();
    let f = KeyFile {
        pkcs8: URL_SAFE_NO_PAD.encode(pkcs8),
        credential_id: URL_SAFE_NO_PAD.encode(id),
        counter,
    };
    let _ = std::fs::write(path, serde_json::to_vec(&f).unwrap_or_default());
}

fn log_line(log: &Option<PathBuf>, v: &serde_json::Value) {
    let Some(p) = log else { return };
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(p)
    {
        let _ = writeln!(f, "{v}");
    }
}

fn log_op(log: &Option<PathBuf>, op: &str, pin_len: Option<usize>) {
    log_line(log, &serde_json::json!({ "op": op, "pin_len": pin_len }));
}

struct Fake {
    key: Option<PathBuf>,
    devices: usize,
    log: Option<PathBuf>,
}

impl Backend for Fake {
    fn devices(&self) -> usize {
        self.devices
    }

    fn assert(&self, r: &AssertReq) -> Result<AssertParts, String> {
        log_op(&self.log, "assert", r.pin.as_ref().map(|p| p.len()));
        let path = self.key.as_ref().ok_or(NO_CREDENTIALS)?;
        let key = load(path).ok_or(NO_CREDENTIALS)?;
        // A non-discoverable key: only an allow entry names it.
        if !r.allow.contains(&key.credential_id()) {
            return Err(NO_CREDENTIALS.into());
        }
        let Assertion::Ctap2 {
            credential_id,
            auth_data,
            signature,
            ..
        } = key.assert_ctap(&r.rp_id, &r.challenge)
        else {
            return Err("fake: not a CTAP2 assertion".into());
        };
        save(path, &key);
        Ok((credential_id, auth_data, signature))
    }

    fn enrol(&self, r: &EnrolReq) -> Result<Vec<u8>, String> {
        log_op(&self.log, "enrol", Some(r.pin.len()));
        let key = match self.key.as_ref().and_then(|p| load(p)) {
            Some(k) => k,
            None => {
                let k = SoftAuthenticator::new_es256();
                if let Some(p) = &self.key {
                    save(p, &k);
                }
                k
            }
        };
        key.enrol(&EnrolRequest {
            rp_id: r.rp_id.clone(),
            rp_name: r.rp_id.clone(),
            user_id: r.user_id.clone(),
            user_name: r.user_name.clone(),
            challenge: r.challenge,
            exclude: r.exclude.clone(),
        })
        .map_err(|e| format!("fake: {e:?}"))
    }
}

fn block() -> ! {
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

/// The fake helper. Exit codes: the mode's own, 2 for a bad request, 1 for
/// an unreadable knobs file or a broken pipe.
pub fn main() -> ExitCode {
    let args: Vec<String> = std::env::args_os()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let mut knobs_path = std::env::args_os().next().unwrap_or_default();
    knobs_path.push(".json");
    let knobs: Knobs = match std::fs::read(&knobs_path)
        .map_err(|e| e.to_string())
        .and_then(|b| serde_json::from_slice(&b).map_err(|e| e.to_string()))
    {
        Ok(k) => k,
        Err(e) => {
            eprintln!("saiife-fake-fido: knobs: {e}");
            return ExitCode::from(1);
        }
    };
    let env: Vec<String> = std::env::vars_os()
        .map(|(k, _)| k.to_string_lossy().into_owned())
        .collect();
    log_line(
        &knobs.log,
        &serde_json::json!({ "pid": std::process::id(), "argv": args, "env": env }),
    );

    let mode = knobs.mode.as_str();
    if let Some(code) = mode.strip_prefix("exit_at_start:") {
        eprintln!("saiife-fake-fido: exit at start");
        return ExitCode::from(code.parse::<u8>().unwrap_or(1));
    }
    if mode == "no_hello" {
        block();
    }
    let backend = Fake {
        key: knobs.key.clone(),
        devices: knobs.devices,
        log: knobs.log.clone(),
    };
    let mut hello = helper::hello(knobs.devices);
    if let Some(n) = mode.strip_prefix("proto:") {
        hello.proto = n.parse().unwrap_or(0);
    }
    if let Some(v) = mode.strip_prefix("version:") {
        hello.version = v.to_string();
    }
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    let code = match mode {
        "ok" => helper::serve_hello(hello, stdin.lock(), out, &backend),
        _ if mode.starts_with("proto:") || mode.starts_with("version:") => {
            helper::serve_hello(hello, stdin.lock(), out, &backend)
        }
        "hang_after_hello" => {
            if helper::write_line(&mut out, &Answer::Hello(hello)).is_err() {
                return ExitCode::from(1);
            }
            block()
        }
        "garbage" | "long_line" | "wrong_type" => scripted(hello, &knobs, &mut out, mode),
        _ if mode.starts_with("ctap_error:") => scripted(hello, &knobs, &mut out, mode),
        _ => {
            eprintln!("saiife-fake-fido: unknown mode");
            1
        }
    };
    ExitCode::from(code)
}

/// Hello, read one request, answer it with the mode's odd answer.
fn scripted(hello: Hello, knobs: &Knobs, out: &mut impl Write, mode: &str) -> u8 {
    if helper::write_line(out, &Answer::Hello(hello)).is_err() {
        return 1;
    }
    let line = match helper::read_line(std::io::stdin().lock()) {
        Ok(Some(l)) => l,
        Ok(None) => return 0,
        Err(_) => return 1,
    };
    let req = match decode::<Request>(&line) {
        Ok(r) => r,
        Err(why) => {
            let _ = helper::write_line(out, &Answer::error(&format!("bad request: {why}")));
            return 2;
        }
    };
    let (op, pin_len) = match &req {
        Request::Assert(a) => ("assert", a.pin.as_ref().map(|p| p.len())),
        Request::Enrol(e) => ("enrol", Some(e.pin.len())),
    };
    log_op(&knobs.log, op, pin_len);
    let raw: Vec<u8> = match mode {
        "garbage" => b"this is not json\n".to_vec(),
        "long_line" => {
            let mut v = vec![b'x'; MAX_LINE + 10];
            v.push(b'\n');
            v
        }
        "wrong_type" => {
            let a = match req {
                Request::Assert(_) => Answer::Attestation { auth_data: vec![1] },
                Request::Enrol(_) => Answer::Assertion {
                    credential_id: vec![1],
                    auth_data: vec![2],
                    signature: vec![3],
                },
            };
            crate::proto::encode(&a).to_vec()
        }
        _ => {
            // The raw text, uncut: the client does the cutting.
            let text = mode.strip_prefix("ctap_error:").unwrap_or_default();
            crate::proto::encode(&Answer::Error { error: text.into() }).to_vec()
        }
    };
    if out.write_all(&raw).and_then(|()| out.flush()).is_err() {
        return 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn dir() -> PathBuf {
        let base = std::env::var_os("SAIIFE_TEST_TMP")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let d = base.join(
            format!(
                "fake-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            )
            .replace(['(', ')'], ""),
        );
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn enrol_req() -> EnrolReq {
        EnrolReq {
            rp_id: "saiife.local".into(),
            challenge: [1; 32],
            user_id: vec![1],
            user_name: "u".into(),
            exclude: vec![],
            pin: Zeroizing::new("1234".into()),
        }
    }

    fn assert_req(allow: Vec<Vec<u8>>) -> AssertReq {
        AssertReq {
            rp_id: "saiife.local".into(),
            challenge: [2; 32],
            allow,
            pin: None,
        }
    }

    #[test]
    fn fake_enrols_then_asserts_with_the_allow_entry_and_counts_up() {
        let d = dir();
        let key = d.join("key.json");
        let log = d.join("log");
        let f = Fake {
            key: Some(key.clone()),
            devices: 1,
            log: Some(log.clone()),
        };
        // No key yet, or no allow entry: no credentials.
        assert!(f
            .assert(&assert_req(vec![]))
            .unwrap_err()
            .contains("CTAP2_ERR_NO_CREDENTIALS"));
        f.enrol(&enrol_req()).unwrap();
        let id = load(&key).unwrap().credential_id();
        assert!(f
            .assert(&assert_req(vec![]))
            .unwrap_err()
            .contains("NO_CREDENTIALS"));
        let (cid, ad, _) = f.assert(&assert_req(vec![id.clone()])).unwrap();
        assert_eq!(cid, id);
        let (_, ad2, _) = f.assert(&assert_req(vec![id])).unwrap();
        assert_eq!(ad[33..37], 1u32.to_be_bytes());
        assert_eq!(ad2[33..37], 2u32.to_be_bytes());
        assert_eq!(load(&key).unwrap().parts().3, 2);
        let text = std::fs::read_to_string(&log).unwrap();
        assert!(text.contains("\"pin_len\":4"), "{text}");
        assert!(!text.contains("1234"), "{text}");
    }
}
