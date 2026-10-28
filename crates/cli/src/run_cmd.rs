//! `saiife run --secret <name>[:ENV] -- <cmd> [args]` (spec §6.14): the
//! daemon leases the secret for one allowed, root-owned command; this puts
//! it in that command's environment and masks both of its output streams.
//! Linux only. Exit codes: the command's own (128 + signal when a signal
//! ended it), 2 refused, 5 the daemon cannot be reached, 127 the command
//! was not found.
//!
//! The command runs as the calling user, so the agent's code holds the
//! value while it runs; masking only hides what the command prints. That is
//! why the daemon lists the executables (`run_allow`) and why that list
//! should hold purpose-built, argument-constrained programs only. Prefer a
//! connector wherever one exists.
//!
//! Trust boundary: any process of the agent's uid can lease a listed secret
//! straight from the daemon. The executable check binds only this honest
//! client. The boundary is the uid plus its scope.

use std::path::PathBuf;
use std::process::ExitCode;

/// What `clap` hands over.
pub struct RunArgs {
    pub system_config: Option<PathBuf>,
    /// `<name>[:ENV_VAR]`, repeatable.
    pub secrets: Vec<String>,
    /// The command and its arguments.
    pub command: Vec<String>,
}

#[cfg(not(target_os = "linux"))]
pub fn run(args: RunArgs) -> ExitCode {
    let RunArgs {
        system_config,
        secrets,
        command,
    } = args;
    let _ = (system_config, secrets, command);
    eprintln!("saiife: locked mode needs Linux in this version (macOS: v2.1)");
    ExitCode::from(5)
}

#[cfg(target_os = "linux")]
pub fn run(args: RunArgs) -> ExitCode {
    linux::run(args)
}

#[cfg(any(target_os = "linux", test))]
/// `NAME` or `NAME:ENV_VAR` into the name and the variable. The default
/// variable is the name upper-cased with `-` and `.` turned into `_`.
pub(crate) fn parse_spec(spec: &str) -> Result<(String, String), String> {
    let (name, env) = match spec.split_once(':') {
        Some((n, e)) => (n, e.to_string()),
        None => (spec, spec.to_ascii_uppercase().replace(['-', '.'], "_")),
    };
    if name.is_empty() {
        return Err("--secret needs a name".into());
    }
    if is_loader_var(&env) {
        return Err(format!(
            "{env} is a loader variable and is removed from the command's environment; pick another"
        ));
    }
    let mut chars = env.chars();
    let ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !ok {
        return Err(format!(
            "{env:?} is not a valid environment variable name (give one: --secret {name}:ENV_VAR)"
        ));
    }
    Ok((name.to_string(), env))
}

#[cfg(any(target_os = "linux", test))]
/// Copy `r` to `w`, replacing every form of a masked value with
/// `[MASKED]`. The bytes held back between reads (`max_span - 1`) make a
/// value split across two reads masked whole. A write error stops the
/// writing but not the reading, so the command never blocks on a full pipe.
pub(crate) fn pump(
    mut r: impl std::io::Read,
    mut w: impl std::io::Write,
    masker: &saiife_broker::mask::Masker,
) {
    let mut held: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 8192];
    let mut writing = true;
    let emit = |bytes: &[u8], w: &mut dyn std::io::Write, writing: &mut bool| {
        if *writing && !bytes.is_empty() && (w.write_all(bytes).is_err() || w.flush().is_err()) {
            *writing = false;
        }
    };
    loop {
        let n = match r.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        held.extend_from_slice(&chunk[..n]);
        let (out, used) = masker.mask_chunk(&held, false);
        held.drain(..used);
        emit(&out, &mut w, &mut writing);
    }
    let (out, _) = masker.mask_chunk(&held, true);
    emit(&out, &mut w, &mut writing);
}

/// The variables the dynamic loader and libc read that could make the
/// command load or run other code: `LD_*` and a few more. They are removed
/// before the command starts.
#[cfg(any(target_os = "linux", test))]
const LOADER_EXTRA: &[&str] = &[
    "GCONV_PATH",
    "LOCPATH",
    "MALLOC_CHECK_",
    "MALLOC_PERTURB_",
    "HOSTALIASES",
    "NLSPATH",
    "RES_OPTIONS",
    "GLIBC_TUNABLES",
    "MALLOC_TRACE",
    "RESOLV_HOST_CONF",
    "LOCALDOMAIN",
    "GETCONF_DIR",
    "TZDIR",
];

#[cfg(any(target_os = "linux", test))]
fn is_loader_var(n: &str) -> bool {
    n.starts_with("LD_") || LOADER_EXTRA.contains(&n)
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn loader_vars<I: IntoIterator<Item = String>>(names: I) -> Vec<String> {
    names.into_iter().filter(|n| is_loader_var(n)).collect()
}

/// What `argv[0]` is for the command: the canonical file's basename, never
/// the name the user typed (multi-call binaries pick their applet from it).
#[cfg(any(target_os = "linux", test))]
pub(crate) fn argv0_for(exe: &std::path::Path) -> std::ffi::OsString {
    exe.file_name().unwrap_or(exe.as_os_str()).to_os_string()
}

/// The values to mask for a lease: the value, and for a `basic` secret
/// (`user:password`) the password on its own when it is long enough.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn mask_values(kind: &str, value: &str) -> Vec<zeroize::Zeroizing<String>> {
    let mut out = vec![zeroize::Zeroizing::new(value.to_string())];
    if kind == "basic" {
        if let Some((_, pw)) = value.split_once(':') {
            if pw.len() >= 4 {
                out.push(zeroize::Zeroizing::new(pw.to_string()));
            }
        }
    }
    // A PEM key (a service account's) is also hidden in its other forms.
    for f in saiife_broker::mask::pem_forms(value) {
        if !out.iter().any(|o| **o == *f) {
            out.push(f);
        }
    }
    out
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{argv0_for, loader_vars, mask_values, parse_spec, pump, RunArgs};
    use crate::secret_cmd::linux::{call_to, target, Stop};
    use saiife_broker::mask::Masker;
    use serde_json::{json, Map};
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitCode, Stdio};
    use zeroize::Zeroizing;

    pub fn run(args: RunArgs) -> ExitCode {
        match go(args) {
            Ok(code) => code,
            Err(Stop::Refused(m) | Stop::Forbidden(m) | Stop::Unrecorded(m)) => {
                eprintln!("saiife: {m}");
                ExitCode::from(2)
            }
            Err(Stop::Unavailable(m)) => {
                eprintln!("saiife: {m}");
                ExitCode::from(5)
            }
            Err(Stop::NotFound(m)) => {
                eprintln!("saiife: {m}");
                ExitCode::from(127)
            }
        }
    }

    fn go(args: RunArgs) -> Result<ExitCode, Stop> {
        let config = target(args.system_config.as_deref())?;
        let mut specs: Vec<(String, String)> = Vec::new();
        for s in &args.secrets {
            let spec = parse_spec(s).map_err(Stop::Refused)?;
            if specs.iter().any(|(_, e)| *e == spec.1) {
                return Err(Stop::Refused(format!(
                    "two secrets would use the variable {}",
                    spec.1
                )));
            }
            specs.push(spec);
        }
        let Some((argv0, rest)) = args.command.split_first() else {
            return Err(Stop::Refused(
                "run --secret needs a command after --".into(),
            ));
        };
        let exe = resolve(argv0)?;
        let exe_s = exe
            .to_str()
            .ok_or_else(|| Stop::Refused("the command's path is not valid UTF-8".into()))?;
        let mut values: Vec<(String, Zeroizing<String>)> = Vec::new();
        let mut masked: Vec<Zeroizing<String>> = Vec::new();
        for (name, env) in &specs {
            let mut a = Map::new();
            a.insert("name".into(), json!(name));
            a.insert("exe".into(), json!(exe_s));
            let ans = call_to(&config, "secret.lease", a)?;
            let value = ans
                .get("value")
                .and_then(|v| v.as_str())
                .map(|v| Zeroizing::new(v.to_string()))
                .ok_or_else(|| Stop::Unavailable("the daemon sent no value".into()))?;
            let kind = ans.get("kind").and_then(|k| k.as_str()).unwrap_or("");
            masked.extend(mask_values(kind, &value));
            // The answer map holds a copy of the value: drop it now.
            drop(ans);
            values.push((env.clone(), value));
        }
        let refs: Vec<&str> = masked.iter().map(|v| v.as_str()).collect();
        let masker = Masker::new(&refs);

        let mut cmd = Command::new(&exe);
        // The multi-call binaries (busybox, coreutils) pick their applet
        // from argv[0]: it is the canonical file's name, not the typed one.
        cmd.arg0(argv0_for(&exe))
            .args(rest)
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for var in loader_vars(std::env::vars_os().filter_map(|(k, _)| k.into_string().ok())) {
            cmd.env_remove(var);
        }
        for (env, v) in &values {
            cmd.env(env, v.as_str());
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| Stop::Refused(format!("cannot start {}: {e}", exe.display())))?;
        let out = child.stdout.take();
        let errs = child.stderr.take();
        std::thread::scope(|s| {
            if let Some(o) = out {
                s.spawn(|| pump(o, std::io::stdout(), &masker));
            }
            if let Some(e) = errs {
                s.spawn(|| pump(e, std::io::stderr(), &masker));
            }
        });
        let status = child
            .wait()
            .map_err(|e| Stop::Unavailable(format!("cannot wait for the command: {e}")))?;
        Ok(match (status.code(), status.signal()) {
            (Some(c), _) => ExitCode::from(c.clamp(0, 255) as u8),
            (None, Some(sig)) => ExitCode::from((128 + sig).clamp(0, 255) as u8),
            (None, None) => ExitCode::from(1),
        })
    }

    /// `cmd` through `PATH` (or as a path) to its canonical form.
    fn resolve(cmd: &str) -> Result<PathBuf, Stop> {
        let miss = || Stop::NotFound(format!("{cmd}: command not found"));
        let candidate: PathBuf = if cmd.contains('/') {
            PathBuf::from(cmd)
        } else {
            let path = std::env::var_os("PATH").unwrap_or_default();
            std::env::split_paths(&path)
                .filter(|d| !d.as_os_str().is_empty())
                .map(|d| d.join(cmd))
                .find(|p| is_exec(p))
                .ok_or_else(miss)?
        };
        if !is_exec(&candidate) {
            return Err(miss());
        }
        std::fs::canonicalize(&candidate).map_err(|_| miss())
    }

    fn is_exec(p: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use saiife_broker::mask::Masker;
    use std::io::Read;

    /// Hands out `parts` one read at a time.
    struct Parts(std::collections::VecDeque<Vec<u8>>);

    impl Read for Parts {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.0.pop_front() {
                Some(p) => {
                    buf[..p.len()].copy_from_slice(&p);
                    Ok(p.len())
                }
                None => Ok(0),
            }
        }
    }

    fn pumped(parts: &[&[u8]], values: &[&str]) -> Vec<u8> {
        let m = Masker::new(values);
        let mut out = Vec::new();
        pump(
            Parts(parts.iter().map(|p| p.to_vec()).collect()),
            &mut out,
            &m,
        );
        out
    }

    #[test]
    fn split_value_across_reads_masked() {
        let v = "Zq9-run-secret-VALUE-1";
        // Every split point of the value, and of its base64 form.
        let line = format!("before {v} after\n");
        for i in 1..line.len() {
            let (a, b) = line.as_bytes().split_at(i);
            let out = pumped(&[a, b], &[v]);
            assert_eq!(
                String::from_utf8(out).unwrap(),
                "before [MASKED] after\n",
                "split at {i}"
            );
        }
        // Three-way split, one byte at a time.
        let one: Vec<&[u8]> = line.as_bytes().chunks(1).collect();
        let out = pumped(&one, &[v]);
        assert_eq!(String::from_utf8(out).unwrap(), "before [MASKED] after\n");
    }

    #[test]
    fn output_without_the_value_passes_through_whole() {
        let out = pumped(
            &[b"hello ", b"world\n", b"tail"],
            &["Zq9-run-secret-VALUE-1"],
        );
        assert_eq!(out, b"hello world\ntail");
    }

    #[test]
    fn spec_defaults_and_validation() {
        assert_eq!(
            parse_spec("db-readonly.v2").unwrap(),
            ("db-readonly.v2".into(), "DB_READONLY_V2".into())
        );
        assert_eq!(
            parse_spec("tok:TOKEN").unwrap(),
            ("tok".into(), "TOKEN".into())
        );
        assert!(parse_spec("tok:1BAD").is_err());
        assert!(parse_spec("tok:A-B").is_err());
        assert!(
            parse_spec("9lives").is_err(),
            "default would start with a digit"
        );
        assert!(parse_spec(":X").is_err());
        assert!(parse_spec("tok:LD_PRELOAD").is_err());
        assert!(parse_spec("tok:GLIBC_TUNABLES").is_err());
        assert!(parse_spec("tok:LD_X").is_err());
    }

    #[test]
    fn loader_variables_are_picked_out() {
        let names = [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "GCONV_PATH",
            "LOCPATH",
            "MALLOC_CHECK_",
            "MALLOC_PERTURB_",
            "HOSTALIASES",
            "NLSPATH",
            "RES_OPTIONS",
            "GLIBC_TUNABLES",
            "MALLOC_TRACE",
            "RESOLV_HOST_CONF",
            "LOCALDOMAIN",
            "GETCONF_DIR",
            "TZDIR",
            "PATH",
            "HOME",
            "LANG",
            "OLD_LD_X",
        ];
        let got = loader_vars(names.iter().map(|s| s.to_string()));
        assert_eq!(got.len(), 15, "{got:?}");
        assert!(!got
            .iter()
            .any(|n| n == "PATH" || n == "HOME" || n == "LANG"));
    }

    #[test]
    fn argv0_is_the_canonical_basename() {
        assert_eq!(
            argv0_for(std::path::Path::new("/usr/bin/coreutils")),
            std::ffi::OsString::from("coreutils")
        );
    }

    #[test]
    fn pem_key_is_masked_in_every_form() {
        let l1 = "TESTBODYTESTBODYTESTBODYTESTBODY0001";
        let l2 = "TESTBODYTESTBODYTESTBODYTESTBODY0002";
        let pem = format!(
            "{}{}\n{l1}\n{l2}\n{}{}\n",
            "-----BEGIN ", "PRIVATE KEY-----", "-----END ", "PRIVATE KEY-----"
        );
        let v: Vec<String> = mask_values("gcp_sa", &pem)
            .iter()
            .map(|v| v.to_string())
            .collect();
        for want in [
            pem.clone(),
            pem.trim_end().to_string(),
            pem.replace('\n', "\\n"),
            format!("{l1}{l2}"),
            l1.to_string(),
            l2.to_string(),
        ] {
            assert!(v.contains(&want), "missing {want:?}");
        }
        assert_eq!(mask_values("token", "plain-value").len(), 1);
    }

    #[test]
    fn basic_password_is_masked_on_its_own() {
        let v = mask_values("basic", "alice:s3cr3t-pass");
        let strs: Vec<&str> = v.iter().map(|z| z.as_str()).collect();
        assert_eq!(strs, vec!["alice:s3cr3t-pass", "s3cr3t-pass"]);
        let short = mask_values("basic", "alice:abc");
        assert_eq!(short.len(), 1);
        assert_eq!(mask_values("token", "a:bcdefgh").len(), 1);
        let m = Masker::new(&strs);
        let out = m.mask_bytes(b"login with s3cr3t-pass ok");
        assert_eq!(out, b"login with [MASKED] ok");
    }

    #[test]
    fn json_escaped_percent_form_split_across_reads_is_masked() {
        // `a b/c` percent-encoded `a%20b%2Fc`, then written as JSON with
        // every byte \u-escaped: far longer than the plain forms.
        let v = "ab cd/ef+gh";
        let esc: String = "ab%20cd%2Fef%2Bgh"
            .bytes()
            .map(|b| format!("\\u{b:04x}"))
            .collect();
        let line = format!("{{\"x\":\"{esc}\"}}");
        for i in 1..line.len() {
            let (a, b) = line.as_bytes().split_at(i);
            let out = pumped(&[a, b], &[v]);
            let t = String::from_utf8(out).unwrap();
            assert!(
                !t.contains("u0025") && !t.contains("u0032"),
                "split {i}: {t}"
            );
            assert!(t.contains("[MASKED]"), "split {i}: {t}");
        }
    }
}
