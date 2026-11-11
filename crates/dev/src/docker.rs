//! The `docker` CLI runner and its scripted fake.

#[cfg(any(test, feature = "fake"))]
mod fake;
#[cfg(any(test, feature = "fake"))]
pub use fake::{Call, FakeDocker};

use crate::DevError;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The most stderr text kept in a `DevError::Docker`.
const STDERR_CAP: usize = 4096;

/// What a `docker` run produced. A signal death is status `-1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Output {
    /// Exit 0 with this stdout.
    pub fn ok(stdout: impl Into<Vec<u8>>) -> Output {
        Output {
            status: 0,
            stdout: stdout.into(),
            stderr: Vec::new(),
        }
    }

    /// A non-zero exit with this stderr.
    pub fn fail(status: i32, stderr: &str) -> Output {
        Output {
            status,
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }
}

/// Runs `docker` with arguments. `Err` only when the process cannot run at
/// all; a non-zero exit is an `Ok` with that status.
pub trait Docker: Send + Sync {
    fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Output, DevError>;
}

/// The real `docker` binary, run as the current user.
#[derive(Debug, Clone)]
pub struct DockerCli {
    bin: PathBuf,
}

impl DockerCli {
    pub fn new(bin: PathBuf) -> DockerCli {
        DockerCli { bin }
    }

    pub fn bin(&self) -> &Path {
        &self.bin
    }

    /// `SAIIFE_DOCKER`, else `docker` on `PATH`, from the process environment.
    pub fn from_env() -> Result<DockerCli, DevError> {
        DockerCli::from_env_with(&|k| std::env::var_os(k))
    }

    /// Like `from_env`, with the environment passed in.
    pub fn from_env_with(env: &dyn Fn(&str) -> Option<OsString>) -> Result<DockerCli, DevError> {
        if let Some(v) = env("SAIIFE_DOCKER").filter(|v| !v.is_empty()) {
            let p = PathBuf::from(&v);
            if p.is_file() {
                return Ok(DockerCli::new(p));
            }
            return Err(DevError::DockerNotFound {
                tried: format!("SAIIFE_DOCKER={}", v.to_string_lossy()),
            });
        }
        let name = if cfg!(windows) {
            "docker.exe"
        } else {
            "docker"
        };
        if let Some(path) = env("PATH") {
            for dir in std::env::split_paths(&path) {
                let cand = dir.join(name);
                if cand.is_file() {
                    return Ok(DockerCli::new(cand));
                }
            }
        }
        Err(DevError::DockerNotFound {
            tried: "PATH".into(),
        })
    }
}

impl Docker for DockerCli {
    fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Output, DevError> {
        let mut cmd = Command::new(&self.bin);
        cmd.args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|source| DevError::Spawn {
            bin: self.bin.clone(),
            source,
        })?;
        let pipe = child.stdin.take();
        let out = std::thread::scope(|s| {
            // Write stdin from its own thread while the output is read, so a
            // large stdin and a large stdout cannot block each other.
            let writer = s.spawn(move || {
                if let (Some(mut pipe), Some(data)) = (pipe, stdin) {
                    match pipe.write_all(data) {
                        // The child may exit without reading all of it.
                        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
                        r => r,
                    }
                } else {
                    Ok(())
                }
            });
            let out = child.wait_with_output();
            let written = writer.join().unwrap_or(Ok(()));
            (out, written)
        });
        let io = |source| DevError::Io {
            path: self.bin.clone(),
            source,
        };
        let (out, written) = out;
        let out = out.map_err(io)?;
        written.map_err(io)?;
        Ok(Output {
            status: out.status.code().unwrap_or(-1),
            stdout: out.stdout,
            stderr: out.stderr,
        })
    }
}

/// Runs `docker` and returns stdout on exit 0; otherwise `DevError::Docker`
/// with the trimmed, capped stderr.
pub fn run_ok(d: &dyn Docker, args: &[&str]) -> Result<Vec<u8>, DevError> {
    let out = d.run(args, None)?;
    if out.status == 0 {
        return Ok(out.stdout);
    }
    let text = String::from_utf8_lossy(&out.stderr);
    let text = text.trim();
    let mut end = text.len().min(STDERR_CAP);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    Err(DevError::Docker {
        args: args.iter().map(|a| a.to_string()).collect(),
        status: out.status,
        stderr: text[..end].to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::path::Path;

    fn env_of<'a>(pairs: &'a [(&'a str, OsString)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |k| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone())
    }

    #[cfg(unix)]
    fn script(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    /// Run a just-written script, retrying while another thread's fork holds
    /// the write fd open (ETXTBSY).
    #[cfg(unix)]
    fn run_retry(cli: &DockerCli, args: &[&str], stdin: Option<&[u8]>) -> Result<Output, DevError> {
        let mut tries = 0;
        loop {
            match cli.run(args, stdin) {
                Err(DevError::Spawn { source, .. })
                    if source.kind() == std::io::ErrorKind::ExecutableFileBusy && tries < 50 =>
                {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                other => return other,
            }
        }
    }

    fn touch(p: &Path) {
        std::fs::write(p, "").unwrap();
    }

    fn bin_name() -> &'static str {
        if cfg!(windows) {
            "docker.exe"
        } else {
            "docker"
        }
    }

    #[test]
    fn run_ok_maps_failure() {
        let f = FakeDocker::new();
        f.on(&["compose", "up"], Output::fail(1, " boom \n"));
        match run_ok(&f, &["compose", "up"]) {
            Err(DevError::Docker {
                args,
                status,
                stderr,
            }) => {
                assert_eq!(args, vec!["compose", "up"]);
                assert_eq!(status, 1);
                assert_eq!(stderr, "boom");
            }
            other => panic!("{other:?}"),
        }
        f.on(&["x"], Output::fail(2, &"e".repeat(10_000)));
        match run_ok(&f, &["x"]) {
            Err(DevError::Docker { stderr, .. }) => assert_eq!(stderr.len(), 4096),
            other => panic!("{other:?}"),
        }
        f.on(&["y"], Output::fail(2, &"é".repeat(5000)));
        match run_ok(&f, &["y"]) {
            Err(DevError::Docker { stderr, .. }) => {
                assert!(stderr.len() <= 4096 && stderr.chars().all(|c| c == 'é'))
            }
            other => panic!("{other:?}"),
        }
        f.on(&["ok"], Output::ok("fine"));
        assert_eq!(run_ok(&f, &["ok"]).unwrap(), b"fine");
    }

    #[cfg(unix)]
    #[test]
    fn from_env_prefers_saiife_docker() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("d");
        touch(&d);
        let other = t.path().join("other");
        std::fs::create_dir(&other).unwrap();
        touch(&other.join("docker"));
        let pairs = [
            ("SAIIFE_DOCKER", d.clone().into_os_string()),
            ("PATH", other.into_os_string()),
        ];
        let cli = DockerCli::from_env_with(&env_of(&pairs)).unwrap();
        assert_eq!(cli.bin(), d.as_path());
    }

    #[test]
    fn from_env_searches_path() {
        let t = tempfile::tempdir().unwrap();
        let a = t.path().join("a");
        let b = t.path().join("b");
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        touch(&b.join(bin_name()));
        let path = std::env::join_paths([&a, &b]).unwrap();
        let pairs = [("PATH", path)];
        let cli = DockerCli::from_env_with(&env_of(&pairs)).unwrap();
        assert_eq!(cli.bin(), b.join(bin_name()).as_path());
    }

    #[test]
    fn from_env_not_found() {
        let t = tempfile::tempdir().unwrap();
        let pairs = [("PATH", t.path().as_os_str().to_owned())];
        match DockerCli::from_env_with(&env_of(&pairs)) {
            Err(DevError::DockerNotFound { tried }) => assert_eq!(tried, "PATH"),
            other => panic!("{other:?}"),
        }
        let pairs = [
            ("SAIIFE_DOCKER", OsString::from("/nope")),
            ("PATH", t.path().as_os_str().to_owned()),
        ];
        match DockerCli::from_env_with(&env_of(&pairs)) {
            Err(DevError::DockerNotFound { tried }) => {
                assert!(tried.contains("SAIIFE_DOCKER=/nope"), "{tried}")
            }
            other => panic!("{other:?}"),
        }
        // an empty SAIIFE_DOCKER is ignored, and no PATH at all is a miss
        let pairs = [("SAIIFE_DOCKER", OsString::new())];
        assert!(matches!(
            DockerCli::from_env_with(&env_of(&pairs)),
            Err(DevError::DockerNotFound { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn cli_runs_a_script() {
        let t = tempfile::tempdir().unwrap();
        let s = script(t.path(), "d", "printf '%s\\n' \"$@\"; cat >&2; exit 3");
        let out = run_retry(&DockerCli::new(s), &["a b", "c"], Some(b"in")).unwrap();
        assert_eq!(out.status, 3);
        assert_eq!(out.stdout, b"a b\nc\n");
        assert_eq!(out.stderr, b"in");
    }

    #[cfg(unix)]
    #[test]
    fn big_stdin_and_stdout_do_not_deadlock() {
        let t = tempfile::tempdir().unwrap();
        let s = script(t.path(), "d", "cat; cat /dev/null >&2");
        let data: Vec<u8> = (0..4 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        let out = run_retry(&DockerCli::new(s), &["x"], Some(&data)).unwrap();
        assert_eq!(out.status, 0);
        assert_eq!(out.stdout, data);
    }

    #[test]
    fn missing_binary_is_spawn_error() {
        let t = tempfile::tempdir().unwrap();
        let r = DockerCli::new(t.path().join("none")).run(&["ps"], None);
        assert!(matches!(r, Err(DevError::Spawn { .. })), "{r:?}");
    }
}
