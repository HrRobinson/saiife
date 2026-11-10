//! Errors of `saiife dev`.
use std::fmt;
use std::io;
use std::path::PathBuf;

/// Everything `saiife dev` can fail with. Plans 23 and 24 add their variants below.
#[derive(Debug)]
pub enum DevError {
    NoHome,
    Io {
        path: PathBuf,
        source: io::Error,
    },
    DockerNotFound {
        tried: String,
    },
    Spawn {
        bin: PathBuf,
        source: io::Error,
    },
    Docker {
        args: Vec<String>,
        status: i32,
        stderr: String,
    },
    ComposeMissing,
    NoComposeFile {
        dir: PathBuf,
    },
    NonUtf8Path(PathBuf),
    ComposeJson(String),
    BadProjectName(String),
    State {
        path: PathBuf,
        msg: String,
    },
    Quirks {
        path: PathBuf,
        msg: String,
    },
    Rewrite(String),
    // plan 23
    Cert(String),
    CaInvalid {
        path: PathBuf,
        reason: String,
    },
    RouteHost {
        host: String,
        reason: &'static str,
    },
    PortBusy {
        port: u16,
        holder: Option<String>,
    },
    NotOurs {
        kind: &'static str,
        name: String,
    },
    // plan 24
}

impl fmt::Display for DevError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DevError::NoHome => {
                f.write_str("cannot find your home directory (HOME is not set or not absolute)")
            }
            DevError::Io { path, source } => write!(f, "{}: {source}", path.display()),
            DevError::DockerNotFound { tried } => write!(
                f,
                "docker not found ({tried}); install Docker or set SAIIFE_DOCKER to its path"
            ),
            DevError::Spawn { bin, source } => {
                write!(f, "cannot run {}: {source}", bin.display())
            }
            DevError::Docker {
                args,
                status,
                stderr,
            } => write!(
                f,
                "docker {} failed (exit {status}): {stderr}",
                args.join(" ")
            ),
            DevError::ComposeMissing => {
                f.write_str("docker compose is not available; saiife dev needs Docker Compose v2")
            }
            DevError::NoComposeFile { dir } => write!(
                f,
                "no compose file in {} (looked for compose.yaml, compose.yml, docker-compose.yml, docker-compose.yaml)",
                dir.display()
            ),
            DevError::NonUtf8Path(path) => {
                write!(f, "path is not valid UTF-8: {}", path.display())
            }
            DevError::ComposeJson(msg) => {
                write!(f, "unexpected docker compose config output: {msg}")
            }
            DevError::BadProjectName(name) => write!(
                f,
                "not a valid saiife dev project name: {name:?} (lowercase letters, digits and -, at most 40)"
            ),
            DevError::State { path, msg } => {
                write!(f, "{}: {msg}. Fix or delete that file.", path.display())
            }
            DevError::Quirks { path, msg } => write!(f, "{}: {msg}", path.display()),
            DevError::Rewrite(msg) => write!(f, "cannot prepare the compose model: {msg}"),
            // plan 23
            DevError::Cert(msg) => write!(f, "certificate error: {msg}"),
            DevError::CaInvalid { path, reason } => {
                // `path` is the CA directory itself or one of its files.
                let dir = match path.extension() {
                    Some(_) => path.parent().unwrap_or(path),
                    None => path.as_path(),
                };
                write!(
                    f,
                    "the saiife dev CA is unusable: {}: {reason}; saiife never replaces it on its own. \
                     To start over, delete {} and run again, then trust the new CA",
                    path.display(),
                    dir.display()
                )
            }
            DevError::RouteHost { host, reason } => {
                write!(f, "cannot route {host:?}: {reason}")
            }
            DevError::PortBusy { port, holder } => {
                write!(f, "port {port} on 127.0.0.1 is in use by ")?;
                match holder {
                    Some(name) => write!(f, "container {name}")?,
                    None => f.write_str("another program")?,
                }
                f.write_str("; stop it, then run saiife dev up again")
            }
            DevError::NotOurs { kind, name } => write!(
                f,
                "the docker {kind} {name} exists but saiife did not create it; \
                 remove or rename it, then run saiife dev up again"
            ),
        }
    }
}

impl std::error::Error for DevError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DevError::Io { source, .. } | DevError::Spawn { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_error_display() {
        let e = DevError::Docker {
            args: vec!["compose".into(), "up".into()],
            status: 1,
            stderr: "boom".into(),
        };
        assert_eq!(e.to_string(), "docker compose up failed (exit 1): boom");
    }

    #[test]
    fn state_error_says_what_to_do() {
        let e = DevError::State {
            path: PathBuf::from("p/project.json"),
            msg: "expected value at line 1 column 1".into(),
        };
        assert_eq!(
            e.to_string(),
            "p/project.json: expected value at line 1 column 1. Fix or delete that file."
        );
    }
}
