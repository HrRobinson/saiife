//! Infrastructure errors. `BoxError` is the caller-facing one.
use std::fmt;
use std::io;
use std::path::PathBuf;

use saiife_wire::source::BoxError;

#[derive(Debug)]
pub enum BoxesError {
    Io { path: PathBuf, source: io::Error },
    State { path: PathBuf, msg: String },
    Template { path: PathBuf, msg: String },
    Vmm(String),
}

impl fmt::Display for BoxesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BoxesError::Io { path, source } => write!(f, "{}: {source}", path.display()),
            BoxesError::State { path, msg } => {
                write!(f, "box state {}: {msg}", path.display())
            }
            BoxesError::Template { path, msg } => {
                write!(f, "box template {}: {msg}", path.display())
            }
            BoxesError::Vmm(msg) => write!(f, "vmm: {msg}"),
        }
    }
}

impl std::error::Error for BoxesError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BoxesError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<BoxesError> for BoxError {
    fn from(e: BoxesError) -> BoxError {
        BoxError::Unavailable(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_to_unavailable() {
        let e = BoxesError::Vmm("boom".into());
        assert_eq!(BoxError::from(e), BoxError::Unavailable("vmm: boom".into()));
    }
}
