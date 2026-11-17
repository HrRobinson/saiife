//! Plan 45 Task 7: the frames between the daemon and the calculator process
//! (`saiife __blind-calc`, R45-12). One job frame in on stdin, one answer
//! frame out on stdout. A frame is a 4-byte big-endian length, then JSON; a
//! job is at most 1 MiB, an answer at most 64 MiB.
//!
//! Error classes only, never a library's error text: the answer's `class`
//! is an [`ErrorClass`] name, or one of the classes here that the
//! calculator adds ([`CLASS_SANDBOX_UNAVAILABLE`], [`CLASS_SNAPSHOT_MISMATCH`]).

use crate::calc::{Caps, ResultSet};
use crate::plan::SelfCheck;
use crate::public::PublicValues;
use crate::schema::{Param, Schema};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::path::PathBuf;

/// The largest job frame the calculator reads.
pub const MAX_JOB_BYTES: usize = 1024 * 1024;
/// The largest answer frame the calculator writes (and the daemon reads).
pub const MAX_ANSWER_BYTES: usize = 64 * 1024 * 1024;

/// The job format this calculator runs.
pub const CALC_JOB_VERSION: u32 = 1;
/// Debug builds only: the confinement probe (tries to read `/etc/passwd`,
/// open a TCP socket, write `$TMPDIR/x`, exec `/bin/true`, then read the
/// snapshot as a control) instead of a method. Release calculators refuse it
/// as an unknown version.
pub const PROBE_JOB_VERSION: u32 = 999;

/// The calculator could not confine itself (no Landlock, a ruleset that is
/// not fully enforced, a seccomp filter that does not load, a resource
/// limit that does not set): fail closed, the method did not run (spec §9).
pub const CLASS_SANDBOX_UNAVAILABLE: &str = "sandbox_unavailable";
/// The snapshot's SHA-256 is not the one the job names (the audit names
/// the job's): the method did not run. Rebuild or reload the dataset.
pub const CLASS_SNAPSHOT_MISMATCH: &str = "snapshot_mismatch";

/// One method run. `params[*].display` is `""`: the daemon strips it, the
/// calculator needs no names.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalcJob {
    pub v: u32,
    /// The read-only real-data snapshot.
    pub snapshot: PathBuf,
    /// `sha256:` + 64 lowercase hex, as `snapshot::hash_file` prints it.
    pub snapshot_sha256: String,
    pub schema: Schema,
    pub public: Vec<PublicValues>,
    /// The method in cloud names; re-validated by the calculator.
    pub method: String,
    pub checks: Vec<SelfCheck>,
    pub params: Vec<Param>,
    pub caps: Caps,
}

/// What the calculator's sandbox gave it (the daemon reports it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfinementInfo {
    pub landlock_abi: u32,
    /// TCP bind and connect denied by Landlock (ABI 4 or later).
    pub net_denied: bool,
    /// Signal and abstract Unix socket scoping (ABI 6 or later).
    pub scopes: bool,
    pub seccomp: bool,
    /// An empty network namespace (false when the kernel allows no
    /// unprivileged user namespaces).
    pub netns: bool,
}

/// The one answer frame. `Err.confinement` is `None` when the calculator
/// refused before confining itself (a bad frame, no sandbox).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CalcAnswer {
    Ok {
        result: ResultSet,
        confinement: ConfinementInfo,
    },
    Err {
        class: String,
        empty_for: Option<String>,
        confinement: Option<ConfinementInfo>,
    },
}

/// Writes one frame. A body over `max` bytes is an `InvalidData` error and
/// nothing is written.
pub fn write_frame<T: Serialize>(w: &mut dyn Write, v: &T, max: usize) -> io::Result<()> {
    let body = serde_json::to_vec(v).map_err(|_| io::Error::other("cannot encode the frame"))?;
    if body.len() > max || u32::try_from(body.len()).is_err() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the frame is too large",
        ));
    }
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

/// Reads one frame. A length over `max` is refused before the body is read;
/// the error texts hold no input.
pub fn read_frame<T: DeserializeOwned>(r: &mut dyn Read, max: usize) -> io::Result<T> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the frame is too large",
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    serde_json::from_slice(&body)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "not a valid frame"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_bound() {
        let a = CalcAnswer::Err {
            class: CLASS_SNAPSHOT_MISMATCH.into(),
            empty_for: None,
            confinement: Some(ConfinementInfo {
                landlock_abi: 6,
                net_denied: true,
                scopes: true,
                seccomp: true,
                netns: false,
            }),
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &a, MAX_ANSWER_BYTES).unwrap();
        let mut r: &[u8] = &buf;
        let got: CalcAnswer = read_frame(&mut r, MAX_ANSWER_BYTES).unwrap();
        assert_eq!(got, a);
        assert!(r.is_empty());
        // Too large either way; nothing written.
        let mut out = Vec::new();
        assert!(write_frame(&mut out, &a, 8).is_err());
        assert!(out.is_empty());
        let mut r: &[u8] = &buf;
        assert!(read_frame::<CalcAnswer>(&mut r, 8).is_err());
        // A bad body: no input in the error.
        let mut f = 6u32.to_be_bytes().to_vec();
        f.extend_from_slice(b"sekrit");
        let mut r: &[u8] = &f;
        let e = read_frame::<CalcAnswer>(&mut r, 64).unwrap_err();
        assert!(!e.to_string().contains("sekrit"));
    }
}
