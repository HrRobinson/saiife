//! Writing the setup's files as root without trusting what the agent left in
//! its home: every component is opened dirfd-relative with `O_NOFOLLOW`, a file
//! is written to a fresh `O_EXCL` name and renamed over its target, and owner
//! and mode are set on the open fd.
#![cfg(target_os = "linux")]

use crate::env::{GuestEnv, AGENT_HOME, AGENT_USER};
use rustix::fs::{self, AtFlags, Gid, Mode, OFlags, Uid, CWD};
use rustix::io::Errno;
use std::fs::File;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicU64, Ordering};

/// The `agent` user's ids, from the guest's `/etc/passwd`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentIds {
    pub uid: u32,
    pub gid: u32,
}

/// Looks `agent` up in `<root>/etc/passwd` (root-owned in the image).
pub fn agent_ids(env: &GuestEnv) -> Result<AgentIds, String> {
    let text = std::fs::read_to_string(env.path("/etc/passwd"))
        .map_err(|e| format!("cannot read /etc/passwd: {e}"))?;
    for line in text.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() >= 4 && f[0] == AGENT_USER {
            let uid = f[2].parse().map_err(|_| "bad uid for agent".to_string())?;
            let gid = f[3].parse().map_err(|_| "bad gid for agent".to_string())?;
            return Ok(AgentIds { uid, gid });
        }
    }
    Err("no agent user in /etc/passwd".into())
}

/// True for the agent's home and everything below it.
fn agent_owned(abs: &str) -> bool {
    abs == AGENT_HOME || abs.starts_with(&format!("{AGENT_HOME}/"))
}

fn dir_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn set_owner(fd: &OwnedFd, ids: AgentIds) -> Result<(), Errno> {
    fs::fchown(
        fd,
        Some(Uid::from_raw(ids.uid)),
        Some(Gid::from_raw(ids.gid)),
    )
}

/// Writes `data` at the absolute guest path `abs` with `mode`. Missing parent
/// directories are created (0755). Under the agent's home, created directories
/// and the file are owned by `agent`; anywhere else they stay the caller's
/// (root in the VM). A symlink anywhere on the way is refused; a symlink or
/// hard link at the target itself is replaced, never written through.
pub fn write_file(
    env: &GuestEnv,
    abs: &str,
    data: &[u8],
    mode: u32,
    agent: AgentIds,
) -> Result<(), String> {
    let fail = |what: &str, e: Errno| format!("{abs}: {what}: {e}");
    let rel = abs
        .strip_prefix('/')
        .ok_or_else(|| format!("{abs}: not absolute"))?;
    let comps: Vec<&str> = rel.split('/').collect();
    if comps
        .iter()
        .any(|c| c.is_empty() || *c == "." || *c == "..")
    {
        return Err(format!("{abs}: bad path"));
    }
    let (name, parents) = comps.split_last().ok_or_else(|| format!("{abs}: empty"))?;
    // The root is ours (/ in the VM, the test's tempdir); open it as given.
    let mut dir = fs::openat(
        CWD,
        &env.root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| fail("open root", e))?;
    let mut so_far = String::new();
    for c in parents {
        so_far.push('/');
        so_far.push_str(c);
        dir = match fs::openat(&dir, *c, dir_flags(), Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => {
                match fs::mkdirat(&dir, *c, Mode::from_raw_mode(0o700)) {
                    Ok(()) | Err(Errno::EXIST) => {}
                    Err(e) => return Err(fail(&format!("mkdir {so_far}"), e)),
                }
                let fd = fs::openat(&dir, *c, dir_flags(), Mode::empty())
                    .map_err(|e| fail(&format!("open {so_far}"), e))?;
                if agent_owned(&so_far) {
                    set_owner(&fd, agent).map_err(|e| fail(&format!("chown {so_far}"), e))?;
                }
                fs::fchmod(&fd, Mode::from_raw_mode(0o755))
                    .map_err(|e| fail(&format!("chmod {so_far}"), e))?;
                fd
            }
            Err(e) => return Err(fail(&format!("open {so_far}"), e)),
        };
    }
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let mut tmp = None;
    for _ in 0..16 {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let t = format!(".saiife-guest-{}-{n}-{nanos}.tmp", std::process::id());
        match fs::openat(
            &dir,
            t.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(fd) => {
                tmp = Some((t, fd));
                break;
            }
            Err(Errno::EXIST) => continue,
            Err(e) => return Err(fail("create", e)),
        }
    }
    let (t, fd) = tmp.ok_or_else(|| format!("{abs}: no free temporary name"))?;
    let written = (|| -> Result<(), String> {
        if agent_owned(abs) {
            set_owner(&fd, agent).map_err(|e| fail("chown", e))?;
        }
        fs::fchmod(&fd, Mode::from_raw_mode(mode)).map_err(|e| fail("chmod", e))?;
        let mut f = File::from(fd);
        f.write_all(data)
            .map_err(|e| format!("{abs}: write: {e}"))?;
        f.sync_all().map_err(|e| format!("{abs}: sync: {e}"))?;
        fs::renameat(&dir, t.as_str(), &dir, *name).map_err(|e| fail("rename", e))
    })();
    if written.is_err() {
        let _ = fs::unlinkat(&dir, t.as_str(), AtFlags::empty());
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_owned_is_home_and_below() {
        assert!(agent_owned("/home/agent"));
        assert!(agent_owned("/home/agent/.claude"));
        assert!(!agent_owned("/home/agentx"));
        assert!(!agent_owned("/etc/saiife-guest/agent.env"));
    }
}
