//! Where the guest init finds the filesystem, its tools and its timings.

use std::path::PathBuf;
use std::time::Duration;

/// The setup marker: present once the first setup has run (G3).
pub const SETUP_MARKER: &str = "/var/lib/saiife-guest/setup-done";
/// The agent's environment as `KEY=VALUE` lines, root-owned, mode 0600.
pub const AGENT_ENV_FILE: &str = "/etc/saiife-guest/agent.env";
/// The agent's home; files below it are owned by `agent`.
pub const AGENT_HOME: &str = "/home/agent";
/// The agent's working tree.
pub const WORK: &str = "/work";
/// The agent's user name.
pub const AGENT_USER: &str = "agent";

/// The external programs the init runs.
#[derive(Debug, Clone)]
pub struct GuestTools {
    pub setsid: PathBuf,
    pub runuser: PathBuf,
    pub systemctl: PathBuf,
    pub chown: PathBuf,
    pub git: PathBuf,
}

/// The init's timings. `Timing::default()` holds the plan's fixed values; tests
/// build a `GuestEnv` with lowered ones so the suite stays fast (nothing else
/// changes them).
#[derive(Debug, Clone)]
pub struct Timing {
    /// Hello attempts (fixed: `ports::HELLO_TRIES`).
    pub hello_tries: u32,
    /// Pause between hello attempts (fixed: `ports::HELLO_RETRY_SECS`).
    pub hello_retry: Duration,
    /// Deadline for the host's answer to a hello.
    pub hello_reply: Duration,
    /// G1: quiet after output before `started`.
    pub ready_quiet: Duration,
    /// G1: `started` at the latest this long after the spawn.
    pub ready_max: Duration,
    /// G2: at most one `activity` per this interval.
    pub activity_every: Duration,
    /// Overall deadline of one control connection.
    pub control_deadline: Duration,
    /// Overall deadline of one local.sock connection.
    pub local_deadline: Duration,
    /// Plan 39 (I-2): every git child of one export is killed at this
    /// deadline, well under the host's 120 s `EXPORT_TIMEOUT`.
    pub export_deadline: Duration,
    /// Plan 39 (I-2): the same for an advance (the host waits 60 s) and the
    /// first base snapshot (inside setup; the host waits 60 s).
    pub git_deadline: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            hello_tries: saiife_boxproto::ports::HELLO_TRIES,
            hello_retry: Duration::from_secs(saiife_boxproto::ports::HELLO_RETRY_SECS),
            hello_reply: Duration::from_secs(10),
            ready_quiet: Duration::from_secs(1),
            ready_max: Duration::from_secs(30),
            activity_every: Duration::from_secs(5),
            control_deadline: Duration::from_secs(10),
            local_deadline: Duration::from_secs(2),
            export_deadline: Duration::from_secs(90),
            git_deadline: Duration::from_secs(45),
        }
    }
}

/// The guest's view of the machine: a root to resolve absolute guest paths
/// under (`/` in the VM, a tempdir in tests), the tools and the version.
#[derive(Debug, Clone)]
pub struct GuestEnv {
    pub root: PathBuf,
    pub tools: GuestTools,
    pub version: String,
    pub timing: Timing,
}

impl GuestEnv {
    /// The real VM.
    pub fn system() -> GuestEnv {
        GuestEnv {
            root: PathBuf::from("/"),
            tools: GuestTools {
                setsid: PathBuf::from("/usr/bin/setsid"),
                runuser: PathBuf::from("/usr/sbin/runuser"),
                systemctl: PathBuf::from("/usr/bin/systemctl"),
                chown: PathBuf::from("/usr/bin/chown"),
                git: PathBuf::from("/usr/bin/git"),
            },
            version: env!("CARGO_PKG_VERSION").to_string(),
            timing: Timing::default(),
        }
    }

    /// An absolute guest path under `root`.
    pub fn path(&self, abs: &str) -> PathBuf {
        self.root.join(abs.trim_start_matches('/'))
    }
}

/// The agent's environment: the fixed values, then the setup's own (a later
/// entry wins when the process is spawned).
pub fn agent_env(setup_env: &[(String, String)]) -> Vec<(String, String)> {
    let fixed = [
        ("HOME", "/home/agent"),
        ("USER", "agent"),
        ("PATH", "/usr/local/bin:/usr/bin:/bin"),
        ("TERM", "xterm-256color"),
        ("LANG", "C.UTF-8"),
        ("HTTPS_PROXY", "http://127.0.0.1:3128"),
        ("HTTP_PROXY", "http://127.0.0.1:3128"),
        ("NO_PROXY", "localhost,127.0.0.1"),
    ];
    let mut out: Vec<(String, String)> = fixed
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    out.extend(setup_env.iter().cloned());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_maps_under_root() {
        let mut e = GuestEnv::system();
        assert_eq!(e.path("/work"), PathBuf::from("/work"));
        e.root = PathBuf::from("/x/g");
        assert_eq!(
            e.path("/run/saiife-guest/a"),
            PathBuf::from("/x/g/run/saiife-guest/a")
        );
    }

    #[test]
    fn agent_env_is_fixed_then_setup() {
        let e = agent_env(&[("FOO".into(), "bar".into())]);
        assert_eq!(e[0], ("HOME".into(), "/home/agent".into()));
        assert_eq!(e.len(), 9);
        assert_eq!(e[8], ("FOO".into(), "bar".into()));
    }
}
