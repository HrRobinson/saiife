//! Session attribution (spec §6.9.3, §6.3): which agent session a request
//! belongs to, found by walking the requester's ancestors in `/proc`. The
//! pid and its start time together name one process for good, so a reused
//! pid is never mistaken for the agent.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Mutex;

/// Most levels the walk climbs.
const MAX_DEPTH: usize = 64;
/// Most sessions remembered.
pub const MAX_SESSIONS: usize = 4096;
/// Longest session id kept; the id is client-supplied.
pub const MAX_SESSION_ID: usize = 128;
/// Most of a cmdline read.
const MAX_CMDLINE: u64 = 64 * 1024;
const AGENTS: [&str; 3] = ["claude", "codex", "gemini"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcStat {
    pub ppid: u32,
    pub comm: String,
    pub start_time: u64,
}

pub trait Proc {
    fn stat(&self, pid: u32) -> Option<ProcStat>;
    fn cmdline(&self, pid: u32) -> Option<Vec<String>>;
}

/// Reads `<root>/<pid>/stat` and `cmdline`; production root is `/proc`.
pub struct RealProc {
    root: PathBuf,
}

impl RealProc {
    pub fn new(root: impl Into<PathBuf>) -> RealProc {
        RealProc { root: root.into() }
    }
}

impl Proc for RealProc {
    fn stat(&self, pid: u32) -> Option<ProcStat> {
        let s = std::fs::read(self.root.join(pid.to_string()).join("stat")).ok()?;
        parse_stat(&String::from_utf8_lossy(&s))
    }

    fn cmdline(&self, pid: u32) -> Option<Vec<String>> {
        use std::io::Read;
        let f = std::fs::File::open(self.root.join(pid.to_string()).join("cmdline")).ok()?;
        let mut b = Vec::new();
        f.take(MAX_CMDLINE).read_to_end(&mut b).ok()?;
        Some(
            b.split(|&c| c == 0)
                .filter(|a| !a.is_empty())
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect(),
        )
    }
}

/// macOS: `sysctl(KERN_PROC_PID)` through `saiife-darwin`. `start_time` is
/// the process start in microseconds since the epoch. The command line
/// (`KERN_PROCARGS2`) is readable only for one's own uid, so `cmdline` is
/// always `None` and a `node` ancestor never matches an agent (decision 6):
/// such a request gets no session, the stricter shared bucket. Attribution
/// only; nothing is allowed because of it.
#[cfg(target_os = "macos")]
pub struct MacProc;

#[cfg(target_os = "macos")]
impl Proc for MacProc {
    fn stat(&self, pid: u32) -> Option<ProcStat> {
        let i = saiife_darwin::proc_info(pid)?;
        Some(ProcStat {
            ppid: i.ppid,
            comm: i.comm,
            start_time: i.start_us,
        })
    }

    fn cmdline(&self, _pid: u32) -> Option<Vec<String>> {
        None
    }
}

/// The host's process table: `/proc` on Linux, `KERN_PROC_PID` on macOS.
#[cfg(target_os = "linux")]
pub fn host_proc() -> Box<dyn Proc + Send + Sync> {
    Box::new(RealProc::new("/proc"))
}

/// The host's process table: `/proc` on Linux, `KERN_PROC_PID` on macOS.
#[cfg(target_os = "macos")]
pub fn host_proc() -> Box<dyn Proc + Send + Sync> {
    Box::new(MacProc)
}

/// Other unix: no process table, so no session is ever attributed.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn host_proc() -> Box<dyn Proc + Send + Sync> {
    struct NoProc;
    impl Proc for NoProc {
        fn stat(&self, _: u32) -> Option<ProcStat> {
            None
        }
        fn cmdline(&self, _: u32) -> Option<Vec<String>> {
            None
        }
    }
    Box::new(NoProc)
}

/// `pid (comm) state ppid ... starttime(22)`. The comm may hold spaces and
/// parentheses, so it spans the first `(` to the last `)`.
fn parse_stat(s: &str) -> Option<ProcStat> {
    let open = s.find('(')?;
    let close = s.rfind(')')?;
    if close < open {
        return None;
    }
    let comm = s[open + 1..close].to_string();
    // After the comm: field 3 (state) onward.
    let rest: Vec<&str> = s[close + 1..].split_whitespace().collect();
    let ppid = rest.get(1)?.parse().ok()?;
    let start_time = rest.get(19)?.parse().ok()?; // field 22
    Some(ProcStat {
        ppid,
        comm,
        start_time,
    })
}

fn is_agent(p: &dyn Proc, pid: u32, comm: &str) -> bool {
    if AGENTS.contains(&comm) {
        return true;
    }
    if comm != "node" {
        return false;
    }
    p.cmdline(pid).is_some_and(|argv| {
        argv.iter().any(|a| {
            let base = a.rsplit('/').next().unwrap_or(a);
            AGENTS
                .iter()
                .any(|n| base == *n || base.strip_prefix(n).is_some_and(|r| r.starts_with('.')))
        })
    })
}

/// The nearest agent among `pid` and its ancestors, as `(pid, start_time)`.
/// `None` when there is none within 64 levels, or when the agent's start
/// time changed during the walk (the pid was reused).
pub fn agent_ancestor(p: &dyn Proc, pid: u32) -> Option<(u32, u64)> {
    let first = p.stat(pid)?.start_time;
    let mut cur = pid;
    let mut found = None;
    for _ in 0..MAX_DEPTH {
        if cur == 0 {
            return None;
        }
        let st = p.stat(cur)?;
        if is_agent(p, cur, &st.comm) {
            let again = p.stat(cur)?;
            if again.start_time != st.start_time {
                return None;
            }
            found = Some((cur, st.start_time));
            break;
        }
        if cur == 1 || st.ppid == cur {
            return None;
        }
        cur = st.ppid;
    }
    // The requester must still be the same process after the walk.
    (p.stat(pid)?.start_time == first)
        .then_some(found)
        .flatten()
}

#[derive(Default)]
struct Inner {
    map: HashMap<(u32, u64), String>,
    order: VecDeque<(u32, u64)>,
}

/// Agent process -> its latest session id.
#[derive(Default)]
pub struct Sessions {
    inner: Mutex<Inner>,
}

impl Sessions {
    pub fn new() -> Sessions {
        Sessions::default()
    }

    /// The newest session wins. Beyond 4 096 entries the oldest goes.
    pub fn record(&self, ancestor: (u32, u64), session_id: &str) {
        if session_id.len() > MAX_SESSION_ID {
            return;
        }
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if g.map.insert(ancestor, session_id.to_string()).is_some() {
            g.order.retain(|k| *k != ancestor);
        }
        g.order.push_back(ancestor);
        while g.map.len() > MAX_SESSIONS {
            if let Some(old) = g.order.pop_front() {
                g.map.remove(&old);
            } else {
                break;
            }
        }
    }

    pub fn lookup(&self, ancestor: (u32, u64)) -> Option<String> {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.map.get(&ancestor).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    fn put(root: &Path, pid: u32, comm: &str, ppid: u32, start: u64, argv: &[&str]) {
        let d = root.join(pid.to_string());
        fs::create_dir_all(&d).unwrap();
        // After the comm: state, ppid, 17 fillers, then starttime (field 22).
        let stat = format!("{pid} ({comm}) S {ppid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {start} 0 0");
        fs::write(d.join("stat"), stat).unwrap();
        fs::write(d.join("cmdline"), argv.join("\0")).unwrap();
    }

    fn tree() -> (tempfile::TempDir, RealProc) {
        let t = tempfile::tempdir().unwrap();
        let p = RealProc::new(t.path());
        (t, p)
    }

    #[test]
    fn stat_fixture_has_start_in_field_22() {
        let (t, p) = tree();
        put(t.path(), 5, "x", 1, 777, &[]);
        assert_eq!(p.stat(5).unwrap().start_time, 777);
        assert_eq!(p.stat(5).unwrap().ppid, 1);
    }

    #[test]
    fn walks_to_claude() {
        let (t, p) = tree();
        put(t.path(), 1, "init", 0, 1, &[]);
        put(t.path(), 100, "claude", 1, 500, &[]);
        put(t.path(), 200, "bash", 100, 600, &[]);
        put(t.path(), 300, "saiife", 200, 700, &[]);
        assert_eq!(agent_ancestor(&p, 300), Some((100, 500)));
    }

    #[test]
    fn node_with_codex_argv_matches() {
        let (t, p) = tree();
        put(t.path(), 1, "init", 0, 1, &[]);
        put(
            t.path(),
            100,
            "node",
            1,
            500,
            &["node", "/usr/lib/node_modules/@openai/codex/bin/codex.js"],
        );
        put(t.path(), 200, "sh", 100, 600, &[]);
        assert_eq!(agent_ancestor(&p, 200), Some((100, 500)));
        put(t.path(), 101, "node", 1, 501, &["node", "server.js"]);
        put(t.path(), 201, "sh", 101, 601, &[]);
        assert_eq!(agent_ancestor(&p, 201), None);
    }

    #[test]
    fn comm_with_parens_parsed() {
        let (t, p) = tree();
        put(t.path(), 7, "(a) b", 42, 900, &[]);
        let s = p.stat(7).unwrap();
        assert_eq!(s.comm, "(a) b");
        assert_eq!(s.ppid, 42);
        assert_eq!(s.start_time, 900);
    }

    /// Every stat read reports a new start time, as a reused pid would.
    struct Flip(std::cell::Cell<u64>);
    impl Proc for Flip {
        fn stat(&self, pid: u32) -> Option<ProcStat> {
            let n = self.0.get();
            self.0.set(n + 1);
            Some(ProcStat {
                ppid: 1,
                comm: if pid == 10 { "claude" } else { "sh" }.into(),
                start_time: 100 + n,
            })
        }
        fn cmdline(&self, _: u32) -> Option<Vec<String>> {
            None
        }
    }

    /// The requester's own stat changes on its second read only.
    struct RequesterFlip(std::cell::Cell<u32>);
    impl Proc for RequesterFlip {
        fn stat(&self, pid: u32) -> Option<ProcStat> {
            let (comm, ppid, start) = if pid == 20 {
                let n = self.0.get();
                self.0.set(n + 1);
                ("sh", 10, if n == 0 { 5 } else { 6 })
            } else {
                ("claude", 1, 1)
            };
            Some(ProcStat {
                ppid,
                comm: comm.into(),
                start_time: start,
            })
        }
        fn cmdline(&self, _: u32) -> Option<Vec<String>> {
            None
        }
    }

    #[test]
    fn requester_start_time_change_mid_walk_gives_none() {
        assert_eq!(agent_ancestor(&RequesterFlip(Default::default()), 20), None);
    }

    #[test]
    fn long_session_id_not_stored() {
        let s = Sessions::new();
        s.record((1, 1), &"x".repeat(MAX_SESSION_ID + 1));
        assert_eq!(s.lookup((1, 1)), None);
        s.record((1, 1), &"x".repeat(MAX_SESSION_ID));
        assert!(s.lookup((1, 1)).is_some());
    }

    #[test]
    fn pid_reuse_changes_start_time_gives_none() {
        assert_eq!(agent_ancestor(&Flip(Default::default()), 10), None);
    }

    #[test]
    fn loop_and_depth_capped() {
        let (t, p) = tree();
        put(t.path(), 10, "a", 11, 1, &[]);
        put(t.path(), 11, "b", 10, 1, &[]);
        assert_eq!(agent_ancestor(&p, 10), None);
        // A chain deeper than 64 with the agent at the top is not reached.
        for i in 1000..1100u32 {
            put(t.path(), i, "sh", i + 1, 1, &[]);
        }
        put(t.path(), 1100, "claude", 1, 9, &[]);
        assert_eq!(agent_ancestor(&p, 1000), None);
        assert_eq!(agent_ancestor(&p, 1040), Some((1100, 9)));
    }

    #[test]
    fn double_fork_escape_lands_in_null_session() {
        let (t, p) = tree();
        put(t.path(), 1, "init", 0, 1, &[]);
        put(t.path(), 500, "saiife", 1, 5, &[]);
        assert_eq!(agent_ancestor(&p, 500), None);
        assert_eq!(agent_ancestor(&p, 999), None); // vanished
    }

    /// A process table as macOS gives it: names and parents, never a
    /// command line.
    struct NoArgv(HashMap<u32, (u32, &'static str, u64)>);
    impl Proc for NoArgv {
        fn stat(&self, pid: u32) -> Option<ProcStat> {
            let (ppid, comm, start_time) = *self.0.get(&pid)?;
            Some(ProcStat {
                ppid,
                comm: comm.into(),
                start_time,
            })
        }
        fn cmdline(&self, _: u32) -> Option<Vec<String>> {
            None
        }
    }

    #[test]
    fn node_ancestor_has_no_session() {
        let p = NoArgv(HashMap::from([
            (1, (0, "launchd", 1)),
            (100, (1, "node", 500)),
            (200, (100, "zsh", 600)),
            (300, (200, "saiife", 700)),
        ]));
        let s = Sessions::new();
        s.record((100, 500), "gemini-session");
        let a = agent_ancestor(&p, 300);
        assert_eq!(a, None);
        assert_eq!(a.and_then(|a| s.lookup(a)), None);
        // A named agent still matches without a command line.
        let p = NoArgv(HashMap::from([
            (1, (0, "launchd", 1)),
            (100, (1, "claude", 500)),
            (300, (100, "saiife", 700)),
        ]));
        assert_eq!(agent_ancestor(&p, 300), Some((100, 500)));
    }

    #[test]
    fn gone_pid_has_no_session() {
        let p = NoArgv(HashMap::from([
            (1, (0, "launchd", 1)),
            (100, (1, "claude", 500)),
        ]));
        let s = Sessions::new();
        s.record((100, 500), "s");
        // The requester (pid 300) has exited: no session, no crash.
        assert_eq!(agent_ancestor(&p, 300).and_then(|a| s.lookup(a)), None);
        // Its parent has exited mid-chain: likewise.
        let p = NoArgv(HashMap::from([(300, (250, "saiife", 700))]));
        assert_eq!(agent_ancestor(&p, 300), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mac_proc_walks_to_parent() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .unwrap();
        let st = MacProc.stat(child.id());
        child.kill().unwrap();
        child.wait().unwrap();
        let st = st.expect("the child is in the process table");
        assert_eq!(st.ppid, std::process::id());
        assert_eq!(st.comm, "sleep");
        assert!(MacProc.cmdline(std::process::id()).is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mac_proc_start_time_detects_reuse() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .unwrap();
        let pid = child.id();
        let real = crate::reauth::start_time_of(&MacProc, pid);
        let again = crate::reauth::start_time_of(&MacProc, pid);
        child.kill().unwrap();
        child.wait().unwrap();
        let real = real.expect("the child has a start time");
        assert_eq!(again, Some(real));
        // A start time stored for an earlier process of this pid differs.
        let stored = real - 1;
        assert_ne!(crate::reauth::start_time_of(&MacProc, pid), Some(stored));
        // The reaped pid is gone (or reused by a later process, which then
        // has another start time).
        assert_ne!(crate::reauth::start_time_of(&MacProc, pid), Some(real));
    }

    #[test]
    fn eviction_at_4096() {
        let s = Sessions::new();
        for i in 0..4096u32 {
            s.record((i, 1), &format!("s{i}"));
        }
        assert_eq!(s.lookup((0, 1)).as_deref(), Some("s0"));
        s.record((9999, 1), "new");
        assert_eq!(s.lookup((0, 1)), None);
        assert_eq!(s.lookup((1, 1)).as_deref(), Some("s1"));
        s.record((1, 1), "again");
        assert_eq!(s.lookup((1, 1)).as_deref(), Some("again"));
        assert_eq!(s.lookup((9999, 1)).as_deref(), Some("new"));
    }
}
