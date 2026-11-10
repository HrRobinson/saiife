//! Process table entries (plan 19b, W17), free of Windows calls so Linux tests can use
//! them. `ffi::proc` fills them from a Toolhelp snapshot.

/// One line of a process snapshot: names, and where they can be read, the creation
/// time and the session. No command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcEntry {
    pub pid: u32,
    pub ppid: u32,
    /// The executable's file name, as Windows gives it: `Claude.exe`.
    pub exe: String,
    /// When the process was created, in 100 ns ticks since 1601 (a `FILETIME`).
    /// `None` when the reader may not open the process, or did not ask.
    pub created: Option<u64>,
    /// The process's Remote Desktop session id; `None` as for `created`.
    pub session: Option<u32>,
}

/// The name a session walk compares: lower case, without `.exe`.
pub fn comm_of(exe: &str) -> String {
    let lower = exe.to_lowercase();
    match lower.strip_suffix(".exe") {
        Some(stem) => stem.to_string(),
        None => lower,
    }
}

/// Whether `pid` is a descendant of `ancestor` in `snap`, at most `max_depth`
/// parent steps up (plan 21, Task 4: the co-signer ties the hook that bound a
/// call to the process that sent it). A process is not its own descendant.
///
/// The walk stops, with `false`, at a pid not in `snap`, at pid 0 (the idle
/// process) or 4 (System), and at a loop. Pids 0 and 4 are never an ancestor.
/// A parent pid can be stale after its process exits (it names whatever got
/// that pid later). Where both creation times are known, a parent created after
/// its child is such a reused pid, and the walk stops there with `false`. Where
/// both sessions are known, a `pid` in another session than `ancestor` is not its
/// descendant. Where they are not known (the reader may not open the process),
/// the parent pid alone decides, which is the residual risk.
///
/// Not a boundary against code of the same user: a process can be started with
/// any process of its own user as its parent (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`).
pub fn is_descendant(snap: &[ProcEntry], ancestor: u32, pid: u32, max_depth: usize) -> bool {
    let stops = |p: u32| p == 0 || p == 4;
    if stops(ancestor) {
        return false;
    }
    let entry = |p: u32| snap.iter().find(|e| e.pid == p);
    let known_apart =
        |a: Option<u32>, b: Option<u32>| matches!((a, b), (Some(a), Some(b)) if a != b);
    if known_apart(
        entry(pid).and_then(|e| e.session),
        entry(ancestor).and_then(|e| e.session),
    ) {
        return false;
    }
    let mut seen = vec![pid];
    let mut at = pid;
    for _ in 0..max_depth {
        if stops(at) {
            return false;
        }
        let Some(child) = entry(at) else {
            return false;
        };
        let parent = child.ppid;
        if seen.contains(&parent) {
            return false;
        }
        // A parent younger than its child: the pid was reused.
        let born_after = entry(parent)
            .and_then(|p| p.created)
            .zip(child.created)
            .is_some_and(|(p, c)| p > c);
        if born_after {
            return false;
        }
        if parent == ancestor {
            return true;
        }
        seen.push(parent);
        at = parent;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(pid: u32, ppid: u32) -> ProcEntry {
        ProcEntry {
            pid,
            ppid,
            exe: format!("p{pid}.exe"),
            created: None,
            session: None,
        }
    }

    /// `e(pid, ppid)` created at `created` in session `session`.
    fn et(pid: u32, ppid: u32, created: u64, session: u32) -> ProcEntry {
        ProcEntry {
            created: Some(created),
            session: Some(session),
            ..e(pid, ppid)
        }
    }

    #[test]
    fn parent_created_after_its_child_is_a_reused_pid() {
        // Claude Code (100) started at 10, its shell at 20, the hook at 30.
        let ok = vec![et(100, 50, 10, 1), et(200, 100, 20, 1), et(300, 200, 30, 1)];
        assert!(is_descendant(&ok, 100, 300, 3));
        // The hook's parent pid 200 now names a process created after the hook.
        let reused = vec![et(100, 50, 10, 1), et(200, 100, 40, 1), et(300, 200, 30, 1)];
        assert!(!is_descendant(&reused, 100, 300, 3));
        assert!(!is_descendant(&reused, 200, 300, 1));
        // The asker itself younger than its child.
        let young = vec![et(100, 50, 35, 1), et(200, 100, 20, 1), et(300, 200, 30, 1)];
        assert!(!is_descendant(&young, 100, 300, 3));
        // The same tick is not after.
        let same = vec![et(100, 50, 30, 1), et(300, 100, 30, 1)];
        assert!(is_descendant(&same, 100, 300, 1));
    }

    #[test]
    fn another_session_is_not_a_descendant() {
        let t = vec![et(100, 50, 10, 1), et(200, 100, 20, 1), et(300, 200, 30, 2)];
        assert!(!is_descendant(&t, 100, 300, 3));
        let t = vec![et(100, 50, 10, 2), et(200, 100, 20, 2), et(300, 200, 30, 2)];
        assert!(is_descendant(&t, 100, 300, 3));
    }

    #[test]
    fn unknown_times_and_sessions_leave_the_parent_pid() {
        // One side unknown: neither check applies.
        let t = vec![et(100, 50, 40, 1), e(200, 100), et(300, 200, 30, 1)];
        assert!(is_descendant(&t, 100, 300, 3));
        let t = vec![e(100, 50), et(300, 100, 30, 2)];
        assert!(is_descendant(&t, 100, 300, 1));
    }

    /// Claude Code (100), its shell (200), the hook (300), the hook's worker (400).
    fn tree() -> Vec<ProcEntry> {
        vec![
            e(4, 0),
            e(50, 4),
            e(100, 50),
            e(200, 100),
            e(300, 200),
            e(400, 300),
        ]
    }

    #[test]
    fn descendant_within_depth() {
        let t = tree();
        assert!(is_descendant(&t, 100, 300, 3));
        assert!(is_descendant(&t, 100, 300, 2));
        assert!(is_descendant(&t, 100, 200, 1));
        assert!(is_descendant(&t, 100, 400, 3));
        // A process is not its own descendant.
        assert!(!is_descendant(&t, 300, 300, 3));
    }

    #[test]
    fn not_descendant_beyond_depth() {
        let t = tree();
        assert!(!is_descendant(&t, 100, 300, 1));
        assert!(!is_descendant(&t, 50, 400, 3));
        assert!(!is_descendant(&t, 100, 300, 0));
        // Another branch, and a pid not in the snapshot.
        let mut t2 = t.clone();
        t2.push(e(900, 50));
        assert!(!is_descendant(&t2, 100, 900, 3));
        assert!(!is_descendant(&t, 100, 777, 3));
        // A child is not an ancestor.
        assert!(!is_descendant(&t, 300, 100, 3));
    }

    #[test]
    fn loop_in_ppids_stops() {
        let t = vec![e(10, 20), e(20, 30), e(30, 10)];
        assert!(!is_descendant(&t, 99, 10, usize::MAX));
        assert!(is_descendant(&t, 30, 10, 2));
        // A process that is its own parent.
        let t = vec![e(10, 10)];
        assert!(!is_descendant(&t, 10, 10, 3));
        assert!(!is_descendant(&t, 99, 10, 3));
    }

    #[test]
    fn pid_zero_and_four_stop() {
        let t = tree();
        // The walk never reaches System or the idle process as an ancestor.
        assert!(!is_descendant(&t, 4, 50, 3));
        assert!(!is_descendant(&t, 0, 4, 3));
        assert!(!is_descendant(&t, 0, 50, 3));
        // An entry whose parent is 0 or 4 ends the walk there.
        let t = vec![e(4, 0), e(60, 4), e(70, 60), e(0, 0)];
        assert!(!is_descendant(&t, 4, 70, 3));
        assert!(is_descendant(&t, 60, 70, 3));
    }

    #[test]
    fn comm_is_lower_case_without_exe() {
        assert_eq!(comm_of("Claude.EXE"), "claude");
        assert_eq!(comm_of("pwsh.exe"), "pwsh");
        assert_eq!(comm_of("System"), "system");
        assert_eq!(comm_of("a.exe.txt"), "a.exe.txt");
    }
}
