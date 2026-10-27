//! Who may approve or reject a request (spec §6.10.2). The approver must be
//! listed in `[approval] approvers` (by user name, or `group:<name>` through
//! the approver's current groups). The requester's own uid is refused under
//! `same_user = "deny"`, and under `"reauth"` must pass polkit
//! re-authentication; when that is unavailable it behaves as `"deny"`, with
//! its own reason.

use crate::reauth::{start_time_of, InFlight, Reauth, ReauthResult, REAUTH_TIMEOUT};
use crate::sessions::Proc;
use saiife_ipc::peer::PeerCred;
use saiife_policy::{ApprovalCfg, Directory, SameUser};
use std::fmt;

const GROUP_PREFIX: &str = "group:";
/// The `ReauthError` detail when `approver_user` does not resolve to the peer uid.
const MISMATCH: &str = "approver lookup mismatch";

/// The warning when same-user re-authentication cannot run (spec §6.10.2).
pub const REAUTH_UNAVAILABLE: &str =
    "re-authentication unavailable: approvals need a second account";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    NotApprover,
    SameUserDenied,
    ReauthUnavailable,
    ReauthFailed,
    ReauthError(String),
    /// Another re-authentication for the same uid is still running.
    ReauthBusy,
}

impl Refusal {
    /// The `rule` recorded with the refusal.
    pub fn rule(&self) -> &'static str {
        match self {
            Refusal::NotApprover => "not_approver",
            Refusal::SameUserDenied => "same_user",
            Refusal::ReauthUnavailable => "reauth_unavailable",
            Refusal::ReauthFailed => "reauth_failed",
            Refusal::ReauthError(_) => "reauth_error",
            Refusal::ReauthBusy => "reauth_busy",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::NotApprover => f.write_str("not listed in [approval] approvers"),
            Refusal::SameUserDenied => {
                f.write_str("the requester cannot approve its own request (same_user = \"deny\")")
            }
            Refusal::ReauthUnavailable => f.write_str(REAUTH_UNAVAILABLE),
            Refusal::ReauthFailed => f.write_str("re-authentication failed"),
            Refusal::ReauthError(e) => write!(f, "re-authentication error: {e}"),
            Refusal::ReauthBusy => {
                f.write_str("another re-authentication for this user is still running")
            }
        }
    }
}

/// Whether `user` is listed in `approvers`, directly or by a current group.
pub fn is_approver(cfg: &ApprovalCfg, dir: &dyn Directory, user: &str) -> bool {
    let mut groups: Option<Vec<String>> = None;
    cfg.approvers
        .iter()
        .any(|e| match e.strip_prefix(GROUP_PREFIX) {
            Some(g) => groups
                .get_or_insert_with(|| dir.groups_of(user))
                .iter()
                .any(|x| x == g),
            None => e == user,
        })
}

/// May the CLI connected as `peer` decide a request made by
/// `requester_uid`? The approver's uid is `peer.uid`. Every error refuses
/// (fail closed).
///
/// - `approver_user` must be the daemon's own lookup of `peer.uid`
///   (`dir.name_of(peer.uid)`), never a client-supplied name. It is checked
///   against `dir` again. A name that does not resolve to `peer.uid` (a
///   caller bug or a directory changing underneath) is
///   `ReauthError("approver lookup mismatch")`, so it is logged as an error
///   rather than as an unlisted approver.
/// - `start_time` is the peer process's start time (`/proc/<pid>/stat`
///   field 22), read by the caller when the connection was accepted. After
///   polkit authorizes, it is read again through `proc`, and a changed start
///   time or a vanished pid (the pid was reused) is `ReauthError`.
/// - Same-user re-authentication **blocks for up to 120 s** (the password
///   prompt), so call this from `spawn_blocking`, never on a runtime
///   thread. At most one runs per uid; a concurrent one is `ReauthBusy`.
#[allow(clippy::too_many_arguments)]
pub fn may_decide(
    cfg: &ApprovalCfg,
    dir: &dyn Directory,
    approver_user: &str,
    requester_uid: u32,
    reauth: &dyn Reauth,
    peer: &PeerCred,
    start_time: u64,
    proc: &dyn Proc,
) -> Result<(), Refusal> {
    let approver_uid = peer.uid;
    if dir.user(approver_user).map(|u| u.uid) != Some(approver_uid) {
        return Err(Refusal::ReauthError(MISMATCH.to_string()));
    }
    if !is_approver(cfg, dir, approver_user) {
        return Err(Refusal::NotApprover);
    }
    if approver_uid != requester_uid {
        return Ok(());
    }
    match cfg.same_user {
        SameUser::Deny => Err(Refusal::SameUserDenied),
        SameUser::Reauth => {
            if !reauth.available() {
                return Err(Refusal::ReauthUnavailable);
            }
            let Some(_slot) = InFlight::begin(approver_uid) else {
                return Err(Refusal::ReauthBusy);
            };
            match reauth.check(peer.pid, start_time, approver_uid, REAUTH_TIMEOUT) {
                ReauthResult::Authorized => match start_time_of(proc, peer.pid) {
                    Some(now) if now == start_time => Ok(()),
                    Some(_) => Err(Refusal::ReauthError(format!(
                        "process {} changed during re-authentication",
                        peer.pid
                    ))),
                    None => Err(Refusal::ReauthError(format!(
                        "process {} exited during re-authentication",
                        peer.pid
                    ))),
                },
                ReauthResult::Denied => Err(Refusal::ReauthFailed),
                ReauthResult::Unavailable => Err(Refusal::ReauthUnavailable),
                ReauthResult::Error(e) => Err(Refusal::ReauthError(e)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions::ProcStat;
    use saiife_policy::FixedDirectory;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Barrier, Mutex};
    use std::time::Duration;

    const PASSWD: &str = "alice:x:1000:1000::/home/alice:/bin/sh\n\
        bob:x:1001:1001::/home/bob:/bin/sh\n\
        carol:x:1002:3000::/home/carol:/bin/sh\n\
        mallory:x:1003:1003::/home/mallory:/bin/sh\n\
        busy:x:990100:990100::/:/bin/sh\n\
        other:x:990101:990101::/:/bin/sh\n\
        recheck:x:990102:990102::/:/bin/sh\n";
    const GROUP: &str = "alice:x:1000:\nbob:x:1001:\nops:x:2000:alice,bob\nleads:x:3000:\n";
    const PID: u32 = 5555;
    const START: u64 = 424242;

    struct FakeReauth {
        available: bool,
        result: ReauthResult,
        calls: Mutex<Vec<(u32, u64, u32, Duration)>>,
    }

    impl FakeReauth {
        fn new(available: bool, result: ReauthResult) -> FakeReauth {
            FakeReauth {
                available,
                result,
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl Reauth for FakeReauth {
        fn available(&self) -> bool {
            self.available
        }
        fn check(&self, pid: u32, start: u64, uid: u32, timeout: Duration) -> ReauthResult {
            self.calls.lock().unwrap().push((pid, start, uid, timeout));
            self.result.clone()
        }
    }

    /// `/proc` stand-in: each `stat` read returns the next start time in
    /// `starts` (the last one repeats); `None` is a vanished pid.
    struct FakeProc {
        starts: Vec<Option<u64>>,
        reads: AtomicU64,
    }

    impl FakeProc {
        fn new(starts: &[Option<u64>]) -> FakeProc {
            FakeProc {
                starts: starts.to_vec(),
                reads: AtomicU64::new(0),
            }
        }
        fn steady() -> FakeProc {
            FakeProc::new(&[Some(START)])
        }
    }

    impl Proc for FakeProc {
        fn stat(&self, _pid: u32) -> Option<ProcStat> {
            let i = self.reads.fetch_add(1, Ordering::SeqCst) as usize;
            let start = self.starts[i.min(self.starts.len() - 1)]?;
            Some(ProcStat {
                ppid: 1,
                comm: "saiife".into(),
                start_time: start,
            })
        }
        fn cmdline(&self, _pid: u32) -> Option<Vec<String>> {
            None
        }
    }

    fn cfg(approvers: &[&str], same_user: SameUser) -> ApprovalCfg {
        ApprovalCfg {
            approvers: approvers.iter().map(|s| s.to_string()).collect(),
            same_user,
            ..ApprovalCfg::default()
        }
    }

    fn peer(uid: u32) -> PeerCred {
        PeerCred {
            uid,
            gid: uid,
            pid: PID,
        }
    }

    #[test]
    fn may_decide_table() {
        use ReauthResult as R;
        use SameUser::{Deny, Reauth as Re};
        let dir = FixedDirectory::from_text(PASSWD, GROUP);
        let ok = || FakeReauth::new(true, R::Authorized);
        let fake = FakeReauth::new;
        // (approvers, same_user, peer uid, looked-up name, requester uid,
        //  reauth, reauth expected to run, want)
        type Row<'a> = (
            &'a [&'a str],
            SameUser,
            u32,
            &'a str,
            u32,
            FakeReauth,
            bool,
            Result<(), Refusal>,
        );
        let not = Err(Refusal::NotApprover);
        let mismatch = Err(Refusal::ReauthError("approver lookup mismatch".into()));
        #[rustfmt::skip]
        let rows: Vec<Row> = vec![
            // Not listed.
            (&["bob"], Deny, 1003, "mallory", 1000, ok(), false, not.clone()),
            (&[], Re, 1000, "alice", 1000, ok(), false, not.clone()),
            (&["group:leads"], Deny, 1003, "mallory", 1000, ok(), false, not.clone()),
            // `group:` never matches a user name, and a user never a group.
            (&["group:alice"], Deny, 1001, "bob", 1000, ok(), false, not.clone()),
            (&["ops"], Deny, 1001, "bob", 1000, ok(), false, not.clone()),
            // The name must resolve to the peer's uid: a mismatch or an
            // unknown name is an error, not an unlisted approver.
            (&["bob"], Deny, 1003, "bob", 1000, ok(), false, mismatch.clone()),
            (&["ghost"], Deny, 1003, "ghost", 1000, ok(), false, mismatch.clone()),
            // A second uid, listed directly or by group.
            (&["bob"], Deny, 1001, "bob", 1000, ok(), false, Ok(())),
            (&["group:ops"], Deny, 1001, "bob", 1000, ok(), false, Ok(())),
            // Primary-group membership counts.
            (&["group:leads"], Deny, 1002, "carol", 1000, ok(), false, Ok(())),
            // A second uid never needs reauth, even when it is unavailable.
            (&["bob"], Re, 1001, "bob", 1000, fake(false, R::Error("x".into())), false, Ok(())),
            // Same uid, deny: direct and through a group.
            (&["alice"], Deny, 1000, "alice", 1000, ok(), false, Err(Refusal::SameUserDenied)),
            (&["group:ops"], Deny, 1000, "alice", 1000, ok(), false, Err(Refusal::SameUserDenied)),
            // Same uid, reauth.
            (&["alice"], Re, 1000, "alice", 1000, ok(), true, Ok(())),
            (&["group:ops"], Re, 1000, "alice", 1000, ok(), true, Ok(())),
            (&["alice"], Re, 1000, "alice", 1000, fake(true, R::Denied), true, Err(Refusal::ReauthFailed)),
            (&["alice"], Re, 1000, "alice", 1000, fake(true, R::Error("timed out".into())), true, Err(Refusal::ReauthError("timed out".into()))),
            (&["alice"], Re, 1000, "alice", 1000, fake(true, R::Unavailable), true, Err(Refusal::ReauthUnavailable)),
            (&["alice"], Re, 1000, "alice", 1000, fake(false, R::Authorized), false, Err(Refusal::ReauthUnavailable)),
        ];
        for (i, (approvers, same, uid, name, ruid, fake, runs, want)) in
            rows.into_iter().enumerate()
        {
            let c = cfg(approvers, same);
            let p = FakeProc::steady();
            let got = may_decide(&c, &dir, name, ruid, &fake, &peer(uid), START, &p);
            assert_eq!(got, want, "row {i}");
            let calls = fake.calls.lock().unwrap();
            if runs {
                assert_eq!(*calls, vec![(PID, START, uid, REAUTH_TIMEOUT)], "row {i}");
            } else {
                assert!(calls.is_empty(), "row {i}: reauth ran: {calls:?}");
            }
        }
    }

    #[test]
    fn reauth_rechecks_the_peer_start_time() {
        let dir = FixedDirectory::from_text(PASSWD, GROUP);
        let c = cfg(&["recheck"], SameUser::Reauth);
        let ok = FakeReauth::new(true, ReauthResult::Authorized);
        let run =
            |p: &FakeProc| may_decide(&c, &dir, "recheck", 990102, &ok, &peer(990102), START, p);

        // The pid was reused while the prompt was up.
        let changed = FakeProc::new(&[Some(START + 1)]);
        match run(&changed) {
            Err(Refusal::ReauthError(e)) => assert!(e.contains("changed"), "{e}"),
            other => panic!("expected ReauthError, got {other:?}"),
        }
        // The process exited.
        let gone = FakeProc::new(&[None]);
        match run(&gone) {
            Err(Refusal::ReauthError(e)) => assert!(e.contains("exited"), "{e}"),
            other => panic!("expected ReauthError, got {other:?}"),
        }
        // Unchanged: read exactly once, after the check.
        let same = FakeProc::steady();
        assert_eq!(run(&same), Ok(()));
        assert_eq!(same.reads.load(Ordering::SeqCst), 1);

        // A refused check never reads it.
        let denied = FakeReauth::new(true, ReauthResult::Denied);
        let p = FakeProc::new(&[Some(START + 1)]);
        assert_eq!(
            may_decide(
                &c,
                &dir,
                "recheck",
                990102,
                &denied,
                &peer(990102),
                START,
                &p
            ),
            Err(Refusal::ReauthFailed)
        );
        assert_eq!(p.reads.load(Ordering::SeqCst), 0);
    }

    /// Blocks inside `check` until the test releases it.
    struct BlockingReauth {
        entered: Barrier,
        release: Barrier,
    }

    impl Reauth for BlockingReauth {
        fn available(&self) -> bool {
            true
        }
        fn check(&self, _pid: u32, _start: u64, _uid: u32, _t: Duration) -> ReauthResult {
            self.entered.wait();
            self.release.wait();
            ReauthResult::Authorized
        }
    }

    #[test]
    fn one_reauth_in_flight_per_uid() {
        // uids 990100-990102 are used by one test each (the slot set is
        // process-wide).
        let dir = FixedDirectory::from_text(PASSWD, GROUP);
        let c = cfg(&["busy", "other"], SameUser::Reauth);
        let blocking = BlockingReauth {
            entered: Barrier::new(2),
            release: Barrier::new(2),
        };
        let ok = FakeReauth::new(true, ReauthResult::Authorized);
        std::thread::scope(|s| {
            let first = s.spawn(|| {
                let p = FakeProc::steady();
                may_decide(
                    &c,
                    &dir,
                    "busy",
                    990100,
                    &blocking,
                    &peer(990100),
                    START,
                    &p,
                )
            });
            blocking.entered.wait();
            // Same uid while the first prompt is up: busy, no second check.
            let p = FakeProc::steady();
            let same = may_decide(&c, &dir, "busy", 990100, &ok, &peer(990100), START, &p);
            let checks = ok.calls.lock().unwrap().len();
            // Another uid is not blocked.
            let other = may_decide(&c, &dir, "other", 990101, &ok, &peer(990101), START, &p);
            // Release before asserting, so a failure panics instead of hanging.
            blocking.release.wait();
            assert_eq!(same, Err(Refusal::ReauthBusy));
            assert_eq!(checks, 0);
            assert_eq!(other, Ok(()));
            assert_eq!(first.join().unwrap(), Ok(()));
        });
        // The slot is free again.
        let p = FakeProc::steady();
        assert_eq!(
            may_decide(&c, &dir, "busy", 990100, &ok, &peer(990100), START, &p),
            Ok(())
        );
    }

    #[test]
    fn rules_and_messages() {
        let all = [
            (Refusal::NotApprover, "not_approver"),
            (Refusal::SameUserDenied, "same_user"),
            (Refusal::ReauthUnavailable, "reauth_unavailable"),
            (Refusal::ReauthFailed, "reauth_failed"),
            (Refusal::ReauthError("e".into()), "reauth_error"),
            (Refusal::ReauthBusy, "reauth_busy"),
        ];
        for (r, rule) in all {
            assert_eq!(r.rule(), rule);
            assert!(!r.to_string().is_empty());
        }
        assert_eq!(
            Refusal::ReauthUnavailable.to_string(),
            "re-authentication unavailable: approvals need a second account"
        );
    }
}
