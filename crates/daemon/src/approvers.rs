//! Who may approve or reject a request (spec §6.10.2). The approver must be
//! listed in `[approval] approvers` (by user name, or `group:<name>` through
//! the approver's current groups). The requester's own uid is refused under
//! `same_user = "deny"`, and under `"reauth"` must pass polkit
//! re-authentication; when that is unavailable it behaves as `"deny"`, with
//! its own reason.

use crate::reauth::{Reauth, ReauthResult, REAUTH_TIMEOUT};
use saiife_ipc::peer::PeerCred;
use saiife_policy::{ApprovalCfg, Directory, SameUser};
use std::fmt;

const GROUP_PREFIX: &str = "group:";

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

/// May `approver_uid` (named `approver_user`, connected as `peer`, whose
/// process started at `start_time`) decide a request made by
/// `requester_uid`? Every error refuses (fail closed).
#[allow(clippy::too_many_arguments)]
pub fn may_decide(
    cfg: &ApprovalCfg,
    dir: &dyn Directory,
    approver_uid: u32,
    approver_user: &str,
    requester_uid: u32,
    reauth: &dyn Reauth,
    peer: &PeerCred,
    start_time: u64,
) -> Result<(), Refusal> {
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
            match reauth.check(peer.pid, start_time, peer.uid, REAUTH_TIMEOUT) {
                ReauthResult::Authorized => Ok(()),
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
    use saiife_policy::FixedDirectory;
    use std::sync::Mutex;
    use std::time::Duration;

    const PASSWD: &str = "alice:x:1000:1000::/home/alice:/bin/sh\n\
        bob:x:1001:1001::/home/bob:/bin/sh\n\
        carol:x:1002:3000::/home/carol:/bin/sh\n\
        mallory:x:1003:1003::/home/mallory:/bin/sh\n";
    const GROUP: &str = "alice:x:1000:\nbob:x:1001:\nops:x:2000:alice,bob\nleads:x:3000:\n";

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

    fn cfg(approvers: &[&str], same_user: SameUser) -> ApprovalCfg {
        ApprovalCfg {
            approvers: approvers.iter().map(|s| s.to_string()).collect(),
            same_user,
            ..ApprovalCfg::default()
        }
    }

    #[test]
    fn may_decide_table() {
        use ReauthResult as R;
        use SameUser::{Deny, Reauth as Re};
        let dir = FixedDirectory::from_text(PASSWD, GROUP);
        let authorized = || FakeReauth::new(true, R::Authorized);
        // (approvers, same_user, approver uid, name, requester uid, reauth, want)
        type Row<'a> = (
            &'a [&'a str],
            SameUser,
            u32,
            &'a str,
            u32,
            FakeReauth,
            Result<(), Refusal>,
        );
        let rows: Vec<Row> = vec![
            // Not listed.
            (
                &["bob"],
                Deny,
                1003,
                "mallory",
                1000,
                authorized(),
                Err(Refusal::NotApprover),
            ),
            (
                &[],
                Re,
                1000,
                "alice",
                1000,
                authorized(),
                Err(Refusal::NotApprover),
            ),
            (
                &["group:leads"],
                Deny,
                1003,
                "mallory",
                1000,
                authorized(),
                Err(Refusal::NotApprover),
            ),
            // `group:` never matches a user name, and a user never a group.
            (
                &["group:alice"],
                Deny,
                1001,
                "bob",
                1000,
                authorized(),
                Err(Refusal::NotApprover),
            ),
            (
                &["ops"],
                Deny,
                1001,
                "bob",
                1000,
                authorized(),
                Err(Refusal::NotApprover),
            ),
            // A second uid, listed directly or by group.
            (&["bob"], Deny, 1001, "bob", 1000, authorized(), Ok(())),
            (
                &["group:ops"],
                Deny,
                1001,
                "bob",
                1000,
                authorized(),
                Ok(()),
            ),
            // Primary-group membership counts.
            (
                &["group:leads"],
                Deny,
                1002,
                "carol",
                1000,
                authorized(),
                Ok(()),
            ),
            // A second uid never needs reauth, even when it is unavailable.
            (
                &["bob"],
                Re,
                1001,
                "bob",
                1000,
                FakeReauth::new(false, R::Error("x".into())),
                Ok(()),
            ),
            // Same uid, deny: direct and through a group.
            (
                &["alice"],
                Deny,
                1000,
                "alice",
                1000,
                authorized(),
                Err(Refusal::SameUserDenied),
            ),
            (
                &["group:ops"],
                Deny,
                1000,
                "alice",
                1000,
                authorized(),
                Err(Refusal::SameUserDenied),
            ),
            // Same uid, reauth.
            (&["alice"], Re, 1000, "alice", 1000, authorized(), Ok(())),
            (
                &["group:ops"],
                Re,
                1000,
                "alice",
                1000,
                authorized(),
                Ok(()),
            ),
            (
                &["alice"],
                Re,
                1000,
                "alice",
                1000,
                FakeReauth::new(true, R::Denied),
                Err(Refusal::ReauthFailed),
            ),
            (
                &["alice"],
                Re,
                1000,
                "alice",
                1000,
                FakeReauth::new(true, R::Error("timed out".into())),
                Err(Refusal::ReauthError("timed out".into())),
            ),
            (
                &["alice"],
                Re,
                1000,
                "alice",
                1000,
                FakeReauth::new(true, R::Unavailable),
                Err(Refusal::ReauthUnavailable),
            ),
            (
                &["alice"],
                Re,
                1000,
                "alice",
                1000,
                FakeReauth::new(false, R::Authorized),
                Err(Refusal::ReauthUnavailable),
            ),
        ];
        for (i, (approvers, same, auid, name, ruid, fake, want)) in rows.into_iter().enumerate() {
            let c = cfg(approvers, same);
            let peer = PeerCred {
                uid: auid,
                gid: auid,
                pid: 5555,
            };
            let got = may_decide(&c, &dir, auid, name, ruid, &fake, &peer, 424242);
            assert_eq!(got, want, "row {i}");
            let calls = fake.calls.lock().unwrap();
            let expect_call =
                auid == ruid && same == Re && fake.available && got != Err(Refusal::NotApprover);
            if expect_call {
                assert_eq!(
                    *calls,
                    vec![(5555, 424242, auid, REAUTH_TIMEOUT)],
                    "row {i}"
                );
            } else {
                assert!(calls.is_empty(), "row {i}: reauth ran: {calls:?}");
            }
        }
    }

    #[test]
    fn rules_and_messages() {
        let all = [
            (Refusal::NotApprover, "not_approver"),
            (Refusal::SameUserDenied, "same_user"),
            (Refusal::ReauthUnavailable, "reauth_unavailable"),
            (Refusal::ReauthFailed, "reauth_failed"),
            (Refusal::ReauthError("e".into()), "reauth_error"),
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
