//! The named pipe's rules (plan 19b, decision W11), free of Windows calls so Linux
//! tests cover them: the descriptor, the rights a client asks for, the owner check,
//! the options of a server instance, and the order of the impersonation calls.
//! `ffi::pipe` supplies the calls.

use crate::sid::{valid_sid, TokenFacts, ADMINISTRATORS};
use std::io;

/// `ERROR_ACCESS_DENIED`: what `FILE_FLAG_FIRST_PIPE_INSTANCE` gives when the name is
/// taken, and what a pipe's DACL gives a caller who may not add an instance.
pub const ERROR_ACCESS_DENIED: i32 = 5;
/// `ERROR_PIPE_BUSY`: every instance is connected, or (for a create) the pipe is full.
pub const ERROR_PIPE_BUSY: i32 = 231;

/// On a pipe, `FILE_APPEND_DATA` is the right to add a server instance.
pub const FILE_CREATE_PIPE_INSTANCE: u32 = 0x4;
/// What Users hold on the control pipe: `FILE_GENERIC_READ | FILE_GENERIC_WRITE`
/// without [`FILE_CREATE_PIPE_INSTANCE`].
pub const USERS_PIPE_RIGHTS: u32 = 0x0012_019b;
/// What a client asks for when it opens a pipe: `FILE_READ_DATA`, `FILE_WRITE_DATA`,
/// `FILE_READ_ATTRIBUTES`, `READ_CONTROL` (the owner check) and `SYNCHRONIZE`.
///
/// Never `GENERIC_WRITE`: that holds `FILE_APPEND_DATA`, which the DACL refuses, so an
/// open with it would be denied on the very pipe it is meant for.
pub const CLIENT_ACCESS: u32 = 0x0012_0083;
/// `SECURITY_IDENTIFICATION`: the server may learn who the client is, and can never act
/// as the client. `ffi::pipe` asserts this equals the Windows constant.
pub const CLIENT_QOS: u32 = 0x0001_0000;
/// How many instances of a pipe may exist.
pub const MAX_INSTANCES: usize = 254;

/// Longest name Windows accepts for a pipe.
const MAX_NAME: usize = 256;

/// The control pipe's descriptor (W11), for `<S> = service_sid`.
pub fn control_sddl(service_sid: &str) -> String {
    format!(
        "O:{service_sid}G:{service_sid}D:P(D;;GA;;;NU)(A;;GA;;;{service_sid})(A;;GA;;;SY)\
         (A;;{USERS_PIPE_RIGHTS:#x};;;BU)"
    )
}

/// Refuses anything but a plain pipe on this machine. A `\\host\pipe\…` name would send
/// the caller's credentials to that host, and `..` would leave the pipe namespace.
pub fn check_pipe_name(name: &str) -> io::Result<()> {
    let plain = name.strip_prefix(r"\\.\pipe\").is_some_and(|rest| {
        !rest.is_empty()
            && !rest.starts_with('.')
            && rest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    });
    if plain && name.len() <= MAX_NAME {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("not a local pipe name: {name:?}"),
    ))
}

/// The pipe is owned by exactly `expected`. A name proves nothing, since anyone may
/// create any free pipe name, and Windows only lets a caller name itself as owner. So
/// the owner is what tells the daemon from a squatter. The `Err` is the detail to report.
pub fn check_owner(actual: &str, expected: &str) -> Result<(), String> {
    if !valid_sid(expected) {
        return Err(format!("{expected:?} is not a SID to expect"));
    }
    if actual != expected {
        return Err(format!("owned by {actual}, expected {expected}"));
    }
    Ok(())
}

/// The options of one server instance. A flag here is what `ffi::pipe` sets; Windows has
/// no call that reads `reject_remote_clients` back, so this is where it is tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerPlan {
    pub first_pipe_instance: bool,
    pub reject_remote_clients: bool,
    pub max_instances: usize,
    pub byte_mode: bool,
}

impl ServerPlan {
    pub fn instance(first: bool) -> ServerPlan {
        ServerPlan {
            first_pipe_instance: first,
            reject_remote_clients: true,
            max_instances: MAX_INSTANCES,
            byte_mode: true,
        }
    }
}

/// Whether a failed create means someone else holds the name: only a first instance can
/// say so, since a later one may be refused for its own reasons.
pub fn squatted(first: bool, code: Option<i32>) -> bool {
    first && matches!(code, Some(ERROR_ACCESS_DENIED | ERROR_PIPE_BUSY))
}

/// Creating a server instance, as Windows does it.
pub trait Namespace {
    type Instance;
    fn create(&self, plan: &ServerPlan) -> io::Result<Self::Instance>;
    /// The owner of the pipe `instance` belongs to, as a SID.
    fn owner(&self, instance: &Self::Instance) -> io::Result<String>;
}

/// A server instance on a pipe that is really ours.
///
/// The first-instance flag refuses a name already taken. The owner is checked too: an
/// instance joins whatever pipe holds the name, under that pipe's owner and DACL, so a
/// later instance made in a gap, after every one of ours closed, could land on a
/// squatter's permissive pipe and serve its clients.
pub fn create_checked<N: Namespace>(
    ns: &N,
    name: &str,
    expect_owner: &str,
    first: bool,
) -> io::Result<N::Instance> {
    check_pipe_name(name)?;
    let not_ours = || {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("pipe {name} exists and is not ours; refusing to start"),
        )
    };
    let instance = ns.create(&ServerPlan::instance(first)).map_err(|e| {
        match squatted(first, e.raw_os_error()) {
            true => not_ours(),
            false => e,
        }
    })?;
    let owner = ns.owner(&instance)?;
    check_owner(&owner, expect_owner).map_err(|_| not_ours())?;
    Ok(instance)
}

/// Who is on the other end of a server instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipeClient {
    /// From the client's token: the identity.
    pub facts: TokenFacts,
    /// For attribution only: a client's pid proves nothing.
    pub pid: u32,
}

/// `SECURITY_MANDATORY_HIGH_RID`: the integrity level of an elevated process.
pub const INTEGRITY_HIGH_RID: u32 = 0x3000;

/// What a pipe client's token says, before it counts as anyone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerToken {
    pub facts: TokenFacts,
    /// `TokenIntegrityLevel`: the mandatory label's SID.
    pub integrity_sid: String,
    /// `TokenRestrictedSids`: how many the token has.
    pub restricted_sids: usize,
}

/// The level in a mandatory label's SID (`S-1-16-<rid>`). Anything else is `None`.
pub fn integrity_rid(sid: &str) -> Option<u32> {
    let rid = sid.strip_prefix("S-1-16-")?;
    if !valid_sid(sid) {
        return None;
    }
    rid.parse().ok()
}

/// The facts a pipe client counts as. A low-integrity or restricted child of an elevated
/// admin still holds `Administrators`, enabled, but cannot use it, and must not count as
/// uid 0. So the group counts only at high integrity or above with no restricted SIDs.
/// Otherwise it goes too, as `elevated_admin` says that group is in `group_sids`.
pub fn peer_facts(token: PeerToken) -> TokenFacts {
    let mut facts = token.facts;
    let admin_counts = token.restricted_sids == 0
        && integrity_rid(&token.integrity_sid).is_some_and(|rid| rid >= INTEGRITY_HIGH_RID);
    if !admin_counts {
        facts.elevated_admin = false;
        facts.group_sids.retain(|g| g != ADMINISTRATORS);
    }
    facts
}

/// The per-thread calls behind [`read_identity`].
pub trait IdentityOps {
    fn client_pid(&self) -> io::Result<u32>;
    /// Makes this thread impersonate the client. An error leaves it as it was.
    fn impersonate(&self) -> io::Result<()>;
    /// The facts of the token this thread impersonates. A thread with no such token is
    /// an error, never the process's token: that would make the client the daemon.
    fn read_thread_token(&self) -> io::Result<PeerToken>;
    fn revert(&self) -> io::Result<()>;
    /// `revert` failed, so this thread still runs as the client. In production this does
    /// not return.
    fn revert_failed(&self, e: &io::Error);
}

/// Reverts when dropped, so an early return or a panic cannot leave the thread
/// impersonating.
struct Reverter<'a, O: IdentityOps> {
    ops: &'a O,
    armed: bool,
}

impl<O: IdentityOps> Reverter<'_, O> {
    fn finish(mut self) -> io::Result<()> {
        self.armed = false;
        revert_or_die(self.ops)
    }
}

impl<O: IdentityOps> Drop for Reverter<'_, O> {
    fn drop(&mut self) {
        if self.armed {
            let _ = revert_or_die(self.ops);
        }
    }
}

fn revert_or_die<O: IdentityOps>(ops: &O) -> io::Result<()> {
    ops.revert().inspect_err(|e| ops.revert_failed(e))
}

/// Impersonates the client, reads its token and reverts, in one synchronous call: a task
/// could move threads at an `.await`, and the impersonation would stay behind.
///
/// Every failure is an error, so a caller has no identity to go on. The caller's own
/// identity is never the answer.
pub fn read_identity<O: IdentityOps>(ops: &O) -> io::Result<PipeClient> {
    let pid = ops.client_pid()?;
    ops.impersonate()?;
    let reverter = Reverter { ops, armed: true };
    let token = ops.read_thread_token();
    reverter.finish()?;
    let facts = peer_facts(token?);
    if !valid_sid(&facts.sid) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the client's token holds no valid SID",
        ));
    }
    Ok(PipeClient { facts, pid })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sddl;
    use crate::sid::{service_sid, uid_of, ADMINISTRATORS, NETWORK, SYSTEM, USERS};
    use std::cell::{Cell, RefCell};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    const AGENT: &str = "S-1-5-21-1-2-3-1001";
    const ADMIN: &str = "S-1-5-21-1-2-3-500";
    const CONTROL: &str = r"\\.\pipe\saiife";

    fn saiifed() -> String {
        service_sid("saiifed")
    }

    #[test]
    fn control_sddl_is_w11_verbatim() {
        let s = saiifed();
        assert_eq!(
            control_sddl(&s),
            format!("O:{s}G:{s}D:P(D;;GA;;;NU)(A;;GA;;;{s})(A;;GA;;;SY)(A;;0x12019b;;;BU)")
        );
    }

    #[test]
    fn pipe_sddl_has_no_create_instance_for_users() {
        let s = saiifed();
        let sd = sddl::parse(&control_sddl(&s)).unwrap();
        assert_eq!(sd.owner.as_deref(), Some(s.as_str()));
        assert_eq!(sd.group.as_deref(), Some(s.as_str()));
        assert!(sd.dacl_protected);

        let users = sd.aces.iter().find(|a| a.sid == USERS).unwrap();
        assert!(users.allow);
        assert_eq!(users.mask, USERS_PIPE_RIGHTS);
        // Generic rights hold the create right after mapping, so they count as having it.
        const GENERIC_ALL: u32 = 0x1000_0000;
        const GENERIC_WRITE: u32 = 0x4000_0000;
        let adds = FILE_CREATE_PIPE_INSTANCE | GENERIC_ALL | GENERIC_WRITE;
        assert_eq!(users.mask & adds, 0);

        // The deny comes first: a deny after an allow would not bind.
        let first = &sd.aces[0];
        assert!(!first.allow);
        assert_eq!(first.sid, NETWORK);
        assert_eq!(first.mask, GENERIC_ALL);

        // Only the service and SYSTEM may add an instance.
        let may_add: Vec<&str> = sd
            .aces
            .iter()
            .filter(|a| a.allow && a.mask & adds != 0)
            .map(|a| a.sid.as_str())
            .collect();
        assert_eq!(may_add, [s.as_str(), SYSTEM]);
    }

    /// `GENERIC_WRITE` holds `FILE_APPEND_DATA`, which on a pipe is the right to add an
    /// instance, and the DACL does not grant that to Users. So the client asks for its
    /// rights by name, inside what Users hold.
    #[test]
    fn client_access_fits_the_users_ace() {
        assert_eq!(CLIENT_ACCESS & !USERS_PIPE_RIGHTS, 0);
        assert_eq!(CLIENT_ACCESS & FILE_CREATE_PIPE_INSTANCE, 0);
        // Read, write, attributes, the owner check (READ_CONTROL), synchronous I/O.
        assert_eq!(CLIENT_ACCESS, 0x1 | 0x2 | 0x80 | 0x2_0000 | 0x10_0000);
    }

    /// `SecurityIdentification << 16`, and no more: the daemon can learn who the client
    /// is but can never act as the client.
    #[test]
    fn client_qos_is_identification() {
        assert_eq!(CLIENT_QOS, 1 << 16);
    }

    #[test]
    fn pipe_names_must_be_local() {
        for good in [CONTROL, r"\\.\pipe\saiife-user-S-1-5-21-1-2-3-1001"] {
            check_pipe_name(good).unwrap();
        }
        let long = format!(r"\\.\pipe\{}", "a".repeat(300));
        for bad in [
            "",
            "saiife",
            r"\\.\pipe\",
            // A remote name would send the caller's credentials to that host.
            r"\\evil\pipe\saiife",
            r"\\?\pipe\saiife",
            r"\\.\PIPE\saiife",
            r"\\.\pipe\..\..\C:\x",
            r"\\.\pipe\a\b",
            r"\\.\pipe\a/b",
            "\\\\.\\pipe\\a\0b",
            long.as_str(),
        ] {
            let e = check_pipe_name(bad).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{bad:?}");
        }
    }

    #[test]
    fn owner_check_takes_only_the_exact_sid() {
        let s = saiifed();
        check_owner(&s, &s).unwrap();
        check_owner(AGENT, AGENT).unwrap();

        // The same pipe name, someone else's pipe.
        let e = check_owner(AGENT, &s).unwrap_err();
        assert!(e.contains(AGENT) && e.contains(&s), "{e}");
        check_owner(SYSTEM, &s).unwrap_err();
        check_owner(ADMINISTRATORS, &s).unwrap_err();
        // A prefix or a case change is no match.
        check_owner(&s[..s.len() - 1], &s).unwrap_err();
        check_owner(&s.to_lowercase(), &s).unwrap_err();
        // Nothing to compare with is a refusal, even when both sides agree.
        check_owner("", "").unwrap_err();
        check_owner("not a sid", "not a sid").unwrap_err();
    }

    #[test]
    fn remote_clients_rejected_flag_set() {
        for first in [true, false] {
            let plan = ServerPlan::instance(first);
            assert!(plan.reject_remote_clients);
            assert!(plan.byte_mode);
            assert_eq!(plan.max_instances, 254);
            assert_eq!(plan.first_pipe_instance, first);
        }
    }

    #[test]
    fn squat_is_only_a_refused_first_instance() {
        assert!(squatted(true, Some(ERROR_ACCESS_DENIED)));
        assert!(squatted(true, Some(ERROR_PIPE_BUSY)));
        assert!(!squatted(false, Some(ERROR_ACCESS_DENIED)));
        assert!(!squatted(true, Some(2)));
        assert!(!squatted(true, None));
    }

    /// The pipe namespace as Windows behaves: the first instance sets the pipe's owner
    /// and DACL, and each later instance joins that pipe, its own descriptor ignored.
    struct FakeNamespace {
        existing: Option<Existing>,
        our_owner: String,
        seen: RefCell<Vec<ServerPlan>>,
        create_err: Option<i32>,
        owner_err: bool,
    }

    struct Existing {
        owner: String,
        lets_us_add: bool,
    }

    /// An instance knows its pipe's owner.
    struct FakeInstance {
        owner: String,
    }

    impl Namespace for FakeNamespace {
        type Instance = FakeInstance;

        fn create(&self, plan: &ServerPlan) -> io::Result<FakeInstance> {
            self.seen.borrow_mut().push(*plan);
            if let Some(code) = self.create_err {
                return Err(io::Error::from_raw_os_error(code));
            }
            match &self.existing {
                None => Ok(FakeInstance {
                    owner: self.our_owner.clone(),
                }),
                Some(e) if plan.first_pipe_instance || !e.lets_us_add => {
                    Err(io::Error::from_raw_os_error(ERROR_ACCESS_DENIED))
                }
                Some(e) => Ok(FakeInstance {
                    owner: e.owner.clone(),
                }),
            }
        }

        fn owner(&self, instance: &FakeInstance) -> io::Result<String> {
            if self.owner_err {
                return Err(io::Error::from_raw_os_error(ERROR_ACCESS_DENIED));
            }
            Ok(instance.owner.clone())
        }
    }

    fn namespace(existing: Option<Existing>) -> FakeNamespace {
        FakeNamespace {
            existing,
            our_owner: saiifed(),
            seen: RefCell::new(Vec::new()),
            create_err: None,
            owner_err: false,
        }
    }

    fn squatter(lets_us_add: bool) -> Option<Existing> {
        Some(Existing {
            owner: AGENT.to_string(),
            lets_us_add,
        })
    }

    #[test]
    fn free_name_gives_an_instance() {
        let ns = namespace(None);
        create_checked(&ns, CONTROL, &saiifed(), true).unwrap();
        assert!(ns.seen.borrow()[0].first_pipe_instance);
    }

    #[test]
    fn squatted_pipe_owned_by_someone_else_is_refused() {
        let ns = namespace(squatter(false));
        let e = create_checked(&ns, CONTROL, &saiifed(), true)
            .err()
            .unwrap();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            e.to_string(),
            r"pipe \\.\pipe\saiife exists and is not ours; refusing to start"
        );
    }

    /// The caller left the first-instance flag off, and the squatter's DACL lets anyone
    /// add an instance. Windows then joins us to the squatter's pipe. The owner check on
    /// the new instance catches it.
    #[test]
    fn first_instance_flag_missing_on_a_squatted_pipe_is_refused() {
        let ns = namespace(squatter(true));
        let e = create_checked(&ns, CONTROL, &saiifed(), false)
            .err()
            .unwrap();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
        assert!(!ns.seen.borrow()[0].first_pipe_instance);
    }

    /// With the flag set, the same permissive squatter fails at the create.
    #[test]
    fn first_instance_flag_set_on_a_permissive_squatter_is_refused() {
        let ns = namespace(squatter(true));
        let e = create_checked(&ns, CONTROL, &saiifed(), true)
            .err()
            .unwrap();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn later_instance_on_our_own_pipe_is_fine() {
        let ns = namespace(Some(Existing {
            owner: saiifed(),
            lets_us_add: true,
        }));
        create_checked(&ns, CONTROL, &saiifed(), false).unwrap();
    }

    #[test]
    fn unreadable_owner_on_a_new_instance_is_an_error() {
        let mut ns = namespace(None);
        ns.owner_err = true;
        create_checked(&ns, CONTROL, &saiifed(), true)
            .err()
            .unwrap();
    }

    #[test]
    fn other_create_errors_keep_their_code() {
        let mut ns = namespace(None);
        ns.create_err = Some(2);
        let e = create_checked(&ns, CONTROL, &saiifed(), true)
            .err()
            .unwrap();
        assert_eq!(e.raw_os_error(), Some(2));
    }

    #[test]
    fn bad_name_never_reaches_create() {
        let ns = namespace(None);
        create_checked(&ns, r"\\evil\pipe\saiife", &saiifed(), true)
            .err()
            .unwrap();
        assert!(ns.seen.borrow().is_empty());
    }

    /// A scripted server thread. `impersonating` is what Windows tracks per thread.
    #[derive(Default)]
    struct FakeIdentity {
        pid_err: bool,
        impersonate_err: Option<i32>,
        read: RefCell<Option<io::Result<PeerToken>>>,
        read_panics: bool,
        revert_err: bool,
        impersonating: Cell<bool>,
        reads: Cell<u32>,
        reverts: Cell<u32>,
        died: Cell<bool>,
    }

    impl IdentityOps for FakeIdentity {
        fn client_pid(&self) -> io::Result<u32> {
            assert!(!self.impersonating.get(), "the pid needs no impersonation");
            if self.pid_err {
                return Err(io::Error::from_raw_os_error(233));
            }
            Ok(4242)
        }

        fn impersonate(&self) -> io::Result<()> {
            if let Some(code) = self.impersonate_err {
                return Err(io::Error::from_raw_os_error(code));
            }
            self.impersonating.set(true);
            Ok(())
        }

        fn read_thread_token(&self) -> io::Result<PeerToken> {
            self.reads.set(self.reads.get() + 1);
            // What a fallback to the process token would give: the daemon's identity.
            if !self.impersonating.get() {
                return Ok(labeled(token(SYSTEM, &[ADMINISTRATORS]), HIGH, 0));
            }
            if self.read_panics {
                panic!("token read panicked");
            }
            self.read.borrow_mut().take().unwrap()
        }

        fn revert(&self) -> io::Result<()> {
            self.reverts.set(self.reverts.get() + 1);
            if self.revert_err {
                return Err(io::Error::from_raw_os_error(5));
            }
            self.impersonating.set(false);
            Ok(())
        }

        fn revert_failed(&self, _: &io::Error) {
            self.died.set(true);
        }
    }

    fn token(sid: &str, groups: &[&str]) -> TokenFacts {
        let groups = groups
            .iter()
            .map(|g| (g.to_string(), crate::sid::SE_GROUP_ENABLED))
            .collect();
        TokenFacts::from_groups(sid.to_string(), groups)
    }

    fn agent_reads() -> RefCell<Option<io::Result<PeerToken>>> {
        RefCell::new(Some(Ok(labeled(token(AGENT, &[USERS]), MEDIUM, 0))))
    }

    const LOW: &str = "S-1-16-4096";
    const MEDIUM: &str = "S-1-16-8192";
    const HIGH: &str = "S-1-16-12288";
    const SYSTEM_LEVEL: &str = "S-1-16-16384";

    fn labeled(facts: TokenFacts, integrity: &str, restricted_sids: usize) -> PeerToken {
        PeerToken {
            facts,
            integrity_sid: integrity.to_string(),
            restricted_sids,
        }
    }

    /// An admin's token with `Administrators` enabled, as the pipe reads it.
    fn admin_peer(integrity: &str, restricted_sids: usize) -> TokenFacts {
        let ops = FakeIdentity {
            read: RefCell::new(Some(Ok(labeled(
                token(ADMIN, &[ADMINISTRATORS, USERS]),
                integrity,
                restricted_sids,
            )))),
            ..Default::default()
        };
        read_identity(&ops).unwrap().facts
    }

    fn assert_not_root(facts: &TokenFacts) {
        assert!(!facts.elevated_admin);
        assert_ne!(uid_of(&facts.sid, facts.elevated_admin), 0);
        // `elevated_admin` means Administrators is among the groups, and it no longer is.
        assert_eq!(facts.group_sids, [USERS]);
        assert_eq!(facts.sid, ADMIN);
    }

    #[test]
    fn normal_high_integrity_admin_is_elevated() {
        for level in [HIGH, SYSTEM_LEVEL] {
            let facts = admin_peer(level, 0);
            assert!(facts.elevated_admin, "{level}");
            assert_eq!(uid_of(&facts.sid, facts.elevated_admin), 0);
            assert_eq!(facts.group_sids, [ADMINISTRATORS, USERS]);
        }
    }

    /// A low-integrity child of an elevated admin keeps the group, enabled.
    #[test]
    fn low_integrity_child_of_an_admin_is_not_elevated() {
        assert_not_root(&admin_peer(LOW, 0));
    }

    #[test]
    fn medium_integrity_admin_is_not_elevated() {
        assert_not_root(&admin_peer(MEDIUM, 0));
    }

    /// A restricted token at high integrity keeps the group too.
    #[test]
    fn restricted_token_of_an_admin_is_not_elevated() {
        assert_not_root(&admin_peer(HIGH, 1));
    }

    /// What cannot be read as an integrity level is not high.
    #[test]
    fn unreadable_integrity_label_is_not_elevated() {
        for label in [
            "",
            "nonsense",
            ADMINISTRATORS,
            "S-1-16",
            "S-1-16-x",
            "S-1-16-12288-1",
        ] {
            assert_not_root(&admin_peer(label, 0));
        }
    }

    #[test]
    fn integrity_rid_reads_only_a_mandatory_label() {
        assert_eq!(integrity_rid(LOW), Some(0x1000));
        assert_eq!(integrity_rid(HIGH), Some(INTEGRITY_HIGH_RID));
        assert_eq!(integrity_rid(SYSTEM_LEVEL), Some(0x4000));
        assert_eq!(integrity_rid("S-1-5-16-12288"), None);
        assert_eq!(integrity_rid("S-1-16-12288-1"), None);
        assert_eq!(integrity_rid("S-1-16-"), None);
        assert_eq!(integrity_rid("S-1-16-99999999999"), None);
    }

    /// A non-admin gets nothing from a high label, and loses no group from a low one.
    #[test]
    fn labels_change_nothing_for_a_non_admin() {
        for level in [LOW, MEDIUM, HIGH] {
            let ops = FakeIdentity {
                read: RefCell::new(Some(Ok(labeled(token(AGENT, &[USERS]), level, 0)))),
                ..Default::default()
            };
            let facts = read_identity(&ops).unwrap().facts;
            assert!(!facts.elevated_admin);
            assert_eq!(facts.group_sids, [USERS]);
        }
    }

    #[test]
    fn identity_names_the_client_and_reverts_once() {
        let ops = FakeIdentity {
            read: agent_reads(),
            ..Default::default()
        };
        let got = read_identity(&ops).unwrap();
        assert_eq!(got.facts.sid, AGENT);
        assert_eq!(got.facts.group_sids, [USERS]);
        assert!(!got.facts.elevated_admin);
        assert_eq!(got.pid, 4242);
        assert_eq!(ops.reverts.get(), 1);
        assert!(!ops.impersonating.get());
        assert!(!ops.died.get());
    }

    /// The classic hole: impersonation fails, the code reads "the current token" anyway,
    /// and the agent is now the daemon. Here the token is never read.
    #[test]
    fn impersonation_failure_never_reads_a_token() {
        let ops = FakeIdentity {
            impersonate_err: Some(1368),
            ..Default::default()
        };
        let e = read_identity(&ops).err().unwrap();
        assert_eq!(e.raw_os_error(), Some(1368));
        assert_eq!(ops.reads.get(), 0);
        assert_eq!(ops.reverts.get(), 0, "nothing to undo");
    }

    #[test]
    fn client_gone_before_the_pid_is_read_is_an_error() {
        let ops = FakeIdentity {
            pid_err: true,
            ..Default::default()
        };
        read_identity(&ops).err().unwrap();
        assert_eq!(ops.reads.get(), 0);
        assert!(!ops.impersonating.get());
    }

    /// The client disconnects while the thread impersonates it: an error, and reverted.
    #[test]
    fn disconnect_mid_impersonation_errors_and_reverts() {
        let ops = FakeIdentity {
            read: RefCell::new(Some(Err(io::Error::from(io::ErrorKind::BrokenPipe)))),
            ..Default::default()
        };
        let e = read_identity(&ops).err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(ops.reverts.get(), 1);
        assert!(!ops.impersonating.get());
    }

    /// A panic while impersonating must not leave a pool thread running as the client.
    #[test]
    fn panic_mid_impersonation_reverts() {
        let ops = FakeIdentity {
            read_panics: true,
            ..Default::default()
        };
        let r = catch_unwind(AssertUnwindSafe(|| read_identity(&ops)));
        assert!(r.is_err());
        assert_eq!(ops.reverts.get(), 1);
        assert!(!ops.impersonating.get());
    }

    /// Production aborts in `revert_failed`. If that ever returned, there is still no
    /// identity to act on.
    #[test]
    fn failed_revert_dies_and_gives_no_identity() {
        let ops = FakeIdentity {
            read: agent_reads(),
            revert_err: true,
            ..Default::default()
        };
        read_identity(&ops).err().unwrap();
        assert!(ops.died.get());
        assert_eq!(ops.reverts.get(), 1);
    }

    #[test]
    fn failed_revert_on_a_panic_still_dies() {
        let ops = FakeIdentity {
            read_panics: true,
            revert_err: true,
            ..Default::default()
        };
        assert!(catch_unwind(AssertUnwindSafe(|| read_identity(&ops))).is_err());
        assert!(ops.died.get());
    }

    #[test]
    fn failed_revert_after_a_failed_read_still_dies() {
        let ops = FakeIdentity {
            read: RefCell::new(Some(Err(io::Error::from(io::ErrorKind::BrokenPipe)))),
            revert_err: true,
            ..Default::default()
        };
        read_identity(&ops).err().unwrap();
        assert!(ops.died.get());
    }

    #[test]
    fn a_malformed_sid_is_no_identity() {
        let ops = FakeIdentity {
            read: RefCell::new(Some(Ok(labeled(token("nobody", &[USERS]), MEDIUM, 0)))),
            ..Default::default()
        };
        let e = read_identity(&ops).err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert_eq!(ops.reverts.get(), 1);
    }

    /// An admin user's UAC-filtered token, read through the seam, is not elevated.
    #[test]
    fn filtered_admin_token_stays_unelevated() {
        let filtered = TokenFacts::from_groups(
            ADMIN.to_string(),
            vec![
                (
                    ADMINISTRATORS.to_string(),
                    crate::sid::SE_GROUP_USE_FOR_DENY_ONLY,
                ),
                (USERS.to_string(), crate::sid::SE_GROUP_ENABLED),
            ],
        );
        let ops = FakeIdentity {
            read: RefCell::new(Some(Ok(labeled(filtered, MEDIUM, 0)))),
            ..Default::default()
        };
        let got = read_identity(&ops).unwrap();
        assert!(!got.facts.elevated_admin);
        assert_eq!(got.facts.group_sids, [USERS]);
    }
}
