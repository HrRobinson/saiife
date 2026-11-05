//! User and group lookups. [`Getent`] asks NSS (so LDAP/sssd users count);
//! [`WinDirectory`] asks Windows; [`FixedDirectory`] is a passwd/group text pair
//! for tests.

use saiife_win::sid::uid_of;
use std::collections::BTreeMap;
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserEntry {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEntry {
    pub gid: u32,
    pub members: Vec<String>,
}

pub trait Directory {
    fn user(&self, name: &str) -> Option<UserEntry>;
    fn name_of(&self, uid: u32) -> Option<String>;
    fn group(&self, name: &str) -> Option<GroupEntry>;
    /// The user's current groups, primary group included.
    fn groups_of(&self, user: &str) -> Vec<String>;
    /// [`groups_of`](Directory::groups_of), but a failed lookup is an error
    /// instead of an empty list. Callers that must fail closed use this.
    fn try_groups_of(&self, user: &str) -> Result<Vec<String>, String> {
        Ok(self.groups_of(user))
    }
    /// Windows: the SID of an account or group, the identity behind its uid label.
    /// `None` on Linux and macOS, where the uid is the identity, and on a failed lookup.
    fn sid_of(&self, name: &str) -> Option<String> {
        let _ = name;
        None
    }
    /// Windows: the canonical name of a SID, and that SID noted so
    /// [`name_of`](Directory::name_of) can answer for its label. `None` elsewhere.
    fn name_of_sid(&self, sid: &str) -> Option<String> {
        let _ = sid;
        None
    }
}

/// NSS lookups through `getent passwd|group` and `id -Gn`. macOS has no
/// `getent`: there users and groups come from Directory Services through
/// `getpwnam_r`, `getpwuid_r` and `getgrnam_r`, and `id -Gn` stays.
#[derive(Debug, Clone, Copy, Default)]
pub struct Getent;

impl Directory for Getent {
    #[cfg(not(target_os = "macos"))]
    fn user(&self, name: &str) -> Option<UserEntry> {
        if !valid_name(name) {
            return None;
        }
        let line = run("getent", &["passwd", name])?;
        parse_passwd_line(line.lines().next()?).map(|(_, e)| e)
    }

    #[cfg(target_os = "macos")]
    fn user(&self, name: &str) -> Option<UserEntry> {
        if !valid_name(name) {
            return None;
        }
        let u = nix::unistd::User::from_name(name).ok()??;
        Some(UserEntry {
            uid: u.uid.as_raw(),
            gid: u.gid.as_raw(),
        })
    }

    #[cfg(not(target_os = "macos"))]
    fn name_of(&self, uid: u32) -> Option<String> {
        let line = run("getent", &["passwd", &uid.to_string()])?;
        let (name, e) = parse_passwd_line(line.lines().next()?)?;
        (e.uid == uid).then_some(name)
    }

    #[cfg(target_os = "macos")]
    fn name_of(&self, uid: u32) -> Option<String> {
        let u = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)).ok()??;
        (u.uid.as_raw() == uid && !u.name.is_empty()).then_some(u.name)
    }

    #[cfg(not(target_os = "macos"))]
    fn group(&self, name: &str) -> Option<GroupEntry> {
        if !valid_name(name) {
            return None;
        }
        let line = run("getent", &["group", name])?;
        parse_group_line(line.lines().next()?).map(|(_, g)| g)
    }

    #[cfg(target_os = "macos")]
    fn group(&self, name: &str) -> Option<GroupEntry> {
        if !valid_name(name) {
            return None;
        }
        let g = nix::unistd::Group::from_name(name).ok()??;
        Some(GroupEntry {
            gid: g.gid.as_raw(),
            members: g.mem.into_iter().filter(|m| !m.is_empty()).collect(),
        })
    }

    fn groups_of(&self, user: &str) -> Vec<String> {
        self.try_groups_of(user).unwrap_or_default()
    }

    fn try_groups_of(&self, user: &str) -> Result<Vec<String>, String> {
        if !valid_name(user) {
            return Err(format!("{user:?} is not a user name"));
        }
        run("id", &["-Gn", user])
            .map(|out| out.split_whitespace().map(str::to_string).collect())
            .ok_or_else(|| format!("cannot look up the groups of {user}"))
    }
}

/// A user or group name safe to pass as an argument: not empty, no leading
/// `-` (no option injection), no `:`, whitespace or control characters.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('-')
        && !name
            .chars()
            .any(|c| c == ':' || c.is_whitespace() || c.is_control())
}

/// Runs a lookup tool from a fixed system directory when there is one, and
/// returns its stdout on success.
fn run(tool: &str, args: &[&str]) -> Option<String> {
    let program = ["/usr/bin", "/bin"]
        .iter()
        .map(|d| std::path::Path::new(d).join(tool))
        .find(|p| p.is_file())
        .unwrap_or_else(|| tool.into());
    let out = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

/// `name:pw:uid:gid:...` -> (name, entry).
fn parse_passwd_line(line: &str) -> Option<(String, UserEntry)> {
    let f: Vec<&str> = line.split(':').collect();
    if f.len() < 4 || f[0].is_empty() {
        return None;
    }
    Some((
        f[0].to_string(),
        UserEntry {
            uid: f[2].parse().ok()?,
            gid: f[3].parse().ok()?,
        },
    ))
}

/// `name:pw:gid:member,member` -> (name, entry).
fn parse_group_line(line: &str) -> Option<(String, GroupEntry)> {
    let f: Vec<&str> = line.split(':').collect();
    if f.len() < 4 || f[0].is_empty() {
        return None;
    }
    let members = f[3]
        .split(',')
        .map(str::trim)
        .filter(|m| !m.is_empty())
        .map(str::to_string)
        .collect();
    Some((
        f[0].to_string(),
        GroupEntry {
            gid: f[2].parse().ok()?,
            members,
        },
    ))
}

/// The account calls [`WinDirectory`] makes. Each error text says why.
pub trait WinAccounts {
    /// The SID and canonical `DOMAIN\name` of an account.
    fn lookup_name(&self, name: &str) -> Result<(String, String), String>;
    /// The canonical `DOMAIN\name` of a SID.
    fn lookup_sid(&self, sid: &str) -> Result<String, String>;
    /// The local groups a user is in, nested ones included.
    fn local_groups_of(&self, user: &str) -> Result<Vec<String>, String>;
    /// The members of a local group.
    fn local_group_members(&self, group: &str) -> Result<Vec<String>, String>;
}

/// [`WinAccounts`] on the machine, through `saiife_win::ffi::account`.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FfiAccounts;

#[cfg(windows)]
impl WinAccounts for FfiAccounts {
    fn lookup_name(&self, name: &str) -> Result<(String, String), String> {
        saiife_win::ffi::account::lookup_name(name).map_err(|e| e.to_string())
    }

    fn lookup_sid(&self, sid: &str) -> Result<String, String> {
        saiife_win::ffi::account::lookup_sid(sid).map_err(|e| e.to_string())
    }

    fn local_groups_of(&self, user: &str) -> Result<Vec<String>, String> {
        saiife_win::ffi::account::local_groups_of(user).map_err(|e| e.to_string())
    }

    fn local_group_members(&self, group: &str) -> Result<Vec<String>, String> {
        saiife_win::ffi::account::local_group_members(group).map_err(|e| e.to_string())
    }
}

/// A name [`WinDirectory`] looks up. Windows names may hold spaces and `\`, so only
/// empty names, control characters and a leading `-` are refused.
pub fn valid_win_name(name: &str) -> bool {
    !name.is_empty() && !name.starts_with('-') && !name.chars().any(char::is_control)
}

/// What [`WinDirectory::name_of`] knows of a uid.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    One {
        sid: String,
        name: String,
    },
    /// Two SIDs hashed to this uid. The SID is the identity and the uid only a label,
    /// so this label names nobody.
    Collided,
}

/// Lookups on Windows (W12). A uid is [`uid_of`] the SID, a label and never a key:
/// Windows cannot be asked for a name by label, so [`Directory::name_of`] answers
/// only for SIDs this process resolved or saw, and not at all for a label two of
/// them share.
#[derive(Debug, Default)]
pub struct WinDirectory<A> {
    accounts: A,
    seen: Mutex<BTreeMap<u32, Seen>>,
}

#[cfg(windows)]
impl WinDirectory<FfiAccounts> {
    /// The directory of this machine.
    pub fn system() -> WinDirectory<FfiAccounts> {
        WinDirectory::new(FfiAccounts)
    }
}

impl<A: WinAccounts> WinDirectory<A> {
    pub fn new(accounts: A) -> WinDirectory<A> {
        WinDirectory {
            accounts,
            seen: Mutex::new(BTreeMap::new()),
        }
    }

    fn remember(&self, sid: &str, name: &str) {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let uid = uid_of(sid, false);
        let entry = match seen.get(&uid) {
            Some(Seen::One { sid: known, .. }) if known != sid => Seen::Collided,
            Some(Seen::Collided) => Seen::Collided,
            _ => Seen::One {
                sid: sid.to_string(),
                name: name.to_string(),
            },
        };
        seen.insert(uid, entry);
    }

    /// Notes a SID this process met, say a peer's, so [`Directory::name_of`] can
    /// answer for its label. Returns its name when Windows knows one.
    pub fn saw_sid(&self, sid: &str) -> Option<String> {
        // A hook connects on every tool call: a known SID needs no second lookup.
        if let Some(Seen::One { sid: known, name }) = self
            .seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&uid_of(sid, false))
        {
            if known == sid {
                return Some(name.clone());
            }
        }
        let name = self.accounts.lookup_sid(sid).ok()?;
        self.remember(sid, &name);
        Some(name)
    }
}

impl<A: WinAccounts> Directory for WinDirectory<A> {
    fn user(&self, name: &str) -> Option<UserEntry> {
        if !valid_win_name(name) {
            return None;
        }
        let (sid, canonical) = self.accounts.lookup_name(name).ok()?;
        self.remember(&sid, &canonical);
        Some(UserEntry {
            uid: uid_of(&sid, false),
            gid: 0,
        })
    }

    fn name_of(&self, uid: u32) -> Option<String> {
        let seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        match seen.get(&uid)? {
            Seen::One { name, .. } => Some(name.clone()),
            Seen::Collided => None,
        }
    }

    fn group(&self, name: &str) -> Option<GroupEntry> {
        if !valid_win_name(name) {
            return None;
        }
        let (sid, canonical) = self.accounts.lookup_name(name).ok()?;
        // The group calls take the bare name; the lookup above took either form.
        let bare = canonical.rsplit('\\').next().unwrap_or(&canonical);
        let members = self.accounts.local_group_members(bare).ok()?;
        Some(GroupEntry {
            gid: uid_of(&sid, false),
            members,
        })
    }

    fn groups_of(&self, user: &str) -> Vec<String> {
        self.try_groups_of(user).unwrap_or_default()
    }

    fn try_groups_of(&self, user: &str) -> Result<Vec<String>, String> {
        if !valid_win_name(user) {
            return Err(format!("{user:?} is not a user name"));
        }
        self.accounts
            .local_groups_of(user)
            .map_err(|e| format!("cannot look up the groups of {user}: {e}"))
    }

    fn sid_of(&self, name: &str) -> Option<String> {
        if !valid_win_name(name) {
            return None;
        }
        self.accounts.lookup_name(name).ok().map(|(sid, _)| sid)
    }

    fn name_of_sid(&self, sid: &str) -> Option<String> {
        self.saw_sid(sid)
    }
}

/// A fixed directory parsed from `/etc/passwd`- and `/etc/group`-style text.
#[derive(Debug, Clone, Default)]
pub struct FixedDirectory {
    users: Vec<(String, UserEntry)>,
    groups: Vec<(String, GroupEntry)>,
}

impl FixedDirectory {
    /// Lines that do not parse (comments, blanks, junk) are skipped.
    pub fn from_text(passwd: &str, group: &str) -> FixedDirectory {
        FixedDirectory {
            users: passwd.lines().filter_map(parse_passwd_line).collect(),
            groups: group.lines().filter_map(parse_group_line).collect(),
        }
    }
}

impl Directory for FixedDirectory {
    fn user(&self, name: &str) -> Option<UserEntry> {
        self.users
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, e)| e.clone())
    }

    fn name_of(&self, uid: u32) -> Option<String> {
        self.users
            .iter()
            .find(|(_, e)| e.uid == uid)
            .map(|(n, _)| n.clone())
    }

    fn group(&self, name: &str) -> Option<GroupEntry> {
        self.groups
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, g)| g.clone())
    }

    /// Primary group (from passwd) first, then supplementary groups (from
    /// group member lists) in file order.
    fn groups_of(&self, user: &str) -> Vec<String> {
        let Some(u) = self.user(user) else {
            return Vec::new();
        };
        let mut out: Vec<String> = Vec::new();
        if let Some((n, _)) = self.groups.iter().find(|(_, g)| g.gid == u.gid) {
            out.push(n.clone());
        }
        for (n, g) in &self.groups {
            if g.members.iter().any(|m| m == user) && !out.contains(n) {
                out.push(n.clone());
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
        alice:x:1000:1000::/home/alice:/bin/bash\n\
        bob:x:1001:2000::/home/bob:/bin/bash\n\
        # comment\n\
        \n\
        broken line\n";
    const GROUP: &str = "root:x:0:\nalice:x:1000:\ndevs:x:2000:\nwheel:x:10:alice,bob\n";

    #[test]
    fn fixed_directory_lookups() {
        let d = FixedDirectory::from_text(PASSWD, GROUP);
        assert_eq!(
            d.user("bob"),
            Some(UserEntry {
                uid: 1001,
                gid: 2000
            })
        );
        assert_eq!(d.user("nobody"), None);
        assert_eq!(d.name_of(1000).as_deref(), Some("alice"));
        assert_eq!(d.name_of(4242), None);
        assert_eq!(
            d.group("wheel"),
            Some(GroupEntry {
                gid: 10,
                members: vec!["alice".into(), "bob".into()]
            })
        );
        assert_eq!(d.group("devs").unwrap().members, Vec::<String>::new());
        assert_eq!(d.groups_of("bob"), vec!["devs", "wheel"]);
        assert_eq!(d.groups_of("alice"), vec!["alice", "wheel"]);
        assert!(d.groups_of("nobody").is_empty());
    }

    /// Windows' accounts, from a table. Keys are lower case, as Windows is
    /// case-insensitive; the SID is what stays the same.
    #[derive(Default)]
    struct FakeAccounts {
        names: Vec<(&'static str, &'static str, &'static str)>,
        groups: Vec<(&'static str, Vec<String>)>,
        member_of: Vec<(&'static str, Vec<String>)>,
    }

    impl WinAccounts for FakeAccounts {
        fn lookup_name(&self, name: &str) -> Result<(String, String), String> {
            self.names
                .iter()
                .find(|(n, _, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, sid, canonical)| (sid.to_string(), canonical.to_string()))
                .ok_or_else(|| format!("no account {name}"))
        }

        fn lookup_sid(&self, sid: &str) -> Result<String, String> {
            self.names
                .iter()
                .find(|(_, s, _)| *s == sid)
                .map(|(_, _, canonical)| canonical.to_string())
                .ok_or_else(|| format!("no SID {sid}"))
        }

        fn local_groups_of(&self, user: &str) -> Result<Vec<String>, String> {
            self.member_of
                .iter()
                .find(|(u, _)| u.eq_ignore_ascii_case(user))
                .map(|(_, g)| g.clone())
                .ok_or_else(|| format!("no user {user}"))
        }

        fn local_group_members(&self, group: &str) -> Result<Vec<String>, String> {
            self.groups
                .iter()
                .find(|(g, _)| g.eq_ignore_ascii_case(group))
                .map(|(_, m)| m.clone())
                .ok_or_else(|| format!("no group {group}"))
        }
    }

    const ALICE_SID: &str = "S-1-5-21-1-2-3-1001";
    const BOB_SID: &str = "S-1-5-21-1-2-3-1002";

    fn win_dir() -> WinDirectory<FakeAccounts> {
        WinDirectory::new(FakeAccounts {
            names: vec![
                ("alice", ALICE_SID, r"HOST\alice"),
                (r"HOST\alice", ALICE_SID, r"HOST\alice"),
                (r"ACME\some user", BOB_SID, r"ACME\some user"),
                ("Users", "S-1-5-32-545", r"BUILTIN\Users"),
                (r"BUILTIN\Users", "S-1-5-32-545", r"BUILTIN\Users"),
            ],
            groups: vec![("Users", vec![r"HOST\alice".to_string()])],
            member_of: vec![("alice", vec!["Users".to_string()])],
        })
    }

    #[test]
    fn win_user_is_the_label_of_the_sid() {
        let d = win_dir();
        let want = UserEntry {
            uid: uid_of(ALICE_SID, false),
            gid: 0,
        };
        assert_eq!(d.user("alice"), Some(want.clone()));
        assert_eq!(d.user("ALICE"), Some(want.clone()));
        assert_eq!(d.user(r"HOST\alice"), Some(want));
        assert_eq!(d.user("nobody"), None);
        // Names may hold spaces and a backslash.
        assert!(d.user(r"ACME\some user").is_some());
    }

    #[test]
    fn win_refuses_only_empty_control_and_leading_dash() {
        for ok in ["alice", "some user", r"ACME\some user", "a:b", "a/b"] {
            assert!(valid_win_name(ok), "{ok}");
        }
        for bad in ["", "-x", "a\nb", "a\tb", "a\u{7f}"] {
            assert!(!valid_win_name(bad), "{bad:?}");
            let d = win_dir();
            assert_eq!(d.user(bad), None);
            assert_eq!(d.group(bad), None);
            assert!(d.try_groups_of(bad).is_err());
            assert!(d.groups_of(bad).is_empty());
        }
    }

    #[test]
    fn win_name_of_answers_only_for_sids_seen() {
        let d = win_dir();
        let uid = uid_of(ALICE_SID, false);
        assert_eq!(d.name_of(uid), None);
        d.user("alice").unwrap();
        assert_eq!(d.name_of(uid).as_deref(), Some(r"HOST\alice"));

        let bob = uid_of(BOB_SID, false);
        assert_eq!(d.name_of(bob), None);
        assert_eq!(d.saw_sid(BOB_SID).as_deref(), Some(r"ACME\some user"));
        assert_eq!(d.name_of(bob).as_deref(), Some(r"ACME\some user"));

        assert_eq!(d.saw_sid("S-1-5-21-9-9-9-9"), None);
    }

    /// The uid is a label: two SIDs sharing one must name neither.
    #[test]
    fn win_name_of_refuses_a_label_two_sids_share() {
        let d = win_dir();
        let uid = uid_of(ALICE_SID, false);
        d.remember(ALICE_SID, r"HOST\alice");
        d.remember(ALICE_SID, r"HOST\alice");
        assert!(
            d.name_of(uid).is_some(),
            "the same SID twice is no collision"
        );

        // Forced into one slot, as uid_of's hash is not reachable by hand.
        let mut seen = d.seen.lock().unwrap();
        seen.insert(
            uid_of(BOB_SID, false),
            Seen::One {
                sid: ALICE_SID.to_string(),
                name: r"HOST\alice".to_string(),
            },
        );
        drop(seen);
        d.remember(BOB_SID, r"ACME\some user");
        assert_eq!(d.name_of(uid_of(BOB_SID, false)), None);
        // And it stays that way.
        d.remember(BOB_SID, r"ACME\some user");
        assert_eq!(d.name_of(uid_of(BOB_SID, false)), None);
    }

    #[test]
    fn win_groups() {
        let d = win_dir();
        let users = d.group("Users").unwrap();
        assert_eq!(users.gid, uid_of("S-1-5-32-545", false));
        assert_eq!(users.members, [r"HOST\alice"]);
        assert_eq!(d.group(r"BUILTIN\Users").unwrap(), users);
        assert_eq!(d.group("nope"), None);
        // An account that is no local group has no members to list.
        assert_eq!(d.group("alice"), None);

        assert_eq!(d.groups_of("alice"), ["Users"]);
        assert!(d.groups_of("nobody").is_empty());
        let e = d.try_groups_of("nobody").unwrap_err();
        assert!(e.contains("cannot look up the groups of nobody"), "{e}");
    }

    /// Smoke test only: the host's NSS content is not asserted.
    #[test]
    fn getent_does_not_panic() {
        let g = Getent;
        let _ = g.user("root");
        let _ = g.name_of(0);
        let _ = g.group("root");
        let _ = g.groups_of("root");
        assert_eq!(g.user("-x"), None);
        assert_eq!(g.user(""), None);
        assert!(g.groups_of("--help").is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn getent_finds_root_and_wheel() {
        let g = Getent;
        assert_eq!(g.group("wheel").unwrap().gid, 0);
        assert_eq!(g.user("root").unwrap().uid, 0);
        assert_eq!(g.name_of(0).as_deref(), Some("root"));
        assert_eq!(g.group("-wheel"), None);
    }
}
