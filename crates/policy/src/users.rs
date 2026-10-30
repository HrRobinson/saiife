//! User and group lookups. [`Getent`] asks NSS (so LDAP/sssd users count);
//! [`FixedDirectory`] is a passwd/group text pair for tests.

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
