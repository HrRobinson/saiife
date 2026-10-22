//! One scope per uid (builder's call 6, spec §8.1).

use crate::load::{load_system, LoadedPolicy, PolicyError};
use crate::system::{Scope, SystemConfig};
use crate::users::Directory;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const GROUP_PREFIX: &str = "group:";

/// Load-time check: no uid may be listed in two scopes, directly or through a
/// `group:` entry's member list. Unknown users and groups are skipped.
/// Members whose only link to a group is their primary gid cannot be listed
/// here; [`scope_for`] catches them per request.
pub fn check_scopes(cfg: &SystemConfig, dir: &dyn Directory) -> Result<(), PolicyError> {
    let mut by_uid: BTreeMap<u32, (String, BTreeSet<String>)> = BTreeMap::new();
    for scope in &cfg.scope {
        for entry in &scope.users {
            let names = match entry.strip_prefix(GROUP_PREFIX) {
                Some(g) => dir.group(g).map(|g| g.members).unwrap_or_default(),
                None => vec![entry.clone()],
            };
            for name in names {
                if let Some(u) = dir.user(&name) {
                    by_uid
                        .entry(u.uid)
                        .or_insert_with(|| (name.clone(), BTreeSet::new()))
                        .1
                        .insert(scope.name.clone());
                }
            }
        }
    }
    for (uid, (name, scopes)) in by_uid {
        if scopes.len() > 1 {
            return Err(PolicyError::ScopeConflict {
                user: dir.name_of(uid).unwrap_or(name),
                scopes: scopes.into_iter().collect(),
            });
        }
    }
    Ok(())
}

/// The per-request check: the scope `user` belongs to with its current
/// groups (primary group included), or `ScopeConflict` if more than one.
pub fn scope_for<'a>(
    cfg: &'a SystemConfig,
    dir: &dyn Directory,
    user: &str,
) -> Result<Option<&'a Scope>, PolicyError> {
    let groups = dir.groups_of(user);
    let matches: Vec<&Scope> = cfg
        .scope
        .iter()
        .filter(|s| {
            s.users.iter().any(|e| match e.strip_prefix(GROUP_PREFIX) {
                Some(g) => groups.iter().any(|x| x == g),
                None => e == user,
            })
        })
        .collect();
    match matches.as_slice() {
        [] => Ok(None),
        [one] => Ok(Some(one)),
        many => {
            let mut scopes: Vec<String> = many.iter().map(|s| s.name.clone()).collect();
            scopes.sort();
            scopes.dedup();
            Err(PolicyError::ScopeConflict {
                user: user.to_string(),
                scopes,
            })
        }
    }
}

/// [`load_system`] followed by [`check_scopes`].
pub fn load_and_check(
    config_file: &Path,
    dir: &dyn Directory,
) -> Result<LoadedPolicy, PolicyError> {
    let loaded = load_system(config_file)?;
    check_scopes(&loaded.config, dir)?;
    Ok(loaded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::users::FixedDirectory;

    const PASSWD: &str = "alice:x:1000:1000::/home/alice:/bin/sh\n\
        bob:x:1001:2000::/home/bob:/bin/sh\n\
        carol:x:1002:1002::/home/carol:/bin/sh\n";

    fn cfg(scopes: &str) -> SystemConfig {
        toml::from_str(&format!("version = 2\n{scopes}")).unwrap()
    }

    fn conflict(r: Result<(), PolicyError>) -> (String, Vec<String>) {
        match r {
            Err(PolicyError::ScopeConflict { user, scopes }) => (user, scopes),
            other => panic!("expected ScopeConflict, got {other:?}"),
        }
    }

    #[test]
    fn scope_conflict_direct() {
        let d = FixedDirectory::from_text(PASSWD, "");
        let c = cfg("[[scope]]\nname = \"b\"\nusers = [\"alice\"]\n[[scope]]\nname = \"a\"\nusers = [\"alice\"]\n");
        assert_eq!(
            conflict(check_scopes(&c, &d)),
            ("alice".to_string(), vec!["a".to_string(), "b".to_string()])
        );
    }

    #[test]
    fn scope_conflict_through_group() {
        let d = FixedDirectory::from_text(PASSWD, "devs:x:2000:alice\n");
        let c = cfg("[[scope]]\nname = \"a\"\nusers = [\"alice\"]\n[[scope]]\nname = \"b\"\nusers = [\"group:devs\"]\n");
        assert_eq!(
            conflict(check_scopes(&c, &d)),
            ("alice".to_string(), vec!["a".to_string(), "b".to_string()])
        );
    }

    #[test]
    fn disjoint_scopes_ok() {
        let d = FixedDirectory::from_text(PASSWD, "devs:x:2000:bob\n");
        let c = cfg(
            "[[scope]]\nname = \"a\"\nusers = [\"alice\", \"alice\", \"ghost\", \"group:nogroup\"]\n\
             [[scope]]\nname = \"b\"\nusers = [\"group:devs\", \"carol\"]\n",
        );
        check_scopes(&c, &d).unwrap();
    }

    #[test]
    fn scope_for_sees_primary_group() {
        // bob's primary group is devs; the group line lists no members.
        let d = FixedDirectory::from_text(PASSWD, "devs:x:2000:\n");
        let c = cfg("[[scope]]\nname = \"a\"\nusers = [\"alice\"]\n[[scope]]\nname = \"b\"\nusers = [\"group:devs\"]\n");
        check_scopes(&c, &d).unwrap();
        assert_eq!(
            scope_for(&c, &d, "bob").unwrap().map(|s| s.name.as_str()),
            Some("b")
        );
        assert_eq!(
            scope_for(&c, &d, "alice").unwrap().map(|s| s.name.as_str()),
            Some("a")
        );
        assert!(scope_for(&c, &d, "carol").unwrap().is_none());

        // Listed directly in a second scope: load time misses it, the request check does not.
        let c = cfg("[[scope]]\nname = \"z\"\nusers = [\"bob\"]\n[[scope]]\nname = \"b\"\nusers = [\"group:devs\"]\n");
        check_scopes(&c, &d).unwrap();
        match scope_for(&c, &d, "bob") {
            Err(PolicyError::ScopeConflict { user, scopes }) => {
                assert_eq!(user, "bob");
                assert_eq!(scopes, vec!["b", "z"]);
            }
            other => panic!("expected ScopeConflict, got {other:?}"),
        }
    }

    #[test]
    fn load_and_check_reports_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("config.toml");
        std::fs::write(
            &file,
            "version = 2\n[[scope]]\nname = \"a\"\nusers = [\"alice\"]\n[[scope]]\nname = \"b\"\nusers = [\"alice\"]\n",
        )
        .unwrap();
        let d = FixedDirectory::from_text(PASSWD, "");
        assert!(matches!(
            load_and_check(&file, &d),
            Err(PolicyError::ScopeConflict { .. })
        ));
        std::fs::write(
            &file,
            "version = 2\n[[scope]]\nname = \"a\"\nusers = [\"alice\"]\n",
        )
        .unwrap();
        assert_eq!(load_and_check(&file, &d).unwrap().config.scope.len(), 1);
    }
}
