//! Strict loading of user packs (`user.*`): any broken rule fails the whole
//! load (a user pack is a never-rule; dropping one silently would loosen it).

use std::fmt;
use std::sync::Mutex;

use sha2::{Digest, Sha256};

use crate::canon::PathStyle;
use crate::pack::{load_raw, parse_pack, Compile, Pack, PackWarning};
use crate::profile::Profile;

pub const USER_PREFIX: &str = "user.";
pub const MAX_USER_RULES: usize = 128;

/// `user.` plus 1 to 48 of `[a-z0-9-]`, not starting with `-`.
pub fn valid_user_pack_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix(USER_PREFIX) else {
        return false;
    };
    (1..=48).contains(&rest.len())
        && !rest.starts_with('-')
        && rest
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// One user pack file: where it came from and its text.
#[derive(Debug, Clone, Copy)]
pub struct UserSrc<'a> {
    pub source: &'a str,
    pub text: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserPackError {
    pub source: String,
    pub message: String,
}

impl fmt::Display for UserPackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "user pack {}: {}", self.source, self.message)
    }
}

impl std::error::Error for UserPackError {}

fn err(source: &str, message: impl Into<String>) -> UserPackError {
    UserPackError {
        source: source.to_string(),
        message: message.into(),
    }
}

/// Load every user pack, failing on the first problem (see the plan 32 spec).
pub fn load_user_packs(
    srcs: &[UserSrc],
    style: PathStyle,
    profile: Profile,
) -> Result<Vec<Pack>, UserPackError> {
    let mut out: Vec<Pack> = Vec::new();
    let mut total = 0usize;
    for s in srcs {
        let raw = parse_pack(s.text).map_err(|e| err(s.source, e.to_string()))?;
        #[cfg(test)]
        crate::pack::note_compiled();
        let mut warnings: Vec<PackWarning> = Vec::new();
        let loaded = load_raw(
            s.source,
            &raw,
            style,
            profile,
            false,
            Compile::Now,
            &mut warnings,
        );
        // A dropped rule is the cause to report, even when it left no rules
        // (`NoRules`).
        if let Some(w) = warnings.iter().find(|w| w.dropped) {
            return Err(err(s.source, w.message.clone()));
        }
        let pack = loaded.map_err(|e| err(s.source, e.to_string()))?;
        let id = raw.pack.id.as_ref();
        if !valid_user_pack_id(id) {
            return Err(err(
                s.source,
                format!(
                    "invalid pack id {id:?}: use `user.` plus 1 to 48 of a-z, 0-9 or `-` (not first)"
                ),
            ));
        }
        if out.iter().any(|p| p.id == id) {
            return Err(err(s.source, format!("duplicate pack id {id:?}")));
        }
        if !raw.pack.default_on {
            return Err(err(s.source, "a user pack is always on; remove default_on"));
        }
        if raw.pack.lazy {
            return Err(err(s.source, "a user pack cannot be lazy"));
        }
        if raw.deny.iter().any(|r| r.id.is_none()) {
            return Err(err(s.source, "every [[deny]] in a user pack needs an id"));
        }
        total += pack.rule_count();
        if total > MAX_USER_RULES {
            return Err(err(
                s.source,
                format!("{total} rules in all user packs; the cap is {MAX_USER_RULES}"),
            ));
        }
        out.push(pack);
    }
    Ok(out)
}

type Cached = Option<([u8; 32], Result<Vec<Pack>, UserPackError>)>;

/// The last load, kept so a hook that runs again on unchanged packs does not
/// recompile them.
static LAST: Mutex<Cached> = Mutex::new(None);

fn key(srcs: &[UserSrc], style: PathStyle, profile: Profile) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(format!("{style:?}").as_bytes());
    h.update(b"\0");
    h.update(profile.name().as_bytes());
    h.update(b"\0");
    for s in srcs {
        h.update(s.source.as_bytes());
        h.update(b"\0");
        h.update(s.text.as_bytes());
        h.update(b"\0");
    }
    h.finalize().into()
}

/// [`load_user_packs`], with the last result kept for equal input.
pub fn load_user_packs_cached(
    srcs: &[UserSrc],
    style: PathStyle,
    profile: Profile,
) -> Result<Vec<Pack>, UserPackError> {
    let k = key(srcs, style, profile);
    let Ok(mut last) = LAST.lock() else {
        return load_user_packs(srcs, style, profile);
    };
    if let Some((lk, res)) = last.as_ref() {
        if *lk == k {
            return res.clone();
        }
    }
    let res = load_user_packs(srcs, style, profile);
    *last = Some((k, res.clone()));
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::compiled_packs;

    const A: &str = "[pack]\nid = \"user.a\"\ntriggers = [\"zz\"]\n[[deny]]\nid = \"d\"\npattern = '^zz$'\nreason = \"r\"\n";

    fn ids(r: Result<Vec<Pack>, UserPackError>) -> Vec<String> {
        r.unwrap().into_iter().map(|p| p.id).collect()
    }

    #[test]
    fn cache_hits_on_same_input() {
        let s1 = [UserSrc {
            source: "a",
            text: A,
        }];
        let before = compiled_packs();
        let first = ids(load_user_packs_cached(&s1, PathStyle::Posix, Profile::Host));
        assert_eq!(first, ["user.a"]);
        assert_eq!(compiled_packs(), before + 1);
        let again = ids(load_user_packs_cached(&s1, PathStyle::Posix, Profile::Host));
        assert_eq!(again, first);
        assert_eq!(compiled_packs(), before + 1, "a hit compiles nothing");
        let text2 = A.replace("user.a", "user.b");
        let s2 = [UserSrc {
            source: "a",
            text: &text2,
        }];
        let third = ids(load_user_packs_cached(&s2, PathStyle::Posix, Profile::Host));
        assert_eq!(third, ["user.b"]);
        assert_eq!(compiled_packs(), before + 2);
        // The profile is part of the key.
        let _ = load_user_packs_cached(&s2, PathStyle::Posix, Profile::Box);
        assert_eq!(compiled_packs(), before + 3);
    }

    #[test]
    fn id_shape() {
        assert!(valid_user_pack_id("user.a-1"));
        assert!(!valid_user_pack_id("user."));
        assert!(!valid_user_pack_id("user.-a"));
        assert!(!valid_user_pack_id(&format!("user.{}", "a".repeat(49))));
        assert!(valid_user_pack_id(&format!("user.{}", "a".repeat(48))));
    }
}
