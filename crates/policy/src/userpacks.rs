//! User packs (plan 32): `policy.d/packs/*.toml`, read as bytes, hashed, and
//! given a light header check. The rules themselves are compiled by
//! `saiife-guard` (strictly: a broken pack denies every call); this crate does
//! not depend on it, so the id rule is re-stated here.

use crate::effective::PackInfo;
use crate::load::{dropin_paths, invalid, read_policy_file, PolicyError};
use crate::system::SystemConfig;
use std::path::Path;

/// The directory of user packs, below the drop-in dir.
pub const USER_PACKS_DIR: &str = "packs";
/// At most this many pack files.
pub const MAX_USER_PACKS: usize = 32;
/// At most this many bytes in all pack files together.
pub const MAX_USER_PACK_BYTES: usize = 256 * 1024;

/// One user pack file as read: its bytes and what the header says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserPackFile {
    pub path: String,
    pub sha256: String,
    pub text: String,
    pub id: String,
    pub version: u32,
    /// The `[[deny]]` ids.
    pub rules: Vec<String>,
    /// The ids with `ask = true`.
    pub ask: Vec<String>,
}

/// `user.` + 1..=48 of `[a-z0-9-]`, not starting with `-` (the same rule as
/// `saiifeguard::userpack::valid_user_pack_id`).
pub fn valid_user_pack_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("user.") else {
        return false;
    };
    (1..=48).contains(&rest.len())
        && !rest.starts_with('-')
        && rest
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Reads every `*.toml` in `dir` (missing dir: none), recording each file's
/// name and SHA-256 in `files`. Any problem names the file (or the dir).
pub fn read_user_packs(
    dir: &Path,
    files: &mut Vec<(String, String)>,
) -> Result<Vec<UserPackFile>, PolicyError> {
    let paths = dropin_paths(dir)?;
    if paths.len() > MAX_USER_PACKS {
        return Err(invalid(
            dir,
            format!("{} pack files; at most {MAX_USER_PACKS}", paths.len()),
        ));
    }
    let mut out: Vec<UserPackFile> = Vec::new();
    let mut total = 0usize;
    for path in paths {
        let text = read_policy_file(&path, files)?;
        total += text.len();
        if total > MAX_USER_PACK_BYTES {
            return Err(invalid(
                dir,
                format!(
                    "pack files total more than {} KiB",
                    MAX_USER_PACK_BYTES / 1024
                ),
            ));
        }
        let sha256 = files.last().map(|f| f.1.clone()).unwrap_or_default();
        let pack = parse_header(&path, text, sha256)?;
        if let Some(first) = out.iter().find(|p| p.id == pack.id) {
            return Err(invalid(
                &path,
                format!("pack id {} is also defined in {}", pack.id, first.path),
            ));
        }
        out.push(pack);
    }
    Ok(out)
}

fn parse_header(path: &Path, text: String, sha256: String) -> Result<UserPackFile, PolicyError> {
    let bad = |detail: String| invalid(path, detail);
    let table: toml::Table = toml::from_str(&text).map_err(|e| PolicyError::Parse {
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;
    let header = table.get("pack").and_then(|v| v.as_table());
    let id = match header.and_then(|h| h.get("id")) {
        Some(toml::Value::String(s)) => s.clone(),
        _ => return Err(bad("[pack] id must be a string".into())),
    };
    if !valid_user_pack_id(&id) {
        return Err(bad(format!(
            "pack id {id:?} must be user.<1-48 of a-z 0-9 ->, not starting with -"
        )));
    }
    let version = match header.and_then(|h| h.get("version")) {
        None => 1,
        Some(toml::Value::Integer(n)) if *n >= 1 && *n <= i64::from(u32::MAX) => *n as u32,
        Some(_) => return Err(bad("[pack] version must be an integer >= 1".into())),
    };
    let mut rules = Vec::new();
    let mut ask = Vec::new();
    match table.get("deny") {
        None => {}
        Some(toml::Value::Array(items)) => {
            for item in items {
                let t = item
                    .as_table()
                    .ok_or_else(|| bad("[[deny]] entry is not a table".into()))?;
                let rule_id = match t.get("id") {
                    None => None,
                    Some(toml::Value::String(s)) => Some(s.clone()),
                    Some(_) => return Err(bad("[[deny]] id must be a string".into())),
                };
                let asks = match t.get("ask") {
                    None => false,
                    Some(toml::Value::Boolean(b)) => *b,
                    Some(_) => return Err(bad("[[deny]] ask must be a boolean".into())),
                };
                match (rule_id, asks) {
                    (Some(r), a) => {
                        if a {
                            ask.push(r.clone());
                        }
                        rules.push(r);
                    }
                    (None, true) => {
                        return Err(bad("a [[deny]] rule with ask = true needs an id".into()))
                    }
                    (None, false) => {}
                }
            }
        }
        Some(_) => return Err(bad("deny must be an array of tables".into())),
    }
    Ok(UserPackFile {
        path: path.display().to_string(),
        sha256,
        text,
        id,
        version,
        rules,
        ask,
    })
}

/// Every user pack as an always-active pack, with its file's SHA-256.
pub fn pack_infos(cfg: &SystemConfig) -> Vec<PackInfo> {
    cfg.user_packs
        .iter()
        .map(|u| PackInfo {
            id: u.id.clone(),
            version: u.version,
            default_on: true,
            rules: u.rules.clone(),
            sha256: Some(u.sha256.clone()),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_rule() {
        for ok in [
            "user.a",
            "user.a-b",
            "user.0",
            &format!("user.{}", "a".repeat(48)),
        ] {
            assert!(valid_user_pack_id(ok), "{ok}");
        }
        for bad in [
            "core.git",
            "user.",
            "user.-x",
            "user.A",
            "user.a_b",
            "user.a.b",
            "usera",
            "user.é",
            &format!("user.{}", "a".repeat(49)),
        ] {
            assert!(!valid_user_pack_id(bad), "{bad}");
        }
    }
}
