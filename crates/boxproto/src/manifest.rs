//! The base manifest (plan 37, spec §7.5 In): what the box's repo disk holds,
//! written by the CLI at spawn, carried to the daemon with the disk, and the
//! base plan 39's land diffs against. JSON, `deny_unknown_fields`.
//!
//! Paths are the `git ls-files` paths: UTF-8, relative, `/`-separated, with
//! no `.git` component; [`check_path`] is the one rule for them (plan 39's
//! delta validator reuses it).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// The only manifest version.
pub const VERSION: u32 = 1;

/// D5: the most a box repo may hold, summed as in D4 (the CLI's cap on the
/// snapshot; the daemon bounds the repo disk it takes by it).
pub const REPO_MAX_BYTES: u64 = 8 << 30;

/// The longest path [`check_path`] accepts, in bytes.
pub const PATH_MAX: usize = 4096;

/// The longest path component [`check_path`] accepts, in bytes.
pub const NAME_MAX: usize = 255;

/// The longest symlink target an entry may record, in bytes (Linux keeps
/// at most 4095).
pub const LINK_MAX: u64 = 4095;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Symlink,
}

/// One path of the snapshot. `File`: `mode` 0o644 or 0o755, `size` and
/// `sha256` of the content. `Symlink`: `mode` 0, `size` and `sha256` of the
/// target bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub kind: EntryKind,
    pub mode: u32,
    pub size: u64,
    pub sha256: String,
}

/// `files` is the number of entries; `bytes` the sum of their `size`.
/// `snapshot_commit` is empty until the CLI has written the snapshot commit
/// (a parsed manifest always has it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaseManifest {
    pub version: u32,
    pub repo: String,
    pub base_commit: Option<String>,
    pub snapshot_commit: String,
    pub files: u64,
    pub bytes: u64,
    pub entries: BTreeMap<String, Entry>,
}

/// A path inside the repo: non-empty, at most [`PATH_MAX`] bytes, each
/// `/`-separated component 1..=[`NAME_MAX`] bytes (so no leading, trailing
/// or doubled `/`), no NUL, no `\`, no `.` or `..` component, and no
/// component equal to `.git` in any letter case.
pub fn check_path(p: &str) -> Result<(), String> {
    let bad = |why: &str| Err(format!("path {:?}: {why}", p));
    if p.is_empty() {
        return bad("empty");
    }
    if p.len() > PATH_MAX {
        return bad("longer than 4096 bytes");
    }
    if p.starts_with('/') {
        return bad("absolute");
    }
    if p.contains('\0') {
        return bad("contains NUL");
    }
    if p.contains('\\') {
        return bad("contains a backslash");
    }
    for c in p.split('/') {
        if c.is_empty() {
            return bad("has an empty component");
        }
        if c.len() > NAME_MAX {
            return bad("has a component longer than 255 bytes");
        }
        if c == "." || c == ".." {
            return bad("has a . or .. component");
        }
        if c.eq_ignore_ascii_case(".git") {
            return bad("has a .git component");
        }
    }
    Ok(())
}

pub(crate) fn is_hex(s: &str, lens: &[usize]) -> bool {
    lens.contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A git object id: 40 (SHA-1) or 64 (SHA-256) lowercase hex digits.
pub fn is_oid(s: &str) -> bool {
    is_hex(s, &[40, 64])
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl BaseManifest {
    /// Parse and check a manifest: version 1, a display name, commit ids
    /// that are git object ids, every key passing [`check_path`], no key a
    /// parent directory of another, modes and hashes as [`Entry`] says, and
    /// `files`/`bytes` matching the entries.
    pub fn parse(text: &str) -> Result<BaseManifest, String> {
        let m: BaseManifest =
            serde_json::from_str(text).map_err(|e| format!("base manifest: {e}"))?;
        let bad = |why: String| Err(format!("base manifest: {why}"));
        if m.version != VERSION {
            return bad(format!("version {} (want {VERSION})", m.version));
        }
        if m.repo.is_empty() || m.repo.len() > NAME_MAX || m.repo.chars().any(char::is_control) {
            return bad("repo is not a display name".into());
        }
        if let Some(b) = &m.base_commit {
            if !is_oid(b) {
                return bad("base_commit is not a commit id".into());
            }
        }
        if !is_oid(&m.snapshot_commit) {
            return bad("snapshot_commit is not a commit id".into());
        }
        if m.files != m.entries.len() as u64 {
            return bad(format!(
                "files is {} but there are {} entries",
                m.files,
                m.entries.len()
            ));
        }
        let mut bytes = 0u64;
        for (p, e) in &m.entries {
            check_path(p).map_err(|e| format!("base manifest: {e}"))?;
            let ok_mode = match e.kind {
                EntryKind::File => e.mode == 0o644 || e.mode == 0o755,
                EntryKind::Symlink => e.mode == 0 && e.size <= LINK_MAX,
            };
            if !ok_mode {
                return bad(format!("{p:?}: bad mode or size for its kind"));
            }
            if !is_hex(&e.sha256, &[64]) {
                return bad(format!("{p:?}: sha256 is not 64 lowercase hex digits"));
            }
            let mut parent = p.as_str();
            while let Some((up, _)) = parent.rsplit_once('/') {
                if m.entries.contains_key(up) {
                    return bad(format!("{up:?} is both an entry and a directory"));
                }
                parent = up;
            }
            bytes = match bytes.checked_add(e.size) {
                Some(b) => b,
                None => return bad("bytes overflow".into()),
            };
        }
        if bytes != m.bytes {
            return bad(format!("bytes is {} but the entries hold {bytes}", m.bytes));
        }
        Ok(m)
    }

    /// SHA-256 (lowercase hex) of the manifest's JSON with
    /// `snapshot_commit` set to `""`: the value the snapshot commit's
    /// `Saiife-Box-Snapshot:` trailer carries, the same before and after the
    /// commit id is filled in.
    pub fn sha256(&self) -> String {
        let mut m = self.clone();
        m.snapshot_commit.clear();
        let body = serde_json::to_vec(&m).expect("a manifest always serializes");
        hex(&Sha256::digest(&body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_path_rules() {
        for ok in [
            "a/b",
            "a",
            "a b/c\nd",
            ".gitignore",
            "x/.github/y",
            "a.git/b",
        ] {
            assert_eq!(check_path(ok), Ok(()), "{ok:?}");
        }
        let long = "x".repeat(256);
        let deep = vec!["d"; 2049].join("/");
        for bad in [
            "",
            "/a",
            "a/../b",
            "./a",
            "a//b",
            "a/",
            ".GIT/config",
            "x/.git",
            ".Git",
            "a\\b",
            "a\0b",
            long.as_str(),
            deep.as_str(),
        ] {
            assert!(check_path(bad).is_err(), "{bad:?} passed");
        }
        assert_eq!(check_path(&"x".repeat(255)), Ok(()));
    }

    fn sample() -> BaseManifest {
        let mut entries = BTreeMap::new();
        entries.insert(
            "src/main.rs".to_string(),
            Entry {
                kind: EntryKind::File,
                mode: 0o644,
                size: 3,
                sha256: "a".repeat(64),
            },
        );
        entries.insert(
            "run".to_string(),
            Entry {
                kind: EntryKind::Symlink,
                mode: 0,
                size: 11,
                sha256: "b".repeat(64),
            },
        );
        BaseManifest {
            version: 1,
            repo: "demo".into(),
            base_commit: Some("c".repeat(40)),
            snapshot_commit: "d".repeat(40),
            files: 2,
            bytes: 14,
            entries,
        }
    }

    #[test]
    fn parse_round_trips_and_checks() {
        let m = sample();
        let text = serde_json::to_string(&m).unwrap();
        assert_eq!(BaseManifest::parse(&text), Ok(m.clone()));

        let mut unknown: serde_json::Value = serde_json::from_str(&text).unwrap();
        unknown["extra"] = 1.into();
        assert!(BaseManifest::parse(&unknown.to_string()).is_err());

        type Spoil = Box<dyn Fn(&mut BaseManifest)>;
        let cases: Vec<(&str, Spoil)> = vec![
            ("version", Box::new(|m| m.version = 2)),
            ("base", Box::new(|m| m.base_commit = Some("xyz".into()))),
            ("snap", Box::new(|m| m.snapshot_commit.clear())),
            ("files", Box::new(|m| m.files = 3)),
            ("bytes", Box::new(|m| m.bytes = 13)),
            (
                "mode",
                Box::new(|m| m.entries.get_mut("run").unwrap().mode = 0o644),
            ),
            (
                "fmode",
                Box::new(|m| m.entries.get_mut("src/main.rs").unwrap().mode = 0o600),
            ),
            (
                "sha",
                Box::new(|m| m.entries.get_mut("run").unwrap().sha256 = "B".repeat(64)),
            ),
            (
                "path",
                Box::new(|m| {
                    let e = m.entries.remove("run").unwrap();
                    m.entries.insert(".git/config".into(), e);
                }),
            ),
            (
                "dir-and-file",
                Box::new(|m| {
                    let e = m.entries.remove("run").unwrap();
                    m.entries.insert("src".into(), e);
                }),
            ),
        ];
        for (name, f) in cases {
            let mut m = sample();
            f(&mut m);
            let text = serde_json::to_string(&m).unwrap();
            assert!(BaseManifest::parse(&text).is_err(), "{name} passed");
        }
    }

    #[test]
    fn sha256_ignores_the_snapshot_commit() {
        let a = sample();
        let mut b = sample();
        b.snapshot_commit.clear();
        assert_eq!(a.sha256(), b.sha256());
        assert_eq!(a.sha256().len(), 64);
        b.entries.get_mut("run").unwrap().size = 12;
        assert_ne!(a.sha256(), b.sha256());
    }
}
