//! Stable project names and per-project state.
use crate::paths::DevPaths;
use crate::DevError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectState {
    pub name: String,
    pub dir: PathBuf,
    pub created: String,
    pub last_up: Option<String>,
}

const MAX_LEN: usize = 40;

fn io_err(path: &Path, source: std::io::Error) -> DevError {
    DevError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn now() -> String {
    const F: &[time::format_description::FormatItem<'static>] =
        time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    time::OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|t| t.format(F).ok())
        .unwrap_or_default()
}

/// A folder name as a DNS label: `[a-z0-9-]`, at most 40, no leading or trailing `-`.
pub fn dns_label(folder: &str) -> Option<String> {
    let mut out = String::new();
    for c in folder.to_lowercase().chars() {
        let c = if c.is_ascii_lowercase() || c.is_ascii_digit() {
            c
        } else {
            '-'
        };
        if c == '-' && out.ends_with('-') {
            continue;
        }
        out.push(c);
    }
    let trimmed = out.trim_matches('-');
    let cut: String = trimmed.chars().take(MAX_LEN).collect();
    let cut = cut.trim_end_matches('-');
    if cut.is_empty() {
        None
    } else {
        Some(cut.to_string())
    }
}

/// `Ok` only for a name `dns_label` would leave unchanged.
pub fn check_name(p: &str) -> Result<(), DevError> {
    if dns_label(p).as_deref() == Some(p) {
        Ok(())
    } else {
        Err(DevError::BadProjectName(p.to_string()))
    }
}

/// The project for `dir`: the one already recorded, else a new claim.
pub fn assign(paths: &DevPaths, dir: &Path) -> Result<ProjectState, DevError> {
    let dir = std::fs::canonicalize(dir).map_err(|e| io_err(dir, e))?;
    if let Some(s) = list(paths)?.into_iter().find(|s| s.dir == dir) {
        return Ok(s);
    }
    let file = dir
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();
    let base = dns_label(&file).ok_or(DevError::BadProjectName(file))?;
    let projects = paths.state.join("projects");
    std::fs::create_dir_all(&projects).map_err(|e| io_err(&projects, e))?;
    let mut n = 1u32;
    loop {
        let name = if n == 1 {
            base.clone()
        } else {
            let suffix = format!("-{n}");
            let keep: String = base.chars().take(MAX_LEN - suffix.len()).collect();
            format!("{}{suffix}", keep.trim_end_matches('-'))
        };
        let claim = paths.project_dir(&name);
        match std::fs::create_dir(&claim) {
            Ok(()) => {
                let s = ProjectState {
                    name,
                    dir,
                    created: now(),
                    last_up: None,
                };
                save(paths, &s)?;
                return Ok(s);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => n += 1,
            Err(e) => return Err(io_err(&claim, e)),
        }
    }
}

/// Write `project.json` atomically (temp file, then rename).
pub fn save(paths: &DevPaths, s: &ProjectState) -> Result<(), DevError> {
    check_name(&s.name)?;
    let dir = paths.project_dir(&s.name);
    std::fs::create_dir_all(&dir).map_err(|e| io_err(&dir, e))?;
    let file = paths.project_file(&s.name);
    let tmp = dir.join(format!("project.json.tmp.{}", std::process::id()));
    let text = serde_json::to_string_pretty(s).map_err(|e| DevError::State {
        path: file.clone(),
        msg: e.to_string(),
    })?;
    std::fs::write(&tmp, text).map_err(|e| io_err(&tmp, e))?;
    std::fs::rename(&tmp, &file).map_err(|e| io_err(&file, e))
}

fn read_state(file: &Path, expected: &str) -> Result<Option<ProjectState>, DevError> {
    match std::fs::read_to_string(file) {
        Ok(text) => {
            let bad = |msg: String| DevError::State {
                path: file.to_path_buf(),
                msg,
            };
            let s: ProjectState = serde_json::from_str(&text).map_err(|e| bad(e.to_string()))?;
            if s.name != expected || check_name(&s.name).is_err() {
                return Err(bad("name does not match its folder".into()));
            }
            Ok(Some(s))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_err(file, e)),
    }
}

pub fn load(paths: &DevPaths, name: &str) -> Result<Option<ProjectState>, DevError> {
    check_name(name)?;
    read_state(&paths.project_file(name), name)
}

/// Every project with a `project.json`, sorted by name. Other files are ignored.
pub fn list(paths: &DevPaths) -> Result<Vec<ProjectState>, DevError> {
    let projects = paths.state.join("projects");
    let rd = match std::fs::read_dir(&projects) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io_err(&projects, e)),
    };
    let mut out = Vec::new();
    for entry in rd {
        let entry = entry.map_err(|e| io_err(&projects, e))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let folder = entry.file_name().to_string_lossy().into_owned();
        if let Some(s) = read_state(&path.join("project.json"), &folder)? {
            out.push(s);
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup() -> (tempfile::TempDir, DevPaths) {
        let t = tempfile::tempdir().unwrap();
        let paths = DevPaths {
            state: t.path().join("state"),
            config: t.path().join("config"),
        };
        (t, paths)
    }

    fn mk(t: &tempfile::TempDir, rel: &str) -> PathBuf {
        let p = t.path().join(rel);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn dns_label_cases() {
        assert_eq!(dns_label("Shop").as_deref(), Some("shop"));
        assert_eq!(dns_label("My_App.v2").as_deref(), Some("my-app-v2"));
        assert_eq!(dns_label("--a--b--").as_deref(), Some("a-b"));
        assert_eq!(dns_label("..."), None);
        assert_eq!(dns_label(""), None);
        assert_eq!(dns_label("Über").as_deref(), Some("ber"));
        let long = format!("{}-{}", "a".repeat(39), "b".repeat(10));
        assert_eq!(dns_label(&long), Some("a".repeat(39)));
    }

    #[test]
    fn check_name_rejects_traversal() {
        for bad in ["../x", "a/b", "A", "-a", "", &"a".repeat(41)] {
            assert!(
                matches!(check_name(bad), Err(DevError::BadProjectName(_))),
                "{bad}"
            );
        }
        assert!(check_name("shop-2").is_ok());
    }

    #[test]
    fn assign_is_stable() {
        let (t, paths) = setup();
        let d = mk(&t, "a/shop");
        let first = assign(&paths, &d).unwrap();
        let via = d.join("..").join("shop");
        let second = assign(&paths, &via).unwrap();
        assert_eq!(first, second);
        assert_eq!(list(&paths).unwrap().len(), 1);
    }

    #[test]
    fn same_folder_name_gets_suffix() {
        let (t, paths) = setup();
        let a = mk(&t, "a/shop");
        let b = mk(&t, "b/shop");
        let c = mk(&t, "c/shop");
        assert_eq!(assign(&paths, &a).unwrap().name, "shop");
        assert_eq!(assign(&paths, &b).unwrap().name, "shop-2");
        assert_eq!(assign(&paths, &c).unwrap().name, "shop-3");
        assert_eq!(assign(&paths, &a).unwrap().name, "shop");
    }

    #[test]
    fn suffix_respects_length() {
        let (t, paths) = setup();
        let name = "a".repeat(40);
        let a = mk(&t, &format!("a/{name}"));
        let b = mk(&t, &format!("b/{name}"));
        assert_eq!(assign(&paths, &a).unwrap().name, name);
        let second = assign(&paths, &b).unwrap().name;
        assert_eq!(second.len(), 40);
        assert!(second.ends_with("-2"));
        assert!(check_name(&second).is_ok());
    }

    #[test]
    fn unnamable_folder_is_an_error() {
        let (t, paths) = setup();
        let d = mk(&t, "___");
        match assign(&paths, &d) {
            Err(DevError::BadProjectName(n)) => assert_eq!(n, "___"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn claimed_dir_is_skipped() {
        let (t, paths) = setup();
        fs::create_dir_all(paths.project_dir("shop")).unwrap();
        let d = mk(&t, "shop");
        assert_eq!(assign(&paths, &d).unwrap().name, "shop-2");
        let names: Vec<_> = list(&paths).unwrap().into_iter().map(|s| s.name).collect();
        assert_eq!(names, vec!["shop-2".to_string()]);
    }

    #[test]
    fn save_and_load_round_trip() {
        let (t, paths) = setup();
        let d = mk(&t, "shop");
        let mut s = assign(&paths, &d).unwrap();
        s.last_up = Some("2026-11-10T01:02:03Z".into());
        save(&paths, &s).unwrap();
        assert_eq!(load(&paths, "shop").unwrap(), Some(s));
        assert_eq!(load(&paths, "none").unwrap(), None);
        assert!(matches!(
            load(&paths, "../x"),
            Err(DevError::BadProjectName(_))
        ));
    }

    #[test]
    fn cli_files_are_ignored() {
        let (t, paths) = setup();
        let d = mk(&t, "shop");
        assign(&paths, &d).unwrap();
        let pd = paths.project_dir("shop");
        fs::write(pd.join("compose.json"), "{").unwrap();
        fs::write(pd.join("urls.json"), "[").unwrap();
        fs::write(pd.join("project.json.tmp.123"), "x").unwrap();
        fs::write(pd.parent().unwrap().join("README"), "hi").unwrap();
        assert_eq!(list(&paths).unwrap().len(), 1);
    }

    #[test]
    fn save_is_atomic() {
        let (t, paths) = setup();
        let d = mk(&t, "shop");
        let mut s = assign(&paths, &d).unwrap();
        s.last_up = Some("2026-11-10T01:02:03Z".into());
        save(&paths, &s).unwrap();
        s.last_up = None;
        save(&paths, &s).unwrap();
        let leftovers = fs::read_dir(paths.project_dir("shop"))
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("project.json.tmp")
            })
            .count();
        assert_eq!(leftovers, 0);
        let text = fs::read_to_string(paths.project_file("shop")).unwrap();
        let back: ProjectState = serde_json::from_str(&text).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn mismatched_or_unsafe_name_in_state_is_refused() {
        let (t, paths) = setup();
        let d = mk(&t, "shop");
        assign(&paths, &d).unwrap();
        let file = paths.project_file("shop");
        for bad in ["other", "../x"] {
            let text = fs::read_to_string(&file).unwrap();
            let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
            v["name"] = bad.into();
            fs::write(&file, v.to_string()).unwrap();
            assert!(matches!(load(&paths, "shop"), Err(DevError::State { .. })));
            assert!(matches!(list(&paths), Err(DevError::State { .. })));
        }
    }

    #[test]
    fn corrupt_state_is_named() {
        let (_t, paths) = setup();
        fs::create_dir_all(paths.project_dir("shop")).unwrap();
        fs::write(paths.project_file("shop"), "{").unwrap();
        match list(&paths) {
            Err(DevError::State { path, .. }) => assert!(path.ends_with("project.json")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn created_is_utc() {
        let (t, paths) = setup();
        let s = assign(&paths, &mk(&t, "shop")).unwrap();
        let b = s.created.as_bytes();
        assert_eq!(b.len(), 20);
        for (i, c) in b.iter().enumerate() {
            match i {
                4 | 7 => assert_eq!(*c, b'-'),
                10 => assert_eq!(*c, b'T'),
                13 | 16 => assert_eq!(*c, b':'),
                19 => assert_eq!(*c, b'Z'),
                _ => assert!(c.is_ascii_digit(), "{}", s.created),
            }
        }
    }
}
