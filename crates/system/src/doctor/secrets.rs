//! The plaintext-secret scan of `saiife doctor` (spec §6.16): credential
//! files in an agent user's home, `.env*` files under the scoped project
//! roots, and tokens in agent MCP configs. A finding names the path and
//! what was found, never the value.

use rustix::fs::{fstat, openat, statat, AtFlags, Dir, FileType, Mode, OFlags, CWD};
use rustix::io::Errno;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

/// One plaintext credential in an agent user's reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub path: PathBuf,
    pub what: String,
}

/// Credential files and dirs below the home (spec §6.16).
pub const HOME_PATHS: [&str; 11] = [
    ".aws/credentials",
    ".config/gcloud",
    ".azure",
    ".kube/config",
    ".docker/config.json",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
    ".config/gh/hosts.yml",
    ".vault-token",
];

/// Largest prefix read from one file (1 MiB).
pub const MAX_READ: u64 = 1024 * 1024;
/// Most entries the `.env*` walk looks at per project root.
pub const MAX_ENTRIES: usize = 10_000;
/// Deepest level the `.env*` walk reaches (the root's entries are level 1).
pub const MAX_DEPTH: usize = 4;
/// What a symlink at (or above) a scanned path is reported as.
pub const SYMLINK: &str = "is a symlink or lies below one: not followed (check where it points)";

/// Key-name parts that mark an MCP env or header value as a credential.
const CREDENTIAL_KEYS: [&str; 5] = ["TOKEN", "KEY", "SECRET", "PASSWORD", "AUTHORIZATION"];

/// Scans `home` (an agent user's home, as reachable from here) and the
/// `.env*` files under `project_roots`. Nothing is followed through a
/// symlink below `home` or a project root, nothing but regular files is
/// opened, and at most [`MAX_READ`] bytes are read per file. Files that
/// cannot be read are skipped.
pub fn scan(home: &Path, project_roots: &[PathBuf]) -> Vec<Finding> {
    let mut out = Vec::new();
    for rel in HOME_PATHS {
        let path = home.join(rel);
        let what = match open_under(home, Path::new(rel)) {
            Node::Symlink => Some(SYMLINK),
            Node::Dir(fd) if is_cred_dir(rel) => {
                non_empty_dir(&fd).then_some("is a credentials directory with files in it")
            }
            Node::File(f) if !is_cred_dir(rel) => read_bounded(f)
                .ok()
                .and_then(|bytes| file_rule(rel, &bytes)),
            _ => None,
        };
        if let Some(what) = what {
            out.push(Finding {
                path,
                what: what.to_string(),
            });
        }
    }
    mcp(home, &mut out);
    for root in project_roots {
        walk_env(root, &mut out);
    }
    out
}

fn is_cred_dir(rel: &str) -> bool {
    matches!(rel, ".config/gcloud" | ".azure")
}

/// What the file `rel` of [`HOME_PATHS`] holds, by its content.
fn file_rule(rel: &str, bytes: &[u8]) -> Option<&'static str> {
    let text = String::from_utf8_lossy(bytes);
    match rel {
        ".npmrc" => text
            .lines()
            .filter_map(|l| kv(l, &['=']))
            .any(|(k, v)| (k.ends_with("_authToken") || k.ends_with("_auth")) && !v.is_empty())
            .then_some("holds an npm auth token"),
        ".pypirc" => text
            .lines()
            .filter_map(|l| kv(l, &['=', ':']))
            .any(|(k, v)| k == "password" && !v.is_empty())
            .then_some("holds a password"),
        ".netrc" => {
            let words: Vec<&str> = text.split_whitespace().collect();
            words
                .windows(2)
                .any(|w| w[0] == "password")
                .then_some("holds a password")
        }
        ".docker/config.json" => serde_json::from_slice::<serde_json::Value>(bytes)
            .ok()
            .filter(has_docker_auth)
            .map(|_| "holds a registry login (auth)"),
        _ => (!text.trim().is_empty()).then_some("holds credentials"),
    }
}

/// `key<sep>value` of one config line, both trimmed; comments skipped.
fn kv<'a>(line: &'a str, seps: &[char]) -> Option<(&'a str, &'a str)> {
    let line = line.trim();
    if line.starts_with('#') || line.starts_with(';') {
        return None;
    }
    let (k, v) = line.split_once(seps)?;
    Some((k.trim(), v.trim()))
}

/// A non-empty string `auth` anywhere in the Docker config.
fn has_docker_auth(v: &serde_json::Value) -> bool {
    use serde_json::Value;
    match v {
        Value::Object(m) => m.iter().any(|(k, v)| {
            (k == "auth" && v.as_str().is_some_and(|s| !s.trim().is_empty())) || has_docker_auth(v)
        }),
        Value::Array(a) => a.iter().any(has_docker_auth),
        _ => false,
    }
}

// ------------------------------------------------------------ MCP configs

fn mcp(home: &Path, out: &mut Vec<Finding>) {
    use serde_json::Value;
    for rel in [".claude.json", ".gemini/settings.json"] {
        let path = home.join(rel);
        match open_under(home, Path::new(rel)) {
            Node::Symlink => out.push(Finding {
                path,
                what: SYMLINK.to_string(),
            }),
            Node::File(f) => {
                let Some(v) = read_bounded(f)
                    .ok()
                    .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                else {
                    continue;
                };
                let mut servers: Vec<&Value> = vec![&v["mcpServers"]];
                if let Some(projects) = v["projects"].as_object() {
                    servers.extend(projects.values().map(|p| &p["mcpServers"]));
                }
                for map in servers.iter().filter_map(|s| s.as_object()) {
                    for (name, server) in map {
                        for field in ["env", "headers"] {
                            let Some(kvs) = server[field].as_object() else {
                                continue;
                            };
                            for (k, v) in kvs {
                                let set = match v {
                                    Value::Null => false,
                                    Value::String(s) => is_plain_value(s),
                                    _ => true,
                                };
                                if set && is_credential_key(k) {
                                    out.push(mcp_finding(&path, name, k));
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    let rel = ".codex/config.toml";
    let path = home.join(rel);
    match open_under(home, Path::new(rel)) {
        Node::Symlink => out.push(Finding {
            path,
            what: SYMLINK.to_string(),
        }),
        Node::File(f) => {
            let Some(v) = read_bounded(f)
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
                .and_then(|t| t.parse::<toml::Table>().ok())
            else {
                return;
            };
            let Some(servers) = v.get("mcp_servers").and_then(|s| s.as_table()) else {
                return;
            };
            for (name, server) in servers {
                for field in ["env", "http_headers"] {
                    let Some(kvs) = server.get(field).and_then(|e| e.as_table()) else {
                        continue;
                    };
                    for (k, v) in kvs {
                        let set = match v {
                            toml::Value::String(s) => is_plain_value(s),
                            _ => true,
                        };
                        if set && is_credential_key(k) {
                            out.push(mcp_finding(&path, name, k));
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

fn mcp_finding(path: &Path, server: &str, key: &str) -> Finding {
    Finding {
        path: path.to_path_buf(),
        what: format!("MCP server {server} holds a credential in {key}"),
    }
}

fn is_credential_key(k: &str) -> bool {
    let up = k.to_ascii_uppercase();
    CREDENTIAL_KEYS.iter().any(|c| up.contains(c))
}

/// A value that is set and is not just a reference to an environment
/// variable (`$NAME`, `${NAME}`), which holds no credential itself.
fn is_plain_value(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() {
        return false;
    }
    let var = |n: &str| !n.is_empty() && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    let reference = match s.strip_prefix('$') {
        Some(r) => match r.strip_prefix('{').and_then(|r| r.strip_suffix('}')) {
            Some(inner) => var(inner),
            None => var(r),
        },
        None => false,
    };
    !reference
}

// ------------------------------------------------------------ .env walk

fn walk_env(root: &Path, out: &mut Vec<Finding>) -> usize {
    let Ok(fd) = open_base(root) else {
        return 0;
    };
    let mut seen = 0;
    walk(&fd, root, 1, &mut seen, out);
    seen
}

fn walk(dir: &OwnedFd, path: &Path, depth: usize, seen: &mut usize, out: &mut Vec<Finding>) {
    let Ok(entries) = Dir::read_from(dir) else {
        return;
    };
    let mut subdirs = Vec::new();
    for entry in entries {
        if *seen >= MAX_ENTRIES {
            break;
        }
        let Ok(entry) = entry else {
            break;
        };
        let name = OsStr::from_bytes(entry.file_name().to_bytes()).to_os_string();
        if name == "." || name == ".." {
            continue;
        }
        *seen += 1;
        let is_env = name.as_bytes().starts_with(b".env");
        let maybe_dir = matches!(entry.file_type(), FileType::Directory | FileType::Unknown);
        if !is_env && !(maybe_dir && depth < MAX_DEPTH) {
            continue;
        }
        match node_at(dir, &name) {
            Node::Symlink if is_env => out.push(Finding {
                path: path.join(&name),
                what: SYMLINK.to_string(),
            }),
            Node::File(f) if is_env => {
                if f.metadata().map(|m| m.len() > 0).unwrap_or(false) {
                    out.push(Finding {
                        path: path.join(&name),
                        what: "is an environment file (may hold secrets)".to_string(),
                    });
                }
            }
            Node::Dir(fd) if depth < MAX_DEPTH => subdirs.push((fd, name)),
            _ => {}
        }
    }
    for (fd, name) in subdirs {
        if *seen >= MAX_ENTRIES {
            break;
        }
        walk(&fd, &path.join(name), depth + 1, seen, out);
    }
}

// ------------------------------------------------------------ safe opens

/// What a path is, opened without following a symlink.
pub(crate) enum Node {
    Missing,
    /// The path, or a directory above it (below the base), is a symlink.
    Symlink,
    /// A regular file, opened `O_NOFOLLOW | O_NONBLOCK`.
    File(File),
    Dir(OwnedFd),
    /// A FIFO, socket, device, or a non-directory where a directory was
    /// expected. Never opened.
    Other,
    Error,
}

/// Opens `base` itself as a directory. `base` is a home from
/// `/etc/passwd` or a configured project root, so a symlink in it is
/// followed (an admin may link `/home`); nothing below it is.
fn open_base(base: &Path) -> io::Result<OwnedFd> {
    Ok(openat(
        CWD,
        base,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

/// `name` in `dir`, classified by `lstat` first: a regular file is opened
/// `O_NOFOLLOW | O_NONBLOCK` and checked again on the handle, a directory
/// `O_NOFOLLOW | O_DIRECTORY`; nothing else is opened.
fn node_at(dir: &OwnedFd, name: &OsStr) -> Node {
    let st = match statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => st,
        Err(Errno::NOENT) => return Node::Missing,
        Err(_) => return Node::Error,
    };
    match FileType::from_raw_mode(st.st_mode) {
        FileType::Symlink => Node::Symlink,
        FileType::Directory => match openat(
            dir,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => Node::Dir(fd),
            Err(Errno::LOOP) => Node::Symlink,
            Err(Errno::NOENT) => Node::Missing,
            Err(_) => Node::Error,
        },
        FileType::RegularFile => match openat(
            dir,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => match fstat(&fd) {
                Ok(st) if FileType::from_raw_mode(st.st_mode) == FileType::RegularFile => {
                    Node::File(File::from(fd))
                }
                Ok(_) => Node::Other,
                Err(_) => Node::Error,
            },
            Err(Errno::LOOP) => Node::Symlink,
            Err(Errno::NOENT) => Node::Missing,
            Err(_) => Node::Error,
        },
        _ => Node::Other,
    }
}

/// `rel` (plain components only) below `base`, never following a symlink
/// below `base`.
pub(crate) fn open_under(base: &Path, rel: &Path) -> Node {
    let parts: Option<Vec<&OsStr>> = rel
        .components()
        .map(|c| match c {
            Component::Normal(s) => Some(s),
            _ => None,
        })
        .collect();
    let Some(parts) = parts else {
        return Node::Error;
    };
    let mut dir = match open_base(base) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Node::Missing,
        Err(_) => return Node::Error,
    };
    let Some((last, above)) = parts.split_last() else {
        return Node::Dir(dir);
    };
    for part in above {
        dir = match node_at(&dir, part) {
            Node::Dir(d) => d,
            Node::Symlink => return Node::Symlink,
            Node::Missing => return Node::Missing,
            Node::Error => return Node::Error,
            Node::File(_) | Node::Other => return Node::Other,
        };
    }
    node_at(&dir, last)
}

/// The first [`MAX_READ`] bytes of `f`.
pub(crate) fn read_bounded(f: File) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    f.take(MAX_READ).read_to_end(&mut buf)?;
    #[cfg(test)]
    READ.with(|r| r.set(r.get() + buf.len() as u64));
    Ok(buf)
}

/// The regular file `rel` below `base`, read bounded; `None` for anything
/// else (missing, a symlink, unreadable).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn read_under(base: &Path, rel: &str) -> Option<Vec<u8>> {
    match open_under(base, Path::new(rel)) {
        Node::File(f) => read_bounded(f).ok(),
        _ => None,
    }
}

/// The directory has an entry besides `.` and `..`.
pub(crate) fn non_empty_dir(fd: &OwnedFd) -> bool {
    let Ok(entries) = Dir::read_from(fd) else {
        return false;
    };
    entries.filter_map(Result::ok).any(|e| {
        let n = e.file_name().to_bytes();
        n != b"." && n != b".."
    })
}

/// Names in the directory `rel` below `base` (at most [`MAX_ENTRIES`]),
/// with the directory's handle; `None` when it is not a plain directory.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn list_under(base: &Path, rel: &str) -> Option<(OwnedFd, Vec<OsString>)> {
    let Node::Dir(fd) = open_under(base, Path::new(rel)) else {
        return None;
    };
    let names = Dir::read_from(&fd)
        .ok()?
        .filter_map(Result::ok)
        .map(|e| OsStr::from_bytes(e.file_name().to_bytes()).to_os_string())
        .filter(|n| n != "." && n != "..")
        .take(MAX_ENTRIES)
        .collect();
    Some((fd, names))
}

/// The regular file `name` in `dir`, read bounded.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn read_at(dir: &OwnedFd, name: &OsStr) -> Option<Vec<u8>> {
    match node_at(dir, name) {
        Node::File(f) => read_bounded(f).ok(),
        _ => None,
    }
}

#[cfg(test)]
thread_local! {
    static READ: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn walk_count(root: &Path) -> usize {
    walk_env(root, &mut Vec::new())
}

#[cfg(test)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn reset_read_counter() {
    READ.with(|r| r.set(0));
}

#[cfg(test)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn read_counter() -> u64 {
    READ.with(|r| r.get())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{Duration, Instant};

    const VALUE: &str = "s3cr3t-VALUE";

    fn put(base: &Path, rel: &str, text: &str) -> PathBuf {
        let p = base.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, text).unwrap();
        p
    }

    fn whats(f: &[Finding]) -> String {
        format!("{f:?}")
    }

    #[test]
    fn finds_each_home_path_without_values() {
        let home = tempfile::tempdir().unwrap();
        let h = home.path();
        put(
            h,
            ".aws/credentials",
            &format!("[default]\naws_secret_access_key = {VALUE}\n"),
        );
        put(h, ".config/gcloud/credentials.db", VALUE);
        put(h, ".azure/msal_token_cache.json", VALUE);
        put(
            h,
            ".kube/config",
            &format!("users:\n- user:\n    token: {VALUE}\n"),
        );
        put(
            h,
            ".docker/config.json",
            &format!("{{\"auths\":{{\"r.example\":{{\"auth\":\"{VALUE}\"}}}}}}"),
        );
        put(
            h,
            ".npmrc",
            &format!("//registry.npmjs.org/:_authToken={VALUE}\n"),
        );
        put(
            h,
            ".pypirc",
            &format!("[pypi]\nusername = u\npassword = {VALUE}\n"),
        );
        put(
            h,
            ".netrc",
            &format!("machine m login u password {VALUE}\n"),
        );
        put(
            h,
            ".git-credentials",
            &format!("https://u:{VALUE}@github.com\n"),
        );
        put(
            h,
            ".config/gh/hosts.yml",
            &format!("github.com:\n  oauth_token: {VALUE}\n"),
        );
        put(h, ".vault-token", VALUE);

        let found = scan(h, &[]);
        let text = whats(&found);
        assert!(!text.contains(VALUE), "{text}");
        assert_eq!(found.len(), HOME_PATHS.len(), "{text}");
        for rel in HOME_PATHS {
            assert!(
                found.iter().any(|f| f.path == h.join(rel)),
                "{rel} missing in {text}"
            );
        }
    }

    #[test]
    fn empty_or_harmless_files_not_reported() {
        let home = tempfile::tempdir().unwrap();
        let h = home.path();
        put(h, ".pypirc", "[pypi]\nusername = u\n");
        put(h, ".netrc", "machine m login u\n");
        put(
            h,
            ".docker/config.json",
            "{\"auths\":{\"r\":{\"auth\":\"\"}},\"credsStore\":\"pass\"}",
        );
        put(h, ".vault-token", "\n");
        fs::create_dir_all(h.join(".azure")).unwrap();
        let found = scan(h, &[]);
        assert!(found.is_empty(), "{}", whats(&found));
    }

    #[test]
    fn npmrc_without_token_not_reported() {
        let home = tempfile::tempdir().unwrap();
        put(
            home.path(),
            ".npmrc",
            "registry=https://registry.npmjs.org/\n",
        );
        let found = scan(home.path(), &[]);
        assert!(found.is_empty(), "{}", whats(&found));
        put(home.path(), ".npmrc", &format!("_auth={VALUE}\n"));
        let found = scan(home.path(), &[]);
        assert_eq!(found.len(), 1, "{}", whats(&found));
        assert!(!whats(&found).contains(VALUE));
    }

    #[test]
    fn env_files_under_project_found() {
        let home = tempfile::tempdir().unwrap();
        let proj = tempfile::tempdir().unwrap();
        let p = proj.path();
        let top = put(p, "app/.env", &format!("API_KEY={VALUE}\n"));
        let deep = put(p, "app/a/b/.env.local", &format!("X={VALUE}\n"));
        // Depth 5: past the walk limit.
        put(p, "app/a/b/c/.env", &format!("X={VALUE}\n"));
        put(p, "app/.envrc-empty-dir/keep", "");
        put(p, "app/not-env", VALUE);
        // A symlinked directory is not entered.
        let outside = tempfile::tempdir().unwrap();
        put(outside.path(), ".env", VALUE);
        std::os::unix::fs::symlink(outside.path(), p.join("app/link")).unwrap();

        let found = scan(home.path(), &[p.to_path_buf()]);
        let text = whats(&found);
        assert!(!text.contains(VALUE), "{text}");
        let paths: Vec<&PathBuf> = found.iter().map(|f| &f.path).collect();
        assert!(paths.contains(&&top), "{text}");
        assert!(paths.contains(&&deep), "{text}");
        assert!(
            !paths.iter().any(|x| x.starts_with(outside.path())),
            "{text}"
        );
        assert!(!paths.iter().any(|x| x.ends_with("c/.env")), "{text}");
        assert!(!paths.iter().any(|x| x.ends_with("link")), "{text}");
        assert_eq!(found.len(), 2, "{text}");
    }

    #[test]
    fn env_walk_stops_at_entry_cap() {
        let home = tempfile::tempdir().unwrap();
        let proj = tempfile::tempdir().unwrap();
        for i in 0..(MAX_ENTRIES + 50) {
            fs::write(proj.path().join(format!("f{i:05}")), "").unwrap();
        }
        // Sorts after every `f*` name, but the walk order is the
        // directory's; only the cap is checked here.
        let started = Instant::now();
        let _ = scan(home.path(), &[proj.path().to_path_buf()]);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(walk_count(proj.path()), MAX_ENTRIES);
    }

    #[test]
    fn mcp_token_found_by_key_name() {
        let home = tempfile::tempdir().unwrap();
        let h = home.path();
        let claude = put(
            h,
            ".claude.json",
            &format!(
                r#"{{"mcpServers":{{"gh":{{"command":"x","env":{{"GITHUB_TOKEN":"{VALUE}","DEBUG":"1","EMPTY_KEY":"","REF_SECRET":"${{SECRET}}"}}}},
                  "web":{{"url":"https://x","headers":{{"Authorization":"Bearer {VALUE}"}}}}}},
                 "projects":{{"/p":{{"mcpServers":{{"db":{{"env":{{"db_password":"{VALUE}"}}}}}}}}}}}}"#
            ),
        );
        let codex = put(
            h,
            ".codex/config.toml",
            &format!("[mcp_servers.s1]\ncommand = \"x\"\n[mcp_servers.s1.env]\nAPI_KEY = \"{VALUE}\"\nPATH = \"/bin\"\n"),
        );
        let gemini = put(
            h,
            ".gemini/settings.json",
            &format!(r#"{{"mcpServers":{{"g":{{"headers":{{"x-api-key":"{VALUE}"}}}}}}}}"#),
        );
        let found = scan(h, &[]);
        let text = whats(&found);
        assert!(!text.contains(VALUE), "{text}");
        let has = |p: &Path, w: &str| found.iter().any(|f| f.path == p && f.what == w);
        assert!(
            has(&claude, "MCP server gh holds a credential in GITHUB_TOKEN"),
            "{text}"
        );
        assert!(
            has(
                &claude,
                "MCP server web holds a credential in Authorization"
            ),
            "{text}"
        );
        assert!(
            has(&claude, "MCP server db holds a credential in db_password"),
            "{text}"
        );
        assert!(
            has(&codex, "MCP server s1 holds a credential in API_KEY"),
            "{text}"
        );
        assert!(
            has(&gemini, "MCP server g holds a credential in x-api-key"),
            "{text}"
        );
        assert_eq!(found.len(), 5, "{text}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn secret_scan_never_follows_symlinks_or_blocks() {
        let home = tempfile::tempdir().unwrap();
        let h = home.path();
        let elsewhere = tempfile::tempdir().unwrap();
        let target = put(elsewhere.path(), "npmrc", &format!("_authToken={VALUE}\n"));
        std::os::unix::fs::symlink(&target, h.join(".npmrc")).unwrap();
        // A symlinked parent dir is not followed either.
        put(elsewhere.path(), "aws/credentials", VALUE);
        std::os::unix::fs::symlink(elsewhere.path().join("aws"), h.join(".aws")).unwrap();
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            h.join(".netrc"),
            rustix::fs::Mode::from(0o600),
        )
        .unwrap();
        let big = fs::File::create(h.join(".git-credentials")).unwrap();
        big.set_len(2 << 30).unwrap();
        drop(big);

        reset_read_counter();
        let started = Instant::now();
        let found = scan(h, &[]);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
        assert!(read_counter() <= MAX_READ, "read {} bytes", read_counter());
        let text = whats(&found);
        assert!(!text.contains(VALUE), "{text}");
        // Reported as symlinks, never read through.
        let npmrc = found.iter().find(|f| f.path == h.join(".npmrc")).unwrap();
        assert_eq!(npmrc.what, SYMLINK, "{text}");
        let aws = found
            .iter()
            .find(|f| f.path == h.join(".aws/credentials"))
            .unwrap();
        assert_eq!(aws.what, SYMLINK, "{text}");
        assert!(
            !found.iter().any(|f| f.path.starts_with(elsewhere.path())),
            "{text}"
        );
        assert!(!found.iter().any(|f| f.path == h.join(".netrc")), "{text}");
    }
}
