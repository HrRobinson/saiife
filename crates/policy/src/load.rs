//! Loading `config.toml` plus `policy.d/*.toml` (spec §8.1 "Merging").

use crate::capability::validate_pattern;
use crate::service::{is_interpreter, SecretCfg, ServiceCfg, AUTH_KINDS};
use crate::system::{Fail, McpCfg, Scope, SystemConfig};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

/// The merged system config, the files it came from (path, sha256 hex, in
/// read order) and load warnings.
#[derive(Debug, Clone)]
pub struct LoadedPolicy {
    pub config: SystemConfig,
    pub files: Vec<(String, String)>,
    pub warnings: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("{}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{}: {detail}", path.display())]
    Parse { path: PathBuf, detail: String },
    #[error("{}: {detail}", path.display())]
    Invalid { path: PathBuf, detail: String },
    #[error("{}: {key} is reserved for v3", path.display())]
    Reserved { path: PathBuf, key: String },
    #[error("service {name} is defined in {first} and again in {second}")]
    DuplicateService {
        name: String,
        first: String,
        second: String,
    },
    #[error("secret {secret}: run_allow entry {} runs arbitrary code (interpreters and shells are refused)", entry.display())]
    RunAllowInterpreter { secret: String, entry: PathBuf },
    #[error("user {user} matches more than one scope: {}", scopes.join(", "))]
    ScopeConflict { user: String, scopes: Vec<String> },
}

/// Largest config file or drop-in read (1 MiB).
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// Keys only `config.toml` may set; a drop-in setting one is `Invalid`.
const CONFIG_ONLY: &[&str] = &[
    "version", "locked", "daemon", "admin", "audit", "approval", "notify", "gateway",
];
const CONFIG_ONLY_GUARD: &[&str] = &["budget_ms", "fail"];

/// What a drop-in may hold: `[guard] packs/ask`, `[guard.mcp] allow_servers`,
/// `[services.*]`, `[[scope]]` and `[[example]]`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DropIn {
    #[serde(default)]
    guard: DropGuard,
    #[serde(default)]
    services: BTreeMap<String, ServiceCfg>,
    #[serde(default)]
    secrets: BTreeMap<String, SecretCfg>,
    #[serde(default)]
    scope: Vec<Scope>,
    #[serde(default)]
    example: Vec<toml::Table>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct DropGuard {
    packs: Vec<String>,
    ask: Vec<String>,
    mcp: McpCfg,
}

/// Reads `config_file`, then `<its dir>/policy.d/*.toml` in name order.
/// Only regular files are read (symlinks are refused), each at most 1 MiB.
pub fn load_system(config_file: &Path) -> Result<LoadedPolicy, PolicyError> {
    let mut files = Vec::new();
    let mut warnings = Vec::new();

    let text = read_policy_file(config_file, &mut files)?;
    let table = parse_table(config_file, &text)?;
    check_reserved(config_file, &table)?;
    let mut cfg: SystemConfig = toml::from_str(&text).map_err(|e| PolicyError::Parse {
        path: config_file.to_path_buf(),
        detail: e.to_string(),
    })?;
    if cfg.version != 2 {
        return Err(invalid(
            config_file,
            format!("version must be 2, found {}", cfg.version),
        ));
    }

    let config_name = config_file.display().to_string();
    let mut service_origin: BTreeMap<String, String> = cfg
        .services
        .keys()
        .map(|k| (k.clone(), config_name.clone()))
        .collect();
    let mut secret_origin: BTreeMap<String, String> = cfg
        .secrets
        .keys()
        .map(|k| (k.clone(), config_name.clone()))
        .collect();
    let mut scope_origin: BTreeMap<String, String> = BTreeMap::new();
    for s in &cfg.scope {
        if let Some(first) = scope_origin.insert(s.name.clone(), config_name.clone()) {
            return Err(dup_scope(config_file, &s.name, &first));
        }
    }

    for path in dropin_paths(config_file)? {
        let text = read_policy_file(&path, &mut files)?;
        let table = parse_table(&path, &text)?;
        check_reserved(&path, &table)?;
        check_dropin_keys(&path, &table)?;
        let d: DropIn = toml::from_str(&text).map_err(|e| PolicyError::Parse {
            path: path.clone(),
            detail: e.to_string(),
        })?;
        let name = path.display().to_string();

        cfg.guard.packs.extend(d.guard.packs);
        cfg.guard.ask.extend(d.guard.ask);
        cfg.guard
            .mcp
            .allow_servers
            .extend(d.guard.mcp.allow_servers);
        for (svc, t) in d.services {
            if let Some(first) = service_origin.get(&svc) {
                return Err(PolicyError::DuplicateService {
                    name: svc,
                    first: first.clone(),
                    second: name,
                });
            }
            service_origin.insert(svc.clone(), name.clone());
            cfg.services.insert(svc, t);
        }
        for (sec, c) in d.secrets {
            if let Some(first) = secret_origin.get(&sec) {
                return Err(invalid(
                    &path,
                    format!("secret {sec:?} is already defined in {first}"),
                ));
            }
            secret_origin.insert(sec.clone(), name.clone());
            cfg.secrets.insert(sec, c);
        }
        for s in d.scope {
            if let Some(first) = scope_origin.get(&s.name) {
                return Err(dup_scope(&path, &s.name, first));
            }
            scope_origin.insert(s.name.clone(), name.clone());
            cfg.scope.push(s);
        }
        cfg.example.extend(d.example);
    }

    validate_services(config_file, &cfg, &service_origin)?;
    for (name, sec) in &cfg.secrets {
        if let Some(entry) = sec.run_allow.iter().find(|p| !p.is_absolute()) {
            return Err(invalid(
                config_file,
                format!(
                    "secret {name}: run_allow entry {} must be an absolute path",
                    entry.display()
                ),
            ));
        }
        if let Some(entry) = sec.run_allow.iter().find(|p| is_interpreter(p)) {
            return Err(PolicyError::RunAllowInterpreter {
                secret: name.clone(),
                entry: entry.clone(),
            });
        }
    }

    if cfg.locked && cfg.guard.fail == Fail::Open {
        cfg.guard.fail = Fail::Closed;
        warnings.push(format!(
            "{config_name}: guard.fail = \"open\" ignored: locked = true forces \"closed\""
        ));
    }

    Ok(LoadedPolicy {
        config: cfg,
        files,
        warnings,
    })
}

/// Checks the typed services after the merge; errors name the file that
/// defined the service.
fn validate_services(
    config_file: &Path,
    cfg: &SystemConfig,
    origin: &BTreeMap<String, String>,
) -> Result<(), PolicyError> {
    for (name, svc) in &cfg.services {
        let file = origin
            .get(name)
            .map(PathBuf::from)
            .unwrap_or_else(|| config_file.to_path_buf());
        let patterns = svc
            .allow
            .iter()
            .chain(&svc.ask)
            .chain(&svc.deny)
            .chain(svc.rule.iter().map(|r| &r.capability));
        for pat in patterns {
            if let Err(why) = validate_pattern(pat) {
                return Err(invalid(
                    &file,
                    format!("service {name}: capability pattern {pat:?}: {why}"),
                ));
            }
        }
        if let Some(a) = &svc.auth {
            if !AUTH_KINDS.contains(&a.kind.as_str()) {
                return Err(invalid(
                    &file,
                    format!(
                        "service {name}: auth kind {:?} is not one of {}",
                        a.kind,
                        AUTH_KINDS.join(", ")
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn invalid(path: &Path, detail: impl Into<String>) -> PolicyError {
    PolicyError::Invalid {
        path: path.to_path_buf(),
        detail: detail.into(),
    }
}

fn dup_scope(path: &Path, name: &str, first: &str) -> PolicyError {
    invalid(
        path,
        format!("scope {name:?} is already defined in {first}"),
    )
}

fn parse_table(path: &Path, text: &str) -> Result<toml::Table, PolicyError> {
    toml::from_str(text).map_err(|e| PolicyError::Parse {
        path: path.to_path_buf(),
        detail: e.to_string(),
    })
}

/// `profile` is reserved for v3 at the top level and in `[[scope]]` (§18).
fn check_reserved(path: &Path, table: &toml::Table) -> Result<(), PolicyError> {
    let reserved = |key: &str| PolicyError::Reserved {
        path: path.to_path_buf(),
        key: key.to_string(),
    };
    if table.contains_key("profile") {
        return Err(reserved("profile"));
    }
    for section in ["services", "secrets"] {
        let Some(toml::Value::Table(entries)) = table.get(section) else {
            continue;
        };
        for (name, v) in entries {
            // `params` and `fixed` hold connector parameters, whose names are
            // free; §18 reserves config keys only.
            if let Some(at) = find_profile(v, section == "services") {
                let key = if at.is_empty() {
                    format!("{section}.{name}.profile")
                } else {
                    format!("{section}.{name}.{at}.profile")
                };
                return Err(reserved(&key));
            }
        }
    }
    if let Some(toml::Value::Array(scopes)) = table.get("scope") {
        for s in scopes {
            if let toml::Value::Table(t) = s {
                if t.contains_key("profile") {
                    return Err(reserved("scope.profile"));
                }
            }
        }
    }
    Ok(())
}

/// Path (dotted, without the final `profile`) of the first `profile` key
/// anywhere below `v`.
fn find_profile(v: &toml::Value, skip_maps: bool) -> Option<String> {
    match v {
        toml::Value::Table(t) => {
            if t.contains_key("profile") {
                return Some(String::new());
            }
            for (k, child) in t {
                if skip_maps && (k == "params" || k == "fixed") {
                    continue;
                }
                if let Some(rest) = find_profile(child, false) {
                    return Some(if rest.is_empty() {
                        k.clone()
                    } else {
                        format!("{k}.{rest}")
                    });
                }
            }
            None
        }
        toml::Value::Array(a) => a.iter().find_map(|x| find_profile(x, false)),
        _ => None,
    }
}

/// Keys of the system config that a drop-in may not set. Keys the config
/// does not know at all are left to the parser (a `Parse` error naming them).
fn check_dropin_keys(path: &Path, table: &toml::Table) -> Result<(), PolicyError> {
    let only = |key: &str| invalid(path, format!("{key} may only be set in config.toml"));
    for (k, v) in table {
        if CONFIG_ONLY.contains(&k.as_str()) {
            return Err(only(k));
        }
        if k == "guard" {
            if let toml::Value::Table(g) = v {
                for gk in g.keys() {
                    if CONFIG_ONLY_GUARD.contains(&gk.as_str()) {
                        return Err(only(&format!("guard.{gk}")));
                    }
                }
            }
        }
    }
    Ok(())
}

/// `<dir of config_file>/policy.d/*.toml`, sorted by file name (bytes). A
/// missing `policy.d` means no drop-ins; a symlinked one is refused, as a
/// symlinked drop-in is. Dot-files (editor lock links such as emacs
/// `.#a.toml`, hidden backups) are skipped.
fn dropin_paths(config_file: &Path) -> Result<Vec<PathBuf>, PolicyError> {
    let dir = config_file
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join("policy.d");
    match std::fs::symlink_metadata(&dir) {
        Ok(m) if m.file_type().is_symlink() => {
            return Err(invalid(&dir, "is a symlink (symlinks are not followed)"))
        }
        Ok(m) if !m.is_dir() => return Err(invalid(&dir, "not a directory")),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => return Err(PolicyError::Io { path: dir, source }),
    }
    let rd = match std::fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => return Err(PolicyError::Io { path: dir, source }),
    };
    let mut names = Vec::new();
    for entry in rd {
        let entry = entry.map_err(|source| PolicyError::Io {
            path: dir.clone(),
            source,
        })?;
        let name = entry.file_name();
        let bytes = name.as_encoded_bytes();
        if bytes.ends_with(b".toml") && !bytes.starts_with(b".") {
            names.push(name);
        }
    }
    names.sort();
    Ok(names.into_iter().map(|n| dir.join(n)).collect())
}

/// Reads one policy file (regular file, no symlink, at most 1 MiB, UTF-8)
/// and records its name and SHA-256 in `files`.
fn read_policy_file(path: &Path, files: &mut Vec<(String, String)>) -> Result<String, PolicyError> {
    let bytes = read_regular(path)?;
    let digest = Sha256::digest(&bytes);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    files.push((path.display().to_string(), hex));
    String::from_utf8(bytes).map_err(|_| PolicyError::Parse {
        path: path.to_path_buf(),
        detail: "not valid UTF-8".to_string(),
    })
}

/// Opens `path` without following a symlink and without blocking (a FIFO
/// cannot hang the load); anything the handle does not show as a regular
/// file of at most 1 MiB is refused before it is read.
fn read_regular(path: &Path) -> Result<Vec<u8>, PolicyError> {
    let io = |source| PolicyError::Io {
        path: path.to_path_buf(),
        source,
    };
    let not_regular = || invalid(path, "not a regular file (symlinks are not followed)");
    // Clear message for the common case; O_NOFOLLOW below closes the race.
    match std::fs::symlink_metadata(path) {
        Ok(m) if !m.file_type().is_file() => return Err(not_regular()),
        Ok(_) => {}
        Err(e) => return Err(io(e)),
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_NOFOLLOW);
    }
    let file = match opts.open(path) {
        Ok(f) => f,
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Err(not_regular()),
        Err(e) => return Err(io(e)),
    };
    let meta = file.metadata().map_err(io)?;
    if !meta.is_file() {
        return Err(not_regular());
    }
    let too_big = || invalid(path, "larger than 1 MiB");
    if meta.len() > MAX_FILE_BYTES {
        return Err(too_big());
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(too_big());
    }
    Ok(bytes)
}
