//! `saiife env list|use` (spec §6.11, plan 14 decision 10).
//!
//! Locked mode: an environment is bound to a scope (`[[scope]] env`) in the
//! root-owned system config, so `env use <name> --scope <s>` is root only:
//! it edits the file that holds the scope with `toml_edit`, then asks the
//! daemon to reload. Developer mode (and the personal broker): `env use
//! <name>` writes `env = "<name>"` into `.saiife/config.toml`.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Subcommand;
use saiife_agents::config::{find_project_root, read_config_bytes, CONFIG_REL};
use saiife_policy::environment::valid_env_name;
use saiife_policy::{env_for, load_system, parse_project, Getent, SystemConfig};
use serde_json::json;
use toml_edit::{value, DocumentMut};

use crate::audit_locked::{locked_audit_dir, SYSTEM_CONFIG};
use crate::text::sanitize;

#[derive(Subcommand)]
pub enum EnvAction {
    /// Show the environments and which one applies here (`*`).
    List {
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Locked mode (root): bind environment NAME to the scope SCOPE.
    /// Developer mode: write `env = "NAME"` into .saiife/config.toml.
    Use {
        name: String,
        /// The scope to rebind (locked mode).
        #[arg(long, value_name = "SCOPE")]
        scope: Option<String>,
    },
}

/// Where environments live for this invocation.
enum Place {
    /// A locked host: the system config at this path.
    Locked(PathBuf),
    /// Developer mode: the project `env`; `system` is the config that
    /// defines environments, when there is one.
    Developer { system: Option<PathBuf> },
}

/// DEFERRED(plan 16): the one place that decides which config applies. It
/// becomes a call of plan 16's `cli::broker::resolve` (locked, or the
/// personal broker's config) at the rebase; nothing else here knows a path.
fn resolve(system_config: Option<PathBuf>) -> Result<Place, String> {
    let config = system_config.unwrap_or_else(|| PathBuf::from(SYSTEM_CONFIG));
    match locked_audit_dir(&config)? {
        Some(_) => Ok(Place::Locked(config)),
        None => Ok(Place::Developer {
            system: config.is_file().then_some(config),
        }),
    }
}

pub fn run(system_config: Option<PathBuf>, action: EnvAction) -> ExitCode {
    let place = match resolve(system_config) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("saiife: {}", sanitize(&e));
            return ExitCode::from(2);
        }
    };
    let r = match action {
        EnvAction::List { json } => list(&place, json),
        EnvAction::Use { name, scope } => use_env(&place, &name, scope.as_deref()),
    };
    match r {
        Ok(Done::Code(code)) => ExitCode::from(code),
        Ok(Done::Reload(config)) => crate::policy_cmd::reload(Some(config)),
        Err((code, m)) => {
            eprintln!("saiife: {}", sanitize(&m));
            ExitCode::from(code)
        }
    }
}

type Failure = (u8, String);

/// What a command came to: an exit code, or a file changed and the daemon
/// to be told.
enum Done {
    Code(u8),
    Reload(PathBuf),
}

fn load(config: &Path) -> Result<SystemConfig, Failure> {
    load_system(config)
        .map(|l| l.config)
        .map_err(|e| (2, e.to_string()))
}

/// The project `env` of the project around the current directory.
fn project_env() -> Option<String> {
    let root = find_project_root(&std::env::current_dir().ok()?)?;
    let bytes = read_config_bytes(&root).ok().flatten()?;
    parse_project(&bytes).ok()?.env
}

/// One row of the listing.
struct Row {
    name: String,
    applies: bool,
    scopes: Vec<String>,
    packs: Vec<String>,
    services: Vec<String>,
}

fn rows(cfg: &SystemConfig, applies: Option<&str>) -> Vec<Row> {
    cfg.environments
        .iter()
        .map(|(name, e)| Row {
            name: name.clone(),
            applies: applies == Some(name.as_str()),
            scopes: cfg
                .scope
                .iter()
                .filter(|s| s.env.as_deref() == Some(name))
                .map(|s| s.name.clone())
                .collect(),
            packs: e.guard.packs.clone(),
            services: e.services.keys().cloned().collect(),
        })
        .collect()
}

fn list(place: &Place, as_json: bool) -> Result<Done, Failure> {
    let (cfg, applies) = match place {
        Place::Locked(config) => {
            let cfg = load(config)?;
            let user =
                current_user_name().ok_or((2, "cannot tell which user you are".to_string()))?;
            let applies = env_for(&cfg, &Getent, &user)
                .map_err(|e| (2, e.to_string()))?
                .map(str::to_string);
            (cfg, applies)
        }
        Place::Developer { system } => {
            let cfg = match system {
                Some(p) => load(p)?,
                None => load_empty()?,
            };
            (cfg, project_env())
        }
    };
    let rows = rows(&cfg, applies.as_deref());
    if as_json {
        let v: Vec<_> = rows
            .iter()
            .map(|r| {
                json!({
                    "name": r.name,
                    "applies": r.applies,
                    "scopes": r.scopes,
                    "packs": r.packs,
                    "services": r.services,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        return Ok(Done::Code(0));
    }
    if rows.is_empty() {
        println!("no environments defined");
        return Ok(Done::Code(0));
    }
    for r in &rows {
        println!(
            "{} {}  packs+ {}  services overridden {}  bound to {}",
            if r.applies { "*" } else { " " },
            sanitize(&r.name),
            r.packs.len(),
            r.services.len(),
            if r.scopes.is_empty() {
                "-".to_string()
            } else {
                sanitize(&r.scopes.join(", "))
            }
        );
    }
    Ok(Done::Code(0))
}

fn current_user_name() -> Option<String> {
    use saiife_policy::Directory;
    Getent.name_of(rustix::process::getuid().as_raw())
}

fn load_empty() -> Result<SystemConfig, Failure> {
    toml::from_str("version = 2").map_err(|e: toml::de::Error| (2, e.to_string()))
}

// -------------------------------------------------------------------- use

/// The root test seam: a debug build with `SAIIFE_TEST_ASSUME_ROOT` set
/// acts as root for the permission check, so an integration test can drive
/// the binary on files in a temp dir. A release build never honours it.
fn assume_root(seam_set: bool, debug: bool) -> bool {
    seam_set && debug
}

fn is_root() -> bool {
    rustix::process::geteuid().is_root()
        || assume_root(
            std::env::var_os("SAIIFE_TEST_ASSUME_ROOT").is_some(),
            cfg!(debug_assertions),
        )
}

fn use_env(place: &Place, name: &str, scope: Option<&str>) -> Result<Done, Failure> {
    if !valid_env_name(name) {
        return Err((2, format!("{name:?} is not an environment name")));
    }
    match place {
        Place::Locked(config) => {
            let Some(scope) = scope else {
                return Err((
                    2,
                    "locked mode binds an environment to a scope: use --scope <scope>".into(),
                ));
            };
            use_locked(config, name, scope)
        }
        Place::Developer { system } => {
            if scope.is_some() {
                return Err((
                    2,
                    "--scope is for locked mode; here the project chooses its environment".into(),
                ));
            }
            use_project(system.as_deref(), name)
        }
    }
}

/// Every file that may hold a `[[scope]]`: `config.toml`, then
/// `policy.d/*.toml` by name.
fn scope_files(config: &Path) -> Vec<PathBuf> {
    let mut files = vec![config.to_path_buf()];
    let dir = config.parent().unwrap_or(Path::new("/")).join("policy.d");
    if let Ok(rd) = fs::read_dir(&dir) {
        let mut d: Vec<PathBuf> = rd
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .collect();
        d.sort();
        files.extend(d);
    }
    files
}

fn use_locked(config: &Path, name: &str, scope: &str) -> Result<Done, Failure> {
    // Find the file first, so a refusal can name it.
    let mut found = None;
    for f in scope_files(config) {
        let Ok(text) = fs::read_to_string(&f) else {
            continue;
        };
        let Ok(doc) = text.parse::<DocumentMut>() else {
            continue;
        };
        let holds = doc
            .get("scope")
            .and_then(|s| s.as_array_of_tables())
            .is_some_and(|a| {
                a.iter()
                    .any(|t| t.get("name").and_then(|n| n.as_str()) == Some(scope))
            });
        if holds {
            found = Some((f, doc));
            break;
        }
    }
    let Some((file, mut doc)) = found else {
        return Err((
            2,
            format!("no [[scope]] named {scope:?} in {}", config.display()),
        ));
    };
    if !is_root() {
        return Err((
            2,
            format!(
                "needs root: {} is root-owned (env use --scope is for root only)",
                file.display()
            ),
        ));
    }
    let cfg = load(config)?;
    if !cfg.environments.contains_key(name) {
        return Err((
            2,
            format!("environment {name:?} is not defined in [environments]"),
        ));
    }
    if let Some(a) = doc
        .get_mut("scope")
        .and_then(|s| s.as_array_of_tables_mut())
    {
        for t in a.iter_mut() {
            if t.get("name").and_then(|n| n.as_str()) == Some(scope) {
                t.insert("env", value(name));
            }
        }
    }
    write_atomic(&file, doc.to_string().as_bytes())
        .map_err(|e| (2, format!("{}: {e}", file.display())))?;
    println!(
        "scope {scope} is bound to environment {name} in {}",
        file.display()
    );
    Ok(Done::Reload(config.to_path_buf()))
}

fn use_project(system: Option<&Path>, name: &str) -> Result<Done, Failure> {
    // A system config that defines environments is the list of valid names.
    if let Some(p) = system {
        let cfg = load(p)?;
        if !cfg.environments.is_empty() && !cfg.environments.contains_key(name) {
            return Err((
                2,
                format!("environment {name:?} is not defined in [environments]"),
            ));
        }
    }
    let cwd = std::env::current_dir().map_err(|e| (2, e.to_string()))?;
    let root = find_project_root(&cwd).ok_or((
        2,
        format!("no {CONFIG_REL} here or above; run `saiife init` first"),
    ))?;
    let file = root.join(CONFIG_REL);
    let text = fs::read_to_string(&file).map_err(|e| (2, format!("{}: {e}", file.display())))?;
    let mut doc: DocumentMut = text
        .parse()
        .map_err(|e| (2, format!("{}: {e}", file.display())))?;
    doc["env"] = value(name);
    write_atomic(&file, doc.to_string().as_bytes())
        .map_err(|e| (2, format!("{}: {e}", file.display())))?;
    println!("env = {name:?} in {}", file.display());
    Ok(Done::Code(0))
}

/// Replace `path` with `bytes`: a temp file in the same directory, fsynced,
/// renamed over it, keeping the mode and owner of the old file.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let old = fs::metadata(path)?;
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("env"),
        std::process::id()
    ));
    let result = (|| {
        let mut f: File = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.set_permissions(fs::Permissions::from_mode(old.mode() & 0o7777))?;
        let (uid, gid) = (old.uid(), old.gid());
        if uid != rustix::process::geteuid().as_raw() || gid != rustix::process::getegid().as_raw()
        {
            rustix::fs::fchown(
                &f,
                Some(rustix::fs::Uid::from_raw(uid)),
                Some(rustix::fs::Gid::from_raw(gid)),
            )?;
        }
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_ignores_assume_root_seam() {
        assert!(!assume_root(true, false), "a release build ignores it");
        assert!(!assume_root(false, true));
        assert_eq!(
            assume_root(true, cfg!(debug_assertions)),
            cfg!(debug_assertions)
        );
    }

    #[test]
    fn write_atomic_keeps_mode_and_content() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("c.toml");
        fs::write(&f, "a = 1\n").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o640)).unwrap();
        write_atomic(&f, b"a = 2\n").unwrap();
        assert_eq!(fs::read_to_string(&f).unwrap(), "a = 2\n");
        assert_eq!(fs::metadata(&f).unwrap().mode() & 0o777, 0o640);
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1, "no temp left");
    }
}
