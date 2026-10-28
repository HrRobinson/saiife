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
use saiife_policy::scope::try_scope_for;
use saiife_policy::{load_system, parse_project, Directory, Getent, SystemConfig};
use serde_json::json;
use toml_edit::{value, DocumentMut};

#[cfg(not(target_os = "linux"))]
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

/// The one place that decides which config applies; nothing else here
/// knows a path. Without `--system-config`, plan 16's resolver
/// (`cli::broker::resolve`) decides: a locked host is its system config,
/// anything else the personal broker's config, which defines the
/// environments in developer mode. A host it cannot place (a locked install
/// whose config is not locked, no usable `XDG_RUNTIME_DIR`) is an error,
/// never a guess.
///
/// `--system-config <file>` means locked mode, as plan 16's flag does
/// everywhere: a file that does not say `locked = true` is refused.
fn resolve(system_config: Option<PathBuf>) -> Result<Place, String> {
    match system_config {
        Some(config) => locked_flag(config),
        None => resolve_default(),
    }
}

/// The `--system-config` file, which must say `locked = true`.
fn locked_flag(config: PathBuf) -> Result<Place, String> {
    let loaded = load_system(&config)
        .map_err(|e| format!("cannot read the system config {}: {e}", config.display()))?;
    if !loaded.config.locked {
        return Err(format!("{}: locked is not true", config.display()));
    }
    Ok(Place::Locked(config))
}

#[cfg(target_os = "linux")]
fn resolve_default() -> Result<Place, String> {
    use crate::broker::{self, Target};
    Ok(match broker::resolve_here(None)? {
        Target::Locked { config, .. } => Place::Locked(config),
        Target::Personal { config, .. } => Place::Developer {
            system: config.is_file().then_some(config),
        },
    })
}

/// No personal broker off Linux in this version: the system config, as
/// locked mode when it says so, else the developer-mode definitions.
#[cfg(not(target_os = "linux"))]
fn resolve_default() -> Result<Place, String> {
    let config = PathBuf::from(SYSTEM_CONFIG);
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
        Err((code, m)) => {
            eprintln!("saiife: {}", sanitize(&m));
            ExitCode::from(code)
        }
    }
}

type Failure = (u8, String);

/// What a command came to.
enum Done {
    Code(u8),
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
            let applies = scope_env(&cfg, &Getent, &user)?;
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

/// The environment of `user`'s scope. A failed group lookup is an error,
/// never "no environment": the listing would mark the base config as the
/// one that applies.
fn scope_env(
    cfg: &SystemConfig,
    dir: &dyn Directory,
    user: &str,
) -> Result<Option<String>, Failure> {
    let scope = try_scope_for(cfg, dir, user)
        .map_err(|e| (2, format!("cannot tell which scope {user} is in: {e}")))?
        .map_err(|e| (2, e.to_string()))?;
    Ok(scope.and_then(|s| s.env.clone()))
}

fn current_user_name() -> Option<String> {
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
    // Never write through a link: the rename would replace the link, and
    // the daemon would read something else than was validated.
    let meta = fs::symlink_metadata(&file).map_err(|e| (2, format!("{}: {e}", file.display())))?;
    if !meta.file_type().is_file() {
        return Err((
            2,
            format!("{} is not a regular file (a link?)", file.display()),
        ));
    }
    let text = doc.to_string();
    validate_rewritten(config, &file, &text)?;
    write_atomic(&file, text.as_bytes()).map_err(|e| (2, format!("{}: {e}", file.display())))?;
    println!(
        "scope {scope} is bound to environment {name} in {}",
        file.display()
    );
    match reload_daemon(config) {
        Ok(()) => {
            println!("loaded");
            Ok(Done::Code(0))
        }
        Err((code, m)) => Err((code, format!("file updated; reload failed: {m}"))),
    }
}

/// `load_system` over a copy of the config tree with `file` replaced by
/// `text`: what the daemon would load after the rename.
fn validate_rewritten(config: &Path, file: &Path, text: &str) -> Result<(), Failure> {
    let fail = |e: String| (2, format!("the rewritten policy would not load: {e}"));
    let tmp = std::env::temp_dir().join(format!(
        "saiife-env-use-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let result = (|| -> Result<(), String> {
        let io = |e: std::io::Error| e.to_string();
        fs::create_dir(&tmp).map_err(io)?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o700)).map_err(io)?;
        fs::create_dir(tmp.join("policy.d")).map_err(io)?;
        let copy = |from: &Path, to: PathBuf| -> Result<(), String> {
            let body = if from == file {
                text.to_string()
            } else {
                fs::read_to_string(from).map_err(io)?
            };
            fs::write(to, body).map_err(io)
        };
        copy(config, tmp.join("config.toml"))?;
        for f in scope_files(config).into_iter().skip(1) {
            let n = f.file_name().unwrap_or_default();
            copy(&f, tmp.join("policy.d").join(n))?;
        }
        load_system(&tmp.join("config.toml"))
            .map(|_| ())
            .map_err(|e| e.to_string())
    })();
    let _ = fs::remove_dir_all(&tmp);
    result.map_err(fail)
}

/// Ask the daemon to load the policy again. `Err` is an exit code and why.
#[cfg(target_os = "linux")]
fn reload_daemon(config: &Path) -> Result<(), Failure> {
    use crate::secret_cmd::linux::{call, Stop};
    match call(config, "policy.reload", serde_json::Map::new()) {
        Ok(a) if a.get("result").and_then(|r| r.as_str()) == Some("loaded") => Ok(()),
        Ok(a) => {
            let why = a
                .get("reason")
                .and_then(|r| r.as_str())
                .unwrap_or("rejected");
            Err((1, format!("rejected: {why}")))
        }
        Err(Stop::Refused(m) | Stop::Forbidden(m)) => Err((2, m)),
        Err(Stop::Unavailable(m) | Stop::NotFound(m) | Stop::Unrecorded(m)) => Err((5, m)),
    }
}

#[cfg(not(target_os = "linux"))]
fn reload_daemon(_config: &Path) -> Result<(), Failure> {
    Err((5, "locked mode needs Linux in this version".into()))
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

    /// A directory whose group lookups fail.
    struct FailingGroups;

    impl Directory for FailingGroups {
        fn user(&self, _: &str) -> Option<saiife_policy::UserEntry> {
            None
        }
        fn name_of(&self, _: u32) -> Option<String> {
            None
        }
        fn group(&self, _: &str) -> Option<saiife_policy::GroupEntry> {
            None
        }
        fn groups_of(&self, _: &str) -> Vec<String> {
            Vec::new()
        }
        fn try_groups_of(&self, _: &str) -> Result<Vec<String>, String> {
            Err("nss down".into())
        }
    }

    /// `env list` in locked mode: a failed group lookup is an error, not
    /// "no environment applies".
    #[test]
    fn list_scope_env_lookup_failure_is_an_error() {
        let cfg: SystemConfig = toml::from_str(
            "version = 2\n[[scope]]\nname = \"s\"\nusers = [\"group:devs\"]\nenv = \"e\"\n\
             [environments.e]\n",
        )
        .unwrap();
        let (code, m) = scope_env(&cfg, &FailingGroups, "alice").unwrap_err();
        assert_eq!(code, 2);
        assert!(m.contains("nss down"), "{m}");
        // With the lookup answering, the scope's environment.
        let d = saiife_policy::FixedDirectory::from_text(
            "alice:x:1000:1000::/home/alice:/bin/sh\n",
            "devs:x:1000:\n",
        );
        assert_eq!(scope_env(&cfg, &d, "alice").unwrap().as_deref(), Some("e"));
    }

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
    fn rewritten_policy_is_validated_before_the_rename() {
        let d = tempfile::tempdir().unwrap();
        let config = d.path().join("config.toml");
        fs::write(
            &config,
            "version = 2\n[[scope]]\nname = \"s\"\nusers = [\"a\"]\n[environments.e]\n",
        )
        .unwrap();
        let ok = fs::read_to_string(&config)
            .unwrap()
            .replace("]\n[env", "]\nenv = \"e\"\n[env");
        assert!(validate_rewritten(&config, &config, &ok).is_ok(), "{ok}");
        let bad = ok.replace("env = \"e\"", "env = \"nope\"");
        let e = validate_rewritten(&config, &config, &bad).unwrap_err().1;
        assert!(e.contains("would not load"), "{e}");
        // The real file was never touched, and no copy is left behind.
        assert!(!fs::read_to_string(&config).unwrap().contains("nope"));
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
