//! Where `saiife audit` reads from in locked mode (spec §6.4.5): an auditor
//! (root, or a member of `saiife-audit`) reads the locked audit dir
//! directly; anyone else asks the daemon (`audit.query`), which returns
//! only that user's records. The user's home log is shown too, labelled
//! [`V1_LABEL`]. Without a locked system config, developer mode is
//! unchanged.

use saiife_audit::Record;
use saiife_policy::load_system;
use std::path::{Path, PathBuf};

/// The label of the user's home log in locked mode, verbatim (spec §6.4.5).
pub const V1_LABEL: &str = "v1, before locked mode, not tamper-evident";
/// The group whose members read the audit files (spec §5.2).
pub use saiife_system::layout::AUDIT_GROUP;
pub const SYSTEM_CONFIG: &str = "/etc/saiife/config.toml";
const LOCKED_AUDIT_DIR: &str = "/var/log/saiife/audit";

/// Where the records come from: the one locked-mode decision behind both
/// `saiife audit` and `saiife audit verify`.
pub enum Source {
    /// No locked system config: the user's own audit dir, as before.
    Developer,
    /// Locked mode, and the caller may read the files in `dir`.
    Direct { dir: PathBuf, config: PathBuf },
    /// Locked mode, not an auditor: through the daemon (`audit.query`).
    Daemon { dir: PathBuf, config: PathBuf },
}

/// The source for this process, from `system_config` (default
/// [`SYSTEM_CONFIG`]). Only a config that does not exist (`NotFound`), or
/// one without `locked = true`, is developer mode. Any other failure to
/// read it is an error naming the path (fail closed: a locked host never
/// falls back to the home log alone).
pub fn source(system_config: Option<&Path>) -> Result<Source, String> {
    let config = system_config.unwrap_or(Path::new(SYSTEM_CONFIG));
    let Some(dir) = locked_audit_dir(config)? else {
        return Ok(Source::Developer);
    };
    let config = config.to_path_buf();
    if is_auditor() {
        Ok(Source::Direct { dir, config })
    } else {
        Ok(Source::Daemon { dir, config })
    }
}

/// `[audit] dir` when the system config says `locked = true`; `None` when
/// the config does not exist or is not locked. Read as a raw table, like
/// the hook's system view, so a policy error elsewhere does not hide the
/// log. Errors name the path.
pub fn locked_audit_dir(config: &Path) -> Result<Option<PathBuf>, String> {
    let bad = |e: &str| format!("{}: {e}", config.display());
    let Some(bytes) =
        crate::system_view::read_regular(config, false, 1024 * 1024).map_err(|e| bad(&e))?
    else {
        return Ok(None);
    };
    let text = String::from_utf8(bytes).map_err(|_| bad("not valid UTF-8"))?;
    let table: toml::Table = text
        .parse()
        .map_err(|e: toml::de::Error| bad(e.message()))?;
    if table.get("locked").and_then(toml::Value::as_bool) != Some(true) {
        return Ok(None);
    }
    let dir = match table.get("audit").and_then(|a| a.get("dir")) {
        None => PathBuf::from(LOCKED_AUDIT_DIR),
        Some(toml::Value::String(d)) if Path::new(d).is_absolute() => PathBuf::from(d),
        Some(_) => return Err(bad("[audit] dir must be an absolute path")),
    };
    Ok(Some(dir))
}

/// Root, or `audit_gid` among the process's groups.
pub fn auditor(euid_is_root: bool, my_gids: &[u32], audit_gid: Option<u32>) -> bool {
    euid_is_root || audit_gid.is_some_and(|g| my_gids.contains(&g))
}

/// The audit group's name; debug builds take `SAIIFE_TEST_AUDIT_GROUP`
/// so a test never depends on the host's groups.
#[cfg(debug_assertions)]
fn audit_group() -> String {
    std::env::var("SAIIFE_TEST_AUDIT_GROUP").unwrap_or_else(|_| AUDIT_GROUP.to_string())
}

#[cfg(not(debug_assertions))]
fn audit_group() -> String {
    AUDIT_GROUP.to_string()
}

/// Root, or a member of `saiife-audit` in this process's current groups.
#[cfg(unix)]
pub fn is_auditor() -> bool {
    use rustix::process::{getegid, geteuid, getgroups};
    use saiife_policy::Directory;
    let mut gids: Vec<u32> = getgroups()
        .unwrap_or_default()
        .into_iter()
        .map(|g| g.as_raw())
        .collect();
    gids.push(getegid().as_raw());
    let gid = saiife_policy::Getent.group(&audit_group()).map(|g| g.gid);
    auditor(geteuid().is_root(), &gids, gid)
}

#[cfg(not(unix))]
pub fn is_auditor() -> bool {
    false
}

/// The `audit.query` filters the CLI sends.
#[derive(Debug, Clone, Default)]
pub struct QueryArgs {
    pub since: Option<i64>,
    pub project: Option<String>,
    pub agent: Option<String>,
    pub blocked: bool,
    pub kind: Option<String>,
    pub service: Option<String>,
}

/// `r` has `kind` (when given) and names `service` (when given).
pub fn kind_service_match(r: &Record, kind: Option<&str>, service: Option<&str>) -> bool {
    kind.is_none_or(|k| r.kind() == k)
        && service
            .is_none_or(|s| r.extra.get("service").and_then(serde_json::Value::as_str) == Some(s))
}

/// The same directory, as far as can be told.
pub fn same_dir(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

/// Every page of the caller's records from the daemon, oldest first, and
/// how many answer entries were not records.
#[cfg(target_os = "linux")]
pub fn query(config: &Path, q: &QueryArgs) -> Result<(Vec<Record>, usize), String> {
    use saiife_ipc::client::{system_uid, Client};
    use serde_json::{Map, Value};
    use std::time::{Duration, Instant};

    let loaded = load_system(config)
        .map_err(|e| format!("cannot read the system config {}: {e}", config.display()))?;
    let cfg = &loaded.config;
    let user = &cfg.daemon.user;
    let uid = system_uid(user).ok_or_else(|| format!("the daemon user {user} does not exist"))?;
    let mut c = Client::connect(
        &cfg.daemon.socket_dir,
        uid,
        Instant::now() + Duration::from_secs(2),
    )
    .map_err(|e| format!("cannot reach the saiife daemon: {e}"))?;
    let mut base = Map::new();
    let mut put = |k: &str, v: Option<Value>| {
        if let Some(v) = v {
            base.insert(k.to_string(), v);
        }
    };
    put("since", q.since.map(Value::from));
    put("project", q.project.clone().map(Value::from));
    put("agent", q.agent.clone().map(Value::from));
    put("blocked", q.blocked.then_some(Value::Bool(true)));
    put("kind", q.kind.clone().map(Value::from));
    put("service", q.service.clone().map(Value::from));
    base.insert("limit".into(), 5000.into());
    let (mut out, mut skipped) = (Vec::new(), 0usize);
    // Paged by the daemon's opaque `next` position, not by seq: seqs
    // repeat when a chain restarts.
    let mut after: Option<String> = None;
    loop {
        let mut args = base.clone();
        if let Some(a) = &after {
            args.insert("after".into(), a.clone().into());
        }
        let ans = c
            .call(
                "audit.query",
                args,
                Instant::now() + Duration::from_secs(60),
            )
            .map_err(|e| format!("audit.query: {e}"))?;
        for v in ans
            .get("records")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            match serde_json::from_value::<Record>(v) {
                Ok(r) => out.push(r),
                Err(_) => skipped += 1,
            }
        }
        if ans.get("more") != Some(&Value::Bool(true)) {
            break;
        }
        let next = ans.get("next").and_then(Value::as_str).map(str::to_string);
        if next.is_none() || next == after {
            return Err("audit.query: the daemon's answer did not move on".into());
        }
        after = next;
    }
    Ok((out, skipped))
}

#[cfg(not(target_os = "linux"))]
pub fn query(config: &Path, q: &QueryArgs) -> Result<(Vec<Record>, usize), String> {
    // Read every field, so the non-Linux build has no dead fields.
    let QueryArgs {
        since,
        project,
        agent,
        blocked,
        kind,
        service,
    } = q;
    let _ = (
        config,
        load_system,
        since,
        project,
        agent,
        blocked,
        kind,
        service,
    );
    Err("locked mode needs Linux in this version (macOS: v2.1)".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auditor_is_root_or_a_group_member() {
        assert!(auditor(true, &[], None));
        assert!(auditor(false, &[10, 3000], Some(3000)));
        assert!(!auditor(false, &[10], Some(3000)));
        // No such group: nobody but root.
        assert!(!auditor(false, &[10, 3000], None));
    }

    #[test]
    fn no_locked_config_is_developer_mode() {
        let d = tempfile::tempdir().unwrap();
        let missing = d.path().join("config.toml");
        assert!(matches!(source(Some(&missing)), Ok(Source::Developer)));
        std::fs::write(&missing, "version = 2\n").unwrap();
        assert!(matches!(source(Some(&missing)), Ok(Source::Developer)));
        std::fs::write(&missing, "version = 2\nbogus = [\n").unwrap();
        let e = source(Some(&missing)).err().unwrap();
        assert!(e.contains(&missing.display().to_string()), "{e}");
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_config_path_fails_closed() {
        use std::os::unix::fs::PermissionsExt;
        if rustix::process::geteuid().is_root() {
            return; // root reads through any mode
        }
        let d = tempfile::tempdir().unwrap();
        let parent = d.path().join("etc");
        std::fs::create_dir(&parent).unwrap();
        let cfg = parent.join("config.toml");
        std::fs::write(&cfg, "version = 2\nlocked = true\n").unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o000)).unwrap();
        let r = source(Some(&cfg));
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let e = r
            .err()
            .expect("an unreadable config must not be developer mode");
        assert!(e.contains(&cfg.display().to_string()), "{e}");
        // A file in place of the parent dir (ENOTDIR) is not NotFound either.
        let file = d.path().join("f");
        std::fs::write(&file, "x").unwrap();
        assert!(source(Some(&file.join("config.toml"))).is_err());
    }

    #[test]
    fn locked_audit_dir_reads_the_system_config() {
        let d = tempfile::tempdir().unwrap();
        let c = d.path().join("config.toml");
        assert_eq!(locked_audit_dir(&c), Ok(None), "no config: developer mode");
        std::fs::write(&c, "version = 2\n[audit]\ndir = \"/srv/a\"\n").unwrap();
        assert_eq!(locked_audit_dir(&c), Ok(None), "not locked");
        std::fs::write(&c, "version = 2\nlocked = true\n").unwrap();
        assert_eq!(
            locked_audit_dir(&c),
            Ok(Some(PathBuf::from("/var/log/saiife/audit")))
        );
        std::fs::write(
            &c,
            "version = 2\nlocked = true\n[audit]\ndir = \"/srv/a\"\n",
        )
        .unwrap();
        assert_eq!(locked_audit_dir(&c), Ok(Some(PathBuf::from("/srv/a"))));
        std::fs::write(&c, "version = 2\nlocked = true\n[audit]\ndir = \"rel\"\n").unwrap();
        assert!(locked_audit_dir(&c).is_err());
        std::fs::write(&c, "locked = [").unwrap();
        assert!(locked_audit_dir(&c).is_err());
    }

    #[test]
    fn v1_label_is_verbatim() {
        assert_eq!(V1_LABEL, "v1, before locked mode, not tamper-evident");
    }
}
