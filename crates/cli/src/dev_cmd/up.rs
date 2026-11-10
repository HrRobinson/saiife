//! `saiife dev up` (plan 24 Task 2).

use std::path::{Path, PathBuf};

use saiife_dev::certs::{ensure_ca, ensure_project_cert};
use saiife_dev::compose::read_config;
use saiife_dev::docker::{run_ok, Docker};
use saiife_dev::labels::compose_project;
use saiife_dev::paths::DevPaths;
use saiife_dev::{project, proxy, quirks, rewrite, DevError};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::{write_private, Res};
use crate::text::sanitize;

fn msg(e: DevError) -> String {
    e.to_string()
}

fn utf8(p: &Path) -> Result<&str, String> {
    p.to_str()
        .ok_or_else(|| msg(DevError::NonUtf8Path(p.to_path_buf())))
}

fn shown(p: &Path) -> String {
    sanitize(&p.display().to_string())
}

/// `dir` (default: the current folder), canonical, or the plain error.
fn repo_dir(dir: Option<&Path>) -> Result<PathBuf, String> {
    let dir = match dir {
        Some(d) => d.to_path_buf(),
        None => {
            std::env::current_dir().map_err(|e| format!("cannot read the current folder: {e}"))?
        }
    };
    let not_a_folder = || {
        format!(
            "{} is not a folder. Pass the folder that holds the compose file.",
            dir.display()
        )
    };
    if !std::fs::metadata(&dir).is_ok_and(|m| m.is_dir()) {
        return Err(not_a_folder());
    }
    std::fs::canonicalize(&dir).map_err(|_| not_a_folder())
}

/// Now in RFC 3339 UTC, whole seconds.
fn now() -> String {
    let t = OffsetDateTime::now_utc();
    t.replace_nanosecond(0)
        .unwrap_or(t)
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// Starts the compose stack in `dir` (default: the current folder) behind the
/// proxy. Every file it writes is under `paths.state`; the repo is only read.
pub(crate) fn up(d: &dyn Docker, paths: &DevPaths, dir: Option<&Path>) -> Res {
    let dir = repo_dir(dir)?;
    // P1: read compose before assigning, so a folder with no compose file
    // leaves no project state behind.
    let model = read_config(d, &dir).map_err(msg)?;
    let mut p = project::assign(paths, &dir).map_err(msg)?;
    let q = quirks::load(paths, &p.name).map_err(msg)?;
    let rewritten = rewrite::rewrite(&model, &p.name, &q).map_err(msg)?;

    // Plan 23's order: the proxy takes 80 and 443 right after the check.
    proxy::preflight_ports(d).map_err(msg)?;
    proxy::ensure_network(d).map_err(msg)?;
    proxy::ensure_proxy(d, paths).map_err(msg)?;

    let new_ca = std::fs::symlink_metadata(paths.ca_dir()).is_err();
    let ca = ensure_ca(paths).map_err(msg)?;
    let cert = ensure_project_cert(paths, &ca, &p.name).map_err(msg)?;

    // P9: the interpolated model can hold values from `.env`.
    let compose = paths.compose_file(&p.name);
    let body = serde_json::to_vec_pretty(&rewritten.model)
        .map_err(|e| format!("cannot write {}: {e}", shown(&compose)))?;
    write_private(&compose, &body).map_err(|e| format!("cannot write {}: {e}", shown(&compose)))?;

    let cp = compose_project(&p.name);
    let args = [
        "compose",
        "-p",
        &cp,
        "--project-directory",
        utf8(&dir)?,
        "-f",
        utf8(&compose)?,
        "up",
        "-d",
    ];
    if let Err(e) = run_ok(d, &args) {
        // Best effort: a first `up` that failed should not leave the proxy
        // holding 80 and 443. The compose error is the one to report.
        let _ = proxy::stop_proxy_if_unused(d, paths);
        return Err(msg(e));
    }

    // Plan 23 D2: on every `up`, so Traefik rereads a reissued certificate.
    proxy::write_routes(paths, &p.name, &rewritten.routes, &cert).map_err(msg)?;
    // Again: a `down` or `gc` that ran before this `up` took the lock may
    // have stopped the proxy, since it decides from route files.
    proxy::ensure_proxy(d, paths).map_err(msg)?;

    let urls: Vec<String> = rewritten
        .routes
        .iter()
        .map(|r| format!("https://{}", r.host))
        .collect();
    let urls_file = paths.project_dir(&p.name).join("urls.json");
    let body = serde_json::to_vec_pretty(&urls)
        .map_err(|e| format!("cannot write {}: {e}", shown(&urls_file)))?;
    write_private(&urls_file, &body)
        .map_err(|e| format!("cannot write {}: {e}", shown(&urls_file)))?;
    p.last_up = Some(now());
    project::save(paths, &p).map_err(msg)?;

    let quirks_file = shown(&paths.quirks_file(&p.name));
    outln!("saiife dev: {} is up (compose project {cp}).", p.name);
    if urls.is_empty() {
        outln!("No service has a port, so there is no URL. Set one in {quirks_file}.");
    }
    for u in &urls {
        outln!("  {}", sanitize(u));
    }
    let unrouted: Vec<String> = model
        .services
        .iter()
        .map(|s| s.name.as_str())
        .filter(|n| !rewritten.routes.iter().any(|r| r.service == *n))
        .filter(|n| !q.services.get(*n).is_some_and(|s| s.skip))
        .map(sanitize)
        .collect();
    // With no URL at all, the line above already says what to do.
    if !urls.is_empty() && !unrouted.is_empty() {
        outln!(
            "Not routed (no port): {}. Set a port in {quirks_file}.",
            unrouted.join(", ")
        );
    }
    if new_ca {
        outln!("New local CA: run saiife dev ca to trust it.");
    }
    Ok(())
}
