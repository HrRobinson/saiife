//! `saiife dev down` and `saiife dev gc` (plan 24 Tasks 4 and 5).
//!
//! Every removal here comes from a listing filtered on `label=saiife.managed=true`.
//! The proxy goes only through `proxy::stop_proxy_if_unused`; the shared network
//! is never removed (its labels carry no project, so the project filter misses it).

use saiife_dev::docker::{run_ok, Docker};
use saiife_dev::labels::{compose_project, MANAGED, PROJECT};
use saiife_dev::paths::DevPaths;
use saiife_dev::{project, proxy};

use super::{confirm, valid_project, Res};
use crate::text::sanitize;

/// `--filter` pairs: labelled by saiife, and for one project when given.
pub(crate) fn label_filters(project: Option<&str>) -> Vec<String> {
    let mut v = vec!["--filter".to_string(), format!("label={MANAGED}=true")];
    if let Some(p) = project {
        v.push("--filter".to_string());
        v.push(format!("label={PROJECT}={p}"));
    }
    v
}

fn run_strings(d: &dyn Docker, args: &[String]) -> Result<String, String> {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_ok(d, &refs)
        .map(|o| String::from_utf8_lossy(&o).into_owned())
        .map_err(|e| e.to_string())
}

fn words(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// `docker volume ls -q` over saiife's labelled volumes.
pub(crate) fn labelled_volumes(
    d: &dyn Docker,
    project: Option<&str>,
    dangling_only: bool,
) -> Result<Vec<String>, String> {
    let mut args: Vec<String> = vec!["volume".into(), "ls".into(), "-q".into()];
    args.extend(label_filters(project));
    if dangling_only {
        args.push("--filter".into());
        args.push("dangling=true".into());
    }
    run_strings(d, &args).map(|s| words(&s))
}

/// Shows `names` and asks. No names is `Ok`; a no is an error.
// Used by `gc` too (plan 24 Task 5).
pub(crate) fn confirm_volumes(names: &[String], yes: bool, what: &str) -> Res {
    if names.is_empty() {
        return Ok(());
    }
    for n in names {
        outln!("  volume {}", sanitize(n));
    }
    let q = format!(
        "Delete {} volumes of {what}? Their data is gone for good.",
        names.len()
    );
    if confirm(&q, yes)? {
        Ok(())
    } else {
        outln!("Nothing deleted.");
        Err("volumes kept: the answer was not yes.".into())
    }
}

/// `docker volume rm <names>`; nothing for none.
pub(crate) fn rm_volumes(d: &dyn Docker, names: &[String]) -> Res {
    if names.is_empty() {
        return Ok(());
    }
    let mut args: Vec<String> = vec!["volume".into(), "rm".into()];
    args.extend(names.iter().cloned());
    run_strings(d, &args).map(|_| ())
}

/// `docker rm [-f] <ids>`; nothing for none.
// Used by `gc` too (plan 24 Task 5).
pub(crate) fn remove_containers(d: &dyn Docker, ids: &[String], force: bool) -> Res {
    if ids.is_empty() {
        return Ok(());
    }
    let mut args: Vec<String> = vec!["rm".into()];
    if force {
        args.push("-f".into());
    }
    args.extend(ids.iter().cloned());
    run_strings(d, &args).map(|_| ())
}

/// Containers in compose project `saiife-<p>` that lack `saiife.managed=true`.
pub(crate) fn foreign_containers(d: &dyn Docker, project: &str) -> Result<Vec<String>, String> {
    let filter = format!(
        "label=com.docker.compose.project={}",
        compose_project(project)
    );
    let format = format!("{{{{.Names}}}}\t{{{{.Label \"{MANAGED}\"}}}}");
    let out = run_strings(
        d,
        &[
            "ps".into(),
            "-a".into(),
            "--filter".into(),
            filter,
            "--format".into(),
            format,
        ],
    )?;
    Ok(out
        .lines()
        .filter_map(|l| {
            let (name, label) = l.split_once('\t').unwrap_or((l, ""));
            (!name.trim().is_empty() && label.trim() != "true").then(|| name.trim().to_string())
        })
        .collect())
}

fn labelled_ids(d: &dyn Docker, kind: &[&str], project: &str) -> Result<Vec<String>, String> {
    let mut args: Vec<String> = kind.iter().map(|s| s.to_string()).collect();
    args.extend(label_filters(Some(project)));
    run_strings(d, &args).map(|s| words(&s))
}

/// Stops `project` and removes what saiife labelled for it.
pub(crate) fn down(
    d: &dyn Docker,
    paths: &DevPaths,
    project: &str,
    volumes: bool,
    yes: bool,
) -> Res {
    if !valid_project(project) {
        return Err(format!(
            "{} is not a saiife dev project name. saiife dev ls lists them.",
            sanitize(project)
        ));
    }
    let state = project::load(paths, project).map_err(|e| e.to_string())?;
    if state.is_none() && labelled_ids(d, &["ps", "-aq"], project)?.is_empty() {
        return Err(format!(
            "no project named {project}. saiife dev ls lists them."
        ));
    }
    let foreign = foreign_containers(d, project)?;
    if !foreign.is_empty() {
        let names: Vec<String> = foreign.iter().map(|n| sanitize(n)).collect();
        return Err(format!(
            "compose project {} has containers saiife did not create ({}); nothing was touched.",
            compose_project(project),
            names.join(", ")
        ));
    }
    let doomed = if volumes {
        let names = labelled_volumes(d, Some(project), false)?;
        confirm_volumes(&names, yes, project)?;
        names
    } else {
        Vec::new()
    };
    let compose = paths.compose_file(project);
    let folder = state.as_ref().map(|s| s.dir.clone()).filter(|p| p.is_dir());
    match folder {
        Some(dir) if compose.is_file() => {
            let args = [
                "compose".to_string(),
                "-p".into(),
                compose_project(project),
                "--project-directory".into(),
                dir.display().to_string(),
                "-f".into(),
                compose.display().to_string(),
                "down".into(),
            ];
            run_strings(d, &args)?;
        }
        _ => {
            let ids = labelled_ids(d, &["ps", "-aq"], project)?;
            remove_containers(d, &ids, true)?;
            let nets = labelled_ids(d, &["network", "ls", "-q"], project)?;
            if !nets.is_empty() {
                let mut args: Vec<String> = vec!["network".into(), "rm".into()];
                args.extend(nets);
                run_strings(d, &args)?;
            }
        }
    }
    rm_volumes(d, &doomed)?;
    proxy::remove_routes(paths, project).map_err(|e| e.to_string())?;
    let stopped = proxy::stop_proxy_if_unused(d, paths).map_err(|e| e.to_string())?;
    outln!("saiife dev: {project} is down.");
    if stopped {
        outln!("Proxy stopped: no project is running.");
    }
    if !doomed.is_empty() {
        let shown: Vec<String> = doomed.iter().map(|n| sanitize(n)).collect();
        outln!("Volumes deleted: {}.", shown.join(", "));
    }
    Ok(())
}

/// Removes what saiife labelled for stopped and missing projects.
pub(crate) fn gc(d: &dyn Docker, paths: &DevPaths, volumes: bool, yes: bool) -> Res {
    let _ = (d, paths, volumes, yes);
    Err("not built yet".into())
}
