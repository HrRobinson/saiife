//! `saiife dev down` and `saiife dev gc` (plan 24 Tasks 4 and 5).
//!
//! Every removal here comes from a listing filtered on `label=saiife.managed=true`.
//! The proxy goes only through `proxy::stop_proxy_if_unused`; the shared network
//! is never removed (its labels carry no project, so the project filter misses it).

use std::io::IsTerminal;

use saiife_dev::certs::remove_project_cert;
use saiife_dev::docker::{run_ok, Docker};
use saiife_dev::labels::{compose_project, MANAGED, PROJECT};
use saiife_dev::paths::DevPaths;
use saiife_dev::{project, proxy};

use super::inventory::{inventory, Row, State};
use super::{confirm, valid_project, Res, NEED_YES};
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

/// Asks a yes-or-no question: [`super::confirm`] on the terminal.
pub(crate) type Ask<'a> = &'a dyn Fn(&str, bool) -> Result<bool, String>;

/// Shows `names` and asks. No names is `Ok(true)`; a no is `Ok(false)`,
/// and the caller says what it kept.
pub(crate) fn confirm_volumes(
    names: &[String],
    yes: bool,
    what: &str,
    ask: Ask,
) -> Result<bool, String> {
    if names.is_empty() {
        return Ok(true);
    }
    for n in names {
        outln!("  volume {}", sanitize(n));
    }
    let q = format!(
        "Delete {} volumes of {what}? Their data is gone for good.",
        names.len()
    );
    ask(&q, yes)
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
        if !confirm_volumes(&names, yes, project, &confirm)? {
            outln!("Nothing deleted.");
            return Err("volumes kept: the answer was not yes.".into());
        }
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

/// The last line of every `gc` that got past its checks.
const IMAGE_LINE: &str = "Dangling images are not touched: saiife removes only what it labelled saiife.managed=true. docker image prune removes them.";

/// Removes what saiife labelled for stopped and missing projects.
///
/// A stopped project keeps its state dir while its folder exists, so its name
/// and URLs stay stable (P4); a missing one loses its state and leaf cert.
/// An unreadable `project.json` stops `gc` before any docker call: with one
/// project unknown, its labelled things could not be told apart.
pub(crate) fn gc(d: &dyn Docker, paths: &DevPaths, volumes: bool, yes: bool) -> Res {
    let tty = std::io::stdin().is_terminal();
    gc_with(d, paths, volumes, yes, tty, &confirm)
}

/// [`gc`] with the terminal check and the question passed in.
fn gc_with(d: &dyn Docker, paths: &DevPaths, volumes: bool, yes: bool, tty: bool, ask: Ask) -> Res {
    let inv = inventory(d, paths)?;
    if let Some(e) = &inv.docker_error {
        return Err(format!(
            "docker did not answer, so nothing was removed: {}",
            e.trim_end()
        ));
    }
    // Ask nothing halfway: with no one to say yes, nothing at all is removed.
    if volumes && !yes && !tty {
        return Err(NEED_YES.into());
    }
    let mut failed = 0usize;
    // Projects whose route files step 4 leaves alone: kept, or half removed.
    let mut kept: Vec<&str> = Vec::new();
    for row in &inv.rows {
        let name = sanitize(&row.name);
        match row.state {
            // `Unknown` only comes with `docker_error`, handled above.
            State::Running | State::Partial | State::Unknown => {
                kept.push(&row.name);
                outln!("kept {name}: still running");
            }
            State::Stopped | State::Missing => match gc_project(d, paths, row) {
                Ok(()) => outln!("removed {name} ({})", row.state.as_str()),
                Err(e) => {
                    failed += 1;
                    kept.push(&row.name);
                    eprintln!(
                        "saiife dev: could not remove {name}: {}",
                        sanitize(e.trim_end())
                    );
                }
            },
        }
    }
    let rest = gc_shared(d, paths, &kept, volumes, yes, ask);
    outln!("{IMAGE_LINE}");
    rest?;
    if failed > 0 {
        return Err(format!(
            "{failed} of the projects above could not be removed; the lines above say why."
        ));
    }
    Ok(())
}

/// Step 3 for one stopped or missing project.
fn gc_project(d: &dyn Docker, paths: &DevPaths, row: &Row) -> Res {
    let ids: Vec<String> = row.containers.iter().map(|c| c.id.clone()).collect();
    remove_containers(d, &ids, false)?;
    // A name from `docker ps` that is not a project name never reaches a path.
    if !valid_project(&row.name) {
        return Ok(());
    }
    proxy::remove_routes(paths, &row.name).map_err(|e| e.to_string())?;
    if row.state == State::Missing {
        match std::fs::remove_dir_all(paths.project_dir(&row.name)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
        remove_project_cert(paths, &row.name).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Steps 4 to 6: stale route files, the proxy, networks, volumes.
fn gc_shared(
    d: &dyn Docker,
    paths: &DevPaths,
    kept: &[&str],
    volumes: bool,
    yes: bool,
    ask: Ask,
) -> Res {
    let mut stale = Vec::new();
    if let Ok(entries) = std::fs::read_dir(paths.proxy_dir().join("dynamic")) {
        for entry in entries.flatten() {
            let file = entry.file_name();
            let Some(stem) = file.to_str().and_then(|f| f.strip_suffix(".toml")) else {
                continue;
            };
            if valid_project(stem) && !kept.contains(&stem) {
                stale.push(stem.to_string());
            }
        }
    }
    stale.sort();
    for stem in &stale {
        proxy::remove_routes(paths, stem).map_err(|e| e.to_string())?;
    }
    if !stale.is_empty() {
        outln!("removed stale routes: {}", stale.join(", "));
    }
    if proxy::stop_proxy_if_unused(d, paths).map_err(|e| e.to_string())? {
        outln!("Proxy stopped: no project is running.");
    }
    let mut prune: Vec<String> = vec!["network".into(), "prune".into(), "-f".into()];
    prune.extend(label_filters(None));
    prune.push("--filter".into());
    prune.push(format!("label={PROJECT}"));
    let out = run_strings(d, &prune)?;
    let nets: Vec<String> = out
        .lines()
        .skip_while(|l| l.trim() != "Deleted Networks:")
        .skip(1)
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(sanitize)
        .collect();
    if !nets.is_empty() {
        outln!("removed unused saiife networks: {}", nets.join(", "));
    }
    let unused = labelled_volumes(d, None, true)?;
    if volumes {
        // Containers, routes and networks are already gone: a no keeps only
        // the volumes, and is not an error.
        if !confirm_volumes(&unused, yes, "saiife dev", ask)? {
            outln!("Volumes kept.");
            return Ok(());
        }
        rm_volumes(d, &unused)?;
        if !unused.is_empty() {
            let shown: Vec<String> = unused.iter().map(|n| sanitize(n)).collect();
            outln!("Volumes deleted: {}.", shown.join(", "));
        }
    } else if !unused.is_empty() {
        outln!(
            "{} saiife volumes kept; saiife dev gc --volumes deletes them.",
            unused.len()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use saiife_dev::docker::Output;
    use saiife_dev::DevError;

    /// Answers `volume ls` with one volume and every other call with nothing.
    #[derive(Default)]
    struct OneVolume {
        calls: Mutex<Vec<String>>,
    }

    impl Docker for OneVolume {
        fn run(&self, args: &[&str], _stdin: Option<&[u8]>) -> Result<Output, DevError> {
            let line = args.join(" ");
            let stdout = if line.starts_with("volume ls") {
                b"saiife-shop_db\n".to_vec()
            } else {
                Vec::new()
            };
            self.calls.lock().unwrap().push(line);
            Ok(Output {
                status: 0,
                stdout,
                stderr: Vec::new(),
            })
        }
    }

    #[test]
    fn gc_volumes_answered_no_keeps_them_and_succeeds() {
        let base = tempfile::tempdir().unwrap();
        let paths = DevPaths {
            state: base.path().join("state"),
            config: base.path().join("config"),
        };
        let d = OneVolume::default();
        let no = |_: &str, _: bool| Ok(false);
        assert_eq!(gc_with(&d, &paths, true, false, true, &no), Ok(()));
        let calls = d.calls.lock().unwrap();
        assert!(
            calls.iter().any(|c| c.starts_with("volume ls")),
            "{calls:?}"
        );
        assert!(!calls.iter().any(|c| c.contains("volume rm")), "{calls:?}");
    }
}
