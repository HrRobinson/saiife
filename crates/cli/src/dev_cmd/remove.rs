//! `saiife dev down` and `saiife dev gc` (plan 24 Tasks 4 and 5).

use saiife_dev::docker::Docker;
use saiife_dev::paths::DevPaths;

use super::Res;

/// Stops `project` and removes what saiife labelled for it.
pub(crate) fn down(
    d: &dyn Docker,
    paths: &DevPaths,
    project: &str,
    volumes: bool,
    yes: bool,
) -> Res {
    let _ = (d, paths, project, volumes, yes);
    Err("not built yet".into())
}

/// Removes what saiife labelled for stopped and missing projects.
pub(crate) fn gc(d: &dyn Docker, paths: &DevPaths, volumes: bool, yes: bool) -> Res {
    let _ = (d, paths, volumes, yes);
    Err("not built yet".into())
}
