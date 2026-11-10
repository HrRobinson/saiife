//! `saiife dev up` (plan 24 Task 2).

use std::path::Path;

use saiife_dev::docker::Docker;
use saiife_dev::paths::DevPaths;

use super::Res;

/// Starts the compose stack in `dir` (default: the current folder).
pub(crate) fn up(d: &dyn Docker, paths: &DevPaths, dir: Option<&Path>) -> Res {
    let _ = (d, paths, dir);
    Err("not built yet".into())
}
