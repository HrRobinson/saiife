//! `saiife dev ls` (plan 24 Task 3).

use std::process::ExitCode;

use saiife_dev::docker::Docker;
use saiife_dev::paths::DevPaths;

/// Lists every environment, as a table or as JSON.
pub(crate) fn ls(d: &dyn Docker, paths: &DevPaths, json: bool) -> ExitCode {
    let _ = (d, paths, json);
    eprintln!("saiife dev: not built yet");
    ExitCode::from(1)
}
