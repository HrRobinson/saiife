//! `saiife doctor [--user <name>] [--json]`: checks the machine locked mode
//! relies on (spec §5.6, §6.16). Exit 0 all pass, 1 a warning, 2 a failure.
//! Read-only: it changes nothing on the host.

use std::path::PathBuf;
use std::process::ExitCode;

use saiife_policy::{Directory, Getent};
use saiife_system::doctor::{self, DoctorOptions};
use saiife_system::{host_for, Layout};

pub fn run(user: Option<String>, json: bool, root: Option<PathBuf>) -> ExitCode {
    let layout = root.map(Layout::under).unwrap_or_else(Layout::system);
    let host = match host_for(&layout) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("saiife: doctor: {e}");
            return ExitCode::from(2);
        }
    };
    let dir = Getent;
    if let Some(name) = &user {
        let me = dir.name_of(rustix::process::getuid().as_raw());
        if me.as_deref() != Some(name.as_str()) && host.euid() != 0 {
            eprintln!("saiife: --user {name} needs root");
            return ExitCode::from(2);
        }
    }
    let report = doctor::run(&layout, host.as_ref(), &dir, &DoctorOptions { user });
    if json {
        outln!(
            "{}",
            serde_json::to_string_pretty(&report.to_json()).unwrap_or_default()
        );
    } else {
        out!("{}", report.to_text());
    }
    ExitCode::from(report.exit_code())
}
