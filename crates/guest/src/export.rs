//! The base snapshot and the export of `/work` (plan 39 fills these; no-ops here).

use crate::env::GuestEnv;

/// Records `/work` as the base on the first setup. Plan 39 replaces this no-op.
pub fn init_base(env: &GuestEnv) -> Result<(), String> {
    let _ = env;
    Ok(())
}
