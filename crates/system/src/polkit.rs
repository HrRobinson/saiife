//! Polkit re-authentication for approvals (spec §6.10.2): whether polkit is
//! there, and whether the `com.saiife.approve` action file is sound. Shared
//! by `system install` and `saiife doctor`. Nothing here runs `pkcheck`.

use crate::fsops::root_owned_problems;
use crate::host::Host;
use crate::layout::{Layout, PKCHECK, POLKIT_ACTION};
use std::os::unix::fs::MetadataExt;

/// Where distributions put `polkitd`.
pub const POLKITD_PATHS: &[&str] = &[
    "/usr/lib/polkit-1/polkitd",
    "/usr/libexec/polkitd",
    "/usr/lib/policykit-1/polkitd",
];

/// `/usr/bin/pkcheck` is a root-owned regular file that group and others
/// cannot write, and a `polkitd` binary exists.
pub fn polkit_present(layout: &Layout, host: &dyn Host) -> bool {
    let Some(root) = host.user("root") else {
        return false;
    };
    // A symlink is followed (what it reaches must pass the same checks).
    let sound = std::fs::metadata(layout.at(PKCHECK))
        .is_ok_and(|m| m.is_file() && root_owned_problems(&m, root.uid).is_empty());
    sound
        && POLKITD_PATHS
            .iter()
            .any(|p| std::fs::metadata(layout.at(p)).is_ok_and(|m| m.is_file()))
}

/// What is wrong with the installed action file: missing, not a regular
/// file (a symlink included), not root's, or not mode 0644.
pub fn action_problems(layout: &Layout, host: &dyn Host) -> Vec<String> {
    let p = layout.at(POLKIT_ACTION);
    let m = match std::fs::symlink_metadata(&p) {
        Ok(m) => m,
        Err(e) => return vec![format!("{POLKIT_ACTION}: {e}")],
    };
    if !m.is_file() {
        return vec![format!("{POLKIT_ACTION}: not a regular file")];
    }
    let Some(root) = host.user("root") else {
        return vec!["user root not found".into()];
    };
    let mut out = root_owned_problems(&m, root.uid);
    let perm = m.mode() & 0o7777;
    if perm != 0o644 {
        out.push(format!("mode {perm:04o}, not 0644"));
    }
    out
}
