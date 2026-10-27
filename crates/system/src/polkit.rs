//! Polkit re-authentication for approvals (spec §6.10.2): whether polkit is
//! there, and whether the `com.saiife.approve` action file is sound. Shared
//! by `system install` and `saiife doctor`. Nothing here runs `pkcheck`.

use crate::fsops::{root_owned_problems, sha256_file, sha256_hex};
use crate::host::Host;
use crate::layout::{Layout, PKCHECK, POLKIT_ACTION, POLKIT_ACTION_ID, POLKIT_POLICY};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

/// Where polkit reads its JavaScript rules from.
pub const POLKIT_RULES_DIRS: &[&str] = &[
    "/etc/polkit-1/rules.d",
    "/run/polkit-1/rules.d",
    "/usr/local/share/polkit-1/rules.d",
    "/usr/share/polkit-1/rules.d",
];
/// The most of one rules file read when looking for the action id.
const MAX_RULES_FILE_BYTES: u64 = 1024 * 1024;
/// The most rules files looked at per directory.
const MAX_RULES_FILES: usize = 1000;
/// The doctor warning when a polkit rule names the approval action.
pub const RULE_MENTIONS_ACTION: &str =
    "a polkit rule mentions com.saiife.approve; it may pre-authorize approvals";

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
/// file (a symlink included), not root's, not mode 0644, or not exactly
/// [`POLKIT_POLICY`] (which names the daemon user as the action's owner).
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
    match sha256_file(&p) {
        Ok(Some(h)) if h == sha256_hex(POLKIT_POLICY.as_bytes()) => {}
        Ok(_) => out.push(format!(
            "{POLKIT_ACTION}: not the action file saiife installs (run saiife system install)"
        )),
        Err(e) => out.push(format!("{POLKIT_ACTION}: {e}")),
    }
    out
}

/// The polkit rules files (in [`POLKIT_RULES_DIRS`]) that mention
/// `com.saiife.approve`: a rule may answer `YES` for it and so skip the
/// password. Regular files only (a symlink is not followed), each read up
/// to 1 MiB; an unreadable directory or file is skipped.
pub fn rules_mentioning_action(layout: &Layout) -> Vec<String> {
    scan_rules(layout).0
}

/// [`rules_mentioning_action`], and the rules directories that exist but
/// cannot be read (permission denied: not running as root), which the scan
/// could not look in.
pub fn scan_rules(layout: &Layout) -> (Vec<String>, Vec<String>) {
    let mut out = Vec::new();
    let mut unreadable = Vec::new();
    for dir in POLKIT_RULES_DIRS {
        let entries = match std::fs::read_dir(layout.at(dir)) {
            Ok(e) => e,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    unreadable.push((*dir).to_string());
                }
                continue;
            }
        };
        for e in entries.flatten().take(MAX_RULES_FILES) {
            let p = e.path();
            if !e.file_type().is_ok_and(|t| t.is_file()) {
                continue;
            }
            let Ok(f) = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                .open(&p)
            else {
                continue;
            };
            let mut b = Vec::new();
            if f.take(MAX_RULES_FILE_BYTES).read_to_end(&mut b).is_err() {
                continue;
            }
            let needle = POLKIT_ACTION_ID.as_bytes();
            if b.windows(needle.len()).any(|w| w == needle) {
                out.push(format!("{dir}/{}", e.file_name().to_string_lossy()));
            }
        }
    }
    out.sort();
    (out, unreadable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn rules_naming_the_action_are_found() {
        let d = tempfile::tempdir().unwrap();
        let layout = Layout::under(d.path());
        assert!(rules_mentioning_action(&layout).is_empty());
        for dir in POLKIT_RULES_DIRS {
            fs::create_dir_all(layout.at(dir)).unwrap();
        }
        let etc = layout.at(POLKIT_RULES_DIRS[0]);
        let run = layout.at(POLKIT_RULES_DIRS[1]);
        let local = layout.at(POLKIT_RULES_DIRS[2]);
        let usr = layout.at(POLKIT_RULES_DIRS[3]);
        fs::write(etc.join("10-other.rules"), "polkit.addRule(function(){});").unwrap();
        assert!(rules_mentioning_action(&layout).is_empty());
        fs::write(
            etc.join("49-yes.rules"),
            r#"polkit.addRule(function(a){ if (a.id == "com.saiife.approve") return polkit.Result.YES; });"#,
        )
        .unwrap();
        fs::write(usr.join("50-x.rules"), "// com.saiife.approve").unwrap();
        fs::write(run.join("10-r.rules"), "com.saiife.approve").unwrap();
        fs::write(local.join("10-l.rules"), "x com.saiife.approve x").unwrap();
        // A symlink is not followed.
        std::os::unix::fs::symlink(etc.join("49-yes.rules"), usr.join("60-link.rules")).unwrap();
        assert_eq!(
            rules_mentioning_action(&layout),
            vec![
                "/etc/polkit-1/rules.d/49-yes.rules".to_string(),
                "/run/polkit-1/rules.d/10-r.rules".to_string(),
                "/usr/local/share/polkit-1/rules.d/10-l.rules".to_string(),
                "/usr/share/polkit-1/rules.d/50-x.rules".to_string(),
            ]
        );
    }

    #[test]
    fn the_action_names_the_daemon_user_as_its_owner() {
        assert!(POLKIT_POLICY.contains(&format!(
            "<annotate key=\"org.freedesktop.policykit.owner\">unix-user:{}</annotate>",
            crate::layout::DAEMON_USER
        )));
        assert!(POLKIT_POLICY.contains("$(request)"));
    }
}
