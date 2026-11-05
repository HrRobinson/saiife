//! The Windows ACL table (spec §5.3a.3, W14): the one security descriptor each
//! path of the layout must have, and the checks an existing path or an
//! ancestor must pass. Pure text and data, so Linux tests run all of it.
//!
//! [`protected_ok`] and [`ancestor_ok`] read a security descriptor only. The
//! caller checks for reparse points, which an SDDL string cannot show.

use crate::layout::{Layout, WIN_SERVICE};
use saiife_win::sddl::{writers, Sd, WRITE_LIKE};
use saiife_win::sid::{service_sid, valid_sid, ADMINISTRATORS, SYSTEM, TRUSTED_INSTALLER};
use std::path::Path;

/// `C:\ProgramData\saiife`.
const ROOT: &str = "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)(A;;0x1200a9;;;<S>)";
/// `…\bin`, `…\bin\saiife.exe`, `…\etc` and everything below `etc`.
const PROGRAM_AND_CONFIG: &str =
    "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICI;0x1200a9;;;<S>)";
/// `…\state` and everything below it.
const STATE: &str = "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;<S>)";
/// `…\state\keys\vault.key`.
const VAULT_KEY: &str = "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;<S>)";
/// `…\log`.
const LOG: &str = "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;<S>)(A;;0x1200a9;;;BU)";
/// `…\log\audit` and everything below it.
const AUDIT: &str =
    "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;<S>)(A;OICI;0x1200a9;;;<A>)";
/// `…\log\daemon` and everything below it.
const DAEMON_LOG: &str =
    "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;<S>)(A;OICI;FR;;;<A>)";
/// The managed files and every dir install creates for them.
const MANAGED: &str = "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";

/// The owners a protected path or an ancestor may have.
const TRUSTED: [&str; 3] = [SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER];

/// `FILE_DELETE_CHILD`, `DELETE`, `WRITE_DAC`, `WRITE_OWNER`, `GENERIC_ALL`,
/// `GENERIC_WRITE`: what no non-admin may hold on an ancestor. Creating entries
/// is left out: Users may do that in `C:\ProgramData` by default, and it is
/// harmless, because they cannot rename or delete ours.
const ANCESTOR_FORBIDDEN: u32 = 0x0000_0040 | 0x0001_0000 | 0x0004_0000 | 0x0008_0000 | 0x5000_0000;

/// The name of every [`WRITE_LIKE`] bit, the most powerful first.
const RIGHTS: [(u32, &str); 10] = [
    (0x1000_0000, "GENERIC_ALL"),
    (0x4000_0000, "GENERIC_WRITE"),
    (0x0004_0000, "WRITE_DAC"),
    (0x0008_0000, "WRITE_OWNER"),
    (0x0001_0000, "DELETE"),
    (0x0000_0040, "FILE_DELETE_CHILD"),
    (0x0000_0002, "FILE_WRITE_DATA"),
    (0x0000_0004, "FILE_APPEND_DATA"),
    (0x0000_0010, "FILE_WRITE_EA"),
    (0x0000_0100, "FILE_WRITE_ATTRIBUTES"),
];

/// The W14 SDDL for `path`, a path of `layout`, with `<S>` and `<A>` filled in.
///
/// `None` for a path the table does not cover: an ancestor (`C:\ProgramData`
/// must never get one of these), another layout, an `audit_sid` that is not a
/// SID, and any spelling that is not plainly a name of the tree (`..`, a data
/// stream, a trailing dot). Names compare as Windows does, ignoring case.
pub fn expected(layout: &Layout, path: &Path, audit_sid: &str) -> Option<String> {
    if !valid_sid(audit_sid) {
        return None;
    }
    let (drive, names) = layout.windows_location(path)?;
    if !drive.eq_ignore_ascii_case(&'C') {
        return None;
    }
    let lower: Vec<String> = names.iter().map(|n| n.to_ascii_lowercase()).collect();
    let lower: Vec<&str> = lower.iter().map(String::as_str).collect();
    let row = match lower.as_slice() {
        ["programdata", "saiife"] => ROOT,
        ["programdata", "saiife", "bin"]
        | ["programdata", "saiife", "bin", "saiife.exe"]
        | ["programdata", "saiife", "etc", ..] => PROGRAM_AND_CONFIG,
        // Before the row for everything below `state`: the key is tighter.
        ["programdata", "saiife", "state", "keys", "vault.key"] => VAULT_KEY,
        ["programdata", "saiife", "state", ..] => STATE,
        ["programdata", "saiife", "log"] => LOG,
        ["programdata", "saiife", "log", "audit", ..] => AUDIT,
        ["programdata", "saiife", "log", "daemon", ..] => DAEMON_LOG,
        ["program files", "claudecode"]
        | ["program files", "claudecode", "managed-settings.d"]
        | ["program files", "claudecode", "managed-settings.d", "50-saiife.json"]
        | ["program files", "claudecode", "managed-settings.d", "60-saiife-mcp.json"]
        | ["programdata", "openai"]
        | ["programdata", "openai", "codex"]
        | ["programdata", "openai", "codex", "requirements.toml"]
        | ["programdata", "gemini-cli"]
        | ["programdata", "gemini-cli", "settings.json"] => MANAGED,
        _ => return None,
    };
    Some(
        row.replace("<S>", &service_sid(WIN_SERVICE))
            .replace("<A>", audit_sid),
    )
}

/// Whether an existing path of ours is safe to keep (W14): a trusted owner, and
/// no writer but SYSTEM, Administrators, TrustedInstaller and `extra_writers`
/// (`<S>` where the table grants it). `extra_writers` are SIDs.
pub fn protected_ok(sd: &Sd, extra_writers: &[&str]) -> Result<(), String> {
    owner_ok(sd)?;
    for sid in writers(sd) {
        if TRUSTED.contains(&sid.as_str()) || extra_writers.contains(&sid.as_str()) {
            continue;
        }
        let held = sd
            .aces
            .iter()
            .filter(|a| a.allow && !a.flags.inherit_only && a.sid == sid)
            .fold(0, |mask, a| mask | a.mask);
        return Err(refusal(&sid, held & WRITE_LIKE));
    }
    Ok(())
}

/// Whether a folder above ours is safe to build under (W14): a trusted owner,
/// and no non-admin allow ACE (not inherit-only) that could replace or re-ACL
/// what is in it.
pub fn ancestor_ok(sd: &Sd) -> Result<(), String> {
    owner_ok(sd)?;
    for ace in &sd.aces {
        let held = ace.mask & ANCESTOR_FORBIDDEN;
        if ace.allow && !ace.flags.inherit_only && held != 0 && !TRUSTED.contains(&ace.sid.as_str())
        {
            return Err(refusal(&ace.sid, held));
        }
    }
    Ok(())
}

/// The owner holds `WRITE_DAC` whatever the DACL says, so `writers` cannot
/// stand in for this. No owner on record is refused too.
fn owner_ok(sd: &Sd) -> Result<(), String> {
    let owner = sd.owner.as_deref().unwrap_or("nobody known");
    if TRUSTED.contains(&owner) {
        return Ok(());
    }
    Err(format!(
        "owned by {owner}, expected SYSTEM, Administrators or TrustedInstaller"
    ))
}

fn refusal(sid: &str, held: u32) -> String {
    let right = RIGHTS
        .iter()
        .find(|(bit, _)| held & bit != 0)
        .map_or("write", |(_, name)| name);
    format!("{sid} may {right} here")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::{self, Platform};
    use saiife_win::sddl::parse;
    use saiife_win::sid::{AUTHENTICATED_USERS, USERS};
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    const A: &str = "S-1-5-21-1-2-3-1009";
    const S: &str = "S-1-5-80-1485410291-497971702-176010752-1662630379-411534723";

    /// `C:\ProgramData` as Microsoft Q&A question 1841814 prints it with
    /// `icacls`, written as SDDL by hand (`WD,AD,WEA,WA` is `0x116`). `icacls`
    /// does not show the owner; SYSTEM is assumed. Confirm against a real
    /// machine in `locked-windows`.
    const PROGRAMDATA: &str = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;GA;;;CO)\
         (A;OICI;0x1200a9;;;BU)(A;CI;0x116;;;BU)";

    fn test_layout() -> (tempfile::TempDir, Layout) {
        let d = tempfile::tempdir().unwrap();
        let l = Layout::under_for(d.path(), Platform::Windows);
        (d, l)
    }

    /// Who the table lets write, and how it inherits, for one row.
    struct Row {
        path: &'static str,
        sddl: &'static str,
        writers: &'static [&'static str],
        inherits: bool,
        readers: &'static [&'static str],
    }

    const ADMINS: &[&str] = &[SYSTEM, ADMINISTRATORS];
    const ADMINS_AND_S: &[&str] = &[SYSTEM, ADMINISTRATORS, S];

    /// Spec §5.3a.3, typed out here on purpose and not built from the code, so
    /// a slip in the table cannot agree with itself.
    const ROWS: &[Row] = &[
        Row {
            path: r"C:\ProgramData\saiife",
            sddl: "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)(A;;0x1200a9;;;<S>)",
            writers: ADMINS,
            inherits: false,
            readers: &[USERS, S],
        },
        Row {
            path: r"C:\ProgramData\saiife\bin",
            sddl: "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICI;0x1200a9;;;<S>)",
            writers: ADMINS,
            inherits: true,
            readers: &[USERS, S],
        },
        Row {
            path: r"C:\ProgramData\saiife\bin\saiife.exe",
            sddl: "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICI;0x1200a9;;;<S>)",
            writers: ADMINS,
            inherits: true,
            readers: &[USERS, S],
        },
        Row {
            path: r"C:\ProgramData\saiife\etc",
            sddl: "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICI;0x1200a9;;;<S>)",
            writers: ADMINS,
            inherits: true,
            readers: &[USERS, S],
        },
        Row {
            path: r"C:\ProgramData\saiife\etc\policy.d\10-team.toml",
            sddl: "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICI;0x1200a9;;;<S>)",
            writers: ADMINS,
            inherits: true,
            readers: &[USERS, S],
        },
        Row {
            path: r"C:\ProgramData\saiife\state",
            sddl: "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;<S>)",
            writers: ADMINS_AND_S,
            inherits: true,
            readers: &[],
        },
        Row {
            path: r"C:\ProgramData\saiife\state\keys\audit.ed25519",
            sddl: "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;<S>)",
            writers: ADMINS_AND_S,
            inherits: true,
            readers: &[],
        },
        Row {
            path: r"C:\ProgramData\saiife\state\keys\vault.key",
            sddl: "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;<S>)",
            writers: ADMINS,
            inherits: false,
            readers: &[S],
        },
        Row {
            path: r"C:\ProgramData\saiife\log",
            sddl: "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;<S>)(A;;0x1200a9;;;BU)",
            writers: ADMINS,
            inherits: false,
            readers: &[S, USERS],
        },
        Row {
            path: r"C:\ProgramData\saiife\log\audit\2026-11.jsonl",
            sddl: "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;<S>)(A;OICI;0x1200a9;;;<A>)",
            writers: ADMINS_AND_S,
            inherits: true,
            readers: &[A],
        },
        Row {
            path: r"C:\ProgramData\saiife\log\daemon\daemon.log",
            sddl: "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;<S>)(A;OICI;FR;;;<A>)",
            writers: ADMINS_AND_S,
            inherits: true,
            readers: &[A],
        },
        Row {
            path: r"C:\Program Files\ClaudeCode",
            sddl: "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)",
            writers: ADMINS,
            inherits: true,
            readers: &[USERS],
        },
        Row {
            path: r"C:\Program Files\ClaudeCode\managed-settings.d\50-saiife.json",
            sddl: "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)",
            writers: ADMINS,
            inherits: true,
            readers: &[USERS],
        },
        Row {
            path: r"C:\ProgramData\OpenAI\Codex\requirements.toml",
            sddl: "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)",
            writers: ADMINS,
            inherits: true,
            readers: &[USERS],
        },
        Row {
            path: r"C:\ProgramData\gemini-cli\settings.json",
            sddl: "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)",
            writers: ADMINS,
            inherits: true,
            readers: &[USERS],
        },
    ];

    fn at(l: &Layout, windows: &str) -> PathBuf {
        l.try_at(Path::new(windows)).unwrap()
    }

    #[test]
    fn expected_sddl_table() {
        let (_d, l) = test_layout();
        let sys = Layout::system_for(Platform::Windows);
        for row in ROWS {
            let want = row.sddl.replace("<S>", S).replace("<A>", A);
            assert_eq!(
                expected(&l, &at(&l, row.path), A).as_deref(),
                Some(want.as_str()),
                "{}",
                row.path
            );
            assert_eq!(
                expected(&sys, Path::new(row.path), A).as_deref(),
                Some(want.as_str()),
                "real spelling of {}",
                row.path
            );
        }
    }

    /// Read each row as a descriptor: who may write, who owns it, what it
    /// inherits, and who else appears at all.
    #[test]
    fn table_grants_nothing_beyond_the_spec() {
        let (_d, l) = test_layout();
        for row in ROWS {
            let text = expected(&l, &at(&l, row.path), A).unwrap();
            let sd = parse(&text).unwrap_or_else(|e| panic!("{}: {e}", row.path));
            assert_eq!(sd.owner.as_deref(), Some(ADMINISTRATORS), "{}", row.path);
            assert_eq!(sd.group.as_deref(), Some(SYSTEM), "{}", row.path);
            assert!(sd.dacl_protected, "{} inherits its parent", row.path);
            let want: BTreeSet<String> = row.writers.iter().map(|s| s.to_string()).collect();
            assert_eq!(writers(&sd), want, "{}", row.path);
            // Never Users, the audit group or Authenticated Users, even with an
            // ACE `writers` would skip.
            for ace in &sd.aces {
                assert!(ace.allow, "{}", row.path);
                assert!(!ace.flags.inherit_only, "{}", row.path);
                assert_eq!(
                    (ace.flags.object_inherit, ace.flags.container_inherit),
                    (row.inherits, row.inherits),
                    "{}",
                    row.path
                );
                if ace.sid == USERS || ace.sid == A || ace.sid == AUTHENTICATED_USERS {
                    assert_eq!(ace.mask & WRITE_LIKE, 0, "{} {}", row.path, ace.sid);
                }
            }
            // Everyone on the row is an admin, a writer, or a listed reader.
            let named: BTreeSet<&str> = sd.aces.iter().map(|a| a.sid.as_str()).collect();
            let allowed: BTreeSet<&str> = ADMINS
                .iter()
                .chain(row.writers)
                .chain(row.readers)
                .copied()
                .collect();
            assert_eq!(named, allowed, "{}", row.path);
            // Each row passes its own check, and only with `<S>` where it writes.
            let s_writes = row.writers.contains(&S);
            assert_eq!(protected_ok(&sd, &[]).is_ok(), !s_writes, "{}", row.path);
            protected_ok(&sd, &[S]).unwrap_or_else(|e| panic!("{}: {e}", row.path));
        }
    }

    /// Every layout constant with a Windows path lands on its row.
    #[test]
    fn every_constant_of_the_tree_has_its_row() {
        let (_d, l) = test_layout();
        let row = |constant: &str| expected(&l, &l.at(constant), A).unwrap();
        let fill = |s: &str| s.replace("<S>", S).replace("<A>", A);
        for c in [
            layout::BIN_DIR,
            layout::BINARY,
            layout::ETC_DIR,
            layout::CONFIG,
            layout::POLICY_D,
            layout::INSTALLED,
            layout::CA_DIR,
            layout::FLEET_DIR,
            layout::FLEET_CONFIG,
            layout::FLEET_INSTALL,
        ] {
            assert_eq!(row(c), fill(PROGRAM_AND_CONFIG), "{c}");
        }
        for c in [layout::STATE_DIR, layout::KEYS_DIR, layout::AUDIT_KEY] {
            assert_eq!(row(c), fill(STATE), "{c}");
        }
        assert_eq!(row(layout::OPT_DIR), fill(ROOT));
        assert_eq!(row(layout::VAULT_KEY), fill(VAULT_KEY));
        assert_eq!(row(layout::LOG_DIR), fill(LOG));
        assert_eq!(row(layout::AUDIT_DIR), fill(AUDIT));
        assert_eq!(row(layout::DAEMON_LOG), fill(DAEMON_LOG));
        for c in [
            layout::CLAUDE_MANAGED_DIR,
            layout::CLAUDE_MANAGED,
            layout::CLAUDE_MCP,
            layout::CODEX_DIR,
            layout::CODEX_REQUIREMENTS,
            layout::GEMINI_DIR,
            layout::GEMINI_SETTINGS,
        ] {
            assert_eq!(row(c), fill(MANAGED), "{c}");
        }
    }

    #[test]
    fn vault_key_readable_only_by_service() {
        let (_d, l) = test_layout();
        let text = expected(&l, &l.at(layout::VAULT_KEY), A).unwrap();
        let sd = parse(&text).unwrap();
        assert!(sd.dacl_protected);
        let sids: Vec<&str> = sd.aces.iter().map(|a| a.sid.as_str()).collect();
        assert_eq!(sids, [SYSTEM, ADMINISTRATORS, S]);
        let service = sd.aces.iter().find(|a| a.sid == S).unwrap();
        assert_eq!(service.mask, 0x12_0089, "FR, nothing more");
        assert_eq!(service.mask & WRITE_LIKE, 0);
        // Windows ignores case, so another spelling is still the key.
        let shouted = at(&l, r"C:\PROGRAMDATA\SAIIFE\STATE\KEYS\VAULT.KEY");
        assert_eq!(expected(&l, &shouted, A), Some(text));
    }

    /// The service SID in the table is the service's own.
    #[test]
    fn s_is_the_service_sid() {
        assert_eq!(service_sid(WIN_SERVICE), S);
    }

    #[test]
    fn expected_is_none_outside_the_table() {
        let (_d, l) = test_layout();
        let sys = Layout::system_for(Platform::Windows);
        for path in [
            // Ancestors: install must never put these on them.
            r"C:\",
            r"C:\ProgramData",
            r"C:\Program Files",
            // Lookalikes and strangers.
            r"C:\ProgramData\saiife2",
            r"C:\ProgramData\saiife\etcetera",
            r"C:\ProgramData\saiife\bin\other.exe",
            r"C:\ProgramData\saiife\log\other.log",
            r"C:\ProgramData\saiife\other",
            r"C:\ProgramData\OpenAI\other",
            r"C:\ProgramData\OpenAI\Codex\other.toml",
            r"C:\ProgramData\gemini-cli\other.json",
            r"C:\Program Files\ClaudeCode\managed-settings.json",
            r"C:\Program Files\ClaudeCode\managed-settings.d\99-other.json",
            r"C:\Program Files\saiife\saiife.exe",
            r"C:\Windows",
            // Another drive.
            r"D:\ProgramData\saiife\etc",
        ] {
            assert_eq!(expected(&l, &at(&l, path), A), None, "{path}");
            assert_eq!(expected(&sys, Path::new(path), A), None, "{path}");
        }
        // Spellings Win32 would read as some other path of the tree.
        for path in [
            r"C:\ProgramData\saiife\etc\..\state",
            r"C:\ProgramData\saiife\etc\..\..\..\Windows",
            r"C:\ProgramData\saiife\etc\.. \x",
            r"C:\ProgramData\saiife\state\keys\vault.key.",
            r"C:\ProgramData\saiife\state\keys\vault.key ",
            r"C:\ProgramData\saiife\state\keys\vault.key::$DATA",
            r"\\?\C:\ProgramData\saiife\etc",
            r"\\server\share\ProgramData\saiife\etc",
            r"ProgramData\saiife\etc",
        ] {
            assert_eq!(expected(&sys, Path::new(path), A), None, "{path}");
        }
        // The same names below a test root, each as one path component where
        // this OS allows it.
        for rest in [
            "C/ProgramData/saiife/etc/../state",
            "C/ProgramData/saiife/state/keys/vault.key.",
            "C/ProgramData/saiife/state/keys/vault.key::$DATA",
            "CC/ProgramData/saiife/etc",
            "1/ProgramData/saiife/etc",
        ] {
            assert_eq!(expected(&l, &l.root().join(rest), A), None, "{rest}");
        }
        #[cfg(unix)]
        assert_eq!(
            expected(
                &l,
                &l.root().join(r"C/ProgramData/saiife/state/keys\vault.key"),
                A
            ),
            None
        );
        // Outside the root.
        assert_eq!(expected(&l, Path::new("/ProgramData/saiife"), A), None);
    }

    #[test]
    fn expected_is_none_for_other_platforms() {
        let d = tempfile::tempdir().unwrap();
        for p in [Platform::Linux, Platform::Macos] {
            let l = Layout::under_for(d.path(), p);
            assert_eq!(expected(&l, &l.at(layout::CONFIG), A), None);
            assert_eq!(
                expected(&l, &l.root().join("C/ProgramData/saiife/etc"), A),
                None
            );
        }
    }

    /// `audit_sid` goes into the descriptor as text: it can never add an ACE.
    #[test]
    fn expected_refuses_a_malformed_audit_sid() {
        let (_d, l) = test_layout();
        let audit = l.at(layout::AUDIT_DIR);
        for bad in ["", "BU", "saiife-audit", "S-1-5-1)(A;;FA;;;BU"] {
            assert_eq!(expected(&l, &audit, bad), None, "{bad:?}");
        }
    }

    fn ok_sd(owner: &str, aces: &str) -> Sd {
        parse(&format!("O:{owner}G:SYD:P(A;;FA;;;SY){aces}")).unwrap()
    }

    #[test]
    fn protected_ok_refuses_user_owner() {
        let user = "S-1-5-21-1-2-3-1001";
        assert_eq!(
            protected_ok(&ok_sd(user, ""), &[]),
            Err(format!(
                "owned by {user}, expected SYSTEM, Administrators or TrustedInstaller"
            ))
        );
        // Not even when that user is an allowed writer: an owner keeps WRITE_DAC.
        assert!(protected_ok(&ok_sd(user, ""), &[user]).is_err());
        // Users as owner, and no owner on record.
        assert!(protected_ok(&ok_sd("BU", ""), &[]).is_err());
        assert!(protected_ok(&parse("D:P(A;;FA;;;SY)").unwrap(), &[]).is_err());
    }

    #[test]
    fn protected_ok_accepts_each_trusted_owner() {
        for owner in [SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER] {
            protected_ok(&ok_sd(owner, ""), &[]).unwrap();
            ancestor_ok(&ok_sd(owner, "")).unwrap();
        }
    }

    #[test]
    fn protected_ok_refuses_user_write() {
        for (ace, right) in [
            ("(A;OICI;FA;;;BU)", "WRITE_DAC"),
            ("(A;;FW;;;BU)", "FILE_WRITE_DATA"),
            ("(A;;0x1301bf;;;BU)", "DELETE"),
            ("(A;;GA;;;BU)", "GENERIC_ALL"),
            ("(A;;GW;;;BU)", "GENERIC_WRITE"),
            ("(A;;WD;;;BU)", "WRITE_DAC"),
            ("(A;;WO;;;BU)", "WRITE_OWNER"),
        ] {
            assert_eq!(
                protected_ok(&ok_sd("BA", ace), &[]),
                Err(format!("{USERS} may {right} here")),
                "{ace}"
            );
        }
        // A grant to the service is refused unless the table allows it.
        let sd = ok_sd("BA", &format!("(A;OICI;FA;;;{S})"));
        assert!(protected_ok(&sd, &[]).is_err());
        protected_ok(&sd, &[S]).unwrap();
        // The allowance is for that SID alone.
        let sd = ok_sd("BA", &format!("(A;;FA;;;{S})(A;;FA;;;{A})"));
        assert_eq!(
            protected_ok(&sd, &[S]),
            Err(format!("{A} may WRITE_DAC here"))
        );
    }

    #[test]
    fn protected_ok_refuses_append_only_grant() {
        assert_eq!(
            protected_ok(&ok_sd("BA", "(A;;0x4;;;BU)"), &[]),
            Err(format!("{USERS} may FILE_APPEND_DATA here"))
        );
    }

    /// Each write-like bit alone is refused, and has a name in the message.
    #[test]
    fn protected_ok_refuses_every_write_like_bit() {
        assert_eq!(RIGHTS.iter().fold(0, |m, (b, _)| m | b), WRITE_LIKE);
        for (bit, name) in RIGHTS {
            let sd = ok_sd("BA", &format!("(A;;{bit:#x};;;BU)"));
            assert_eq!(
                protected_ok(&sd, &[]),
                Err(format!("{USERS} may {name} here"))
            );
        }
    }

    #[test]
    fn protected_ok_accepts_readers() {
        protected_ok(&ok_sd("BA", "(A;OICI;0x1200a9;;;BU)(A;;FR;;;AU)"), &[]).unwrap();
    }

    /// A deny does not excuse an allow (`writers` errs on the safe side).
    #[test]
    fn protected_ok_does_not_subtract_a_deny() {
        assert!(protected_ok(&ok_sd("BA", "(D;;FA;;;BU)(A;;FA;;;BU)"), &[]).is_err());
    }

    #[test]
    fn ancestor_ok_accepts_programdata_default() {
        ancestor_ok(&parse(PROGRAMDATA).unwrap()).unwrap();
        // The same folder is not fit to be ours: Users may create entries.
        assert!(protected_ok(&parse(PROGRAMDATA).unwrap(), &[]).is_err());
    }

    /// `C:\Program Files` is owned by TrustedInstaller, and an inherit-only
    /// grant applies to children, not to the folder (the `C:\` shape).
    #[test]
    fn ancestor_ok_accepts_trusted_installer_and_inherit_only() {
        let sd = parse(&format!(
            "O:{TRUSTED_INSTALLER}G:SYD:P(A;;FA;;;{TRUSTED_INSTALLER})(A;OICIIO;GA;;;CO)(A;OICIIO;0x1301bf;;;AU)(A;;0x4;;;AU)"
        ))
        .unwrap();
        ancestor_ok(&sd).unwrap();
    }

    #[test]
    fn ancestor_ok_refuses_delete_child_for_users() {
        assert_eq!(
            ancestor_ok(&ok_sd("SY", "(A;CI;0x40;;;BU)")),
            Err(format!("{USERS} may FILE_DELETE_CHILD here"))
        );
    }

    #[test]
    fn ancestor_ok_refuses_each_forbidden_right() {
        for (bit, name) in [
            (0x4_0000u32, "WRITE_DAC"),
            (0x8_0000, "WRITE_OWNER"),
            (0x1_0000, "DELETE"),
            (0x40, "FILE_DELETE_CHILD"),
            (0x4000_0000, "GENERIC_WRITE"),
            (0x1000_0000, "GENERIC_ALL"),
        ] {
            assert_eq!(
                ancestor_ok(&ok_sd("SY", &format!("(A;;{bit:#x};;;AU)"))),
                Err(format!("{AUTHENTICATED_USERS} may {name} here"))
            );
            // Admins may hold it; a deny or an inherit-only grant is no grant.
            ancestor_ok(&ok_sd("SY", &format!("(A;;{bit:#x};;;BA)"))).unwrap();
            ancestor_ok(&ok_sd("SY", &format!("(D;;{bit:#x};;;BU)"))).unwrap();
            ancestor_ok(&ok_sd("SY", &format!("(A;CIIO;{bit:#x};;;BU)"))).unwrap();
        }
    }

    #[test]
    fn ancestor_ok_refuses_a_user_owner() {
        let user = "S-1-5-21-1-2-3-1001";
        assert_eq!(
            ancestor_ok(&ok_sd(user, "")),
            Err(format!(
                "owned by {user}, expected SYSTEM, Administrators or TrustedInstaller"
            ))
        );
        assert!(ancestor_ok(&parse("D:P(A;;FA;;;SY)").unwrap()).is_err());
    }
}
