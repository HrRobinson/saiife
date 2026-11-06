//! The Windows ACL table (spec §5.3a.3, W14): the one security descriptor each
//! path of the layout must have, and the checks an existing path or an
//! ancestor must pass. Pure text and data, so Linux tests run all of it.
//!
//! [`protected_ok`] and [`ancestor_ok`] read a security descriptor only. The
//! caller checks for reparse points, which an SDDL string cannot show.

use crate::host::Host;
use crate::layout::{Layout, WIN_SERVICE};
use saiife_win::sddl::{parse, render, writers, Sd, LOCAL_ADMIN, WRITE_LIKE};
use saiife_win::sid::{service_sid, valid_sid, ADMINISTRATORS, SYSTEM, TRUSTED_INSTALLER};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
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

/// `CREATOR OWNER`: a placeholder for whoever creates a child, stock on
/// `C:\Program Files` and on what is below it.
const CREATOR_OWNER: &str = "S-1-3-0";

/// The owners a protected path or an ancestor may have, and the writers it may have
/// without being named. `LA` is this machine's built-in Administrator, who is always in
/// `Administrators`; Windows prints that account by alias.
const TRUSTED: [&str; 4] = [SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER, LOCAL_ADMIN];

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
/// `Ok(None)` for a path the table does not cover: an ancestor
/// (`C:\ProgramData` must never get one of these), another layout, and any
/// spelling that is not plainly a name of the tree (`..`, a data stream, a
/// trailing dot). Names compare as Windows does, ignoring case.
///
/// `Err` when `audit_sid` is not a SID, on every path: a caller that skips what
/// the table does not cover must not skip every check because of a bad lookup.
/// A well-formed but wrong SID (`S-1-1-0`) passes here; plan 19b Task 7 checks
/// that the lookup found a local group.
pub fn expected(layout: &Layout, path: &Path, audit_sid: &str) -> Result<Option<String>, String> {
    if !valid_sid(audit_sid) {
        return Err(format!("{audit_sid:?} is not a SID"));
    }
    Ok(row_for(layout, path, audit_sid))
}

fn row_for(layout: &Layout, path: &Path, audit_sid: &str) -> Option<String> {
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
/// (`<S>` where the table grants it, see [`service_may_write`]). `extra_writers`
/// are SIDs.
///
/// The service may own what it may write, since a file it creates reads back
/// that way. No other SID in `extra_writers` may own anything.
///
/// Inherit-only grants count, unlike in [`writers`]: every new child would get
/// them until its descriptor is reset, and a handle opened in that window
/// outlives the reset. `CREATOR OWNER` is exempt as a placeholder only.
pub fn protected_ok(sd: &Sd, extra_writers: &[&str]) -> Result<(), String> {
    let service = service_sid(WIN_SERVICE);
    let owned_by_service = sd.owner.as_deref() == Some(service.as_str());
    if !(owned_by_service && extra_writers.contains(&service.as_str())) {
        owner_ok(sd)?;
    }
    let mut held: BTreeMap<&str, u32> = BTreeMap::new();
    for ace in sd.aces.iter().filter(|a| a.allow) {
        if !(ace.flags.inherit_only && ace.sid == CREATOR_OWNER) {
            *held.entry(ace.sid.as_str()).or_default() |= ace.mask & WRITE_LIKE;
        }
    }
    for (sid, mask) in held {
        if mask != 0 && !TRUSTED.contains(&sid) && !extra_writers.contains(&sid) {
            return Err(refusal(sid, mask));
        }
    }
    Ok(())
}

/// Whether the table lets the service write on the row `want`, an SDDL from
/// [`expected`].
pub fn service_may_write(want: &str) -> bool {
    parse(want).is_ok_and(|sd| writers(&sd).contains(&service_sid(WIN_SERVICE)))
}

/// Whether `actual`, read back from a path, is what its row `want` asks for
/// (spec §5.3a.3).
///
/// On a row the service may write, it may also have created the file, which
/// then reads back with itself as owner, its token's group, and the parent's
/// ACEs marked inherited. So there the owner may be `<S>`, the group and the
/// inheritance flags are not compared, and the grants must be the row's grants,
/// no more and no fewer. On every other row the descriptor must be exact.
///
/// This is for a directory, which keeps `OI` and `CI`. For a file use
/// [`actual_file_ok`]. The `AI` flag is not compared at all: [`Sd`] does not keep
/// it, so what protects a path is `P`, which is compared on every row.
pub fn actual_ok(want: &str, actual: &Sd) -> Result<(), String> {
    check(want, actual, false)
}

/// [`actual_ok`] for a file. Windows keeps no `OI` or `CI` on a file, so a row
/// written `OICI` reads back without them (seen in CI on `saiife.exe`). They are
/// cleared from the row before comparing, and a file that reads back with them is
/// refused. Owner, group, `P`, every other flag, and each ACE stay exact.
pub fn actual_file_ok(want: &str, actual: &Sd) -> Result<(), String> {
    check(want, actual, true)
}

fn check(want: &str, actual: &Sd, file: bool) -> Result<(), String> {
    let mut table = parse(want)?;
    if file {
        for ace in &mut table.aces {
            ace.flags.object_inherit = false;
            ace.flags.container_inherit = false;
        }
    }
    let differs = || format!("reads {}, expected {}", render(actual), render(&table));
    if !service_may_write(want) {
        protected_ok(actual, &[])?;
        return if *actual == table {
            Ok(())
        } else {
            Err(differs())
        };
    }
    protected_ok(actual, &[service_sid(WIN_SERVICE).as_str()])?;
    let grants = |sd: &'_ Sd| -> BTreeSet<(bool, String, u32)> {
        sd.aces
            .iter()
            .map(|a| (a.allow, a.sid.clone(), a.mask))
            .collect()
    };
    let passed_on_only = actual.aces.iter().any(|a| a.flags.inherit_only);
    if passed_on_only || grants(actual) != grants(&table) {
        return Err(differs());
    }
    Ok(())
}

/// Sets a descriptor on `root` and on everything below it, top-down. `row` gives the
/// SDDL of one entry from its path and whether it is a directory.
///
/// `Host::set_sddl` propagates to children that inherit, but not to a protected
/// child (`P`) or to an explicit entry a child holds (see its note). A tree an older
/// ACL left with such entries stays user-writable there, so install and reinstall
/// call this to set every entry itself.
///
/// Nothing is followed. A reparse point (symlink, junction, or any other reparse
/// tag) anywhere in the tree is an error, as is a hard-linked file, which
/// `set_sddl` refuses. The walk stops at the first error, so an entry past it is
/// untouched. Returns how many entries were set.
///
/// The walk goes by path, so what it was told must stay true while it works:
/// - `check` runs before every set, and is the caller's check of all the entry's
///   ancestors (W14);
/// - a handle with no `FILE_SHARE_DELETE` holds `root`, so it cannot be renamed;
/// - the real `set_sddl` refuses a handle that is not at the path it was given, which
///   catches a junction swapped in below `root` after `check` read it.
///
/// `Host` cannot list a directory, so this reads the tree with `std::fs`: the
/// real one on Windows, and the fake host's root on Linux.
pub fn set_sddl_tree(
    host: &dyn Host,
    root: &Path,
    check: &mut dyn FnMut(&Path) -> io::Result<()>,
    row: &mut dyn FnMut(&Path, bool) -> io::Result<String>,
) -> io::Result<usize> {
    let meta = std::fs::symlink_metadata(root)?;
    refuse_reparse(root, &meta)?;
    let _hold = if meta.is_dir() {
        Some(host.hold_dir(root)?)
    } else {
        None
    };
    let mut count = 0;
    walk(host, root, meta.is_dir(), check, row, &mut count)?;
    Ok(count)
}

fn walk(
    host: &dyn Host,
    path: &Path,
    is_dir: bool,
    check: &mut dyn FnMut(&Path) -> io::Result<()>,
    row: &mut dyn FnMut(&Path, bool) -> io::Result<String>,
    count: &mut usize,
) -> io::Result<()> {
    let want = row(path, is_dir)?;
    check(path)?;
    host.set_sddl(path, &want)?;
    *count += 1;
    if !is_dir {
        return Ok(());
    }
    let mut names = std::fs::read_dir(path)?
        .map(|e| e.map(|e| e.path()))
        .collect::<io::Result<Vec<_>>>()?;
    names.sort();
    for child in names {
        let meta = std::fs::symlink_metadata(&child)?;
        refuse_reparse(&child, &meta)?;
        walk(host, &child, meta.is_dir(), check, row, count)?;
    }
    Ok(())
}

pub(crate) fn refuse_reparse(path: &Path, meta: &std::fs::Metadata) -> io::Result<()> {
    #[cfg(windows)]
    let reparse = {
        use std::os::windows::fs::MetadataExt;
        meta.file_attributes() & 0x400 != 0
    };
    #[cfg(not(windows))]
    let reparse = meta.file_type().is_symlink();
    if reparse {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is a reparse point", path.display()),
        ));
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
    use saiife_win::sddl::stock;
    use saiife_win::sid::{AUTHENTICATED_USERS, USERS};
    use std::path::PathBuf;

    const A: &str = "S-1-5-21-1-2-3-1009";
    const S: &str = "S-1-5-80-1485410291-497971702-176010752-1662630379-411534723";

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

    fn covered(l: &Layout, path: &Path) -> Option<String> {
        expected(l, path, A).unwrap()
    }

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
                covered(&l, &at(&l, row.path)).as_deref(),
                Some(want.as_str()),
                "{}",
                row.path
            );
            assert_eq!(
                covered(&sys, Path::new(row.path)).as_deref(),
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
            let text = covered(&l, &at(&l, row.path)).unwrap();
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
        let row = |constant: &str| covered(&l, &l.at(constant)).unwrap();
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
        let text = covered(&l, &l.at(layout::VAULT_KEY)).unwrap();
        let sd = parse(&text).unwrap();
        assert!(sd.dacl_protected);
        let sids: Vec<&str> = sd.aces.iter().map(|a| a.sid.as_str()).collect();
        assert_eq!(sids, [SYSTEM, ADMINISTRATORS, S]);
        let service = sd.aces.iter().find(|a| a.sid == S).unwrap();
        assert_eq!(service.mask, 0x12_0089, "FR, nothing more");
        assert_eq!(service.mask & WRITE_LIKE, 0);
        // Windows ignores case, so another spelling is still the key.
        let shouted = at(&l, r"C:\PROGRAMDATA\SAIIFE\STATE\KEYS\VAULT.KEY");
        assert_eq!(covered(&l, &shouted), Some(text));
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
            assert_eq!(covered(&l, &at(&l, path)), None, "{path}");
            assert_eq!(covered(&sys, Path::new(path)), None, "{path}");
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
            assert_eq!(covered(&sys, Path::new(path)), None, "{path}");
        }
        // The same names below a test root, each as one path component where
        // this OS allows it. Built as text: on Windows the root is canonical, so `\\?\`,
        // and `join` there resolves `..` itself and hands back a path that truly is
        // `state`, which is right for that path and tests nothing here.
        let root = l.root().to_str().unwrap();
        for rest in [
            ["C", "ProgramData", "saiife", "etc", "..", "state"].as_slice(),
            &["C", "ProgramData", "saiife", "state", "keys", "vault.key."],
            &[
                "C",
                "ProgramData",
                "saiife",
                "state",
                "keys",
                "vault.key::$DATA",
            ],
            &["CC", "ProgramData", "saiife", "etc"],
            &["1", "ProgramData", "saiife", "etc"],
        ] {
            let sep = std::path::MAIN_SEPARATOR_STR;
            let path = PathBuf::from(format!("{root}{sep}{}", rest.join(sep)));
            assert_eq!(covered(&l, &path), None, "{}", path.display());
        }
        #[cfg(unix)]
        assert_eq!(
            covered(
                &l,
                &l.root().join(r"C/ProgramData/saiife/state/keys\vault.key")
            ),
            None
        );
        // Outside the root.
        assert_eq!(covered(&l, Path::new("/ProgramData/saiife")), None);
    }

    #[test]
    fn expected_is_none_for_other_platforms() {
        let d = tempfile::tempdir().unwrap();
        for p in [Platform::Linux, Platform::Macos] {
            let l = Layout::under_for(d.path(), p);
            assert_eq!(covered(&l, &l.at(layout::CONFIG)), None);
            assert_eq!(
                covered(&l, &l.root().join("C/ProgramData/saiife/etc")),
                None
            );
        }
    }

    /// `audit_sid` goes into the descriptor as text, so a bad one can never add
    /// an ACE. It is an error, not "not covered": a caller that skips on `None`
    /// would silently check nothing. That holds on every row and for a path the
    /// table does not cover.
    #[test]
    fn expected_errors_on_a_malformed_audit_sid() {
        let (_d, l) = test_layout();
        let audit = l.at(layout::AUDIT_DIR);
        let config = l.at(layout::CONFIG);
        let outside = at(&l, r"C:\Windows");
        for bad in ["", "BU", "saiife-audit", "S-1-5-1)(A;;FA;;;BU"] {
            for path in [&audit, &config, &outside] {
                let got = expected(&l, path, bad);
                assert!(got.is_err(), "{bad:?} {path:?}: {got:?}");
            }
        }
        assert_eq!(expected(&l, &outside, A), Ok(None));
    }

    /// A well-formed SID is taken as given: Task 7 checks that the lookup is a
    /// local group.
    #[test]
    fn expected_takes_any_well_formed_audit_sid() {
        let (_d, l) = test_layout();
        let row = expected(&l, &l.at(layout::AUDIT_DIR), "S-1-1-0").unwrap();
        assert!(row.unwrap().contains(";;;S-1-1-0)"));
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

    /// An inheritable grant is a grant to every new child, from the moment it
    /// is created until the descriptor is reset, and a handle opened in that
    /// window outlives the reset.
    #[test]
    fn protected_ok_refuses_inherit_only_write() {
        assert_eq!(
            protected_ok(&ok_sd("BA", "(A;OICIIO;FA;;;BU)"), &[]),
            Err(format!("{USERS} may WRITE_DAC here"))
        );
        assert_eq!(
            protected_ok(&ok_sd("BA", "(A;CIIO;0x4;;;BU)"), &[]),
            Err(format!("{USERS} may FILE_APPEND_DATA here"))
        );
        assert_eq!(
            protected_ok(&ok_sd("BA", "(A;OICIIO;GA;;;AU)"), &[]),
            Err(format!("{AUTHENTICATED_USERS} may GENERIC_ALL here"))
        );
        // The rights an ACE holds now and passes on count together.
        assert_eq!(
            protected_ok(&ok_sd("BA", "(A;;0x4;;;BU)(A;OICIIO;WD;;;BU)"), &[]),
            Err(format!("{USERS} may WRITE_DAC here"))
        );
    }

    #[test]
    fn protected_ok_inherit_only_exemptions() {
        // Trusted SIDs, stock `Program Files` shapes.
        protected_ok(
            &ok_sd(
                "BA",
                &format!("(A;OICIIO;GA;;;SY)(A;OICIIO;GA;;;BA)(A;CIIO;GA;;;{TRUSTED_INSTALLER})"),
            ),
            &[],
        )
        .unwrap();
        // CREATOR OWNER is a placeholder, stock in Program Files.
        protected_ok(&ok_sd("BA", "(A;OICIIO;GA;;;CO)"), &[]).unwrap();
        // ... only as a placeholder: effective, it is no exemption.
        assert!(protected_ok(&ok_sd("BA", "(A;;FA;;;CO)"), &[]).is_err());
        // OWNER RIGHTS is not CREATOR OWNER.
        assert!(protected_ok(&ok_sd("BA", "(A;OICIIO;GA;;;OW)"), &[]).is_err());
        // `<S>` only where the caller says the table grants it.
        let sd = ok_sd("BA", &format!("(A;OICIIO;FA;;;{S})"));
        assert!(protected_ok(&sd, &[]).is_err());
        protected_ok(&sd, &[S]).unwrap();
        // An inheritable read is no write.
        protected_ok(&ok_sd("BA", "(A;OICIIO;GXGR;;;BU)"), &[]).unwrap();
    }

    /// `ancestor_ok` keeps ignoring these: stock `C:\` has an inherit-only
    /// Modify for Authenticated Users, and our dirs are created protected.
    #[test]
    fn ancestor_ok_still_ignores_inherit_only() {
        ancestor_ok(&ok_sd("SY", "(A;OICIIO;FA;;;BU)")).unwrap();
    }

    /// `want` for `path`, with the fixed `<A>`.
    fn want(l: &Layout, path: &str) -> String {
        covered(l, &at(l, path)).unwrap()
    }

    const DAEMON_LOG_1: &str = r"C:\ProgramData\saiife\log\daemon\daemon.log.1";
    const SEGMENT: &str = r"C:\ProgramData\saiife\log\audit\2026-11.jsonl";

    /// A file the service created under the daemon log dir: its owner, whatever
    /// group its token has, and the parent's ACEs marked inherited.
    fn inherited_daemon_log(owner: &str, extra: &str) -> Sd {
        parse(&format!(
            "O:{owner}G:S-1-5-21-1-2-3-513D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;{S})(A;ID;FR;;;{A}){extra}"
        ))
        .unwrap()
    }

    #[test]
    fn service_created_files_match_on_rows_it_may_write() {
        let (_d, l) = test_layout();
        let log = want(&l, DAEMON_LOG_1);
        assert!(service_may_write(&log));
        actual_ok(&log, &inherited_daemon_log(S, "")).unwrap();
        // A subdir carries the inherit flags on as well.
        let subdir = parse(&format!(
            "O:{S}G:{S}D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;FA;;;{S})(A;OICIID;0x1200a9;;;{A})"
        ))
        .unwrap();
        actual_ok(&want(&l, SEGMENT), &subdir).unwrap();
        // The exact descriptor, as install sets it, matches too.
        actual_ok(&log, &parse(&log).unwrap()).unwrap();
        // And a reinstall keeps the file.
        protected_ok(&inherited_daemon_log(S, ""), &[S]).unwrap();
        // State files the service writes.
        let state = want(&l, r"C:\ProgramData\saiife\state\sessions.db");
        let file = parse(&format!(
            "O:{S}G:{S}D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;{S})"
        ))
        .unwrap();
        actual_ok(&state, &file).unwrap();
    }

    /// The lockdown flag (`<state>\state\lockdown.json`): the service creates it
    /// and must be able to delete it (`lockdown off`, CI run 42188746371), and
    /// nobody but it, SYSTEM and Administrators holds any right on it or its dir.
    #[test]
    fn lockdown_flag_is_deletable_by_the_service_only() {
        const DELETE: u32 = 0x0001_0000;
        const FILE_DELETE_CHILD: u32 = 0x0000_0040;
        let (_d, l) = test_layout();
        let dir = want(&l, r"C:\ProgramData\saiife\state\state");
        let file = want(&l, r"C:\ProgramData\saiife\state\state\lockdown.json");
        assert_eq!(dir, STATE.replace("<S>", S));
        assert_eq!(file, dir);
        for (row, bit) in [(&file, DELETE), (&dir, FILE_DELETE_CHILD)] {
            let sd = parse(row).unwrap();
            let sids: Vec<&str> = sd.aces.iter().map(|a| a.sid.as_str()).collect();
            assert_eq!(sids, [SYSTEM, ADMINISTRATORS, S], "{row}");
            for ace in &sd.aces {
                assert_eq!(ace.mask & bit, bit, "{} lacks {bit:#x}: {row}", ace.sid);
            }
        }
        // The file as the service writes it (a renamed temp file, with the dir's
        // ACEs inherited) matches its row.
        let written = parse(&format!(
            "O:{S}G:{S}D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;{S})"
        ))
        .unwrap();
        actual_file_ok(&file, &written).unwrap();
        // One more holder of any right on it does not.
        let widened = parse(&format!(
            "O:{S}G:{S}D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;{S})(A;;0x10000;;;BU)"
        ))
        .unwrap();
        assert!(actual_file_ok(&file, &widened).is_err());
    }

    #[test]
    fn service_owner_needs_the_table_to_grant_the_service() {
        assert!(protected_ok(&inherited_daemon_log(S, ""), &[]).is_err());
        assert_eq!(
            protected_ok(&ok_sd(S, ""), &[]),
            Err(format!(
                "owned by {S}, expected SYSTEM, Administrators or TrustedInstaller"
            ))
        );
        protected_ok(&ok_sd(S, ""), &[S]).unwrap();
        // Any other SID stays refused as an owner, even when named as a writer.
        assert!(protected_ok(&ok_sd(A, ""), &[A]).is_err());
    }

    #[test]
    fn normalising_lets_no_foreign_file_through() {
        let (_d, l) = test_layout();
        let log = want(&l, DAEMON_LOG_1);
        let user = "S-1-5-21-1-2-3-1001";
        for (why, sd) in [
            ("user owner", inherited_daemon_log(user, "")),
            ("Users owner", inherited_daemon_log("BU", "")),
            ("audit group owner", inherited_daemon_log(A, "")),
            ("Users write", inherited_daemon_log(S, "(A;ID;FA;;;BU)")),
            ("Users append", inherited_daemon_log(S, "(A;ID;0x4;;;BU)")),
            (
                "explicit Users write",
                inherited_daemon_log(S, "(A;;FA;;;BU)"),
            ),
            (
                "inheritable Users write",
                inherited_daemon_log(S, "(A;OICIIO;FA;;;BU)"),
            ),
            (
                "Users read",
                inherited_daemon_log(S, "(A;ID;0x1200a9;;;BU)"),
            ),
            ("a stray deny", inherited_daemon_log(S, "(D;;FA;;;BA)")),
            (
                "audit group write",
                parse(&format!(
                    "O:{S}D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;{S})(A;ID;FA;;;{A})"
                ))
                .unwrap(),
            ),
            (
                "audit group lost",
                parse(&format!(
                    "O:{S}D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;{S})"
                ))
                .unwrap(),
            ),
            (
                "rights only passed on",
                parse(&format!(
                    "O:{S}D:AI(A;OICIIO;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;{S})(A;ID;FR;;;{A})"
                ))
                .unwrap(),
            ),
        ] {
            let got = actual_ok(&log, &sd);
            assert!(got.is_err(), "{why}: {got:?}");
        }
    }

    /// Off the service's rows the descriptor must be exact: no service owner,
    /// no inherited form. The vault key is the one that matters most.
    #[test]
    fn rows_the_service_cannot_write_stay_exact() {
        let (_d, l) = test_layout();
        for path in [
            r"C:\ProgramData\saiife",
            r"C:\ProgramData\saiife\bin\saiife.exe",
            r"C:\ProgramData\saiife\etc\config.toml",
            r"C:\ProgramData\saiife\state\keys\vault.key",
            r"C:\ProgramData\saiife\log",
            r"C:\ProgramData\gemini-cli\settings.json",
        ] {
            let row = want(&l, path);
            assert!(!service_may_write(&row), "{path}");
            let exact = parse(&row).unwrap();
            actual_ok(&row, &exact).unwrap_or_else(|e| panic!("{path}: {e}"));
            // Owned by the service.
            let mut sd = exact.clone();
            sd.owner = Some(S.to_string());
            assert!(actual_ok(&row, &sd).is_err(), "{path}: service owner");
            // Inherited.
            let mut sd = exact.clone();
            sd.dacl_protected = false;
            for ace in &mut sd.aces {
                ace.flags.inherited = true;
            }
            assert!(actual_ok(&row, &sd).is_err(), "{path}: inherited form");
        }
    }

    fn file_row(l: &Layout) -> String {
        want(l, r"C:\ProgramData\saiife\bin\saiife.exe")
    }

    /// What Windows printed in CI for an `OICI` row set on a file.
    #[test]
    fn a_file_reads_back_without_oici_and_passes_actual_file_ok() {
        let (_d, l) = test_layout();
        let row = file_row(&l);
        let mut sd = parse(&row).unwrap();
        for ace in &mut sd.aces {
            ace.flags.object_inherit = false;
            ace.flags.container_inherit = false;
        }
        actual_file_ok(&row, &sd).unwrap();
        // For a directory the same read-back is wrong.
        assert!(actual_ok(&row, &sd).is_err());
        // A file keeping OICI is refused: the row was cleared, so it must match.
        assert!(actual_file_ok(&row, &parse(&row).unwrap()).is_err());
    }

    #[test]
    fn actual_file_ok_relaxes_only_oici() {
        let (_d, l) = test_layout();
        let row = file_row(&l);
        let mut good = parse(&row).unwrap();
        for ace in &mut good.aces {
            ace.flags.object_inherit = false;
            ace.flags.container_inherit = false;
        }
        actual_file_ok(&row, &good).unwrap();
        let mut sd = good.clone();
        sd.dacl_protected = false;
        assert!(actual_file_ok(&row, &sd).is_err(), "P is required");
        let mut sd = good.clone();
        sd.owner = Some(S.to_string());
        assert!(actual_file_ok(&row, &sd).is_err(), "owner");
        let mut sd = good.clone();
        sd.group = Some(ADMINISTRATORS.to_string());
        assert!(actual_file_ok(&row, &sd).is_err(), "group");
        let mut sd = good.clone();
        sd.aces[0].mask ^= 0x1;
        assert!(actual_file_ok(&row, &sd).is_err(), "mask");
        let mut sd = good.clone();
        sd.aces.pop();
        assert!(actual_file_ok(&row, &sd).is_err(), "missing ACE");
        let mut sd = good.clone();
        sd.aces[0].flags.inherited = true;
        assert!(actual_file_ok(&row, &sd).is_err(), "inherited flag");
        let mut sd = good;
        sd.aces[0].flags.inherit_only = true;
        assert!(actual_file_ok(&row, &sd).is_err(), "inherit-only");
    }

    /// A directory keeps `OICI` (seen in CI), so a dir row stays exact.
    #[test]
    fn dir_rows_stay_exact_including_oici() {
        let (_d, l) = test_layout();
        let row = want(&l, r"C:\ProgramData\saiife\etc");
        actual_ok(&row, &parse(&row).unwrap()).unwrap();
        let mut sd = parse(&row).unwrap();
        sd.aces[0].flags.container_inherit = false;
        assert!(actual_ok(&row, &sd).is_err());
    }

    fn tree_host() -> (tempfile::TempDir, crate::host::FakeHost) {
        let dir = tempfile::tempdir().unwrap();
        let host = crate::host::FakeHost::open(dir.path()).unwrap();
        (dir, host)
    }

    const ROW: &str = "O:BAG:SYD:PAI(A;OICI;FA;;;SY)";

    fn no_check(_: &Path) -> io::Result<()> {
        Ok(())
    }

    /// The security scan's finding: the check runs before every set, the root is held
    /// across the walk and let go after it.
    #[test]
    fn set_sddl_tree_checks_before_every_set_and_holds_the_root() {
        let (dir, host) = tree_host();
        let root = std::fs::canonicalize(dir.path()).unwrap().join("t");
        std::fs::create_dir_all(root.join("a")).unwrap();
        std::fs::write(root.join("a/f"), b"x").unwrap();
        let mut checked = Vec::new();
        set_sddl_tree(
            &host,
            &root,
            &mut |p| {
                assert!(host.get_sddl(p).is_err(), "checked before its set: {p:?}");
                checked.push(p.to_path_buf());
                Ok(())
            },
            &mut |_, _| Ok(ROW.to_string()),
        )
        .unwrap();
        assert_eq!(checked, [root.clone(), root.join("a"), root.join("a/f")]);
        let calls = host.state().calls;
        let at = |line: String| calls.iter().position(|c| *c == line).unwrap();
        let held = at(format!("hold {}", root.display()));
        let freed = at(format!("release {}", root.display()));
        for p in &checked {
            let set = at(format!("set_sddl {} {ROW}", p.display()));
            assert!(held < set && set < freed, "{calls:?}");
        }
    }

    /// A check that fails stops the walk before anything is set on that entry.
    #[test]
    fn set_sddl_tree_stops_at_a_failed_check() {
        let (dir, host) = tree_host();
        let root = std::fs::canonicalize(dir.path()).unwrap().join("t");
        std::fs::create_dir_all(root.join("a")).unwrap();
        let e = set_sddl_tree(
            &host,
            &root,
            &mut |p| {
                if p.ends_with("a") {
                    Err(io::Error::other("chain"))
                } else {
                    Ok(())
                }
            },
            &mut |_, _| Ok(ROW.to_string()),
        )
        .unwrap_err();
        assert!(e.to_string().contains("chain"));
        assert!(host.get_sddl(&root.join("a")).is_err());
    }

    /// A junction swapped in below the root: the fake answers as the handle compare does.
    #[cfg(unix)]
    #[test]
    fn set_refuses_a_path_redirected_above_the_last_component() {
        let (dir, host) = tree_host();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::create_dir_all(base.join("real")).unwrap();
        std::fs::write(base.join("real/f"), b"x").unwrap();
        std::os::unix::fs::symlink(base.join("real"), base.join("link")).unwrap();
        let e = host.set_sddl(&base.join("link/f"), ROW).unwrap_err();
        assert!(e.to_string().contains("is really"), "{e}");
        assert!(host.get_sddl(&base.join("real/f")).is_err());
        host.set_sddl(&base.join("real/f"), ROW).unwrap();
    }

    #[test]
    fn set_sddl_tree_sets_every_entry_top_down() {
        let (dir, host) = tree_host();
        let root = std::fs::canonicalize(dir.path()).unwrap().join("t");
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        std::fs::write(root.join("a/b/f"), b"x").unwrap();
        std::fs::write(root.join("g"), b"x").unwrap();
        let mut seen = Vec::new();
        let n = set_sddl_tree(&host, &root, &mut no_check, &mut |p, d| {
            seen.push((p.strip_prefix(&root).unwrap().to_path_buf(), d));
            Ok(ROW.to_string())
        })
        .unwrap();
        assert_eq!(n, 5);
        let names: Vec<Vec<_>> = seen
            .iter()
            .map(|(p, _)| p.components().map(|c| c.as_os_str().to_owned()).collect())
            .collect();
        let want: Vec<Vec<_>> = ["", "a", "a/b", "a/b/f", "g"]
            .iter()
            .map(|p| {
                Path::new(p)
                    .components()
                    .map(|c| c.as_os_str().to_owned())
                    .collect()
            })
            .collect();
        assert_eq!(names, want);
        assert!(seen[1].1 && !seen[3].1);
        assert_eq!(host.get_sddl(&root.join("a/b/f")).unwrap(), ROW);
    }

    #[test]
    fn set_sddl_tree_stops_at_a_row_error() {
        let (dir, host) = tree_host();
        let root = std::fs::canonicalize(dir.path()).unwrap().join("t");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("f"), b"x").unwrap();
        let e = set_sddl_tree(&host, &root, &mut no_check, &mut |p, _| {
            if p.ends_with("f") {
                Err(io::Error::other("no row"))
            } else {
                Ok(ROW.to_string())
            }
        })
        .unwrap_err();
        assert!(e.to_string().contains("no row"));
    }

    #[cfg(unix)]
    #[test]
    fn set_sddl_tree_refuses_a_reparse_point_without_following_it() {
        let (dir, host) = tree_host();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        let root = base.join("t");
        let outside = base.join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret"), b"x").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        let e = set_sddl_tree(&host, &root, &mut no_check, &mut |_, _| Ok(ROW.to_string()))
            .unwrap_err();
        assert!(e.to_string().contains("reparse point"), "{e}");
        assert!(host.get_sddl(&outside.join("secret")).is_err());
        assert!(host.get_sddl(&outside).is_err());
        // A link as the root is refused too.
        let e = set_sddl_tree(&host, &root.join("link"), &mut no_check, &mut |_, _| {
            Ok(ROW.to_string())
        });
        assert!(e.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn set_sddl_tree_refuses_a_hard_link() {
        let (dir, host) = tree_host();
        let root = std::fs::canonicalize(dir.path()).unwrap().join("t");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a"), b"x").unwrap();
        std::fs::hard_link(root.join("a"), root.join("b")).unwrap();
        let e = set_sddl_tree(&host, &root, &mut no_check, &mut |_, _| Ok(ROW.to_string()))
            .unwrap_err();
        assert!(e.to_string().contains("hard link"), "{e}");
        assert!(host.get_sddl(&root.join("b")).is_err());
    }

    #[test]
    fn service_may_write_follows_the_table() {
        let (_d, l) = test_layout();
        for row in ROWS {
            assert_eq!(
                service_may_write(&want(&l, row.path)),
                row.writers.contains(&S),
                "{}",
                row.path
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
        let program_data = parse(stock::PROGRAM_DATA).unwrap();
        ancestor_ok(&program_data).unwrap();
        // The same folder is not fit to be ours: Users may create entries.
        assert_eq!(
            protected_ok(&program_data, &[]),
            Err(format!("{USERS} may FILE_WRITE_DATA here"))
        );
    }

    /// A refusal here would stop install on every stock machine.
    #[test]
    fn ancestor_ok_accepts_the_real_folders() {
        for text in [
            stock::DRIVE_ROOT,
            stock::PROGRAM_DATA,
            stock::PROGRAM_FILES,
            stock::WINDOWS,
        ] {
            ancestor_ok(&parse(text).unwrap()).unwrap_or_else(|e| panic!("{text}: {e}"));
        }
    }

    /// `LA` is the built-in Administrator: fit to own or write, and nothing more. Windows
    /// prints it for that account; the row still has to read back as the table says.
    #[test]
    fn la_counts_as_admin_for_owner_and_writers() {
        protected_ok(&ok_sd(LOCAL_ADMIN, ""), &[]).unwrap();
        ancestor_ok(&ok_sd(LOCAL_ADMIN, "")).unwrap();
        for ace in ["(A;;FA;;;LA)", "(A;OICI;FA;;;LA)", "(A;OICIIO;GA;;;LA)"] {
            protected_ok(&ok_sd("BA", ace), &[]).unwrap_or_else(|e| panic!("{ace}: {e}"));
            ancestor_ok(&ok_sd("SY", ace)).unwrap_or_else(|e| panic!("{ace}: {e}"));
        }
        // Others are not excused by its being there.
        assert!(protected_ok(&ok_sd("LA", "(A;;FA;;;BU)"), &[]).is_err());
        assert!(ancestor_ok(&ok_sd("LA", "(A;;WD;;;BU)")).is_err());

        let (_d, l) = test_layout();
        let row = want(&l, r"C:\ProgramData\saiife\etc\config.toml");
        let mut sd = parse(&row).unwrap();
        actual_ok(&row, &sd).unwrap();
        sd.owner = Some(LOCAL_ADMIN.to_string());
        assert!(actual_ok(&row, &sd).is_err(), "off-row owner");
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
